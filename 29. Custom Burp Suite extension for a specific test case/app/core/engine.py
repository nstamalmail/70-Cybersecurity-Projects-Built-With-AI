"""Test-case engines for CBSEF (architecture.md §3.1 Test-Case Engine).

The reference implementation is **mass-assignment detection**; three more
analyzers (JWT algorithm confusion, OAuth redirect_uri validation, GraphQL
introspection) cover the cases named in the spec. Engines work in two modes:

- **analyze(request, response)** — passive inspection of one proxy pair.
- **probe(baseline)** — active probe: builds a mutated request the caller
  may send (rate-limited, non-destructive), then analyzes the pair.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, parse_qsl

from app.core.models import CandidateFinding, new_finding_id


# ------------------------------------------------------------------ HTTP utils
def parse_raw_request(raw: str) -> Dict[str, Any]:
    """Parse a raw HTTP request (method, url, headers, body)."""
    out: Dict[str, Any] = {"method": "", "url": "", "headers": {}, "body": ""}
    if not raw:
        return out
    lines = raw.replace("\r\n", "\n").split("\n")
    if not lines:
        return out
    first = lines[0].split()
    if len(first) >= 2:
        out["method"] = first[0]
        out["url"] = first[1]
    in_body = False
    body_lines = []
    for line in lines[1:]:
        if in_body:
            body_lines.append(line)
        elif line.strip() == "":
            in_body = True
        elif ":" in line:
            k, _, v = line.partition(":")
            out["headers"][k.strip()] = v.strip()
    out["body"] = "\n".join(body_lines).strip()
    return out


def json_body(body: str) -> Dict[str, Any]:
    try:
        doc = json.loads(body)
        return doc if isinstance(doc, dict) else {}
    except Exception:
        return {}


def format_response(resp: Dict[str, Any]) -> str:
    """Compact fingerprint of a response for differential display."""
    if not resp:
        return "(none)"
    return (f"status={resp.get('status')} len={resp.get('len')} "
            f"body_hash={resp.get('body_hash', '')[:12]}")


# ------------------------------------------------------------------ mass assignment
MASS_ASSIGNMENT_CANARIES = [
    ("is_admin", True), ("isadmin", True), ("admin", True),
    ("role", "admin"), ("user_role", "admin"),
    ("is_superuser", True), ("isAdmin", True), ("scope", "admin"),
]


@dataclass
class Probe:
    """A mutated request ready to send (active probing is opt-in upstream)."""

    name: str
    raw_request: str
    description: str


def mass_assignment_probes(raw_request: str) -> List[Probe]:
    """Build JSON-body probes with extra authorization-ish fields."""
    req = parse_raw_request(raw_request)
    body = json_body(req["body"])
    if not body:
        return []
    probes = []
    for field_name, value in MASS_ASSIGNMENT_CANARIES[:4]:
        mutated = dict(body)
        mutated[field_name] = value
        body_str = json.dumps(mutated)
        raw = (f"{req['method']} {req['url']}\n"
               + "\n".join(f"{k}: {v}" for k, v in req["headers"].items()
                           if k.lower() != "content-length")
               + f"\nContent-Length: {len(body_str)}\n\n{body_str}")
        probes.append(Probe(
            name=f"mass-assign:{field_name}",
            raw_request=raw,
            description=f"adds {field_name}={value!r} to the JSON body"))
    return probes


def analyze_mass_assignment(baseline_req: str, baseline_resp: Dict[str, Any],
                            probe_req: str, probe_resp: Dict[str, Any],
                            probe_name: str = "") -> Optional[CandidateFinding]:
    """Signal: the server accepts and echoes the injected field / grants change."""
    req = parse_raw_request(probe_req)
    body = json_body(req["body"])
    baseline_body = json_body(parse_raw_request(baseline_req)["body"])
    added = {k: v for k, v in body.items() if k not in baseline_body}
    if not added:
        return None

    signals = []
    status_changed = probe_resp.get("status") != baseline_resp.get("status")
    len_delta = probe_resp.get("len", 0) - baseline_resp.get("len", 0)
    echoed_fields = []

    probe_body_text = str(probe_resp.get("body", ""))
    for k, v in added.items():
        if k.lower() in probe_body_text.lower():
            echoed_fields.append(k)
    if echoed_fields:
        signals.append(f"probe field(s) echoed in response: {echoed_fields}")
    if status_changed:
        signals.append(f"status changed {baseline_resp.get('status')} → "
                       f"{probe_resp.get('status')}")
    if abs(len_delta) > 16:
        signals.append(f"response length delta {len_delta:+d} bytes")

    if not signals:
        return None

    echoed = bool(echoed_fields)
    finding = CandidateFinding(
        finding_id=new_finding_id(),
        test_case="mass_assignment",
        url=req["url"], method=req["method"],
        endpoint=urlparse(req["url"]).path if req["url"] else "",
        parameter=", ".join(added),
        confidence="high" if (echoed and status_changed) else
                   ("medium" if echoed or status_changed else "low"),
        status="candidate",
        signal_description="; ".join(signals),
        baseline_request=baseline_req,
        baseline_response=format_response(baseline_resp),
        probe_request=probe_req,
        probe_response=format_response(probe_resp),
        differential={"added_fields": added, "status_changed": status_changed,
                      "len_delta": len_delta, "echoed_fields": echoed_fields},
        remediation=(
            "Mass assignment: the API binds unvalidated client-supplied fields "
            "to internal models.\n"
            "Fix:\n"
            "  1. Use explicit field allowlists (DTOs / strong parameters) for "
            "every bindable model.\n"
            "  2. Reject unknown fields instead of silently ignoring them.\n"
            "  3. Never bind security-sensitive fields (role/is_admin/scope) "
            "from user input.\n"
            "  4. Test: send requests with added authorization fields and "
            "assert they are ignored.")
    )
    return finding


# ------------------------------------------------------------------ JWT confusion
def analyze_jwt_confusion(request_text: str) -> Optional[CandidateFinding]:
    """Passive: locate a JWT and check for algorithm-confusion hazards."""
    m = re.search(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*",
                  request_text)
    if not m:
        return None
    token = m.group()
    try:
        head_b64 = token.split(".")[0]        # segment 0 = JOSE header
        head_b64 += "=" * (-len(head_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(head_b64))
    except Exception:
        return None
    alg = str(header.get("alg", "")).lower()
    signals, severity, conf = [], "medium", "low"
    if alg == "none":
        signals.append("JWT alg=none token in traffic")
        severity, conf = "high", "high"
    elif alg.startswith("hs") and header.get("kid", "").startswith(("http", "/")):
        signals.append(f"HS JWT with external/path kid ({header.get('kid')}) — "
                       f"possible key-injection confusion")
        conf = "medium"
    if alg.startswith("rs") or alg.startswith("es"):
        # note only: acceptance of HS256 with public key as HMAC secret is
        # verified by active probing, not passively
        signals.append(f"asymmetric JWT (alg={alg}) — verify the service does "
                       f"not accept HS256 with the public key as secret")
        severity, conf = "medium", "low"
    if not signals:
        return None
    finding = CandidateFinding(
        finding_id=new_finding_id(),
        test_case="jwt_confusion",
        url="", method="", endpoint="(observed in traffic)",
        parameter="Authorization/JWT",
        confidence=conf, status="candidate",
        signal_description="; ".join(signals),
        baseline_request=request_text[:600],
        baseline_response="",
        remediation=(
            "JWT algorithm confusion.\n"
            "Fix:\n"
            "  1. Pin the expected algorithm server-side; reject alg=none and "
            "any algorithm not in the allowlist.\n"
            "  2. For asymmetric algorithms, never use the public key as an "
            "HMAC secret.\n"
            "  3. Validate kid against a strict allowlist (no paths/URLs).")
    )
    return finding


# ------------------------------------------------------------------ OAuth redirect
REDIRECT_BYPASS_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
    "https://trusted.example.com.evil.example.com",
    "https://trusted.example.com@evil.example.com",
    "https://trusted.example.com/..%2fevil.example.com",
]


def oauth_redirect_probes(raw_request: str, param: str = "redirect_uri") -> List[Probe]:
    req = parse_raw_request(raw_request)
    probes = []
    for payload in REDIRECT_BYPASS_PAYLOADS:
        if req["url"]:
            parsed = urlparse(req["url"])
            qs = [(k, v) for k, v in parse_qsl(parsed.query) if k != param]
            qs.append((param, payload))
            new_url = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}?"
                       + urlencode(qs))
            raw = (f"{req['method']} {new_url}\n"
                   + "\n".join(f"{k}: {v}" for k, v in req["headers"].items()
                               if k.lower() != "content-length"))
            probes.append(Probe(name=f"redirect:{payload[:40]}", raw_request=raw,
                                description=f"redirect_uri={payload!r}"))
    return probes


def analyze_oauth_redirect(baseline_req: str, probe_req: str,
                           probe_resp: Dict[str, Any]) -> Optional[CandidateFinding]:
    """Signal: the authorization server accepts a mutated redirect_uri
    (302/Location to an off-allowlist origin, or no rejection)."""
    req = parse_raw_request(probe_req)
    url = req.get("url", "")
    m = re.search(r"redirect_uri=([^&\s]+)", url)
    if not m:
        return None
    from urllib.parse import unquote
    payload = unquote(m.group(1))
    location = str(probe_resp.get("location", ""))
    body = str(probe_resp.get("body", ""))
    accepted = (location and "evil.example.com" in location) or \
               ("evil.example.com" in body and "error" not in body.lower())
    if not accepted:
        return None
    finding = CandidateFinding(
        finding_id=new_finding_id(),
        test_case="oauth_redirect",
        url=url, method=req["method"], endpoint=urlparse(url).path,
        parameter="redirect_uri",
        confidence="high", status="candidate",
        signal_description=f"mutated redirect_uri accepted: {payload}",
        baseline_request=baseline_req,
        probe_request=probe_req,
        probe_response=format_response(probe_resp),
        differential={"payload": payload, "location": location[:200]},
        remediation=(
            "OAuth open redirect / redirect_uri validation bypass.\n"
            "Fix:\n"
            "  1. Register and compare exact redirect_uri strings "
            "(no prefix or wildcard matching).\n"
            "  2. Reject path traversal, userinfo (@), and look-alike "
            "domains.\n"
            "  3. Keep state/PKCE mandatory.")
    )
    return finding


# ------------------------------------------------------------------ GraphQL introspection
INTROSPECTION_QUERY = '{"query":"{ __schema { types { name } } }"}'


def introspection_probe(raw_request: str) -> Optional[Probe]:
    req = parse_raw_request(raw_request)
    if req["url"]:
        body = INTROSPECTION_QUERY
        raw = (f"POST {req['url']}\n"
               + "\n".join(f"{k}: {v}" for k, v in req["headers"].items()
                           if k.lower() != "content-length")
               + f"\nContent-Type: application/json\n"
                 f"Content-Length: {len(body)}\n\n{body}")
        return Probe(name="introspection", raw_request=raw,
                     description="GraphQL introspection query")
    return None


def analyze_introspection(probe_req: str,
                          probe_resp: Dict[str, Any]) -> Optional[CandidateFinding]:
    body = str(probe_resp.get("body", ""))
    if "__schema" in body and probe_resp.get("status") == 200:
        req = parse_raw_request(probe_req)
        finding = CandidateFinding(
            finding_id=new_finding_id(),
            test_case="introspection",
            url=req.get("url", ""), method="POST",
            endpoint=urlparse(req.get("url", "")).path,
            parameter="query",
            confidence="high", status="candidate",
            signal_description="GraphQL introspection is enabled "
                               "(__schema returned data)",
            probe_request=probe_req,
            probe_response=format_response(probe_resp),
            remediation=(
                "GraphQL introspection enabled.\n"
                "Fix:\n"
                "  1. Disable introspection in production "
                "(schema exposure aids attackers).\n"
                "  2. Add depth/amount-of-aliases limits; consider "
                "persisted queries.")
        )
        return finding
    return None
