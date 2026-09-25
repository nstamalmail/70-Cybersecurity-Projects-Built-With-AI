"""Builds concrete HTTP requests for each injection point & payload."""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.core.models import InjectionPoint, RequestSpec, ScanConfig

_P = re.compile(r"\{\{\{payload\}\}\}")


def discover_injection_points(cfg: ScanConfig) -> List[InjectionPoint]:
    """Auto-discover injection points from the target URL, headers and body.

    Returns only enabled points. URL query params and headers/cookies are always
    included; form/JSON bodies are parsed when present.
    """
    points: List[InjectionPoint] = []
    if not cfg.target_url:
        return points

    parsed = urlparse(cfg.target_url)
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        points.append(InjectionPoint("query", key, value, True))
    for name, value in cfg.headers.items():
        points.append(InjectionPoint("header", name, value, True))
    for name, value in cfg.cookies.items():
        points.append(InjectionPoint("cookie", name, value, True))

    if cfg.body_type in ("form", "raw") and cfg.body:
        for key, value in parse_qsl(cfg.body, keep_blank_values=True):
            points.append(InjectionPoint("body_form", key, value, True))
    elif cfg.body_type == "json":
        try:
            data = json.loads(cfg.body or "{}")
        except Exception:
            data = {}
        if isinstance(data, dict):
            _walk_json(data, "", points)

    return points


def _walk_json(data, prefix: str, out: List[InjectionPoint]) -> None:
    for key, value in data.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            _walk_json(value, name, out)
        elif isinstance(value, list):
            out.append(InjectionPoint("body_json", name, str(value), True))
        elif value is None:
            out.append(InjectionPoint("body_json", name, "", True))
        else:
            out.append(InjectionPoint("body_json", name, str(value), True))


def _replace_json_path(data, path: str, value) -> None:
    keys = path.split(".")
    cur = data
    for k in keys[:-1]:
        if not isinstance(cur, dict) or k not in cur:
            return
        cur = cur[k]
    if isinstance(cur, dict):
        cur[keys[-1]] = value


def build_request(cfg: ScanConfig, ip: InjectionPoint, payload: str) -> RequestSpec:
    """Return a RequestSpec with `payload` injected into `ip`.

    Headers/cookies/body are copied, then mutated in place for their respective
    injection kinds; the URL is rebuilt for query/path kinds.
    """
    headers = dict(cfg.headers)
    cookies = dict(cfg.cookies)
    body = cfg.body or ""
    body_type = cfg.body_type

    url, body = _inject(cfg.target_url, ip, payload, headers, cookies, body, body_type)

    return RequestSpec(
        url=url,
        method=cfg.method.upper(),
        headers=headers,
        cookies=cookies,
        body=body,
        body_type=body_type,
        timeout=cfg.timeout,
        allow_redirects=cfg.follow_redirects,
        verify=cfg.verify_ssl,
        proxies={"http": cfg.proxy, "https": cfg.proxy} if cfg.proxy else None,
    )


def _inject(url: str, ip: InjectionPoint, payload: str,
            headers: Dict[str, str], cookies: Dict[str, str],
            body: str, body_type: str) -> Tuple[str, str]:
    """Return (url, body). headers/cookies/body mutated in place as needed."""
    parsed = urlparse(url)
    query = parsed.query

    if ip.kind == "query":
        pairs = parse_qsl(query, keep_blank_values=True)
        pairs = [(k, payload if k == ip.name else v) for k, v in pairs]
        query = urlencode(pairs)
    elif ip.kind == "path":
        # Replace the last segment (or append if path ends with '/').
        path = parsed.path
        if path.endswith("/"):
            path = path + payload
        else:
            parts = path.split("/")
            parts[-1] = payload if parts[-1] else payload
            path = "/".join(parts)
        parsed = parsed._replace(path=path)
    elif ip.kind == "header":
        headers[ip.name] = payload
    elif ip.kind == "cookie":
        cookies[ip.name] = payload
    elif ip.kind == "body_form":
        pairs = parse_qsl(body, keep_blank_values=True)
        pairs = [(k, payload if k == ip.name else v) for k, v in pairs]
        body = urlencode(pairs)
    elif ip.kind == "body_json":
        try:
            data = json.loads(body or "{}")
        except Exception:
            data = {}
        if isinstance(data, dict):
            try:
                injected = json.loads(payload) if payload.lstrip().startswith(("{", "[")) else payload
            except Exception:
                injected = payload
            _replace_json_path(data, ip.name, injected)
            body = json.dumps(data)
    elif ip.kind == "body_raw":
        if _P.search(body):
            body = _P.sub(payload, body)
        else:
            body = body + payload

    return urlunparse(parsed._replace(query=query)), body


def payload_contains_marker(body: str) -> bool:
    return bool(_P.search(body or ""))


def json_paths(body: str) -> List[str]:
    """JSON path keys for user-selectable JSON body injection."""
    try:
        data = json.loads(body or "{}")
    except Exception:
        return []
    out: List[str] = []

    def walk(d, prefix):
        if not isinstance(d, dict):
            return
        for k, v in d.items():
            name = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                walk(v, name)
            else:
                out.append(name)
    walk(data, "")
    return out