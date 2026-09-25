"""
CBSEF Burp Suite extension (reference implementation, Montoya API).

This file is the in-Burp side of the framework: a passive-first HttpHandler
that detects the mass-assignment test case in proxied traffic and posts
candidate findings to the companion GUI's loopback bridge.

Build/install options:
  - Montoya (modern Burp): port the logic to a Java/Kotlin project and load
    the JAR via Extender. The JSON payload contract below is the interface.
  - Quick lab use: run this file through a Jython 2.7 environment in legacy
    Burp, or adapt it as a standalone proxy script.

The JSON posted to the companion GUI (POST http://127.0.0.1:<port>/findings):

    {
      "finding_id": "hex12",
      "test_case": "mass_assignment",
      "url": "/api/users",
      "method": "POST",
      "endpoint": "/api/users",
      "parameter": "is_admin",
      "confidence": "medium",
      "status": "candidate",
      "signal_description": "JSON body binds authorization-like fields",
      "baseline_request": "...",
      "baseline_response": "...",
      "probe_request": null,
      "probe_response": null,
      "differential": null,
      "remediation": "..."
    }
"""

BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 8737            # must match the companion GUI
BRIDGE_TOKEN = ""             # optional; set the same value in the GUI

# Authorization-ish field names watched by the mass-assignment detector.
CANARY_FIELDS = [
    "is_admin", "isadmin", "admin", "is_superuser", "role", "user_role",
    "scope", "permissions",
]


def detect_mass_assignment(method: str, body: str) -> dict | None:
    """Passive check: does a JSON body contain authorization-like fields?"""
    import json
    try:
        doc = json.loads(body)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    hits = [k for k in doc if str(k).lower() in CANARY_FIELDS]
    if not hits:
        return None
    return {
        "finding_id": uuid_hex(),
        "test_case": "mass_assignment",
        "method": method,
        "parameter": ", ".join(hits),
        "confidence": "medium",
        "status": "candidate",
        "signal_description": (
            "JSON body binds authorization-like field(s): "
            f"{hits} — analyst confirmation required"),
        "remediation": (
            "Use explicit field allowlists for model binding; reject unknown "
            "fields; never bind role/admin fields from user input."),
    }


def uuid_hex() -> str:
    import uuid
    return uuid.uuid4().hex[:12]


def post_finding(finding: dict) -> bool:
    """POST one finding to the companion GUI bridge (loopback only)."""
    import json
    try:
        from urllib import request as urlrequest
        data = json.dumps(finding).encode("utf-8")
        req = urlrequest.Request(
            f"http://{BRIDGE_HOST}:{BRIDGE_PORT}/findings", data=data,
            headers={"Content-Type": "application/json",
                     "X-CBSEF-Token": BRIDGE_TOKEN}, method="POST")
        with urlrequest.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Montoya API sketch (Java-like pseudocode; implement in a Gradle project):
#
# public class CbsefExtension implements BurpExtension {
#     public void initialize(MontoyaApi api) {
#         api.extension().setName("CBSEF mass-assignment");
#         api.http().registerHttpHandler(new HttpHandler() {
#             public void handleHttpRequest(HttpRequestToSent req,
#                                           HttpResponseReceived resp,
#                                           ToolSource src) {
#                 var finding = MassAssignmentDetector.check(
#                     req.method(), req.bodyToString());
#                 if (finding != null) {
#                     BridgeClient.post(finding);   // loopback POST, non-blocking
#                 }
#             }
#         });
#         api.extension().registerUnloadingHandler(msg ->
#             BridgeClient.close());               // flush + close on unload
#     }
# }
# ---------------------------------------------------------------------------
