"""Remediation guidance for XSS findings (context-specific output encoding)."""

from __future__ import annotations

from typing import Dict

CONTEXT_REMEDIATION: Dict[str, str] = {
    "html_body": (
        "Untrusted data lands in the HTML body unencoded (reflected XSS).\n"
        "Fix: HTML-encode (& < > \" ') before rendering; prefer templating\n"
        "engines with auto-escaping enabled (Jinja2 autoescape, Django templates)."
    ),
    "html_attribute": (
        "Untrusted data breaks out of an HTML attribute.\n"
        "Fix: attribute-encode and ALWAYS quote attributes; never build\n"
        "attributes by concatenation. Use safe URL schemes only."
    ),
    "js_string": (
        "Untrusted data is concatenated into inline JavaScript.\n"
        "Fix: avoid inline JS with user data; pass data via data-* attributes\n"
        "and JSON.parse; use JSON serialization with < escaped (\\u003c)."
    ),
    "url_param": (
        "Untrusted data used in URLs (href/src) may execute javascript:.\n"
        "Fix: validate schemes against an allowlist (http/https/mailto);\n"
        "URL-encode before placing into URLs."
    ),
    "css_context": (
        "Untrusted data flows into CSS contexts.\n"
        "Fix: never interpolate user data into style blocks; use CSS custom\n"
        "properties set server-side from validated values."
    ),
    "unknown": (
        "Reflected input detected with partial/unknown encoding.\n"
        "Fix: apply context-aware output encoding at the render boundary."
    ),
}

CSP_GUIDANCE = (
    "Deploy a Content-Security-Policy as defense-in-depth, e.g.:\n"
    "  Content-Security-Policy: default-src 'self'; script-src 'self';\n"
    "    object-src 'none'; base-uri 'none'\n"
    "Avoid 'unsafe-inline' and 'unsafe-eval' in script-src."
)

FRAMEWORK_GUIDANCE = {
    "react": "React escapes by default — avoid dangerouslySetInnerHTML with user data.",
    "angular": "Angular sanitizes by default — bypassing with DomSanitizer is prohibited for user data.",
    "django": "Django templates auto-escape — never use |safe or mark_safe() on user input.",
    "rails": "Rails ERB escapes by default — avoid raw/html_safe on user input.",
    "vue": "Vue escapes interpolations — avoid v-html with user data.",
}

REFERENCES = [
    "OWASP Top 10 A03:2021 — Injection",
    "OWASP XSS Prevention Cheat Sheet",
    "CWE-79: Improper Neutralization of Input During Web Page Generation",
]


def build_remediation(context: str, xss_type: str, csp_present: bool = False) -> str:
    parts = [CONTEXT_REMEDIATION.get(context, CONTEXT_REMEDIATION["unknown"]), ""]
    if xss_type == "stored":
        parts.append("Stored XSS: encode at every render location; sanitize on "
                     "input with an allowlist library (e.g. DOMPurify server-side) "
                     "but never rely on input filtering alone.")
    elif xss_type == "dom":
        parts.append("DOM XSS: refactor sinks to use safe APIs (textContent, "
                     "setAttribute); validate sources before they reach sinks.")
    parts.append("")
    parts.append("Framework guidance:")
    for fw, tip in FRAMEWORK_GUIDANCE.items():
        parts.append(f"  - {fw}: {tip}")
    parts.append("")
    parts.append("CSP:")
    parts.append(CSP_GUIDANCE)
    if csp_present:
        parts.append("(CSP header present on target — verify it blocks inline "
                     "execution; finding may be mitigated.)")
    parts.append("")
    parts.append("References:")
    for ref in REFERENCES:
        parts.append(f"  - {ref}")
    return "\n".join(parts)
