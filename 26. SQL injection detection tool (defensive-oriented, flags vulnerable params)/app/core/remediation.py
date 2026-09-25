"""Remediation guidance generator (parameterized queries, ORM, WAF rules)."""

from __future__ import annotations

REMEDIATION_TEMPLATES = {
    "error": (
        "User input reaches a SQL query without sanitization (error-based signal).\n"
        "Fix:\n"
        "  1. Use parameterized queries / prepared statements — never build SQL by\n"
        "     string concatenation or f-strings.\n"
        "  2. Validate and type-cast the parameter server-side (allowlist).\n"
        "  3. Suppress verbose DBMS errors in production; log them server-side only."
    ),
    "boolean": (
        "The application reacts differently to TRUE/FALSE injected conditions,\n"
        "allowing data inference (boolean-based blind SQLi).\n"
        "Fix:\n"
        "  1. Use parameterized queries / prepared statements.\n"
        "  2. Return consistent, generic error pages regardless of query outcome.\n"
        "  3. Apply least privilege to the application's DB account."
    ),
    "time": (
        "The backend executes time-delaying SQL functions from user input\n"
        "(time-based blind SQLi).\n"
        "Fix:\n"
        "  1. Use parameterized queries / prepared statements.\n"
        "  2. Block stacked queries if not required.\n"
        "  3. Set DB-side statement timeouts."
    ),
    "union": (
        "UNION SELECT payloads are accepted, allowing row-level data concatenation\n"
        "into responses (union-based SQLi).\n"
        "Fix:\n"
        "  1. Use parameterized queries / prepared statements.\n"
        "  2. Avoid echoing raw query results; map columns explicitly.\n"
        "  3. Restrict DB user to required tables only."
    ),
}

PARAMETERIZED_EXAMPLES = {
    "python": (
        "# Python (sqlite3 / DB-API)\n"
        "cur.execute(\"SELECT * FROM users WHERE name = ? AND pass = ?\", (name, password))"
    ),
    "python-orm": (
        "# Python SQLAlchemy ORM\n"
        "session.query(User).filter(User.name == name, User.pass_ == password).first()"
    ),
    "java": (
        "// Java JDBC\n"
        "PreparedStatement ps = conn.prepareStatement(\n"
        "    \"SELECT * FROM users WHERE name = ? AND pass = ?\");\n"
        "ps.setString(1, name);\n"
        "ps.setString(2, password);"
    ),
    "node": (
        "// Node.js (mysql2 / pg)\n"
        "db.query('SELECT * FROM users WHERE name = ? AND pass = ?', [name, password])"
    ),
    "php": (
        "// PHP PDO\n"
        "$stmt = $pdo->prepare('SELECT * FROM users WHERE name = :n AND pass = :p');\n"
        "$stmt->execute(['n' => $name, 'p' => $password]);"
    ),
}

WAF_RULE_SUGGESTIONS = [
    "Block/flag common SQLi tokens in parameters: ' -- /* */ UNION SELECT SLEEP( WAITFOR ",
    "Enable SQLi ruleset (OWASP CRS 942xxx) in blocking mode after a log-only period.",
    "Rate-limit repeated 40x/500 responses from the same client (probing behaviour).",
]

REFERENCES = [
    "OWASP Top 10 A03:2021 — Injection",
    "OWASP SQL Injection Prevention Cheat Sheet",
    "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
]


def build_remediation(technique: str, dbms_hint: str = "") -> str:
    """Compose a remediation block for a finding."""
    parts = [REMEDIATION_TEMPLATES.get(technique, REMEDIATION_TEMPLATES["error"]), ""]
    parts.append("Parameterized query examples:")
    for lang in ("python", "java", "node", "php"):
        parts.append("")
        parts.append(PARAMETERIZED_EXAMPLES[lang])
    if dbms_hint:
        parts.append("")
        parts.append(f"Detected backend: {dbms_hint} — apply the matching driver API above.")
    parts.append("")
    parts.append("WAF rule suggestions:")
    for rule in WAF_RULE_SUGGESTIONS:
        parts.append(f"  - {rule}")
    parts.append("")
    parts.append("References:")
    for ref in REFERENCES:
        parts.append(f"  - {ref}")
    return "\n".join(parts)
