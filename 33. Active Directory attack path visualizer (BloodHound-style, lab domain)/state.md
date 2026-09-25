# State: Active Directory Attack Path Visualizer (ADAPV)

## Current Session State

- **Application Version:** 1.0
- **Last Updated:** {timestamp}
- **Active Domain:** lab.local
- **Collection Mode:** Pre-collected JSON import
- **Graph Built:** Yes

## Session Variables

| Variable | Value | Description |
|---|---|---|
| current_domain | lab.local | Currently configured domain |
| collection_status | imported | Data collection status (none, rusthound, sharp hound, imported) |
| graph_nodes | 8 | Number of nodes in graph |
| graph_edges | 10 | Number of edges in graph |
| paths_analyzed | false | Whether attack paths have been analyzed |
| report_generated | false | Whether a report has been generated for current session |
| export_format | JSON | Last exported report format |
| cypher_query | "" | Last Cypher query entered |

## Database Status

- **graph.db:** Initialized at {timestamp}
- **Nodes:** 8 (Users, Groups, Computers, OUs, GPOs)
- **Edges:** 10 (MemberOf, HasSession, GPOLink)
- **Saved Queries:** 0

## UI State

- **Current View:** domain config (main dashboard)
- **Last Selected Row:** -1 (none)
- **Allowlist Status:** Enabled (refuses unauthorized domains)
- **Graph Layout:** Force-directed (default)

## Collection Status

- **RustHound (Linux):** Not executed
- **SharpHound (Windows):** Not executed
- **JSON Import:** Sample data loaded at startup
- **Domain Allowlist:** Active (only lab.local permitted)

## Report State

- **Report Formats Available:** JSON, CSV, HTML, PDF
- **Last Export:** Never
- **Export Path:** N/A
- **Report Sections:** Attack paths, graph export, remediation, collection metadata

## Security Considerations

- **Domain Allowlist:** Mandatory; tool refuses to collect from unauthorized domains
- **Credential Handling:** LDAP credentials in OS keychain; never logged
- **Lab-only Scope:** Documented; production AD enumeration blocked
- **Data Sensitivity:** Graph data reveals privilege relationships; local-only storage
- **Remediation Safety:** Guidance only; tool does not modify AD

## Consent Management

- **Not applicable for lab-domain scoped tool**
- **Authorization:** Explicit acknowledgment required before domain configuration
- **Data Export:** Anonymized by default; no PII in dashboards unless explicitly enabled