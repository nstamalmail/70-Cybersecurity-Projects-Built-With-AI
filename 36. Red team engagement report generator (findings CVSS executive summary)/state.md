# State: Red Team Engagement Report Generator (RTERG)

## Current Session State

- **Application Version:** 1.0
- **Last Updated:** {timestamp}
- **Active Engagement:** None
- **Client Name:** None
- **Findings Count:** 0

## Session Variables

| Variable | Value | Description |
|---|---|---|
| current_engagement_id | None | Currently selected/edited engagement identifier |
| client_name | None | Client organization name |
| engagement_type | red_team | Engagement type (red_team, pentest, adversary_sim) |
| findings_loaded | false | Whether findings have been loaded for current engagement |
| attack_chains_built | false | Whether attack chains have been assembled |
| executive_summary_generated | false | Whether executive summary has been generated |
| report_composed | false | Whether report has been composed/exported |
| export_format | DOCX | Last exported report format |
| current_template | Executive Brief | Current report template selection |

## Database Status

- **engagement_data.db:** Initialized at {timestamp}
- **Engagements:** 0 (new engagements created during workflow)
- **Findings:** 0 (recorded per engagement)
- **Attack Chains:** 0 (recorded per engagement)

## UI State

- **Current View:** engagement manager (main dashboard)
- **Last Selected Row:** -1 (none)
- **Findings Filter:** None
- **Severity Color Coding:** Critical (red), High (orange), Medium (yellow), Low (blue), Info (gray)
- **Template Selection:** Executive Brief (default)

## Workflow State

- **Current Step:** 1 (Engagement Creation)
- **Steps Completed:** 0
- **Estimated Steps Remaining:** 10 (engagement → findings → CVSS → narrative → executive → remediation → roadmap → compose → export)
- **Step Gates:** Each step has validation before proceeding

## Security Considerations

- **Client Data Sensitivity:** Engagement data may contain client IPs, credentials, evidence; local-only storage; optional encryption at rest
- **Evidence Leakage:** Evidence may contain PII or credentials; redaction profile for external sharing
- **LLM Assistance:** Disabled by default; when enabled, only anonymized summaries sent; client approval required
- **Report Integrity:** Report hash recorded; optional digital signature
- **Access Control:** Optional case-level password; audit log of edits
- **Legal Sensitivity:** Rules of engagement captured; disclaimers included in report

## Report State

- **Report Formats Available:** DOCX, PDF, HTML, Markdown, JSON
- **Last Export:** Never
- **Export Path:** N/A
- **Report Sections:** Executive summary, findings, attack narrative, remediation roadmap, appendices
- **Export Includes:** CVSS scores, vector strings, affected assets, remediation actions, timeline

## Consent Management

- **Not applicable for report generation tool**
- **Authorization:** Rules of engagement captured per engagement
- **Data Export:** Client approval required for external sharing; anonymized by default