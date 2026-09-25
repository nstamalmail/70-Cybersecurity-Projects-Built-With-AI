# State: Social Engineering Awareness Simulator (SEAS)

## Current Session State

- **Application Version:** 1.0
- **Last Updated:** {timestamp}
- **Active Campaign:** None
- **Target Count:** 0
- **Consent Status:** No targets loaded

## Session Variables

| Variable | Value | Description |
|---|---|---|
| current_campaign_id | None | Currently selected campaign identifier |
| campaign_status | None | Status of current campaign (planned, active, completed) |
| selected_targets | [] | List of selected target participant IDs |
| report_generated | false | Whether a report has been generated for current session |
| export_format | JSON | Last exported report format |

## Database Status

- **campaigns.db:** Initialized at {timestamp}
- **Records:** Campaigns: 0, Targets: 0, Events: 0, Training Modules: 0

## UI State

- **Current View:** campaigns (main dashboard)
- **Last Selected Row:** -1 (none)
- **Filter Applied:** None
- **Sort Order:** Created descending (newest first)

## Consent Management

- **Consent Collection Status:** Pending
- **Consented Targets:** 0
- **Non-Consented Targets:** 0
- **Excluded from Campaigns:** Yes (by default for pending consent)

## Report State

- **Report Formats Available:** JSON, CSV, HTML, PDF
- **Last Export:** Never
- **Export Path:** N/A

## Security State

- **Psychological Safety Mode:** Enforced (no panic-inducing lures)
- **PII Exposure Protection:** Active (anonymized IDs in dashboards)
- **Credential Storage:** Not applicable (no credential persistence)