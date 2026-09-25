# State: Privilege Escalation Checklist Automation Tool (PECAT)

## Current Session State

- **Application Version:** 1.0
- **Last Updated:** {timestamp}
- **Active Enumeration:** None
- **Target Host:** localhost
- **Target OS:** Linux
- **Consent Status:** Not applicable (local enumeration only)

## Session Variables

| Variable | Value | Description |
|---|---|---|
| current_enum_id | None | Currently running/last enumeration identifier |
| target_os | Linux | Selected target operating system |
| checks_selected | [] | List of selected check categories |
| findings_loaded | false | Whether findings have been loaded from enumeration |
| report_generated | false | Whether a report has been generated for current session |
| export_format | JSON | Last exported report format |

## Database Status

- **enum_data.db:** Initialized at {timestamp}
- **Records:** Enumerations: 0, Findings: 0, Checklists: 0

## UI State

- **Current View:** local enumeration (main dashboard)
- **Last Selected Row:** -1 (none)
- **Filter Applied:** None
- **Sort Order:** Severity (critical → info)

## Enumeration State

- **Enumeration Running:** No
- **Categories Enabled:** SUID/SGID, Sudo, Cron, Services, Credentials
- **Parallel Workers:** 5 (default)
- **Remote Connection Status:** Disconnected

## Report State

- **Report Formats Available:** JSON, CSV, HTML, PDF
- **Last Export:** Never
- **Export Path:** N/A

## Security Considerations

- **Authorization Required:** Explicit acknowledgment needed before enumeration
- **Read-Only Checks:** All enumeration commands are read-only; no system modification
- **Evidence Sensitivity:** Evidence may contain credentials; local-only storage
- **Remote Credentials:** Stored in OS keychain; never logged or transmitted insecurely

## Consent Management

- **Not applicable for local enumeration**
- **Remote targets:** Consent collected prior to enumeration
- **Non-consented targets:** Excluded from enumeration results