# State: Metasploit Module Builder Workbench (MMBW)

## Current Session State

- **Application Version:** 1.0
- **Last Updated:** {timestamp}
- **Active Module:** None
- **Lab Target:** None configured
- **Metasploit RPC:** Disconnected

## Session Variables

| Variable | Value | Description |
|---|---|---|
| current_module_id | None | Currently edited/loaded module identifier |
| lab_target_url | None | Vulnerable service URL/IP |
| lab_target_port | 4555 | Target port number |
| service_type | HTTP | Service type (HTTP/TCP/FTP/SMB/Custom) |
| rpc_password | None | msfrpcd password (OS keychain) |
| module_loaded | false | Whether a module is loaded in the editor |
| module_deployed | false | Whether module is deployed to Metasploit |
| execution_status | draft | Current status: draft/deployed/executed/session_created |
| session_created | false | Whether a session was created during execution |
| report_generated | false | Whether a report has been generated for current session |
| export_format | JSON | Last exported report format |

## Database Status

- **module_data.db:** Initialized at {timestamp}
- **Modules:** 0 (new modules created during workflow)
- **Validation Checks:** 0 (recorded per module)
- **Execution Logs:** 0 (entries per module)

## UI State

- **Current View:** lab target config (wizard step 1 of 9)
- **Wizard Progress:** 0% (starting at lab target configuration)
- **Module Editor:** Empty (ready for scaffold or manual entry)
- **Mixin Reference:** Available mixins listed in table
- **Payload Selector:** Compatible payloads shown per platform
- **Execution Console:** Disconnected (RPC not connected)
- **Session Inspector:** No sessions recorded
- **Validation Dashboard:** Ready (awaiting start)

## Workflow State

- **Current Step:** 1 (Lab Target Config)
- **Steps Completed:** 0
- **Estimated Steps Remaining:** 9 (scaffold → author → payload → execute → validate → report)
- **Step Gates:** Each step has validation before proceeding

## Security Considerations

- **Lab-Only Scope:** Tool operates against configured lab targets only; no scanning/unauthorized targeting
- **RPC Credentials:** Stored in OS keychain; never logged; transmitted over secure RPC only
- **Module Deployment:** Deployed only to `$HOME/.msf4/modules/`; user-local, no elevated privileges
- **Payload Delivery:** Restricted to localhost or lab target; no external C2
- **Session Data Sensitivity:** Session transcripts may contain sensitive data; local-only storage
- **Metasploit Dependency:** Tool is lab-scoped and does not automate broad exploitation

## Report State

- **Report Formats Available:** JSON, CSV, HTML, PDF
- **Last Export:** Never
- **Export Path:** N/A
- **Report Sections:** Module source, execution log, validation results, session evidence, development walkthrough
- **Export Includes:** Ruby module source code, RPC output transcripts, validation pass/fail summary

## Consent Management

- **Not applicable for lab-scoped module development**
- **Authorization:** Explicit acknowledgment required before lab target configuration
- **Deployment Scope:** Module deployed only to user-local Metasploit directories