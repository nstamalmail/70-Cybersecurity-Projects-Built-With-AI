# Windows Event Log Correlation Tool - State

## Current State
- **Version**: 1.0
- **Status**: Complete
- **Last Updated**: 2026-09-17

## Features Implemented
- Windows Event Log file loading (EVTX/XML format)
- Simulated event generation with 39+ event types
- Event filtering by level and full-text search
- Event correlation engine with pattern detection
- Suspicious activity detection (7 attack patterns)
- MITRE ATT&CK technique mapping
- Tactic/technique breakdown display
- Full report generation with JSON/CSV/TXT/HTML export
- Dark-themed professional UI with 4 tabs

## Event Types Supported
- 4624/4625: Logon success/failure
- 4672: Special privileges assigned
- 4720/4726: Account create/delete
- 4728/4732/4756: Group membership changes
- 4771: Kerberos pre-auth failure
- 4104: PowerShell script block
- 4688: Process creation
- 4698/4699: Scheduled task create/delete
- 7045: Service installation
- 1102: Log clearing
- And more...

## Detected Attack Patterns
- Brute Force Attack (T1110)
- Privilege Escalation (T1078.003)
- Lateral Movement via SMB (T1021.002)
- Persistence - Scheduled Task (T1053.005)
- Defense Evasion - Log Clearing (T1070.001)
- Kerberoasting (T1558.003)
- Execution - PowerShell (T1059.001)

## Known Limitations
- Uses simulated data (does not parse actual EVTX files)
- No evtx library dependency
- Correlation is sequential pattern matching only
- No temporal window analysis
- MITRE mapping is static, not dynamic

## Test Coverage
- Manual UI testing: All tabs functional
- Export formats verified: JSON, CSV, TXT, HTML
- Correlation engine verified
- MITRE mapping verified

## Dependencies
- Python 3.8+
- tkinter (stdlib)
- hashlib (stdlib)
- No external packages required
