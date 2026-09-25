# Windows Event Log Correlation Tool - Memory

## Architecture
- Single-file tkinter application
- Event-driven correlation engine
- Pattern matching for suspicious activity detection

## Design Decisions
- **Event Templates**: 39+ predefined event types with MITRE mappings
- **Correlation Engine**: Sequential pattern matching across event ID sequences
- **MITRE Mapping**: Static mapping from event IDs to ATT&CK techniques
- **Severity Levels**: Critical, High, Medium, Low, Information
- **Filtering**: Real-time search and level-based filtering

## Data Model

### Event Dictionary
```python
{
    "time_created": str,  # "YYYY-MM-DD HH:MM:SS"
    "event_id": int,
    "level": str,         # "Critical", "Error", "Warning", "Information"
    "task": str,
    "provider": str,
    "computer": str,
    "description": str,
    "user": str,
    "mitre": str          # MITRE ATT&CK technique ID
}
```

### Correlation Dictionary
```python
{
    "name": str,          # Pattern name
    "severity": str,      # "CRITICAL", "HIGH", "MEDIUM"
    "description": str,
    "events": str,        # Event ID sequence "4672 -> 4720 -> 4728"
    "indicators": str,    # Human-readable indicators
    "mitre": str          # MITRE technique ID
}
```

## Correlation Patterns

### Brute Force Attack
- Pattern: 4771 -> 4771 -> 4771 -> 4625 -> 4624
- MITRE: T1110
- Description: Multiple failed logon attempts followed by success

### Privilege Escalation
- Pattern: 4672 -> 4720 -> 4728
- MITRE: T1078.003
- Description: Special privileges followed by account/group changes

### Lateral Movement via SMB
- Pattern: 5140 -> 4688
- MITRE: T1021.002
- Description: Network share access followed by process creation

### Defense Evasion - Log Clearing
- Pattern: 1102
- MITRE: T1070.001
- Description: Audit log cleared

### Kerberoasting
- Pattern: Multiple 4771 events
- MITRE: T1558.003
- Description: Excessive Kerberos pre-auth failures

## MITRE ATT&CK Tactics Covered
- Initial Access (T1078)
- Execution (T1059, T1053.005)
- Persistence (T1078.003, T1136.001, T1543.003, T1053.005)
- Privilege Escalation (T1078.003)
- Defense Evasion (T1070.001, T1562.001, T1134.005)
- Credential Access (T1110, T1558.003)
- Lateral Movement (T1021.002, T1021.001)
- Discovery (T1135, T1082)
- Collection (T1005)
- Impact (T1531)
