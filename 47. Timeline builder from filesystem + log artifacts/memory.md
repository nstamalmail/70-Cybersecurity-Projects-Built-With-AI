# Timeline Builder - Memory

## Architecture
- Single-file tkinter application
- Event-driven architecture with callback-based filtering
- Threaded analysis for long operations

## Design Decisions
- **Multi-tab Layout**: Timeline, Anomalies, Sources, Statistics, Report
- **Search + Filter**: Combined text search and dropdown type filter for timeline
- **Anomaly Tagging**: Events flagged with anomaly="YES" for visual highlighting
- **MITRE Mapping**: Anomalies mapped to ATT&CK techniques for forensic relevance

## Data Model

### Event Dictionary
```python
{
    "timestamp": str,  # ISO format "YYYY-MM-DD HH:MM:SS.mmm"
    "source": str,     # Log source filename
    "event_type": str, # "File System", "Registry", "Process", "Network", "Login", "Application"
    "description": str,
    "artifact": str,   # File path, registry key, IP address, etc.
    "anomaly": str     # "" or "YES"
}
```

### Anomaly Dictionary
```python
{
    "type": str,       # "Timestomping", "Brute Force", "Lateral Movement", etc.
    "severity": str,   # "HIGH", "MEDIUM", "LOW"
    "timestamp": str,
    "description": str,
    "evidence": str,
    "mitre": str       # MITRE ATT&CK technique ID
}
```

### Log Source Dictionary
```python
{
    "name": str,
    "path": str,
    "type": str,       # "CSV Log", "Text Log", "Event Log"
    "size": int,
    "hash": str        # MD5 hash
}
```

## Anomaly Detection Categories
- Timestomping (T1070.006)
- Suspicious Process (T1059.001)
- Brute Force (T1110)
- Lateral Movement (T1021.002)
- Data Exfiltration (T1048)
- Privilege Escalation (T1136.001)
- Persistence (T1547.001)
- Defense Evasion (T1562.001)
- Reconnaissance (T1082)

## Statistics Calculated
- Event counts by type
- Anomaly counts by severity
- Time range coverage
- Events per source breakdown
