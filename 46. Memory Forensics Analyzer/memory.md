# Memory Forensics Analyzer - Memory

## Architecture
- Single-file tkinter application
- MVC-inspired pattern: UI components in `_build_*_tab()` methods, data in instance variables, logic in `_detect_*` methods
- Threaded analysis to prevent UI blocking

## Design Decisions
- **Dark Theme**: Used consistent dark palette (#1e1e2e base) for forensic tool aesthetic
- **Tab Organization**: 7 tabs separating Processes, Network, Modules, Anomalies, YARA, Timeline, Report
- **Treeview Widgets**: Primary data display throughout for consistency and scrolling
- **Threat Score**: 0-100 scale calculated from anomaly count and severity weights

## Data Model

### Process Dictionary
```python
{
    "pid": int,
    "name": str,
    "ppid": int,
    "path": str,
    "cmdline": str,
    "memory_kb": int,
    "threads": int,
    "handles": int,
    "status": str,  # "Active", "Suspended", "SUSPICIOUS"
    "suspicious": bool,
    "start_time": datetime
}
```

### Network Connection Dictionary
```python
{
    "proto": str,  # "TCP", "UDP"
    "local_addr": str,
    "local_port": int,
    "remote_addr": str,
    "remote_port": int,
    "pid": int,
    "state": str,
    "process": str
}
```

### Module Dictionary
```python
{
    "name": str,
    "path": str,
    "base_addr": str,
    "size": int,
    "entropy": float,
    "signed": bool,
    "anomaly": str
}
```

### Anomaly Dictionary
```python
{
    "type": str,
    "severity": str,  # "HIGH", "MEDIUM", "LOW"
    "process": str,
    "description": str,
    "evidence": str
}
```

## Anomaly Detection Logic
- Identifies suspicious process names (unknown_xyz, updater, helper)
- Detects LOLBins (mshta.exe, rundll32.exe from temp)
- Flags encoded PowerShell commands
- Detects reconnaissance commands (whoami, ipconfig)
- Module entropy analysis (high entropy = packed/encrypted)
- Unsigned module detection

## YARA Rule Simulation
- 8 built-in rules covering malware patterns, suspicious activity, TTPs
- Pattern matching against command lines and process names
- Severity classification per rule
