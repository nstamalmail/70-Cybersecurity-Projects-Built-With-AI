# Memory: Privilege Escalation Checklist Automation Tool (PECAT)

## Runtime Memory Footprint

- **Current RSS Memory:** ~30-50 MB
- **Peak Expected RSS:** < 300 MB (per non-functional requirements)
- **Memory Mode:** Normal operation

## Active Memory Objects

| Object Type | Estimated Size | Count | Description |
|---|---|---|---|
| Qt Widgets | ~5-10 MB | ~60 | Main window, tables, views, buttons, group boxes |
| SQLite Connections | ~1-2 MB | 1 | enum_data.db connection (WAL mode) |
| Enumeration Data | ~10-100 KB | 0-1 | Current enumeration session data |
| Findings Records | ~1-5 KB | 0-500 | Collected privilege escalation findings |
| Checklist Definitions | ~10-50 KB | 1-20 | Linux/Windows checklist configurations |
| Evidence Strings | ~500 B - 5 KB | 0-20 | Raw command output snippets |
| Report Buffer | ~10-100 KB | 0-1 | Current report being generated/exported |

## Memory Management

- **SQLite WAL Mode:** Write-Ahead Logging for efficient concurrent reads
- **Caching:** Findings table data cached in Qt model (refreshes on new enumeration)
- **State Persistence:** Saved to `~/.pecAT/state.json` on report export or app exit
- **Garbage Collection:** Python Qt auto-management; no memory leaks expected

## Data Flow

1. **Startup:** Initialize directories and SQLite database `enum_data.db`
2. **User Action:** Select target OS and check categories → click "Run Local Enumeration"
3. **Enumeration:** Execute shell commands (find, sudo -l, crontab, etc.) in parallel
4. **Findings Storage:** Parse command output → store in SQLite `findings` table
5. **Dashboard Update:** Refresh findings table with severity-sorted results
6. **Report Generation:** Aggregate findings → format selection → export
7. **State Save:** Persist UI state and findings count to `state.json`
8. **Export:** Generate report in selected format (JSON/CSV/HTML/PDF)

## Memory Warnings

- **High Memory Alert:** RSS > 250 MB → suggest closing and restarting
- **Leak Detection:** Monitor SQLite WAL file size growth during long sessions
- **Optimization:** Parallel checks across categories (default: 5 workers); serialized remote execution

## Current Session Memory Summary

- **Total Active:** ~35 MB
- **Trend:** Stable (no upward creep detected after enumeration)
- **Last GC:** At startup and after enumeration completion
- **Memory Status:** OK

## Enumeration Performance

- **Local Checks (Linux):** < 60 seconds for all categories
- **Local Checks (Windows):** < 90 seconds for all categories
- **Remote Check Latency:** < 5 seconds per check (SSH/WinRM)
- **Findings per Run:** Typically 3-8 findings depending on target configuration