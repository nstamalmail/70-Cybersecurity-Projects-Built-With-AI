# Memory: Metasploit Module Builder Workbench (MMBW)

## Runtime Memory Footprint

- **Current RSS Memory:** ~30-50 MB
- **Peak Expected RSS:** < 500 MB (per non-functional requirements)
- **Memory Mode:** Normal operation

## Active Memory Objects

| Object Type | Estimated Size | Count | Description |
|---|---|---|---|
| Qt Widgets | ~5-10 MB | ~65 | Main window, tables, views, text editors, combo boxes, tables |
| SQLite Connections | ~1-2 MB | 1 | module_data.db connection (WAL mode) |
| Module Data | ~10-50 KB | 0-1 | Current module source code and metadata |
| Validation Results | ~1-5 KB | 0-10 | Validation check records (syntax, load, execution) |
| Execution Logs | ~1-5 KB | 0-20 | RPC communication logs, output snippets, session data |
| Payload Matrix | ~5-15 KB | 1 | Compatible payloads table per platform |
| Mixin Registry | ~5-10 KB | 1 | Documented mixins with methods and usage examples |

## Memory Management

- **SQLite WAL Mode:** Write-Ahead Logging for efficient concurrent session persistence
- **Caching:** Module editor content cached in Qt text model (auto-save on view switch)
- **State Persistence:** Saved to `~/.mmbw/state.json` on report generation or app exit
- **Garbage Collection:** Python Qt auto-management; no memory leaks expected

## Data Flow

1. **Startup:** Initialize directories and SQLite database `module_data.db`
2. **User Action:** Configure lab target → scaffold module → author in editor → select payload
3. **Module Author:** Edit Ruby source; use mixin reference for guidance
4. **Payload Selection:** Browse compatible payloads; select target payload
5. **Deploy Module:** Copy to `$HOME/.msf4/modules/exploits/<category>/`; trigger `reload_all`
6. **Validate:** Run syntax check (ruby -c), module load check, `check` method
7. **Execute:** Configure options (RHOSTS, RPORT, LHOST, LPORT); run via RPC
8. **Capture Session:** If session created, interact and capture transcript
9. **Export Report:** Aggregate all data → format selection → export (JSON/CSV/HTML/PDF)
10. **State Save:** Persist UI state and session data to `state.json`
11. **Export:** Generate report in selected format

## Memory Warnings

- **High Memory Alert:** RSS > 400 MB → suggest closing and restarting
- **Leak Detection:** Monitor SQLite WAL file size growth during multi-module workflows
- **Optimization:** Module scaffold generation is instant; validation (ruby -c) is fast (< 50 ms)
- **Session Limit:** Recommended < 3 concurrent modules for optimal performance

## Current Session Memory Summary

- **Total Active:** ~40 MB
- **Trend:** Stable (no upward creep detected after module execution)
- **Last GC:** At startup and after report generation
- **Memory Status:** OK

## Performance Metrics

- **RPC Connection:** < 2 seconds to establish msfrpcd connection
- **Module Deploy + Reload:** < 10 seconds
- **Syntax Validation (ruby -c):** < 50 milliseconds
- **Validation Checks:** Instant (inline computation)
- **Report Generation:** < 5 seconds