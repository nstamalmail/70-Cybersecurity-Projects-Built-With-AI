# Memory: Red Team Engagement Report Generator (RTERG)

## Runtime Memory Footprint

- **Current RSS Memory:** ~40-65 MB
- **Peak Expected RSS:** < 500 MB (per non-functional requirements)
- **Memory Mode:** Normal operation

## Active Memory Objects

| Object Type | Estimated Size | Count | Description |
|---|---|---|---|
| Qt Widgets | ~5-10 MB | ~75 | Main window, tables, views, text editors, combo boxes, tables, group boxes |
| SQLite Connections | ~1-2 MB | 1 | engagement_data.db connection (WAL mode) |
| Engagement Data | ~10-50 KB | 0-1 | Current engagement metadata and findings |
| Finding Records | ~1-5 KB | 0-200 | Individual finding records with CVSS scores and details |
| Attack Chain Records | ~500 B - 2 KB | 0-10 | Attack chain step records with objectives and notes |
| Executive Summary | ~1-5 KB | 0-1 | Generated summary text |
| Evidence Attachments | ~10 KB - 1 MB | 0-50 | Screenshots, command output snippets, file references |

## Memory Management

- **SQLite WAL Mode:** Write-Ahead Logging for efficient concurrent reads/writes
- **Caching:** Engagement/findings data cached in Qt model (refreshes on new engagement load)
- **State Persistence:** Saved to `~/.rterg/state.json` on report export or app exit
- **Garbage Collection:** Python Qt auto-management; no memory leaks expected

## Data Flow

1. **Startup:** Initialize directories and SQLite database `engagement_data.db`
2. **User Action:** Create/new engagement → add findings with CVSS scoring → build attack chains
3. **CVSS Scoring:** Select metrics (3.1 or 4.0) → compute base score → update severity
4. **Narrative Assembly:** Link findings into chronological attack chain steps
5. **Executive Summary:** Aggregate findings into business-impact themes → generate strategic recommendations
6. **Remediation:** Per-finding short-term mitigation and long-term fix
7. **Roadmap:** Prioritize remediation into tiers (immediate / 30-day / 90-day / strategic)
8. **Report Composition:** Select template (DOCX/PDF/HTML/MD/JSON) → order sections → compose
9. **Export:** Generate report in selected format
10. **State Save:** Persist UI state and findings/chain data to `state.json`
11. **Export:** Generate report in selected format

## Memory Warnings

- **High Memory Alert:** RSS > 400 MB → suggest closing and restarting
- **Leak Detection:** Monitor SQLite WAL file size growth during large engagements (100+ findings)
- **Optimization:** CVSS computation is instant (50 ms); chain analysis is fast (QThreadPool parallel)
- **Finding Capacity:** Recommended < 500 findings per engagement for optimal performance

## Current Session Memory Summary

- **Total Active:** ~50 MB
- **Trend:** Stable (no upward creep detected after report composition)
- **Last GC:** At startup and after report export
- **Memory Status:** OK

## Performance Metrics

- **CVSS Computation:** < 50 ms (per finding)
- **Report Rendering (100 findings):** < 30 seconds
- **PDF Export:** < 60 seconds
- **Finding Creation:** < 200 ms
- **Attack Chain Assembly:** < 5 seconds
- **Executive Summary Generation:** < 10 seconds (optional LLM assistance adds time)
- **Roadmap Prioritization:** < 5 seconds