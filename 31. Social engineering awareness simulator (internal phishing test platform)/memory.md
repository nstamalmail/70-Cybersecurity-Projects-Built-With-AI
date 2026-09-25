# Memory: Social Engineering Awareness Simulator (SEAS)

## Runtime Memory Footprint

- **Current RSS Memory:** ~25-45 MB
- **Peak Expected RSS:** < 300 MB (per non-functional requirements)
- **Memory Mode:** Normal operation

## Active Memory Objects

| Object Type | Estimated Size | Count | Description |
|---|---|---|---|
| Qt Widgets | ~5-10 MB | ~50 | Main window, tables, views, buttons |
| SQLite Connections | ~1-2 MB | 1 | campaigns.db connection (WAL mode) |
| Campaign Data | ~50-200 KB | 1-10 | Active campaign metadata and targets |
| Event Records | ~1-5 KB | 0-1000 | Campaign events (sent, opened, clicked, etc.) |
| Template Data | ~10-50 KB | 1-20 | Email template definitions |
| Export Buffer | ~10-100 KB | 0-1 | Current report being generated |
| Sample Data | ~50-100 KB | 1 | Sample campaign JSON loaded at startup |

## Memory Management

- **SQLite WAL Mode:** Write-Ahead Logging for efficient batch inserts
- **Caching:** Campaign table data cached in Qt model (auto-released on view switch)
- **State Persistence:** Saved to `~/.seas/state.json` on report generation or app exit
- **Garbage Collection:** Python Qt auto-management; no memory leaks expected

## Data Flow

1. **Startup:** Load sample campaign data from `data/sample_campaign.json`
2. **DB Initialize:** Create `campaigns.db` in `~/.seas/` if not exists
3. **User Action:** Select campaign → load targets from DB
4. **Metrics Update:** Real-time calculation from campaign_events table
5. **Report Generation:** Aggregate events → format selection → export
6. **State Save:** Persist UI state and metrics to `state.json`
7. **Export:** Generate report in selected format (JSON/CSV/HTML/PDF)

## Memory Warnings

- **High Memory Alert:** RSS > 250 MB → suggest closing and restarting
- **Leak Detection:** Monitor SQLite WAL file size growth
- **Optimization:** Batch event inserts (default: 100 records per transaction)

## Current Session Memory Summary

- **Total Active:** ~30 MB
- **Trend:** Stable (no upward creep detected)
- **Last GC:** At startup
- **Memory Status:** OK