# Memory: Active Directory Attack Path Visualizer (ADAPV)

## Runtime Memory Footprint

- **Current RSS Memory:** ~40-60 MB
- **Peak Expected RSS:** < 1 GB (per non-functional requirements)
- **Memory Mode:** Normal operation

## Active Memory Objects

| Object Type | Estimated Size | Count | Description |
|---|---|---|---|
| Qt Widgets | ~5-10 MB | ~70 | Main window, tables, views, group boxes, text edits |
| SQLite Connections | ~1-2 MB | 1 | graph.db connection (WAL mode) |
| Graph Data | ~10-50 KB | 1 | Current graph (nodes: ~8, edges: ~10) |
| Query Results | ~1-5 KB | 0-100 | Cypher query results table |
| Path Records | ~500 B - 2 KB | 0-50 | Attack path analysis results |
| Query History | ~1-5 KB | 0-20 | Saved Cypher queries in database |

## Memory Management

- **SQLite WAL Mode:** Write-Ahead Logging for efficient concurrent queries
- **Caching:** Graph node/edge data cached in Qt model (refreshes on new import)
- **State Persistence:** Saved to `~/.adapV/state.json` on query execution or app exit
- **Garbage Collection:** Python Qt auto-management; no memory leaks expected

## Data Flow

1. **Startup:** Initialize directories and SQLite database `graph.db`
2. **User Action:** Configure domain → load sample AD data or import JSON
3. **Graph Build:** Ingest JSON → construct node/edge model → SQLite indexing
4. **Graph Explorer:** Interactive visualization (display area in UI)
5. **Cypher Query:** Enter query → execute against graph store → display results
6. **Path Analysis:** Run path finding algorithms → score paths → list results
7. **Report Generation:** Aggregate paths → format selection → export
8. **State Save:** Persist UI state and query history to `state.json`
9. **Export:** Generate report in selected format (JSON/CSV/HTML/PDF)

## Memory Warnings

- **High Memory Alert:** RSS > 800 MB → suggest closing and restarting
- **Leak Detection:** Monitor SQLite WAL file size growth during large graph operations
- **Optimization:** NetworkX for smaller domains (< 50k nodes); SQLite for portability
- **Graph Size Limit:** Recommended < 100k nodes for real-time interaction

## Current Session Memory Summary

- **Total Active:** ~50 MB
- **Trend:** Stable (no upward creep detected after graph build)
- **Last GC:** At startup and after graph import
- **Memory Status:** OK

## Graph Performance

- **Query Execution (shortest path):** < 2 seconds for < 10k nodes
- **Graph Render (10k nodes):** 30 fps (target)
- **Path Finding:** BFS/Dijkstra algorithm; parallelized across queries
- **Node/Edge Indexing:** SQLite indexes on source/target/kind for fast queries