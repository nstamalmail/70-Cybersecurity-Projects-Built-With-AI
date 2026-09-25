# SOC Dashboard - 3D Network Topology Visualization - System State

## Overview
A real-time Security Operations Center dashboard with Three.js 3D network topology visualization, Chart.js metrics, alert management, and incident tracking. Powered by a FastAPI backend.

## Current State
- **Status**: Complete
- **Version**: 1.0.0
- **Last Updated**: 2025-08-20

## Architecture
- **Backend**: Python FastAPI (app.py)
- **Frontend**: Three.js r128 + Chart.js 4.4 + vanilla JS
- **Data**: JSON file-based storage (50 alerts, 30 network nodes, metrics)
- **Reports**: HTML security report generation with file download

## File Structure
```
74. Real-time SOC dashboard.../
├── app.py                        # FastAPI backend
├── static/
│   ├── index.html                # Main dashboard page
│   ├── css/style.css             # SOC dark theme
│   └── js/main.js                # 3D topology + charts + UI
├── data/
│   ├── sample_alerts.json        # 50 security alerts
│   ├── sample_network.json       # 30 network nodes + edges
│   └── sample_metrics.json       # CPU, memory, traffic, incidents
├── reports/                      # Generated report storage
├── state.md                      # This file
└── memory.md                     # Learned patterns
```

## API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Serve dashboard HTML |
| GET | `/api/alerts` | Get alerts (filterable by severity/status/category/search) |
| GET | `/api/alerts/{id}` | Get single alert |
| PUT | `/api/alerts/{id}` | Update alert status/severity |
| GET | `/api/network` | Get full network topology |
| GET | `/api/network/{id}` | Get single node |
| GET | `/api/metrics` | Get all metrics |
| GET | `/api/report/security` | Generate & download HTML security report |

## Dashboard Sections
1. **Overview**: Stats cards, CPU/memory/network charts, category doughnut, recent critical alerts
2. **3D Topology**: Three.js scene with 30 nodes (firewalls, routers, servers, workstations), animated edges, tooltips, click-to-inspect
3. **Alerts**: Filterable table with severity/status/category/search
4. **Incidents**: Timeline bar chart, active incidents list with severity sorting

## Network Topology
- 30 nodes across 5 zones: DMZ, DC-Core, DC-Sec, DC-App, DC-Data
- Node types: 3 firewalls, 2 routers, 15 servers, 10 workstations
- Status colors: green (healthy), yellow (warning), red (critical), grey (offline)
- 37 edges representing network connections

## Dependencies
- FastAPI, Uvicorn, Pydantic (backend)
- Three.js r128 via CDN (3D visualization)
- Chart.js 4.4 via CDN (metrics charts)
