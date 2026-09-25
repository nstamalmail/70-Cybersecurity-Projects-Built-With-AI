# 3D Attack Path Visualizer - Project State

## Overview
A BloodHound-style 3D network attack path visualizer built with FastAPI and Three.js. Displays Active Directory graph data with force-directed layout, node/edge filtering, attack path highlighting, and risk scoring.

## Architecture
- **Backend**: FastAPI (Python) serving REST API and static files
- **Frontend**: Three.js 3D force-directed graph + vanilla HTML/CSS/JS
- **Data**: JSON files for graph nodes/edges and pre-computed attack paths

## Files
```
app.py                      - FastAPI backend with graph API, pathfinding, report generation
static/index.html           - Visualizer page with search, filters, panels
static/js/main.js           - Three.js 3D scene, force layout, interaction logic
static/css/style.css        - Dark security tool theme
data/sample_graph.json      - 50 AD nodes (users, groups, computers, domains)
data/sample_paths.json      - 5 pre-computed attack paths with risk scores
reports/                    - Generated HTML reports
```

## API Endpoints
| Endpoint | Description |
|----------|-------------|
| GET /api/graph | Full graph (nodes + edges) |
| GET /api/nodes | Nodes (filterable by type) |
| GET /api/nodes/{id} | Node with connected edges/nodes |
| GET /api/edges | Edges (filterable by type) |
| GET /api/paths | Pre-computed attack paths |
| GET /api/paths/{id} | Path with node details |
| GET /api/search?q= | Search nodes by name/IP |
| GET /api/pathfind?source=&target= | BFS shortest path |
| GET /api/stats | Graph statistics |
| GET /api/report | Generate HTML report |

## Node Types
- User (blue sphere) - Active Directory user accounts
- Group (red cube) - AD security groups
- Computer (green box) - Domain-joined machines
- Domain (yellow star) - Domain controllers

## Edge Types
AdminTo (red), GenericAll (orange), MemberOf (blue), HasSession (green), DCSync (magenta), WriteDacl (yellow)

## Features
- 3D force-directed graph layout
- Click nodes to see details and connected edges
- Attack path visualization with animated highlighting
- Search bar for finding nodes by name/IP
- Filter by node type
- Pre-computed attack paths with risk scores
- Dynamic pathfinding between any two nodes
- Minimap for navigation
- HTML report generation with risk analysis

## Run
```bash
cd "80. Interactive 3D network attack-path visualizer (web-based BloodHound viewer)"
pip install fastapi uvicorn
python app.py
```
Server runs on http://localhost:8001
