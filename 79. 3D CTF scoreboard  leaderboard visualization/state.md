# 3D CTF Scoreboard - Project State

## Overview
A real-time 3D CTF (Capture The Flag) scoreboard built with FastAPI and Three.js. Features animated bar race visualization, challenge node graphs, and live solve feeds.

## Architecture
- **Backend**: FastAPI (Python) serving REST API and static files
- **Frontend**: Three.js 3D visualization + vanilla HTML/CSS/JS
- **Data**: JSON files for teams, challenges, and solve events

## Files
```
app.py                      - FastAPI backend with all API endpoints
static/index.html           - Main scoreboard page
static/js/main.js           - Three.js 3D scene + UI logic
static/css/style.css        - Neon gaming theme styling
data/sample_teams.json      - 20 CTF teams
data/sample_challenges.json - 30 challenges across 5 categories
data/sample_solves.json     - 100 solve events
reports/                    - Generated HTML reports
```

## API Endpoints
| Endpoint | Description |
|----------|-------------|
| GET /api/teams | All teams |
| GET /api/teams/{id} | Team details with solves |
| GET /api/challenges | All challenges (filterable) |
| GET /api/solves | Solve events (filterable) |
| GET /api/solves/feed | Recent solves feed |
| GET /api/leaderboard | Ranked leaderboard |
| GET /api/scoreboard/timeline | Score timeline for replay |
| GET /api/stats | Competition statistics |
| GET /api/report | Generate HTML report |

## Features
- 3D animated bar race showing team scores
- Challenge node graph by category
- Live solve feed with timestamps
- Timeline replay controls (play/pause/restart)
- Team detail popup on click
- Sound effects toggle
- Fullscreen mode for projectors
- HTML report generation with rankings and stats

## Run
```bash
cd "79. 3D CTF scoreboard  leaderboard visualization"
pip install fastapi uvicorn
python app.py
```
Server runs on http://localhost:8000
