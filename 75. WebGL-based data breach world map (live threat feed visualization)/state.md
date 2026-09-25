# State: Data Breach World Map

## Project Status: ✅ Complete

## Architecture

### Backend (FastAPI)
- **app.py**: Main FastAPI application with REST API endpoints
- **Port**: 8003 (default, auto-falls back to the next free port 8004–8052 if busy)
- **API Endpoints**:
  - `GET /api/breaches` - List breaches with optional filters (severity, region, date range)
  - `GET /api/breaches/{id}` - Get specific breach details
  - `GET /api/threats` - List threat indicators with filters
  - `GET /api/stats` - Get aggregate statistics
  - `GET /api/geographic_data` - Get geographic coordinates for visualization
  - `POST /api/reports/generate` - Generate HTML threat intelligence report

### Frontend (Three.js)
- **index.html**: Main page with 3D globe, sidebar, and panels
- **main.js**: Three.js scene, globe rendering, markers, arcs, interactions
- **style.css**: Dark cybersecurity theme with responsive design

### Data Structure
- **sample_breaches.json**: 30 data breach events with coordinates, severity, records
- **sample_threats.json**: 20 live threat indicators with source/target locations

## Current State

### Features Implemented
- ✅ 3D rotating Earth globe with grid overlay
- ✅ Breach markers with color-coded severity (critical/high/medium/low)
- ✅ Animated threat arcs from source to target countries
- ✅ Pulsing marker animations
- ✅ Hover tooltips showing breach information
- ✅ Click-to-expand details panel
- ✅ Sidebar with filters (severity, region, date range)
- ✅ Real-time statistics display
- ✅ Top targets and recent activity lists
- ✅ Report generation with Chart.js visualizations
- ✅ Drag to rotate globe manually
- ✅ Mouse wheel zoom controls
- ✅ Responsive design for different screen sizes

### Data Coverage
- **Breaches**: 30 events across Healthcare, Finance, Technology, Government, Energy, etc.
- **Threats**: 20 indicators from Russia, China, Iran, North Korea, and other nations
- **Attack Types**: DDoS, APT, Ransomware, Phishing, Zero-Day, Data Exfiltration, BEC
- **Regions**: North America, Europe, Asia, South America, Africa, Oceania

## How to Run

```bash
cd "75. WebGL-based data breach world map (live threat feed visualization)"
pip install fastapi uvicorn jinja2 python-multipart
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

Open browser to: `http://localhost:8000`

## Dependencies
- Python: fastapi, uvicorn, jinja2, python-multipart
- Frontend: Three.js (CDN), Chart.js (CDN)
