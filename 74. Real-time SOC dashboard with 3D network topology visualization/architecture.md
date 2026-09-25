# SOC Dashboard - Architecture

## System Architecture

### Backend (FastAPI)
- **Framework**: Python FastAPI with async support
- **Server**: Uvicorn ASGI server (port 8001)
- **Data Storage**: JSON file-based (no database required)
- **API Pattern**: RESTful with filtering and pagination

### Frontend
- **3D Engine**: Three.js r128 (CDN) - WebGL-based 3D rendering
- **Charts**: Chart.js 4.4 (CDN) - Responsive data visualization
- **UI**: Vanilla JavaScript with modern ES6+ syntax
- **Styling**: Custom CSS with SOC dark theme

### Data Flow
```
Client (Browser)
    ↓ HTTP/REST
FastAPI Backend
    ↓ File I/O
JSON Data Files
    ↑
Generated Reports (HTML)
```

### Component Architecture

#### 3D Network Topology
- **Scene Management**: Three.js Scene, Camera, Renderer
- **Node Rendering**: MeshPhongMaterial with emissive glow
- **Edge Rendering**: BufferGeometry Line with transparency
- **Interaction**: Raycaster for mouse picking (hover/click)
- **Animation**: RequestAnimationFrame loop with time-based effects

#### Dashboard Sections
1. **Overview**: Stats cards + real-time charts
2. **3D Topology**: Interactive network visualization
3. **Alerts**: Filterable data table with CRUD operations
4. **Incidents**: Timeline chart + incident management

### API Endpoints
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Serve dashboard |
| GET | `/api/alerts` | List alerts (filterable) |
| GET | `/api/alerts/{id}` | Get single alert |
| PUT | `/api/alerts/{id}` | Update alert |
| GET | `/api/network` | Network topology |
| GET | `/api/network/{id}` | Get single node |
| GET | `/api/metrics` | All metrics |
| GET | `/api/report/security` | Generate report |

### Security Considerations
- CORS enabled for development (restrict in production)
- No authentication implemented (add JWT/OAuth for production)
- Input validation via Pydantic models
- File path traversal prevention via os.path.join

### Performance Notes
- 30 network nodes: No performance issues
- Chart.js handles 50+ data points smoothly
- Raycaster on 30 meshes: Negligible overhead
- For 100+ nodes: Consider InstancedMesh or LOD
