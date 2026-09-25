# SOC Dashboard - 3D Network Topology - Memory & Learned Patterns

## Design Patterns

### 3D Network Topology
- Layered layout by location zones (DMZ=0, Core=1, App=2, Data=3) with Y-axis separation
- Node type determines geometry: firewall=box, router=sphere, server=cylinder, workstation=flat box
- Color from status, not type - keeps visual scanning intuitive
- Edges as `THREE.Line` with `BufferGeometry` for lightweight rendering
- Animated edge opacity using sin wave creates "data flow" visual effect

### Raycasting for Interaction
- `THREE.Raycaster` + `THREE.Vector2` for mouse picking
- Normalize mouse coords: `mouse.x = (e.clientX / width) * 2 - 1`
- Store node data in `mesh.userData.node` for easy retrieval on intersection
- Show tooltip on hover, full modal on click

### Chart.js Integration
- Destroy previous chart instances before creating new ones (`chart.destroy()`)
- Consistent styling: `grid: { color: '#30363d' }`, `ticks: { color: '#8b949e' }`
- Chart.js 4.x uses UMD build from CDN, auto-registers all components

### SOC Color Scheme
- Background: `#0a0e17` (very dark blue-black)
- Cards: `#1c2128` (slightly lighter)
- Borders: `#30363d`
- Green: `#00ff88` (healthy/live indicators)
- Red: `#ff4444` (critical), Orange: `#ff8800` (high), Yellow: `#ffcc00` (medium)
- Text: `#c9d1d9` primary, `#8b949e` secondary

### API Filtering Pattern
- FastAPI `Query(None)` for optional parameters
- Chain filter conditions: `if param: data = [d for d in data if matches]`
- Support multiple filter types in single endpoint
- Search across multiple fields with lowercase matching

### Real-time Feel
- CSS `pulse` animation on live indicator dot
- Green glow animation: `box-shadow` keyframes
- Status dots with color + glow for at-a-glance status

### Responsive Sidebar
- Collapse to icon-only at 768px
- Hide text labels, keep nav icons
- Fixed width sidebar + flex main content

## Performance Notes
- 30 nodes with simple geometries: no performance concern
- For 100+ nodes, consider `InstancedMesh` or LOD
- Chart.js handles ~50 data points smoothly
- Raycasting on 30 meshes is negligible overhead

## Gotchas
- Three.js r128 CDN: use `THREE` global, no module imports
- Chart.js 4.x CDN auto-registers everything, no manual registration needed
- `raycaster.intersectObjects(nodeMeshes)` requires meshes to be in the scene
- Modal click-outside-to-close needs event listener on backdrop, not just close button
