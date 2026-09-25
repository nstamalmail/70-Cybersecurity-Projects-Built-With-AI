# Memory: Data Breach World Map

## Project Overview
Real-time cybersecurity threat visualization platform using 3D globe rendering to display global data breaches and threat indicators.

## Key Implementation Details

### 3D Globe Technology
- **Three.js** for WebGL rendering
- Custom Earth texture generated programmatically with Canvas API
- Latitude/longitude to 3D vector conversion for accurate marker placement
- QuadraticBezierCurve3 for animated threat arcs between countries

### Data Visualization Strategy
- **Severity Mapping**: Critical (red), High (orange), Medium (yellow), Low (green)
- **Marker Sizing**: Proportional to number of records affected
- **Arc Animation**: Pulsing opacity effect to simulate live threat activity
- **Pulse Animation**: Scale oscillation on markers for visual feedback

### API Design Patterns
- Query parameters for flexible filtering (severity, region, date range)
- Separate endpoints for different data views (breaches, threats, stats)
- Geographic data endpoint for frontend visualization needs
- POST endpoint for report generation with configurable options

### Report Generation
- Server-side HTML generation with embedded Chart.js
- Doughnut chart for severity distribution
- Responsive tables for breach and threat data
- Professional styling matching the application theme
- Unique report IDs for tracking

### Interaction Design
- **Hover**: Tooltip with quick summary
- **Click**: Expandable details panel
- **Drag**: Manual globe rotation
- **Scroll**: Zoom in/out control
- **Auto-rotation**: Resumes after 1 second of inactivity

### Performance Considerations
- Marker count capped by data size (30 breaches)
- Arc segments limited to 50 points each
- Pixel ratio capping for high-DPI displays
- RequestAnimationFrame for smooth 60fps animation
- Raycaster intersection for efficient hit detection

### CSS Architecture
- CSS custom properties for theming
- Flexbox and Grid for layout
- Backdrop-filter for glass effects
- Smooth transitions for UI state changes
- Mobile-first responsive breakpoints

## File Relationships
```
app.py
├── /api/breaches → sample_breaches.json
├── /api/threats → sample_threats.json
├── /api/stats → computed from breach/threat data
├── /api/geographic_data → computed coordinates
└── /api/reports/generate → reports/*.html

index.html
├── style.css (dark theme)
└── main.js
    ├── Three.js (3D globe)
    ├── Chart.js (report charts)
    ├── API calls (fetch data)
    └── DOM manipulation (UI updates)
```

## Extension Points
- Add real-time WebSocket for live threat updates
- Integrate with actual threat intelligence APIs (OTX, VirusTotal)
- Add clustering for dense regions
- Implement timeline scrubber for historical analysis
- Add export to PDF functionality
- Add user authentication for sensitive data
