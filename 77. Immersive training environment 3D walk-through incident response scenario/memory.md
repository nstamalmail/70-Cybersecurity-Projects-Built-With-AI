# Immersive Training Environment - Memory & Design Decisions

## Project Overview
This 3D training environment simulates incident response scenarios for cybersecurity training. Trainees navigate through virtual office spaces, collect evidence, and make critical decisions that affect their scores.

## Architecture Decisions

### Frontend Architecture
- **Three.js**: Chosen for cross-browser 3D rendering without plugins
- **First-Person Controls**: Implemented custom WASD movement with collision detection
- **Interactive Objects**: Raycasting used for object selection and interaction
- **UI Overlays**: HTML/CSS panels for minimap, evidence, and decision points

### Backend Architecture
- **FastAPI**: High-performance async framework for API endpoints
- **JSON Storage**: Simple file-based storage for scenarios and sessions
- **Report Generation**: Server-side HTML generation with download capability

### 3D Environment Design
- **Modular Rooms**: Each scenario consists of connected rooms with consistent sizing
- **Primitive Geometry**: Walls, floors, and furniture built from basic Three.js primitives
- **Lighting**: Ambient + directional lighting for realistic shadows
- **Materials**: MeshPhongMaterial for interactive objects, MeshLambertMaterial for static elements

## Key Design Patterns

### Scenario Structure
```json
{
  "id": "unique_scenario_id",
  "rooms": [
    {
      "objects": [...],
      "decision_points": [...]
    }
  ],
  "completion_criteria": {...}
}
```

### Decision Point System
- Each decision point has 3 options with different score values
- Scores range from 1-10 based on response quality
- Feedback provided immediately after selection
- Cumulative score determines final assessment

### Evidence Collection
- Interactive objects contain clues
- Collecting evidence adds to trainee's investigation file
- Some evidence unlocks additional decision options
- Evidence affects final score and report generation

## Performance Considerations

### 3D Rendering
- **Object Pooling**: Reuse geometry and materials where possible
- **LOD**: Not implemented (simple scene doesn't require it)
- **Frustum Culling**: Enabled by default in Three.js
- **Texture Optimization**: Using solid colors instead of textures for performance

### API Performance
- **Caching**: Scenario data cached in memory after first load
- **Pagination**: Session list supports pagination for large datasets
- **Async Operations**: Non-blocking file I/O for report generation

## Security Considerations

### Data Privacy
- Training data stored locally (no external transmission)
- No PII collected beyond trainee name and department
- Reports generated server-side and returned as download

### API Security
- CORS enabled for development (restrict in production)
- Input validation on all endpoints
- Rate limiting recommended for production deployment

## Accessibility Features

### Current
- Keyboard navigation support
- High contrast color scheme
- Responsive design for different screen sizes

### Planned
- Screen reader support for UI elements
- Alternative 2D mode for non-WebGL devices
- Audio descriptions for visual elements

## Future Enhancements

### Short Term
1. Add more incident response scenarios
2. Implement trainee progress tracking over time
3. Add team-based training modes
4. Create scenario editor for custom content

### Long Term
1. VR/AR support using WebXR
2. Integration with enterprise LMS platforms
3. AI-powered adaptive difficulty
4. Real-time multiplayer training sessions
5. Voice-controlled interactions

## Technical Debt
- No unit tests implemented
- No CI/CD pipeline
- No automated backups
- No monitoring/logging system

## Version History
- **v1.0.0**: Initial release with 3 scenarios and 10 sample sessions
