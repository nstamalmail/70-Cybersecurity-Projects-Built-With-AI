# 3D Attack Path Visualizer - Memory & Design Notes

## Design Decisions
- **Force-directed layout**: Nodes positioned by type in layers (domain -> group -> computer -> user) with repulsion/attraction forces for organic spacing
- **Security tool aesthetic**: Dark GitHub-style theme (#0d1117) matching modern security tools like BloodHound
- **Node shapes**: Distinct geometries per type (spheres for users, cubes for groups, boxes for computers, stars for domains) for accessibility
- **BFS pathfinding**: Simple breadth-first search for shortest path, extensible to weighted algorithms

## Technical Notes
- Pre-computed force layout (80 iterations) at load time for stable positioning
- Raycasting for node click detection in Three.js scene
- Dynamic highlighting dims unconnected nodes/edges to focus attention
- Minimap renders camera-relative positions for spatial awareness
- Edge opacity manipulation for path visualization

## Data Model
- Graph stored as flat nodes/edges arrays with source/target references
- Paths reference node IDs and edge types for sequential traversal
- Risk scores computed from path length, node privileges, and edge sensitivity

## Security Context
- DCSync and GenericAll edges weighted highest for risk scoring
- Admin accounts increase path risk score
- Domain controller access triggers critical risk threshold
- Recommendations focused on least privilege and monitoring

## Future Improvements
- Cypher query support for custom graph queries
- Edge weight visualization (thickness = frequency)
- Time-based graph evolution (track changes over time)
- Integration with real BloodHound data via API
- SPARQL endpoint for graph database backends
