# 3D CTF Scoreboard - Memory & Design Notes

## Design Decisions
- **Neon aesthetic**: Used cyberpunk/neon color scheme with cyan, pink, green accents on dark background for competitive gaming feel
- **Three.js for 3D bars**: Bar heights animate smoothly using lerp interpolation for fluid race visualization
- **Timeline system**: All solves ordered by timestamp; playback steps through cumulative score snapshots
- **Category colors**: Web=blue, Crypto=orange, Forensics=green, Reversing=purple, Pwn=red consistently across UI

## Technical Notes
- Canvas texture labels on 3D bars update dynamically when scores change
- OrbitControls for camera interaction (rotate, zoom, pan)
- Emissive glow on bars and challenge nodes for visual feedback during solves
- Fog added for depth perception in 3D scene

## Data Model
- Teams have static total_score from JSON; timeline replay shows progressive scoring
- Challenges are categorized with point values and difficulty levels
- Solve events link team_id to challenge_id with timestamps

## Future Improvements
- WebSocket for real-time solve events instead of polling
- Persistent database instead of JSON files
- Team avatars/logos in 3D
- Sound pack with custom solve jingles
- Historical competition comparison
