# 3D Interactive Portfolio Site - Memory & Learned Patterns

## Design Patterns

### Three.js Scene Setup
- Always set `renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))` for performance
- Use `THREE.AdditiveBlending` for particle effects to get glow without post-processing
- Wireframe materials with transparency create lightweight but visually rich shapes
- Floating animation: store original Y position, apply sin-wave offset using `Date.now()`

### Particle Systems
- 1000-2000 particles is a good balance for background density vs performance
- Use `THREE.BufferGeometry` with position and color attributes for GPU-efficient rendering
- HSL colors in the teal range (0.47-0.57) give a consistent tech aesthetic

### Camera Interaction
- Mouse-tracked rotation with lerp interpolation (`targetRotation += (target - current) * 0.02`) produces smooth, non-jittery motion
- Keep rotation limits small (±0.3 rad) to prevent disorientation

### UI/UX Patterns
- Dark theme with `#0a0a0f` base provides good contrast for teal (#64ffda) accents
- Section transitions using CSS `fadeIn` animation with `display: block/none` toggle
- Card hover effects: left border scale + translateY + box-shadow create depth
- Responsive hamburger menu at 768px breakpoint

### Data Architecture
- JSON file storage works well for single-developer portfolios
- Contact form submissions append to a contacts.json file with timestamps
- Report generation: build HTML string in Python, return as `HTMLResponse` with `Content-Disposition` header for download

### Performance Notes
- Three.js `requestAnimationFrame` loop should check if section is visible before heavy operations
- Use `THREE.PointsMaterial` instead of individual meshes for large particle counts
- Webpack/bundling not needed when using CDN links for Three.js

## Gotchas
- Three.js r128 CDN: use `THREE` as global, no ES modules needed
- FastAPI `Form(...)` requires `python-multipart` package
- File downloads via HTMLResponse need proper Content-Disposition header
- CORS middleware needed even for same-origin if testing with different ports
