# Memory: 3D Product Configurator

## Project Overview
Interactive e-commerce product configurator with real-time 3D preview, drag rotation, and dynamic pricing.

## Key Implementation Details

### 3D Product Modeling
- Products built from Three.js primitives (BoxGeometry, CylinderGeometry, TorusGeometry, TubeGeometry)
- Each product category has a dedicated builder function
- Models respond to color selection changes in real-time
- Shadow mapping enabled for realistic grounding

### Product Model Structure
| Product | Geometry Used | Key Components |
|---------|--------------|----------------|
| Laptop | Box, Box | Base, screen (pivoting), keyboard, touchpad |
| Phone | Box, Cylinder | Body, screen, camera bump |
| Headphones | Cylinder, Torus, Tube | Ear cups, cushions, curved headband |
| Watch | Cylinder, Box, Box | Case, face, bands, hour markers |
| Camera | Box, Cylinder | Body, grip, lens barrel, glass, viewfinder |

### Interaction System
- **Drag Rotation**: mousedown/mousemove/mouseup on canvas
- **Zoom**: Mouse wheel with position clamping (min 2, max 8 units)
- **Touch Support**: Single finger drag, pinch-to-zoom
- **Reset**: Button restores camera to (3, 2, 3) looking at origin

### Configuration State Management
- `currentSelections` object stores all option choices
- Color options trigger 3D model rebuild
- Accessory selections use arrays (multiple allowed)
- Price calculated from base + all option additions

### API Design
- Products served from JSON file
- Configurations persisted to JSON file (simulated database)
- Price calculation done server-side for accuracy
- Report generation creates downloadable HTML file

### Report Generation
- Professional order summary with customer info
- Product configuration details in formatted tables
- Price breakdown (subtotal, tax, total)
- Unique quote IDs for tracking
- Clean gradient design matching brand

### CSS Design System
- Primary gradient: #667eea → #764ba2
- Card-based layout with rounded corners
- Smooth hover transitions and transforms
- Active states with gradient backgrounds
- Mobile-first responsive breakpoints

### File Relationships
```
app.py
├── /api/products → sample_products.json
├── /api/configurations → sample_configurations.json (read/write)
├── /api/cart/calculate → computed from configurations
└── /api/reports/generate → reports/*.html

index.html
├── style.css (gradient theme)
└── main.js
    ├── Three.js (3D models)
    ├── API calls (CRUD operations)
    └── DOM manipulation (UI state)
```

## Extension Points
- Add actual product images as textures
- Implement comparison mode (side by side)
- Add sharing functionality (URL parameters)
- Integrate with payment processing
- Add inventory/availability checking
- Implement multi-language support
- Add accessibility features (ARIA labels)
- Create admin panel for product management
