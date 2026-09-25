let scene, camera, renderer, globe, breaches = [], threats = [], markers = [], arcs = [];
let raycaster, mouse, hoveredMarker = null;
let rotationSpeed = 0.001;
let isRotating = true;

const COLORS = {
    critical: 0xff0040,
    high: 0xff6600,
    medium: 0xffcc00,
    low: 0x00cc44
};

document.addEventListener('DOMContentLoaded', () => {
    init();
    loadData();
    setupEventListeners();
    animate();
});

function init() {
    const container = document.getElementById('globe-container');
    const canvas = document.getElementById('globe');

    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0a0e17);

    camera = new THREE.PerspectiveCamera(
        60,
        container.clientWidth / container.clientHeight,
        0.1,
        1000
    );
    camera.position.z = 2.5;

    renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    const ambientLight = new THREE.AmbientLight(0xffffff, 0.4);
    scene.add(ambientLight);

    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(5, 3, 5);
    scene.add(directionalLight);

    const pointLight = new THREE.PointLight(0x00ff88, 0.5, 10);
    pointLight.position.set(-3, 2, 3);
    scene.add(pointLight);

    createGlobe();
    createStarfield();

    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();

    window.addEventListener('resize', onWindowResize);
    canvas.addEventListener('mousemove', onMouseMove);
    canvas.addEventListener('click', onMouseClick);
    canvas.addEventListener('mousedown', onDragStart);
    canvas.addEventListener('mouseup', onDragEnd);
    canvas.addEventListener('mouseleave', onDragEnd);
}

function createGlobe() {
    const geometry = new THREE.SphereGeometry(1, 64, 64);

    const canvas = document.createElement('canvas');
    canvas.width = 2048;
    canvas.height = 1024;
    const ctx = canvas.getContext('2d');

    const gradient = ctx.createLinearGradient(0, 0, 0, 1024);
    gradient.addColorStop(0, '#1a2a3a');
    gradient.addColorStop(0.3, '#0d1926');
    gradient.addColorStop(0.5, '#1a3040');
    gradient.addColorStop(0.7, '#0d1926');
    gradient.addColorStop(1, '#1a2a3a');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, 2048, 1024);

    ctx.strokeStyle = '#00ff88';
    ctx.lineWidth = 0.5;
    ctx.globalAlpha = 0.15;

    for (let i = 0; i < 18; i++) {
        ctx.beginPath();
        ctx.moveTo(0, i * (1024 / 18));
        ctx.lineTo(2048, i * (1024 / 18));
        ctx.stroke();
    }

    for (let i = 0; i < 36; i++) {
        ctx.beginPath();
        ctx.moveTo(i * (2048 / 36), 0);
        ctx.lineTo(i * (2048 / 36), 1024);
        ctx.stroke();
    }

    ctx.globalAlpha = 0.4;
    ctx.lineWidth = 1.5;
    drawContinents(ctx);

    const texture = new THREE.CanvasTexture(canvas);
    
    const material = new THREE.MeshPhongMaterial({
        map: texture,
        transparent: true,
        opacity: 0.9,
        shininess: 25,
        specular: new THREE.Color(0x00ff88)
    });

    globe = new THREE.Mesh(geometry, material);
    scene.add(globe);

    const glowGeometry = new THREE.SphereGeometry(1.02, 64, 64);
    const glowMaterial = new THREE.MeshBasicMaterial({
        color: 0x00ff88,
        transparent: true,
        opacity: 0.05,
        side: THREE.BackSide
    });
    const glow = new THREE.Mesh(glowGeometry, glowMaterial);
    globe.add(glow);
}

function drawContinents(ctx) {
    ctx.fillStyle = '#00ff88';
    
    const continents = [
        {x: 280, y: 180, w: 180, h: 150},
        {x: 460, y: 200, w: 120, h: 180},
        {x: 280, y: 380, w: 150, h: 120},
        {x: 500, y: 350, w: 80, h: 100},
        {x: 1100, y: 150, w: 400, h: 250},
        {x: 950, y: 420, w: 150, h: 200},
        {x: 1600, y: 500, w: 200, h: 150},
        {x: 1500, y: 250, w: 120, h: 100}
    ];

    continents.forEach(c => {
        ctx.beginPath();
        ctx.ellipse(c.x + c.w/2, c.y + c.h/2, c.w/2, c.h/2, 0, 0, Math.PI * 2);
        ctx.fill();
    });
}

function createStarfield() {
    const geometry = new THREE.BufferGeometry();
    const vertices = [];
    
    for (let i = 0; i < 3000; i++) {
        const x = (Math.random() - 0.5) * 100;
        const y = (Math.random() - 0.5) * 100;
        const z = (Math.random() - 0.5) * 100;
        vertices.push(x, y, z);
    }
    
    geometry.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3));
    
    const material = new THREE.PointsMaterial({
        color: 0xffffff,
        size: 0.05,
        transparent: true,
        opacity: 0.6
    });
    
    const stars = new THREE.Points(geometry, material);
    scene.add(stars);
}

function latLngToVector3(lat, lng, radius = 1.01) {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lng + 180) * (Math.PI / 180);
    
    return new THREE.Vector3(
        -radius * Math.sin(phi) * Math.cos(theta),
        radius * Math.cos(phi),
        radius * Math.sin(phi) * Math.sin(theta)
    );
}

function numericRecords(value) {
    if (typeof value === 'number' && isFinite(value)) return value;
    if (typeof value === 'string') {
        const parsed = parseFloat(value.replace(/[^0-9.]/g, ''));
        if (isFinite(parsed) && /\d/.test(value)) return parsed;
    }
    return null;
}

function formatRecords(value) {
    const num = numericRecords(value);
    if (num === null) return 'Unknown';
    return formatNumber(num);
}

function createBreachMarker(breach) {
    const position = latLngToVector3(breach.lat, breach.lng);
    const color = COLORS[breach.severity] || COLORS.medium;
    
    const records = numericRecords(breach.records) || 0;
    const size = 0.01 + (records / 5000000) * 0.02;
    const geometry = new THREE.SphereGeometry(size, 16, 16);
    const material = new THREE.MeshBasicMaterial({
        color: color,
        transparent: true,
        opacity: 0.9
    });
    
    const marker = new THREE.Mesh(geometry, material);
    marker.position.copy(position);
    marker.userData = breach;
    
    const glowGeometry = new THREE.SphereGeometry(size * 2, 16, 16);
    const glowMaterial = new THREE.MeshBasicMaterial({
        color: color,
        transparent: true,
        opacity: 0.3
    });
    const glow = new THREE.Mesh(glowGeometry, glowMaterial);
    marker.add(glow);
    
    globe.add(marker);
    markers.push(marker);
    
    return marker;
}

function createThreatArc(threat) {
    // Support all feed shapes: nested {source:{lat,lng}} (geographic_data),
    // flat source_lat/source_lng (sample data), flat lat/lng (live feeds).
    const srcLat = threat.source?.lat ?? threat.source_lat ?? threat.lat;
    const srcLng = threat.source?.lng ?? threat.source_lng ?? threat.lng;
    const tgtLat = threat.target?.lat ?? threat.target_lat;
    const tgtLng = threat.target?.lng ?? threat.target_lng;

    if (![srcLat, srcLng, tgtLat, tgtLng].every(v => Number.isFinite(v))) {
        console.warn('Skipping threat arc with invalid coordinates:', threat.id, { srcLat, srcLng, tgtLat, tgtLng });
        return null;
    }

    const source = latLngToVector3(srcLat, srcLng, 1.02);
    const target = latLngToVector3(tgtLat, tgtLng, 1.02);
    
    const mid = new THREE.Vector3().addVectors(source, target).multiplyScalar(0.5);
    const distance = source.distanceTo(target);
    mid.normalize().multiplyScalar(1.02 + distance * 0.3);
    
    const curve = new THREE.QuadraticBezierCurve3(source, mid, target);
    const points = curve.getPoints(50);
    
    const color = COLORS[threat.severity] || COLORS.medium;
    const geometry = new THREE.BufferGeometry().setFromPoints(points);
    const material = new THREE.LineBasicMaterial({
        color: color,
        transparent: true,
        opacity: 0.6
    });
    
    const arc = new THREE.Line(geometry, material);
    arc.userData = { threat, progress: 0 };
    globe.add(arc);
    arcs.push(arc);
    
    return arc;
}

async function loadData() {
    try {
        const [breachesRes, threatsRes, statsRes] = await Promise.all([
            fetch('/api/breaches'),
            fetch('/api/threats'),
            fetch('/api/stats')
        ]);
        
        const breachesData = await breachesRes.json();
        const threatsData = await threatsRes.json();
        const statsData = await statsRes.json();
        
        breaches = breachesData.breaches;
        threats = threatsData.threats;
        
        createMarkersAndArcs();
        updateStats(statsData);
        updateSidebar();
        
        document.getElementById('loading').classList.add('hidden');
    } catch (error) {
        console.error('Error loading data:', error);
        document.getElementById('loading').innerHTML = '<p style="color: #ff0040;">Error loading data. Please refresh.</p>';
    }
}

function createMarkersAndArcs() {
    markers.forEach(m => globe.remove(m));
    arcs.forEach(a => globe.remove(a));
    markers = [];
    arcs = [];
    
    breaches.forEach(breach => createBreachMarker(breach));
    threats.forEach(threat => createThreatArc(threat));
}

function updateStats(stats) {
    // Backend /api/stats provides total_breaches / total_threats;
    // records total is summed client-side since live feeds may set records to "Unknown".
    const totalRecords = breaches.reduce((sum, b) => sum + (numericRecords(b.records) || 0), 0);
    
    document.getElementById('totalBreaches').textContent = stats.total_breaches ?? breaches.length;
    document.getElementById('totalRecords').textContent = totalRecords > 0 ? formatNumber(totalRecords) : 'N/A';
    document.getElementById('activeThreats').textContent = stats.total_threats ?? threats.length;
}

function updateSidebar() {
    const sources = {};
    breaches.forEach(b => {
        sources[b.source] = (sources[b.source] || 0) + 1;
    });
    
    const sortedSources = Object.entries(sources)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);
    
    document.getElementById('topTargets').innerHTML = sortedSources
        .map(([source, count]) => `
            <div class="target-item">
                <span>${source}</span>
                <span class="target-count">${count}</span>
            </div>
        `).join('');
    
    const recent = [...breaches].sort((a, b) => b.date.localeCompare(a.date)).slice(0, 5);
    document.getElementById('recentActivity').innerHTML = recent
        .map(b => `
            <div class="activity-item">
                <span>${b.name.substring(0, 20)}...</span>
                <span class="severity-badge severity-${b.severity}">${b.severity}</span>
            </div>
        `).join('');
}

function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(0) + 'K';
    return num.toString();
}

function setupEventListeners() {
    document.getElementById('applyFilters').addEventListener('click', applyFilters);
    document.getElementById('closePanel').addEventListener('click', closePanel);
    document.getElementById('reportBtn').addEventListener('click', generateReport);
}

async function applyFilters() {
    const severity = document.getElementById('severityFilter').value;
    const region = document.getElementById('regionFilter').value;
    const dateFrom = document.getElementById('dateFrom').value;
    const dateTo = document.getElementById('dateTo').value;
    
    let url = '/api/breaches?';
    if (severity) url += `severity=${severity}&`;
    if (region) url += `region=${region}&`;
    if (dateFrom) url += `start_date=${dateFrom}&`;
    if (dateTo) url += `end_date=${dateTo}&`;
    
    try {
        const response = await fetch(url);
        const data = await response.json();
        breaches = data.breaches;
        createMarkersAndArcs();
    } catch (error) {
        console.error('Error applying filters:', error);
    }
}

async function generateReport() {
    try {
        const response = await fetch('/api/reports/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title: 'Threat Intelligence Report' })
        });
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'Threat_Intelligence_Report.html';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Error generating report:', error);
    }
}

function onWindowResize() {
    const container = document.getElementById('globe-container');
    camera.aspect = container.clientWidth / container.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(container.clientWidth, container.clientHeight);
}

function onMouseMove(event) {
    const rect = renderer.domElement.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
    
    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(markers);
    
    if (intersects.length > 0) {
        const marker = intersects[0].object;
        if (hoveredMarker !== marker) {
            hoveredMarker = marker;
            showTooltip(event, marker.userData);
        }
    } else {
        hoveredMarker = null;
        hideTooltip();
    }
}

function onMouseClick(event) {
    const rect = renderer.domElement.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
    
    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(markers);
    
    if (intersects.length > 0) {
        const breach = intersects[0].object.userData;
        showBreachDetails(breach);
    }
}

let isDragging = false;
let previousMousePosition = { x: 0, y: 0 };

function onDragStart(event) {
    isDragging = true;
    isRotating = false;
    previousMousePosition = { x: event.clientX, y: event.clientY };
}

function onDragEnd() {
    isDragging = false;
    setTimeout(() => { isRotating = true; }, 1000);
}

document.addEventListener('mousemove', (event) => {
    if (!isDragging) return;
    
    const deltaMove = {
        x: event.clientX - previousMousePosition.x,
        y: event.clientY - previousMousePosition.y
    };
    
    globe.rotation.y += deltaMove.x * 0.005;
    globe.rotation.x += deltaMove.y * 0.005;
    globe.rotation.x = Math.max(-Math.PI / 4, Math.min(Math.PI / 4, globe.rotation.x));
    
    previousMousePosition = { x: event.clientX, y: event.clientY };
});

document.addEventListener('wheel', (event) => {
    event.preventDefault();
    camera.position.z += event.deltaY * 0.001;
    camera.position.z = Math.max(1.5, Math.min(5, camera.position.z));
}, { passive: false });

function showTooltip(event, data) {
    const tooltip = document.getElementById('tooltip');
    tooltip.innerHTML = `
        <h4>${data.name}</h4>
        <p><span class="severity-badge severity-${data.severity}">${data.severity.toUpperCase()}</span></p>
        <p>Records: ${formatRecords(data.records)}</p>
        <p>Date: ${data.date}</p>
        <p>Industry: ${data.source}</p>
    `;
    tooltip.style.left = (event.clientX + 15) + 'px';
    tooltip.style.top = (event.clientY + 15) + 'px';
    tooltip.classList.add('visible');
}

function hideTooltip() {
    document.getElementById('tooltip').classList.remove('visible');
}

function showBreachDetails(breach) {
    const panel = document.getElementById('details-panel');
    const title = document.getElementById('panelTitle');
    const content = document.getElementById('panelContent');
    
    title.textContent = breach.name;
    content.innerHTML = `
        <div class="detail-row">
            <span class="detail-label">Severity</span>
            <span class="severity-badge severity-${breach.severity}">${breach.severity.toUpperCase()}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Records Affected</span>
            <span class="detail-value">${formatRecords(breach.records)}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Date</span>
            <span class="detail-value">${breach.date}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Industry</span>
            <span class="detail-value">${breach.source}</span>
        </div>
        <div class="detail-row">
            <span class="detail-label">Coordinates</span>
            <span class="detail-value">${breach.lat.toFixed(4)}, ${breach.lng.toFixed(4)}</span>
        </div>
        <div class="detail-description">
            <strong>Description:</strong><br>
            ${breach.description}
        </div>
    `;
    
    panel.classList.remove('hidden');
    panel.classList.add('visible');
}

function closePanel() {
    const panel = document.getElementById('details-panel');
    panel.classList.remove('visible');
    panel.classList.add('hidden');
}

function animate() {
    requestAnimationFrame(animate);
    
    if (isRotating && globe) {
        globe.rotation.y += rotationSpeed;
    }
    
    arcs.forEach((arc, index) => {
        arc.userData.progress += 0.005;
        if (arc.userData.progress > 1) arc.userData.progress = 0;
        
        const material = arc.material;
        material.opacity = 0.3 + Math.sin(arc.userData.progress * Math.PI) * 0.4;
    });
    
    markers.forEach(marker => {
        const scale = 1 + Math.sin(Date.now() * 0.003 + marker.id) * 0.1;
        marker.scale.setScalar(scale);
    });
    
    renderer.render(scene, camera);
}
