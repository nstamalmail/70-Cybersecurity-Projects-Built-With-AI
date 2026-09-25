const API = '';
let graphData = { nodes: [], edges: [] };
let paths = [];
let scene, camera, renderer, controls;
let nodeMeshes = {}, edgeLines = {}, edgeObjects = [];
let nodePositions = {};
let selectedNode = null, selectedPath = null;
let highlightedNodes = new Set(), highlightedEdges = new Set();
let filterState = { user: true, group: true, computer: true, domain: true };
let animFrame;

const NODE_CONFIG = {
    user: { color: 0x3388ff, shape: 'sphere', size: 0.6 },
    group: { color: 0xff4444, shape: 'cube', size: 0.7 },
    computer: { color: 0x33bb55, shape: 'box', size: 0.55 },
    domain: { color: 0xffaa33, shape: 'star', size: 0.9 }
};

const EDGE_COLORS = {
    AdminTo: 0xff4444,
    GenericAll: 0xff8800,
    MemberOf: 0x4488ff,
    HasSession: 0x44ff88,
    DCSync: 0xff00ff,
    WriteDacl: 0xffff00,
    ReadLAPSPassword: 0x00ffff
};

async function fetchData() {
    [graphData, paths] = await Promise.all([
        fetch(`${API}/api/graph`).then(r => r.json()),
        fetch(`${API}/api/paths`).then(r => r.json())
    ]);
}

function initThreeScene() {
    const container = document.getElementById('three-canvas');
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0d1117);
    scene.fog = new THREE.FogExp2(0x0d1117, 0.008);

    camera = new THREE.PerspectiveCamera(55, container.clientWidth / container.clientHeight, 0.1, 500);
    camera.position.set(0, 40, 50);

    renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(window.devicePixelRatio);
    container.appendChild(renderer.domElement);

    controls = new THREE.OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.maxDistance = 120;

    scene.add(new THREE.AmbientLight(0x445566, 0.8));
    const dirLight = new THREE.DirectionalLight(0xffffff, 0.6);
    dirLight.position.set(20, 30, 20);
    scene.add(dirLight);

    createGrid();
    layoutNodes();
    createEdgeLines();
    createNodeMeshes();

    window.addEventListener('resize', onResize);
    animate();
}

function createGrid() {
    const gridGeo = new THREE.PlaneGeometry(100, 100, 40, 40);
    const gridMat = new THREE.MeshBasicMaterial({ color: 0x21262d, wireframe: true, transparent: true, opacity: 0.3 });
    const grid = new THREE.Mesh(gridGeo, gridMat);
    grid.rotation.x = -Math.PI / 2;
    grid.position.y = -1;
    scene.add(grid);
}

function layoutNodes() {
    const typeGroups = {};
    graphData.nodes.forEach(n => {
        if (!typeGroups[n.type]) typeGroups[n.type] = [];
        typeGroups[n.type].push(n);
    });

    const typeOrder = ['domain', 'group', 'computer', 'user'];
    const layerSpacing = 12;
    const startY = (typeOrder.length - 1) * layerSpacing / 2;

    typeOrder.forEach((type, ti) => {
        const nodes = typeGroups[type] || [];
        const radius = 8 + nodes.length * 0.8;
        nodes.forEach((n, ni) => {
            const angle = (ni / nodes.length) * Math.PI * 2 + ti * 0.3;
            const r = radius + (Math.random() - 0.5) * 4;
            nodePositions[n.id] = {
                x: Math.cos(angle) * r,
                y: startY - ti * layerSpacing + (Math.random() - 0.5) * 3,
                z: Math.sin(angle) * r,
                tx: Math.cos(angle) * r,
                ty: startY - ti * layerSpacing + (Math.random() - 0.5) * 3,
                tz: Math.sin(angle) * r,
                vx: 0, vy: 0, vz: 0,
            };
        });
    });

    for (let iter = 0; iter < 80; iter++) {
        applyForces();
    }

    Object.values(nodePositions).forEach(p => {
        p.x = p.tx;
        p.y = p.ty;
        p.z = p.tz;
    });
}

function applyForces() {
    const nodes = graphData.nodes;
    const repulsion = 150;
    const attraction = 0.005;
    const centerPull = 0.01;

    for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
            const a = nodePositions[nodes[i].id];
            const b = nodePositions[nodes[j].id];
            if (!a || !b) continue;
            const dx = a.tx - b.tx;
            const dy = a.ty - b.ty;
            const dz = a.tz - b.tz;
            const dist = Math.sqrt(dx * dx + dy * dy + dz * dz) + 0.1;
            const force = repulsion / (dist * dist);
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            const fz = (dz / dist) * force;
            a.vx += fx; a.vy += fy; a.vz += fz;
            b.vx -= fx; b.vy -= fy; b.vz -= fz;
        }
    }

    graphData.edges.forEach(e => {
        const a = nodePositions[e.source];
        const b = nodePositions[e.target];
        if (!a || !b) return;
        const dx = b.tx - a.tx;
        const dy = b.ty - a.ty;
        const dz = b.tz - a.tz;
        const dist = Math.sqrt(dx * dx + dy * dy + dz * dz) + 0.1;
        const force = (dist - 8) * attraction;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        const fz = (dz / dist) * force;
        a.vx += fx; a.vy += fy; a.vz += fz;
        b.vx -= fx; b.vy -= fy; b.vz -= fz;
    });

    Object.values(nodePositions).forEach(p => {
        p.vx -= p.tx * centerPull;
        p.vy -= p.ty * centerPull;
        p.vz -= p.tz * centerPull;
        p.vx *= 0.85;
        p.vy *= 0.85;
        p.vz *= 0.85;
        p.tx += p.vx;
        p.ty += p.vy;
        p.tz += p.vz;
    });
}

function createNodeMeshes() {
    graphData.nodes.forEach(n => {
        const config = NODE_CONFIG[n.type] || NODE_CONFIG.user;
        let geo;
        if (config.shape === 'sphere') {
            geo = new THREE.SphereGeometry(config.size, 16, 16);
        } else if (config.shape === 'cube') {
            geo = new THREE.BoxGeometry(config.size * 1.4, config.size * 1.4, config.size * 1.4);
        } else if (config.shape === 'star') {
            geo = new THREE.OctahedronGeometry(config.size, 1);
        } else {
            geo = new THREE.BoxGeometry(config.size * 1.2, config.size * 0.8, config.size * 1.2);
        }

        const mat = new THREE.MeshPhongMaterial({
            color: config.color,
            emissive: config.color,
            emissiveIntensity: 0.25,
            transparent: true,
            opacity: 0.9,
        });

        const mesh = new THREE.Mesh(geo, mat);
        const pos = nodePositions[n.id];
        mesh.position.set(pos.x, pos.y, pos.z);
        mesh.userData = { nodeId: n.id, nodeData: n };
        scene.add(mesh);
        nodeMeshes[n.id] = mesh;

        const glowGeo = new THREE.SphereGeometry(config.size * 1.8, 8, 8);
        const glowMat = new THREE.MeshBasicMaterial({ color: config.color, transparent: true, opacity: 0.08 });
        const glow = new THREE.Mesh(glowGeo, glowMat);
        mesh.add(glow);

        createLabel(n.name, mesh, config.color);
    });
}

function createLabel(text, parent, color) {
    const canvas = document.createElement('canvas');
    canvas.width = 256;
    canvas.height = 48;
    const ctx = canvas.getContext('2d');
    ctx.font = 'bold 22px Segoe UI';
    ctx.fillStyle = '#' + color.toString(16).padStart(6, '0');
    ctx.textAlign = 'center';
    ctx.fillText(text.length > 16 ? text.substring(0, 14) + '..' : text, 128, 32);

    const texture = new THREE.CanvasTexture(canvas);
    const spriteMat = new THREE.SpriteMaterial({ map: texture, transparent: true, depthTest: false });
    const sprite = new THREE.Sprite(spriteMat);
    sprite.scale.set(3, 0.6, 1);
    sprite.position.y = 1.2;
    parent.add(sprite);
}

function createEdgeLines() {
    graphData.edges.forEach(e => {
        const sourcePos = nodePositions[e.source];
        const targetPos = nodePositions[e.target];
        if (!sourcePos || !targetPos) return;

        const points = [
            new THREE.Vector3(sourcePos.x, sourcePos.y, sourcePos.z),
            new THREE.Vector3(targetPos.x, targetPos.y, targetPos.z)
        ];
        const geo = new THREE.BufferGeometry().setFromPoints(points);
        const color = EDGE_COLORS[e.type] || 0x666666;
        const mat = new THREE.LineBasicMaterial({ color: color, transparent: true, opacity: 0.25 });
        const line = new THREE.Line(geo, mat);
        line.userData = { edgeId: e.id, edgeData: e };
        scene.add(line);
        edgeObjects.push(line);
        edgeLines[e.id] = line;
    });
}

function animate() {
    animFrame = requestAnimationFrame(animate);
    controls.update();
    renderer.render(scene, camera);
    updateMinimap();
}

function onResize() {
    const container = document.getElementById('three-canvas');
    camera.aspect = container.clientWidth / container.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(container.clientWidth, container.clientHeight);
}

function focusNode(nodeId) {
    const mesh = nodeMeshes[nodeId];
    if (!mesh) return;
    const pos = mesh.position;
    camera.position.set(pos.x + 15, pos.y + 10, pos.z + 15);
    controls.target.set(pos.x, pos.y, pos.z);
}

function showNodeDetails(nodeId) {
    const node = graphData.nodes.find(n => n.id === nodeId);
    if (!node) return;
    selectedNode = nodeId;
    const connectedEdges = graphData.edges.filter(e => e.source === nodeId || e.target === nodeId);
    const connNodes = new Set();
    connectedEdges.forEach(e => { connNodes.add(e.source); connNodes.add(e.target); });
    connNodes.delete(nodeId);

    const props = node.properties || {};
    const container = document.getElementById('node-details');
    let html = `
        <div class="detail-row"><span class="detail-label">Name:</span><span class="detail-value">${node.name}</span></div>
        <div class="detail-row"><span class="detail-label">Type:</span><span class="detail-value">${node.type}</span></div>
    `;
    Object.entries(props).forEach(([k, v]) => {
        html += `<div class="detail-row"><span class="detail-label">${k}:</span><span class="detail-value">${v}</span></div>`;
    });
    html += `<div class="detail-row"><span class="detail-label">Connections:</span><span class="detail-value">${connectedEdges.length}</span></div>`;

    if (connectedEdges.length > 0) {
        html += '<div class="detail-connections"><h3 style="font-size:0.75em;color:#8b949e;margin:8px 0 4px">Connected Edges:</h3>';
        connectedEdges.forEach(e => {
            const otherId = e.source === nodeId ? e.target : e.source;
            const other = graphData.nodes.find(n => n.id === otherId);
            const direction = e.source === nodeId ? '->' : '<-';
            html += `<div class="detail-connection" data-node-id="${otherId}">${e.type} ${direction} ${other ? other.name : otherId}</div>`;
        });
        html += '</div>';
    }

    container.innerHTML = html;
    container.querySelectorAll('.detail-connection').forEach(el => {
        el.addEventListener('click', () => {
            const nid = el.dataset.nodeId;
            showNodeDetails(nid);
            focusNode(nid);
        });
    });

    highlightConnected(nodeId);
}

function highlightConnected(nodeId) {
    Object.values(edgeObjects).forEach(line => {
        line.material.opacity = 0.08;
    });
    Object.values(nodeMeshes).forEach(mesh => {
        mesh.material.opacity = 0.3;
    });

    const mesh = nodeMeshes[nodeId];
    if (mesh) mesh.material.opacity = 1;

    const connectedEdges = graphData.edges.filter(e => e.source === nodeId || e.target === nodeId);
    const connNodes = new Set([nodeId]);
    connectedEdges.forEach(e => {
        connNodes.add(e.source);
        connNodes.add(e.target);
        if (edgeLines[e.id]) edgeLines[e.id].material.opacity = 0.8;
    });
    connNodes.forEach(nid => {
        if (nodeMeshes[nid]) nodeMeshes[nid].material.opacity = 1;
    });
}

function clearHighlights() {
    Object.values(edgeObjects).forEach(line => { line.material.opacity = 0.25; });
    Object.values(nodeMeshes).forEach(mesh => { mesh.material.opacity = 0.9; });
    highlightedNodes.clear();
    highlightedEdges.clear();
}

function renderPaths() {
    const container = document.getElementById('paths-list');
    container.innerHTML = paths.map(p => {
        const riskClass = p.risk_score >= 85 ? 'critical' : p.risk_score >= 70 ? 'high' : 'medium';
        return `
            <div class="path-item" data-path-id="${p.id}">
                <div class="path-name">${p.name}</div>
                <div class="path-meta">
                    Hops: ${p.path.length - 1} | 
                    Risk: <span class="path-risk ${riskClass}">${p.risk_score}/100</span>
                </div>
            </div>
        `;
    }).join('');

    container.querySelectorAll('.path-item').forEach(el => {
        el.addEventListener('click', () => {
            const pid = parseInt(el.dataset.pathId);
            showPathDetail(pid);
            container.querySelectorAll('.path-item').forEach(e => e.classList.remove('active'));
            el.classList.add('active');
        });
    });
}

function showPathDetail(pathId) {
    const path = paths.find(p => p.id === pathId);
    if (!path) return;
    selectedPath = path;

    clearHighlights();

    const nodes = graphData.nodes;
    const nodesMap = {};
    nodes.forEach(n => nodesMap[n.id] = n);

    let chainHtml = '<div class="path-chain">';
    path.path.forEach((nid, i) => {
        const node = nodesMap[nid];
        const config = NODE_CONFIG[node?.type] || NODE_CONFIG.user;
        chainHtml += `<span class="path-node" data-node-id="${nid}" style="border-color:#${config.color.toString(16).padStart(6, '0')}">${node?.name || nid}</span>`;
        if (i < path.path.length - 1) {
            chainHtml += `<span class="path-edge">--${path.edges[i]}--></span>`;
        }
    });
    chainHtml += '</div>';

    const riskClass = path.risk_score >= 85 ? 'critical' : path.risk_score >= 70 ? 'high' : 'medium';
    const container = document.getElementById('path-detail');
    container.innerHTML = `
        <div style="margin-bottom:10px">
            <strong style="color:#c9d1d9">${path.name}</strong>
            <span class="path-risk ${riskClass}" style="margin-left:10px">${path.risk_score}/100</span>
        </div>
        ${chainHtml}
        <p style="color:#8b949e;font-size:0.82em;margin-top:8px">${path.description}</p>
    `;

    container.querySelectorAll('.path-node').forEach(el => {
        el.addEventListener('click', () => {
            showNodeDetails(el.dataset.nodeId);
            focusNode(el.dataset.nodeId);
        });
    });

    path.path.forEach(nid => {
        highlightedNodes.add(nid);
        if (nodeMeshes[nid]) nodeMeshes[nid].material.opacity = 1;
    });

    for (let i = 0; i < path.path.length - 1; i++) {
        const edge = graphData.edges.find(e =>
            (e.source === path.path[i] && e.target === path.path[i + 1]) ||
            (e.source === path.path[i + 1] && e.target === path.path[i])
        );
        if (edge && edgeLines[edge.id]) {
            highlightedEdges.add(edge.id);
            edgeLines[edge.id].material.opacity = 1;
            edgeLines[edge.id].material.linewidth = 3;
        }
    }

    Object.values(edgeObjects).forEach(line => {
        if (!highlightedEdges.has(line.userData.edgeId)) {
            line.material.opacity = 0.06;
        }
    });
    Object.values(nodeMeshes).forEach(mesh => {
        if (!highlightedNodes.has(mesh.userData.nodeId)) {
            mesh.material.opacity = 0.15;
        }
    });
}

function populateNodeSelects() {
    const sourceSelect = document.getElementById('source-node');
    const targetSelect = document.getElementById('target-node');
    const sortedNodes = [...graphData.nodes].sort((a, b) => a.name.localeCompare(b.name));
    sortedNodes.forEach(n => {
        const opt1 = document.createElement('option');
        opt1.value = n.id;
        opt1.textContent = `${n.name} (${n.type})`;
        sourceSelect.appendChild(opt1);
        const opt2 = document.createElement('option');
        opt2.value = n.id;
        opt2.textContent = `${n.name} (${n.type})`;
        targetSelect.appendChild(opt2);
    });
}

async function findPath() {
    const source = document.getElementById('source-node').value;
    const target = document.getElementById('target-node').value;
    if (!source || !target) {
        document.getElementById('pathfind-result').innerHTML = '<div class="pf-result pf-fail">Please select both source and target nodes.</div>';
        return;
    }
    if (source === target) {
        document.getElementById('pathfind-result').innerHTML = '<div class="pf-result pf-fail">Source and target must be different.</div>';
        return;
    }

    try {
        const resp = await fetch(`${API}/api/pathfind?source=${source}&target=${target}`);
        const result = await resp.json();
        const container = document.getElementById('pathfind-result');
        if (result.found) {
            const riskClass = result.risk_score >= 85 ? 'critical' : result.risk_score >= 70 ? 'high' : 'medium';
            container.innerHTML = `
                <div class="pf-result pf-success">
                    <strong>Path Found!</strong><br>
                    Hops: ${result.hops} | Risk: <span class="path-risk ${riskClass}">${result.risk_score}/100</span><br>
                    <span style="font-size:0.85em;color:#8b949e">${result.path.join(' -> ')}</span>
                </div>
            `;
            showDynamicPath(result);
        } else {
            container.innerHTML = '<div class="pf-result pf-fail">No path found between selected nodes.</div>';
        }
    } catch (e) {
        console.error(e);
    }
}

function showDynamicPath(result) {
    clearHighlights();
    result.path.forEach(nid => {
        highlightedNodes.add(nid);
        if (nodeMeshes[nid]) nodeMeshes[nid].material.opacity = 1;
    });
    for (let i = 0; i < result.path.length - 1; i++) {
        const edge = graphData.edges.find(e =>
            (e.source === result.path[i] && e.target === result.path[i + 1]) ||
            (e.source === result.path[i + 1] && e.target === result.path[i])
        );
        if (edge && edgeLines[edge.id]) {
            highlightedEdges.add(edge.id);
            edgeLines[edge.id].material.opacity = 1;
        }
    }
    Object.values(edgeObjects).forEach(line => {
        if (!highlightedEdges.has(line.userData.edgeId)) line.material.opacity = 0.06;
    });
    Object.values(nodeMeshes).forEach(mesh => {
        if (!highlightedNodes.has(mesh.userData.nodeId)) mesh.material.opacity = 0.15;
    });
}

function setupSearch() {
    const input = document.getElementById('search-input');
    const results = document.getElementById('search-results');

    input.addEventListener('input', async () => {
        const q = input.value.trim();
        if (q.length < 2) { results.classList.add('hidden'); return; }
        try {
            const resp = await fetch(`${API}/api/search?q=${encodeURIComponent(q)}`);
            const found = await resp.json();
            if (found.length === 0) { results.classList.add('hidden'); return; }
            results.innerHTML = found.map(n => {
                const config = NODE_CONFIG[n.type] || NODE_CONFIG.user;
                const color = '#' + config.color.toString(16).padStart(6, '0');
                return `<div class="search-result-item" data-node-id="${n.id}">
                    <span>${n.name}</span>
                    <span class="search-result-type" style="background:${color}22;color:${color}">${n.type}</span>
                </div>`;
            }).join('');
            results.classList.remove('hidden');
            results.querySelectorAll('.search-result-item').forEach(el => {
                el.addEventListener('click', () => {
                    const nid = el.dataset.nodeId;
                    showNodeDetails(nid);
                    focusNode(nid);
                    results.classList.add('hidden');
                    input.value = '';
                });
            });
        } catch (e) { results.classList.add('hidden'); }
    });

    input.addEventListener('blur', () => {
        setTimeout(() => results.classList.add('hidden'), 200);
    });
}

function setupFilters() {
    ['user', 'group', 'computer', 'domain'].forEach(type => {
        document.getElementById(`filter-${type}`).addEventListener('change', (e) => {
            filterState[type] = e.target.checked;
            applyFilters();
        });
    });
}

function applyFilters() {
    graphData.nodes.forEach(n => {
        const mesh = nodeMeshes[n.id];
        if (mesh) {
            mesh.visible = filterState[n.type] !== false;
        }
    });
    graphData.edges.forEach(e => {
        const line = edgeLines[e.id];
        if (line) {
            const sourceNode = graphData.nodes.find(n => n.id === e.source);
            const targetNode = graphData.nodes.find(n => n.id === e.target);
            line.visible = sourceNode && targetNode &&
                filterState[sourceNode.type] !== false &&
                filterState[targetNode.type] !== false;
        }
    });
}

function updateMinimap() {
    const canvas = document.getElementById('minimap-canvas');
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#0d1117';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    const camPos = camera.position;
    const scale = 0.8;
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;

    graphData.nodes.forEach(n => {
        const mesh = nodeMeshes[n.id];
        if (!mesh || !mesh.visible) return;
        const config = NODE_CONFIG[n.type] || NODE_CONFIG.user;
        const x = cx + (mesh.position.x - camPos.x) * scale;
        const z = cy + (mesh.position.z - camPos.z) * scale;
        if (x < 0 || x > canvas.width || z < 0 || z > canvas.height) return;
        ctx.fillStyle = '#' + config.color.toString(16).padStart(6, '0');
        ctx.beginPath();
        ctx.arc(x, z, 2, 0, Math.PI * 2);
        ctx.fill();
    });

    ctx.strokeStyle = '#58a6ff44';
    ctx.strokeRect(cx - 15, cy - 10, 30, 20);
}

function setupEventListeners() {
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    document.getElementById('three-canvas').addEventListener('click', (e) => {
        const rect = e.target.getBoundingClientRect();
        mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
        mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
        raycaster.setFromCamera(mouse, camera);
        const meshes = Object.values(nodeMeshes).filter(m => m.visible);
        const intersects = raycaster.intersectObjects(meshes);
        if (intersects.length > 0) {
            const nodeId = intersects[0].object.userData.nodeId;
            if (nodeId) {
                showNodeDetails(nodeId);
            }
        } else {
            clearHighlights();
            selectedNode = null;
            document.getElementById('node-details').innerHTML = '<p class="placeholder-text">Click a node to see details</p>';
        }
    });

    document.getElementById('btn-find-path').addEventListener('click', findPath);

    document.getElementById('btn-report').addEventListener('click', async () => {
        try {
            const resp = await fetch(`${API}/api/report`);
            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'attack_path_report.html';
            a.click();
            URL.revokeObjectURL(url);
        } catch (e) { console.error('Report failed:', e); }
    });

    document.getElementById('three-canvas').addEventListener('dblclick', (e) => {
        const rect = e.target.getBoundingClientRect();
        mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
        mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
        raycaster.setFromCamera(mouse, camera);
        const meshes = Object.values(nodeMeshes).filter(m => m.visible);
        const intersects = raycaster.intersectObjects(meshes);
        if (intersects.length > 0) {
            const nodeId = intersects[0].object.userData.nodeId;
            if (nodeId) focusNode(nodeId);
        }
    });
}

async function init() {
    await fetchData();
    initThreeScene();
    setupEventListeners();
    setupSearch();
    setupFilters();
    renderPaths();
    populateNodeSelects();
}

init();
