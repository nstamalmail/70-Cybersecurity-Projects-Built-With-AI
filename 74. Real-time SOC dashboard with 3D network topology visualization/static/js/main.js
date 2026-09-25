let scene, camera, renderer, controls;
let nodeMeshes = [];
let networkData = null;
let cpuChart, memoryChart, networkChart, categoryChart, incidentsChart;
const raycaster = new THREE.Raycaster();
const mouse = new THREE.Vector2();

document.addEventListener('DOMContentLoaded', init);

async function init() {
    setupNavigation();
    await Promise.all([
        loadOverviewData(),
        loadAlerts(),
        loadIncidents(),
        loadNetworkTopology()
    ]);
    setupEventListeners();
}

function setupNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const section = item.dataset.section;
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
            document.getElementById(`${section}-section`).classList.add('active');
            document.getElementById('page-title').textContent =
                section === 'overview' ? 'SOC Overview' :
                section === 'topology' ? '3D Network Topology' :
                section === 'alerts' ? 'Security Alerts' : 'Active Incidents';
            if (section === 'topology' && !scene) init3DTopology();
        });
    });
}

function setupEventListeners() {
    document.getElementById('filter-severity').addEventListener('change', filterAlerts);
    document.getElementById('filter-status').addEventListener('change', filterAlerts);
    document.getElementById('filter-category').addEventListener('change', filterAlerts);
    document.getElementById('search-input').addEventListener('input', filterAlerts);
    document.getElementById('generate-report').addEventListener('click', () => window.open('/api/report/security', '_blank'));
    document.getElementById('modal-close').addEventListener('click', () => {
        document.getElementById('node-modal').style.display = 'none';
    });
}

async function loadOverviewData() {
    try {
        const [alertsRes, metricsRes] = await Promise.all([
            fetch('/api/alerts'),
            fetch('/api/metrics')
        ]);
        const alerts = await alertsRes.json();
        const metrics = await metricsRes.json();

        document.getElementById('critical-count').textContent = alerts.filter(a => a.severity === 'critical').length;
        document.getElementById('high-count').textContent = alerts.filter(a => a.severity === 'high').length;
        document.getElementById('medium-count').textContent = alerts.filter(a => a.severity === 'medium').length;
        document.getElementById('healthy-nodes').textContent = metrics.overview.nodes_online;
        document.getElementById('alert-count').textContent = metrics.overview.total_alerts;
        document.getElementById('incident-count').textContent = metrics.overview.active_incidents;

        renderOverviewCharts(metrics);
        renderRecentAlerts(alerts.filter(a => a.severity === 'critical').slice(0, 5));
    } catch (err) {
        console.error('Failed to load overview:', err);
    }
}

function renderOverviewCharts(metrics) {
    const chartDefaults = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
            x: { grid: { color: '#30363d' }, ticks: { color: '#8b949e', font: { size: 10 } } },
            y: { grid: { color: '#30363d' }, ticks: { color: '#8b949e', font: { size: 10 } } }
        }
    };

    if (cpuChart) cpuChart.destroy();
    cpuChart = new Chart(document.getElementById('cpu-chart'), {
        type: 'line',
        data: {
            labels: metrics.cpu_history.map(h => h.timestamp),
            datasets: [{
                data: metrics.cpu_history.map(h => h.value),
                borderColor: '#00ff88',
                backgroundColor: 'rgba(0, 255, 136, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 2
            }]
        },
        options: { ...chartDefaults, scales: { ...chartDefaults.scales, y: { ...chartDefaults.scales.y, min: 0, max: 100 } } }
    });

    if (memoryChart) memoryChart.destroy();
    memoryChart = new Chart(document.getElementById('memory-chart'), {
        type: 'line',
        data: {
            labels: metrics.memory_history.map(h => h.timestamp),
            datasets: [{
                data: metrics.memory_history.map(h => h.value),
                borderColor: '#58a6ff',
                backgroundColor: 'rgba(88, 166, 255, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 2
            }]
        },
        options: { ...chartDefaults, scales: { ...chartDefaults.scales, y: { ...chartDefaults.scales.y, min: 0, max: 100 } } }
    });

    if (networkChart) networkChart.destroy();
    networkChart = new Chart(document.getElementById('network-chart'), {
        type: 'line',
        data: {
            labels: metrics.network_traffic.map(h => h.timestamp),
            datasets: [
                { label: 'Inbound', data: metrics.network_traffic.map(h => h.inbound), borderColor: '#00ff88', tension: 0.4, pointRadius: 2 },
                { label: 'Outbound', data: metrics.network_traffic.map(h => h.outbound), borderColor: '#ff8800', tension: 0.4, pointRadius: 2 }
            ]
        },
        options: { ...chartDefaults, plugins: { legend: { display: true, labels: { color: '#8b949e' } } } }
    });

    if (categoryChart) categoryChart.destroy();
    categoryChart = new Chart(document.getElementById('category-chart'), {
        type: 'doughnut',
        data: {
            labels: Object.keys(metrics.alerts_by_category),
            datasets: [{
                data: Object.values(metrics.alerts_by_category),
                backgroundColor: ['#ff4444', '#ff8800', '#58a6ff', '#ffcc00', '#00ff88', '#f778ba']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'right', labels: { color: '#8b949e', padding: 12 } } }
        }
    });
}

function renderRecentAlerts(alerts) {
    const container = document.getElementById('recent-alerts-list');
    container.innerHTML = alerts.map(alert => `
        <div class="alert-item ${alert.severity}">
            <span class="alert-severity">${alert.severity}</span>
            <div class="alert-info">
                <div class="alert-type">${alert.type}</div>
                <div class="alert-message">${alert.message}</div>
            </div>
            <div class="alert-time">${formatTime(alert.timestamp)}</div>
        </div>
    `).join('');
}

async function loadAlerts() {
    try {
        const res = await fetch('/api/alerts');
        const alerts = await res.json();
        renderAlertsTable(alerts);
    } catch (err) {
        console.error('Failed to load alerts:', err);
    }
}

function renderAlertsTable(alerts) {
    const tbody = document.getElementById('alerts-table-body');
    tbody.innerHTML = alerts.map(alert => `
        <tr>
            <td><span class="severity-badge ${alert.severity}">${alert.severity}</span></td>
            <td>${alert.type}</td>
            <td>${alert.source}</td>
            <td><code>${alert.ip}</code></td>
            <td>${alert.message}</td>
            <td><span class="status-badge ${alert.status}">${alert.status}</span></td>
            <td>${formatTime(alert.timestamp)}</td>
            <td><button class="action-btn" onclick="updateAlertStatus(${alert.id}, '${alert.status}')">Update</button></td>
        </tr>
    `).join('');
}

async function filterAlerts() {
    const severity = document.getElementById('filter-severity').value;
    const status = document.getElementById('filter-status').value;
    const category = document.getElementById('filter-category').value;
    const search = document.getElementById('search-input').value;

    const params = new URLSearchParams();
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);
    if (category) params.append('category', category);
    if (search) params.append('search', search);

    try {
        const res = await fetch(`/api/alerts?${params}`);
        const alerts = await res.json();
        renderAlertsTable(alerts);
    } catch (err) {
        console.error('Failed to filter alerts:', err);
    }
}

async function updateAlertStatus(alertId, currentStatus) {
    const newStatus = prompt(`Update status for alert ${alertId}:`, currentStatus);
    if (newStatus && newStatus !== currentStatus) {
        try {
            await fetch(`/api/alerts/${alertId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus })
            });
            filterAlerts();
        } catch (err) {
            console.error('Failed to update alert:', err);
        }
    }
}

async function loadIncidents() {
    try {
        const res = await fetch('/api/metrics');
        const metrics = await res.json();
        renderIncidentsChart(metrics.incidents_timeline);
        renderIncidentsList(metrics.active_incidents);
    } catch (err) {
        console.error('Failed to load incidents:', err);
    }
}

function renderIncidentsChart(timeline) {
    if (incidentsChart) incidentsChart.destroy();
    incidentsChart = new Chart(document.getElementById('incidents-chart'), {
        type: 'bar',
        data: {
            labels: timeline.map(d => d.date),
            datasets: [
                { label: 'Critical', data: timeline.map(d => d.critical), backgroundColor: '#ff4444' },
                { label: 'High', data: timeline.map(d => d.high), backgroundColor: '#ff8800' },
                { label: 'Medium', data: timeline.map(d => d.medium), backgroundColor: '#ffcc00' },
                { label: 'Low', data: timeline.map(d => d.low), backgroundColor: '#00ff88' }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#8b949e' } } },
            scales: {
                x: { stacked: true, grid: { color: '#30363d' }, ticks: { color: '#8b949e' } },
                y: { stacked: true, grid: { color: '#30363d' }, ticks: { color: '#8b949e' } }
            }
        }
    });
}

function renderIncidentsList(incidents) {
    const container = document.getElementById('incidents-list');
    container.innerHTML = incidents.map(incident => `
        <div class="incident-item ${incident.severity}">
            <div class="incident-id">${incident.id}</div>
            <div class="incident-title">${incident.title}</div>
            <div class="incident-meta">
                <span class="status-badge ${incident.status}">${incident.status}</span>
                <span class="incident-assignee">${incident.assignee}</span>
                <span class="incident-time">${formatTime(incident.created)}</span>
            </div>
        </div>
    `).join('');
}

async function loadNetworkTopology() {
    try {
        const res = await fetch('/api/network');
        networkData = await res.json();
    } catch (err) {
        console.error('Failed to load network:', err);
    }
}

function init3DTopology() {
    const container = document.getElementById('topology-3d');
    const width = container.clientWidth;
    const height = container.clientHeight;

    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0d1117);

    camera = new THREE.PerspectiveCamera(60, width / height, 0.1, 1000);
    camera.position.set(0, 15, 25);
    camera.lookAt(0, 0, 0);

    renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(width, height);
    container.appendChild(renderer.domElement);

    const ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
    scene.add(ambientLight);
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(10, 20, 10);
    scene.add(directionalLight);

    const gridHelper = new THREE.GridHelper(40, 40, 0x30363d, 0x21262d);
    scene.add(gridHelper);

    if (networkData) createNetworkGraph();

    container.addEventListener('mousemove', onMouseMove);
    container.addEventListener('click', onMouseClick);
    window.addEventListener('resize', () => {
        camera.aspect = container.clientWidth / container.clientHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(container.clientWidth, container.clientHeight);
    });

    animate();
}

function createNetworkGraph() {
    const locationZones = { 'DMZ': -6, 'DC-Core': -2, 'DC-Sec': 2, 'DC-App': 6, 'DC-Data': 10 };
    const statusColors = { healthy: 0x00ff88, warning: 0xffcc00, critical: 0xff4444, offline: 0x484f58 };

    networkData.nodes.forEach((node, i) => {
        const zoneY = locationZones[node.location] || 0;
        const angle = (i / networkData.nodes.length) * Math.PI * 2;
        const radius = 4 + Math.random() * 3;
        const x = Math.cos(angle) * radius;
        const z = Math.sin(angle) * radius;

        let geometry;
        switch (node.type) {
            case 'firewall': geometry = new THREE.BoxGeometry(0.8, 0.8, 0.8); break;
            case 'router': geometry = new THREE.SphereGeometry(0.5, 16, 16); break;
            case 'server': geometry = new THREE.CylinderGeometry(0.4, 0.4, 1, 16); break;
            case 'workstation': geometry = new THREE.BoxGeometry(0.6, 0.3, 0.6); break;
            default: geometry = new THREE.BoxGeometry(0.5, 0.5, 0.5);
        }

        const material = new THREE.MeshPhongMaterial({
            color: statusColors[node.status] || 0x8b949e,
            emissive: statusColors[node.status] || 0x8b949e,
            emissiveIntensity: node.status === 'critical' ? 0.4 : 0.1
        });

        const mesh = new THREE.Mesh(geometry, material);
        mesh.position.set(x, zoneY / 2, z);
        mesh.userData.node = node;
        scene.add(mesh);
        nodeMeshes.push(mesh);
    });

    const edgeMaterial = new THREE.LineBasicMaterial({ color: 0x30363d, transparent: true, opacity: 0.4 });
    networkData.edges.forEach(edge => {
        const sourceNode = nodeMeshes.find(m => m.userData.node.id === edge.source);
        const targetNode = nodeMeshes.find(m => m.userData.node.id === edge.target);
        if (sourceNode && targetNode) {
            const points = [sourceNode.position.clone(), targetNode.position.clone()];
            const geometry = new THREE.BufferGeometry().setFromPoints(points);
            const line = new THREE.Line(geometry, edgeMaterial.clone());
            line.userData = { source: edge.source, target: edge.target };
            scene.add(line);
        }
    });
}

function onMouseMove(event) {
    const container = document.getElementById('topology-3d');
    const rect = container.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(nodeMeshes);

    const tooltip = document.getElementById('node-tooltip');
    if (intersects.length > 0) {
        const node = intersects[0].object.userData.node;
        tooltip.style.display = 'block';
        tooltip.style.left = (event.clientX - rect.left + 15) + 'px';
        tooltip.style.top = (event.clientY - rect.top + 15) + 'px';
        tooltip.innerHTML = `
            <div class="tooltip-label">${node.label}</div>
            <div class="tooltip-type">${node.type.toUpperCase()} - ${node.location}</div>
            <div class="tooltip-stats">
                <div class="tooltip-stat"><span class="stat-key">Status:</span><span class="stat-val">${node.status}</span></div>
                <div class="tooltip-stat"><span class="stat-key">IP:</span><span class="stat-val">${node.ip}</span></div>
                <div class="tooltip-stat"><span class="stat-key">CPU:</span><span class="stat-val">${node.cpu}%</span></div>
                <div class="tooltip-stat"><span class="stat-key">Memory:</span><span class="stat-val">${node.memory}%</span></div>
            </div>
        `;
    } else {
        tooltip.style.display = 'none';
    }
}

function onMouseClick(event) {
    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(nodeMeshes);
    if (intersects.length > 0) {
        const node = intersects[0].object.userData.node;
        const modal = document.getElementById('node-modal');
        document.getElementById('modal-title').textContent = `${node.label} - ${node.type.toUpperCase()}`;
        document.getElementById('modal-details').innerHTML = `
            <div class="modal-detail"><span class="detail-label">Status</span><span class="detail-value">${node.status}</span></div>
            <div class="modal-detail"><span class="detail-label">IP Address</span><span class="detail-value">${node.ip}</span></div>
            <div class="modal-detail"><span class="detail-label">Location</span><span class="detail-value">${node.location}</span></div>
            <div class="modal-detail"><span class="detail-label">CPU Usage</span><span class="detail-value">${node.cpu}%</span></div>
            <div class="modal-detail"><span class="detail-label">Memory Usage</span><span class="detail-value">${node.memory}%</span></div>
            <div class="modal-detail"><span class="detail-label">Uptime</span><span class="detail-value">${node.uptime}</span></div>
        `;
        modal.style.display = 'flex';
    }
}

function animate() {
    requestAnimationFrame(animate);

    const time = Date.now() * 0.001;
    scene.children.forEach(child => {
        if (child.isMesh) {
            child.material.emissiveIntensity = child.userData.node?.status === 'critical'
                ? 0.3 + Math.sin(time * 3) * 0.2
                : 0.1;
        }
    });

    if (camera) {
        camera.position.x = Math.sin(time * 0.1) * 25;
        camera.position.z = Math.cos(time * 0.1) * 25;
        camera.lookAt(0, 0, 0);
    }

    renderer.render(scene, camera);
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return date.toLocaleDateString();
}
