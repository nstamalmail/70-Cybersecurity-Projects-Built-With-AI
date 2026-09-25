let scene, camera, renderer, particles, floatingShapes = [];
let mouseX = 0, mouseY = 0;
let targetRotationX = 0, targetRotationY = 0;
let currentSection = 'home';
let animationId;

function init() {
    scene = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.z = 5;

    renderer = new THREE.WebGLRenderer({ canvas: document.getElementById('bg-canvas'), antialias: true, alpha: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x0a0a0f, 1);

    createLights();
    createParticles();
    createFloatingShapes();

    document.addEventListener('mousemove', onMouseMove);
    window.addEventListener('resize', onResize);

    animate();
    setTimeout(() => document.getElementById('loading-screen').classList.add('hidden'), 800);
}

function createLights() {
    const ambient = new THREE.AmbientLight(0x404040, 0.5);
    scene.add(ambient);

    const point1 = new THREE.PointLight(0x64ffda, 1.5, 50);
    point1.position.set(5, 5, 5);
    scene.add(point1);

    const point2 = new THREE.PointLight(0x6366f1, 1, 50);
    point2.position.set(-5, -3, 3);
    scene.add(point2);
}

function createParticles() {
    const count = 1500;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(count * 3);
    const colors = new Float32Array(count * 3);

    for (let i = 0; i < count; i++) {
        positions[i * 3] = (Math.random() - 0.5) * 20;
        positions[i * 3 + 1] = (Math.random() - 0.5) * 20;
        positions[i * 3 + 2] = (Math.random() - 0.5) * 20;

        const c = new THREE.Color();
        c.setHSL(0.47 + Math.random() * 0.1, 0.8, 0.5 + Math.random() * 0.3);
        colors[i * 3] = c.r;
        colors[i * 3 + 1] = c.g;
        colors[i * 3 + 2] = c.b;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
        size: 0.03,
        vertexColors: true,
        transparent: true,
        opacity: 0.7,
        blending: THREE.AdditiveBlending,
    });

    particles = new THREE.Points(geometry, material);
    scene.add(particles);
}

function createFloatingShapes() {
    const shapes = [];
    const geometries = [
        new THREE.BoxGeometry(0.5, 0.5, 0.5),
        new THREE.SphereGeometry(0.3, 16, 16),
        new THREE.TorusGeometry(0.3, 0.1, 12, 24),
        new THREE.OctahedronGeometry(0.35),
        new THREE.TetrahedronGeometry(0.35),
    ];

    for (let i = 0; i < 15; i++) {
        const geo = geometries[Math.floor(Math.random() * geometries.length)];
        const color = Math.random() > 0.5 ? 0x64ffda : 0x6366f1;
        const mat = new THREE.MeshPhongMaterial({
            color: color,
            wireframe: Math.random() > 0.4,
            transparent: true,
            opacity: 0.6 + Math.random() * 0.3,
        });

        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(
            (Math.random() - 0.5) * 10,
            (Math.random() - 0.5) * 6,
            (Math.random() - 0.5) * 4 - 2
        );
        mesh.userData = {
            rotSpeed: { x: (Math.random() - 0.5) * 0.02, y: (Math.random() - 0.5) * 0.02 },
            floatSpeed: Math.random() * 0.5 + 0.3,
            floatOffset: Math.random() * Math.PI * 2,
            originalY: mesh.position.y,
        };

        scene.add(mesh);
        floatingShapes.push(mesh);
    }
}

function onMouseMove(e) {
    mouseX = (e.clientX / window.innerWidth) * 2 - 1;
    mouseY = -(e.clientY / window.innerHeight) * 2 + 1;
}

function onResize() {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
}

function animate() {
    animationId = requestAnimationFrame(animate);

    targetRotationY += (mouseX * 0.3 - targetRotationY) * 0.02;
    targetRotationX += (mouseY * 0.2 - targetRotationX) * 0.02;

    camera.rotation.y = targetRotationY;
    camera.rotation.x = targetRotationX;

    if (particles) {
        particles.rotation.y += 0.0003;
        particles.rotation.x += 0.0001;
    }

    const time = Date.now() * 0.001;
    floatingShapes.forEach(shape => {
        shape.rotation.x += shape.userData.rotSpeed.x;
        shape.rotation.y += shape.userData.rotSpeed.y;
        shape.position.y = shape.userData.originalY + Math.sin(time * shape.userData.floatSpeed + shape.userData.floatOffset) * 0.3;
    });

    renderer.render(scene, camera);
}

/* Navigation */
function navigateTo(section) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));

    document.getElementById(section).classList.add('active');
    document.querySelector(`[data-section="${section}"]`).classList.add('active');
    currentSection = section;

    document.querySelector('.nav-links').classList.remove('open');

    if (section === 'projects') loadProjects();
    if (section === 'analytics') loadAnalytics();
}

document.querySelectorAll('.nav-btn[data-section]').forEach(btn => {
    btn.addEventListener('click', e => {
        e.preventDefault();
        navigateTo(btn.dataset.section);
    });
});

document.getElementById('hamburger').addEventListener('click', () => {
    document.querySelector('.nav-links').classList.toggle('open');
});

/* Projects */
let allProjects = [];

async function loadProjects() {
    if (allProjects.length === 0) {
        const res = await fetch('/api/projects');
        allProjects = await res.json();
    }
    renderProjects(allProjects);
}

function renderProjects(projects) {
    const grid = document.getElementById('projects-grid');
    document.getElementById('project-detail').classList.add('hidden');
    grid.style.display = '';

    grid.innerHTML = projects.map(p => `
        <div class="project-card" onclick="showProjectDetail(${p.id})">
            ${p.featured ? '<div class="featured-badge">FEATURED</div>' : ''}
            <h3>${p.title}</h3>
            <div class="category">${p.category} &bull; ${p.year}</div>
            <p>${p.description}</p>
            <div class="tech-stack">${p.tech_stack.map(t => `<span class="badge">${t}</span>`).join('')}</div>
        </div>
    `).join('');
}

async function showProjectDetail(id) {
    const res = await fetch(`/api/projects/${id}`);
    const p = await res.json();
    document.getElementById('projects-grid').style.display = 'none';
    document.getElementById('project-detail').classList.remove('hidden');
    document.getElementById('project-detail-content').innerHTML = `
        <h2 style="font-size:32px;margin-bottom:10px;">${p.title}</h2>
        <p style="color:var(--accent);margin-bottom:20px;">${p.category} &bull; ${p.year} ${p.featured ? '&bull; ★ Featured' : ''}</p>
        <p style="line-height:1.7;color:var(--text-secondary);margin-bottom:20px;">${p.description}</p>
        <div style="margin-bottom:20px;">${p.tech_stack.map(t => `<span class="badge" style="font-size:13px;padding:5px 14px;">${t}</span>`).join(' ')}</div>
        <a href="${p.link}" target="_blank" class="cta-btn" style="text-decoration:none;display:inline-block;">View on GitHub &rarr;</a>
    `;
}

function closeProjectDetail() {
    document.getElementById('project-detail').classList.add('hidden');
    document.getElementById('projects-grid').style.display = '';
}

/* Filters */
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const filter = btn.dataset.filter;
        if (filter === 'featured') {
            renderProjects(allProjects.filter(p => p.featured));
        } else {
            renderProjects(allProjects);
        }
    });
});

/* Analytics */
async function loadAnalytics() {
    const res = await fetch('/api/analytics');
    const a = await res.json();
    const container = document.getElementById('analytics-content');

    const sourceItems = a.visitor_sources.map(s => `
        <li>
            <span>${s.source}</span>
            <span>${s.count.toLocaleString()} (${s.percentage}%)</span>
        </li>
        <li style="padding:0;">
            <div class="source-bar"><div class="source-bar-fill" style="width:${s.percentage}%"></div></div>
        </li>
    `).join('');

    container.innerHTML = `
        <div class="analytics-card">
            <h3>Total Visitors</h3>
            <div class="big-value">${a.total_visitors.toLocaleString()}</div>
            <div class="sub-value">${a.unique_visitors.toLocaleString()} unique</div>
        </div>
        <div class="analytics-card">
            <h3>Page Views</h3>
            <div class="big-value">${a.page_views.toLocaleString()}</div>
            <div class="sub-value">${a.avg_session_duration}s avg session</div>
        </div>
        <div class="analytics-card">
            <h3>Bounce Rate</h3>
            <div class="big-value">${a.bounce_rate}%</div>
            <div class="sub-value">${a.engagement.avg_pages_per_session} pages/session</div>
        </div>
        <div class="analytics-card">
            <h3>Returning Visitors</h3>
            <div class="big-value">${a.engagement.returning_visitors.toLocaleString()}</div>
            <div class="sub-value">${((a.engagement.returning_visitors / a.total_visitors) * 100).toFixed(1)}% return rate</div>
        </div>
        <div class="analytics-card analytics-full">
            <h3>Traffic Sources</h3>
            <ul class="source-list">${sourceItems}</ul>
        </div>
        <div class="analytics-card analytics-full">
            <h3>Monthly Visits</h3>
            <div style="display:flex;align-items:end;gap:8px;height:150px;margin-top:10px;">
                ${a.monthly_visits.map(m => {
                    const h = (m.visits / Math.max(...a.monthly_visits.map(x => x.visits))) * 120;
                    return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;">
                        <span style="font-size:11px;color:var(--accent);margin-bottom:4px;">${m.visits}</span>
                        <div style="width:100%;height:${h}px;background:var(--accent);border-radius:4px 4px 0 0;opacity:0.7;"></div>
                        <span style="font-size:10px;color:var(--text-secondary);margin-top:4px;">${m.month.split('-')[1]}</span>
                    </div>`;
                }).join('')}
            </div>
        </div>
        <div class="analytics-card">
            <h3>Device Breakdown</h3>
            ${a.device_breakdown.map(d => `
                <div style="margin:8px 0;">
                    <div style="display:flex;justify-content:space-between;font-size:13px;">
                        <span>${d.device}</span><span style="color:var(--accent)">${d.percentage}%</span>
                    </div>
                    <div class="source-bar"><div class="source-bar-fill" style="width:${d.percentage}%"></div></div>
                </div>
            `).join('')}
        </div>
        <div class="analytics-card">
            <h3>Browser Breakdown</h3>
            ${a.browser_breakdown.map(b => `
                <div style="margin:8px 0;">
                    <div style="display:flex;justify-content:space-between;font-size:13px;">
                        <span>${b.browser}</span><span style="color:var(--accent)">${b.percentage}%</span>
                    </div>
                    <div class="source-bar"><div class="source-bar-fill" style="width:${b.percentage}%"></div></div>
                </div>
            `).join('')}
        </div>
    `;
}

/* Contact Form */
document.getElementById('contact-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const status = document.getElementById('contact-status');

    const name = document.getElementById('contact-name').value.trim();
    const email = document.getElementById('contact-email').value.trim();
    const subject = document.getElementById('contact-subject').value.trim();
    const message = document.getElementById('contact-message').value.trim();

    if (!name || !email || !subject || !message) {
        status.className = 'contact-status error';
        status.textContent = 'Please fill in all fields.';
        return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        status.className = 'contact-status error';
        status.textContent = 'Please enter a valid email address.';
        return;
    }

    try {
        const res = await fetch('/api/contact', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ name, email, subject, message })
        });
        if (res.ok) {
            status.className = 'contact-status success';
            status.textContent = 'Message sent successfully! I\'ll get back to you soon.';
            document.getElementById('contact-form').reset();
        } else {
            throw new Error('Failed');
        }
    } catch {
        status.className = 'contact-status error';
        status.textContent = 'Failed to send message. Please try again.';
    }
});

init();
