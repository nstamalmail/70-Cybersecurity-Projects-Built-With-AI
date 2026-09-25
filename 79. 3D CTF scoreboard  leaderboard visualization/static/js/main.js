const API = '';
let teams = [], challenges = [], solves = [], timeline = [];
let scene, camera, renderer, controls;
let barMeshes = {}, nodeMeshes = [], edgeLines = [];
let isPlaying = true, timelineIndex = 0, animFrame;
let soundEnabled = false;
let audioCtx;

const CATEGORY_COLORS = {
    web: 0x44aaff,
    crypto: 0xffaa44,
    forensics: 0x00ff88,
    reversing: 0xcc88ff,
    pwn: 0xff4466
};

const TEAM_COLORS = [
    0x00ffcc, 0xff00aa, 0xffee00, 0x00aaff, 0x00ff88,
    0xff3366, 0xff8800, 0xaa44ff, 0x44ffaa, 0xff44aa,
    0x88aaff, 0xffaa88, 0x44ffcc, 0xcc44ff, 0xffcc44,
    0x44ccff, 0xff6688, 0x88ff44, 0xaa88ff, 0xff8844
];

async function fetchData() {
    [teams, challenges, solves, timeline] = await Promise.all([
        fetch(`${API}/api/teams`).then(r => r.json()),
        fetch(`${API}/api/challenges`).then(r => r.json()),
        fetch(`${API}/api/solves`).then(r => r.json()),
        fetch(`${API}/api/scoreboard/timeline`).then(r => r.json())
    ]);
    document.getElementById('timeline-slider').max = timeline.length - 1;
}

function initThreeScene() {
    const container = document.getElementById('three-canvas');
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0a0a1a);
    scene.fog = new THREE.FogExp2(0x0a0a1a, 0.015);

    camera = new THREE.PerspectiveCamera(60, container.clientWidth / container.clientHeight, 0.1, 1000);
    camera.position.set(0, 25, 35);

    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(window.devicePixelRatio);
    container.appendChild(renderer.domElement);

    controls = new THREE.OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.maxPolarAngle = Math.PI / 2.2;
    controls.minDistance = 10;
    controls.maxDistance = 80;

    const ambientLight = new THREE.AmbientLight(0x334466, 0.6);
    scene.add(ambientLight);
    const dirLight = new THREE.DirectionalLight(0xffffff, 0.8);
    dirLight.position.set(10, 20, 10);
    scene.add(dirLight);
    const pointLight = new THREE.PointLight(0x00ffcc, 0.5, 50);
    pointLight.position.set(0, 15, 0);
    scene.add(pointLight);

    createGrid();
    createBars();
    createChallengeNodes();

    window.addEventListener('resize', onResize);
    animate();
}

function createGrid() {
    const gridGeo = new THREE.PlaneGeometry(60, 60, 30, 30);
    const gridMat = new THREE.MeshBasicMaterial({ color: 0x00ffcc, wireframe: true, transparent: true, opacity: 0.08 });
    const grid = new THREE.Mesh(gridGeo, gridMat);
    grid.rotation.x = -Math.PI / 2;
    grid.position.y = -0.1;
    scene.add(grid);
}

function createBars() {
    const topTeams = [...teams].sort((a, b) => b.total_score - a.total_score).slice(0, 20);
    const spacing = 2.2;
    const startX = -(topTeams.length * spacing) / 2;

    topTeams.forEach((team, i) => {
        const color = TEAM_COLORS[i % TEAM_COLORS.length];
        const height = 0.1;
        const geo = new THREE.BoxGeometry(1.4, height, 1.4);
        const mat = new THREE.MeshPhongMaterial({
            color: color,
            emissive: color,
            emissiveIntensity: 0.3,
            transparent: true,
            opacity: 0.9,
        });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(startX + i * spacing, height / 2, 0);
        mesh.userData = { teamId: team.id, teamData: team, baseColor: color, targetHeight: 1 };
        scene.add(mesh);

        const edgeGeo = new THREE.EdgesGeometry(geo);
        const edgeMat = new THREE.LineBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.3 });
        const edges = new THREE.LineSegments(edgeGeo, edgeMat);
        mesh.add(edges);

        barMeshes[team.id] = mesh;

        createFloatingLabel(team.name, mesh, color);
    });
}

function createFloatingLabel(text, parent, color) {
    const canvas = document.createElement('canvas');
    canvas.width = 256;
    canvas.height = 64;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = 'rgba(0,0,0,0.6)';
    ctx.roundRect(0, 0, 256, 64, 8);
    ctx.fill();
    ctx.strokeStyle = '#' + color.toString(16).padStart(6, '0');
    ctx.lineWidth = 2;
    ctx.roundRect(0, 0, 256, 64, 8);
    ctx.stroke();
    ctx.font = 'bold 20px Courier New';
    ctx.fillStyle = '#ffffff';
    ctx.textAlign = 'center';
    ctx.fillText(text.substring(0, 14), 128, 28);
    ctx.font = '14px Courier New';
    ctx.fillStyle = '#00ff88';
    ctx.fillText('0 pts', 128, 50);

    const texture = new THREE.CanvasTexture(canvas);
    const spriteMat = new THREE.SpriteMaterial({ map: texture, transparent: true });
    const sprite = new THREE.Sprite(spriteMat);
    sprite.scale.set(4, 1, 1);
    sprite.position.y = 2;
    sprite.userData = { isLabel: true, canvas: canvas, texture: texture, scoreText: '' };
    parent.add(sprite);
}

function createChallengeNodes() {
    const categories = [...new Set(challenges.map(c => c.category))];
    const radius = 18;

    categories.forEach((cat, ci) => {
        const catChallenges = challenges.filter(c => c.category === cat);
        const angleOffset = (ci / categories.length) * Math.PI * 2;

        catChallenges.forEach((ch, chi) => {
            const angle = angleOffset + (chi / catChallenges.length) * (Math.PI * 2 / categories.length);
            const x = Math.cos(angle) * radius;
            const z = Math.sin(angle) * radius;

            const geo = new THREE.OctahedronGeometry(0.5, 0);
            const color = CATEGORY_COLORS[cat] || 0xffffff;
            const mat = new THREE.MeshPhongMaterial({
                color: color,
                emissive: color,
                emissiveIntensity: 0.4,
                transparent: true,
                opacity: 0.8,
            });
            const mesh = new THREE.Mesh(geo, mat);
            mesh.position.set(x, 1, z);
            mesh.userData = { challengeId: ch.id, challengeData: ch, solved: false };
            scene.add(mesh);

            const glowGeo = new THREE.SphereGeometry(0.8, 8, 8);
            const glowMat = new THREE.MeshBasicMaterial({ color: color, transparent: true, opacity: 0.1 });
            const glow = new THREE.Mesh(glowGeo, glowMat);
            mesh.add(glow);

            nodeMeshes.push(mesh);
        });
    });
}

function updateBars(scores) {
    const maxScore = Math.max(...Object.values(scores), 1);
    Object.keys(barMeshes).forEach(teamId => {
        const mesh = barMeshes[teamId];
        const score = scores[parseInt(teamId)] || 0;
        const targetHeight = Math.max((score / maxScore) * 18, 0.1);

        mesh.userData.targetHeight = targetHeight;

        const currentHeight = mesh.scale.y * mesh.geometry.parameters.height;
        const newHeight = currentHeight + (targetHeight - currentHeight) * 0.1;
        mesh.scale.y = Math.max(newHeight / mesh.geometry.parameters.height, 0.01);
        mesh.position.y = (mesh.scale.y * mesh.geometry.parameters.height) / 2;

        mesh.children.forEach(child => {
            if (child.userData && child.userData.isLabel) {
                const canvas = child.userData.canvas;
                const ctx = canvas.getContext('2d');
                ctx.clearRect(0, 0, 256, 64);
                ctx.fillStyle = 'rgba(0,0,0,0.6)';
                ctx.roundRect(0, 0, 256, 64, 8);
                ctx.fill();
                ctx.strokeStyle = '#' + mesh.userData.baseColor.toString(16).padStart(6, '0');
                ctx.lineWidth = 2;
                ctx.roundRect(0, 0, 256, 64, 8);
                ctx.stroke();
                ctx.font = 'bold 20px Courier New';
                ctx.fillStyle = '#ffffff';
                ctx.textAlign = 'center';
                const teamData = teams.find(t => t.id === parseInt(teamId));
                ctx.fillText(teamData ? teamData.name.substring(0, 14) : '', 128, 28);
                ctx.font = '14px Courier New';
                ctx.fillStyle = '#00ff88';
                ctx.fillText(score + ' pts', 128, 50);
                child.userData.texture.needsUpdate = true;
            }
        });
    });
}

function animate() {
    animFrame = requestAnimationFrame(animate);
    controls.update();

    const time = Date.now() * 0.001;
    nodeMeshes.forEach((mesh, i) => {
        mesh.rotation.y = time * 0.5 + i;
        mesh.position.y = 1 + Math.sin(time * 2 + i) * 0.2;
    });

    Object.values(barMeshes).forEach(mesh => {
        const currentScale = mesh.scale.y;
        const target = mesh.userData.targetHeight / mesh.geometry.parameters.height;
        const newScale = currentScale + (target - currentScale) * 0.08;
        mesh.scale.y = Math.max(newScale, 0.01);
        mesh.position.y = (mesh.scale.y * mesh.geometry.parameters.height) / 2;
    });

    renderer.render(scene, camera);
}

function onResize() {
    const container = document.getElementById('three-canvas');
    camera.aspect = container.clientWidth / container.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(container.clientWidth, container.clientHeight);
}

function renderLeaderboard(scores) {
    const sorted = teams.map(t => ({ ...t, current_score: scores[t.id] || 0 }))
        .sort((a, b) => b.current_score - a.current_score);

    const container = document.getElementById('leaderboard-list');
    container.innerHTML = sorted.slice(0, 15).map((t, i) => `
        <div class="leaderboard-entry ${i < 3 ? 'rank-' + (i + 1) : ''}" data-team-id="${t.id}">
            <span class="lb-rank">#${i + 1}</span>
            <span class="lb-name">${t.name}</span>
            <span class="lb-score">${t.current_score}</span>
        </div>
    `).join('');

    container.querySelectorAll('.leaderboard-entry').forEach(el => {
        el.addEventListener('click', () => showTeamPopup(parseInt(el.dataset.teamId)));
    });
}

function renderFeed(limit = 15) {
    const sorted = [...solves].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    const container = document.getElementById('solve-feed');
    container.innerHTML = sorted.slice(0, limit).map(s => {
        const team = teams.find(t => t.id === s.team_id);
        const challenge = challenges.find(c => c.id === s.challenge_id);
        if (!team || !challenge) return '';
        const time = new Date(s.timestamp).toLocaleTimeString();
        return `
            <div class="feed-entry">
                <div><span class="feed-team">${team.name}</span> solved <span class="feed-challenge">${challenge.name}</span></div>
                <div class="feed-meta">
                    <span class="feed-category cat-${challenge.category}">${challenge.category}</span>
                    <span>+${s.points} pts</span>
                    <span>${time}</span>
                </div>
            </div>
        `;
    }).join('');
}

function renderCategories() {
    const catTotals = {};
    const catMax = {};
    challenges.forEach(c => {
        catTotals[c.category] = (catTotals[c.category] || 0) + c.points;
    });
    const maxCat = Math.max(...Object.values(catTotals));

    const container = document.getElementById('category-breakdown');
    container.innerHTML = Object.entries(catTotals).map(([cat, total]) => `
        <div class="cat-stat" style="background: ${getCatBg(cat)}">
            <div class="cat-stat-name">${cat}</div>
            <div class="cat-stat-score" style="color: ${getCatColor(cat)}">${total}</div>
            <div class="cat-stat-bar">
                <div class="cat-stat-fill" style="width: ${(total / maxCat) * 100}%; background: ${getCatColor(cat)}"></div>
            </div>
        </div>
    `).join('');
}

function renderChallengeGraph() {
    const container = document.getElementById('challenge-graph');
    container.innerHTML = challenges.map(c => {
        const solveCount = solves.filter(s => s.challenge_id === c.id).length;
        const isSolved = solveCount > 0;
        return `
            <div class="challenge-node ${isSolved ? 'solved' : 'unsolved'}"
                 style="background: ${getCatBg(c.category)}; color: ${getCatColor(c.category)}"
                 data-challenge-id="${c.id}" title="${c.name} (${c.points} pts) - ${solveCount} solves">
                ${c.points}
            </div>
        `;
    }).join('');

    container.querySelectorAll('.challenge-node').forEach(el => {
        el.addEventListener('click', () => {
            const chId = parseInt(el.dataset.challengeId);
            const ch = challenges.find(c => c.id === chId);
            if (ch) {
                const solvedBy = solves.filter(s => s.challenge_id === chId);
                alert(`${ch.name}\nCategory: ${ch.category}\nPoints: ${ch.points}\nDifficulty: ${ch.difficulty}\nSolves: ${solvedBy.length}`);
            }
        });
    });
}

function getCatBg(cat) {
    const map = {
        web: 'rgba(68,170,255,0.15)',
        crypto: 'rgba(255,170,68,0.15)',
        forensics: 'rgba(0,255,136,0.15)',
        reversing: 'rgba(204,136,255,0.15)',
        pwn: 'rgba(255,68,102,0.15)'
    };
    return map[cat] || 'rgba(255,255,255,0.1)';
}

function getCatColor(cat) {
    const map = {
        web: '#44aaff',
        crypto: '#ffaa44',
        forensics: '#00ff88',
        reversing: '#cc88ff',
        pwn: '#ff4466'
    };
    return map[cat] || '#ffffff';
}

function showTeamPopup(teamId) {
    const team = teams.find(t => t.id === teamId);
    if (!team) return;
    const teamSolves = solves.filter(s => s.team_id === teamId);
    const catBreakdown = {};
    teamSolves.forEach(s => {
        const ch = challenges.find(c => c.id === s.challenge_id);
        if (ch) {
            catBreakdown[ch.category] = (catBreakdown[ch.category] || 0) + s.points;
        }
    });

    const popup = document.getElementById('team-popup');
    const body = document.getElementById('popup-body');
    body.innerHTML = `
        <div class="popup-team-name">${team.name}</div>
        <div class="popup-affiliation">${team.affiliation}</div>
        <div class="popup-score">${team.total_score} PTS</div>
        <div class="popup-stats">
            <div class="popup-stat"><div class="popup-stat-value">${teamSolves.length}</div><div class="popup-stat-label">Solves</div></div>
            <div class="popup-stat"><div class="popup-stat-value">${Object.keys(catBreakdown).length}</div><div class="popup-stat-label">Categories</div></div>
            ${Object.entries(catBreakdown).map(([cat, pts]) => `
                <div class="popup-stat"><div class="popup-stat-value" style="color:${getCatColor(cat)}">${pts}</div><div class="popup-stat-label">${cat.toUpperCase()}</div></div>
            `).join('')}
        </div>
        <div class="popup-solves-title">RECENT SOLVES</div>
        ${teamSolves.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 10).map(s => {
            const ch = challenges.find(c => c.id === s.challenge_id);
            return ch ? `<div class="popup-solve"><span>${ch.name}</span><span>+${s.points}</span></div>` : '';
        }).join('')}
    `;
    popup.classList.remove('hidden');
}

function playTickSound() {
    if (!soundEnabled) return;
    try {
        if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.frequency.value = 880;
        osc.type = 'sine';
        gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.15);
        osc.start(audioCtx.currentTime);
        osc.stop(audioCtx.currentTime + 0.15);
    } catch (e) {}
}

function stepTimeline(index) {
    if (index < 0 || index >= timeline.length) return;
    timelineIndex = index;
    const entry = timeline[index];
    updateBars(entry.scores_after);
    renderLeaderboard(entry.scores_after);
    document.getElementById('timeline-slider').value = index;
    const time = new Date(entry.timestamp);
    document.getElementById('current-time').textContent = time.toLocaleTimeString();

    Object.keys(barMeshes).forEach(teamId => {
        if (entry.team_id === parseInt(teamId)) {
            const mesh = barMeshes[teamId];
            const origIntensity = mesh.material.emissiveIntensity;
            mesh.material.emissiveIntensity = 1.0;
            setTimeout(() => { mesh.material.emissiveIntensity = origIntensity; }, 300);
        }
    });

    const node = nodeMeshes.find(n => n.userData.challengeId === entry.challenge_id);
    if (node) {
        node.material.emissiveIntensity = 1.5;
        node.scale.set(1.5, 1.5, 1.5);
        setTimeout(() => {
            node.material.emissiveIntensity = 0.4;
            node.scale.set(1, 1, 1);
            node.userData.solved = true;
        }, 500);
    }

    playTickSound();
}

function autoPlay() {
    if (!isPlaying) return;
    if (timelineIndex < timeline.length - 1) {
        timelineIndex++;
        stepTimeline(timelineIndex);
    } else {
        isPlaying = false;
        document.getElementById('btn-play').classList.remove('active');
    }
    setTimeout(autoPlay, 800);
}

function setupControls() {
    document.getElementById('btn-play').addEventListener('click', () => {
        isPlaying = true;
        document.getElementById('btn-play').classList.add('active');
        document.getElementById('btn-pause').classList.remove('active');
        autoPlay();
    });

    document.getElementById('btn-pause').addEventListener('click', () => {
        isPlaying = false;
        document.getElementById('btn-pause').classList.add('active');
        document.getElementById('btn-play').classList.remove('active');
    });

    document.getElementById('btn-restart').addEventListener('click', () => {
        timelineIndex = 0;
        isPlaying = false;
        document.getElementById('btn-play').classList.remove('active');
        document.getElementById('btn-pause').classList.remove('active');
        Object.keys(barMeshes).forEach(id => {
            const mesh = barMeshes[id];
            mesh.scale.y = 0.01;
            mesh.position.y = 0.005;
        });
        stepTimeline(0);
    });

    document.getElementById('timeline-slider').addEventListener('input', (e) => {
        isPlaying = false;
        document.getElementById('btn-play').classList.remove('active');
        stepTimeline(parseInt(e.target.value));
    });

    document.getElementById('btn-sound').addEventListener('click', () => {
        soundEnabled = !soundEnabled;
        document.getElementById('btn-sound').textContent = soundEnabled ? '\uD83D\uDD0A' : '\uD83D\uDD07';
    });

    document.getElementById('btn-fullscreen').addEventListener('click', () => {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen();
        } else {
            document.exitFullscreen();
        }
    });

    document.getElementById('btn-report').addEventListener('click', async () => {
        try {
            const resp = await fetch(`${API}/api/report`);
            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'ctf_report.html';
            a.click();
            URL.revokeObjectURL(url);
        } catch (e) {
            console.error('Report generation failed:', e);
        }
    });

    document.querySelector('.popup-close').addEventListener('click', () => {
        document.getElementById('team-popup').classList.add('hidden');
    });

    document.getElementById('team-popup').addEventListener('click', (e) => {
        if (e.target === document.getElementById('team-popup')) {
            document.getElementById('team-popup').classList.add('hidden');
        }
    });
}

async function init() {
    await fetchData();
    initThreeScene();
    setupControls();
    renderLeaderboard({});
    renderFeed();
    renderCategories();
    renderChallengeGraph();
    stepTimeline(timeline.length - 1);
    isPlaying = true;
    document.getElementById('btn-play').classList.add('active');
    autoPlay();
}

init();
