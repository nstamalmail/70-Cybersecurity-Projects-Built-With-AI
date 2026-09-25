let scene, camera, renderer, controls;
let rooms = [];
let currentRoom = null;
let interactiveObjects = [];
let evidenceCollected = [];
let decisions = [];
let score = 0;
let timer = 0;
let timerInterval = null;
let isPlaying = false;
let scenarioData = null;
let sessionId = null;
let moveForward = false, moveBackward = false, moveLeft = false, moveRight = false;
let velocity = new THREE.Vector3();
let direction = new THREE.Vector3();
let raycaster = new THREE.Raycaster();
let mouse = new THREE.Vector2();
let interactableObject = null;
let floor, walls = [];

const API_BASE = '';

async function init() {
    await loadScenario('ransomware_001');
    initThree();
    initControls();
    initUI();
    startTimer();
    animate();
}

async function loadScenario(scenarioId) {
    try {
        const response = await fetch(`${API_BASE}/api/scenarios/${scenarioId}`);
        scenarioData = await response.json();
        
        document.getElementById('scenario-title').textContent = scenarioData.title;
        document.getElementById('scenario-description').textContent = scenarioData.description;
        
        await startSession(scenarioId);
    } catch (error) {
        console.error('Failed to load scenario:', error);
        showNotification('Failed to load scenario', true);
    }
}

async function startSession(scenarioId) {
    try {
        const response = await fetch(`${API_BASE}/api/sessions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                scenario_id: scenarioId,
                trainee: 'Training User',
                department: 'Security Operations'
            })
        });
        const data = await response.json();
        sessionId = data.id;
    } catch (error) {
        console.error('Failed to start session:', error);
    }
}

function initThree() {
    const container = document.getElementById('canvas-container');
    
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0a0a0f);
    scene.fog = new THREE.Fog(0x0a0a0f, 10, 50);
    
    camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.set(0, 1.6, 3);
    
    renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(window.devicePixelRatio);
    renderer.shadowMap.enabled = true;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    container.appendChild(renderer.domElement);
    
    const ambientLight = new THREE.AmbientLight(0x404040, 0.5);
    scene.add(ambientLight);
    
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(5, 10, 5);
    directionalLight.castShadow = true;
    directionalLight.shadow.mapSize.width = 2048;
    directionalLight.shadow.mapSize.height = 2048;
    scene.add(directionalLight);
    
    buildEnvironment();
    
    window.addEventListener('resize', onWindowResize);
    document.addEventListener('keydown', onKeyDown);
    document.addEventListener('keyup', onKeyUp);
    document.addEventListener('mousemove', onMouseMove);
    document.addEventListener('click', onMouseClick);
}

function buildEnvironment() {
    if (!scenarioData || !scenarioData.rooms) return;
    
    scenarioData.rooms.forEach(roomData => {
        const room = createRoom(roomData);
        rooms.push(room);
    });
    
    if (rooms.length > 0) {
        setCurrentRoom(rooms[0]);
    }
}

function createRoom(roomData) {
    const roomGroup = new THREE.Group();
    roomGroup.userData = roomData;
    
    const { position, size } = roomData;
    
    const floorGeometry = new THREE.PlaneGeometry(size.width, size.depth);
    const floorMaterial = new THREE.MeshPhongMaterial({ 
        color: 0x1a1a2e,
        side: THREE.DoubleSide
    });
    floor = new THREE.Mesh(floorGeometry, floorMaterial);
    floor.rotation.x = -Math.PI / 2;
    floor.position.set(position.x, position.y, position.z);
    floor.receiveShadow = true;
    floor.userData.roomId = roomData.id;
    roomGroup.add(floor);
    
    const wallMaterial = new THREE.MeshPhongMaterial({ 
        color: 0x16213e,
        side: THREE.DoubleSide
    });
    
    const wallPositions = [
        { pos: [position.x, position.y + size.height/2, position.z - size.depth/2], rot: [0, 0, 0], size: [size.width, size.height] },
        { pos: [position.x, position.y + size.height/2, position.z + size.depth/2], rot: [0, Math.PI, 0], size: [size.width, size.height] },
        { pos: [position.x - size.width/2, position.y + size.height/2, position.z], rot: [0, Math.PI/2, 0], size: [size.depth, size.height] },
        { pos: [position.x + size.width/2, position.y + size.height/2, position.z], rot: [0, -Math.PI/2, 0], size: [size.depth, size.height] }
    ];
    
    wallPositions.forEach(wallData => {
        const wallGeometry = new THREE.PlaneGeometry(wallData.size[0], wallData.size[1]);
        const wall = new THREE.Mesh(wallGeometry, wallMaterial);
        wall.position.set(...wallData.pos);
        wall.rotation.set(...wallData.rot);
        wall.receiveShadow = true;
        roomGroup.add(wall);
        walls.push(wall);
    });
    
    const ceilingGeometry = new THREE.PlaneGeometry(size.width, size.depth);
    const ceilingMaterial = new THREE.MeshPhongMaterial({ 
        color: 0x0f3460,
        side: THREE.DoubleSide
    });
    const ceiling = new THREE.Mesh(ceilingGeometry, ceilingMaterial);
    ceiling.rotation.x = Math.PI / 2;
    ceiling.position.set(position.x, position.y + size.height, position.z);
    roomGroup.add(ceiling);
    
    roomData.objects.forEach(objData => {
        const obj = createInteractiveObject(objData);
        roomGroup.add(obj);
        interactiveObjects.push(obj);
    });
    
    scene.add(roomGroup);
    
    createDoorways(roomData, roomGroup);
    
    return roomGroup;
}

function createInteractiveObject(objData) {
    const group = new THREE.Group();
    group.userData = objData;
    
    const { type, position } = objData;
    let geometry, material;
    
    const interactiveMaterial = new THREE.MeshPhongMaterial({ 
        color: 0x00d9ff,
        emissive: 0x003344,
        emissiveIntensity: 0.3
    });
    
    switch(type) {
        case 'computer':
            geometry = new THREE.BoxGeometry(0.8, 0.6, 0.05);
            const monitor = new THREE.Mesh(geometry, interactiveMaterial);
            monitor.position.set(0, 0.4, 0);
            monitor.castShadow = true;
            group.add(monitor);
            
            const standGeometry = new THREE.CylinderGeometry(0.05, 0.1, 0.3, 8);
            const stand = new THREE.Mesh(standGeometry, interactiveMaterial);
            stand.position.set(0, 0.1, 0);
            group.add(stand);
            
            const screenGeometry = new THREE.PlaneGeometry(0.7, 0.5);
            const screenMaterial = new THREE.MeshPhongMaterial({ 
                color: 0x001122,
                emissive: 0x001122,
                emissiveIntensity: 0.5
            });
            const screen = new THREE.Mesh(screenGeometry, screenMaterial);
            screen.position.set(0, 0.4, 0.03);
            group.add(screen);
            break;
            
        case 'file':
            geometry = new THREE.BoxGeometry(0.3, 0.05, 0.4);
            material = new THREE.MeshPhongMaterial({ color: 0x8B4513 });
            const file = new THREE.Mesh(geometry, material);
            file.position.set(0, 0.1, 0);
            file.castShadow = true;
            group.add(file);
            break;
            
        case 'phone':
            geometry = new THREE.BoxGeometry(0.15, 0.05, 0.25);
            material = new THREE.MeshPhongMaterial({ color: 0x333333 });
            const phone = new THREE.Mesh(geometry, material);
            phone.position.set(0, 0.05, 0);
            phone.castShadow = true;
            group.add(phone);
            break;
            
        default:
            geometry = new THREE.BoxGeometry(0.5, 0.5, 0.5);
            material = new THREE.MeshPhongMaterial({ color: 0x666666 });
            const defaultObj = new THREE.Mesh(geometry, material);
            defaultObj.castShadow = true;
            group.add(defaultObj);
    }
    
    group.position.set(position.x, position.y, position.z);
    if (objData.rotation) {
        group.rotation.y = THREE.MathUtils.degToRad(objData.rotation);
    }
    
    const glowGeometry = new THREE.SphereGeometry(0.1, 16, 16);
    const glowMaterial = new THREE.MeshBasicMaterial({ 
        color: 0x00d9ff,
        transparent: true,
        opacity: 0.6
    });
    const glow = new THREE.Mesh(glowGeometry, glowMaterial);
    glow.position.set(0, 0.8, 0);
    group.add(glow);
    
    return group;
}

function createDoorways(roomData, roomGroup) {
    const doorwayGeometry = new THREE.PlaneGeometry(1.5, 2.5);
    const doorwayMaterial = new THREE.MeshBasicMaterial({ 
        color: 0x001122,
        transparent: true,
        opacity: 0.3,
        side: THREE.DoubleSide
    });
    
    const doorway = new THREE.Mesh(doorwayGeometry, doorwayMaterial);
    doorway.position.set(roomData.position.x + roomData.size.width/2, 1.25, roomData.position.z);
    doorway.rotation.y = Math.PI/2;
    roomGroup.add(doorway);
}

function setCurrentRoom(roomGroup) {
    currentRoom = roomGroup;
    const roomData = roomGroup.userData;
    
    document.getElementById('current-room-name').textContent = roomData.name;
    
    updateMinimap();
}

function initControls() {
    document.addEventListener('keydown', (e) => {
        switch(e.code) {
            case 'KeyW': moveForward = true; break;
            case 'KeyS': moveBackward = true; break;
            case 'KeyA': moveLeft = true; break;
            case 'KeyD': moveRight = true; break;
            case 'KeyE': interact(); break;
            case 'Escape': togglePause(); break;
        }
    });
    
    document.addEventListener('keyup', (e) => {
        switch(e.code) {
            case 'KeyW': moveForward = false; break;
            case 'KeyS': moveBackward = false; break;
            case 'KeyA': moveLeft = false; break;
            case 'KeyD': moveRight = false; break;
        }
    });
    
    renderer.domElement.addEventListener('click', () => {
        renderer.domElement.requestPointerLock();
    });
    
    document.addEventListener('pointerlockchange', () => {
        if (document.pointerLockElement === renderer.domElement) {
            document.addEventListener('mousemove', onMouseMove);
        } else {
            document.removeEventListener('mousemove', onMouseMove);
        }
    });
}

function onMouseMove(event) {
    if (document.pointerLockElement !== renderer.domElement) return;
    
    const movementX = event.movementX || 0;
    const movementY = event.movementY || 0;
    
    camera.rotation.y -= movementX * 0.002;
    camera.rotation.x -= movementY * 0.002;
    camera.rotation.x = Math.max(-Math.PI/2, Math.min(Math.PI/2, camera.rotation.x));
}

function onMouseClick(event) {
    if (document.pointerLockElement !== renderer.domElement) return;
    
    mouse.x = 0;
    mouse.y = 0;
    
    raycaster.setFromCamera(mouse, camera);
    
    const intersects = raycaster.intersectObjects(interactiveObjects, true);
    
    if (intersects.length > 0) {
        let obj = intersects[0].object;
        while (obj.parent && !obj.userData.id) {
            obj = obj.parent;
        }
        
        if (obj.userData.id) {
            collectEvidence(obj);
        }
    }
}

function interact() {
    if (interactableObject) {
        collectEvidence(interactableObject);
    }
}

function collectEvidence(obj) {
    const objData = obj.userData;
    
    if (evidenceCollected.find(e => e.id === objData.id)) {
        showNotification('Evidence already collected');
        return;
    }
    
    evidenceCollected.push({
        id: objData.id,
        name: objData.name,
        clue: objData.clue
    });
    
    showNotification(`Collected: ${objData.name}`);
    updateEvidencePanel();
    checkDecisionPoints();
    
    if (sessionId) {
        fetch(`${API_BASE}/api/sessions/${sessionId}/progress`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: sessionId,
                evidence_collected: [objData.id],
                rooms_visited: [currentRoom?.userData?.id].filter(Boolean)
            })
        });
    }
}

function checkDecisionPoints() {
    if (!currentRoom || !currentRoom.userData.decision_points) return;
    
    const decisionPoints = currentRoom.userData.decision_points;
    
    for (const dp of decisionPoints) {
        if (!decisions.find(d => d.decision_point === dp.id)) {
            showDecisionPanel(dp);
            return;
        }
    }
}

function showDecisionPanel(decisionPoint) {
    const panel = document.getElementById('decision-panel');
    const question = document.getElementById('decision-question');
    const options = document.getElementById('decision-options');
    
    question.textContent = decisionPoint.question;
    options.innerHTML = '';
    
    decisionPoint.options.forEach(option => {
        const optionDiv = document.createElement('div');
        optionDiv.className = 'decision-option';
        optionDiv.innerHTML = `
            <span class="decision-option-key">${option.id.toUpperCase()}</span>
            <span class="decision-option-text">${option.text}</span>
        `;
        optionDiv.onclick = () => makeDecision(decisionPoint, option);
        options.appendChild(optionDiv);
    });
    
    panel.style.display = 'block';
    document.exitPointerLock();
}

function makeDecision(decisionPoint, option) {
    decisions.push({
        decision_point: decisionPoint.id,
        chosen: option.id,
        score: option.score
    });
    
    score = decisions.reduce((sum, d) => sum + d.score, 0);
    document.getElementById('score-value').textContent = score;
    
    showNotification(`${option.feedback} (+${option.score} points)`);
    
    document.getElementById('decision-panel').style.display = 'none';
    
    if (sessionId) {
        fetch(`${API_BASE}/api/sessions/${sessionId}/decisions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                decision_point: decisionPoint.id,
                chosen: option.id
            })
        });
    }
    
    checkCompletion();
}

function checkCompletion() {
    if (!scenarioData) return;
    
    const criteria = scenarioData.completion_criteria;
    const allRoomsVisited = criteria.required_rooms.every(roomId => 
        rooms.some(r => r.userData.id === roomId)
    );
    
    const allDecisionPoints = scenarioData.rooms.reduce((count, room) => 
        count + (room.decision_points?.length || 0), 0
    );
    const allDecisionsMade = decisions.length >= allDecisionPoints;
    
    if (allRoomsVisited && allDecisionsMade) {
        completeScenario();
    }
}

function completeScenario() {
    stopTimer();
    
    document.getElementById('completion-score').textContent = `${score}/100`;
    
    const criteria = scenarioData.completion_criteria;
    if (score >= criteria.minimum_score) {
        document.getElementById('completion-title').textContent = 'Scenario Complete!';
        document.getElementById('completion-message').textContent = 'Excellent work! You have successfully completed the incident response training.';
    } else {
        document.getElementById('completion-title').textContent = 'Scenario Failed';
        document.getElementById('completion-message').textContent = `You need ${criteria.minimum_score} points to pass. Review your decisions and try again.`;
    }
    
    document.getElementById('completion-modal').style.display = 'flex';
    document.exitPointerLock();
    
    if (sessionId) {
        fetch(`${API_BASE}/api/sessions/${sessionId}/complete`, {
            method: 'POST'
        });
    }
}

function updateEvidencePanel() {
    const list = document.getElementById('evidence-list');
    const count = document.getElementById('evidence-count');
    
    list.innerHTML = '';
    evidenceCollected.forEach(evidence => {
        const item = document.createElement('div');
        item.className = 'evidence-item';
        item.innerHTML = `
            <div class="evidence-icon"></div>
            <span>${evidence.name}</span>
        `;
        list.appendChild(item);
    });
    
    const totalEvidence = scenarioData?.rooms?.reduce((count, room) => 
        count + (room.objects?.length || 0), 0
    ) || 0;
    count.textContent = `${evidenceCollected.length}/${totalEvidence}`;
}

function updateMinimap() {
    const canvas = document.getElementById('minimap-canvas');
    const ctx = canvas.getContext('2d');
    
    canvas.width = 180;
    canvas.height = 180;
    
    ctx.fillStyle = '#0a0a0f';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    rooms.forEach(room => {
        const roomData = room.userData;
        const x = (roomData.position.x / 20 + 0.5) * canvas.width;
        const y = (roomData.position.z / 20 + 0.5) * canvas.height;
        const w = (roomData.size.width / 20) * canvas.width;
        const h = (roomData.size.depth / 20) * canvas.height;
        
        ctx.fillStyle = room === currentRoom ? '#00d9ff' : '#16213e';
        ctx.fillRect(x - w/2, y - h/2, w, h);
        
        ctx.strokeStyle = '#0f3460';
        ctx.strokeRect(x - w/2, y - h/2, w, h);
    });
    
    const playerX = (camera.position.x / 20 + 0.5) * canvas.width;
    const playerY = (camera.position.z / 20 + 0.5) * canvas.height;
    
    ctx.fillStyle = '#00ff88';
    ctx.beginPath();
    ctx.arc(playerX, playerY, 4, 0, Math.PI * 2);
    ctx.fill();
    
    const angle = camera.rotation.y;
    ctx.strokeStyle = '#00ff88';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(playerX, playerY);
    ctx.lineTo(
        playerX + Math.sin(angle) * 10,
        playerY - Math.cos(angle) * 10
    );
    ctx.stroke();
}

function initUI() {
    updateEvidencePanel();
}

function startTimer() {
    timer = 0;
    isPlaying = true;
    timerInterval = setInterval(() => {
        if (isPlaying) {
            timer++;
            updateTimerDisplay();
        }
    }, 1000);
}

function stopTimer() {
    isPlaying = false;
    if (timerInterval) {
        clearInterval(timerInterval);
    }
}

function updateTimerDisplay() {
    const minutes = Math.floor(timer / 60).toString().padStart(2, '0');
    const seconds = (timer % 60).toString().padStart(2, '0');
    document.getElementById('timer-value').textContent = `${minutes}:${seconds}`;
}

function togglePause() {
    isPlaying = !isPlaying;
    if (isPlaying) {
        showNotification('Training resumed');
    } else {
        showNotification('Training paused');
    }
}

function showNotification(message, isError = false) {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.style.background = isError ? '#ff4444' : '#00ff88';
    notification.classList.add('visible');
    
    setTimeout(() => {
        notification.classList.remove('visible');
    }, 2000);
}

function onWindowResize() {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
}

function animate() {
    requestAnimationFrame(animate);
    
    if (isPlaying) {
        updatePlayerMovement();
        updateInteractionDetection();
    }
    
    updateMinimap();
    renderer.render(scene, camera);
}

function updatePlayerMovement() {
    velocity.x -= velocity.x * 5.0 * 0.016;
    velocity.z -= velocity.z * 5.0 * 0.016;
    
    direction.z = Number(moveForward) - Number(moveBackward);
    direction.x = Number(moveRight) - Number(moveLeft);
    direction.normalize();
    
    if (moveForward || moveBackward) velocity.z -= direction.z * 50.0 * 0.016;
    if (moveLeft || moveRight) velocity.x -= direction.x * 50.0 * 0.016;
    
    const forward = new THREE.Vector3(0, 0, -1);
    forward.applyQuaternion(camera.quaternion);
    forward.y = 0;
    forward.normalize();
    
    const right = new THREE.Vector3(1, 0, 0);
    right.applyQuaternion(camera.quaternion);
    right.y = 0;
    right.normalize();
    
    camera.position.addScaledVector(forward, -velocity.z * 0.016);
    camera.position.addScaledVector(right, velocity.x * 0.016);
    
    camera.position.y = 1.6;
    
    checkRoomTransition();
}

function checkRoomTransition() {
    for (const room of rooms) {
        const roomData = room.userData;
        const minX = roomData.position.x - roomData.size.width/2;
        const maxX = roomData.position.x + roomData.size.width/2;
        const minZ = roomData.position.z - roomData.size.depth/2;
        const maxZ = roomData.position.z + roomData.size.depth/2;
        
        if (camera.position.x >= minX && camera.position.x <= maxX &&
            camera.position.z >= minZ && camera.position.z <= maxZ) {
            if (currentRoom !== room) {
                setCurrentRoom(room);
            }
            break;
        }
    }
}

function updateInteractionDetection() {
    raycaster.setFromCamera(new THREE.Vector2(0, 0), camera);
    
    const intersects = raycaster.intersectObjects(interactiveObjects, true);
    
    const prompt = document.getElementById('interaction-prompt');
    
    if (intersects.length > 0) {
        let obj = intersects[0].object;
        while (obj.parent && !obj.userData.id) {
            obj = obj.parent;
        }
        
        if (obj.userData.id && intersects[0].distance < 3) {
            interactableObject = obj;
            prompt.classList.add('visible');
            return;
        }
    }
    
    interactableObject = null;
    prompt.classList.remove('visible');
}

async function downloadReport() {
    if (!sessionId) {
        showNotification('No session to report', true);
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/api/reports/${sessionId}`);
        const html = await response.text();
        
        const blob = new Blob([html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `training_report_${sessionId}.html`;
        a.click();
        URL.revokeObjectURL(url);
        
        showNotification('Report downloaded');
    } catch (error) {
        console.error('Failed to download report:', error);
        showNotification('Failed to generate report', true);
    }
}

function restartScenario() {
    window.location.reload();
}

document.addEventListener('DOMContentLoaded', init);
