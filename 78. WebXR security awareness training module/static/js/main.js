let scene, camera, renderer;
let currentModule = null;
let currentLesson = null;
let modules = [];
let employeeData = null;
let isTraining = false;
let trainingTimer = 0;
let trainingInterval = null;
let currentQuestionIndex = 0;
let quizScore = 0;
let quizAnswers = [];

const API_BASE = '';

async function init() {
    await loadModules();
    await loadEmployeeProgress('emp_001');
    initThree();
    initUI();
}

async function loadModules() {
    try {
        const response = await fetch(`${API_BASE}/api/modules`);
        const data = await response.json();
        modules = data.modules || [];
        renderModuleList();
    } catch (error) {
        console.error('Failed to load modules:', error);
        showNotification('Failed to load modules', 'error');
    }
}

async function loadEmployeeProgress(employeeId) {
    try {
        const response = await fetch(`${API_BASE}/api/progress/${employeeId}`);
        employeeData = await response.json();
        updateStats();
    } catch (error) {
        console.error('Failed to load progress:', error);
    }
}

function renderModuleList() {
    const list = document.getElementById('module-list');
    list.innerHTML = '';
    
    modules.forEach(module => {
        const completed = employeeData?.modules_completed?.includes(module.id) || false;
        const score = employeeData?.quiz_scores?.[module.id] || 0;
        
        const item = document.createElement('div');
        item.className = 'module-item';
        item.onclick = () => selectModule(module);
        
        item.innerHTML = `
            <div class="module-item-title">${module.title}</div>
            <div class="module-item-meta">${module.category} • ${module.estimated_time_minutes} min</div>
            <div class="module-item-progress">
                <div class="module-item-progress-bar" style="width: ${completed ? 100 : 0}%"></div>
            </div>
        `;
        
        list.appendChild(item);
    });
}

function selectModule(module) {
    currentModule = module;
    currentLesson = module.lessons[0] || null;
    
    document.querySelectorAll('.module-item').forEach(item => {
        item.classList.remove('active');
    });
    event.currentTarget.classList.add('active');
    
    document.getElementById('module-title').textContent = module.title;
    document.getElementById('module-description').textContent = module.description;
    
    if (currentLesson) {
        document.getElementById('lesson-content').textContent = currentLesson.content;
    }
    
    updateProgress();
    load3DScene(module.id);
}

function initThree() {
    const container = document.getElementById('canvas-container');
    const canvas = document.getElementById('training-canvas');
    
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x1a1a2e);
    
    camera = new THREE.PerspectiveCamera(75, container.clientWidth / container.clientHeight, 0.1, 1000);
    camera.position.set(0, 2, 5);
    
    renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(window.devicePixelRatio);
    
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
    scene.add(ambientLight);
    
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(5, 10, 5);
    scene.add(directionalLight);
    
    createDefaultScene();
    animate();
    
    window.addEventListener('resize', onWindowResize);
}

function createDefaultScene() {
    while(scene.children.length > 0) { 
        scene.remove(scene.children[0]); 
    }
    
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
    scene.add(ambientLight);
    
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(5, 10, 5);
    scene.add(directionalLight);
    
    const floorGeometry = new THREE.PlaneGeometry(20, 20);
    const floorMaterial = new THREE.MeshPhongMaterial({ color: 0x16213e });
    const floor = new THREE.Mesh(floorGeometry, floorMaterial);
    floor.rotation.x = -Math.PI / 2;
    scene.add(floor);
    
    const deskGeometry = new THREE.BoxGeometry(2, 0.8, 1);
    const deskMaterial = new THREE.MeshPhongMaterial({ color: 0x8B4513 });
    const desk = new THREE.Mesh(deskGeometry, deskMaterial);
    desk.position.set(0, 0.4, 0);
    scene.add(desk);
    
    const monitorGeometry = new THREE.BoxGeometry(0.8, 0.6, 0.05);
    const monitorMaterial = new THREE.MeshPhongMaterial({ color: 0x333333 });
    const monitor = new THREE.Mesh(monitorGeometry, monitorMaterial);
    monitor.position.set(0, 1.1, -0.4);
    scene.add(monitor);
    
    const screenGeometry = new THREE.PlaneGeometry(0.7, 0.5);
    const screenMaterial = new THREE.MeshBasicMaterial({ color: 0x0066cc });
    const screen = new THREE.Mesh(screenGeometry, screenMaterial);
    screen.position.set(0, 1.1, -0.37);
    scene.add(screen);
}

function load3DScene(moduleId) {
    createDefaultScene();
    
    switch(moduleId) {
        case 'phishing_001':
            createPhishingScene();
            break;
        case 'passwords_001':
            createPasswordScene();
            break;
        case 'social_001':
            createSocialScene();
            break;
        case 'data_001':
            createDataScene();
            break;
        case 'physical_001':
            createPhysicalScene();
            break;
        default:
            createDefaultScene();
    }
}

function createPhishingScene() {
    const emailGeometry = new THREE.PlaneGeometry(3, 2);
    const emailMaterial = new THREE.MeshBasicMaterial({ color: 0xffffff, side: THREE.DoubleSide });
    const email = new THREE.Mesh(emailGeometry, emailMaterial);
    email.position.set(0, 1.5, 0);
    email.rotation.y = Math.PI / 8;
    scene.add(email);
    
    const headerGeometry = new THREE.PlaneGeometry(2.8, 0.3);
    const headerMaterial = new THREE.MeshBasicMaterial({ color: 0x0066cc });
    const header = new THREE.Mesh(headerGeometry, headerMaterial);
    header.position.set(0, 2.2, 0.01);
    header.rotation.y = Math.PI / 8;
    scene.add(header);
    
    const warningGeometry = new THREE.ConeGeometry(0.3, 0.5, 3);
    const warningMaterial = new THREE.MeshPhongMaterial({ color: 0xff6600 });
    const warning = new THREE.Mesh(warningGeometry, warningMaterial);
    warning.position.set(2, 2, 0);
    scene.add(warning);
}

function createPasswordScene() {
    const strengthColors = [0xff0000, 0xff6600, 0xffff00, 0x66ff00, 0x00ff00];
    
    for(let i = 0; i < 5; i++) {
        const barGeometry = new THREE.BoxGeometry(0.3, 1 + i * 0.5, 0.3);
        const barMaterial = new THREE.MeshPhongMaterial({ color: strengthColors[i] });
        const bar = new THREE.Mesh(barGeometry, barMaterial);
        bar.position.set(-2 + i, 0.5 + (1 + i * 0.5) / 2, 0);
        scene.add(bar);
    }
}

function createSocialScene() {
    const personGeometry = new THREE.CylinderGeometry(0.3, 0.3, 1.5, 8);
    const personMaterial = new THREE.MeshPhongMaterial({ color: 0x0066cc });
    
    for(let i = 0; i < 3; i++) {
        const person = new THREE.Mesh(personGeometry, personMaterial);
        person.position.set(-2 + i * 2, 0.75, 0);
        scene.add(person);
        
        const headGeometry = new THREE.SphereGeometry(0.3, 16, 16);
        const head = new THREE.Mesh(headGeometry, personMaterial);
        head.position.set(-2 + i * 2, 1.8, 0);
        scene.add(head);
    }
}

function createDataScene() {
    const classifications = [
        { color: 0x00ff00, label: 'Public', y: 0.5 },
        { color: 0xffff00, label: 'Internal', y: 1.5 },
        { color: 0xff6600, label: 'Confidential', y: 2.5 },
        { color: 0xff0000, label: 'Restricted', y: 3.5 }
    ];
    
    classifications.forEach((cls, i) => {
        const boxGeometry = new THREE.BoxGeometry(1, 0.8, 1);
        const boxMaterial = new THREE.MeshPhongMaterial({ color: cls.color });
        const box = new THREE.Mesh(boxGeometry, boxMaterial);
        box.position.set(-1.5 + i, cls.y / 2, 0);
        scene.add(box);
    });
}

function createPhysicalScene() {
    const doorGeometry = new THREE.BoxGeometry(1.5, 2.5, 0.1);
    const doorMaterial = new THREE.MeshPhongMaterial({ color: 0x8B4513 });
    const door = new THREE.Mesh(doorGeometry, doorMaterial);
    door.position.set(0, 1.25, -2);
    scene.add(door);
    
    const lockGeometry = new THREE.BoxGeometry(0.1, 0.15, 0.05);
    const lockMaterial = new THREE.MeshPhongMaterial({ color: 0xcccccc });
    const lock = new THREE.Mesh(lockGeometry, lockMaterial);
    lock.position.set(0.6, 1.2, -1.95);
    scene.add(lock);
    
    const badgeGeometry = new THREE.BoxGeometry(0.4, 0.6, 0.02);
    const badgeMaterial = new THREE.MeshPhongMaterial({ color: 0x0066cc });
    const badge = new THREE.Mesh(badgeGeometry, badgeMaterial);
    badge.position.set(2, 1, 0);
    scene.add(badge);
}

function startTraining() {
    if (!currentModule) {
        showNotification('Please select a module first', 'info');
        return;
    }
    
    isTraining = true;
    trainingTimer = 0;
    
    if (trainingInterval) clearInterval(trainingInterval);
    trainingInterval = setInterval(() => {
        trainingTimer++;
    }, 1000);
    
    showNotification('Training started!', 'success');
}

function pauseTraining() {
    isTraining = false;
    if (trainingInterval) {
        clearInterval(trainingInterval);
        trainingInterval = null;
    }
    showNotification('Training paused', 'info');
}

function startQuiz() {
    if (!currentModule || !currentModule.quiz) {
        showNotification('No quiz available for this module', 'error');
        return;
    }
    
    currentQuestionIndex = 0;
    quizScore = 0;
    quizAnswers = [];
    
    document.getElementById('quiz-area').classList.add('active');
    renderQuestion();
}

function renderQuestion() {
    const quiz = currentModule.quiz;
    if (currentQuestionIndex >= quiz.questions.length) {
        finishQuiz();
        return;
    }
    
    const question = quiz.questions[currentQuestionIndex];
    const container = document.getElementById('quiz-container');
    
    container.innerHTML = `
        <div class="quiz-question">${question.question}</div>
        <div class="quiz-options">
            ${question.options.map(opt => `
                <div class="quiz-option" data-id="${opt.id}" onclick="selectAnswer('${opt.id}')">
                    ${opt.text}
                </div>
            `).join('')}
        </div>
        <p>Question ${currentQuestionIndex + 1} of ${quiz.questions.length}</p>
    `;
}

function selectAnswer(answerId) {
    const question = currentModule.quiz.questions[currentQuestionIndex];
    const isCorrect = answerId === question.correct;
    
    if (isCorrect) {
        quizScore += 10;
    }
    
    quizAnswers.push({
        question_id: question.id,
        selected: answerId,
        correct: question.correct,
        is_correct: isCorrect
    });
    
    document.querySelectorAll('.quiz-option').forEach(opt => {
        opt.onclick = null;
        if (opt.dataset.id === question.correct) {
            opt.classList.add('correct');
        } else if (opt.dataset.id === answerId && !isCorrect) {
            opt.classList.add('incorrect');
        }
    });
    
    setTimeout(() => {
        currentQuestionIndex++;
        renderQuestion();
    }, 1500);
}

async function finishQuiz() {
    const quiz = currentModule.quiz;
    const percentage = Math.round((quizScore / (quiz.questions.length * 10)) * 100);
    const passed = percentage >= quiz.passing_score;
    
    document.getElementById('quiz-area').innerHTML = `
        <h2>Quiz Complete!</h2>
        <p>Your score: ${percentage}%</p>
        <p>${passed ? 'Congratulations! You passed!' : 'Keep practicing!'}</p>
        <button class="btn btn-primary" onclick="closeQuiz()">Close</button>
    `;
    
    if (employeeData) {
        try {
            await fetch(`${API_BASE}/api/progress/${employeeData.id}/complete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    module_id: currentModule.id,
                    quiz_score: percentage,
                    time_spent_minutes: Math.ceil(trainingTimer / 60)
                })
            });
            
            await loadEmployeeProgress(employeeData.id);
            renderModuleList();
            updateStats();
        } catch (error) {
            console.error('Failed to save progress:', error);
        }
    }
    
    showNotification(passed ? 'Quiz passed!' : 'Quiz failed. Try again!', passed ? 'success' : 'error');
}

function closeQuiz() {
    document.getElementById('quiz-area').classList.remove('active');
    document.getElementById('quiz-area').innerHTML = '<h2>Quiz</h2><div id="quiz-container"></div>';
}

function updateStats() {
    if (!employeeData) return;
    
    const completed = employeeData.modules_completed?.length || 0;
    const scores = Object.values(employeeData.quiz_scores || {});
    const avgScore = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
    
    document.getElementById('stat-completed').textContent = `${completed}/5`;
    document.getElementById('stat-score').textContent = `${avgScore}%`;
    document.getElementById('stat-time').textContent = employeeData.total_training_minutes || 0;
    document.getElementById('stat-cert').textContent = employeeData.certificate_earned ? 'Yes' : 'No';
}

function updateProgress() {
    if (!currentModule || !employeeData) return;
    
    const completed = employeeData.modules_completed?.includes(currentModule.id) || false;
    const percentage = completed ? 100 : 0;
    
    document.getElementById('progress-fill').style.width = `${percentage}%`;
    document.getElementById('progress-text').textContent = `${percentage}% Complete`;
}

function initUI() {
    updateStats();
}

function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification ${type} show`;
    
    setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}

function onWindowResize() {
    const container = document.getElementById('canvas-container');
    camera.aspect = container.clientWidth / container.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(container.clientWidth, container.clientHeight);
}

function animate() {
    requestAnimationFrame(animate);
    
    if (isTraining) {
        camera.rotation.y += 0.002;
    }
    
    renderer.render(scene, camera);
}

async function downloadReport() {
    if (!employeeData) {
        showNotification('No employee data available', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/api/reports/${employeeData.id}`);
        const html = await response.text();
        
        const blob = new Blob([html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `training_report_${employeeData.id}.html`;
        a.click();
        URL.revokeObjectURL(url);
        
        showNotification('Report downloaded', 'success');
    } catch (error) {
        console.error('Failed to download report:', error);
        showNotification('Failed to generate report', 'error');
    }
}

async function viewCertificate() {
    if (!employeeData || !employeeData.certificate_earned) {
        showNotification('Certificate not yet earned', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/api/certificates/${employeeData.id}`);
        const html = await response.text();
        
        const newWindow = window.open('', '_blank');
        newWindow.document.write(html);
        newWindow.document.close();
        
        showNotification('Certificate opened', 'success');
    } catch (error) {
        console.error('Failed to view certificate:', error);
        showNotification('Failed to load certificate', 'error');
    }
}

document.addEventListener('DOMContentLoaded', init);
