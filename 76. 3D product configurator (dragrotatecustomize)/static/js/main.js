let scene, camera, renderer, productGroup;
let products = [], currentProduct = null, currentSelections = {};
let configurations = [], savedConfigs = [];
let isDragging = false, previousMousePosition = { x: 0, y: 0 };

document.addEventListener('DOMContentLoaded', () => {
    init();
    loadData();
    setupEventListeners();
    animate();
});

function init() {
    const canvas = document.getElementById('product-canvas');
    const container = document.getElementById('viewer-container');

    scene = new THREE.Scene();
    scene.background = new THREE.Color(0xf5f7fa);

    camera = new THREE.PerspectiveCamera(45, container.clientWidth / container.clientHeight, 0.1, 1000);
    camera.position.set(3, 2, 3);
    camera.lookAt(0, 0, 0);

    renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.shadowMap.enabled = true;

    const ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
    scene.add(ambientLight);

    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(5, 10, 7);
    directionalLight.castShadow = true;
    scene.add(directionalLight);

    const fillLight = new THREE.DirectionalLight(0x667eea, 0.3);
    fillLight.position.set(-5, 5, -5);
    scene.add(fillLight);

    const gridHelper = new THREE.GridHelper(10, 20, 0xdddddd, 0xeeeeee);
    scene.add(gridHelper);

    productGroup = new THREE.Group();
    scene.add(productGroup);

    canvas.addEventListener('mousedown', onDragStart);
    canvas.addEventListener('mousemove', onDragMove);
    canvas.addEventListener('mouseup', onDragEnd);
    canvas.addEventListener('mouseleave', onDragEnd);
    canvas.addEventListener('wheel', onZoom);
    canvas.addEventListener('touchstart', onTouchStart, { passive: false });
    canvas.addEventListener('touchmove', onTouchMove, { passive: false });
    canvas.addEventListener('touchend', onTouchEnd);

    window.addEventListener('resize', onWindowResize);
}

function createProductModel(product) {
    while (productGroup.children.length > 0) {
        productGroup.remove(productGroup.children[0]);
    }

    const color = getColorFromSelection(product);
    const material = new THREE.MeshStandardMaterial({
        color: color,
        roughness: 0.5,
        metalness: 0.1
    });

    const metallicMaterial = new THREE.MeshStandardMaterial({
        color: 0xaaaaaa,
        roughness: 0.2,
        metalness: 0.8
    });

    switch (product.category) {
        case 'Laptop':
            createLaptop(material, metallicMaterial);
            break;
        case 'Phone':
            createPhone(material, metallicMaterial);
            break;
        case 'Headphones':
            createHeadphones(material, metallicMaterial);
            break;
        case 'Watch':
            createWatch(material, metallicMaterial);
            break;
        case 'Camera':
            createCamera(material, metallicMaterial);
            break;
        default:
            createDefaultProduct(material);
    }
}

function createLaptop(bodyMat, metalMat) {
    const base = new THREE.Mesh(
        new THREE.BoxGeometry(2.2, 0.1, 1.5),
        bodyMat
    );
    base.position.y = 0.05;
    base.castShadow = true;
    productGroup.add(base);

    const keyboard = new THREE.Mesh(
        new THREE.BoxGeometry(1.6, 0.02, 0.8),
        new THREE.MeshStandardMaterial({ color: 0x1a1a1a, roughness: 0.8 })
    );
    keyboard.position.set(0, 0.11, 0.15);
    productGroup.add(keyboard);

    const touchpad = new THREE.Mesh(
        new THREE.BoxGeometry(0.5, 0.01, 0.35),
        new THREE.MeshStandardMaterial({ color: 0x2a2a2a, roughness: 0.6 })
    );
    touchpad.position.set(0, 0.115, 0.5);
    productGroup.add(touchpad);

    const screenPivot = new THREE.Group();
    screenPivot.position.set(0, 0.1, -0.7);
    screenPivot.rotation.x = -0.2;

    const screen = new THREE.Mesh(
        new THREE.BoxGeometry(2.1, 1.4, 0.05),
        bodyMat
    );
    screen.position.y = 0.7;
    screen.castShadow = true;
    screenPivot.add(screen);

    const display = new THREE.Mesh(
        new THREE.BoxGeometry(1.9, 1.2, 0.01),
        new THREE.MeshStandardMaterial({ color: 0x0a0a0a, emissive: 0x111122, emissiveIntensity: 0.3 })
    );
    display.position.set(0, 0.7, 0.03);
    screenPivot.add(display);

    productGroup.add(screenPivot);
}

function createPhone(bodyMat, metalMat) {
    const body = new THREE.Mesh(
        new THREE.BoxGeometry(0.8, 1.6, 0.1),
        bodyMat
    );
    body.position.y = 0.8;
    body.castShadow = true;
    productGroup.add(body);

    const screen = new THREE.Mesh(
        new THREE.BoxGeometry(0.72, 1.4, 0.01),
        new THREE.MeshStandardMaterial({ color: 0x0a0a0a, emissive: 0x112233, emissiveIntensity: 0.4 })
    );
    screen.position.set(0, 0.8, 0.06);
    productGroup.add(screen);

    const cameraBump = new THREE.Mesh(
        new THREE.CylinderGeometry(0.06, 0.06, 0.03, 16),
        metalMat
    );
    cameraBump.position.set(-0.2, 1.35, -0.06);
    cameraBump.rotation.x = Math.PI / 2;
    productGroup.add(cameraBump);
}

function createHeadphones(bodyMat, metalMat) {
    const leftCup = new THREE.Mesh(
        new THREE.CylinderGeometry(0.35, 0.35, 0.2, 32),
        bodyMat
    );
    leftCup.position.set(-0.55, 0.8, 0);
    leftCup.rotation.z = Math.PI / 2;
    leftCup.castShadow = true;
    productGroup.add(leftCup);

    const rightCup = new THREE.Mesh(
        new THREE.CylinderGeometry(0.35, 0.35, 0.2, 32),
        bodyMat
    );
    rightCup.position.set(0.55, 0.8, 0);
    rightCup.rotation.z = Math.PI / 2;
    rightCup.castShadow = true;
    productGroup.add(rightCup);

    const cushionMat = new THREE.MeshStandardMaterial({ color: 0x333333, roughness: 0.9 });
    const leftCushion = new THREE.Mesh(
        new THREE.TorusGeometry(0.25, 0.08, 16, 32),
        cushionMat
    );
    leftCushion.position.set(-0.45, 0.8, 0);
    leftCushion.rotation.y = Math.PI / 2;
    productGroup.add(leftCushion);

    const rightCushion = new THREE.Mesh(
        new THREE.TorusGeometry(0.25, 0.08, 16, 32),
        cushionMat
    );
    rightCushion.position.set(0.45, 0.8, 0);
    rightCushion.rotation.y = Math.PI / 2;
    productGroup.add(rightCushion);

    const bandCurve = new THREE.CatmullRomCurve3([
        new THREE.Vector3(-0.55, 0.8, 0),
        new THREE.Vector3(-0.4, 1.4, 0),
        new THREE.Vector3(0, 1.55, 0),
        new THREE.Vector3(0.4, 1.4, 0),
        new THREE.Vector3(0.55, 0.8, 0)
    ]);
    const bandGeometry = new THREE.TubeGeometry(bandCurve, 32, 0.04, 8, false);
    const band = new THREE.Mesh(bandGeometry, metalMat);
    band.castShadow = true;
    productGroup.add(band);
}

function createWatch(bodyMat, metalMat) {
    const caseBody = new THREE.Mesh(
        new THREE.CylinderGeometry(0.5, 0.5, 0.15, 32),
        bodyMat
    );
    caseBody.position.y = 0.5;
    caseBody.castShadow = true;
    productGroup.add(caseBody);

    const face = new THREE.Mesh(
        new THREE.CylinderGeometry(0.42, 0.42, 0.02, 32),
        new THREE.MeshStandardMaterial({ color: 0x0a0a0a, emissive: 0x112233, emissiveIntensity: 0.5 })
    );
    face.position.y = 0.59;
    productGroup.add(face);

    const bandTop = new THREE.Mesh(
        new THREE.BoxGeometry(0.35, 0.8, 0.08),
        bodyMat
    );
    bandTop.position.set(0, 1.0, 0);
    productGroup.add(bandTop);

    const bandBottom = new THREE.Mesh(
        new THREE.BoxGeometry(0.35, 0.8, 0.08),
        bodyMat
    );
    bandBottom.position.set(0, 0.05, 0);
    productGroup.add(bandBottom);

    for (let i = 0; i < 12; i++) {
        const angle = (i / 12) * Math.PI * 2;
        const marker = new THREE.Mesh(
            new THREE.BoxGeometry(0.02, 0.05, 0.01),
            metalMat
        );
        marker.position.set(
            Math.sin(angle) * 0.35,
            0.6,
            Math.cos(angle) * 0.35
        );
        productGroup.add(marker);
    }
}

function createCamera(bodyMat, metalMat) {
    const body = new THREE.Mesh(
        new THREE.BoxGeometry(1.4, 0.9, 0.8),
        bodyMat
    );
    body.position.y = 0.55;
    body.castShadow = true;
    productGroup.add(body);

    const grip = new THREE.Mesh(
        new THREE.BoxGeometry(0.25, 0.7, 0.3),
        new THREE.MeshStandardMaterial({ color: 0x2a2a2a, roughness: 0.9 })
    );
    grip.position.set(0.75, 0.45, 0);
    productGroup.add(grip);

    const lens = new THREE.Mesh(
        new THREE.CylinderGeometry(0.3, 0.35, 0.5, 32),
        metalMat
    );
    lens.position.set(0, 0.55, 0.6);
    lens.rotation.x = Math.PI / 2;
    lens.castShadow = true;
    productGroup.add(lens);

    const glass = new THREE.Mesh(
        new THREE.CylinderGeometry(0.25, 0.25, 0.05, 32),
        new THREE.MeshStandardMaterial({ color: 0x112233, transparent: true, opacity: 0.7 })
    );
    glass.position.set(0, 0.55, 0.86);
    glass.rotation.x = Math.PI / 2;
    productGroup.add(glass);

    const viewfinder = new THREE.Mesh(
        new THREE.BoxGeometry(0.2, 0.15, 0.25),
        bodyMat
    );
    viewfinder.position.set(0.4, 1.05, 0);
    productGroup.add(viewfinder);

    const flash = new THREE.Mesh(
        new THREE.BoxGeometry(0.15, 0.1, 0.1),
        metalMat
    );
    flash.position.set(-0.4, 1.05, 0.1);
    productGroup.add(flash);
}

function createDefaultProduct(bodyMat) {
    const body = new THREE.Mesh(
        new THREE.BoxGeometry(1, 1, 1),
        bodyMat
    );
    body.position.y = 0.5;
    body.castShadow = true;
    productGroup.add(body);
}

function getColorFromSelection(product) {
    const colorOption = product.options?.color;
    if (!colorOption) return 0x667eea;

    const selectedColorId = currentSelections.color || colorOption.choices[0].id;
    const colorChoice = colorOption.choices.find(c => c.id === selectedColorId);

    if (colorChoice && colorChoice.hex) {
        return parseInt(colorChoice.hex.replace('#', ''), 16);
    }
    return 0x667eea;
}

async function loadData() {
    try {
        const [productsRes, configsRes] = await Promise.all([
            fetch('/api/products'),
            fetch('/api/configurations')
        ]);

        const productsData = await productsRes.json();
        const configsData = await configsRes.json();

        products = productsData.products;
        configurations = configsData.configurations;

        renderProductGrid();
        updateSavedView();
        updateCartCount();

        if (products.length > 0) {
            selectProduct(products[0]);
        }

        document.getElementById('loading').classList.add('hidden');
    } catch (error) {
        console.error('Error loading data:', error);
        document.getElementById('loading').innerHTML = '<p style="color: #ff4757;">Error loading data</p>';
    }
}

function renderProductGrid() {
    const icons = { Laptop: '💻', Phone: '📱', Headphones: '🎧', Watch: '⌚', Camera: '📷' };
    const grid = document.getElementById('product-grid');

    grid.innerHTML = products.map(p => `
        <div class="product-card" data-id="${p.id}">
            <div class="icon">${icons[p.category] || '📦'}</div>
            <h3>${p.name}</h3>
            <p>$${p.base_price.toFixed(2)}</p>
        </div>
    `).join('');

    grid.querySelectorAll('.product-card').forEach(card => {
        card.addEventListener('click', () => {
            const product = products.find(p => p.id === card.dataset.id);
            if (product) selectProduct(product);
        });
    });
}

function selectProduct(product) {
    currentProduct = product;
    currentSelections = {};

    document.querySelectorAll('.product-card').forEach(c => c.classList.remove('selected'));
    document.querySelector(`.product-card[data-id="${product.id}"]`)?.classList.add('selected');

    document.getElementById('configTitle').textContent = `Configure ${product.name}`;
    document.getElementById('configName').value = product.name;

    renderOptions();
    createProductModel(product);
    updatePrice();
}

function renderOptions() {
    const container = document.getElementById('options-container');
    if (!currentProduct) return;

    container.innerHTML = '';

    for (const [key, option] of Object.entries(currentProduct.options)) {
        const group = document.createElement('div');
        group.className = 'option-group';

        if (key === 'color') {
            group.innerHTML = `
                <label>${option.label}</label>
                <div class="color-options">
                    ${option.choices.map(c => `
                        <button class="color-swatch ${c.id === (currentSelections.color || option.choices[0].id) ? 'selected' : ''}"
                                data-option="${key}" data-value="${c.id}"
                                style="background-color: ${c.hex}">
                            <span class="tooltip">${c.name}${c.price > 0 ? ' (+$' + c.price + ')' : ''}</span>
                        </button>
                    `).join('')}
                </div>
            `;
        } else if (option.multiple) {
            group.innerHTML = `
                <label>${option.label}</label>
                <div class="accessory-grid">
                    ${option.choices.map(c => `
                        <button class="accessory-btn ${(currentSelections[key] || []).includes(c.id) ? 'selected' : ''}"
                                data-option="${key}" data-value="${c.id}">
                            <span class="name">${c.name}</span>
                            <span class="price">${c.price > 0 ? '+$' + c.price : 'Free'}</span>
                        </button>
                    `).join('')}
                </div>
            `;
        } else {
            group.innerHTML = `
                <label>${option.label}</label>
                <div class="choice-options">
                    ${option.choices.map(c => `
                        <button class="choice-btn ${c.id === (currentSelections[key] || option.choices[0].id) ? 'selected' : ''}"
                                data-option="${key}" data-value="${c.id}">
                            <span class="choice-name">${c.name}</span>
                            <span class="choice-price">${c.price > 0 ? '+$' + c.price : 'Included'}</span>
                        </button>
                    `).join('')}
                </div>
            `;
        }

        container.appendChild(group);
    }

    container.querySelectorAll('.color-swatch, .choice-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const option = btn.dataset.option;
            const value = btn.dataset.value;
            currentSelections[option] = value;

            btn.parentElement.querySelectorAll('.color-swatch, .choice-btn').forEach(b => b.classList.remove('selected'));
            btn.classList.add('selected');

            createProductModel(currentProduct);
            updatePrice();
        });
    });

    container.querySelectorAll('.accessory-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const option = btn.dataset.option;
            const value = btn.dataset.value;

            if (!currentSelections[option]) currentSelections[option] = [];

            if (currentSelections[option].includes(value)) {
                currentSelections[option] = currentSelections[option].filter(v => v !== value);
                btn.classList.remove('selected');
            } else {
                currentSelections[option].push(value);
                btn.classList.add('selected');
            }
            updatePrice();
        });
    });
}

function updatePrice() {
    if (!currentProduct) return;

    let total = currentProduct.base_price;
    let optionsHtml = '';

    for (const [key, value] of Object.entries(currentSelections)) {
        const option = currentProduct.options[key];
        if (!option) continue;

        if (Array.isArray(value)) {
            value.forEach(v => {
                const choice = option.choices.find(c => c.id === v);
                if (choice && choice.price > 0) {
                    total += choice.price;
                    optionsHtml += `<div class="price-row"><span>${choice.name}</span><span class="option-add">+$${choice.price.toFixed(2)}</span></div>`;
                }
            });
        } else {
            const choice = option.choices.find(c => c.id === value);
            if (choice && choice.price > 0) {
                total += choice.price;
                optionsHtml += `<div class="price-row"><span>${choice.name}</span><span class="option-add">+$${choice.price.toFixed(2)}</span></div>`;
            }
        }
    }

    document.getElementById('basePrice').textContent = '$' + currentProduct.base_price.toFixed(2);
    document.getElementById('optionsPrice').innerHTML = optionsHtml;
    document.getElementById('totalPrice').textContent = '$' + total.toFixed(2);
}

async function saveConfiguration() {
    if (!currentProduct) return;

    const configName = document.getElementById('configName').value || 'My Configuration';

    try {
        const response = await fetch('/api/configurations', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                product_id: currentProduct.id,
                name: configName,
                selections: currentSelections
            })
        });

        const config = await response.json();
        configurations.push(config);
        updateSavedView();
        updateCartCount();
        showNotification('Configuration saved successfully!');
    } catch (error) {
        console.error('Error saving configuration:', error);
        showNotification('Error saving configuration', true);
    }
}

function updateSavedView() {
    const list = document.getElementById('saved-list');
    if (configurations.length === 0) {
        list.innerHTML = '<div class="empty-state"><div class="icon">📋</div><p>No saved configurations yet</p></div>';
        return;
    }

    list.innerHTML = configurations.map(c => `
        <div class="saved-item">
            <div class="saved-info">
                <h4>${c.name}</h4>
                <p>${c.product_name} | $${c.total_price.toFixed(2)}</p>
            </div>
            <div class="saved-actions">
                <button class="load-btn" onclick="loadConfiguration('${c.id}')">Load</button>
                <button class="delete-btn" onclick="deleteConfiguration('${c.id}')">Delete</button>
            </div>
        </div>
    `).join('');
}

function loadConfiguration(configId) {
    const config = configurations.find(c => c.id === configId);
    if (!config) return;

    const product = products.find(p => p.id === config.product_id);
    if (!product) return;

    currentProduct = product;
    currentSelections = { ...config.selections };

    document.querySelectorAll('.product-card').forEach(c => c.classList.remove('selected'));
    document.querySelector(`.product-card[data-id="${product.id}"]`)?.classList.add('selected');

    document.getElementById('configTitle').textContent = `Configure ${product.name}`;
    document.getElementById('configName').value = config.name;

    renderOptions();
    createProductModel(product);
    updatePrice();
    showNotification('Configuration loaded!');
}

async function deleteConfiguration(configId) {
    try {
        await fetch(`/api/configurations/${configId}`, { method: 'DELETE' });
        configurations = configurations.filter(c => c.id !== configId);
        updateSavedView();
        updateCartCount();
        showNotification('Configuration deleted');
    } catch (error) {
        console.error('Error deleting configuration:', error);
    }
}

function updateCartCount() {
    document.getElementById('cartBtn').textContent = `Cart (${configurations.length})`;
}

function showNotification(message, isError = false) {
    const notif = document.getElementById('notification');
    notif.textContent = message;
    notif.style.background = isError ? '#ff4757' : '#1a1a2e';
    notif.classList.remove('hidden');
    notif.classList.add('show');
    setTimeout(() => notif.classList.remove('show'), 3000);
}

function setupEventListeners() {
    document.getElementById('saveConfig').addEventListener('click', saveConfiguration);
    document.getElementById('addToCart').addEventListener('click', () => {
        showNotification('Added to cart!');
    });

    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const view = btn.dataset.view;
            document.getElementById('configurator-view').classList.toggle('active', view === 'configurator');
            document.getElementById('saved-view').classList.toggle('hidden', view !== 'saved');
        });
    });

    document.getElementById('zoomIn').addEventListener('click', () => {
        camera.position.multiplyScalar(0.85);
    });

    document.getElementById('zoomOut').addEventListener('click', () => {
        camera.position.multiplyScalar(1.15);
    });

    document.getElementById('resetView').addEventListener('click', () => {
        camera.position.set(3, 2, 3);
        camera.lookAt(0, 0, 0);
        productGroup.rotation.set(0, 0, 0);
    });
}

function onDragStart(e) {
    isDragging = true;
    previousMousePosition = { x: e.clientX, y: e.clientY };
}

function onDragMove(e) {
    if (!isDragging) return;

    const delta = {
        x: e.clientX - previousMousePosition.x,
        y: e.clientY - previousMousePosition.y
    };

    productGroup.rotation.y += delta.x * 0.01;
    productGroup.rotation.x += delta.y * 0.01;
    productGroup.rotation.x = Math.max(-Math.PI / 3, Math.min(Math.PI / 3, productGroup.rotation.x));

    previousMousePosition = { x: e.clientX, y: e.clientY };
}

function onDragEnd() {
    isDragging = false;
}

function onZoom(e) {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 1.1 : 0.9;
    camera.position.multiplyScalar(factor);
    camera.position.clampLength(2, 8);
}

let touchStartDistance = 0;

function onTouchStart(e) {
    if (e.touches.length === 1) {
        isDragging = true;
        previousMousePosition = { x: e.touches[0].clientX, y: e.touches[0].clientY };
    } else if (e.touches.length === 2) {
        touchStartDistance = Math.hypot(
            e.touches[0].clientX - e.touches[1].clientX,
            e.touches[0].clientY - e.touches[1].clientY
        );
    }
    e.preventDefault();
}

function onTouchMove(e) {
    if (e.touches.length === 1 && isDragging) {
        const delta = {
            x: e.touches[0].clientX - previousMousePosition.x,
            y: e.touches[0].clientY - previousMousePosition.y
        };
        productGroup.rotation.y += delta.x * 0.01;
        productGroup.rotation.x += delta.y * 0.01;
        previousMousePosition = { x: e.touches[0].clientX, y: e.touches[0].clientY };
    } else if (e.touches.length === 2) {
        const distance = Math.hypot(
            e.touches[0].clientX - e.touches[1].clientX,
            e.touches[0].clientY - e.touches[1].clientY
        );
        const factor = touchStartDistance / distance;
        camera.position.multiplyScalar(factor);
        camera.position.clampLength(2, 8);
        touchStartDistance = distance;
    }
    e.preventDefault();
}

function onTouchEnd() {
    isDragging = false;
}

function onWindowResize() {
    const container = document.getElementById('viewer-container');
    camera.aspect = container.clientWidth / container.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(container.clientWidth, container.clientHeight);
}

function animate() {
    requestAnimationFrame(animate);
    renderer.render(scene, camera);
}
