/**
 * WebShield Scanner - Cyber Grid Animation
 * Creates a 3D cyber grid background using Three.js.
 */

(function() {
    'use strict';

    let scene, camera, renderer, grid;
    let animationId = null;

    /**
     * Initialize cyber grid animation
     */
    window.initCyberGrid = function(containerId = 'three-container') {
        const container = document.getElementById(containerId);
        if (!container) return;

        // Scene setup
        scene = new THREE.Scene();
        scene.background = new THREE.Color(0x0a0a1a);

        // Camera
        const width = container.clientWidth || window.innerWidth;
        const height = container.clientHeight || window.innerHeight;
        camera = new THREE.PerspectiveCamera(60, width / height, 0.1, 1000);
        camera.position.set(0, 5, 15);
        camera.lookAt(0, 0, 0);

        // Renderer
        renderer = new THREE.WebGLRenderer({
            antialias: true,
            alpha: true
        });
        renderer.setSize(width, height);
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        renderer.shadowMap.enabled = true;
        container.appendChild(renderer.domElement);

        // Create grid
        createGrid();

        // Add lights
        addLights();

        // Start animation
        animate();

        // Handle resize
        window.addEventListener('resize', function() {
            const w = container.clientWidth || window.innerWidth;
            const h = container.clientHeight || window.innerHeight;
            camera.aspect = w / h;
            camera.updateProjectionMatrix();
            renderer.setSize(w, h);
        });

        // Handle visibility change
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                if (animationId) {
                    cancelAnimationFrame(animationId);
                    animationId = null;
                }
            } else {
                if (!animationId) {
                    animate();
                }
            }
        });
    };

    /**
     * Create the grid
     */
    function createGrid() {
        // Create a grid of points
        const gridSize = 20;
        const spacing = 1.2;
        const points = [];
        const colors = [];

        for (let x = -gridSize / 2; x < gridSize / 2; x++) {
            for (let z = -gridSize / 2; z < gridSize / 2; z++) {
                const y = Math.sin(x * 0.3) * Math.cos(z * 0.3) * 0.3;
                points.push(x * spacing, y, z * spacing);

                // Color based on position
                const r = 0.0;
                const g = 0.6 + Math.sin(x * 0.2 + z * 0.2) * 0.2;
                const b = 0.8 + Math.sin(x * 0.3 - z * 0.3) * 0.2;
                colors.push(r, g, b);
            }
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.Float32BufferAttribute(points, 3));
        geometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));

        // Create points material
        const material = new THREE.PointsMaterial({
            size: 0.08,
            vertexColors: true,
            transparent: true,
            opacity: 0.8,
            blending: THREE.AdditiveBlending
        });

        grid = new THREE.Points(geometry, material);
        scene.add(grid);

        // Add connecting lines
        const linePositions = [];
        const gridPoints = [];

        // Collect grid points by x,z position
        const pointMap = {};
        const pos = grid.geometry.attributes.position.array;
        for (let i = 0; i < pos.length; i += 3) {
            const x = Math.round(pos[i] / spacing);
            const z = Math.round(pos[i + 2] / spacing);
            const key = x + ',' + z;
            pointMap[key] = {
                x: pos[i],
                y: pos[i + 1],
                z: pos[i + 2]
            };
        }

        // Connect adjacent points
        const keys = Object.keys(pointMap);
        keys.forEach(key => {
            const [x, z] = key.split(',').map(Number);
            const current = pointMap[key];

            // Connect to right neighbor
            const rightKey = (x + 1) + ',' + z;
            if (pointMap[rightKey]) {
                const right = pointMap[rightKey];
                linePositions.push(current.x, current.y, current.z);
                linePositions.push(right.x, right.y, right.z);
            }

            // Connect to forward neighbor
            const forwardKey = x + ',' + (z + 1);
            if (pointMap[forwardKey]) {
                const forward = pointMap[forwardKey];
                linePositions.push(current.x, current.y, current.z);
                linePositions.push(forward.x, forward.y, forward.z);
            }
        });

        const lineGeometry = new THREE.BufferGeometry();
        lineGeometry.setAttribute('position', new THREE.Float32BufferAttribute(linePositions, 3));

        const lineMaterial = new THREE.LineBasicMaterial({
            color: 0x00f0ff,
            transparent: true,
            opacity: 0.08,
            blending: THREE.AdditiveBlending
        });

        const lines = new THREE.LineSegments(lineGeometry, lineMaterial);
        scene.add(lines);
    }

    /**
     * Add lights
     */
    function addLights() {
        const ambientLight = new THREE.AmbientLight(0x222244, 0.5);
        scene.add(ambientLight);

        const dirLight = new THREE.DirectionalLight(0x00f0ff, 0.8);
        dirLight.position.set(5, 10, 5);
        scene.add(dirLight);

        const pointLight = new THREE.PointLight(0x0066ff, 0.5, 20);
        pointLight.position.set(-5, 5, -5);
        scene.add(pointLight);
    }

    /**
     * Animation loop
     */
    function animate() {
        animationId = requestAnimationFrame(animate);

        if (grid) {
            grid.rotation.y += 0.001;
            grid.rotation.x = Math.sin(Date.now() * 0.0001) * 0.05;
        }

        renderer.render(scene, camera);
    }

    /**
     * Cleanup
     */
    window.destroyCyberGrid = function() {
        if (animationId) {
            cancelAnimationFrame(animationId);
            animationId = null;
        }
        if (renderer) {
            renderer.dispose();
            renderer.domElement.remove();
        }
    };

})();