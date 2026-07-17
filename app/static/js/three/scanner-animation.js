/**
 * WebShield Scanner - Scanner Animation
 * Creates a 3D scanner animation using Three.js.
 */

(function() {
    'use strict';

    let scene, camera, renderer, scannerRing, scanLine, particles;
    let animationId = null;

    /**
     * Initialize scanner animation
     */
    window.initScannerAnimation = function(containerId = 'three-container') {
        const container = document.getElementById(containerId);
        if (!container) return;

        // Scene setup
        scene = new THREE.Scene();
        scene.background = new THREE.Color(0x0a0a1a);

        // Camera
        const width = container.clientWidth || window.innerWidth;
        const height = container.clientHeight || window.innerHeight;
        camera = new THREE.PerspectiveCamera(60, width / height, 0.1, 1000);
        camera.position.set(0, 2, 6);
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

        // Create scanner elements
        createScannerRing();
        createScanLine();
        createParticles();

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
    };

    /**
     * Create scanner ring
     */
    function createScannerRing() {
        // Outer ring
        const ringGeometry = new THREE.TorusGeometry(1.8, 0.03, 32, 64);
        const ringMaterial = new THREE.MeshBasicMaterial({
            color: 0x00f0ff,
            transparent: true,
            opacity: 0.6,
            blending: THREE.AdditiveBlending
        });

        scannerRing = new THREE.Mesh(ringGeometry, ringMaterial);
        scannerRing.position.set(0, 0, 0);
        scannerRing.rotation.x = Math.PI / 2.5;
        scene.add(scannerRing);

        // Inner ring
        const innerRingGeometry = new THREE.TorusGeometry(1.4, 0.015, 24, 48);
        const innerRingMaterial = new THREE.MeshBasicMaterial({
            color: 0x0066ff,
            transparent: true,
            opacity: 0.4,
            blending: THREE.AdditiveBlending
        });
        const innerRing = new THREE.Mesh(innerRingGeometry, innerRingMaterial);
        innerRing.position.set(0, 0, 0);
        innerRing.rotation.x = Math.PI / 2.5 + 0.1;
        scene.add(innerRing);

        // Store reference
        window._innerRing = innerRing;
    }

    /**
     * Create scan line
     */
    function createScanLine() {
        const lineGeometry = new THREE.RingGeometry(0.1, 1.8, 64);
        const lineMaterial = new THREE.MeshBasicMaterial({
            color: 0x00f0ff,
            transparent: true,
            opacity: 0.2,
            side: THREE.DoubleSide,
            blending: THREE.AdditiveBlending
        });

        scanLine = new THREE.Mesh(lineGeometry, lineMaterial);
        scanLine.position.set(0, 0, 0);
        scanLine.rotation.x = Math.PI / 2.5;
        scene.add(scanLine);

        // Add a glow line
        const glowGeometry = new THREE.RingGeometry(0.5, 1.5, 32);
        const glowMaterial = new THREE.MeshBasicMaterial({
            color: 0x0066ff,
            transparent: true,
            opacity: 0.1,
            side: THREE.DoubleSide,
            blending: THREE.AdditiveBlending
        });
        const glowLine = new THREE.Mesh(glowGeometry, glowMaterial);
        glowLine.position.set(0, 0, 0);
        glowLine.rotation.x = Math.PI / 2.5;
        scene.add(glowLine);

        // Store reference
        window._glowLine = glowLine;
    }

    /**
     * Create particles
     */
    function createParticles() {
        const count = 200;
        const positions = new Float32Array(count * 3);

        for (let i = 0; i < count; i++) {
            const radius = 0.5 + Math.random() * 1.8;
            const angle = Math.random() * Math.PI * 2;
            const height = (Math.random() - 0.5) * 0.5;

            positions[i * 3] = Math.cos(angle) * radius;
            positions[i * 3 + 1] = height;
            positions[i * 3 + 2] = Math.sin(angle) * radius;
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

        const material = new THREE.PointsMaterial({
            size: 0.04,
            color: 0x00f0ff,
            transparent: true,
            opacity: 0.8,
            blending: THREE.AdditiveBlending
        });

        particles = new THREE.Points(geometry, material);
        particles.position.set(0, 0, 0);
        scene.add(particles);
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
    }

    /**
     * Animation loop
     */
    function animate() {
        animationId = requestAnimationFrame(animate);

        const time = Date.now() * 0.001;

        // Rotate scanner ring
        if (scannerRing) {
            scannerRing.rotation.z += 0.005;
            scannerRing.material.opacity = 0.4 + Math.sin(time * 0.8) * 0.2;
        }

        // Animate inner ring
        if (window._innerRing) {
            window._innerRing.rotation.z -= 0.008;
            window._innerRing.material.opacity = 0.3 + Math.sin(time * 1.2 + 1) * 0.15;
        }

        // Animate scan line
        if (scanLine) {
            scanLine.material.opacity = 0.15 + Math.sin(time * 0.5) * 0.1;
            scanLine.scale.set(
                1 + Math.sin(time * 0.3) * 0.05,
                1 + Math.sin(time * 0.3) * 0.05,
                1
            );
        }

        // Animate glow line
        if (window._glowLine) {
            window._glowLine.material.opacity = 0.08 + Math.sin(time * 0.7 + 0.5) * 0.05;
            window._glowLine.scale.set(
                1 + Math.sin(time * 0.4 + 1) * 0.08,
                1 + Math.sin(time * 0.4 + 1) * 0.08,
                1
            );
        }

        // Rotate particles
        if (particles) {
            particles.rotation.y += 0.01;
            particles.rotation.x = Math.sin(time * 0.2) * 0.05;
        }

        renderer.render(scene, camera);
    }

    /**
     * Cleanup
     */
    window.destroyScannerAnimation = function() {
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