/**
 * WebShield Scanner - Splash Animation
 * Creates the 3D splash screen animation using Three.js.
 */

(function() {
    'use strict';

    let scene, camera, renderer, shield, particles, glowRing;
    let animationId = null;

    /**
     * Initialize splash animation
     */
    window.initSplashAnimation = function(containerId = 'three-container') {
        const container = document.getElementById(containerId);
        if (!container) return;

        // Scene setup
        scene = new THREE.Scene();
        scene.background = new THREE.Color(0x0a0a1a);

        // Camera
        const width = container.clientWidth || window.innerWidth;
        const height = container.clientHeight || window.innerHeight;
        camera = new THREE.PerspectiveCamera(60, width / height, 0.1, 1000);
        camera.position.set(0, 0, 8);
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

        // Create shield
        createShield();

        // Create particles
        createParticles();

        // Create glow ring
        createGlowRing();

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
     * Create shield geometry
     */
    function createShield() {
        // Create a shield shape using a custom geometry
        const shape = new THREE.Shape();
        const width = 2;
        const height = 2.4;

        // Shield shape: top curve, straight sides, pointed bottom
        shape.moveTo(0, height / 2);
        shape.quadraticCurveTo(width / 2, height / 2, width / 2, height / 4);
        shape.quadraticCurveTo(width / 2, 0, width / 3, -height / 3);
        shape.lineTo(0, -height / 2);
        shape.lineTo(-width / 3, -height / 3);
        shape.quadraticCurveTo(-width / 2, 0, -width / 2, height / 4);
        shape.quadraticCurveTo(-width / 2, height / 2, 0, height / 2);

        // Extrude settings
        const extrudeSettings = {
            depth: 0.3,
            bevelEnabled: true,
            bevelThickness: 0.1,
            bevelSize: 0.05,
            bevelSegments: 10
        };

        const geometry = new THREE.ExtrudeGeometry(shape, extrudeSettings);

        // Create material with gradient
        const material = new THREE.MeshPhongMaterial({
            color: 0x00f0ff,
            emissive: 0x004466,
            emissiveIntensity: 0.3,
            shininess: 80,
            transparent: true,
            opacity: 0.9,
            side: THREE.DoubleSide
        });

        shield = new THREE.Mesh(geometry, material);
        shield.position.set(0, 0, 0);
        shield.rotation.x = 0.1;
        shield.rotation.z = 0.1;
        scene.add(shield);

        // Add inner glow (smaller shield)
        const innerMaterial = new THREE.MeshPhongMaterial({
            color: 0x0066ff,
            emissive: 0x0066ff,
            emissiveIntensity: 0.5,
            transparent: true,
            opacity: 0.3,
            side: THREE.DoubleSide
        });
        const innerShield = new THREE.Mesh(geometry.clone(), innerMaterial);
        innerShield.scale.set(0.85, 0.85, 0.85);
        innerShield.position.set(0, 0, 0.05);
        innerShield.rotation.x = 0.1;
        innerShield.rotation.z = 0.1;
        scene.add(innerShield);
    }

    /**
     * Create particles
     */
    function createParticles() {
        const particleCount = 1000;
        const positions = new Float32Array(particleCount * 3);
        const colors = new Float32Array(particleCount * 3);

        for (let i = 0; i < particleCount; i++) {
            const radius = 3 + Math.random() * 4;
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.random() * Math.PI * 2;

            positions[i * 3] = Math.sin(theta) * Math.cos(phi) * radius;
            positions[i * 3 + 1] = Math.sin(theta) * Math.sin(phi) * radius;
            positions[i * 3 + 2] = Math.cos(theta) * radius;

            colors[i * 3] = 0.0;
            colors[i * 3 + 1] = 0.6 + Math.random() * 0.4;
            colors[i * 3 + 2] = 0.8 + Math.random() * 0.2;
        }

        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

        const material = new THREE.PointsMaterial({
            size: 0.05,
            vertexColors: true,
            transparent: true,
            opacity: 0.8,
            blending: THREE.AdditiveBlending
        });

        particles = new THREE.Points(geometry, material);
        scene.add(particles);
    }

    /**
     * Create glow ring
     */
    function createGlowRing() {
        const ringGeometry = new THREE.TorusGeometry(1.8, 0.02, 32, 64);
        const ringMaterial = new THREE.MeshBasicMaterial({
            color: 0x00f0ff,
            transparent: true,
            opacity: 0.3,
            blending: THREE.AdditiveBlending
        });

        glowRing = new THREE.Mesh(ringGeometry, ringMaterial);
        glowRing.position.set(0, 0.1, 0);
        glowRing.rotation.x = Math.PI / 2;
        scene.add(glowRing);

        // Second ring
        const ring2Geometry = new THREE.TorusGeometry(1.5, 0.01, 16, 64);
        const ring2Material = new THREE.MeshBasicMaterial({
            color: 0x0066ff,
            transparent: true,
            opacity: 0.2,
            blending: THREE.AdditiveBlending
        });
        const ring2 = new THREE.Mesh(ring2Geometry, ring2Material);
        ring2.position.set(0, -0.1, 0);
        ring2.rotation.x = Math.PI / 2 + 0.1;
        scene.add(ring2);

        // Store reference for animation
        window._glowRing2 = ring2;
    }

    /**
     * Add lights
     */
    function addLights() {
        const ambientLight = new THREE.AmbientLight(0x222244, 0.5);
        scene.add(ambientLight);

        const dirLight = new THREE.DirectionalLight(0x00f0ff, 1);
        dirLight.position.set(5, 10, 5);
        scene.add(dirLight);

        const pointLight = new THREE.PointLight(0x0066ff, 0.8, 20);
        pointLight.position.set(-5, 5, -5);
        scene.add(pointLight);

        // Add spot light behind shield
        const spotLight = new THREE.SpotLight(0x00f0ff, 0.5, 20, Math.PI / 4);
        spotLight.position.set(0, 0, 5);
        spotLight.target.position.set(0, 0, 0);
        scene.add(spotLight);
        scene.add(spotLight.target);
    }

    /**
     * Animation loop
     */
    function animate() {
        animationId = requestAnimationFrame(animate);

        const time = Date.now() * 0.001;

        // Rotate shield
        if (shield) {
            shield.rotation.y = Math.sin(time * 0.3) * 0.1;
            shield.rotation.x = 0.1 + Math.sin(time * 0.5) * 0.05;
            shield.position.y = Math.sin(time * 0.8) * 0.1;
        }

        // Rotate particles
        if (particles) {
            particles.rotation.x = Math.sin(time * 0.05) * 0.1;
            particles.rotation.y += 0.001;
            particles.rotation.z = Math.sin(time * 0.03) * 0.05;
        }

        // Pulse glow ring
        if (glowRing) {
            const scale = 1 + Math.sin(time * 0.8) * 0.05;
            glowRing.scale.set(scale, scale, scale);
            glowRing.material.opacity = 0.2 + Math.sin(time * 0.8) * 0.1;
        }

        // Animate second ring
        if (window._glowRing2) {
            const ring2 = window._glowRing2;
            const scale2 = 1 + Math.sin(time * 0.6 + 1) * 0.08;
            ring2.scale.set(scale2, scale2, scale2);
            ring2.rotation.z += 0.005;
        }

        renderer.render(scene, camera);
    }

    /**
     * Cleanup
     */
    window.destroySplashAnimation = function() {
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