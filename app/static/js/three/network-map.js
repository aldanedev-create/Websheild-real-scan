/**
 * WebShield Scanner - Network Map Animation
 * Creates a 3D network visualization using Three.js.
 */

(function() {
    'use strict';

    let scene, camera, renderer, nodes, edges;
    let animationId = null;

    /**
     * Initialize network map
     */
    window.initNetworkMap = function(containerId, data) {
        const container = document.getElementById(containerId);
        if (!container) return;

        // Clear container
        container.innerHTML = '';

        // Scene setup
        scene = new THREE.Scene();
        scene.background = new THREE.Color(0x0a0a1a);

        // Camera
        const width = container.clientWidth || 600;
        const height = container.clientHeight || 400;
        camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
        camera.position.set(0, 5, 10);
        camera.lookAt(0, 0, 0);

        // Renderer
        renderer = new THREE.WebGLRenderer({
            antialias: true,
            alpha: true
        });
        renderer.setSize(width, height);
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        container.appendChild(renderer.domElement);

        // Create network nodes
        createNetwork(data);

        // Add lights
        addLights();

        // Start animation
        animate();

        // Handle resize
        window.addEventListener('resize', function() {
            const w = container.clientWidth || 600;
            const h = container.clientHeight || 400;
            camera.aspect = w / h;
            camera.updateProjectionMatrix();
            renderer.setSize(w, h);
        });
    };

    /**
     * Create network visualization
     */
    function createNetwork(data) {
        // If no data, create a demo network
        if (!data || !data.endpoints) {
            createDemoNetwork();
            return;
        }

        const endpoints = data.endpoints || [];
        const count = Math.min(endpoints.length, 30);

        if (count === 0) {
            createDemoNetwork();
            return;
        }

        // Generate positions for nodes
        const positions = [];
        const colors = [];
        const connections = [];

        // Central node
        positions.push(0, 0, 0);
        colors.push(0, 0.94, 1); // #00f0ff

        // Create nodes from endpoints
        const nodeCount = Math.min(count + 1, 30);
        for (let i = 1; i < nodeCount; i++) {
            const angle = (i / nodeCount) * Math.PI * 2;
            const radius = 2 + Math.random() * 1.5;
            const height = (Math.random() - 0.5) * 1.5;

            positions.push(
                Math.cos(angle + Math.random() * 0.2) * radius,
                height,
                Math.sin(angle + Math.random() * 0.2) * radius
            );

            // Color based on depth
            const green = 0.4 + Math.random() * 0.6;
            const blue = 0.6 + Math.random() * 0.4;
            colors.push(0, green, blue);
        }

        // Create connections (edges)
        for (let i = 0; i < nodeCount; i++) {
            for (let j = i + 1; j < nodeCount; j++) {
                if (Math.random() < 0.15) {
                    connections.push(i, j);
                }
            }
        }

        // Create node geometry
        const nodeGeometry = new THREE.BufferGeometry();
        nodeGeometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
        nodeGeometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));

        const nodeMaterial = new THREE.PointsMaterial({
            size: 0.2,
            vertexColors: true,
            transparent: true,
            opacity: 0.9,
            blending: THREE.AdditiveBlending
        });

        nodes = new THREE.Points(nodeGeometry, nodeMaterial);
        scene.add(nodes);

        // Create edge geometry
        if (connections.length > 0) {
            const edgePositions = [];
            const posArray = positions;

            for (let i = 0; i < connections.length; i += 2) {
                const idx1 = connections[i] * 3;
                const idx2 = connections[i + 1] * 3;

                edgePositions.push(
                    posArray[idx1], posArray[idx1 + 1], posArray[idx1 + 2],
                    posArray[idx2], posArray[idx2 + 1], posArray[idx2 + 2]
                );
            }

            const edgeGeometry = new THREE.BufferGeometry();
            edgeGeometry.setAttribute('position', new THREE.Float32BufferAttribute(edgePositions, 3));

            const edgeMaterial = new THREE.LineBasicMaterial({
                color: 0x00f0ff,
                transparent: true,
                opacity: 0.15,
                blending: THREE.AdditiveBlending
            });

            edges = new THREE.LineSegments(edgeGeometry, edgeMaterial);
            scene.add(edges);
        }
    }

    /**
     * Create demo network
     */
    function createDemoNetwork() {
        const nodeCount = 20;
        const positions = [];
        const colors = [];

        // Central node
        positions.push(0, 0, 0);
        colors.push(0, 0.94, 1);

        for (let i = 1; i < nodeCount; i++) {
            const angle = (i / nodeCount) * Math.PI * 2;
            const radius = 2 + Math.random() * 1.5;
            const height = (Math.random() - 0.5) * 1.5;

            positions.push(
                Math.cos(angle) * radius,
                height,
                Math.sin(angle) * radius
            );

            colors.push(0, 0.4 + Math.random() * 0.6, 0.6 + Math.random() * 0.4);
        }

        const nodeGeometry = new THREE.BufferGeometry();
        nodeGeometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
        nodeGeometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));

        const nodeMaterial = new THREE.PointsMaterial({
            size: 0.25,
            vertexColors: true,
            transparent: true,
            opacity: 0.8,
            blending: THREE.AdditiveBlending
        });

        nodes = new THREE.Points(nodeGeometry, nodeMaterial);
        scene.add(nodes);

        // Create some random edges
        const edgePositions = [];
        for (let i = 0; i < 30; i++) {
            const idx1 = Math.floor(Math.random() * nodeCount) * 3;
            const idx2 = Math.floor(Math.random() * nodeCount) * 3;
            if (idx1 !== idx2) {
                edgePositions.push(
                    positions[idx1], positions[idx1 + 1], positions[idx1 + 2],
                    positions[idx2], positions[idx2 + 1], positions[idx2 + 2]
                );
            }
        }

        if (edgePositions.length > 0) {
            const edgeGeometry = new THREE.BufferGeometry();
            edgeGeometry.setAttribute('position', new THREE.Float32BufferAttribute(edgePositions, 3));

            const edgeMaterial = new THREE.LineBasicMaterial({
                color: 0x00f0ff,
                transparent: true,
                opacity: 0.1,
                blending: THREE.AdditiveBlending
            });

            edges = new THREE.LineSegments(edgeGeometry, edgeMaterial);
            scene.add(edges);
        }
    }

    /**
     * Add lights
     */
    function addLights() {
        const ambientLight = new THREE.AmbientLight(0x222244, 0.5);
        scene.add(ambientLight);

        const dirLight = new THREE.DirectionalLight(0x00f0ff, 0.5);
        dirLight.position.set(5, 10, 5);
        scene.add(dirLight);
    }

    /**
     * Animation loop
     */
    function animate() {
        animationId = requestAnimationFrame(animate);

        if (nodes) {
            nodes.rotation.y += 0.003;
            nodes.rotation.x = Math.sin(Date.now() * 0.0001) * 0.05;
        }

        if (edges) {
            edges.rotation.y += 0.003;
            edges.rotation.x = Math.sin(Date.now() * 0.0001) * 0.05;
        }

        renderer.render(scene, camera);
    }

    /**
     * Cleanup
     */
    window.destroyNetworkMap = function() {
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