import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

const NetworkMap = ({
  containerId = 'network-map-container',
  data = null,
  nodeCount = 25,
  nodeSize = 0.2,
  edgeOpacity = 0.1,
  color = '#00f0ff',
  autoRotate = true
}) => {
  const containerRef = useRef(null);
  const animationId = useRef(null);
  const sceneRef = useRef(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // Scene setup
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0a0a1a);

    const width = container.clientWidth || window.innerWidth;
    const height = container.clientHeight || window.innerHeight;
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 5, 10);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Create network
    const endpoints = data?.endpoints || [];
    const count = Math.min(endpoints.length, 30);
    
    let positions = [];
    let colors = [];
    let edgePositions = [];

    if (count > 0) {
      // Use real data
      const nodeCount = Math.min(count, 30);
      
      // Central node
      positions.push(0, 0, 0);
      const colorObj = new THREE.Color(color);
      colors.push(colorObj.r, colorObj.g, colorObj.b);

      // Create nodes from endpoints
      for (let i = 1; i < nodeCount + 1; i++) {
        const angle = (i / (nodeCount + 1)) * Math.PI * 2;
        const radius = 2 + Math.random() * 1.5;
        const height = (Math.random() - 0.5) * 1.5;

        positions.push(
          Math.cos(angle + Math.random() * 0.2) * radius,
          height,
          Math.sin(angle + Math.random() * 0.2) * radius
        );

        // Color variation
        const c = colorObj.clone();
        c.multiplyScalar(0.5 + Math.random() * 0.5);
        colors.push(c.r, c.g, c.b);
      }

      // Create edges
      const nodeCountTotal = positions.length / 3;
      for (let i = 0; i < nodeCountTotal; i++) {
        for (let j = i + 1; j < nodeCountTotal; j++) {
          if (Math.random() < 0.12) {
            const idx1 = i * 3;
            const idx2 = j * 3;
            edgePositions.push(
              positions[idx1], positions[idx1 + 1], positions[idx1 + 2],
              positions[idx2], positions[idx2 + 1], positions[idx2 + 2]
            );
          }
        }
      }
    } else {
      // Create demo network
      const totalNodes = nodeCount;
      
      // Central node
      positions.push(0, 0, 0);
      const colorObj = new THREE.Color(color);
      colors.push(colorObj.r, colorObj.g, colorObj.b);

      for (let i = 1; i < totalNodes; i++) {
        const angle = (i / totalNodes) * Math.PI * 2;
        const radius = 2 + Math.random() * 1.5;
        const height = (Math.random() - 0.5) * 1.5;

        positions.push(
          Math.cos(angle + Math.random() * 0.1) * radius,
          height,
          Math.sin(angle + Math.random() * 0.1) * radius
        );

        const c = colorObj.clone();
        c.multiplyScalar(0.5 + Math.random() * 0.5);
        colors.push(c.r, c.g, c.b);
      }

      // Create random edges
      const totalNodesCount = positions.length / 3;
      for (let i = 0; i < Math.min(totalNodesCount * 2, 50); i++) {
        const idx1 = Math.floor(Math.random() * totalNodesCount) * 3;
        const idx2 = Math.floor(Math.random() * totalNodesCount) * 3;
        if (idx1 !== idx2 && Math.random() < 0.15) {
          edgePositions.push(
            positions[idx1], positions[idx1 + 1], positions[idx1 + 2],
            positions[idx2], positions[idx2 + 1], positions[idx2 + 2]
          );
        }
      }
    }

    // Create node geometry
    const nodeGeometry = new THREE.BufferGeometry();
    nodeGeometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    nodeGeometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));

    const nodeMaterial = new THREE.PointsMaterial({
      size: nodeSize,
      vertexColors: true,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending
    });

    const nodes = new THREE.Points(nodeGeometry, nodeMaterial);
    scene.add(nodes);

    // Create edge geometry
    if (edgePositions.length > 0) {
      const edgeGeometry = new THREE.BufferGeometry();
      edgeGeometry.setAttribute('position', new THREE.Float32BufferAttribute(edgePositions, 3));

      const edgeMaterial = new THREE.LineBasicMaterial({
        color: color,
        transparent: true,
        opacity: edgeOpacity,
        blending: THREE.AdditiveBlending
      });

      const edges = new THREE.LineSegments(edgeGeometry, edgeMaterial);
      scene.add(edges);
    }

    // Lights
    const ambientLight = new THREE.AmbientLight(0x222244, 0.5);
    scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(color, 0.5);
    dirLight.position.set(5, 10, 5);
    scene.add(dirLight);

    // Animation loop
    const animate = () => {
      if (nodes) {
        if (autoRotate) {
          nodes.rotation.y += 0.003;
        }
        nodes.rotation.x = Math.sin(Date.now() * 0.0001) * 0.05;
      }
      if (edges) {
        if (autoRotate) {
          edges.rotation.y += 0.003;
        }
        edges.rotation.x = Math.sin(Date.now() * 0.0001) * 0.05;
      }
      renderer.render(scene, camera);
      animationId.current = requestAnimationFrame(animate);
    };

    animate();

    // Handle resize
    const handleResize = () => {
      const w = container.clientWidth || window.innerWidth;
      const h = container.clientHeight || window.innerHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    window.addEventListener('resize', handleResize);

    sceneRef.current = {
      scene,
      camera,
      renderer,
      nodes,
      edges
    };

    return () => {
      if (animationId.current) {
        cancelAnimationFrame(animationId.current);
      }
      window.removeEventListener('resize', handleResize);
      renderer.dispose();
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [data, nodeCount, nodeSize, edgeOpacity, color, autoRotate]);

  return (
    <div 
      ref={containerRef} 
      id={containerId}
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        zIndex: 0,
        pointerEvents: 'none',
        overflow: 'hidden'
      }}
    />
  );
};

export default NetworkMap;