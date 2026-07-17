import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

const CyberGrid = ({ 
  containerId = 'cyber-grid-container',
  gridSize = 20,
  spacing = 1.2,
  color = '#00f0ff',
  opacity = 0.6,
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
    const camera = new THREE.PerspectiveCamera(60, width / height, 0.1, 1000);
    camera.position.set(0, 5, 15);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Create grid points
    const points = [];
    const colors = [];
    const colorObj = new THREE.Color(color);

    for (let x = -gridSize / 2; x < gridSize / 2; x++) {
      for (let z = -gridSize / 2; z < gridSize / 2; z++) {
        const y = Math.sin(x * 0.3) * Math.cos(z * 0.3) * 0.3;
        points.push(x * spacing, y, z * spacing);
        
        // Vary color slightly
        const c = colorObj.clone();
        c.multiplyScalar(0.6 + Math.sin(x * 0.2 + z * 0.2) * 0.2 + 0.4);
        colors.push(c.r, c.g, c.b);
      }
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.Float32BufferAttribute(points, 3));
    geometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
      size: 0.08,
      vertexColors: true,
      transparent: true,
      opacity: opacity,
      blending: THREE.AdditiveBlending
    });

    const grid = new THREE.Points(geometry, material);
    scene.add(grid);

    // Add connecting lines
    const linePositions = [];
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

    const keys = Object.keys(pointMap);
    keys.forEach(key => {
      const [x, z] = key.split(',').map(Number);
      const current = pointMap[key];

      const rightKey = (x + 1) + ',' + z;
      if (pointMap[rightKey]) {
        const right = pointMap[rightKey];
        linePositions.push(current.x, current.y, current.z);
        linePositions.push(right.x, right.y, right.z);
      }

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
      color: color,
      transparent: true,
      opacity: 0.08,
      blending: THREE.AdditiveBlending
    });

    const lines = new THREE.LineSegments(lineGeometry, lineMaterial);
    scene.add(lines);

    // Add lights
    const ambientLight = new THREE.AmbientLight(0x222244, 0.5);
    scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0x00f0ff, 0.8);
    dirLight.position.set(5, 10, 5);
    scene.add(dirLight);

    // Animation loop
    const animate = () => {
      if (grid) {
        grid.rotation.y += 0.001;
        grid.rotation.x = Math.sin(Date.now() * 0.0001) * 0.05;
      }
      if (lines) {
        lines.rotation.y += 0.001;
        lines.rotation.x = Math.sin(Date.now() * 0.0001) * 0.05;
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

    // Store for cleanup
    sceneRef.current = {
      scene,
      camera,
      renderer,
      grid,
      lines
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
  }, [gridSize, spacing, color, opacity]);

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

export default CyberGrid;