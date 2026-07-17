import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

const ScannerAnimation = ({
  containerId = 'scanner-animation-container',
  ringColor = '#00f0ff',
  ringSize = 1.8,
  autoRotate = true,
  particleCount = 200
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
    camera.position.set(0, 2, 6);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Outer ring
    const ringGeometry = new THREE.TorusGeometry(ringSize, 0.03, 32, 64);
    const ringMaterial = new THREE.MeshBasicMaterial({
      color: ringColor,
      transparent: true,
      opacity: 0.6,
      blending: THREE.AdditiveBlending
    });

    const scannerRing = new THREE.Mesh(ringGeometry, ringMaterial);
    scannerRing.position.set(0, 0, 0);
    scannerRing.rotation.x = Math.PI / 2.5;
    scene.add(scannerRing);

    // Inner ring
    const innerRingGeometry = new THREE.TorusGeometry(ringSize * 0.8, 0.015, 24, 48);
    const innerRingMaterial = new THREE.MeshBasicMaterial({
      color: '#0066ff',
      transparent: true,
      opacity: 0.4,
      blending: THREE.AdditiveBlending
    });
    const innerRing = new THREE.Mesh(innerRingGeometry, innerRingMaterial);
    innerRing.position.set(0, 0, 0);
    innerRing.rotation.x = Math.PI / 2.5 + 0.1;
    scene.add(innerRing);

    // Scan line (ring with partial opacity)
    const scanLineGeometry = new THREE.RingGeometry(0.1, ringSize, 64);
    const scanLineMaterial = new THREE.MeshBasicMaterial({
      color: ringColor,
      transparent: true,
      opacity: 0.15,
      side: THREE.DoubleSide,
      blending: THREE.AdditiveBlending
    });
    const scanLine = new THREE.Mesh(scanLineGeometry, scanLineMaterial);
    scanLine.position.set(0, 0, 0);
    scanLine.rotation.x = Math.PI / 2.5;
    scene.add(scanLine);

    // Glow line
    const glowGeometry = new THREE.RingGeometry(ringSize * 0.3, ringSize * 0.8, 32);
    const glowMaterial = new THREE.MeshBasicMaterial({
      color: '#0066ff',
      transparent: true,
      opacity: 0.08,
      side: THREE.DoubleSide,
      blending: THREE.AdditiveBlending
    });
    const glowLine = new THREE.Mesh(glowGeometry, glowMaterial);
    glowLine.position.set(0, 0, 0);
    glowLine.rotation.x = Math.PI / 2.5;
    scene.add(glowLine);

    // Particles
    const positions = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount; i++) {
      const radius = 0.5 + Math.random() * (ringSize - 0.3);
      const angle = Math.random() * Math.PI * 2;
      const height = (Math.random() - 0.5) * 0.5;

      positions[i * 3] = Math.cos(angle) * radius;
      positions[i * 3 + 1] = height;
      positions[i * 3 + 2] = Math.sin(angle) * radius;
    }

    const particleGeometry = new THREE.BufferGeometry();
    particleGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const particleMaterial = new THREE.PointsMaterial({
      size: 0.04,
      color: ringColor,
      transparent: true,
      opacity: 0.8,
      blending: THREE.AdditiveBlending
    });

    const particles = new THREE.Points(particleGeometry, particleMaterial);
    particles.position.set(0, 0, 0);
    scene.add(particles);

    // Lights
    const ambientLight = new THREE.AmbientLight(0x222244, 0.5);
    scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(ringColor, 0.8);
    dirLight.position.set(5, 10, 5);
    scene.add(dirLight);

    // Animation loop
    const animate = () => {
      const time = Date.now() * 0.001;

      scannerRing.rotation.z += 0.005;
      scannerRing.material.opacity = 0.4 + Math.sin(time * 0.8) * 0.2;

      innerRing.rotation.z -= 0.008;
      innerRing.material.opacity = 0.3 + Math.sin(time * 1.2 + 1) * 0.15;

      scanLine.material.opacity = 0.15 + Math.sin(time * 0.5) * 0.1;
      const scale = 1 + Math.sin(time * 0.3) * 0.05;
      scanLine.scale.set(scale, scale, 1);

      glowLine.material.opacity = 0.08 + Math.sin(time * 0.7 + 0.5) * 0.05;
      const glowScale = 1 + Math.sin(time * 0.4 + 1) * 0.08;
      glowLine.scale.set(glowScale, glowScale, 1);

      particles.rotation.y += 0.01;
      particles.rotation.x = Math.sin(time * 0.2) * 0.05;

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
      scannerRing,
      innerRing,
      scanLine,
      glowLine,
      particles
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
  }, [ringColor, ringSize, particleCount]);

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

export default ScannerAnimation;