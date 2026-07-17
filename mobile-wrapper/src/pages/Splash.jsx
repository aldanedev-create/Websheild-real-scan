import React, { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import * as THREE from 'three';

// Styles
import '../styles/global.css';

const Splash = () => {
  const navigate = useNavigate();
  const containerRef = useRef(null);
  const animationRef = useRef(null);

  useEffect(() => {
    // Three.js animation
    const container = containerRef.current;
    if (!container) return;

    // Scene setup
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0a0a1a);

    const width = container.clientWidth;
    const height = container.clientHeight;
    const camera = new THREE.PerspectiveCamera(60, width / height, 0.1, 1000);
    camera.position.set(0, 0, 8);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Shield shape
    const shape = new THREE.Shape();
    const w = 2;
    const h = 2.4;
    shape.moveTo(0, h / 2);
    shape.quadraticCurveTo(w / 2, h / 2, w / 2, h / 4);
    shape.quadraticCurveTo(w / 2, 0, w / 3, -h / 3);
    shape.lineTo(0, -h / 2);
    shape.lineTo(-w / 3, -h / 3);
    shape.quadraticCurveTo(-w / 2, 0, -w / 2, h / 4);
    shape.quadraticCurveTo(-w / 2, h / 2, 0, h / 2);

    const extrudeSettings = {
      depth: 0.3,
      bevelEnabled: true,
      bevelThickness: 0.1,
      bevelSize: 0.05,
      bevelSegments: 10
    };

    const geometry = new THREE.ExtrudeGeometry(shape, extrudeSettings);
    const material = new THREE.MeshPhongMaterial({
      color: 0x00f0ff,
      emissive: 0x004466,
      emissiveIntensity: 0.3,
      shininess: 80,
      transparent: true,
      opacity: 0.9,
      side: THREE.DoubleSide
    });

    const shield = new THREE.Mesh(geometry, material);
    shield.position.set(0, 0, 0);
    shield.rotation.x = 0.1;
    shield.rotation.z = 0.1;
    scene.add(shield);

    // Particles
    const particleCount = 800;
    const positions = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount; i++) {
      const radius = 3 + Math.random() * 4;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.random() * Math.PI * 2;
      positions[i * 3] = Math.sin(theta) * Math.cos(phi) * radius;
      positions[i * 3 + 1] = Math.sin(theta) * Math.sin(phi) * radius;
      positions[i * 3 + 2] = Math.cos(theta) * radius;
    }

    const particleGeometry = new THREE.BufferGeometry();
    particleGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const particleMaterial = new THREE.PointsMaterial({
      size: 0.05,
      color: 0x00f0ff,
      transparent: true,
      opacity: 0.6,
      blending: THREE.AdditiveBlending
    });

    const particles = new THREE.Points(particleGeometry, particleMaterial);
    scene.add(particles);

    // Lights
    const ambientLight = new THREE.AmbientLight(0x222244, 0.5);
    scene.add(ambientLight);
    const dirLight = new THREE.DirectionalLight(0x00f0ff, 1);
    dirLight.position.set(5, 10, 5);
    scene.add(dirLight);

    // Animation loop
    let startTime = Date.now();

    const animate = () => {
      const time = Date.now() * 0.001;
      shield.rotation.y = Math.sin(time * 0.3) * 0.1;
      shield.rotation.x = 0.1 + Math.sin(time * 0.5) * 0.05;
      shield.position.y = Math.sin(time * 0.8) * 0.1;
      particles.rotation.y += 0.001;
      particles.rotation.x = Math.sin(time * 0.05) * 0.05;

      renderer.render(scene, camera);
      animationRef.current = requestAnimationFrame(animate);
    };

    animate();

    // Handle resize
    const handleResize = () => {
      const w = container.clientWidth;
      const h = container.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    window.addEventListener('resize', handleResize);

    // Auto navigate after 3 seconds
    const timer = setTimeout(() => {
      navigate('/login');
    }, 3000);

    return () => {
      clearTimeout(timer);
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
      window.removeEventListener('resize', handleResize);
      renderer.dispose();
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [navigate]);

  return (
    <div className="splash-container" ref={containerRef}>
      <div className="splash-overlay">
        <div className="splash-title">WebShield</div>
        <div className="splash-subtitle">Security Scanner</div>
      </div>
    </div>
  );
};

export default Splash;