import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { reportApi } from '../api/reportApi.js';
import { getToken } from '../api/client.js';
import * as THREE from 'three';
import '../styles/global.css';

const AttackSurfaceMap = () => {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const containerRef = useRef(null);
  const animationRef = useRef(null);
  const sceneRef = useRef(null);

  useEffect(() => {
    const token = getToken();
    if (!token) {
      navigate('/login');
      return;
    }

    loadData();
  }, [scanId]);

  useEffect(() => {
    if (data) {
      initThreeScene();
    }
    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
      if (sceneRef.current) {
        sceneRef.current.dispose();
      }
    };
  }, [data]);

  const loadData = async () => {
    setLoading(true);
    setError('');

    try {
      const response = await reportApi.getReport(scanId);
      if (response.success) {
        const surfaceData = response.report.scan.attack_surface_data;
        setData(surfaceData || {});
      } else {
        setError(response.message || 'Failed to load attack surface data.');
      }
    } catch (err) {
      console.error('Attack surface error:', err);
      setError('An error occurred while loading data.');
    } finally {
      setLoading(false);
    }
  };

  const initThreeScene = () => {
    const container = containerRef.current;
    if (!container) return;

    // Clean up previous scene
    if (sceneRef.current) {
      sceneRef.current.dispose();
    }

    // Scene setup
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0a0a1a);

    const width = container.clientWidth;
    const height = container.clientHeight || 400;
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

    // Get endpoints
    const endpoints = data?.endpoints || [];
    const count = Math.min(endpoints.length, 30);

    if (count === 0) {
      // Create demo network
      createDemoNetwork(scene);
    } else {
      createNetwork(scene, endpoints);
    }

    // Add lights
    const ambientLight = new THREE.AmbientLight(0x222244, 0.5);
    scene.add(ambientLight);
    const dirLight = new THREE.DirectionalLight(0x00f0ff, 0.5);
    dirLight.position.set(5, 10, 5);
    scene.add(dirLight);

    // Animation loop
    let nodes = null;
    let edges = null;
    scene.children.forEach(child => {
      if (child.type === 'Points') nodes = child;
      if (child.type === 'LineSegments') edges = child;
    });

    const animate = () => {
      if (nodes) {
        nodes.rotation.y += 0.003;
        nodes.rotation.x = Math.sin(Date.now() * 0.0001) * 0.05;
      }
      if (edges) {
        edges.rotation.y += 0.003;
        edges.rotation.x = Math.sin(Date.now() * 0.0001) * 0.05;
      }
      renderer.render(scene, camera);
      animationRef.current = requestAnimationFrame(animate);
    };

    animate();

    // Handle resize
    const handleResize = () => {
      const w = container.clientWidth;
      const h = container.clientHeight || 400;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    window.addEventListener('resize', handleResize);

    sceneRef.current = {
      dispose: () => {
        renderer.dispose();
        if (container.contains(renderer.domElement)) {
          container.removeChild(renderer.domElement);
        }
        window.removeEventListener('resize', handleResize);
      }
    };
  };

  const createNetwork = (scene, endpoints) => {
    const count = Math.min(endpoints.length, 30);
    const positions = [];
    const colors = [];

    // Central node
    positions.push(0, 0, 0);
    colors.push(0, 0.94, 1);

    for (let i = 1; i < count + 1; i++) {
      const angle = (i / (count + 1)) * Math.PI * 2;
      const radius = 2 + Math.random() * 1.5;
      const height = (Math.random() - 0.5) * 1.5;

      positions.push(
        Math.cos(angle + Math.random() * 0.2) * radius,
        height,
        Math.sin(angle + Math.random() * 0.2) * radius
      );

      colors.push(0, 0.4 + Math.random() * 0.6, 0.6 + Math.random() * 0.4);
    }

    // Node geometry
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

    const nodes = new THREE.Points(nodeGeometry, nodeMaterial);
    scene.add(nodes);

    // Edge geometry
    const edgePositions = [];
    for (let i = 0; i < positions.length; i += 3) {
      for (let j = i + 3; j < positions.length; j += 3) {
        if (Math.random() < 0.1) {
          edgePositions.push(
            positions[i], positions[i + 1], positions[i + 2],
            positions[j], positions[j + 1], positions[j + 2]
          );
        }
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

      const edges = new THREE.LineSegments(edgeGeometry, edgeMaterial);
      scene.add(edges);
    }
  };

  const createDemoNetwork = (scene) => {
    const nodeCount = 20;
    const positions = [];
    const colors = [];

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

    const nodes = new THREE.Points(nodeGeometry, nodeMaterial);
    scene.add(nodes);

    // Random edges
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
        opacity: 0.08,
        blending: THREE.AdditiveBlending
      });
      const edges = new THREE.LineSegments(edgeGeometry, edgeMaterial);
      scene.add(edges);
    }
  };

  const renderList = (items, limit = 50) => {
    if (!items || items.length === 0) {
      return <div className="no-data">None detected</div>;
    }

    const displayItems = items.slice(0, limit);
    const hasMore = items.length > limit;

    return (
      <>
        {displayItems.map((item, index) => (
          <div key={index} className="item">{item}</div>
        ))}
        {hasMore && (
          <div className="item" style={{ color: '#667', fontStyle: 'italic' }}>
            + {items.length - limit} more...
          </div>
        )}
      </>
    );
  };

  const asArray = (value) => Array.isArray(value) ? value : [];

  const renderMiniList = (label, values) => {
    const items = asArray(values).filter(Boolean).slice(0, 5);
    if (!items.length) return null;

    return (
      <div className="analysis-meta">
        <strong>{label}:</strong> {items.map(item => typeof item === 'string' ? item : JSON.stringify(item)).join(' · ')}
      </div>
    );
  };

  const renderAnalysisCards = (items, emptyMessage, renderItem) => {
    const values = asArray(items).filter(Boolean);
    if (!values.length) {
      return <div className="no-data">{emptyMessage}</div>;
    }
    return values.slice(0, 10).map(renderItem);
  };

  if (loading) {
    return (
      <div className="page-container">
        <div className="loading-container">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
          <p className="mt-2 text-muted">Loading attack surface data...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page-container">
        <div className="alert alert-danger" role="alert">
          <i className="fas fa-exclamation-circle me-2"></i>
          {error}
        </div>
        <button className="btn btn-secondary" onClick={() => navigate('/dashboard')}>
          <i className="fas fa-arrow-left"></i> Back to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">
          <i className="fas fa-sitemap"></i> Attack Surface Map
        </h1>
        <span className="text-muted" style={{ fontSize: '0.85rem' }}>
          {data?.target_url || 'N/A'}
        </span>
      </div>

      <div className="surface-intel">
        <div className="surface-section">
          <h4><i className="fas fa-crosshairs"></i> Pentest Exposure Summary</h4>
          <div className="risk-row">
            <div className="risk-score">{data?.risk_score || 0}/100</div>
            <div>
              <span className={`severity-pill ${data?.risk_level || 'minimal'}`}>
                {data?.risk_level || 'unknown'}
              </span>
              <div className="analysis-meta" style={{ marginTop: 8 }}>
                {data?.exposure_summary || 'No exposure summary available.'}
              </div>
            </div>
          </div>
        </div>

        <div className="surface-section">
          <h4><i className="fas fa-seedling"></i> Honeypot / WAF Signal</h4>
          <span className={`severity-pill ${data?.honeypot_assessment?.likelihood || 'minimal'}`}>
            {data?.honeypot_assessment?.likelihood || 'unknown'}
          </span>
          <div className="analysis-meta" style={{ marginTop: 8 }}>
            {asArray(data?.honeypot_assessment?.notes)[0] || 'No deception indicators available.'}
          </div>
          {renderMiniList('Signals', asArray(data?.honeypot_assessment?.indicators).map(item => item.type))}
        </div>
      </div>

      {/* Stats */}
      <div className="surface-stats">
        <div className="surface-stat">
          <div className="num">{data?.total_pages || 0}</div>
          <div className="label">Total Pages</div>
        </div>
        <div className="surface-stat">
          <div className="num">{(data?.endpoints || []).length}</div>
          <div className="label">Endpoints</div>
        </div>
        <div className="surface-stat">
          <div className="num">{(data?.forms || []).length}</div>
          <div className="label">Forms</div>
        </div>
        <div className="surface-stat">
          <div className="num">{(data?.login_pages || []).length}</div>
          <div className="label">Login Pages</div>
        </div>
        <div className="surface-stat">
          <div className="num">{(data?.api_endpoints || []).length}</div>
          <div className="label">API Endpoints</div>
        </div>
        <div className="surface-stat">
          <div className="num">{(data?.admin_pages || []).length}</div>
          <div className="label">Admin Pages</div>
        </div>
      </div>

      {/* 3D Map */}
      <div className="surface-map-container" ref={containerRef} style={{ minHeight: '400px' }}></div>

      {/* Details */}
      <div className="surface-details">
        <div className="surface-section">
          <h4><i className="fas fa-code"></i> Technologies Detected</h4>
          <div className="technologies">
            {data?.technologies && data.technologies.length > 0 ? (
              data.technologies.map((tech, index) => (
                <span key={index} className="tech-tag">{tech}</span>
              ))
            ) : (
              <div className="no-data">No technologies detected</div>
            )}
          </div>
        </div>

        <div className="surface-section">
          <h4><i className="fas fa-file"></i> File Types</h4>
          <div>
            {data?.file_types && Object.keys(data.file_types).length > 0 ? (
              Object.entries(data.file_types)
                .sort((a, b) => b[1] - a[1])
                .map(([ext, count]) => (
                  <div key={ext} className="item">
                    <span>.<strong>{ext}</strong></span>
                    <span className="badge-count">{count}</span>
                  </div>
                ))
            ) : (
              <div className="no-data">No files detected</div>
            )}
          </div>
        </div>

        <div className="surface-section">
          <h4><i className="fas fa-link"></i> Directories</h4>
          <div className="item-list">
            {renderList(data?.directories)}
          </div>
        </div>

        <div className="surface-section">
          <h4><i className="fas fa-user-lock"></i> Login Pages</h4>
          <div className="item-list">
            {renderList(data?.login_pages)}
          </div>
        </div>

        <div className="surface-section">
          <h4><i className="fas fa-server"></i> API Endpoints</h4>
          <div className="item-list">
            {renderList(data?.api_endpoints)}
          </div>
        </div>

        <div className="surface-section">
          <h4><i className="fas fa-user-shield"></i> Admin Pages</h4>
          <div className="item-list">
            {renderList(data?.admin_pages)}
          </div>
        </div>

        <div className="surface-section">
          <h4><i className="fas fa-layer-group"></i> OWASP Review Buckets</h4>
          <div className="item-list analysis-list">
            {renderAnalysisCards(
              asArray(data?.owasp_buckets).filter(bucket => Number(bucket.count || 0) > 0),
              'No review buckets available',
              (bucket, index) => (
                <div key={index} className="analysis-card">
                  <div className="analysis-title">
                    <span>{bucket.name}</span>
                    <span className={`severity-pill ${bucket.risk || 'medium'}`}>{bucket.risk || 'medium'} · {bucket.count || 0}</span>
                  </div>
                  <div>{bucket.description}</div>
                  {renderMiniList('Test focus', bucket.testing_focus)}
                  {renderMiniList('Examples', bucket.examples)}
                </div>
              )
            )}
          </div>
        </div>

        <div className="surface-section">
          <h4><i className="fas fa-route"></i> Likely Attack Paths</h4>
          <div className="item-list analysis-list">
            {renderAnalysisCards(data?.attack_paths, 'No attack paths inferred', (path, index) => (
              <div key={index} className="analysis-card">
                <div className="analysis-title">
                  <span>{path.title}</span>
                  <span className={`severity-pill ${path.severity || 'medium'}`}>{path.severity || 'medium'}</span>
                </div>
                <div>{path.how_it_could_be_hacked}</div>
                {renderMiniList('Start with', path.entry)}
                {renderMiniList('Pentest steps', path.pentest_steps)}
              </div>
            ))}
          </div>
        </div>

        <div className="surface-section">
          <h4><i className="fas fa-database"></i> Sensitive Data Signals</h4>
          <div className="item-list analysis-list">
            {renderAnalysisCards(data?.sensitive_data_signals, 'No sensitive data signals inferred', (signal, index) => (
              <div key={index} className="analysis-card">
                <div className="analysis-title">
                  <span>{signal.data_type}</span>
                  <span className="severity-pill medium">{signal.confidence || 'medium'}</span>
                </div>
                {renderMiniList('Evidence', signal.evidence)}
                {renderMiniList('Review focus', signal.review_focus)}
              </div>
            ))}
          </div>
        </div>

        <div className="surface-section">
          <h4><i className="fas fa-code-branch"></i> Trust Boundaries</h4>
          <div className="item-list analysis-list">
            {renderAnalysisCards(data?.trust_boundaries, 'No trust boundaries inferred', (boundary, index) => (
              <div key={index} className="analysis-card">
                <div className="analysis-title">
                  <span>{boundary.name}</span>
                  <span className={`severity-pill ${boundary.risk || 'medium'}`}>{boundary.risk || 'medium'}</span>
                </div>
                <div>{boundary.evidence}</div>
                {renderMiniList('Controls', boundary.controls_to_verify)}
              </div>
            ))}
          </div>
        </div>

        <div className="surface-section">
          <h4><i className="fas fa-clipboard-check"></i> Review Priorities</h4>
          <div className="item-list analysis-list">
            {renderAnalysisCards(data?.review_priorities, 'No priorities available', (priority, index) => (
              <div key={index} className="analysis-card">
                <div className="analysis-title">
                  <span>{priority.area}</span>
                  <span className={`severity-pill ${priority.priority || 'medium'}`}>{priority.priority || 'medium'}</span>
                </div>
                <div>{priority.why}</div>
                {renderMiniList('Start with', priority.start_with)}
                {renderMiniList('Test for', priority.test_for)}
              </div>
            ))}
          </div>
        </div>
      </div>

      <style>{`
        .surface-intel {
          display: grid;
          grid-template-columns: 1fr;
          gap: 12px;
          margin-bottom: 16px;
        }
        .risk-row {
          display: flex;
          gap: 12px;
          align-items: center;
        }
        .risk-score {
          font-family: Orbitron, monospace;
          font-size: 1.8rem;
          color: #00f0ff;
          min-width: 92px;
        }
        .analysis-list {
          display: grid;
          gap: 10px;
        }
        .analysis-card {
          background: rgba(255, 255, 255, 0.03);
          border: 1px solid rgba(255, 255, 255, 0.05);
          border-radius: 8px;
          padding: 10px;
          color: #ccd;
          font-size: 0.78rem;
        }
        .analysis-title {
          display: flex;
          justify-content: space-between;
          gap: 8px;
          color: #fff;
          font-weight: 700;
          margin-bottom: 6px;
        }
        .analysis-meta {
          color: #8899aa;
          font-size: 0.72rem;
          line-height: 1.45;
          margin-top: 6px;
        }
        .severity-pill {
          border-radius: 999px;
          padding: 2px 8px;
          font-size: 0.62rem;
          text-transform: uppercase;
          white-space: nowrap;
          background: rgba(255, 255, 255, 0.08);
          color: #ccd;
        }
        .severity-pill.critical,
        .severity-pill.high {
          color: #ff8a80;
          background: rgba(244, 67, 54, 0.1);
        }
        .severity-pill.medium,
        .severity-pill.low-medium {
          color: #ffd166;
          background: rgba(255, 193, 7, 0.1);
        }
        .severity-pill.low,
        .severity-pill.minimal {
          color: #8df7a7;
          background: rgba(76, 175, 80, 0.1);
        }
      `}</style>
    </div>
  );
};

export default AttackSurfaceMap;
