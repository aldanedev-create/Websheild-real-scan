import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { scanApi } from '../api/scanApi.js';
import { getToken } from '../api/client.js';
import '../styles/global.css';

const Dashboard = ({ user }) => {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    const token = getToken();
    if (!token) {
      navigate('/login');
      return;
    }

    setLoading(true);
    setError('');

    try {
      // Load stats and recent scans in parallel
      const [statsData, scansData] = await Promise.all([
        scanApi.getStats(),
        scanApi.getScanHistory(1, 5)
      ]);

      if (statsData.success) {
        setStats(statsData.stats);
      }

      if (scansData.success) {
        setRecentScans(scansData.scans || []);
      }
    } catch (err) {
      console.error('Dashboard error:', err);
      setError('Failed to load dashboard data.');
    } finally {
      setLoading(false);
    }
  };

  const getScoreClass = (score) => {
    if (score === null || score === undefined || score === '') return 'text-muted';
    if (score >= 80) return 'score-good';
    if (score >= 60) return 'score-medium';
    return 'score-bad';
  };

  const formatScore = (score) => {
    if (score === null || score === undefined || score === '') return '--';
    const parsed = Number(score);
    return Number.isFinite(parsed) ? Math.round(parsed) : '--';
  };

  const getStatusIcon = (status) => {
    const icons = {
      completed: 'fa-check-circle',
      running: 'fa-spinner fa-spin',
      pending: 'fa-clock',
      failed: 'fa-exclamation-circle',
      cancelled: 'fa-ban'
    };
    return icons[status] || 'fa-circle';
  };

  const getStatusColor = (status) => {
    const colors = {
      completed: '#4caf50',
      running: '#00f0ff',
      pending: '#ff9800',
      failed: '#f44336',
      cancelled: '#667'
    };
    return colors[status] || '#667';
  };

  if (loading) {
    return (
      <div className="page-container">
        <div className="loading-container">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
          <p className="mt-2 text-muted">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">
          <i className="fas fa-home"></i> Dashboard
        </h1>
      </div>

      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          <i className="fas fa-exclamation-circle me-2"></i>
          {error}
          <button type="button" className="btn-close" onClick={() => setError('')}></button>
        </div>
      )}

      {/* Stats */}
      {stats && (
        <div className="dashboard-stats">
          <div className="stat-card">
            <div className="stat-number">{stats.total_scans || 0}</div>
            <div className="stat-label">Total Scans</div>
          </div>
          <div className="stat-card">
            <div className={`stat-number ${getScoreClass(stats.average_score)}`}>
              {formatScore(stats.average_score)}
            </div>
            <div className="stat-label">Avg Security Score</div>
          </div>
          <div className="stat-card">
            <div className="stat-number">
              {Object.values(stats.findings_by_severity || {}).reduce((a, b) => a + b, 0)}
            </div>
            <div className="stat-label">Total Findings</div>
          </div>
          <div className="stat-card">
            <div className="stat-number">{stats.remaining_scans ?? '∞'}</div>
            <div className="stat-label">Scans Remaining Today</div>
          </div>
        </div>
      )}

      {/* Quick Actions */}
      <div className="quick-actions">
        <Link to="/new-scan" className="quick-action-btn">
          <i className="fas fa-plus-circle"></i>
          <span>New Scan</span>
        </Link>
        <Link to="/learning-center" className="quick-action-btn">
          <i className="fas fa-graduation-cap"></i>
          <span>Learn</span>
        </Link>
        <Link to="/settings" className="quick-action-btn">
          <i className="fas fa-cog"></i>
          <span>Settings</span>
        </Link>
        <Link to="/learning-center" className="quick-action-btn">
          <i className="fas fa-book-open"></i>
          <span>Lessons</span>
        </Link>
      </div>

      {/* Recent Scans */}
      <div className="recent-scans">
        <h3 className="section-title">
          <i className="fas fa-clock"></i> Recent Scans
        </h3>
        {recentScans.length === 0 ? (
          <div className="no-scans">
            <i className="fas fa-search"></i>
            <p>No scans yet. Start your first scan!</p>
            <Link to="/new-scan" className="btn btn-primary btn-sm mt-2">
              Start Scanning
            </Link>
          </div>
        ) : (
          recentScans.map(scan => (
            <div key={scan.id} className="scan-item">
              <div className="scan-info">
                <div className="scan-url">{scan.target_url}</div>
                <div className="scan-date">
                  <i className={`fas ${getStatusIcon(scan.scan_status)}`} style={{ color: getStatusColor(scan.scan_status) }}></i>
                  {new Date(scan.created_at).toLocaleDateString()}
                  {scan.scan_status === 'completed' && ` · ${scan.total_findings || 0} findings`}
                </div>
              </div>
              {scan.scan_status === 'completed' ? (
                <Link to={`/report/${scan.id}`} className={`scan-score ${getScoreClass(scan.security_score)}`}>
                  {formatScore(scan.security_score)}
                </Link>
              ) : (
                <div className="scan-score" style={{ color: getStatusColor(scan.scan_status), fontSize: '0.7rem', textTransform: 'uppercase' }}>
                  {scan.scan_status}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Dashboard;
