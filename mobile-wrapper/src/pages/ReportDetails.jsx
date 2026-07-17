import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { reportApi } from '../api/reportApi.js';
import { getToken } from '../api/client.js';
import { APP_CONFIG } from '../config.js';
import '../styles/global.css';

const ReportDetails = () => {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');
  const [findings, setFindings] = useState([]);

  useEffect(() => {
    const token = getToken();
    if (!token) {
      navigate('/login');
      return;
    }

    loadReport();
  }, [scanId]);

  const loadReport = async () => {
    setLoading(true);
    setError('');

    try {
      const response = await reportApi.getReport(scanId);
      if (response.success) {
        setReport(response.report);
        setFindings(response.report.findings || []);
      } else {
        setError(response.message || 'Failed to load report.');
        if (response.message === 'Scan not found') {
          navigate('/dashboard');
        }
      }
    } catch (err) {
      console.error('Report error:', err);
      setError('An error occurred while loading the report.');
    } finally {
      setLoading(false);
    }
  };

  const handleFilter = (severity) => {
    setFilter(severity);
    if (!report) return;

    if (severity === 'all') {
      setFindings(report.findings || []);
    } else {
      setFindings((report.findings || []).filter(f => f.severity === severity));
    }
  };

  const handleExport = async (format) => {
    try {
      const token = getToken();
      if (!token) return;

      const safeFormat = ['html', 'pdf', 'json'].includes(format) ? format : 'json';
      const response = await fetch(`${APP_CONFIG.apiBase}/report/${encodeURIComponent(scanId)}/export/${safeFormat}`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: safeFormat === 'json' ? 'application/json' : '*/*',
        },
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Failed to export report.');
      }

      const contentType = response.headers.get('content-type') || '';
      const blob = safeFormat === 'json'
        ? new Blob([JSON.stringify(await response.json(), null, 2)], { type: 'application/json' })
        : await response.blob();

      downloadBlob(blob, `webshield_report_${scanId}.${safeFormat}`, contentType);
    } catch (err) {
      console.error('Export error:', err);
      alert('Failed to export report.');
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

  const downloadBlob = (blob, filename, contentType) => {
    const typedBlob = contentType && !blob.type ? new Blob([blob], { type: contentType }) : blob;
    const url = URL.createObjectURL(typedBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const getSeverityClass = (severity) => {
    return `severity-${severity}`;
  };

  const getSeverityBadgeClass = (severity) => {
    return `badge-${severity}`;
  };

  if (loading) {
    return (
      <div className="page-container">
        <div className="loading-container">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
          <p className="mt-2 text-muted">Loading report...</p>
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

  if (!report) {
    return (
      <div className="page-container">
        <div className="alert alert-warning" role="alert">
          <i className="fas fa-exclamation-triangle me-2"></i>
          Report not found.
        </div>
        <button className="btn btn-secondary" onClick={() => navigate('/dashboard')}>
          <i className="fas fa-arrow-left"></i> Back to Dashboard
        </button>
      </div>
    );
  }

  const scan = report.scan;
  const severityCounts = report.summary?.by_severity || {};

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">
          <i className="fas fa-file-alt"></i> Report
        </h1>
        <div className="report-actions">
          <button className="btn btn-outline-primary btn-sm" onClick={() => handleExport('html')}>
            <i className="fas fa-file-code"></i> HTML
          </button>
          <button className="btn btn-outline-primary btn-sm" onClick={() => handleExport('pdf')}>
            <i className="fas fa-file-pdf"></i> PDF
          </button>
          <button className="btn btn-outline-primary btn-sm" onClick={() => handleExport('json')}>
            <i className="fas fa-file-code"></i> JSON
          </button>
        </div>
      </div>

      {/* Report Header */}
      <div className="report-header">
        <div className="report-score">
          <div className={`score-circle ${getScoreClass(scan.security_score)}`}>
            {formatScore(scan.security_score)}
          </div>
          <div className="report-meta">
            <div className="url">{scan.target_url}</div>
            <div className="details">
              <span>Started: {new Date(scan.created_at).toLocaleString()}</span>
              <span className="mx-2">|</span>
              <span>Duration: {scan.duration || 0}s</span>
              <span className="mx-2">|</span>
              <span>{scan.pages_crawled || 0} pages</span>
            </div>
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="report-summary-stats">
        <div className="summary-stat">
          <div className="num">{report.findings?.length || 0}</div>
          <div className="label">Total</div>
        </div>
        <div className="summary-stat">
          <div className="num" style={{ color: '#f44336' }}>{severityCounts.critical || 0}</div>
          <div className="label">Critical</div>
        </div>
        <div className="summary-stat">
          <div className="num" style={{ color: '#ff6b6b' }}>{severityCounts.high || 0}</div>
          <div className="label">High</div>
        </div>
        <div className="summary-stat">
          <div className="num" style={{ color: '#ff9800' }}>{severityCounts.medium || 0}</div>
          <div className="label">Medium</div>
        </div>
        <div className="summary-stat">
          <div className="num" style={{ color: '#4caf50' }}>{severityCounts.low || 0}</div>
          <div className="label">Low</div>
        </div>
        <div className="summary-stat">
          <div className="num" style={{ color: '#8899aa' }}>{severityCounts.info || 0}</div>
          <div className="label">Info</div>
        </div>
      </div>

      {/* Filters */}
      <div className="finding-filters">
        <button 
          className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
          onClick={() => handleFilter('all')}
        >
          All
        </button>
        <button 
          className={`filter-btn ${filter === 'critical' ? 'active' : ''}`}
          onClick={() => handleFilter('critical')}
        >
          Critical
        </button>
        <button 
          className={`filter-btn ${filter === 'high' ? 'active' : ''}`}
          onClick={() => handleFilter('high')}
        >
          High
        </button>
        <button 
          className={`filter-btn ${filter === 'medium' ? 'active' : ''}`}
          onClick={() => handleFilter('medium')}
        >
          Medium
        </button>
        <button 
          className={`filter-btn ${filter === 'low' ? 'active' : ''}`}
          onClick={() => handleFilter('low')}
        >
          Low
        </button>
        <button 
          className={`filter-btn ${filter === 'info' ? 'active' : ''}`}
          onClick={() => handleFilter('info')}
        >
          Info
        </button>
      </div>

      {/* Findings */}
      <div className="finding-list">
        {findings.length === 0 ? (
          <div className="no-findings">
            <i className="fas fa-shield-halved"></i>
            <p>No security issues found!</p>
            <span style={{ fontSize: '0.8rem', color: '#667' }}>
              The website appears to be well-configured.
            </span>
          </div>
        ) : (
          findings.map((finding, index) => (
            <div key={index} className={`finding-item ${finding.severity}`}>
              <div className="finding-header">
                <div className="finding-title">{finding.title}</div>
                <span className={`finding-severity ${getSeverityClass(finding.severity)}`}>
                  {finding.severity.toUpperCase()}
                </span>
              </div>
              <div className="finding-body">
                {finding.affected_url && (
                  <div><strong>URL:</strong> {finding.affected_url}</div>
                )}
                {finding.description && (
                  <div className="mt-1"><strong>Description:</strong> {finding.description}</div>
                )}
                {finding.evidence && (
                  <div className="evidence"><strong>Evidence:</strong> {finding.evidence}</div>
                )}
                {finding.recommendation && (
                  <div className="recommendation"><strong>Recommendation:</strong> {finding.recommendation}</div>
                )}
                <div className="meta-tags">
                  {finding.cwe_id && <span>CWE-{finding.cwe_id}</span>}
                  {finding.owasp_category && <span>OWASP: {finding.owasp_category}</span>}
                  {finding.category && <span>Category: {finding.category}</span>}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default ReportDetails;
