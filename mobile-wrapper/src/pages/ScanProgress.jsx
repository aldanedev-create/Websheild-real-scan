import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { scanApi } from '../api/scanApi.js';
import { getToken } from '../api/client.js';
import '../styles/global.css';

const ScanProgress = () => {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [elapsedTime, setElapsedTime] = useState(0);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState([]);
  const [cancelling, setCancelling] = useState(false);
  const intervalRef = useRef(null);
  const timerRef = useRef(null);
  const startTimeRef = useRef(Date.now());

  useEffect(() => {
    const token = getToken();
    if (!token) {
      navigate('/login');
      return;
    }

    startTimeRef.current = Date.now();
    fetchScanStatus();
    
    // Poll every 2 seconds
    intervalRef.current = setInterval(fetchScanStatus, 2000);
    
    // Update timer every second
    timerRef.current = setInterval(() => {
      setElapsedTime(Math.floor((Date.now() - startTimeRef.current) / 1000));
    }, 1000);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [scanId]);

  const fetchScanStatus = async () => {
    try {
      const response = await scanApi.getScanStatus(scanId);
      if (response.success) {
        const scanData = response.scan;
        setScan(scanData);
        updateProgress(scanData);
        
        // Stop polling if scan is complete
        if (['completed', 'failed', 'cancelled'].includes(scanData.scan_status)) {
          if (intervalRef.current) {
            clearInterval(intervalRef.current);
            intervalRef.current = null;
          }
          if (timerRef.current) {
            clearInterval(timerRef.current);
            timerRef.current = null;
          }
        }
      } else {
        setError('Failed to fetch scan status.');
      }
    } catch (err) {
      console.error('Status fetch error:', err);
      setError('An error occurred while fetching scan status.');
    } finally {
      setLoading(false);
    }
  };

  const updateProgress = (scanData) => {
    // Update progress
    let prog = 0;
    if (scanData.scan_status === 'completed') {
      prog = 100;
    } else if (scanData.scan_status === 'running') {
      const maxPages = scanData.max_pages || 100;
      prog = Math.min(95, ((scanData.pages_crawled || 0) / maxPages) * 100);
    } else if (scanData.scan_status === 'pending') {
      prog = 5;
    }
    setProgress(prog);

    // Add log entries
    if (scanData.scan_status === 'running' && scanData.pages_crawled > 0) {
      const lastLog = logs[logs.length - 1];
      if (!lastLog || lastLog.message !== `Crawled ${scanData.pages_crawled} pages...`) {
        addLog(`Crawled ${scanData.pages_crawled} pages...`, 'info');
      }
    }

    // Handle completion
    if (scanData.scan_status === 'completed') {
      addLog('Scan completed successfully!', 'success');
    } else if (scanData.scan_status === 'failed') {
      addLog(`Scan failed: ${scanData.summary || 'Unknown error'}`, 'error');
    } else if (scanData.scan_status === 'cancelled') {
      addLog('Scan cancelled by user.', 'warning');
    }
  };

  const addLog = (message, type = 'info') => {
    const time = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { time, message, type }]);
  };

  const handleCancel = async () => {
    if (cancelling) return;
    if (!confirm('Are you sure you want to cancel this scan?')) return;

    setCancelling(true);
    setError('');
    try {
      const response = await scanApi.cancelScan(scanId);
      if (response.success) {
        addLog('Scan cancelled by user.', 'warning');
        const cancelledScan = {
          ...(scan || {}),
          ...(response.scan || {}),
          scan_status: 'cancelled',
          summary: response.message || 'Scan cancelled by user.'
        };
        setScan(cancelledScan);
        updateProgress(cancelledScan);
        stopPolling();
      } else {
        setError(response.message || 'Failed to cancel scan.');
      }
    } catch (err) {
      console.error('Cancel error:', err);
      setError(err.message || 'An error occurred while cancelling the scan.');
    } finally {
      setCancelling(false);
    }
  };

  const stopPolling = () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  };

  const formatTime = (seconds) => {
    const mins = String(Math.floor(seconds / 60)).padStart(2, '0');
    const secs = String(seconds % 60).padStart(2, '0');
    return `${mins}:${secs}`;
  };

  const getScoreClass = (score) => {
    if (score === null || score === undefined || score === '') return 'text-muted';
    if (score >= 80) return 'score-good';
    if (score >= 60) return 'score-medium';
    return 'score-bad';
  };

  const formatScore = (score) => {
    if (score === null || score === undefined || score === '') return '--/100';
    const parsed = Number(score);
    return Number.isFinite(parsed) ? `${Math.round(parsed)}/100` : '--/100';
  };

  if (loading) {
    return (
      <div className="page-container">
        <div className="loading-container">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
          <p className="mt-2 text-muted">Loading scan status...</p>
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

  // Scan Complete
  if (scan && scan.scan_status === 'completed') {
    return (
      <div className="page-container">
        <div className="scan-complete-container">
          <div className="scan-status-icon" style={{ color: '#4caf50' }}>
            <i className="fas fa-check-circle"></i>
          </div>
          <h2 style={{ color: '#4caf50' }}>Scan Complete!</h2>
          
          <div className={`score-display ${getScoreClass(scan.security_score)}`}>
            {formatScore(scan.security_score)}
          </div>
          <div style={{ color: '#8899aa', marginBottom: '8px' }}>
            Risk Level: {scan.risk_level ? scan.risk_level.toUpperCase() : 'Unknown'}
          </div>
          <div style={{ color: '#8899aa', marginBottom: '20px' }}>
            Findings: {scan.total_findings || 0}
          </div>
          
          <Link to={`/report/${scan.id}`} className="btn-view-report">
            <i className="fas fa-file-alt"></i> View Report
          </Link>
          <br />
          <Link to="/dashboard" className="btn btn-secondary mt-3" style={{ borderColor: 'rgba(255,255,255,0.1)', color: '#8899aa' }}>
            <i className="fas fa-home"></i> Dashboard
          </Link>
        </div>
      </div>
    );
  }

  // Scan Failed or Cancelled
  if (scan && ['failed', 'cancelled'].includes(scan.scan_status)) {
    return (
      <div className="page-container">
        <div className="scan-complete-container">
          <div className="scan-status-icon" style={{ color: scan.scan_status === 'failed' ? '#f44336' : '#ff9800' }}>
            <i className={`fas ${scan.scan_status === 'failed' ? 'fa-exclamation-circle' : 'fa-ban'}`}></i>
          </div>
          <h2 style={{ color: scan.scan_status === 'failed' ? '#f44336' : '#ff9800' }}>
            Scan {scan.scan_status === 'failed' ? 'Failed' : 'Cancelled'}
          </h2>
          <p style={{ color: '#8899aa' }}>{scan.summary || 'No additional information.'}</p>
          <button className="btn btn-secondary" onClick={() => navigate('/dashboard')}>
            <i className="fas fa-arrow-left"></i> Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  // Scan Running
  return (
    <div className="page-container">
      <div className="progress-container">
        <div className="scan-status-icon running">
          <i className="fas fa-shield-halved"></i>
        </div>
        
        <div className="scan-status-text" id="status-text">
          {scan?.scan_status === 'pending' ? 'Initializing scan...' : 'Scanning in progress...'}
        </div>
        <div className="scan-url-display">{scan?.target_url || ''}</div>

        <div className="progress-bar-container">
          <div className="progress-bar-fill" style={{ width: `${progress}%` }}></div>
        </div>

        <div className="progress-stats">
          <div className="progress-stat">
            <div className="number">{scan?.pages_crawled || 0}</div>
            <div className="label">Pages Crawled</div>
          </div>
          <div className="progress-stat">
            <div className="number">{scan?.total_findings || 0}</div>
            <div className="label">Findings Found</div>
          </div>
          <div className="progress-stat">
            <div className="number">{formatTime(elapsedTime)}</div>
            <div className="label">Elapsed Time</div>
          </div>
        </div>

        <div className="scan-log">
          {logs.map((log, index) => (
            <div key={index} className="log-entry">
              <span className="time">[{log.time}]</span>
              <span className={log.type}>{log.message}</span>
            </div>
          ))}
        </div>

        <button className="btn-cancel-scan" onClick={handleCancel} disabled={cancelling}>
          <i className={cancelling ? 'fas fa-spinner fa-spin' : 'fas fa-times'}></i>
          {cancelling ? ' Cancelling...' : ' Cancel Scan'}
        </button>
      </div>
    </div>
  );
};

export default ScanProgress;
