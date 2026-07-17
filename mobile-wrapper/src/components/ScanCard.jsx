import React from 'react';
import { Link } from 'react-router-dom';
import '../styles/mobile.css';

const ScanCard = ({ scan, showScore = true, onDelete }) => {
  const getStatusBadge = (status) => {
    const config = {
      completed: { class: 'status-completed', icon: 'fa-check-circle', label: 'Complete' },
      running: { class: 'status-running', icon: 'fa-spinner fa-spin', label: 'Running' },
      pending: { class: 'status-pending', icon: 'fa-clock', label: 'Pending' },
      failed: { class: 'status-failed', icon: 'fa-exclamation-circle', label: 'Failed' },
      cancelled: { class: 'status-cancelled', icon: 'fa-ban', label: 'Cancelled' }
    };
    return config[status] || config.pending;
  };

  const getScoreClass = (score) => {
    if (score >= 80) return 'score-good';
    if (score >= 60) return 'score-medium';
    return 'score-bad';
  };

  const status = getStatusBadge(scan.scan_status);
  const isComplete = scan.scan_status === 'completed';

  return (
    <div className="scan-card">
      <div className="scan-card-header">
        <div className="scan-card-url">
          <i className="fas fa-link"></i>
          <span>{scan.target_url}</span>
        </div>
        <div className="scan-card-status">
          <span className={`status-badge ${status.class}`}>
            <i className={`fas ${status.icon}`}></i> {status.label}
          </span>
        </div>
      </div>

      <div className="scan-card-body">
        {showScore && isComplete && scan.security_score !== undefined && (
          <div className="scan-card-score">
            <div className={`score-ring ${getScoreClass(scan.security_score)}`}>
              <span className="score-number">{scan.security_score}</span>
            </div>
            <div className="score-label">Security Score</div>
          </div>
        )}

        <div className="scan-card-stats">
          <div className="scan-stat">
            <span className="stat-number">{scan.pages_crawled || 0}</span>
            <span className="stat-label">Pages</span>
          </div>
          <div className="scan-stat">
            <span className="stat-number">{scan.total_findings || 0}</span>
            <span className="stat-label">Findings</span>
          </div>
          <div className="scan-stat">
            <span className="stat-number">{scan.duration || 0}s</span>
            <span className="stat-label">Duration</span>
          </div>
        </div>
      </div>

      <div className="scan-card-footer">
        <span className="scan-date">
          <i className="far fa-calendar-alt"></i>
          {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}
        </span>
        <div className="scan-card-actions">
          {isComplete && (
            <Link to={`/report/${scan.id}`} className="btn btn-primary btn-sm">
              <i className="fas fa-file-alt"></i> Report
            </Link>
          )}
          {scan.scan_status === 'running' && (
            <Link to={`/scan-progress/${scan.id}`} className="btn btn-warning btn-sm">
              <i className="fas fa-spinner fa-spin"></i> Progress
            </Link>
          )}
          {onDelete && (
            <button 
              className="btn btn-outline-secondary btn-sm" 
              onClick={() => onDelete(scan.id)}
              title="Delete scan"
            >
              <i className="fas fa-trash"></i>
            </button>
          )}
        </div>
      </div>

      <style>{`
        .scan-card {
          background: rgba(255, 255, 255, 0.02);
          border-radius: 12px;
          border: 1px solid rgba(255, 255, 255, 0.05);
          padding: 16px;
          margin-bottom: 12px;
          transition: all 0.3s ease;
        }
        .scan-card:hover {
          background: rgba(255, 255, 255, 0.04);
          border-color: rgba(0, 240, 255, 0.1);
        }
        .scan-card-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          gap: 10px;
          flex-wrap: wrap;
          margin-bottom: 10px;
        }
        .scan-card-url {
          display: flex;
          align-items: center;
          gap: 6px;
          color: #ccd;
          font-size: 0.85rem;
          font-weight: 500;
          word-break: break-all;
          flex: 1;
        }
        .scan-card-url i {
          color: #00f0ff;
          font-size: 0.8rem;
          flex-shrink: 0;
        }
        .scan-card-status {
          flex-shrink: 0;
        }
        .status-badge {
          display: inline-flex;
          align-items: center;
          gap: 4px;
          padding: 2px 12px;
          border-radius: 12px;
          font-size: 0.65rem;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.3px;
        }
        .status-completed {
          background: rgba(76, 175, 80, 0.15);
          color: #4caf50;
        }
        .status-running {
          background: rgba(0, 240, 255, 0.15);
          color: #00f0ff;
        }
        .status-pending {
          background: rgba(255, 152, 0, 0.15);
          color: #ff9800;
        }
        .status-failed {
          background: rgba(244, 67, 54, 0.15);
          color: #f44336;
        }
        .status-cancelled {
          background: rgba(255, 255, 255, 0.05);
          color: #8899aa;
        }
        .scan-card-body {
          display: flex;
          align-items: center;
          gap: 16px;
          flex-wrap: wrap;
        }
        .scan-card-score {
          display: flex;
          align-items: center;
          gap: 8px;
          flex-shrink: 0;
        }
        .score-ring {
          width: 44px;
          height: 44px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: 'Orbitron', monospace;
          font-size: 0.9rem;
          font-weight: 700;
          border: 3px solid #8899aa;
          background: rgba(255, 255, 255, 0.02);
        }
        .score-ring.score-good {
          border-color: #4caf50;
          color: #4caf50;
        }
        .score-ring.score-medium {
          border-color: #ff9800;
          color: #ff9800;
        }
        .score-ring.score-bad {
          border-color: #f44336;
          color: #f44336;
        }
        .score-label {
          font-size: 0.6rem;
          color: #8899aa;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .scan-card-stats {
          display: flex;
          gap: 16px;
          flex: 1;
        }
        .scan-stat {
          text-align: center;
        }
        .scan-stat .stat-number {
          font-family: 'Orbitron', monospace;
          font-size: 0.9rem;
          font-weight: 700;
          color: #ccd;
          display: block;
        }
        .scan-stat .stat-label {
          font-size: 0.55rem;
          color: #667;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .scan-card-footer {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-top: 10px;
          padding-top: 10px;
          border-top: 1px solid rgba(255, 255, 255, 0.03);
          flex-wrap: wrap;
          gap: 8px;
        }
        .scan-date {
          font-size: 0.7rem;
          color: #667;
        }
        .scan-date i {
          margin-right: 4px;
        }
        .scan-card-actions {
          display: flex;
          gap: 6px;
        }
        .scan-card-actions .btn {
          font-size: 0.7rem;
          padding: 4px 12px;
          border-radius: 6px;
        }
        .btn-warning {
          background: rgba(255, 152, 0, 0.15);
          border: 1px solid rgba(255, 152, 0, 0.2);
          color: #ff9800;
        }
        .btn-warning:hover {
          background: rgba(255, 152, 0, 0.25);
        }
        .scan-card-actions .btn-outline-secondary {
          color: #667;
          border-color: rgba(255, 255, 255, 0.05);
          background: transparent;
        }
        .scan-card-actions .btn-outline-secondary:hover {
          color: #f44336;
          border-color: #f44336;
          background: rgba(244, 67, 54, 0.05);
        }
        @media (max-width: 576px) {
          .scan-card-body {
            flex-direction: column;
            align-items: flex-start;
          }
          .scan-card-stats {
            width: 100%;
            justify-content: space-around;
          }
          .scan-card-header {
            flex-direction: column;
          }
          .scan-card-footer {
            flex-direction: column;
            align-items: stretch;
          }
          .scan-card-actions {
            justify-content: flex-end;
          }
        }
      `}</style>
    </div>
  );
};

export default ScanCard;