import React, { useState } from 'react';
import '../styles/mobile.css';

const FindingCard = ({ finding, onUpdate }) => {
  const [expanded, setExpanded] = useState(false);
  const [updating, setUpdating] = useState(false);

  const getSeverityClass = (severity) => {
    const classes = {
      critical: 'severity-critical',
      high: 'severity-high',
      medium: 'severity-medium',
      low: 'severity-low',
      info: 'severity-info'
    };
    return classes[severity] || 'severity-info';
  };

  const getSeverityBadge = (severity) => {
    const classes = {
      critical: 'badge-critical',
      high: 'badge-high',
      medium: 'badge-medium',
      low: 'badge-low',
      info: 'badge-info'
    };
    return classes[severity] || 'badge-info';
  };

  const handleUpdate = async (action) => {
    setUpdating(true);
    try {
      if (onUpdate) {
        await onUpdate(finding.id, action);
      }
    } catch (error) {
      console.error('Update finding error:', error);
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className={`finding-card ${finding.severity}`}>
      <div className="finding-card-header" onClick={() => setExpanded(!expanded)}>
        <div className="finding-card-title">
          <span className={`severity-badge ${getSeverityBadge(finding.severity)}`}>
            {finding.severity.toUpperCase()}
          </span>
          <span className="finding-title-text">{finding.title}</span>
        </div>
        <div className="finding-card-toggle">
          <i className={`fas fa-chevron-${expanded ? 'up' : 'down'}`}></i>
        </div>
      </div>

      {expanded && (
        <div className="finding-card-body">
          {finding.affected_url && (
            <div className="finding-field">
              <strong>URL:</strong>
              <span className="finding-url">{finding.affected_url}</span>
            </div>
          )}

          {finding.description && (
            <div className="finding-field">
              <strong>Description:</strong>
              <p>{finding.description}</p>
            </div>
          )}

          {finding.evidence && (
            <div className="finding-field">
              <strong>Evidence:</strong>
              <div className="finding-evidence">{finding.evidence}</div>
            </div>
          )}

          {finding.recommendation && (
            <div className="finding-field">
              <strong>Recommendation:</strong>
              <div className="finding-recommendation">{finding.recommendation}</div>
            </div>
          )}

          <div className="finding-meta">
            {finding.cwe_id && <span className="meta-tag">CWE-{finding.cwe_id}</span>}
            {finding.owasp_category && <span className="meta-tag">OWASP: {finding.owasp_category}</span>}
            {finding.category && <span className="meta-tag">Category: {finding.category}</span>}
          </div>

          <div className="finding-actions">
            {!finding.is_fixed && (
              <button 
                className="btn-fix" 
                onClick={() => handleUpdate('mark_fixed')}
                disabled={updating}
              >
                <i className="fas fa-check"></i> Mark Fixed
              </button>
            )}
            {!finding.is_false_positive && (
              <button 
                className="btn-fp" 
                onClick={() => handleUpdate('mark_false_positive')}
                disabled={updating}
              >
                <i className="fas fa-times"></i> False Positive
              </button>
            )}
            {finding.is_fixed && (
              <span className="status-badge status-fixed">
                <i className="fas fa-check-circle"></i> Fixed
              </span>
            )}
            {finding.is_false_positive && (
              <span className="status-badge status-fp">
                <i className="fas fa-ban"></i> False Positive
              </span>
            )}
          </div>
        </div>
      )}

      <style>{`
        .finding-card {
          background: rgba(255, 255, 255, 0.02);
          border-radius: 10px;
          border: 1px solid rgba(255, 255, 255, 0.05);
          border-left: 4px solid #8899aa;
          margin-bottom: 10px;
          overflow: hidden;
          transition: all 0.3s ease;
        }
        .finding-card.critical { border-left-color: #f44336; }
        .finding-card.high { border-left-color: #ff6b6b; }
        .finding-card.medium { border-left-color: #ff9800; }
        .finding-card.low { border-left-color: #4caf50; }
        .finding-card.info { border-left-color: #8899aa; }

        .finding-card-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 12px 16px;
          cursor: pointer;
          transition: background 0.2s ease;
        }
        .finding-card-header:hover {
          background: rgba(255, 255, 255, 0.02);
        }
        .finding-card-title {
          display: flex;
          align-items: center;
          gap: 10px;
          flex: 1;
          min-width: 0;
        }
        .severity-badge {
          padding: 2px 10px;
          border-radius: 10px;
          font-size: 0.6rem;
          font-weight: 700;
          text-transform: uppercase;
          flex-shrink: 0;
        }
        .badge-critical { background: rgba(244, 67, 54, 0.15); color: #f44336; }
        .badge-high { background: rgba(255, 107, 107, 0.15); color: #ff6b6b; }
        .badge-medium { background: rgba(255, 152, 0, 0.15); color: #ff9800; }
        .badge-low { background: rgba(76, 175, 80, 0.15); color: #4caf50; }
        .badge-info { background: rgba(255, 255, 255, 0.05); color: #8899aa; }

        .finding-title-text {
          color: #ccd;
          font-size: 0.85rem;
          font-weight: 500;
          word-break: break-word;
        }
        .finding-card-toggle {
          color: #667;
          font-size: 0.8rem;
          flex-shrink: 0;
          margin-left: 8px;
        }

        .finding-card-body {
          padding: 0 16px 16px 16px;
          border-top: 1px solid rgba(255, 255, 255, 0.03);
          animation: slideDown 0.3s ease;
        }
        @keyframes slideDown {
          from { opacity: 0; transform: translateY(-10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .finding-field {
          margin-top: 10px;
        }
        .finding-field strong {
          color: #8899aa;
          font-size: 0.75rem;
          display: block;
          margin-bottom: 2px;
        }
        .finding-field p {
          color: #ccd;
          font-size: 0.85rem;
          margin: 0;
          line-height: 1.5;
        }
        .finding-url {
          color: #00f0ff;
          font-size: 0.8rem;
          word-break: break-all;
        }
        .finding-evidence {
          background: rgba(0, 0, 0, 0.3);
          padding: 8px 12px;
          border-radius: 6px;
          font-family: 'Courier New', monospace;
          font-size: 0.7rem;
          color: #8899aa;
          overflow-x: auto;
          word-break: break-all;
        }
        .finding-recommendation {
          background: rgba(0, 240, 255, 0.03);
          padding: 8px 12px;
          border-radius: 6px;
          border-left: 3px solid #00f0ff;
          color: #ccd;
          font-size: 0.85rem;
        }
        .finding-meta {
          display: flex;
          gap: 6px;
          flex-wrap: wrap;
          margin-top: 10px;
        }
        .meta-tag {
          background: rgba(255, 255, 255, 0.03);
          padding: 2px 10px;
          border-radius: 10px;
          font-size: 0.6rem;
          color: #667;
        }
        .finding-actions {
          display: flex;
          gap: 8px;
          margin-top: 12px;
          flex-wrap: wrap;
        }
        .finding-actions .btn-fix,
        .finding-actions .btn-fp {
          padding: 4px 14px;
          border-radius: 6px;
          font-size: 0.7rem;
          font-weight: 600;
          border: none;
          cursor: pointer;
          transition: all 0.2s ease;
        }
        .btn-fix {
          background: rgba(76, 175, 80, 0.1);
          color: #4caf50;
        }
        .btn-fix:hover:not(:disabled) {
          background: rgba(76, 175, 80, 0.2);
        }
        .btn-fp {
          background: rgba(255, 255, 255, 0.03);
          color: #8899aa;
        }
        .btn-fp:hover:not(:disabled) {
          background: rgba(255, 255, 255, 0.08);
        }
        .finding-actions button:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
        .status-badge {
          padding: 4px 14px;
          border-radius: 6px;
          font-size: 0.7rem;
          font-weight: 600;
        }
        .status-fixed {
          background: rgba(76, 175, 80, 0.1);
          color: #4caf50;
        }
        .status-fp {
          background: rgba(255, 255, 255, 0.03);
          color: #8899aa;
        }
      `}</style>
    </div>
  );
};

export default FindingCard;