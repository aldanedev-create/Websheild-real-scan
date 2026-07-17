import React from 'react';
import '../styles/mobile.css';

const ScoreRing = ({ score, size = 'md', showLabel = true }) => {
  const getScoreClass = (score) => {
    if (score >= 80) return 'score-good';
    if (score >= 60) return 'score-medium';
    return 'score-bad';
  };

  const getSize = () => {
    const sizes = {
      sm: { ring: 56, font: '1.2rem', label: '0.55rem' },
      md: { ring: 80, font: '1.8rem', label: '0.65rem' },
      lg: { ring: 120, font: '2.8rem', label: '0.8rem' },
    };
    return sizes[size] || sizes.md;
  };

  const sizeConfig = getSize();

  return (
    <div className="score-ring-container">
      <div 
        className={`score-ring-display ${getScoreClass(score)}`}
        style={{
          width: sizeConfig.ring,
          height: sizeConfig.ring,
          fontSize: sizeConfig.font,
          borderWidth: size === 'lg' ? 6 : size === 'sm' ? 3 : 4
        }}
      >
        {score !== undefined && score !== null ? score : '—'}
      </div>
      {showLabel && (
        <div className="score-ring-label" style={{ fontSize: sizeConfig.label }}>
          Security Score
        </div>
      )}

      <style>{`
        .score-ring-container {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 4px;
        }
        .score-ring-display {
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: 'Orbitron', monospace;
          font-weight: 700;
          border-style: solid;
          background: rgba(255, 255, 255, 0.02);
          transition: all 0.3s ease;
        }
        .score-ring-display.score-good {
          border-color: #4caf50;
          color: #4caf50;
        }
        .score-ring-display.score-medium {
          border-color: #ff9800;
          color: #ff9800;
        }
        .score-ring-display.score-bad {
          border-color: #f44336;
          color: #f44336;
        }
        .score-ring-label {
          color: #8899aa;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          font-weight: 500;
        }
      `}</style>
    </div>
  );
};

export default ScoreRing;