import React from 'react';
import '../styles/mobile.css';

const PremiumBadge = ({ size = 'md', showIcon = true, glow = false, className = '' }) => {
  const getSize = () => {
    const sizes = {
      sm: { padding: '2px 10px', fontSize: '0.55rem', iconSize: '0.7rem' },
      md: { padding: '4px 14px', fontSize: '0.7rem', iconSize: '0.8rem' },
      lg: { padding: '6px 18px', fontSize: '0.85rem', iconSize: '1rem' },
      xl: { padding: '8px 24px', fontSize: '1rem', iconSize: '1.2rem' },
    };
    return sizes[size] || sizes.md;
  };

  const sizeConfig = getSize();

  return (
    <span 
      className={`premium-badge ${glow ? 'premium-glow' : ''} ${className}`}
      style={{
        padding: sizeConfig.padding,
        fontSize: sizeConfig.fontSize,
      }}
    >
      {showIcon && <i className="fas fa-crown" style={{ fontSize: sizeConfig.iconSize, marginRight: '4px' }}></i>}
      Premium
      <style>{`
        .premium-badge {
          display: inline-flex;
          align-items: center;
          background: linear-gradient(135deg, #ffd700, #f57c00);
          color: #fff;
          font-weight: 700;
          border-radius: 20px;
          font-family: 'Rajdhani', sans-serif;
          letter-spacing: 0.5px;
          text-transform: uppercase;
          box-shadow: 0 0 20px rgba(255, 215, 0, 0.15);
          transition: all 0.3s ease;
        }
        .premium-badge i {
          font-size: 0.8em;
        }
        .premium-glow {
          animation: premiumPulse 2s ease-in-out infinite;
        }
        @keyframes premiumPulse {
          0%, 100% {
            box-shadow: 0 0 20px rgba(255, 215, 0, 0.15);
          }
          50% {
            box-shadow: 0 0 40px rgba(255, 215, 0, 0.35);
          }
        }
        .premium-badge-sm {
          padding: 2px 10px;
          font-size: 0.55rem;
        }
        .premium-badge-md {
          padding: 4px 14px;
          font-size: 0.7rem;
        }
        .premium-badge-lg {
          padding: 6px 18px;
          font-size: 0.85rem;
        }
        .premium-badge-xl {
          padding: 8px 24px;
          font-size: 1rem;
          border-radius: 30px;
        }
      `}</style>
    </span>
  );
};

export default PremiumBadge;