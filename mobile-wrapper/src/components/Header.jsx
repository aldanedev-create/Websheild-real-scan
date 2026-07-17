import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { removeToken, removeUser } from '../api/client.js';

const Header = ({ user, onLogout }) => {
  const navigate = useNavigate();

  const handleLogout = () => {
    removeToken();
    removeUser();
    if (onLogout) onLogout();
    navigate('/login');
  };

  return (
    <header className="app-header">
      <div className="header-left">
        <Link to="/dashboard" className="header-brand">
          <span className="brand-icon">🛡️</span>
          <span className="brand-text">WebShield</span>
        </Link>
      </div>

      <div className="header-right">
        <div className="header-user">
          <button
            className="user-menu-btn"
            onClick={() => document.getElementById('user-dropdown').classList.toggle('show')}
          >
            <div className="user-avatar">
              {user?.avatar_url ? (
                <img src={user.avatar_url} alt={user?.username} />
              ) : (
                <i className="fas fa-user-circle"></i>
              )}
            </div>
          </button>

          <div className="user-dropdown" id="user-dropdown">
            <div className="dropdown-header">
              <div className="dropdown-avatar">
                {user?.avatar_url ? (
                  <img src={user.avatar_url} alt={user?.username} />
                ) : (
                  <i className="fas fa-user-circle"></i>
                )}
              </div>
              <div className="dropdown-user-info">
                <div className="dropdown-username">{user?.username || 'User'}</div>
                <div className="dropdown-email">{user?.email || ''}</div>
              </div>
            </div>
            <div className="dropdown-divider"></div>
            <Link to="/dashboard" className="dropdown-item">
              <i className="fas fa-home"></i> Dashboard
            </Link>
            <Link to="/settings" className="dropdown-item">
              <i className="fas fa-cog"></i> Settings
            </Link>
            <button className="dropdown-item text-danger" onClick={handleLogout}>
              <i className="fas fa-sign-out-alt"></i> Logout
            </button>
          </div>
        </div>
      </div>

      <style>{`
        .app-header {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          height: 56px;
          background: rgba(10, 10, 26, 0.95);
          backdrop-filter: blur(10px);
          border-bottom: 1px solid rgba(255, 255, 255, 0.05);
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 16px;
          z-index: 1050;
        }
        .header-brand {
          display: flex;
          align-items: center;
          gap: 8px;
          text-decoration: none;
          color: #00f0ff;
          font-family: 'Orbitron', monospace;
          font-weight: 700;
          font-size: 1.1rem;
        }
        .header-brand .brand-icon {
          font-size: 1.3rem;
        }
        .header-right {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .premium-badge-header {
          background: linear-gradient(135deg, #ffd700, #f57c00);
          color: #fff;
          padding: 2px 12px;
          border-radius: 12px;
          font-size: 0.65rem;
          font-weight: 600;
          display: flex;
          align-items: center;
          gap: 4px;
        }
        .user-menu-btn {
          background: none;
          border: none;
          padding: 0;
          cursor: pointer;
        }
        .user-avatar {
          width: 32px;
          height: 32px;
          border-radius: 50%;
          background: rgba(0, 240, 255, 0.1);
          display: flex;
          align-items: center;
          justify-content: center;
          color: #00f0ff;
          font-size: 1.5rem;
          overflow: hidden;
        }
        .user-avatar img {
          width: 100%;
          height: 100%;
          object-fit: cover;
        }
        .user-dropdown {
          position: absolute;
          top: 52px;
          right: 16px;
          background: rgba(20, 20, 40, 0.98);
          backdrop-filter: blur(10px);
          border: 1px solid rgba(255, 255, 255, 0.05);
          border-radius: 12px;
          padding: 8px 0;
          min-width: 220px;
          box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
          display: none;
          z-index: 1060;
        }
        .user-dropdown.show {
          display: block;
        }
        .dropdown-header {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 8px 16px 12px 16px;
        }
        .dropdown-avatar {
          width: 40px;
          height: 40px;
          border-radius: 50%;
          background: rgba(0, 240, 255, 0.1);
          display: flex;
          align-items: center;
          justify-content: center;
          color: #00f0ff;
          font-size: 1.8rem;
          overflow: hidden;
        }
        .dropdown-avatar img {
          width: 100%;
          height: 100%;
          object-fit: cover;
        }
        .dropdown-user-info {
          flex: 1;
        }
        .dropdown-username {
          color: #fff;
          font-weight: 600;
          font-size: 0.9rem;
        }
        .dropdown-email {
          color: #8899aa;
          font-size: 0.75rem;
        }
        .dropdown-divider {
          height: 1px;
          background: rgba(255, 255, 255, 0.05);
          margin: 4px 0;
        }
        .dropdown-item {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 8px 16px;
          color: rgba(255, 255, 255, 0.8);
          text-decoration: none;
          font-size: 0.85rem;
          transition: all 0.2s ease;
          background: none;
          border: none;
          width: 100%;
          cursor: pointer;
          text-align: left;
        }
        .dropdown-item:hover {
          background: rgba(0, 240, 255, 0.05);
          color: #00f0ff;
        }
        .dropdown-item i {
          width: 18px;
          text-align: center;
        }
        .dropdown-item.text-danger:hover {
          background: rgba(244, 67, 54, 0.05);
          color: #f44336;
        }
        @media (min-width: 768px) {
          .app-header {
            padding: 0 24px;
          }
        }
      `}</style>
    </header>
  );
};

export default Header;
