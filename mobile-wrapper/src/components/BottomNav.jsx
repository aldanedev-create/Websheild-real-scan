import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import '../styles/mobile.css';

const BottomNav = () => {
  const location = useLocation();

  const isActive = (path) => {
    return location.pathname === path || location.pathname.startsWith(path + '/');
  };

  const navItems = [
    { path: '/dashboard', icon: 'fa-home', label: 'Home' },
    { path: '/new-scan', icon: 'fa-plus-circle', label: 'Scan' },
    { path: '/learning-center', icon: 'fa-graduation-cap', label: 'Learn' },
    { path: '/settings', icon: 'fa-cog', label: 'Settings' },
  ];

  return (
    <nav className="bottom-nav d-md-none">
      <div className="bottom-nav-inner">
        {navItems.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            className={`bottom-nav-item ${isActive(item.path) ? 'active' : ''}`}
          >
            <i className={`fas ${item.icon}`}></i>
            <span>{item.label}</span>
          </Link>
        ))}
      </div>
    </nav>
  );
};

export default BottomNav;