import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { StatusBar, Style } from '@capacitor/status-bar';
import { SplashScreen } from '@capacitor/splash-screen';

// Pages
import Splash from './pages/Splash.jsx';
import Login from './pages/Login.jsx';
import Register from './pages/Register.jsx';
import Dashboard from './pages/Dashboard.jsx';
import NewScan from './pages/NewScan.jsx';
import ScanProgress from './pages/ScanProgress.jsx';
import ReportDetails from './pages/ReportDetails.jsx';
import AttackSurfaceMap from './pages/AttackSurfaceMap.jsx';
import LearningCenter from './pages/LearningCenter.jsx';
import Settings from './pages/Settings.jsx';

// Components
import BottomNav from './components/BottomNav.jsx';

// API
import apiClient, { getToken, removeToken, getUser, setToken, setUser } from './api/client.js';
import { authApi } from './api/authApi.js';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [isPremium, setIsPremium] = useState(false);
  const [user, setUserState] = useState(null);

  useEffect(() => {
    checkAuth();
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute(
      'data-theme',
      user?.theme === 'light' ? 'light' : 'dark'
    );
  }, [user?.theme]);

  const checkAuth = async () => {
    try {
      const token = getToken();
      const userData = getUser();

      if (token && userData) {
        setUserState(userData);
        setIsAuthenticated(true);
        setIsPremium(userData.plan === 'premium' || userData.is_admin);
      } else {
        const refreshed = await apiClient.refreshToken();
        if (!refreshed) {
          setIsAuthenticated(false);
          setIsPremium(false);
          setUserState(null);
          return;
        }

        const data = await authApi.getMe();
        if (data.success && data.user) {
          setUser(data.user);
          setUserState(data.user);
          setIsAuthenticated(true);
          setIsPremium(data.user.plan === 'premium' || data.user.is_admin);
          return;
        }

        setIsAuthenticated(false);
        setIsPremium(false);
        setUserState(null);
      }
    } catch (error) {
      console.error('Auth check error:', error);
      setIsAuthenticated(false);
      setIsPremium(false);
      setUserState(null);
    } finally {
      setIsLoading(false);
      // Hide splash screen
      try {
        await SplashScreen.hide();
      } catch (e) {
        // Ignore
      }
    }
  };

  const handleLogin = (userData, token) => {
    setToken(token);
    setUser(userData);
    setUserState(userData);
    setIsAuthenticated(true);
    setIsPremium(userData.plan === 'premium' || userData.is_admin);
  };

  const handleLogout = () => {
    removeToken();
    setUserState(null);
    setIsAuthenticated(false);
    setIsPremium(false);
  };

  const handleUserUpdated = (updatedUser) => {
    setUser(updatedUser);
    setUserState(updatedUser);
    setIsPremium(updatedUser.plan === 'premium' || updatedUser.is_admin);
  };

  // Status bar style
  useEffect(() => {
    const setStatusBar = async () => {
      try {
        await StatusBar.setStyle({ style: Style.Dark });
        await StatusBar.setBackgroundColor({ color: '#0a0a1a' });
      } catch (e) {
        // Ignore
      }
    };
    setStatusBar();
  }, []);

  if (isLoading) {
    return (
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center', 
        height: '100vh',
        background: '#0a0a1a',
        color: '#00f0ff'
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ 
            fontFamily: 'Orbitron, monospace', 
            fontSize: '1.5rem',
            marginBottom: '16px'
          }}>
            WebShield
          </div>
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <BrowserRouter>
      <div className="app-container">
        <Routes>
          {/* Public Routes */}
          <Route path="/" element={<Splash />} />
          <Route path="/login" element={<Login onLogin={handleLogin} />} />
          <Route path="/register" element={<Register onLogin={handleLogin} />} />

          {/* Protected Routes */}
          <Route 
            path="/dashboard" 
            element={
              isAuthenticated ? (
                <Dashboard user={user} isPremium={isPremium} />
              ) : (
                <Navigate to="/login" />
              )
            } 
          />
          <Route 
            path="/new-scan" 
            element={
              isAuthenticated ? <NewScan /> : <Navigate to="/login" />
            } 
          />
          <Route 
            path="/scan-progress/:scanId" 
            element={
              isAuthenticated ? <ScanProgress /> : <Navigate to="/login" />
            } 
          />
          <Route 
            path="/report/:scanId" 
            element={
              isAuthenticated ? <ReportDetails /> : <Navigate to="/login" />
            } 
          />
          <Route 
            path="/attack-surface/:scanId" 
            element={
              isAuthenticated ? <AttackSurfaceMap /> : <Navigate to="/login" />
            } 
          />
          <Route 
            path="/learning-center" 
            element={
              isAuthenticated ? <LearningCenter isPremium={isPremium} /> : <Navigate to="/login" />
            } 
          />
          <Route 
            path="/settings" 
            element={
              isAuthenticated ? (
                <Settings
                  user={user}
                  onLogout={handleLogout}
                  onUserUpdated={handleUserUpdated}
                />
              ) : <Navigate to="/login" />
            } 
          />

          {/* Catch All */}
          <Route path="*" element={<Navigate to={isAuthenticated ? "/dashboard" : "/"} />} />
        </Routes>

        {/* Bottom Navigation - Only show on protected routes */}
        {isAuthenticated && (
          <>
            <BottomNav />
          </>
        )}
      </div>
    </BrowserRouter>
  );
}

export default App;
