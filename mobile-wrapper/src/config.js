/**
 * WebShield Scanner - Mobile App Configuration
 */

import { Capacitor } from '@capacitor/core';
import { StatusBar, Style } from '@capacitor/status-bar';
import { SplashScreen } from '@capacitor/splash-screen';
import { Device } from '@capacitor/device';

const getApiBase = () => {
  if (import.meta.env.VITE_API_BASE) {
    const apiBase = import.meta.env.VITE_API_BASE.replace(/\/+$/, '');
    if (import.meta.env.PROD && !apiBase.startsWith('https://')) {
      throw new Error('VITE_API_BASE must use HTTPS for production builds');
    }
    return apiBase;
  }

  if (import.meta.env.PROD) {
    throw new Error('VITE_API_BASE must be set for production builds');
  }

  if (Capacitor.isNativePlatform()) {
    return Capacitor.getPlatform() === 'android'
      ? 'http://10.0.2.2:5000/api'
      : 'http://localhost:5000/api';
  }

  return '/api';
};

// App Configuration
export const APP_CONFIG = {
  name: 'WebShield Scanner',
  version: '1.0.0',
  apiBase: getApiBase(),
  environment: import.meta.env.MODE || 'development',
  isProduction: import.meta.env.PROD || false,
  isDevelopment: import.meta.env.DEV || false,
};

// API Endpoints
export const API_ENDPOINTS = {
  AUTH: {
    LOGIN: '/auth/login',
    REGISTER: '/auth/register',
    LOGOUT: '/auth/logout',
    REFRESH: '/auth/refresh',
    ME: '/auth/me',
    CHANGE_PASSWORD: '/auth/change-password',
    FORGOT_PASSWORD: '/auth/forgot-password',
    RESET_PASSWORD: '/auth/reset-password',
  },
  SCAN: {
    VALIDATE: '/scan/validate',
    START: '/scan/start',
    STATUS: '/scan/:id/status',
    CANCEL: '/scan/:id/cancel',
    HISTORY: '/dashboard/scan-history',
    STATS: '/dashboard/stats',
  },
  REPORT: {
    GET: '/report/:id',
    FINDINGS: '/report/:id/findings',
    UPDATE_FINDING: '/report/:id/findings/:findingId',
    EXPORT: '/report/:id/export/:format',
    SHARE: '/report/:id/share',
  },
  LEARNING: {
    LESSONS: '/learning/lessons',
    LESSON: '/learning/lessons/:id',
    LIKE: '/learning/lessons/:id/like',
    CATEGORIES: '/learning/categories',
    SEARCH: '/learning/search',
  },
  SETTINGS: {
    PROFILE: '/settings/profile',
    EMAIL: '/settings/email',
    USERNAME: '/settings/username',
    DELETE_ACCOUNT: '/settings/delete-account',
    SECURITY: '/settings/security',
  },
};

// Storage Keys
export const STORAGE_KEYS = {
  TOKEN: 'webshield_token',
  REFRESH_TOKEN: 'webshield_refresh_token',
  USER: 'webshield_user',
  THEME: 'webshield_theme',
  ADS_CLOSED: 'webshield_ads_closed',
};

// Default Headers
export const DEFAULT_HEADERS = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
};

// Register Capacitor Plugins
export const registerPlugins = () => {
  // Only run on native platforms
  if (Capacitor.isNativePlatform()) {
    // Status bar styling
    StatusBar.setStyle({ style: Style.Dark }).catch(() => {});
    StatusBar.setBackgroundColor({ color: '#0a0a1a' }).catch(() => {});
    
    // Splash screen
    SplashScreen.show({
      showDuration: 2000,
      autoHide: true,
    }).catch(() => {});
  }
};

// Get device info
export const getDeviceInfo = async () => {
  try {
    const info = await Device.getInfo();
    return info;
  } catch (error) {
    console.error('Device info error:', error);
    return null;
  }
};

// Check if running on mobile
export const isMobile = () => {
  return Capacitor.isNativePlatform();
};

// Check if running on web
export const isWeb = () => {
  return !Capacitor.isNativePlatform();
};

// Check if running on Android
export const isAndroid = () => {
  return Capacitor.getPlatform() === 'android';
};

// Check if running on iOS
export const isIOS = () => {
  return Capacitor.getPlatform() === 'ios';
};
