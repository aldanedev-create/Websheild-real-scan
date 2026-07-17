/**
 * WebShield Scanner - API Client
 * Handles HTTP requests and authentication tokens.
 */

import { APP_CONFIG, STORAGE_KEYS } from '../config.js';

let memoryToken = null;
let memoryUser = null;

const purgeLegacyAuthStorage = () => {
  try {
    sessionStorage.removeItem(STORAGE_KEYS.TOKEN);
    sessionStorage.removeItem(STORAGE_KEYS.REFRESH_TOKEN);
    sessionStorage.removeItem(STORAGE_KEYS.USER);
    localStorage.removeItem(STORAGE_KEYS.TOKEN);
    localStorage.removeItem(STORAGE_KEYS.REFRESH_TOKEN);
    localStorage.removeItem(STORAGE_KEYS.USER);
  } catch {
    // Storage can be unavailable in hardened WebView contexts.
  }
};

purgeLegacyAuthStorage();

// In-memory auth helpers. Do not persist bearer tokens in Web Storage.
export const getToken = () => {
  return memoryToken;
};

export const setToken = (token) => {
  purgeLegacyAuthStorage();
  memoryToken = token || null;
};

export const getRefreshToken = () => {
  return null;
};

export const setRefreshToken = () => {
  purgeLegacyAuthStorage();
};

export const getUser = () => {
  return memoryUser;
};

export const setUser = (user) => {
  purgeLegacyAuthStorage();
  memoryUser = user || null;
};

export const removeToken = () => {
  memoryToken = null;
  purgeLegacyAuthStorage();
};

export const removeUser = () => {
  memoryUser = null;
  purgeLegacyAuthStorage();
};

export const clearAuth = () => {
  removeToken();
  removeUser();
};

export const isPersistentSession = () => {
  return false;
};

// API Client
class ApiClient {
  constructor() {
    this.baseUrl = APP_CONFIG.apiBase || '/api';
    this.isRefreshing = false;
    this.refreshSubscribers = [];
  }

  /**
   * Get headers for request
   */
  getHeaders(includeAuth = true, isFormData = false) {
    const headers = {};
    
    if (!isFormData) {
      headers['Content-Type'] = 'application/json';
    }
    
    headers['Accept'] = 'application/json';

    if (includeAuth) {
      const token = getToken();
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
    }

    return headers;
  }

  /**
   * Make a request
   */
  async request(endpoint, options = {}) {
    const { 
      method = 'GET', 
      data = null, 
      includeAuth = true, 
      isFormData = false,
      retry = true 
    } = options;

    const url = `${this.baseUrl}${endpoint}`;
    const headers = this.getHeaders(includeAuth, isFormData);

    const config = {
      method,
      headers,
      credentials: 'include',
    };

    if (data && !isFormData) {
      config.body = JSON.stringify(data);
    } else if (data && isFormData) {
      config.body = data;
    }

    try {
      const response = await fetch(url, config);
      const contentType = response.headers.get('content-type') || '';
      const responseData = contentType.includes('application/json')
        ? await response.json()
        : { message: await response.text() };

      // Handle token expiration
      if (response.status === 401 && retry && includeAuth) {
        const token = getToken();
        if (token) {
          const refreshed = await this.refreshToken();
          if (refreshed) {
            // Retry with new token
            return this.request(endpoint, { ...options, retry: false });
          }
        }
      }

      if (!response.ok) {
        throw {
          status: response.status,
          message: responseData.message || responseData.error || 'API request failed',
          data: responseData
        };
      }

      return responseData;
    } catch (error) {
      if (error.status === 401 && includeAuth) {
        clearAuth();
        // Redirect to login if not already there
        if (!window.location.pathname.includes('/login')) {
          window.location.href = '/login';
        }
      }
      throw error;
    }
  }

  /**
   * Refresh access token
   */
  async refreshToken() {
    if (this.isRefreshing) {
      // Wait for refresh to complete
      return new Promise((resolve) => {
        this.refreshSubscribers.push(resolve);
      });
    }

    this.isRefreshing = true;

    try {
      const response = await fetch(`${this.baseUrl}/auth/refresh`, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'include'
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setToken(data.access_token);
        // Notify subscribers
        this.refreshSubscribers.forEach(cb => cb(true));
        this.refreshSubscribers = [];
        return true;
      }

      throw new Error('Refresh failed');
    } catch (error) {
      clearAuth();
      this.refreshSubscribers.forEach(cb => cb(false));
      this.refreshSubscribers = [];
      return false;
    } finally {
      this.isRefreshing = false;
    }
  }

  // ========================================
  // HTTP Methods
  // ========================================

  get(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: 'GET' });
  }

  post(endpoint, data, options = {}) {
    return this.request(endpoint, { ...options, method: 'POST', data });
  }

  put(endpoint, data, options = {}) {
    return this.request(endpoint, { ...options, method: 'PUT', data });
  }

  delete(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: 'DELETE' });
  }

  patch(endpoint, data, options = {}) {
    return this.request(endpoint, { ...options, method: 'PATCH', data });
  }
}

// Create singleton instance
export const apiClient = new ApiClient();

// Export default instance
export default apiClient;
