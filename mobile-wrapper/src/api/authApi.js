/**
 * WebShield Scanner - Authentication API
 * Handles login, registration, and authentication endpoints.
 */

import apiClient from './client.js';
import { API_ENDPOINTS } from '../config.js';

export const authApi = {
  /**
   * Login user
   */
  login: (emailOrUsername, password, remember = false) => {
    return apiClient.post(API_ENDPOINTS.AUTH.LOGIN, {
      email_or_username: emailOrUsername,
      password: password,
      remember: remember
    }, { includeAuth: false });
  },

  /**
   * Register new user
   */
  register: (username, email, password, fullName = '') => {
    return apiClient.post(API_ENDPOINTS.AUTH.REGISTER, {
      username: username,
      email: email,
      password: password,
      full_name: fullName
    }, { includeAuth: false });
  },

  /**
   * Logout user
   */
  logout: () => {
    return apiClient.post(API_ENDPOINTS.AUTH.LOGOUT, {});
  },

  /**
   * Refresh access token
   */
  refresh: () => {
    return apiClient.post(API_ENDPOINTS.AUTH.REFRESH, {});
  },

  /**
   * Get current user
   */
  getMe: () => {
    return apiClient.get(API_ENDPOINTS.AUTH.ME);
  },

  /**
   * Update current user
   */
  updateMe: (data) => {
    return apiClient.put(API_ENDPOINTS.AUTH.ME, data);
  },

  /**
   * Change password
   */
  changePassword: (currentPassword, newPassword) => {
    return apiClient.post(API_ENDPOINTS.AUTH.CHANGE_PASSWORD, {
      current_password: currentPassword,
      new_password: newPassword
    });
  },

  /**
   * Forgot password
   */
  forgotPassword: (email) => {
    return apiClient.post(API_ENDPOINTS.AUTH.FORGOT_PASSWORD, {
      email: email
    }, { includeAuth: false });
  },

  /**
   * Reset password
   */
  resetPassword: (token, password) => {
    return apiClient.post(API_ENDPOINTS.AUTH.RESET_PASSWORD, {
      token: token,
      password: password
    }, { includeAuth: false });
  }
};

export default authApi;