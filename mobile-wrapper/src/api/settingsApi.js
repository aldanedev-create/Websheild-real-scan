/**
 * WebShield Scanner - Settings API
 */

import apiClient from './client.js';
import { API_ENDPOINTS } from '../config.js';

export const settingsApi = {
  getProfile: () => {
    return apiClient.get(API_ENDPOINTS.SETTINGS.PROFILE);
  },

  updateProfile: (data) => {
    return apiClient.put(API_ENDPOINTS.SETTINGS.PROFILE, data);
  },

  updateEmail: (email, password) => {
    return apiClient.put(API_ENDPOINTS.SETTINGS.EMAIL, { email, password });
  },

  updateUsername: (username) => {
    return apiClient.put(API_ENDPOINTS.SETTINGS.USERNAME, { username });
  },

  getSecuritySettings: () => {
    return apiClient.get(API_ENDPOINTS.SETTINGS.SECURITY);
  },

  deleteAccount: (password, confirm = false) => {
    return apiClient.post(API_ENDPOINTS.SETTINGS.DELETE_ACCOUNT, {
      password,
      confirm
    });
  }
};

export default settingsApi;
