/**
 * WebShield Scanner - Scan API
 * Handles scan operations and management.
 */

import apiClient from './client.js';
import { API_ENDPOINTS } from '../config.js';

export const scanApi = {
  /**
   * Validate a URL
   */
  validateUrl: (url) => {
    return apiClient.post(API_ENDPOINTS.SCAN.VALIDATE, { url });
  },

  /**
   * Start a new scan
   */
  startScan: (url, confirmAuth, options = {}) => {
    return apiClient.post(API_ENDPOINTS.SCAN.START, {
      url: url,
      confirm_authorization: confirmAuth,
      crawl_depth: options.crawlDepth || 3,
      max_pages: options.maxPages || 100,
      auth_cookie: options.authCookie || null,
      check_sensitive: options.checkSensitive || false,
      check_components: options.checkComponents || false
    });
  },

  /**
   * Get scan status
   */
  getScanStatus: (scanId) => {
    const endpoint = API_ENDPOINTS.SCAN.STATUS.replace(':id', scanId);
    return apiClient.get(endpoint);
  },

  /**
   * Cancel a scan
   */
  cancelScan: (scanId) => {
    const endpoint = API_ENDPOINTS.SCAN.CANCEL.replace(':id', scanId);
    return apiClient.post(endpoint, {});
  },

  /**
   * Get scan history
   */
  getScanHistory: (page = 1, perPage = 10, status = 'all', sortBy = 'created_at', sortOrder = 'desc') => {
    const params = new URLSearchParams({
      page: page,
      per_page: perPage,
      status: status,
      sort_by: sortBy,
      sort_order: sortOrder
    });
    return apiClient.get(`${API_ENDPOINTS.SCAN.HISTORY}?${params}`);
  },

  /**
   * Get scan statistics
   */
  getStats: () => {
    return apiClient.get(API_ENDPOINTS.SCAN.STATS);
  }
};

export default scanApi;
