/**
 * WebShield Scanner - Report API
 * Handles report generation and management.
 */

import apiClient from './client.js';
import { API_ENDPOINTS } from '../config.js';

export const reportApi = {
  /**
   * Get full report
   */
  getReport: (scanId) => {
    const endpoint = API_ENDPOINTS.REPORT.GET.replace(':id', scanId);
    return apiClient.get(endpoint);
  },

  /**
   * Get findings with filters
   */
  getFindings: (scanId, severity = null, category = null) => {
    const endpoint = API_ENDPOINTS.REPORT.FINDINGS.replace(':id', scanId);
    const params = new URLSearchParams();
    if (severity) params.append('severity', severity);
    if (category) params.append('category', category);
    const url = params.toString() ? `${endpoint}?${params}` : endpoint;
    return apiClient.get(url);
  },

  /**
   * Update a finding
   */
  updateFinding: (scanId, findingId, action, note = null) => {
    const endpoint = API_ENDPOINTS.REPORT.UPDATE_FINDING
      .replace(':id', scanId)
      .replace(':findingId', findingId);
    return apiClient.put(endpoint, {
      action: action,
      note: note
    });
  },

  /**
   * Export report
   */
  exportReport: (scanId, format = 'html') => {
    const endpoint = API_ENDPOINTS.REPORT.EXPORT
      .replace(':id', scanId)
      .replace(':format', format);
    return apiClient.get(endpoint);
  },

  /**
   * Share report
   */
  shareReport: (scanId) => {
    const endpoint = API_ENDPOINTS.REPORT.SHARE.replace(':id', scanId);
    return apiClient.post(endpoint, {});
  }
};

export default reportApi;