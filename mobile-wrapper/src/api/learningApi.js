/**
 * WebShield Scanner - Learning API
 */

import apiClient from './client.js';
import { API_ENDPOINTS } from '../config.js';

const buildQuery = (params = {}) => {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      query.append(key, value);
    }
  });
  const text = query.toString();
  return text ? `?${text}` : '';
};

export const learningApi = {
  getLessons: (params = {}) => {
    return apiClient.get(`${API_ENDPOINTS.LEARNING.LESSONS}${buildQuery(params)}`);
  },

  getLesson: (lessonId) => {
    const endpoint = API_ENDPOINTS.LEARNING.LESSON.replace(':id', lessonId);
    return apiClient.get(endpoint);
  },

  likeLesson: (lessonId) => {
    const endpoint = API_ENDPOINTS.LEARNING.LIKE.replace(':id', lessonId);
    return apiClient.post(endpoint, {});
  },

  getCategories: () => {
    return apiClient.get(API_ENDPOINTS.LEARNING.CATEGORIES);
  },

  search: (query) => {
    return apiClient.get(`${API_ENDPOINTS.LEARNING.SEARCH}${buildQuery({ q: query })}`);
  }
};

export default learningApi;
