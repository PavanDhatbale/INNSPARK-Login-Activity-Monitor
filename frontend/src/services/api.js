const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080';

/**
 * Helper to make API requests with automatic session token attachment.
 */
async function request(endpoint, options = {}) {
  const token = localStorage.getItem('session_token');

  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  if (token) {
    headers['X-Session-Token'] = token;
    headers['Authorization'] = `Bearer ${token}`;
  }

  const config = {
    ...options,
    headers,
  };

  const response = await fetch(`${API_BASE_URL}${endpoint}`, config);

  // Handle 204 No Content
  if (response.status === 204) {
    return null;
  }

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    if (response.status === 401 && token) {
      // Session expired due to inactivity or invalidation -> purge cached token
      localStorage.removeItem('session_token');
      localStorage.removeItem('user_info');
    }
    const error = new Error((data && data.message) || (data && data.error) || `HTTP error ${response.status}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}

export const api = {
  // --- Authentication ---
  async login(username, password, captchaToken = null) {
    return request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, captchaToken }),
    });
  },

  async verifyOtp(challengeId, otp) {
    return request('/auth/verify-otp', {
      method: 'POST',
      body: JSON.stringify({ challengeId, otp }),
    });
  },

  async resendOtp(challengeId) {
    return request('/auth/resend-otp', {
      method: 'POST',
      body: JSON.stringify({ challengeId }),
    });
  },

  async register(username, email, password) {
    return request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, email, password }),
    });
  },

  async getCaptchaStatus(username = null) {
    let url = '/auth/captcha-status';
    if (username) {
      url += `?username=${encodeURIComponent(username)}`;
    }
    return request(url, { method: 'GET' });
  },

  async getCurrentUser() {
    return request('/auth/me', { method: 'GET' });
  },

  async logout() {
    try {
      await request('/auth/logout', { method: 'POST' });
    } finally {
      localStorage.removeItem('session_token');
      localStorage.removeItem('user_info');
    }
  },

  // --- User Dashboard ---
  async getUserStats() {
    return request('/dashboard/stats', { method: 'GET' });
  },

  async getUserLoginHistory(status = null, page = 0, size = 10) {
    let url = `/dashboard/login-history?page=${page}&size=${size}`;
    if (status) {
      url += `&status=${status}`;
    }
    return request(url, { method: 'GET' });
  },

  async getUserSuspiciousActivities(page = 0, size = 10) {
    return request(`/dashboard/suspicious-activities?page=${page}&size=${size}`, { method: 'GET' });
  },

  // --- Admin Dashboard ---
  async getAdminStats() {
    return request('/admin/dashboard/stats', { method: 'GET' });
  },

  async getAdminUsers(page = 0, size = 10) {
    return request(`/admin/users?page=${page}&size=${size}`, { method: 'GET' });
  },

  async updateUserRole(id, role) {
    return request(`/admin/users/${id}/role`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    });
  },

  async updateUserStatus(id, enabled) {
    return request(`/admin/users/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    });
  },

  async getUserSessions(id) {
    return request(`/admin/users/${id}/sessions`, { method: 'GET' });
  },

  async revokeUserSession(userId, sessionId) {
    if (userId && sessionId) {
      return request(`/admin/users/${userId}/sessions/${sessionId}`, { method: 'DELETE' });
    }
    if (sessionId) {
      return request(`/admin/sessions/${sessionId}`, { method: 'DELETE' });
    }
    throw new Error('Valid session ID required to terminate session.');
  },

  async revokeAllUserSessions(userId) {
    return request(`/admin/users/${userId}/sessions`, { method: 'DELETE' });
  },

  async getAllSuspicious() {
    return request('/suspicious', { method: 'GET' });
  },
};
