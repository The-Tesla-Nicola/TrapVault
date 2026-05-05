const API_BASE = '/monitor/api/';

/**
 * Core API Client with JWT interception and auto-refresh logic.
 */
export const api = {
    async request(endpoint, options = {}) {
        const token = localStorage.getItem('monitor_access_token');
        const headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
            ...options.headers
        };

        try {
            const response = await fetch(`${API_BASE}${endpoint}`, { ...options, headers });

            // Handle unauthorized (401) - attempt token refresh
            if (response.status === 401 && !endpoint.includes('auth/')) {
                const refreshed = await this.refreshToken();
                if (refreshed) {
                    // Retry original request with new token
                    return this.request(endpoint, options);
                } else {
                    // Refresh failed, redirect to login
                    this.logout();
                    return;
                }
            }

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || errorData.detail || `HTTP error! status: ${response.status}`);
            }

            // For metrics/plain text responses, check content type
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('text/plain')) {
                return response.text();
            }

            return response.json();
        } catch (error) {
            console.error(`API Request failed [${endpoint}]:`, error);
            throw error;
        }
    },

    async refreshToken() {
        const refresh = localStorage.getItem('monitor_refresh_token');
        if (!refresh) return false;

        try {
            const response = await fetch('/monitor/api/auth/refresh/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: refresh })
            });

            if (!response.ok) return false;

            const data = await response.json();
            localStorage.setItem('monitor_access_token', data.access_token);
            if (data.refresh_token) {
                localStorage.setItem('monitor_refresh_token', data.refresh_token);
            }
            return true;
        } catch (e) {
            return false;
        }
    },

    logout() {
        localStorage.removeItem('monitor_access_token');
        localStorage.removeItem('monitor_refresh_token');
        localStorage.removeItem('monitor_user_role');
        localStorage.removeItem('monitor_username');
        window.location.href = '/monitor/login/';
    },

    get: (endpoint) => api.request(endpoint, { method: 'GET' }),
    post: (endpoint, body) => api.request(endpoint, { method: 'POST', body: JSON.stringify(body) }),
    put: (endpoint, body) => api.request(endpoint, { method: 'PUT', body: JSON.stringify(body) }),
    delete: (endpoint) => api.request(endpoint, { method: 'DELETE' })
};
