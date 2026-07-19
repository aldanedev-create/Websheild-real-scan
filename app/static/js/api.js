/**
 * WebShield Scanner - API Client
 * Centralized API access, auth token handling, and report downloads.
 */

(function() {
    'use strict';

    const ACCESS_TOKEN_KEY = 'webshield_token';
    const USER_KEY = 'webshield_user';
    const PERSIST_KEY = 'webshield_persistent';
    const LEGACY_REFRESH_KEY = 'webshield_refresh_token';
    const DEFAULT_TIMEOUT = 15000;

    class ApiClient {
        constructor(baseUrl = '/api') {
            this.baseUrl = baseUrl;
            this.defaultTimeout = DEFAULT_TIMEOUT;
            this.migrateLegacyStorage();
            this.token = this.getStoredToken();
        }

        migrateLegacyStorage() {
            const localToken = this.safeGet(localStorage, ACCESS_TOKEN_KEY);
            const localUser = this.safeGet(localStorage, USER_KEY);

            if (localToken && !this.safeGet(sessionStorage, ACCESS_TOKEN_KEY)) {
                this.safeSet(sessionStorage, ACCESS_TOKEN_KEY, localToken);
            }

            if (localUser && !this.safeGet(sessionStorage, USER_KEY)) {
                try {
                    this.safeSet(sessionStorage, USER_KEY, JSON.stringify(this.sanitizeUserForStorage(JSON.parse(localUser))));
                } catch (err) {
                    // Drop malformed legacy user cache.
                }
            }

            this.safeRemove(localStorage, ACCESS_TOKEN_KEY);
            this.safeRemove(localStorage, USER_KEY);
            this.safeRemove(localStorage, LEGACY_REFRESH_KEY);
            this.safeRemove(sessionStorage, LEGACY_REFRESH_KEY);
        }

        safeGet(storage, key) {
            try {
                return storage.getItem(key);
            } catch (err) {
                return null;
            }
        }

        safeSet(storage, key, value) {
            try {
                storage.setItem(key, value);
            } catch (err) {
                // Storage can be blocked in private modes. Keep the in-memory token.
            }
        }

        safeRemove(storage, key) {
            try {
                storage.removeItem(key);
            } catch (err) {
                // Ignore storage cleanup failures.
            }
        }

        usesPersistentSession() {
            return this.safeGet(localStorage, PERSIST_KEY) === 'true';
        }

        getStoredToken() {
            return this.safeGet(sessionStorage, ACCESS_TOKEN_KEY);
        }

        setToken(token, remember = this.usesPersistentSession()) {
            this.token = token || null;

            this.safeRemove(sessionStorage, LEGACY_REFRESH_KEY);
            this.safeRemove(localStorage, LEGACY_REFRESH_KEY);
            this.safeRemove(localStorage, ACCESS_TOKEN_KEY);

            if (!token) {
                this.safeRemove(sessionStorage, ACCESS_TOKEN_KEY);
                return;
            }

            this.safeSet(sessionStorage, ACCESS_TOKEN_KEY, token);

            if (remember) {
                this.safeSet(localStorage, PERSIST_KEY, 'true');
            } else {
                this.safeRemove(localStorage, PERSIST_KEY);
            }
        }

        storeUser(user, remember = this.usesPersistentSession()) {
            if (!user) return;
            this.safeSet(sessionStorage, USER_KEY, JSON.stringify(this.sanitizeUserForStorage(user)));
            this.safeRemove(localStorage, USER_KEY);
        }

        getUser() {
            const raw = this.safeGet(sessionStorage, USER_KEY);
            this.safeRemove(localStorage, USER_KEY);
            if (!raw) return null;
            try {
                return JSON.parse(raw);
            } catch (err) {
                return null;
            }
        }

        sanitizeUserForStorage(user) {
            const safeUser = {};
            [
                'id',
                'username',
                'email',
                'full_name',
                'avatar_url',
                'plan',
                'theme'
            ].forEach((key) => {
                if (Object.prototype.hasOwnProperty.call(user, key)) {
                    safeUser[key] = user[key];
                }
            });
            return safeUser;
        }

        storeSession(data, remember = false) {
            if (!data) return data;
            if (data.access_token) this.setToken(data.access_token, remember);
            if (data.user) this.storeUser(data.user, remember);
            this.safeRemove(localStorage, LEGACY_REFRESH_KEY);
            this.safeRemove(sessionStorage, LEGACY_REFRESH_KEY);
            return data;
        }

        clearTokens(redirect = false) {
            this.token = null;
            [sessionStorage, localStorage].forEach((storage) => {
                this.safeRemove(storage, ACCESS_TOKEN_KEY);
                this.safeRemove(storage, USER_KEY);
                this.safeRemove(storage, LEGACY_REFRESH_KEY);
            });
            this.safeRemove(localStorage, PERSIST_KEY);

            if (redirect) {
                window.location.href = '/login';
            }
        }

        isAuthenticated() {
            this.token = this.getStoredToken();
            return Boolean(this.token);
        }

        getCsrfToken() {
            const meta = document.querySelector('meta[name="csrf-token"]');
            if (meta && meta.content) return meta.content;

            const input = document.querySelector('input[name="csrf_token"]');
            return input ? input.value : null;
        }

        getHeaders(includeAuth = true, hasBody = false, extraHeaders = {}) {
            this.token = this.getStoredToken();

            const headers = {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                ...extraHeaders
            };

            if (hasBody && !headers['Content-Type']) {
                headers['Content-Type'] = 'application/json';
            }

            if (includeAuth && this.token) {
                headers.Authorization = 'Bearer ' + this.token;
            }

            const csrf = this.getCsrfToken();
            if (csrf && hasBody) {
                headers['X-CSRFToken'] = csrf;
                headers['X-CSRF-Token'] = csrf;
            }

            return headers;
        }

        async get(endpoint, includeAuth = true, options = {}) {
            return this.request(endpoint, { ...options, method: 'GET', includeAuth });
        }

        async post(endpoint, data = {}, includeAuth = true, options = {}) {
            return this.request(endpoint, { ...options, method: 'POST', data, includeAuth });
        }

        async put(endpoint, data = {}, includeAuth = true, options = {}) {
            return this.request(endpoint, { ...options, method: 'PUT', data, includeAuth });
        }

        async delete(endpoint, includeAuth = true, options = {}) {
            return this.request(endpoint, { ...options, method: 'DELETE', includeAuth });
        }

        async request(endpoint, options = {}) {
            const method = options.method || 'GET';
            const includeAuth = options.includeAuth !== false;
            const hasBody = Object.prototype.hasOwnProperty.call(options, 'data') &&
                options.data !== undefined &&
                options.data !== null;
            const timeout = options.timeout === undefined ? this.defaultTimeout : options.timeout;
            const url = this.resolveUrl(endpoint);

            const fetchOptions = {
                method,
                credentials: 'same-origin',
                headers: this.getHeaders(includeAuth, hasBody, options.headers || {})
            };

            if (hasBody) {
                fetchOptions.body = JSON.stringify(options.data);
            }

            const response = await this.fetchWithTimeout(url, fetchOptions, timeout, options.signal);

            if (
                response.status === 401 &&
                includeAuth &&
                options.retryAuth !== false &&
                endpoint !== '/auth/refresh'
            ) {
                const refreshed = await this.refreshAccessToken();
                if (refreshed) {
                    return this.request(endpoint, { ...options, retryAuth: false });
                }
            }

            if (!response.ok && response.status === 401 && includeAuth) {
                this.clearTokens(false);
            }

            return this.handleResponse(response);
        }

        async fetchWithTimeout(url, fetchOptions, timeout, externalSignal) {
            if (!timeout && !externalSignal) {
                return fetch(url, fetchOptions);
            }

            const controller = new AbortController();
            let timer = null;

            const abortRequest = () => controller.abort();
            if (externalSignal) {
                if (externalSignal.aborted) abortRequest();
                externalSignal.addEventListener('abort', abortRequest, { once: true });
            }

            if (timeout) {
                timer = window.setTimeout(abortRequest, timeout);
            }

            try {
                return await fetch(url, { ...fetchOptions, signal: controller.signal });
            } finally {
                if (timer) window.clearTimeout(timer);
                if (externalSignal) externalSignal.removeEventListener('abort', abortRequest);
            }
        }

        async handleResponse(response) {
            const data = await this.parseResponse(response);

            if (!response.ok) {
                throw this.apiError(response, data);
            }

            return data;
        }

        async parseResponse(response) {
            if (response.status === 204) return null;

            const contentType = response.headers.get('content-type') || '';
            if (contentType.includes('application/json')) {
                try {
                    return await response.json();
                } catch (err) {
                    return { message: 'Invalid JSON response' };
                }
            }

            const text = await response.text();
            return { message: this.safeResponseMessage(text, response.status), raw: text };
        }

        safeResponseMessage(text, status) {
            if (!text) return 'Request failed';
            if (/^\s*</.test(text)) return 'Request failed with status ' + status;
            return text.length > 500 ? text.slice(0, 500) + '...' : text;
        }

        apiError(response, data = {}) {
            const error = new Error(data.message || data.error || 'API request failed');
            error.status = response.status;
            error.data = data;
            return error;
        }

        async refreshAccessToken() {
            try {
                const data = await this.request('/auth/refresh', {
                    method: 'POST',
                    data: {},
                    includeAuth: false,
                    retryAuth: false,
                    timeout: 10000
                });

                if (data && data.success && data.access_token) {
                    this.setToken(data.access_token, this.usesPersistentSession());
                    if (data.user) this.storeUser(data.user, this.usesPersistentSession());
                    return true;
                }
            } catch (err) {
                // Refresh uses the httpOnly refresh cookie; no JS refresh token is kept.
            }

            this.clearTokens(false);
            return false;
        }

        async download(endpoint, includeAuth = true, options = {}) {
            const response = await this.requestRaw(endpoint, includeAuth, options);
            const blob = await response.blob();
            return {
                blob,
                filename: this.sanitizeFilename(this.filenameFromResponse(response) || options.filename || 'webshield_report')
            };
        }

        async requestRaw(endpoint, includeAuth = true, options = {}) {
            const timeout = options.timeout === undefined ? this.defaultTimeout : options.timeout;
            const response = await this.fetchWithTimeout(
                this.resolveUrl(endpoint),
                {
                    method: options.method || 'GET',
                    credentials: 'same-origin',
                    headers: this.getHeaders(includeAuth, false, options.headers || {})
                },
                timeout,
                options.signal
            );

            if (
                response.status === 401 &&
                includeAuth &&
                options.retryAuth !== false &&
                endpoint !== '/auth/refresh'
            ) {
                const refreshed = await this.refreshAccessToken();
                if (refreshed) {
                    return this.requestRaw(endpoint, includeAuth, { ...options, retryAuth: false });
                }
            }

            if (!response.ok) {
                throw this.apiError(response, await this.parseResponse(response));
            }

            return response;
        }

        filenameFromResponse(response) {
            const disposition = response.headers.get('content-disposition') || '';
            const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i);
            if (encoded) return decodeURIComponent(encoded[1]);

            const plain = disposition.match(/filename="?([^";]+)"?/i);
            return plain ? plain[1] : null;
        }

        sanitizeFilename(filename) {
            return String(filename || 'download')
                .replace(/[/\\?%*:|"<>]/g, '_')
                .replace(/\s+/g, '_')
                .slice(0, 180);
        }

        resolveUrl(endpoint) {
            if (/^https?:\/\//i.test(endpoint)) return endpoint;
            return this.baseUrl + endpoint;
        }

        auth = {
            login: async (emailOrUsername, password, remember = false) => {
                const data = await this.post('/auth/login', {
                    email_or_username: emailOrUsername,
                    password,
                    remember
                }, false);
                return this.storeSession(data, remember);
            },

            register: async (username, email, password, fullName = '', remember = false) => {
                const data = await this.post('/auth/register', {
                    username,
                    email,
                    password,
                    full_name: fullName,
                    remember
                }, false);
                return this.storeSession(data, remember);
            },

            logout: async () => {
                try {
                    return await this.post('/auth/logout', {}, true, { retryAuth: false });
                } finally {
                    this.clearTokens(false);
                }
            },

            refresh: async () => {
                const success = await this.refreshAccessToken();
                return { success, access_token: this.token };
            },

            me: () => this.get('/auth/me'),
            updateProfile: (data) => this.put('/auth/me', data),
            changePassword: (currentPassword, newPassword) => this.post('/auth/change-password', {
                current_password: currentPassword,
                new_password: newPassword
            }),
            forgotPassword: (email) => this.post('/auth/forgot-password', { email }, false),
            resetPassword: (token, password) => this.post('/auth/reset-password', { token, password }, false)
        };

        scan = {
            validate: (url, options = {}) => this.post('/scan/validate', { url }, true, options),
            start: (url, confirmAuth, options = {}) => this.post('/scan/start', {
                url,
                confirm_authorization: Boolean(confirmAuth),
                crawl_depth: options.crawlDepth || 1,
                max_pages: options.maxPages || 20,
                auth_cookie: options.authCookie || null,
                check_sensitive: Boolean(options.checkSensitive),
                check_components: Boolean(options.checkComponents)
            }),
            status: (scanId, options = {}) => this.get('/scan/' + encodeURIComponent(scanId) + '/status', true, options),
            cancel: (scanId, options = {}) => this.post(
                '/scan/' + encodeURIComponent(scanId) + '/cancel',
                {},
                true,
                options
            ),
            delete: (scanId) => this.post('/scan/' + encodeURIComponent(scanId) + '/delete'),
            history: (page = 1, perPage = 10, status = 'all', extra = {}) => {
                const params = new URLSearchParams();
                params.set('page', page);
                params.set('per_page', perPage);
                if (status && status !== 'all') params.set('status', status);
                if (extra.query) params.set('q', extra.query);
                if (extra.sort) params.set('sort', extra.sort);
                return this.get('/dashboard/scan-history?' + params.toString());
            },
            stats: () => this.get('/dashboard/stats')
        };

        report = {
            get: (scanId) => this.get('/report/' + encodeURIComponent(scanId)),
            findings: (scanId, severity = null, category = null) => {
                const params = new URLSearchParams();
                if (severity) params.set('severity', severity);
                if (category) params.set('category', category);
                const suffix = params.toString() ? '?' + params.toString() : '';
                return this.get('/report/' + encodeURIComponent(scanId) + '/findings' + suffix);
            },
            updateFinding: (scanId, findingId, action, note = null) => this.put(
                '/report/' + encodeURIComponent(scanId) + '/findings/' + encodeURIComponent(findingId),
                { action, note }
            ),
            export: (scanId, format) => {
                const safeFormat = ['html', 'pdf', 'json'].includes(format) ? format : 'json';
                return this.download(
                    '/report/' + encodeURIComponent(scanId) + '/export/' + safeFormat,
                    true,
                    { timeout: safeFormat === 'pdf' ? 60000 : this.defaultTimeout }
                );
            },
            share: (scanId) => this.post('/report/' + encodeURIComponent(scanId) + '/share')
        };

        learning = {
            getLessons: (category = null, difficulty = null, search = null, limit = 20, offset = 0) => {
                const params = new URLSearchParams();
                if (category) params.set('category', category);
                if (difficulty) params.set('difficulty', difficulty);
                if (search) params.set('search', search);
                params.set('limit', limit);
                params.set('offset', offset);
                return this.get('/learning/lessons?' + params.toString(), false);
            },
            getLesson: (lessonId) => this.get('/learning/lessons/' + encodeURIComponent(lessonId), false),
            likeLesson: (lessonId) => this.post('/learning/lessons/' + encodeURIComponent(lessonId) + '/like'),
            getCategories: () => this.get('/learning/categories', false),
            search: (query) => this.get('/learning/search?q=' + encodeURIComponent(query), false)
        };

        settings = {
            getProfile: () => this.get('/settings/profile'),
            updateProfile: (data) => this.put('/settings/profile', data),
            updateEmail: (email, password) => this.put('/settings/email', { email, password }),
            updateUsername: (username) => this.put('/settings/username', { username }),
            deleteAccount: (password, confirm = true) => this.post('/settings/delete-account', { password, confirm }),
            getSecurity: () => this.get('/settings/security')
        };

        admin = {
            stats: () => this.get('/admin/dashboard/stats'),
            users: (options = {}) => {
                const params = new URLSearchParams();
                params.set('page', options.page || 1);
                params.set('per_page', options.perPage || 20);
                if (options.search) params.set('search', options.search);
                if (options.plan && options.plan !== 'all') params.set('plan', options.plan);
                return this.get('/admin/users?' + params.toString());
            },
            getUser: (userId) => this.get('/admin/users/' + encodeURIComponent(userId)),
            updateUser: (userId, data) => this.put('/admin/users/' + encodeURIComponent(userId), data),
            deleteUser: (userId) => this.post('/admin/users/' + encodeURIComponent(userId) + '/delete', {}),
            auditLogs: (options = {}) => {
                const params = new URLSearchParams();
                params.set('page', options.page || 1);
                params.set('per_page', options.perPage || 20);
                if (options.action) params.set('action', options.action);
                if (options.severity && options.severity !== 'all') params.set('severity', options.severity);
                if (options.userId) params.set('user_id', options.userId);
                if (options.days) params.set('days', options.days);
                return this.get('/admin/audit-logs?' + params.toString());
            },
            scans: (options = {}) => {
                const params = new URLSearchParams();
                params.set('page', options.page || 1);
                params.set('per_page', options.perPage || 20);
                if (options.status && options.status !== 'all') params.set('status', options.status);
                if (options.userId) params.set('user_id', options.userId);
                return this.get('/admin/scans?' + params.toString());
            },
            health: () => this.get('/admin/system/health')
        };
    }

    window.ApiClient = ApiClient;
    window.api = new ApiClient();
})();
