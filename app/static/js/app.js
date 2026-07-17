/**
 * WebShield Scanner - Main Application JavaScript
 * Initializes the application and provides common utilities.
 */

(function() {
    'use strict';

    // ========================================
    // Application Configuration
    // ========================================
    const AppConfig = {
        version: '1.0.0',
        apiBase: '/api',
        debug: true,
        defaultHeaders: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    };

    // ========================================
    // Application State
    // ========================================
    const AppState = {
        user: null,
        isAuthenticated: false,
        isPremium: false,
        currentPage: null,
        loading: false
    };

    function applyTheme(theme) {
        const normalizedTheme = theme === 'light' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', normalizedTheme);
    }

    // ========================================
    // DOM Ready
    // ========================================
    document.addEventListener('DOMContentLoaded', function() {
        // Initialize app
        initApp();
    });

    /**
     * Initialize the application
     */
    function initApp() {
        // Set up CSRF token for forms
        setupCSRF();

        // Load display session and refresh it from the server when possible.
        loadUserSession();
        refreshUserSession();

        // Initialize tooltips
        initTooltips();

        // Initialize popovers
        initPopovers();

        // Handle mobile menu
        initMobileMenu();

        // Log app start
        if (AppConfig.debug) {
            console.log(`WebShield Scanner v${AppConfig.version} initialized`);
        }
    }

    /**
     * Set up CSRF token for forms
     */
    function setupCSRF() {
        const csrfToken = document.querySelector('meta[name="csrf-token"]');
        if (csrfToken) {
            // Add CSRF token to all forms
            document.querySelectorAll('form').forEach(form => {
                if (!form.querySelector('input[name="csrf_token"]')) {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = 'csrf_token';
                    input.value = csrfToken.content;
                    form.appendChild(input);
                }
            });
        }
    }

    /**
     * Load user session from browser storage for display only.
     */
    function loadUserSession() {
        try {
            localStorage.removeItem('webshield_user');

            const isAuthenticated = Boolean(window.api && window.api.isAuthenticated());
            if (!isAuthenticated) {
                sessionStorage.removeItem('webshield_user');
                return;
            }

            const cachedUser = window.api && typeof window.api.getUser === 'function'
                ? window.api.getUser()
                : readDisplayUserCache();

            if (cachedUser) {
                AppState.user = cachedUser;
                AppState.isAuthenticated = true;
                AppState.isPremium = false;
                applyTheme(cachedUser.theme);
            }
        } catch (e) {
            console.error('Error loading user session:', e);
        }
    }

    function refreshUserSession() {
        if (!window.api || !window.api.isAuthenticated()) return;

        window.api.auth.me()
            .then(data => {
                if (!data.success || !data.user) return;
                AppState.user = data.user;
                AppState.isAuthenticated = true;
                AppState.isPremium = Boolean(data.user.is_premium || data.user.plan === 'premium' || data.user.is_admin);
                applyTheme(data.user.theme);

                if (typeof window.api.storeUser === 'function') {
                    window.api.storeUser(data.user, false);
                } else {
                    sessionStorage.setItem('webshield_user', JSON.stringify(displaySafeUser(data.user)));
                    localStorage.removeItem('webshield_user');
                }
            })
            .catch(() => {
                AppState.user = null;
                AppState.isAuthenticated = false;
                AppState.isPremium = false;
            });
    }

    function readDisplayUserCache() {
        const userData = sessionStorage.getItem('webshield_user');
        if (!userData) return null;

        try {
            return JSON.parse(userData);
        } catch (err) {
            sessionStorage.removeItem('webshield_user');
            return null;
        }
    }

    function displaySafeUser(user) {
        const safeUser = {};
        ['id', 'username', 'email', 'full_name', 'avatar_url', 'plan', 'theme'].forEach((key) => {
            if (Object.prototype.hasOwnProperty.call(user, key)) {
                safeUser[key] = user[key];
            }
        });
        return safeUser;
    }

    /**
     * Initialize Bootstrap tooltips
     */
    function initTooltips() {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function(tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }

    /**
     * Initialize Bootstrap popovers
     */
    function initPopovers() {
        const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
        popoverTriggerList.map(function(popoverTriggerEl) {
            return new bootstrap.Popover(popoverTriggerEl);
        });
    }

    /**
     * Initialize mobile menu handling
     */
    function initMobileMenu() {
        const navbarToggler = document.querySelector('.navbar-toggler');
        const navbarCollapse = document.querySelector('#navbarMain');

        if (navbarToggler && navbarCollapse) {
            // Close menu when clicking outside
            document.addEventListener('click', function(e) {
                if (window.innerWidth < 992) {
                    const isClickInside = navbarToggler.contains(e.target) || navbarCollapse.contains(e.target);
                    if (!isClickInside && navbarCollapse.classList.contains('show')) {
                        const bsCollapse = bootstrap.Collapse.getInstance(navbarCollapse);
                        if (bsCollapse) {
                            bsCollapse.hide();
                        }
                    }
                }
            });

            // Close menu on nav link click
            navbarCollapse.querySelectorAll('.nav-link').forEach(link => {
                link.addEventListener('click', function() {
                    if (window.innerWidth < 992) {
                        const bsCollapse = bootstrap.Collapse.getInstance(navbarCollapse);
                        if (bsCollapse) {
                            bsCollapse.hide();
                        }
                    }
                });
            });
        }
    }

    // ========================================
    // Public API
    // ========================================
    window.WebShield = {
        config: AppConfig,
        state: AppState,
        applyTheme: applyTheme,
        
        /**
         * Show a loading spinner
         */
        showLoading: function(element) {
            if (element) {
                element.classList.add('loading');
                const spinner = document.createElement('div');
                spinner.className = 'spinner-border spinner-border-sm text-primary';
                spinner.setAttribute('role', 'status');
                element.appendChild(spinner);
            }
        },

        /**
         * Hide loading spinner
         */
        hideLoading: function(element) {
            if (element) {
                element.classList.remove('loading');
                const spinner = element.querySelector('.spinner-border');
                if (spinner) {
                    spinner.remove();
                }
            }
        },

        /**
         * Show a toast notification
         */
        showToast: function(message, type = 'info') {
            const allowedTypes = ['success', 'danger', 'warning', 'info'];
            const safeType = allowedTypes.includes(type) ? type : 'info';
            let toastContainer = document.getElementById('toast-container');
            if (!toastContainer) {
                // Create container if it doesn't exist
                const container = document.createElement('div');
                container.id = 'toast-container';
                container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
                document.body.appendChild(container);
                toastContainer = container;
            }

            const toastEl = document.createElement('div');
            toastEl.className = `toast align-items-center text-white bg-${safeType} border-0`;
            toastEl.setAttribute('role', 'alert');
            toastEl.setAttribute('aria-live', 'assertive');
            toastEl.setAttribute('aria-atomic', 'true');

            const iconMap = {
                success: 'fa-check-circle',
                danger: 'fa-exclamation-circle',
                warning: 'fa-exclamation-triangle',
                info: 'fa-info-circle'
            };

            toastEl.innerHTML = `
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="fas ${iconMap[safeType] || 'fa-info-circle'} me-2"></i>
                        <span class="toast-message"></span>
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            `;
            toastEl.querySelector('.toast-message').textContent = message || '';

            toastContainer.appendChild(toastEl);
            const toast = new bootstrap.Toast(toastEl, { delay: 5000 });
            toast.show();

            // Remove after hide
            toastEl.addEventListener('hidden.bs.toast', function() {
                toastEl.remove();
            });
        },

        /**
         * Format a date
         */
        formatDate: function(date, format = 'short') {
            const d = new Date(date);
            if (format === 'short') {
                return d.toLocaleDateString();
            } else if (format === 'long') {
                return d.toLocaleString();
            } else if (format === 'relative') {
                const now = new Date();
                const diff = now - d;
                const minutes = Math.floor(diff / 60000);
                const hours = Math.floor(diff / 3600000);
                const days = Math.floor(diff / 86400000);

                if (minutes < 1) return 'Just now';
                if (minutes < 60) return `${minutes}m ago`;
                if (hours < 24) return `${hours}h ago`;
                if (days < 7) return `${days}d ago`;
                return d.toLocaleDateString();
            }
            return d.toISOString();
        },

        /**
         * Truncate text
         */
        truncate: function(text, length = 100) {
            if (!text) return '';
            if (text.length <= length) return text;
            return text.substring(0, length) + '...';
        },

        /**
         * Escape HTML
         */
        escapeHtml: function(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        /**
         * Debounce function
         */
        debounce: function(func, wait = 300) {
            let timeout;
            return function executedFunction(...args) {
                const context = this;
                const later = () => {
                    clearTimeout(timeout);
                    func.apply(context, args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        },

        /**
         * Get URL parameters
         */
        getUrlParams: function() {
            const params = {};
            const search = window.location.search.substring(1);
            if (search) {
                search.split('&').forEach(pair => {
                    const [key, value] = pair.split('=');
                    params[decodeURIComponent(key)] = decodeURIComponent(value || '');
                });
            }
            return params;
        },

        /**
         * Update URL without reload
         */
        updateUrl: function(url, replace = false) {
            if (replace) {
                window.history.replaceState({}, '', url);
            } else {
                window.history.pushState({}, '', url);
            }
        }
    };

    window.deleteScan = async function(scanId) {
        if (!window.api || !window.api.isAuthenticated()) {
            window.location.href = '/login';
            return;
        }
        if (!confirm('Delete this scan? This cannot be undone.')) return;
        try {
            await window.api.scan.delete(scanId);
            WebShield.showToast('Scan deleted.', 'success');
            const card = document.querySelector(`[data-scan-id="${Number(scanId)}"]`);
            if (card) card.remove();
        } catch (error) {
            WebShield.showToast(error.message || 'Could not delete scan.', 'danger');
        }
    };

})();
