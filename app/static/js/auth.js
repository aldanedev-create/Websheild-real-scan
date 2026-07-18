/**
 * WebShield Scanner - Authentication JavaScript
 * Handles login, registration, and password reset functionality.
 */

(function() {
    'use strict';

    // ========================================
    // Login Form Handler
    // ========================================
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            handleLogin(this);
        });
    }

    /**
     * Handle login form submission
     */
    async function handleLogin(form) {
        const emailOrUsername = document.getElementById('email_or_username').value.trim();
        const password = document.getElementById('password').value;
        const remember = document.getElementById('remember') ? document.getElementById('remember').checked : false;

        // Validate
        if (!emailOrUsername || !password) {
            showError('Please enter your email/username and password.');
            return;
        }

        // Show loading
        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing in...';

        try {
            const data = await window.api.auth.login(emailOrUsername, password, remember);
            if (data.success) {
                window.location.href = '/dashboard';
            } else {
                showError(data.message || 'Login failed. Please try again.');
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalText;
            }
        } catch (error) {
            console.error('Login error:', error);
            showError(error.message || 'An error occurred. Please try again.');
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        }
    }

    // ========================================
    // Registration Form Handler
    // ========================================
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            e.preventDefault();
            handleRegistration(this);
        });
    }

    /**
     * Handle registration form submission
     */
    async function handleRegistration(form) {
        const username = document.getElementById('username').value.trim();
        const email = document.getElementById('email').value.trim();
        const fullName = document.getElementById('full_name') ? document.getElementById('full_name').value.trim() : '';
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm_password').value;
        const terms = document.getElementById('terms') ? document.getElementById('terms').checked : false;

        // Validate
        if (!username || !email || !password || !confirmPassword) {
            showError('Please fill in all required fields.');
            return;
        }

        if (password !== confirmPassword) {
            showError('Passwords do not match.');
            return;
        }

        if (!terms) {
            showError('You must agree to the Terms of Service and Privacy Policy.');
            return;
        }

        // Validate password strength
        if (!isValidPassword(password)) {
            showError('Password must be at least 8 characters and use at least 3 of: uppercase, lowercase, number, or symbol.');
            return;
        }

        // Show loading
        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating account...';

        try {
            const data = await window.api.auth.register(username, email, password, fullName, false);
            if (data.success) {
                window.location.href = '/dashboard';
            } else {
                showError(data.message || 'Registration failed. Please try again.');
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalText;
            }
        } catch (error) {
            console.error('Registration error:', error);
            showError(error.message || 'An error occurred. Please try again.');
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        }
    }

    // ========================================
    // Forgot Password Handler
    // ========================================
    const forgotForm = document.getElementById('forgot-form');
    if (forgotForm) {
        forgotForm.addEventListener('submit', function(e) {
            e.preventDefault();
            handleForgotPassword(this);
        });
    }

    /**
     * Handle forgot password form submission
     */
    async function handleForgotPassword(form) {
        const email = document.getElementById('email').value.trim();

        if (!email) {
            showError('Please enter your email address.');
            return;
        }

        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';

        try {
            const data = await window.api.auth.forgotPassword(email);
            if (data.success) {
                showSuccess('Password reset link sent to your email. Please check your inbox.');
                form.reset();
            } else {
                showError(data.message || 'Failed to send reset link.');
            }
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        } catch (error) {
            console.error('Forgot password error:', error);
            showError(error.message || 'An error occurred. Please try again.');
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        }
    }

    // ========================================
    // Reset Password Handler
    // ========================================
    const resetForm = document.getElementById('reset-form');
    if (resetForm) {
        resetForm.addEventListener('submit', function(e) {
            e.preventDefault();
            handleResetPassword(this);
        });
    }

    /**
     * Handle reset password form submission
     */
    async function handleResetPassword(form) {
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm_password').value;

        if (!password || !confirmPassword) {
            showError('Please enter and confirm your new password.');
            return;
        }

        if (password !== confirmPassword) {
            showError('Passwords do not match.');
            return;
        }

        if (!isValidPassword(password)) {
            showError('Password must be at least 8 characters and use at least 3 of: uppercase, lowercase, number, or symbol.');
            return;
        }

        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Resetting...';

        const token = window.location.pathname.split('/').pop();

        try {
            const data = await window.api.auth.resetPassword(token, password);
            if (data.success) {
                showSuccess('Password reset successfully! Redirecting to login...');
                setTimeout(() => {
                    window.location.href = '/login';
                }, 2000);
            } else {
                showError(data.message || 'Failed to reset password.');
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalText;
            }
        } catch (error) {
            console.error('Reset password error:', error);
            showError(error.message || 'An error occurred. Please try again.');
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        }
    }

    // ========================================
    // Password Strength Checker
    // ========================================
    window.checkPasswordStrength = function(password) {
        let score = 0;
        if (password.length >= 8) score++;
        if (password.length >= 12) score++;
        if (/[a-z]/.test(password)) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/\d/.test(password)) score++;
        if (/[^a-zA-Z0-9]/.test(password)) score++;
        return score;
    };

    function isValidPassword(password) {
        if (password.length < 8) return false;

        const characterTypes = [
            /[a-z]/.test(password),
            /[A-Z]/.test(password),
            /\d/.test(password),
            /[^a-zA-Z0-9\s]/.test(password)
        ];

        return characterTypes.filter(Boolean).length >= 3;
    }

    // ========================================
    // Toast / Notification Helpers
    // ========================================
    function showError(message) {
        const container = document.querySelector('.flash-container') || document.body;
        const alert = document.createElement('div');
        alert.className = 'alert alert-danger alert-dismissible fade show flash-message';
        alert.innerHTML = `
            <div class="flash-icon"><i class="fas fa-exclamation-circle"></i></div>
            <div class="flash-message-text"></div>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        alert.querySelector('.flash-message-text').textContent = message || '';
        container.prepend(alert);
        setTimeout(() => {
            if (alert.parentNode) {
                alert.classList.remove('show');
                setTimeout(() => alert.remove(), 300);
            }
        }, 5000);
    }

    function showSuccess(message) {
        const container = document.querySelector('.flash-container') || document.body;
        const alert = document.createElement('div');
        alert.className = 'alert alert-success alert-dismissible fade show flash-message';
        alert.innerHTML = `
            <div class="flash-icon"><i class="fas fa-check-circle"></i></div>
            <div class="flash-message-text"></div>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        alert.querySelector('.flash-message-text').textContent = message || '';
        container.prepend(alert);
        setTimeout(() => {
            if (alert.parentNode) {
                alert.classList.remove('show');
                setTimeout(() => alert.remove(), 300);
            }
        }, 5000);
    }

    // ========================================
    // Toggle Password Visibility
    // ========================================
    window.togglePassword = function(inputId) {
        const input = document.getElementById(inputId);
        if (!input) return;
        const icon = input.parentElement.querySelector('.password-toggle i');
        if (input.type === 'password') {
            input.type = 'text';
            if (icon) {
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            }
        } else {
            input.type = 'password';
            if (icon) {
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        }
    };

    // ========================================
    // Logout Handler
    // ========================================
    window.logout = async function() {
        try {
            await window.api.auth.logout();
        } catch (err) {
            if (window.api) window.api.clearTokens(false);
        }
        window.location.href = '/login';
    };

})();
