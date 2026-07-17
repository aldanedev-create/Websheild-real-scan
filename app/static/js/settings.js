/**
 * WebShield Scanner - Settings JavaScript
 * Handles user profile, preferences, password, and account settings.
 */

(function() {
    'use strict';

    const initialValues = {};

    window.initSettings = function() {
        captureInitialValues();
        applyTheme(valueOf('theme') || 'dark');

        const profileForm = document.getElementById('profile-form');
        if (profileForm) {
            profileForm.addEventListener('submit', function(e) {
                e.preventDefault();
                updateProfile(this);
            });
        }

        const prefsForm = document.getElementById('preferences-form');
        if (prefsForm) {
            prefsForm.addEventListener('submit', function(e) {
                e.preventDefault();
                updatePreferences(this);
            });
        }

        const themeControl = document.getElementById('theme');
        if (themeControl) {
            themeControl.addEventListener('change', function() {
                applyTheme(this.value);
            });
        }

        const passwordForm = document.getElementById('password-form');
        if (passwordForm) {
            passwordForm.addEventListener('submit', function(e) {
                e.preventDefault();
                changePassword(this);
            });
        }
    };

    function captureInitialValues() {
        initialValues.username = valueOf('username');
        initialValues.email = valueOf('email');
    }

    async function updateProfile(form) {
        if (!ensureAuthenticated()) return;

        const fullName = valueOf('full-name');
        const username = valueOf('username');
        const email = valueOf('email');
        const bio = valueOf('bio');
        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = setBusy(submitBtn, '<i class="fas fa-spinner fa-spin"></i> Saving...');

        try {
            const tasks = [
                window.api.settings.updateProfile({
                    full_name: fullName,
                    bio: bio
                })
            ];

            if (username && username !== initialValues.username) {
                tasks.push(window.api.settings.updateUsername(username));
            }

            if (email && email !== initialValues.email) {
                const password = prompt('Enter your current password to change email:');
                if (!password) {
                    throw new Error('Current password is required to change email.');
                }
                tasks.push(window.api.settings.updateEmail(email, password));
            }

            await Promise.all(tasks);
            await refreshStoredUser();
            initialValues.username = username;
            initialValues.email = email;
            WebShield.showToast('Profile updated successfully!', 'success');
        } catch (error) {
            console.error('Update profile error:', error);
            WebShield.showToast(error.message || 'Failed to update profile.', 'danger');
        } finally {
            restoreBusy(submitBtn, originalText);
        }
    }

    async function updatePreferences(form) {
        if (!ensureAuthenticated()) return;

        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = setBusy(submitBtn, '<i class="fas fa-spinner fa-spin"></i> Saving...');

        try {
            const response = await window.api.settings.updateProfile({
                theme: valueOf('theme'),
                notifications_enabled: checked('notifications'),
                marketing_emails: checked('marketing')
            });
            applyTheme(response.profile && response.profile.theme);
            await refreshStoredUser();
            WebShield.showToast('Preferences updated successfully!', 'success');
        } catch (error) {
            console.error('Update preferences error:', error);
            WebShield.showToast(error.message || 'Failed to update preferences.', 'danger');
        } finally {
            restoreBusy(submitBtn, originalText);
        }
    }

    async function changePassword(form) {
        if (!ensureAuthenticated()) return;

        const currentPassword = valueOf('current-password', false);
        const newPassword = valueOf('new-password', false);
        const confirmPassword = valueOf('confirm-password', false);

        if (!currentPassword || !newPassword || !confirmPassword) {
            WebShield.showToast('Please fill in all fields.', 'warning');
            return;
        }

        if (newPassword !== confirmPassword) {
            WebShield.showToast('New passwords do not match.', 'warning');
            return;
        }

        if (!isValidPassword(newPassword)) {
            WebShield.showToast('New password must be at least 8 characters with uppercase, lowercase, numbers, and a special character.', 'warning');
            return;
        }

        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = setBusy(submitBtn, '<i class="fas fa-spinner fa-spin"></i> Changing...');

        try {
            await window.api.auth.changePassword(currentPassword, newPassword);
            WebShield.showToast('Password changed successfully!', 'success');
            form.reset();
        } catch (error) {
            console.error('Change password error:', error);
            WebShield.showToast(error.message || 'Failed to change password.', 'danger');
        } finally {
            restoreBusy(submitBtn, originalText);
        }
    }

    window.deleteAccount = async function() {
        if (!ensureAuthenticated()) return;

        const typed = prompt('Type DELETE to permanently delete your account and all scan data:');
        if (typed !== 'DELETE') {
            WebShield.showToast('Account deletion cancelled.', 'info');
            return;
        }

        const password = prompt('Please enter your password to confirm:');
        if (!password) {
            WebShield.showToast('Password required to delete account.', 'warning');
            return;
        }

        try {
            const data = await window.api.settings.deleteAccount(password, true);
            if (data.success) {
                WebShield.showToast('Account deleted successfully.', 'success');
                window.api.clearTokens(false);
                setTimeout(() => {
                    window.location.href = '/';
                }, 1500);
            }
        } catch (error) {
            console.error('Delete account error:', error);
            WebShield.showToast(error.message || 'Failed to delete account.', 'danger');
        }
    };

    async function refreshStoredUser() {
        const data = await window.api.auth.me();
        if (!data.success || !data.user) return;

        if (typeof window.api.storeUser === 'function') {
            window.api.storeUser(data.user, false);
        } else {
            sessionStorage.setItem('webshield_user', JSON.stringify(displaySafeUser(data.user)));
            localStorage.removeItem('webshield_user');
        }

        if (window.WebShield && window.WebShield.state) {
            window.WebShield.state.user = data.user;
            window.WebShield.state.isAuthenticated = true;
            window.WebShield.state.isPremium = Boolean(data.user.is_premium || data.user.plan === 'premium' || data.user.is_admin);
        }
        applyTheme(data.user.theme);
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

    function ensureAuthenticated() {
        if (!window.api || !window.api.isAuthenticated()) {
            window.location.href = '/login';
            return false;
        }
        return true;
    }

    function setBusy(button, html) {
        if (!button) return '';
        const original = button.innerHTML;
        button.disabled = true;
        button.innerHTML = html;
        return original;
    }

    function restoreBusy(button, original) {
        if (!button) return;
        button.disabled = false;
        button.innerHTML = original;
    }

    function applyTheme(theme) {
        if (window.WebShield && typeof window.WebShield.applyTheme === 'function') {
            window.WebShield.applyTheme(theme);
        } else {
            document.documentElement.setAttribute('data-theme', theme === 'light' ? 'light' : 'dark');
        }
    }

    function valueOf(id, trim = true) {
        const element = document.getElementById(id);
        if (!element) return '';
        return trim ? element.value.trim() : element.value;
    }

    function checked(id) {
        const element = document.getElementById(id);
        return Boolean(element && element.checked);
    }

    function isValidPassword(password) {
        return password.length >= 8 &&
            /[a-z]/.test(password) &&
            /[A-Z]/.test(password) &&
            /\d/.test(password) &&
            /[^a-zA-Z0-9]/.test(password);
    }

})();
