import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authApi } from '../api/authApi.js';
import { settingsApi } from '../api/settingsApi.js';
import { getToken, removeToken, removeUser, setUser } from '../api/client.js';
import '../styles/global.css';

const Settings = ({ user, onLogout, onUserUpdated }) => {
  const navigate = useNavigate();
  const [profile, setProfile] = useState({
    full_name: user?.full_name || '',
    bio: user?.bio || '',
    theme: user?.theme || 'dark',
    notifications_enabled: user?.notifications_enabled ?? true,
    marketing_emails: user?.marketing_emails ?? false
  });
  const [passwords, setPasswords] = useState({
    current: '',
    new: '',
    confirm: ''
  });
  const [loading, setLoading] = useState({
    profile: false,
    password: false,
    delete: false
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    document.documentElement.setAttribute(
      'data-theme',
      profile.theme === 'light' ? 'light' : 'dark'
    );
  }, [profile.theme]);

  const handleProfileChange = (e) => {
    const { name, value, type, checked } = e.target;
    setProfile(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
    setError('');
    setSuccess('');
  };

  const handlePasswordChange = (e) => {
    const { name, value } = e.target;
    setPasswords(prev => ({ ...prev, [name]: value }));
    setError('');
    setSuccess('');
  };

  const handleProfileSubmit = async (e) => {
    e.preventDefault();
    const token = getToken();
    if (!token) {
      navigate('/login');
      return;
    }

    setLoading(prev => ({ ...prev, profile: true }));
    setError('');
    setSuccess('');

    try {
      const response = await settingsApi.updateProfile({
        full_name: profile.full_name,
        bio: profile.bio,
        theme: profile.theme,
        notifications_enabled: profile.notifications_enabled,
        marketing_emails: profile.marketing_emails
      });

      if (response.success) {
        const updatedUser = {
          ...(user || {}),
          ...profile,
          ...(response.profile || {})
        };
        setSuccess('Profile updated successfully!');
        setUser(updatedUser);
        if (onUserUpdated) onUserUpdated(updatedUser);
      } else {
        setError(response.message || 'Failed to update profile.');
      }
    } catch (err) {
      console.error('Profile update error:', err);
      setError('An error occurred. Please try again.');
    } finally {
      setLoading(prev => ({ ...prev, profile: false }));
    }
  };

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();

    if (!passwords.current || !passwords.new || !passwords.confirm) {
      setError('Please fill in all password fields.');
      return;
    }

    if (passwords.new !== passwords.confirm) {
      setError('New passwords do not match.');
      return;
    }

    if (passwords.new.length < 8) {
      setError('New password must be at least 8 characters.');
      return;
    }

    const token = getToken();
    if (!token) {
      navigate('/login');
      return;
    }

    setLoading(prev => ({ ...prev, password: true }));
    setError('');
    setSuccess('');

    try {
      const response = await authApi.changePassword(passwords.current, passwords.new);
      if (response.success) {
        setSuccess('Password changed successfully!');
        setPasswords({ current: '', new: '', confirm: '' });
      } else {
        setError(response.message || 'Failed to change password.');
      }
    } catch (err) {
      console.error('Password change error:', err);
      setError('An error occurred. Please try again.');
    } finally {
      setLoading(prev => ({ ...prev, password: false }));
    }
  };

  const handleDeleteAccount = async () => {
    if (!confirm('WARNING: This will permanently delete your account and all data. Are you sure?')) {
      return;
    }

    if (!confirm('This action cannot be undone. Type "DELETE" to confirm.')) {
      return;
    }

    const password = prompt('Please enter your password to confirm:');
    if (!password) {
      setError('Password required to delete account.');
      return;
    }

    const token = getToken();
    if (!token) {
      navigate('/login');
      return;
    }

    setLoading(prev => ({ ...prev, delete: true }));
    setError('');
    setSuccess('');

    try {
      const response = await settingsApi.deleteAccount(password, true);
      if (response.success) {
        setSuccess('Account deleted successfully.');
        removeToken();
        removeUser();
        setTimeout(() => {
          onLogout();
          navigate('/');
        }, 1500);
      } else {
        setError(response.message || 'Failed to delete account.');
      }
    } catch (err) {
      console.error('Delete account error:', err);
      setError('An error occurred. Please try again.');
    } finally {
      setLoading(prev => ({ ...prev, delete: false }));
    }
  };

  const handleLogout = () => {
    removeToken();
    removeUser();
    onLogout();
    navigate('/login');
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">
          <i className="fas fa-cog"></i> Settings
        </h1>
      </div>

      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          <i className="fas fa-exclamation-circle me-2"></i>
          {error}
          <button type="button" className="btn-close" onClick={() => setError('')}></button>
        </div>
      )}

      {success && (
        <div className="alert alert-success alert-dismissible fade show" role="alert">
          <i className="fas fa-check-circle me-2"></i>
          {success}
          <button type="button" className="btn-close" onClick={() => setSuccess('')}></button>
        </div>
      )}

      {/* Profile Section */}
      <div className="settings-section">
        <h4><i className="fas fa-user"></i> Profile</h4>
        <form onSubmit={handleProfileSubmit}>
          <div className="form-group">
            <label className="form-label">Full Name</label>
            <input
              type="text"
              className="form-control"
              name="full_name"
              value={profile.full_name}
              onChange={handleProfileChange}
              disabled={loading.profile}
            />
          </div>
          <div className="form-group">
            <label className="form-label">Username</label>
            <input
              type="text"
              className="form-control"
              value={user?.username || ''}
              disabled
            />
            <div className="form-text">Username cannot be changed</div>
          </div>
          <div className="form-group">
            <label className="form-label">Email</label>
            <input
              type="email"
              className="form-control"
              value={user?.email || ''}
              disabled
            />
            <div className="form-text">Email cannot be changed</div>
          </div>
          <div className="form-group">
            <label className="form-label">Bio</label>
            <textarea
              className="form-control"
              name="bio"
              rows="2"
              value={profile.bio}
              onChange={handleProfileChange}
              disabled={loading.profile}
            />
          </div>
          <button type="submit" className="btn-save" disabled={loading.profile}>
            {loading.profile ? (
              <><i className="fas fa-spinner fa-spin"></i> Saving...</>
            ) : (
              <><i className="fas fa-save"></i> Save Profile</>
            )}
          </button>
        </form>
      </div>

      {/* Preferences Section */}
      <div className="settings-section">
        <h4><i className="fas fa-sliders-h"></i> Preferences</h4>
        <form onSubmit={handleProfileSubmit}>
          <div className="form-group">
            <label className="form-label">Theme</label>
            <select
              className="form-control"
              name="theme"
              value={profile.theme}
              onChange={handleProfileChange}
              disabled={loading.profile}
            >
              <option value="dark">Dark</option>
              <option value="light">Light</option>
            </select>
          </div>
          <div className="form-check mb-2">
            <input
              type="checkbox"
              className="form-check-input"
              id="notifications"
              name="notifications_enabled"
              checked={profile.notifications_enabled}
              onChange={handleProfileChange}
              disabled={loading.profile}
            />
            <label className="form-check-label" htmlFor="notifications">
              Enable notifications
            </label>
          </div>
          <div className="form-check mb-2">
            <input
              type="checkbox"
              className="form-check-input"
              id="marketing"
              name="marketing_emails"
              checked={profile.marketing_emails}
              onChange={handleProfileChange}
              disabled={loading.profile}
            />
            <label className="form-check-label" htmlFor="marketing">
              Receive marketing emails
            </label>
          </div>
          <button type="submit" className="btn-save" disabled={loading.profile}>
            {loading.profile ? (
              <><i className="fas fa-spinner fa-spin"></i> Saving...</>
            ) : (
              <><i className="fas fa-save"></i> Save Preferences</>
            )}
          </button>
        </form>
      </div>

      {/* Security Section */}
      <div className="settings-section">
        <h4><i className="fas fa-shield-halved"></i> Security</h4>
        <form onSubmit={handlePasswordSubmit}>
          <div className="form-group">
            <label className="form-label">Current Password</label>
            <input
              type="password"
              className="form-control"
              name="current"
              placeholder="Enter current password"
              value={passwords.current}
              onChange={handlePasswordChange}
              disabled={loading.password}
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">New Password</label>
            <input
              type="password"
              className="form-control"
              name="new"
              placeholder="Enter new password"
              value={passwords.new}
              onChange={handlePasswordChange}
              disabled={loading.password}
              required
            />
            <div className="form-text">Minimum 8 characters with uppercase, lowercase, and numbers</div>
          </div>
          <div className="form-group">
            <label className="form-label">Confirm New Password</label>
            <input
              type="password"
              className="form-control"
              name="confirm"
              placeholder="Confirm new password"
              value={passwords.confirm}
              onChange={handlePasswordChange}
              disabled={loading.password}
              required
            />
          </div>
          <button type="submit" className="btn-save" disabled={loading.password}>
            {loading.password ? (
              <><i className="fas fa-spinner fa-spin"></i> Changing...</>
            ) : (
              <><i className="fas fa-key"></i> Change Password</>
            )}
          </button>
        </form>
      </div>

      {/* Account Section */}
      <div className="settings-section">
        <h4><i className="fas fa-user-circle"></i> Account</h4>
        <div className="security-info mb-3">
          <div className="item">
            <span className="label">Plan: </span>
            <span className="value">{user?.plan?.charAt(0).toUpperCase() + user?.plan?.slice(1) || 'Free'}</span>
          </div>
          <div className="item">
            <span className="label">Member since: </span>
            <span className="value">
              {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
            </span>
          </div>
          <div className="item">
            <span className="label">Total scans: </span>
            <span className="value">{user?.total_scans || 0}</span>
          </div>
        </div>
        <div className="account-actions">
          <button className="btn-logout" onClick={handleLogout}>
            <i className="fas fa-sign-out-alt"></i> Logout
          </button>
          <button 
            className="btn-danger-outline" 
            onClick={handleDeleteAccount}
            disabled={loading.delete}
          >
            {loading.delete ? (
              <><i className="fas fa-spinner fa-spin"></i> Deleting...</>
            ) : (
              <><i className="fas fa-trash"></i> Delete Account</>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default Settings;
