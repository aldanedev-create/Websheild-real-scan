import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { authApi } from '../api/authApi.js';
import { setToken, setUser } from '../api/client.js';
import '../styles/global.css';

const Register = ({ onLogin }) => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    full_name: '',
    password: '',
    confirm_password: '',
    terms: false
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [passwordStrength, setPasswordStrength] = useState({ score: 0, text: 'Weak', color: '#f44336' });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [passwordMatch, setPasswordMatch] = useState(true);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
    setError('');

    // Password strength check
    if (name === 'password') {
      checkPasswordStrength(value);
    }

    // Password match check
    if (name === 'password' || name === 'confirm_password') {
      const pass = name === 'password' ? value : formData.password;
      const confirm = name === 'confirm_password' ? value : formData.confirm_password;
      setPasswordMatch(pass === confirm || !confirm);
    }
  };

  const checkPasswordStrength = (password) => {
    let score = 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;

    let text, color;
    if (score < 2) { text = 'Weak'; color = '#f44336'; }
    else if (score < 4) { text = 'Fair'; color = '#ff9800'; }
    else if (score < 6) { text = 'Good'; color = '#ffc107'; }
    else { text = 'Strong'; color = '#4caf50'; }

    setPasswordStrength({ score, text, color });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    // Validate
    if (formData.password !== formData.confirm_password) {
      setError('Passwords do not match.');
      setLoading(false);
      return;
    }

    if (passwordStrength.score < 3) {
      setError('Password is too weak. Please use a stronger password.');
      setLoading(false);
      return;
    }

    if (!formData.terms) {
      setError('You must agree to the Terms of Service and Privacy Policy.');
      setLoading(false);
      return;
    }

    try {
      const response = await authApi.register(
        formData.username,
        formData.email,
        formData.password,
        formData.full_name
      );

      if (response.success) {
        setToken(response.access_token);
        setUser(response.user);
        onLogin(response.user, response.access_token);
        navigate('/dashboard');
      } else {
        setError(response.message || 'Registration failed. Please try again.');
      }
    } catch (err) {
      setError(err.message || 'An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-container">
        <div className="auth-logo">
          <div className="auth-logo-text">WebShield</div>
          <div className="auth-logo-subtitle">Security Scanner</div>
        </div>

        <div className="auth-form">
          <h2 className="auth-title">Create Account</h2>
          <p className="auth-subtitle">Start securing your web applications today</p>

          {error && (
            <div className="alert alert-danger alert-dismissible fade show" role="alert">
              <i className="fas fa-exclamation-circle me-2"></i>
              {error}
              <button type="button" className="btn-close" onClick={() => setError('')}></button>
            </div>
          )}

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">
                <i className="fas fa-user"></i> Username
              </label>
              <input
                type="text"
                className="form-control"
                name="username"
                placeholder="Choose a username"
                value={formData.username}
                onChange={handleChange}
                required
                autoFocus
              />
              <div className="form-text">3-30 characters, alphanumeric with underscores</div>
            </div>

            <div className="form-group">
              <label className="form-label">
                <i className="fas fa-envelope"></i> Email Address
              </label>
              <input
                type="email"
                className="form-control"
                name="email"
                placeholder="Enter your email address"
                value={formData.email}
                onChange={handleChange}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">
                <i className="fas fa-user-circle"></i> Full Name (Optional)
              </label>
              <input
                type="text"
                className="form-control"
                name="full_name"
                placeholder="Enter your full name"
                value={formData.full_name}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label className="form-label">
                <i className="fas fa-lock"></i> Password
              </label>
              <div className="password-input-wrapper">
                <input
                  type={showPassword ? 'text' : 'password'}
                  className="form-control"
                  name="password"
                  placeholder="Create a strong password"
                  value={formData.password}
                  onChange={handleChange}
                  required
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  <i className={`fas ${showPassword ? 'fa-eye-slash' : 'fa-eye'}`}></i>
                </button>
              </div>
              <div className="password-strength mt-1">
                <div className="strength-bar">
                  <div 
                    className="fill" 
                    style={{ 
                      width: `${(passwordStrength.score / 6) * 100}%`,
                      background: passwordStrength.color
                    }}
                  ></div>
                </div>
                <div className="strength-text">
                  Password strength: <span style={{ color: passwordStrength.color, fontWeight: '600' }}>
                    {passwordStrength.text}
                  </span>
                </div>
              </div>
              <div className="form-text">Minimum 8 characters with uppercase, lowercase, and numbers</div>
            </div>

            <div className="form-group">
              <label className="form-label">
                <i className="fas fa-check-circle"></i> Confirm Password
              </label>
              <div className="password-input-wrapper">
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  className="form-control"
                  name="confirm_password"
                  placeholder="Confirm your password"
                  value={formData.confirm_password}
                  onChange={handleChange}
                  required
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                >
                  <i className={`fas ${showConfirmPassword ? 'fa-eye-slash' : 'fa-eye'}`}></i>
                </button>
              </div>
              {formData.confirm_password && (
                <div className={`form-text ${passwordMatch ? 'text-success' : 'text-danger'}`}>
                  {passwordMatch ? '✓ Passwords match' : '✗ Passwords do not match'}
                </div>
              )}
            </div>

            <div className="form-group">
              <div className="form-check">
                <input
                  type="checkbox"
                  className="form-check-input"
                  id="terms"
                  name="terms"
                  checked={formData.terms}
                  onChange={handleChange}
                  required
                />
                <label className="form-check-label" htmlFor="terms">
                  I agree to the <Link to="/terms" target="_blank" rel="noopener noreferrer">Terms of Service</Link> and <Link to="/privacy" target="_blank" rel="noopener noreferrer">Privacy Policy</Link>
                </label>
              </div>
            </div>

            <button
              type="submit"
              className="btn btn-primary btn-auth"
              disabled={loading}
            >
              {loading ? (
                <><i className="fas fa-spinner fa-spin"></i> Creating account...</>
              ) : (
                <><i className="fas fa-user-plus"></i> Create Account</>
              )}
            </button>
          </form>

          <div className="auth-divider">
            <span>or</span>
          </div>

          <div className="auth-footer-link">
            Already have an account? <Link to="/login">Sign In</Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;
