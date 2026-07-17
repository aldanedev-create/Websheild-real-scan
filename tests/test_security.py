# -*- coding: utf-8 -*-

"""
WebShield Scanner - Security Tests
Tests for security controls, rate limiting, and access control.
"""

import json
import pytest
from flask_jwt_extended import create_access_token
from app.models.user import User
from app.models.audit_log import AuditLog
from app.security.rate_limit import RateLimiter
from app.security.password import PasswordPolicy
from app.security.csrf import CSRFProtection


class TestSecurity:
    """Test security controls."""

    def test_password_policy_valid(self):
        """Test valid password passes policy."""
        valid, error = PasswordPolicy.validate_password('TestPass123!')
        assert valid is True
        assert error is None

    def test_password_policy_too_short(self):
        """Test password too short."""
        valid, error = PasswordPolicy.validate_password('Tp1!')
        assert valid is False
        assert 'at least 8 characters' in error

    def test_password_policy_no_uppercase(self):
        """Test password with no uppercase."""
        valid, error = PasswordPolicy.validate_password('testpass123!')
        assert valid is False
        assert 'uppercase' in error

    def test_password_policy_no_lowercase(self):
        """Test password with no lowercase."""
        valid, error = PasswordPolicy.validate_password('TESTPASS123!')
        assert valid is False
        assert 'lowercase' in error

    def test_password_policy_no_digit(self):
        """Test password with no digit."""
        valid, error = PasswordPolicy.validate_password('TestPass!')
        assert valid is False
        assert 'number' in error

    def test_password_policy_no_special(self):
        """Test password with no special character."""
        valid, error = PasswordPolicy.validate_password('TestPass123')
        assert valid is False
        assert 'special' in error

    def test_password_policy_common_password(self):
        """Test common password is rejected."""
        valid, error = PasswordPolicy.validate_password('password123')
        assert valid is False
        assert 'common' in error

    def test_password_strength_scoring(self):
        """Test password strength scoring."""
        # Weak password
        weak = PasswordPolicy.get_password_strength('pass')
        assert weak['strength'] == 'weak'
        assert weak['level'] == 1

        # Strong password
        strong = PasswordPolicy.get_password_strength('TestPass123!@#')
        assert strong['strength'] == 'strong'
        assert strong['level'] == 4

    def test_rate_limiter(self):
        """Test rate limiter functionality."""
        limiter = RateLimiter()
        client_id = 'test_client'
        action = 'test_action'

        # Should allow up to limit
        for i in range(5):
            allowed, remaining, reset = limiter.check_rate_limit(client_id, action, 5, 60)
            assert allowed is True
            assert remaining == 5 - i - 1

        # Should block when limit exceeded
        allowed, remaining, reset = limiter.check_rate_limit(client_id, action, 5, 60)
        assert allowed is False
        assert remaining == 0

    def test_rate_limiter_reset(self):
        """Test rate limiter reset."""
        limiter = RateLimiter()
        client_id = 'test_client'
        action = 'test_action'

        # Use all limits
        for _ in range(5):
            limiter.check_rate_limit(client_id, action, 5, 60)

        # Reset
        limiter.reset_rate_limit(client_id, action)

        # Should allow again
        allowed, remaining, reset = limiter.check_rate_limit(client_id, action, 5, 60)
        assert allowed is True

    def test_csrf_token_generation(self):
        """Test CSRF token generation."""
        with pytest.raises(Exception):
            # This test would need session context
            # For now, just check the method exists
            assert hasattr(CSRFProtection, 'generate_token')

    def test_csrf_token_validation(self):
        """Test CSRF token validation."""
        # This would need session context
        # For now, just check the method exists
        assert hasattr(CSRFProtection, 'validate_token')

    def test_jwt_required_decorator(self, client, test_user):
        """Test JWT required decorator on protected endpoint."""
        # Without token
        response = client.get('/api/auth/me')
        assert response.status_code == 401

        # With valid token
        token = create_access_token(identity=test_user.id)
        response = client.get('/api/auth/me',
            headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200

    def test_jwt_expired_token(self, client, test_user):
        """Test expired JWT token."""
        from datetime import timedelta
        token = create_access_token(
            identity=test_user.id,
            expires_delta=timedelta(seconds=-1)  # Already expired
        )

        response = client.get('/api/auth/me',
            headers={'Authorization': f'Bearer {token}'})

        assert response.status_code == 401

    def test_admin_required(self, client, auth_headers, test_user):
        """Test admin required decorator."""
        # Non-admin user trying to access admin endpoint
        response = client.get('/api/admin/dashboard/stats',
            headers=auth_headers)

        assert response.status_code == 403
        data = response.get_json()
        assert data['success'] is False
        assert 'admin' in data['message'].lower()

    def test_admin_required_admin_user(self, client, auth_headers_admin, test_admin_user):
        """Test admin access with admin user."""
        response = client.get('/api/admin/dashboard/stats',
            headers=auth_headers_admin)

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'stats' in data

    def test_audit_logging(self, client, auth_headers, test_user):
        """Test audit logging on actions."""
        # Perform an action that should be logged
        client.get('/api/auth/me', headers=auth_headers)

        # Check audit log
        log = AuditLog.query.filter_by(user_id=test_user.id).first()
        assert log is not None

    def test_rate_limit_decorator(self, client):
        """Test rate limit decorator on endpoints."""
        # Make multiple requests to a rate-limited endpoint
        for i in range(15):  # Assuming limit is 10 per hour
            response = client.post('/api/auth/login', json={
                'email_or_username': 'nonexistent@example.com',
                'password': 'wrong'
            })
            if i >= 10:
                assert response.status_code == 429
                break

    def test_sql_injection_prevention(self, client, auth_headers):
        """Test SQL injection prevention in queries."""
        # Try to inject SQL in a parameter
        response = client.post('/api/scan/validate',
            headers=auth_headers,
            json={'url': "'; DROP TABLE users; --"})

        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False

        # Verify database is intact
        user_count = User.query.count()
        assert user_count > 0

    def test_xss_prevention(self, client, auth_headers):
        """Test XSS prevention in responses."""
        # Try to inject script in registration
        response = client.post('/api/auth/register', json={
            'username': '<script>alert("XSS")</script>',
            'email': 'test@example.com',
            'password': 'TestPass123!'
        })

        # Should reject or sanitize the input
        assert response.status_code == 400 or response.status_code == 409

    def test_private_ip_blocking(self, client, auth_headers):
        """Test private IP blocking."""
        response = client.post('/api/scan/validate',
            headers=auth_headers,
            json={'url': 'http://192.168.1.1'})

        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
        assert 'private' in data['message'].lower()

    def test_localhost_blocking(self, client, auth_headers):
        """Test localhost blocking."""
        response = client.post('/api/scan/validate',
            headers=auth_headers,
            json={'url': 'http://localhost'})

        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
        assert 'localhost' in data['message'].lower() or 'private' in data['message'].lower()

    def test_url_validation_block_suspicious(self, client, auth_headers):
        """Test URL validation blocks suspicious URLs."""
        suspicious_urls = [
            'http://example.com/../../../etc/passwd',
            'http://example.com/%2e%2e/%2e%2e/etc/passwd',
            'http://example.com?redirect=http://evil.com'
        ]

        for url in suspicious_urls:
            response = client.post('/api/scan/validate',
                headers=auth_headers,
                json={'url': url})

            assert response.status_code == 400
            data = response.get_json()
            assert data['success'] is False