# -*- coding: utf-8 -*-

"""
WebShield Scanner - Authentication Tests
Tests for user registration, login, and authentication endpoints.
"""

import json
import pytest
from datetime import datetime, timedelta
from flask_jwt_extended import create_access_token
from app.models.user import User
from app.models.audit_log import AuditLog
from extensions import db


class TestAuth:
    """Test authentication endpoints."""

    def test_register_success(self, client, db_session):
        """Test successful user registration."""
        response = client.post('/api/auth/register', json={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'TestPass123!',
            'full_name': 'Test User'
        })

        assert response.status_code == 201
        data = response.get_json()
        assert data['success'] is True
        assert data['user']['username'] == 'testuser'
        assert data['user']['email'] == 'test@example.com'
        assert 'access_token' in data

        # Verify user was created in database
        user = User.query.filter_by(email='test@example.com').first()
        assert user is not None
        assert user.username == 'testuser'
        assert user.plan == 'free'

    def test_register_duplicate_email(self, client, db_session, test_user):
        """Test registration with duplicate email."""
        response = client.post('/api/auth/register', json={
            'username': 'newuser',
            'email': test_user.email,
            'password': 'TestPass123!'
        })

        assert response.status_code == 409
        data = response.get_json()
        assert data['success'] is False
        assert 'email already' in data['message'].lower()

    def test_register_duplicate_username(self, client, db_session, test_user):
        """Test registration with duplicate username."""
        response = client.post('/api/auth/register', json={
            'username': test_user.username,
            'email': 'new@example.com',
            'password': 'TestPass123!'
        })

        assert response.status_code == 409
        data = response.get_json()
        assert data['success'] is False
        assert 'username already' in data['message'].lower()

    def test_register_invalid_email(self, client, db_session):
        """Test registration with invalid email."""
        response = client.post('/api/auth/register', json={
            'username': 'testuser',
            'email': 'invalid-email',
            'password': 'TestPass123!'
        })

        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
        assert 'valid email' in data['message'].lower()

    def test_register_weak_password(self, client, db_session):
        """Test registration with weak password."""
        response = client.post('/api/auth/register', json={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'weak'
        })

        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
        assert 'password' in data['message'].lower()

    def test_login_success(self, client, db_session, test_user):
        """Test successful login with email."""
        response = client.post('/api/auth/login', json={
            'email_or_username': test_user.email,
            'password': 'TestPass123!'
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['user']['id'] == test_user.id
        assert data['user']['username'] == test_user.username
        assert 'access_token' in data
        assert 'refresh_token' in data

    def test_login_with_username(self, client, db_session, test_user):
        """Test successful login with username."""
        response = client.post('/api/auth/login', json={
            'email_or_username': test_user.username,
            'password': 'TestPass123!'
        })

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['user']['id'] == test_user.id

    def test_login_invalid_credentials(self, client, db_session, test_user):
        """Test login with invalid credentials."""
        response = client.post('/api/auth/login', json={
            'email_or_username': test_user.email,
            'password': 'WrongPassword'
        })

        assert response.status_code == 401
        data = response.get_json()
        assert data['success'] is False
        assert 'invalid' in data['message'].lower()

    def test_login_nonexistent_user(self, client, db_session):
        """Test login with nonexistent user."""
        response = client.post('/api/auth/login', json={
            'email_or_username': 'nonexistent@example.com',
            'password': 'TestPass123!'
        })

        assert response.status_code == 401
        data = response.get_json()
        assert data['success'] is False
        assert 'invalid' in data['message'].lower()

    def test_login_account_locked(self, client, db_session, test_user):
        """Test login with locked account."""
        # Simulate 5 failed login attempts
        for _ in range(5):
            client.post('/api/auth/login', json={
                'email_or_username': test_user.email,
                'password': 'WrongPassword'
            })

        # Try again with correct password
        response = client.post('/api/auth/login', json={
            'email_or_username': test_user.email,
            'password': 'TestPass123!'
        })

        assert response.status_code == 403
        data = response.get_json()
        assert data['success'] is False
        assert 'locked' in data['message'].lower()

    def test_logout(self, client, db_session, auth_headers):
        """Test user logout."""
        response = client.post('/api/auth/logout', headers=auth_headers)

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

        # Verify audit log entry
        log = AuditLog.query.filter_by(action='logout').first()
        assert log is not None

    def test_get_current_user(self, client, db_session, auth_headers, test_user):
        """Test getting current user information."""
        response = client.get('/api/auth/me', headers=auth_headers)

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['user']['id'] == test_user.id
        assert data['user']['username'] == test_user.username
        assert data['user']['email'] == test_user.email

    def test_change_password_success(self, client, db_session, auth_headers, test_user):
        """Test successful password change."""
        response = client.post('/api/auth/change-password', 
            headers=auth_headers,
            json={
                'current_password': 'TestPass123!',
                'new_password': 'NewPass456!'
            })

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

        # Verify password was changed
        db.session.refresh(test_user)
        assert test_user.check_password('NewPass456!') is True

    def test_change_password_wrong_current(self, client, db_session, auth_headers, test_user):
        """Test password change with wrong current password."""
        response = client.post('/api/auth/change-password',
            headers=auth_headers,
            json={
                'current_password': 'WrongPassword',
                'new_password': 'NewPass456!'
            })

        assert response.status_code == 401
        data = response.get_json()
        assert data['success'] is False
        assert 'incorrect' in data['message'].lower()

    def test_change_password_weak(self, client, db_session, auth_headers, test_user):
        """Test password change with weak new password."""
        response = client.post('/api/auth/change-password',
            headers=auth_headers,
            json={
                'current_password': 'TestPass123!',
                'new_password': 'weak'
            })

        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
        assert 'password' in data['message'].lower()

    def test_refresh_token(self, client, db_session, test_user):
        """Test refreshing access token."""
        # Login to get refresh token
        login_response = client.post('/api/auth/login', json={
            'email_or_username': test_user.email,
            'password': 'TestPass123!'
        })
        refresh_token = login_response.get_json()['refresh_token']

        response = client.post('/api/auth/refresh', 
            headers={'Authorization': f'Bearer {refresh_token}'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'access_token' in data
        assert data['access_token'] != login_response.get_json()['access_token']

    def test_refresh_token_from_cookie(self, client, db_session, test_user):
        """Test refreshing access token from the httpOnly refresh cookie."""
        login_response = client.post('/api/auth/login', json={
            'email_or_username': test_user.email,
            'password': 'TestPass123!'
        })
        assert login_response.status_code == 200

        response = client.post('/api/auth/refresh')

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'access_token' in data
