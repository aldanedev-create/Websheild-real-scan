# -*- coding: utf-8 -*-

"""
WebShield Scanner - Authentication Routes
Handles user registration, login, logout, and account management.
"""

import re
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app, make_response
from flask_login import login_user, logout_user, login_required, current_user
from flask_jwt_extended import (
    create_access_token, create_refresh_token, 
    jwt_required, verify_jwt_in_request, get_jwt_identity, get_jwt, decode_token
)
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db, limiter, mail
from app.models.user import User
from app.models.audit_log import AuditLog
from app.utils.validators import validate_email, validate_password, validate_username
from app.services.auth_service import AuthService

auth_bp = Blueprint('auth', __name__)


REFRESH_COOKIE_NAME = 'webshield_refresh_token'


def _refresh_cookie_max_age(remember=False):
    if not remember:
        return None
    expires = current_app.config.get('JWT_REFRESH_TOKEN_EXPIRES')
    if hasattr(expires, 'total_seconds'):
        return int(expires.total_seconds())
    try:
        return int(expires)
    except (TypeError, ValueError):
        return 60 * 60 * 24 * 30


def _set_refresh_cookie(response, refresh_token, remember=False):
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        refresh_token,
        max_age=_refresh_cookie_max_age(remember),
        httponly=True,
        secure=current_app.config.get('SESSION_COOKIE_SECURE', True),
        samesite=current_app.config.get('SESSION_COOKIE_SAMESITE', 'Lax') or 'Lax',
        path='/api/auth/refresh',
    )
    return response


def _clear_refresh_cookie(response):
    response.delete_cookie(REFRESH_COOKIE_NAME, path='/api/auth/refresh')
    return response


def _refresh_identity_from_header_or_cookie():
    try:
        verify_jwt_in_request(refresh=True)
        return get_jwt_identity()
    except Exception:
        refresh_token = request.cookies.get(REFRESH_COOKIE_NAME)
        if not refresh_token:
            raise ValueError('missing_refresh_token')
        decoded = decode_token(refresh_token)
        if decoded.get('type') != 'refresh':
            raise ValueError('invalid_refresh_token')
        return decoded.get('sub')


@auth_bp.route('/register', methods=['POST'])
@limiter.limit('5 per hour')
def register():
    """
    Register a new user account.
    
    Request body:
        username: str
        email: str
        password: str
        full_name: str (optional)
    
    Returns:
        User data with access token
    """
    try:
        data = request.get_json(silent=True) or {}
        
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'error': 'missing_field',
                    'message': f'{field} is required'
                }), 400
        
        username = data['username'].strip()
        email = data['email'].strip().lower()
        password = data['password']
        full_name = data.get('full_name', '').strip()
        
        # Validate username
        if not validate_username(username):
            return jsonify({
                'error': 'invalid_username',
                'message': 'Username must be 3-30 characters, alphanumeric with underscores'
            }), 400
        
        # Validate email
        if not validate_email(email):
            return jsonify({
                'error': 'invalid_email',
                'message': 'Please provide a valid email address'
            }), 400
        
        # Validate password
        if not validate_password(password):
            return jsonify({
                'error': 'invalid_password',
                'message': 'Password must be at least 8 characters and use at least 3 of: uppercase, lowercase, number, or symbol'
            }), 400
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            return jsonify({
                'error': 'username_taken',
                'message': 'Username already taken'
            }), 409
        
        if User.query.filter_by(email=email).first():
            return jsonify({
                'error': 'email_taken',
                'message': 'Email already registered'
            }), 409
        
        # Create user
        remember = bool(data.get('remember', False))

        user = User(
            username=username,
            email=email,
            full_name=full_name,
            password=password
        )
        
        db.session.add(user)
        db.session.commit()
        login_user(user, remember=remember)
        
        # Log registration
        AuditLog.log(
            user_id=user.id,
            action='register',
            details=f'User registered with email {email}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        # Create access token
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        response = make_response(jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 201)
        return _set_refresh_cookie(response, refresh_token, remember)
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Registration error: {str(e)}')
        return jsonify({
            'error': 'registration_failed',
            'message': 'Could not create account'
        }), 500


@auth_bp.route('/login', methods=['POST'])
@limiter.limit('10 per minute')
def login():
    """
    Authenticate user and return access token.
    
    Request body:
        email_or_username: str
        password: str
        remember: bool (optional)
    
    Returns:
        User data with access token
    """
    try:
        data = request.get_json(silent=True) or {}
        
        if not data.get('email_or_username') or not data.get('password'):
            return jsonify({
                'error': 'missing_credentials',
                'message': 'Email/username and password are required'
            }), 400
        
        identifier = data['email_or_username'].strip()
        password = data['password']
        remember = data.get('remember', False)
        
        # Find user by email or username
        user = User.query.filter(
            (User.email == identifier.lower()) | (User.username == identifier.lower())
        ).first()
        
        if not user:
            return jsonify({
                'error': 'invalid_credentials',
                'message': 'Invalid email/username or password'
            }), 401
        
        # Check if account is locked
        if user.is_locked():
            return jsonify({
                'error': 'account_locked',
                'message': 'Account temporarily locked due to too many failed attempts. Try again later.'
            }), 403
        
        # Check password
        if not user.check_password(password):
            user.increment_login_attempts()
            db.session.commit()
            return jsonify({
                'error': 'invalid_credentials',
                'message': 'Invalid email/username or password'
            }), 401
        
        # Check if account is active
        if not user.is_active:
            return jsonify({
                'error': 'account_inactive',
                'message': 'Account is deactivated. Please contact support.'
            }), 403
        
        # Record successful login
        user.record_login(request.remote_addr)
        db.session.commit()
        login_user(user, remember=remember)
        
        # Log login
        AuditLog.log(
            user_id=user.id,
            action='login',
            details=f'User logged in from {request.remote_addr}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        # Create tokens
        access_token = create_access_token(
            identity=user.id,
            expires_delta=timedelta(days=7 if remember else 1)
        )
        refresh_token = create_refresh_token(identity=user.id)
        
        response = make_response(jsonify({
            'success': True,
            'message': 'Login successful',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token,
            'is_premium': user.is_premium()
        }), 200)
        return _set_refresh_cookie(response, refresh_token, remember)
        
    except Exception as e:
        current_app.logger.error(f'Login error: {str(e)}')
        return jsonify({
            'error': 'login_failed',
            'message': 'Could not log in'
        }), 500


@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Logout user and invalidate tokens."""
    try:
        user_id = current_user.id if current_user.is_authenticated else None
        verify_jwt_in_request(optional=True)
        user_id = user_id or get_jwt_identity()

        if current_user.is_authenticated:
            logout_user()
        
        # Log logout
        if user_id:
            AuditLog.log(
                user_id=user_id,
                action='logout',
                details='User logged out',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
        
        response = make_response(jsonify({
            'success': True,
            'message': 'Logout successful'
        }), 200)
        return _clear_refresh_cookie(response)
        
    except Exception as e:
        current_app.logger.error(f'Logout error: {str(e)}')
        return jsonify({
            'error': 'logout_failed',
            'message': 'Could not log out'
        }), 500


@auth_bp.route('/refresh', methods=['POST'])
def refresh_token():
    """Refresh access token using refresh token."""
    try:
        try:
            user_id = _refresh_identity_from_header_or_cookie()
        except Exception:
            return jsonify({
                'error': 'invalid_refresh',
                'message': 'Refresh token is missing or invalid'
            }), 401

        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        if not user.is_active:
            return jsonify({
                'error': 'account_inactive',
                'message': 'Account is deactivated'
            }), 403
        
        new_access_token = create_access_token(identity=user.id)
        
        return jsonify({
            'success': True,
            'access_token': new_access_token
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Token refresh error: {str(e)}')
        return jsonify({
            'error': 'refresh_failed',
            'message': 'Could not refresh token'
        }), 500


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current authenticated user."""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        return jsonify({
            'success': True,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get user error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch user data'
        }), 500


@auth_bp.route('/me', methods=['PUT'])
@jwt_required()
def update_current_user():
    """Update current user profile."""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        data = request.get_json(silent=True) or {}
        
        # Update supported profile fields. English is the only application
        # language, so clients cannot switch the language setting.
        allowed_fields = [
            'full_name',
            'bio',
            'theme',
            'notifications_enabled',
            'marketing_emails',
        ]
        
        for field in allowed_fields:
            if field in data:
                value = data[field]
                if field == 'theme' and value not in {'dark', 'light'}:
                    return jsonify({
                        'error': 'invalid_theme',
                        'message': 'Theme must be dark or light'
                    }), 400
                if field in {'notifications_enabled', 'marketing_emails'} and not isinstance(value, bool):
                    return jsonify({
                        'error': 'invalid_preference',
                        'message': f'{field} must be true or false'
                    }), 400
                if field in {'full_name', 'bio'}:
                    if not isinstance(value, str):
                        return jsonify({
                            'error': 'invalid_profile_value',
                            'message': f'{field} must be text'
                        }), 400
                    value = value.strip()
                setattr(user, field, value)

        user.language = 'en'
        
        db.session.commit()
        
        # Log update
        AuditLog.log(
            user_id=user.id,
            action='profile_updated',
            details='User updated profile',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Update user error: {str(e)}')
        return jsonify({
            'error': 'update_failed',
            'message': 'Could not update profile'
        }), 500


@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change user password."""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        data = request.get_json(silent=True) or {}
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({
                'error': 'missing_fields',
                'message': 'Current password and new password are required'
            }), 400
        
        # Verify current password
        if not user.check_password(current_password):
            return jsonify({
                'error': 'invalid_password',
                'message': 'Current password is incorrect'
            }), 401
        
        # Validate new password
        if not validate_password(new_password):
            return jsonify({
                'error': 'invalid_password',
                'message': 'Password must be at least 8 characters and use at least 3 of: uppercase, lowercase, number, or symbol'
            }), 400
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        # Log password change
        AuditLog.log(
            user_id=user.id,
            action='password_changed',
            details='User changed password',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            severity='warning'
        )
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Change password error: {str(e)}')
        return jsonify({
            'error': 'change_failed',
            'message': 'Could not change password'
        }), 500


@auth_bp.route('/forgot-password', methods=['POST'])
@limiter.limit('3 per hour')
def forgot_password():
    """
    Request password reset.
    
    Request body:
        email: str
    """
    try:
        data = request.get_json(silent=True) or {}
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({
                'error': 'missing_email',
                'message': 'Email is required'
            }), 400
        
        user = User.query.filter_by(email=email).first()
        
        # Always return success even if user not found (security through obscurity)
        # In production, this would send a reset email
        if user:
            # Generate reset token and send email
            # For now, just log it
            AuditLog.log(
                user_id=user.id,
                action='password_reset_requested',
                details=f'Password reset requested for {email}',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                severity='warning'
            )
        
        return jsonify({
            'success': True,
            'message': 'If an account exists with this email, a password reset link will be sent.'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Forgot password error: {str(e)}')
        return jsonify({
            'error': 'request_failed',
            'message': 'Could not process password reset request'
        }), 500


@auth_bp.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    """Verify user email using token."""
    try:
        # In production, decode token and verify user
        # For now, return success
        return jsonify({
            'success': True,
            'message': 'Email verified successfully'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Verify email error: {str(e)}')
        return jsonify({
            'error': 'verification_failed',
            'message': 'Could not verify email'
        }), 500
