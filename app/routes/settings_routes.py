# -*- coding: utf-8 -*-

"""
WebShield Scanner - Settings Routes
Manages user settings and preferences.
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.utils.validators import validate_email, validate_username

settings_bp = Blueprint('settings', __name__)


@settings_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get user profile settings."""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        # English is the only supported application language.
        if user.language != 'en':
            user.language = 'en'
            db.session.commit()

        return jsonify({
            'success': True,
            'profile': {
                'username': user.username,
                'email': user.email,
                'full_name': user.full_name,
                'bio': user.bio,
                'avatar_url': user.avatar_url,
                'theme': user.theme,
                'language': 'en',
                'notifications_enabled': user.notifications_enabled,
                'marketing_emails': user.marketing_emails
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get profile error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch profile'
        }), 500


@settings_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """Update user profile settings."""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        data = request.get_json(silent=True) or {}
        
        # Update allowed fields
        allowed_fields = [
            'full_name',
            'bio',
            'theme',
            'notifications_enabled',
            'marketing_emails',
        ]

        changes = []
        for field in allowed_fields:
            if field in data:
                old_value = getattr(user, field)
                new_value = data[field]

                if field == 'theme' and new_value not in {'dark', 'light'}:
                    return jsonify({
                        'error': 'invalid_theme',
                        'message': 'Theme must be dark or light'
                    }), 400

                if field in {'notifications_enabled', 'marketing_emails'} and not isinstance(new_value, bool):
                    return jsonify({
                        'error': 'invalid_preference',
                        'message': f'{field} must be true or false'
                    }), 400

                if field in {'full_name', 'bio'} and not isinstance(new_value, str):
                    return jsonify({
                        'error': 'invalid_profile_value',
                        'message': f'{field} must be text'
                    }), 400

                if field == 'full_name' and len(new_value.strip()) > 150:
                    return jsonify({
                        'error': 'invalid_full_name',
                        'message': 'Full name is too long'
                    }), 400

                if field == 'bio' and len(new_value) > 5000:
                    return jsonify({
                        'error': 'invalid_bio',
                        'message': 'Bio is too long'
                    }), 400

                if field in {'full_name', 'bio'}:
                    new_value = new_value.strip()

                if old_value != new_value:
                    setattr(user, field, new_value)
                    changes.append(f'{field}: {old_value} -> {new_value}')

        user.language = 'en'
        
        db.session.commit()
        
        if changes:
            AuditLog.log(
                user_id=user.id,
                action='settings_updated',
                details=f'Updated settings: {", ".join(changes)}',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'profile': {
                'username': user.username,
                'email': user.email,
                'full_name': user.full_name,
                'bio': user.bio,
                'avatar_url': user.avatar_url,
                'theme': user.theme,
                'language': 'en',
                'notifications_enabled': user.notifications_enabled,
                'marketing_emails': user.marketing_emails
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Update profile error: {str(e)}')
        return jsonify({
            'error': 'update_failed',
            'message': 'Could not update profile'
        }), 500


@settings_bp.route('/email', methods=['PUT'])
@jwt_required()
def update_email():
    """Update user email address."""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        data = request.get_json(silent=True) or {}
        new_email = data.get('email', '').strip().lower()
        password = data.get('password')
        
        if not new_email or not password:
            return jsonify({
                'error': 'missing_fields',
                'message': 'Email and password are required'
            }), 400
        
        # Verify password
        if not user.check_password(password):
            return jsonify({
                'error': 'invalid_password',
                'message': 'Invalid password'
            }), 401
        
        # Validate email
        if not validate_email(new_email):
            return jsonify({
                'error': 'invalid_email',
                'message': 'Please provide a valid email address'
            }), 400
        
        # Check if email is taken
        existing = User.query.filter_by(email=new_email).first()
        if existing and existing.id != user.id:
            return jsonify({
                'error': 'email_taken',
                'message': 'Email already registered'
            }), 409
        
        old_email = user.email
        user.email = new_email
        
        db.session.commit()
        
        AuditLog.log(
            user_id=user.id,
            action='email_changed',
            details=f'Changed email from {old_email} to {new_email}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            severity='warning'
        )
        
        return jsonify({
            'success': True,
            'message': 'Email updated successfully',
            'email': new_email
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Update email error: {str(e)}')
        return jsonify({
            'error': 'update_failed',
            'message': 'Could not update email'
        }), 500


@settings_bp.route('/username', methods=['PUT'])
@jwt_required()
def update_username():
    """Update username."""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        data = request.get_json(silent=True) or {}
        new_username = data.get('username', '').strip()
        
        if not new_username:
            return jsonify({
                'error': 'missing_username',
                'message': 'Username is required'
            }), 400
        
        # Validate username
        if not validate_username(new_username):
            return jsonify({
                'error': 'invalid_username',
                'message': 'Username must be 3-30 characters, alphanumeric with underscores'
            }), 400
        
        # Check if username is taken
        existing = User.query.filter_by(username=new_username).first()
        if existing and existing.id != user.id:
            return jsonify({
                'error': 'username_taken',
                'message': 'Username already taken'
            }), 409
        
        old_username = user.username
        user.username = new_username
        
        db.session.commit()
        
        AuditLog.log(
            user_id=user.id,
            action='username_changed',
            details=f'Changed username from {old_username} to {new_username}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'message': 'Username updated successfully',
            'username': new_username
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Update username error: {str(e)}')
        return jsonify({
            'error': 'update_failed',
            'message': 'Could not update username'
        }), 500


@settings_bp.route('/delete-account', methods=['POST'])
@jwt_required()
def delete_account():
    """Delete user account."""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        data = request.get_json(silent=True) or {}
        password = data.get('password')
        confirm = data.get('confirm', False)
        
        if not password:
            return jsonify({
                'error': 'missing_password',
                'message': 'Password is required to confirm account deletion'
            }), 400
        
        if not confirm:
            return jsonify({
                'error': 'confirmation_required',
                'message': 'Please confirm account deletion'
            }), 400
        
        # Verify password
        if not user.check_password(password):
            return jsonify({
                'error': 'invalid_password',
                'message': 'Invalid password'
            }), 401
        
        # Log deletion before deleting
        AuditLog.log(
            user_id=user.id,
            action='account_deleted',
            details=f'User account deleted',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            severity='critical'
        )
        
        # Delete user (cascading will delete related records)
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Account deleted successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Delete account error: {str(e)}')
        return jsonify({
            'error': 'delete_failed',
            'message': 'Could not delete account'
        }), 500


@settings_bp.route('/security', methods=['GET'])
@jwt_required()
def get_security_settings():
    """Get security-related settings."""
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
            'security': {
                'two_factor_enabled': False,
                'last_login_ip': user.last_login_ip,
                'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None,
                'login_attempts': user.login_attempts,
                'is_locked': user.is_locked(),
                'email_verified': user.email_verified
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get security settings error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch security settings'
        }), 500
