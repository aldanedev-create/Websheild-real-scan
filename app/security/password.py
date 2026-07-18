# -*- coding: utf-8 -*-

"""
WebShield Scanner - Authentication Service
Handles user authentication, registration, and authorization logic.
"""

import re
from datetime import datetime, timedelta
from flask import current_app, request
from flask_jwt_extended import create_access_token, create_refresh_token, decode_token
from extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.utils.validators import validate_email, validate_password, validate_username


class AuthService:
    """Service for handling authentication operations."""
    
    @staticmethod
    def register_user(username, email, password, full_name=None):
        """
        Register a new user.
        
        Args:
            username: Username
            email: Email address
            password: Password
            full_name: Full name (optional)
            
        Returns:
            dict: User data and tokens
            
        Raises:
            ValueError: Validation errors
        """
        # Validate inputs
        if not username:
            raise ValueError("Username is required")
        if not email:
            raise ValueError("Email is required")
        if not password:
            raise ValueError("Password is required")
        
        # Validate username
        if not validate_username(username):
            raise ValueError("Username must be 3-30 characters, alphanumeric with underscores")
        
        # Validate email
        if not validate_email(email):
            raise ValueError("Please provide a valid email address")
        
        # Validate password
        if not validate_password(password):
            raise ValueError("Password must be at least 8 characters and use at least 3 of: uppercase, lowercase, number, or symbol")
        
        # Check if user exists
        if User.query.filter_by(username=username.lower()).first():
            raise ValueError("Username already taken")
        
        if User.query.filter_by(email=email.lower()).first():
            raise ValueError("Email already registered")
        
        # Create user
        user = User(
            username=username.lower(),
            email=email.lower(),
            full_name=full_name,
            password=password
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Log registration
        AuditService.log(
            user_id=user.id,
            action='register',
            details=f'User registered with email {email}',
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None
        )
        
        # Generate tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        return {
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }
    
    @staticmethod
    def login_user(identifier, password, remember=False):
        """
        Authenticate and login a user.
        
        Args:
            identifier: Email or username
            password: Password
            remember: Remember me flag
            
        Returns:
            dict: User data and tokens
            
        Raises:
            ValueError: Authentication errors
        """
        if not identifier or not password:
            raise ValueError("Email/username and password are required")
        
        # Find user by email or username
        user = User.query.filter(
            (User.email == identifier.lower()) | (User.username == identifier.lower())
        ).first()
        
        if not user:
            raise ValueError("Invalid credentials")
        
        # Check if account is locked
        if user.is_locked():
            raise ValueError("Account temporarily locked due to too many failed attempts")
        
        # Check password
        if not user.check_password(password):
            user.increment_login_attempts()
            db.session.commit()
            raise ValueError("Invalid credentials")
        
        # Check if account is active
        if not user.is_active:
            raise ValueError("Account is deactivated. Please contact support.")
        
        # Record successful login
        user.record_login(request.remote_addr if request else None)
        db.session.commit()
        
        # Log login
        AuditService.log(
            user_id=user.id,
            action='login',
            details=f'User logged in from {request.remote_addr if request else "unknown"}',
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None
        )
        
        # Generate tokens
        access_token = create_access_token(
            identity=user.id,
            expires_delta=timedelta(days=7 if remember else 1)
        )
        refresh_token = create_refresh_token(identity=user.id)
        
        return {
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token,
            'is_premium': user.is_premium()
        }
    
    @staticmethod
    def logout_user(user_id):
        """
        Logout a user.
        
        Args:
            user_id: User ID
            
        Returns:
            bool: Success status
        """
        AuditService.log(
            user_id=user_id,
            action='logout',
            details='User logged out',
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None
        )
        
        return True
    
    @staticmethod
    def refresh_token(user_id):
        """
        Refresh access token.
        
        Args:
            user_id: User ID
            
        Returns:
            str: New access token
            
        Raises:
            ValueError: User not found
        """
        user = User.query.get(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        if not user.is_active:
            raise ValueError("Account is deactivated")
        
        return create_access_token(identity=user.id)
    
    @staticmethod
    def change_password(user_id, current_password, new_password):
        """
        Change user password.
        
        Args:
            user_id: User ID
            current_password: Current password
            new_password: New password
            
        Returns:
            bool: Success status
            
        Raises:
            ValueError: Validation errors
        """
        user = User.query.get(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        if not current_password or not new_password:
            raise ValueError("Current password and new password are required")
        
        # Verify current password
        if not user.check_password(current_password):
            raise ValueError("Current password is incorrect")
        
        # Validate new password
        if not validate_password(new_password):
            raise ValueError("Password must be at least 8 characters and use at least 3 of: uppercase, lowercase, number, or symbol")
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        # Log password change
        AuditService.log(
            user_id=user.id,
            action='password_changed',
            details='User changed password',
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None,
            severity='warning'
        )
        
        return True
    
    @staticmethod
    def update_profile(user_id, data):
        """
        Update user profile.
        
        Args:
            user_id: User ID
            data: Profile data
            
        Returns:
            dict: Updated user data
            
        Raises:
            ValueError: Validation errors
        """
        user = User.query.get(user_id)
        
        if not user:
            raise ValueError("User not found")
        
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
                    raise ValueError('Theme must be dark or light')
                if field in {'notifications_enabled', 'marketing_emails'} and not isinstance(new_value, bool):
                    raise ValueError(f'{field} must be true or false')
                if field in {'full_name', 'bio'}:
                    if not isinstance(new_value, str):
                        raise ValueError(f'{field} must be text')
                    new_value = new_value.strip()
                if old_value != new_value:
                    setattr(user, field, new_value)
                    changes.append(f'{field}: {old_value} -> {new_value}')

        user.language = 'en'
        
        if changes:
            db.session.commit()
            
            AuditService.log(
                user_id=user.id,
                action='profile_updated',
                details=f'Updated profile: {", ".join(changes)}',
                ip_address=request.remote_addr if request else None,
                user_agent=request.headers.get('User-Agent') if request else None
            )
        
        return user.to_dict()
    
    @staticmethod
    def update_email(user_id, new_email, password):
        """
        Update user email.
        
        Args:
            user_id: User ID
            new_email: New email
            password: Password for verification
            
        Returns:
            dict: Updated user data
            
        Raises:
            ValueError: Validation errors
        """
        user = User.query.get(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        if not new_email or not password:
            raise ValueError("Email and password are required")
        
        # Verify password
        if not user.check_password(password):
            raise ValueError("Invalid password")
        
        # Validate email
        if not validate_email(new_email):
            raise ValueError("Please provide a valid email address")
        
        # Check if email is taken
        existing = User.query.filter_by(email=new_email.lower()).first()
        if existing and existing.id != user.id:
            raise ValueError("Email already registered")
        
        old_email = user.email
        user.email = new_email.lower()
        db.session.commit()
        
        AuditService.log(
            user_id=user.id,
            action='email_changed',
            details=f'Changed email from {old_email} to {new_email}',
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None,
            severity='warning'
        )
        
        return user.to_dict()
    
    @staticmethod
    def update_username(user_id, new_username):
        """
        Update username.
        
        Args:
            user_id: User ID
            new_username: New username
            
        Returns:
            dict: Updated user data
            
        Raises:
            ValueError: Validation errors
        """
        user = User.query.get(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        if not new_username:
            raise ValueError("Username is required")
        
        # Validate username
        if not validate_username(new_username):
            raise ValueError("Username must be 3-30 characters, alphanumeric with underscores")
        
        # Check if username is taken
        existing = User.query.filter_by(username=new_username.lower()).first()
        if existing and existing.id != user.id:
            raise ValueError("Username already taken")
        
        old_username = user.username
        user.username = new_username.lower()
        db.session.commit()
        
        AuditService.log(
            user_id=user.id,
            action='username_changed',
            details=f'Changed username from {old_username} to {new_username}',
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None
        )
        
        return user.to_dict()
    
    @staticmethod
    def delete_account(user_id, password, confirm=False):
        """
        Delete user account.
        
        Args:
            user_id: User ID
            password: Password for verification
            confirm: Confirmation flag
            
        Returns:
            bool: Success status
            
        Raises:
            ValueError: Validation errors
        """
        user = User.query.get(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        if not password:
            raise ValueError("Password is required to confirm account deletion")
        
        if not confirm:
            raise ValueError("Please confirm account deletion")
        
        # Verify password
        if not user.check_password(password):
            raise ValueError("Invalid password")
        
        # Log deletion
        AuditService.log(
            user_id=user.id,
            action='account_deleted',
            details=f'User account deleted',
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None,
            severity='critical'
        )
        
        # Delete user
        db.session.delete(user)
        db.session.commit()
        
        return True
    
    @staticmethod
    def get_user_by_id(user_id):
        """
        Get user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User: User object or None
        """
        return User.query.get(user_id)
    
    @staticmethod
    def get_user_by_email(email):
        """
        Get user by email.
        
        Args:
            email: Email address
            
        Returns:
            User: User object or None
        """
        return User.query.filter_by(email=email.lower()).first()
    
    @staticmethod
    def get_user_by_username(username):
        """
        Get user by username.
        
        Args:
            username: Username
            
        Returns:
            User: User object or None
        """
        return User.query.filter_by(username=username.lower()).first()
    
    @staticmethod
    def is_admin(user_id):
        """
        Check if user is admin.
        
        Args:
            user_id: User ID
            
        Returns:
            bool: True if admin
        """
        user = User.query.get(user_id)
        return user and user.is_admin
    
    @staticmethod
    def is_premium(user_id):
        """
        Check if user has premium access.
        
        Args:
            user_id: User ID
            
        Returns:
            bool: True if premium
        """
        user = User.query.get(user_id)
        return user and user.is_premium()
