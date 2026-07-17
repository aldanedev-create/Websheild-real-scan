# -*- coding: utf-8 -*-

"""
WebShield Scanner - CSRF Protection
Provides CSRF protection for forms and API requests.
"""

import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from flask import request, session, current_app, jsonify
from functools import wraps
from extensions import db
from app.models.audit_log import AuditLog


class CSRFProtection:
    """
    CSRF protection implementation.
    Supports both form-based and API-based CSRF protection.
    """
    
    @staticmethod
    def generate_token():
        """
        Generate a CSRF token.
        
        Returns:
            str: CSRF token
        """
        # Generate a secure random token
        token = secrets.token_urlsafe(32)
        
        # Store token in session
        if 'csrf_tokens' not in session:
            session['csrf_tokens'] = {}
        
        # Store token with timestamp
        session['csrf_tokens'][token] = datetime.utcnow().isoformat()
        
        # Clean up old tokens
        CSRFProtection._clean_old_tokens()
        
        return token
    
    @staticmethod
    def validate_token(token):
        """
        Validate a CSRF token.
        
        Args:
            token: CSRF token to validate
            
        Returns:
            bool: True if valid
        """
        if not token:
            return False
        
        # Check if token exists in session
        if 'csrf_tokens' not in session:
            return False
        
        if token not in session['csrf_tokens']:
            return False
        
        # Check token age
        token_time = datetime.fromisoformat(session['csrf_tokens'][token])
        max_age = timedelta(hours=1)  # Tokens expire after 1 hour
        
        if datetime.utcnow() - token_time > max_age:
            # Remove expired token
            del session['csrf_tokens'][token]
            return False
        
        # Remove token after use (one-time use)
        del session['csrf_tokens'][token]
        
        return True
    
    @staticmethod
    def _clean_old_tokens():
        """
        Clean up old CSRF tokens from session.
        """
        if 'csrf_tokens' not in session:
            return
        
        max_age = timedelta(hours=1)
        now = datetime.utcnow()
        
        expired = []
        for token, time_str in session['csrf_tokens'].items():
            try:
                token_time = datetime.fromisoformat(time_str)
                if now - token_time > max_age:
                    expired.append(token)
            except (TypeError, ValueError):
                expired.append(token)
        
        for token in expired:
            del session['csrf_tokens'][token]
    
    @staticmethod
    def protect_form(form):
        """
        Add CSRF protection to a form.
        
        Args:
            form: Flask-WTF form
            
        Returns:
            Flask-WTF form with CSRF field
        """
        # This is handled by Flask-WTF's CSRFProtect
        return form
    
    @staticmethod
    def require_csrf_token(f):
        """
        Decorator to require CSRF token for API endpoints.
        
        Usage:
            @CSRFProtection.require_csrf_token
            def api_endpoint():
                return "Protected"
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip CSRF check for GET, HEAD, OPTIONS
            if request.method in ['GET', 'HEAD', 'OPTIONS']:
                return f(*args, **kwargs)
            
            # Get token from header or request body
            token = request.headers.get('X-CSRF-Token')
            
            if not token:
                token = request.form.get('csrf_token')
            
            if not token:
                json_data = request.get_json(silent=True) or {}
                token = json_data.get('csrf_token')
            
            if not token:
                # Log CSRF failure
                AuditLog.log(
                    user_id=None,
                    action='csrf_failure',
                    details=f'CSRF token missing for {request.endpoint}',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    severity='warning'
                )
                
                return jsonify({
                    'error': 'csrf_required',
                    'message': 'CSRF token required'
                }), 403
            
            if not CSRFProtection.validate_token(token):
                # Log CSRF failure
                AuditLog.log(
                    user_id=None,
                    action='csrf_failure',
                    details=f'Invalid CSRF token for {request.endpoint}',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    severity='warning'
                )
                
                return jsonify({
                    'error': 'csrf_invalid',
                    'message': 'Invalid CSRF token'
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    @staticmethod
    def get_token_for_form():
        """
        Get a CSRF token for a form.
        
        Returns:
            str: CSRF token
        """
        return CSRFProtection.generate_token()
    
    @staticmethod
    def get_token_for_api():
        """
        Get a CSRF token for an API request.
        
        Returns:
            dict: Token data
        """
        token = CSRFProtection.generate_token()
        return {
            'csrf_token': token,
            'expires_in': 3600  # 1 hour
        }


def csrf_protect(f):
    """
    Decorator for CSRF protection (compatibility with Flask-WTF).
    
    Usage:
        @csrf_protect
        def endpoint():
            return "Protected"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return CSRFProtection.require_csrf_token(f)(*args, **kwargs)
    
    return decorated_function


# CSRF exempt decorator
def csrf_exempt(f):
    """
    Decorator to exempt an endpoint from CSRF protection.
    
    Usage:
        @csrf_exempt
        def webhook():
            return "Webhook"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Set a flag to skip CSRF check
        request._csrf_exempt = True
        return f(*args, **kwargs)
    
    return decorated_function
