# -*- coding: utf-8 -*-

"""
WebShield Scanner - Security Decorators
Provides decorators for authorization, rate limiting, and security checks.
"""

from functools import wraps
from flask import request, jsonify, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from app.models.user import User
from app.models.audit_log import AuditLog


def admin_required(f):
    """
    Decorator to require admin privileges.
    
    Usage:
        @admin_required
        def admin_endpoint():
            return "Admin only"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user:
                return jsonify({
                    'error': 'unauthorized',
                    'message': 'User not found'
                }), 401
            
            if not user.is_admin:
                # Log unauthorized access attempt
                AuditLog.log(
                    user_id=user_id,
                    action='unauthorized_access',
                    details=f'Non-admin user attempted to access admin endpoint: {request.endpoint}',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    severity='warning'
                )
                
                return jsonify({
                    'error': 'forbidden',
                    'message': 'Admin privileges required'
                }), 403
            
            return f(*args, **kwargs)
            
        except Exception as e:
            return jsonify({
                'error': 'unauthorized',
                'message': 'Authentication required'
            }), 401
    
    return decorated_function


def rate_limit(limit, period=3600):
    """
    Decorator to apply rate limiting to endpoints.
    
    Args:
        limit: Maximum number of requests
        period: Time period in seconds (default: 3600 = 1 hour)
    
    Usage:
        @rate_limit(100, 3600)
        def endpoint():
            return "Rate limited"
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client identifier (IP or user ID)
            client_id = request.remote_addr
            
            # Check if authenticated
            try:
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                if user_id:
                    client_id = f"user_{user_id}"
            except Exception:
                pass
            
            # Initialize rate limiter
            from app.security.rate_limit import RateLimiter
            limiter = RateLimiter()
            
            # Check rate limit
            allowed, remaining, reset_time = limiter.check_rate_limit(
                client_id, f"{request.endpoint}_{request.method}", limit, period
            )
            
            if not allowed:
                return jsonify({
                    'error': 'rate_limited',
                    'message': f'Rate limit exceeded. Try again in {reset_time} seconds.',
                    'retry_after': reset_time
                }), 429
            
            # Add rate limit headers
            response = f(*args, **kwargs)
            
            # If response is a tuple, handle it
            if isinstance(response, tuple):
                return response
            
            # If response is a dict or JSON, add headers
            if isinstance(response, dict):
                response['rate_limit'] = {
                    'limit': limit,
                    'remaining': remaining,
                    'reset': reset_time
                }
                return response
            
            return response
        
        return decorated_function
    return decorator


def jwt_required_custom(f):
    """
    Custom JWT required decorator with better error handling.
    
    Usage:
        @jwt_required_custom
        def protected_endpoint():
            return "Protected"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request()
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({
                'error': 'unauthorized',
                'message': 'Invalid or missing authentication token'
            }), 401
    
    return decorated_function


def check_authorization(f):
    """
    Decorator to verify authorization for scanning.
    
    Checks that the user has confirmed authorization before scanning a URL.
    
    Usage:
        @check_authorization
        def scan_endpoint():
            return "Scan started"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        data = request.get_json(silent=True) or {}
        confirm_authorization = data.get('confirm_authorization', False)
        
        if not confirm_authorization:
            return jsonify({
                'error': 'authorization_required',
                'message': 'You must confirm that you own the website or have written permission to scan it.'
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


def validate_scan_url(f):
    """
    Decorator to validate URLs before scanning.
    
    Usage:
        @validate_scan_url
        def scan_endpoint():
            return "URL validated"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        data = request.get_json(silent=True) or {}
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'error': 'missing_url',
                'message': 'URL is required'
            }), 400
        
        # Basic URL validation
        from app.scanner.url_validator import URLValidator
        validator = URLValidator()
        is_valid, error_message = validator.validate(url)
        
        if not is_valid:
            return jsonify({
                'error': 'invalid_url',
                'message': error_message
            }), 400
        
        # Store validated URL in request context
        request.validated_url = validator.normalize_url(url)
        
        return f(*args, **kwargs)
    
    return decorated_function


def log_request(f):
    """
    Decorator to log API requests for audit purposes.
    
    Usage:
        @log_request
        def endpoint():
            return "Logged"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get user ID if authenticated
        user_id = None
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
        except Exception:
            pass
        
        # Log request
        AuditLog.log(
            user_id=user_id,
            action='api_request',
            details=f'API request to {request.endpoint}',
            metadata={
                'method': request.method,
                'endpoint': request.endpoint,
                'args': dict(request.args),
                'headers': dict(request.headers)
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return f(*args, **kwargs)
    
    return decorated_function


def check_scan_limit(f):
    """
    Decorator to check user's scan limit before allowing a scan.
    
    Usage:
        @check_scan_limit
        def scan_endpoint():
            return "Scan started"
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user:
                return jsonify({
                    'error': 'unauthorized',
                    'message': 'User not found'
                }), 401
            
            return f(*args, **kwargs)
            
        except Exception as e:
            return jsonify({
                'error': 'unauthorized',
                'message': 'Authentication required'
            }), 401
    
    return decorated_function
