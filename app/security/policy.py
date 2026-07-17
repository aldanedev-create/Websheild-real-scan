# -*- coding: utf-8 -*-

"""
WebShield Scanner - Security Policy
Defines and enforces application security policies.
"""

import re
import ipaddress
from datetime import datetime, timedelta
from flask import request, current_app, jsonify
from functools import wraps
from app.models.audit_log import AuditLog


class SecurityPolicy:
    """
    Application security policy enforcement.
    """
    
    # Security headers to enforce
    SECURITY_HEADERS = {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    }
    
    # CORS policy
    ALLOWED_ORIGINS = []
    ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    ALLOWED_HEADERS = ['Content-Type', 'Authorization', 'X-CSRF-Token']
    
    @classmethod
    def apply_security_headers(cls, response):
        """
        Apply security headers to a response.
        
        Args:
            response: Flask response object
            
        Returns:
            Flask response with headers applied
        """
        # Only apply in production-like deployments.
        if current_app.config.get('FLASK_ENV') != 'production':
            return response
        
        security_headers = cls.SECURITY_HEADERS.copy()
        if current_app.config.get('HSTS_ENABLED', True):
            max_age = current_app.config.get('HSTS_MAX_AGE', 31536000)
            security_headers['Strict-Transport-Security'] = (
                f'max-age={max_age}; includeSubDomains'
            )
        else:
            security_headers.pop('Strict-Transport-Security', None)

        for header, value in security_headers.items():
            if header not in response.headers:
                response.headers[header] = value
        
        # Add CSP if configured
        if current_app.config.get('CSP_ENABLED', True):
            csp_policy = current_app.config.get('CSP_POLICY')
            if csp_policy and 'Content-Security-Policy' not in response.headers:
                response.headers['Content-Security-Policy'] = csp_policy
        
        return response
    
    @classmethod
    def validate_input(cls, data, schema):
        """
        Validate input against a schema.
        
        Args:
            data: Input data
            schema: Validation schema
            
        Returns:
            tuple: (is_valid, errors)
        """
        errors = {}
        
        for field, rules in schema.items():
            value = data.get(field)
            
            # Check required
            if rules.get('required', False) and not value:
                errors[field] = f"{field} is required"
                continue
            
            # Check type
            if value is not None and 'type' in rules:
                expected_type = rules['type']
                if not isinstance(value, expected_type):
                    errors[field] = f"{field} must be of type {expected_type.__name__}"
                    continue
            
            # Check length
            if value is not None and 'min_length' in rules:
                if len(str(value)) < rules['min_length']:
                    errors[field] = f"{field} must be at least {rules['min_length']} characters"
            
            if value is not None and 'max_length' in rules:
                if len(str(value)) > rules['max_length']:
                    errors[field] = f"{field} must be no more than {rules['max_length']} characters"
            
            # Check pattern
            if value is not None and 'pattern' in rules:
                if not re.match(rules['pattern'], str(value)):
                    errors[field] = f"{field} has invalid format"
            
            # Check allowed values
            if value is not None and 'allowed' in rules:
                if value not in rules['allowed']:
                    errors[field] = f"{field} must be one of: {', '.join(rules['allowed'])}"
            
            # Check email
            if value is not None and rules.get('email', False):
                if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', str(value)):
                    errors[field] = f"{field} must be a valid email address"
            
            # Check URL
            if value is not None and rules.get('url', False):
                if not re.match(r'^https?://[^\s/$.?#].[^\s]*$', str(value)):
                    errors[field] = f"{field} must be a valid URL"
        
        return len(errors) == 0, errors
    
    @classmethod
    def require_https(cls, f):
        """
        Decorator to require HTTPS.
        
        Usage:
            @SecurityPolicy.require_https
            def endpoint():
                return "Secure"
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip in development
            if current_app.config.get('DEBUG', False):
                return f(*args, **kwargs)
            
            # Check if request is HTTPS
            if not request.is_secure:
                # Log insecure request
                AuditLog.log(
                    user_id=None,
                    action='insecure_request',
                    details=f'Insecure HTTP request to {request.endpoint}',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    severity='warning'
                )
                
                return jsonify({
                    'error': 'https_required',
                    'message': 'HTTPS is required for this endpoint'
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    @classmethod
    def block_private_ips(cls, f):
        """
        Decorator to block requests from private IPs.
        
        Usage:
            @SecurityPolicy.block_private_ips
            def endpoint():
                return "Public only"
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip if not configured
            if not current_app.config.get('BLOCK_PRIVATE_IPS', True):
                return f(*args, **kwargs)
            
            remote_ip = request.remote_addr
            
            try:
                ip_obj = ipaddress.ip_address(remote_ip)
                
                # Check if IP is private
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                    # Log blocked request
                    AuditLog.log(
                        user_id=None,
                        action='blocked_request',
                        details=f'Blocked request from private IP: {remote_ip}',
                        ip_address=remote_ip,
                        user_agent=request.headers.get('User-Agent'),
                        severity='warning'
                    )
                    
                    return jsonify({
                        'error': 'blocked',
                        'message': 'Requests from private IPs are not allowed'
                    }), 403
            except (TypeError, ValueError):
                current_app.logger.warning("Could not parse remote IP: %s", remote_ip)
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    @classmethod
    def rate_limit_by_ip(cls, limit, period=3600):
        """
        Decorator to rate limit by IP address.
        
        Args:
            limit: Maximum requests
            period: Time period in seconds
            
        Usage:
            @SecurityPolicy.rate_limit_by_ip(100, 3600)
            def endpoint():
                return "Rate limited"
        """
        from app.security.rate_limit import RateLimiter
        
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                limiter = RateLimiter()
                client_id = request.remote_addr
                action = f"{request.endpoint}_{request.method}"
                
                allowed, remaining, reset_time = limiter.check_rate_limit(
                    client_id, action, limit, period
                )
                
                if not allowed:
                    return jsonify({
                        'error': 'rate_limited',
                        'message': f'Rate limit exceeded. Try again in {reset_time} seconds.',
                        'retry_after': reset_time
                    }), 429
                
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
    
    @classmethod
    def sanitize_input(cls, data, fields_to_sanitize=None):
        """
        Sanitize input data to prevent injection attacks.
        
        Args:
            data: Input data (dict or string)
            fields_to_sanitize: List of fields to sanitize (optional)
            
        Returns:
            Sanitized data
        """
        import html
        
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                if fields_to_sanitize is None or key in fields_to_sanitize:
                    if isinstance(value, str):
                        sanitized[key] = html.escape(value.strip())
                    else:
                        sanitized[key] = value
                else:
                    sanitized[key] = value
            return sanitized
        elif isinstance(data, str):
            return html.escape(data.strip())
        else:
            return data
    
    @classmethod
    def get_security_info(cls):
        """
        Get security policy information.
        
        Returns:
            dict: Security policy info
        """
        return {
            'version': current_app.config.get('APP_VERSION', '1.0.0'),
            'environment': current_app.config.get('FLASK_ENV', 'development'),
            'features': {
                'ssl_enforced': current_app.config.get('SSL_ENFORCED', False),
                'rate_limiting': current_app.config.get('RATELIMIT_ENABLED', False),
                'csrf_protection': current_app.config.get('WTF_CSRF_ENABLED', True),
                'block_private_ips': current_app.config.get('BLOCK_PRIVATE_IPS', True),
                'hsts_enabled': current_app.config.get('HSTS_ENABLED', True),
                'csp_enabled': current_app.config.get('CSP_ENABLED', True),
            },
            'headers': list(cls.SECURITY_HEADERS.keys()),
            'allowed_methods': cls.ALLOWED_METHODS,
            'rate_limits': {
                'default': current_app.config.get('RATELIMIT_DEFAULT', '100 per hour'),
            }
        }
