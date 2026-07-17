# -*- coding: utf-8 -*-

"""
WebShield Scanner - Security Package
Contains security utilities, decorators, and middleware for the application.
"""

from app.security.decorators import (
    admin_required,
    rate_limit,
    jwt_required_custom,
    check_authorization,
    validate_scan_url
)

from app.security.rate_limit import RateLimiter
from app.security.csrf import CSRFProtection
from app.security.password import PasswordPolicy
from app.security.policy import SecurityPolicy

__all__ = [
    'admin_required',
    'rate_limit',
    'jwt_required_custom',
    'check_authorization',
    'validate_scan_url',
    'RateLimiter',
    'CSRFProtection',
    'PasswordPolicy',
    'SecurityPolicy'
]
