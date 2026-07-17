# -*- coding: utf-8 -*-

"""
WebShield Scanner - Validators
Input validation functions for the application.
"""

import re
import ipaddress
from datetime import datetime


def validate_email(email):
    """
    Validate an email address.
    
    Args:
        email: Email address to validate
        
    Returns:
        bool: True if valid
    """
    if not email:
        return False
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email.strip()))


def validate_username(username):
    """
    Validate a username.
    
    Args:
        username: Username to validate
        
    Returns:
        bool: True if valid
    """
    if not username:
        return False
    
    # 3-30 characters, alphanumeric and underscores
    username_pattern = r'^[a-zA-Z0-9_]{3,30}$'
    return bool(re.match(username_pattern, username.strip()))


def validate_password(password):
    """
    Validate a password.
    
    Args:
        password: Password to validate
        
    Returns:
        bool: True if valid
    """
    if not password:
        return False
    
    # At least 8 characters
    if len(password) < 8:
        return False
    
    # At least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False
    
    # At least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False
    
    # At least one number
    if not re.search(r'\d', password):
        return False
    
    # At least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    
    return True


def validate_url(url):
    """
    Validate a URL.
    
    Args:
        url: URL to validate
        
    Returns:
        bool: True if valid
    """
    if not url:
        return False
    
    # Basic URL validation
    url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return bool(re.match(url_pattern, url.strip()))


def validate_domain(domain):
    """
    Validate a domain name.
    
    Args:
        domain: Domain to validate
        
    Returns:
        bool: True if valid
    """
    if not domain:
        return False
    
    domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, domain.strip()))


def validate_ip(ip):
    """
    Validate an IP address.
    
    Args:
        ip: IP address to validate
        
    Returns:
        bool: True if valid
    """
    if not ip:
        return False
    
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def validate_phone(phone):
    """
    Validate a phone number.
    
    Args:
        phone: Phone number to validate
        
    Returns:
        bool: True if valid
    """
    if not phone:
        return False
    
    # Remove common separators
    cleaned = re.sub(r'[\s\-\(\)\+]', '', phone)
    
    # Check if it's a valid phone number (international format)
    phone_pattern = r'^[1-9]\d{1,14}$'
    return bool(re.match(phone_pattern, cleaned))


def validate_postal_code(postal_code, country='US'):
    """
    Validate a postal code.
    
    Args:
        postal_code: Postal code to validate
        country: Country code
        
    Returns:
        bool: True if valid
    """
    if not postal_code:
        return False
    
    patterns = {
        'US': r'^\d{5}(-\d{4})?$',
        'UK': r'^[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}$',
        'CA': r'^[A-Z]\d[A-Z] ?\d[A-Z]\d$',
        'AU': r'^\d{4}$',
        'DE': r'^\d{5}$',
        'FR': r'^\d{5}$',
        'JP': r'^\d{3}-\d{4}$',
        'IN': r'^\d{6}$',
        'BR': r'^\d{5}-\d{3}$'
    }
    
    pattern = patterns.get(country.upper(), r'^[A-Z0-9\s\-]{3,10}$')
    return bool(re.match(pattern, postal_code.strip(), re.IGNORECASE))


def validate_date(date_string, format='%Y-%m-%d'):
    """
    Validate a date string.
    
    Args:
        date_string: Date string to validate
        format: Date format
        
    Returns:
        bool: True if valid
    """
    if not date_string:
        return False
    
    try:
        datetime.strptime(date_string.strip(), format)
        return True
    except ValueError:
        return False


def validate_boolean(value):
    """
    Validate a boolean value.
    
    Args:
        value: Value to validate
        
    Returns:
        bool: True if value is boolean or can be converted to boolean
    """
    if isinstance(value, bool):
        return True
    
    if isinstance(value, str):
        return value.lower() in ['true', 'false', '1', '0', 'yes', 'no']
    
    if isinstance(value, (int, float)):
        return value in [0, 1]
    
    return False


def validate_integer(value, min_value=None, max_value=None):
    """
    Validate an integer.
    
    Args:
        value: Value to validate
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        
    Returns:
        bool: True if valid
    """
    try:
        int_value = int(value)
        if min_value is not None and int_value < min_value:
            return False
        if max_value is not None and int_value > max_value:
            return False
        return True
    except (ValueError, TypeError):
        return False


def validate_float(value, min_value=None, max_value=None):
    """
    Validate a float.
    
    Args:
        value: Value to validate
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        
    Returns:
        bool: True if valid
    """
    try:
        float_value = float(value)
        if min_value is not None and float_value < min_value:
            return False
        if max_value is not None and float_value > max_value:
            return False
        return True
    except (ValueError, TypeError):
        return False


def validate_hex_color(color):
    """
    Validate a hex color code.
    
    Args:
        color: Color code to validate
        
    Returns:
        bool: True if valid
    """
    if not color:
        return False
    
    color_pattern = r'^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$'
    return bool(re.match(color_pattern, color.strip()))


def validate_credit_card(card_number):
    """
    Validate a credit card number (Luhn algorithm).
    
    Args:
        card_number: Credit card number to validate
        
    Returns:
        bool: True if valid
    """
    if not card_number:
        return False
    
    # Remove spaces and dashes
    cleaned = re.sub(r'[\s\-]', '', card_number)
    
    if not cleaned.isdigit():
        return False
    
    # Luhn algorithm
    total = 0
    reverse_digits = cleaned[::-1]
    
    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    
    return total % 10 == 0


def validate_required(value):
    """
    Check if a value is present (not None, not empty).
    
    Args:
        value: Value to check
        
    Returns:
        bool: True if present
    """
    if value is None:
        return False
    
    if isinstance(value, str) and not value.strip():
        return False
    
    if isinstance(value, (list, dict)) and not value:
        return False
    
    return True


def validate_one_of(value, allowed_values):
    """
    Check if a value is in a list of allowed values.
    
    Args:
        value: Value to check
        allowed_values: List of allowed values
        
    Returns:
        bool: True if value is allowed
    """
    if not allowed_values:
        return True
    
    return value in allowed_values


def validate_choice(value, choices):
    """
    Validate that a value is one of the choices.
    
    Args:
        value: Value to validate
        choices: List of choices
        
    Returns:
        bool: True if valid
    """
    if not choices:
        return True
    
    return value in choices