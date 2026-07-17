# -*- coding: utf-8 -*-

"""
WebShield Scanner - Helpers
Common utility functions used throughout the application.
"""

import re
import json
import uuid
import secrets
import html
import time
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse
from flask import request, current_app


def format_datetime(dt, format_str='%Y-%m-%d %H:%M:%S'):
    """
    Format a datetime object.
    
    Args:
        dt: datetime object
        format_str: Format string
        
    Returns:
        str: Formatted datetime string
    """
    if not dt:
        return None
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except (TypeError, ValueError):
            return dt
    return dt.strftime(format_str)


def format_currency(amount, currency='USD'):
    """
    Format a currency amount.
    
    Args:
        amount: Amount to format
        currency: Currency code
        
    Returns:
        str: Formatted currency string
    """
    symbols = {
        'USD': '$',
        'EUR': '€',
        'GBP': '£',
        'JPY': '¥',
        'CAD': 'C$',
        'AUD': 'A$',
        'INR': '₹',
        'CNY': '¥',
        'BRL': 'R$',
        'ZAR': 'R'
    }
    
    symbol = symbols.get(currency, '$')
    return f"{symbol}{amount:.2f}"


def truncate_text(text, max_length=100, suffix='...'):
    """
    Truncate text to a maximum length.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add
        
    Returns:
        str: Truncated text
    """
    if not text:
        return ''
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def generate_id(prefix='', length=16):
    """
    Generate a unique ID.
    
    Args:
        prefix: Optional prefix
        length: Length of random part
        
    Returns:
        str: Generated ID
    """
    random_part = secrets.token_hex(length // 2)
    if prefix:
        return f"{prefix}_{random_part}"
    return random_part


def safe_json_loads(json_string, default=None):
    """
    Safely load JSON from a string.
    
    Args:
        json_string: JSON string
        default: Default value if parsing fails
        
    Returns:
        dict: Parsed JSON or default
    """
    if not json_string:
        return default
    try:
        return json.loads(json_string)
    except (TypeError, json.JSONDecodeError):
        return default


def clean_html(html_content):
    """
    Clean HTML content (remove tags, scripts, etc.).
    
    Args:
        html_content: HTML content to clean
        
    Returns:
        str: Cleaned text
    """
    if not html_content:
        return ''
    
    # Remove script tags
    html_content = re.sub(r'<script.*?</script>', '', html_content, flags=re.DOTALL)
    
    # Remove style tags
    html_content = re.sub(r'<style.*?</style>', '', html_content, flags=re.DOTALL)
    
    # Remove HTML tags
    html_content = re.sub(r'<[^>]+>', ' ', html_content)
    
    # Decode HTML entities
    html_content = html.unescape(html_content)
    
    # Remove extra whitespace
    html_content = re.sub(r'\s+', ' ', html_content)
    
    return html_content.strip()


def extract_domain(url):
    """
    Extract domain from a URL.
    
    Args:
        url: URL to extract from
        
    Returns:
        str: Domain name
    """
    if not url:
        return None
    parsed = urlparse(url)
    return parsed.netloc


def is_valid_url(url):
    """
    Check if a URL is valid.
    
    Args:
        url: URL to check
        
    Returns:
        bool: True if valid
    """
    if not url:
        return False
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except (TypeError, ValueError):
        return False


def get_client_ip():
    """
    Get client IP address from request.
    
    Returns:
        str: Client IP address
    """
    if request:
        # Check for proxy headers
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            return forwarded.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        return request.remote_addr
    
    return None


def get_user_agent():
    """
    Get user agent from request.
    
    Returns:
        str: User agent string
    """
    if request:
        return request.headers.get('User-Agent')
    return None


def sanitize_filename(filename):
    """
    Sanitize a filename to remove dangerous characters.
    
    Args:
        filename: Filename to sanitize
        
    Returns:
        str: Sanitized filename
    """
    if not filename:
        return 'file'
    
    # Remove path separators
    filename = filename.replace('/', '_').replace('\\', '_')
    
    # Remove dangerous characters
    filename = re.sub(r'[<>:"|?*]', '_', filename)
    
    # Remove leading/trailing whitespace
    filename = filename.strip()
    
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:250] + ('.' + ext if ext else '')
    
    return filename


def create_slug(text):
    """
    Create a URL-friendly slug from text.
    
    Args:
        text: Text to slugify
        
    Returns:
        str: Slug
    """
    if not text:
        return ''
    
    # Convert to lowercase
    slug = text.lower()
    
    # Remove accents
    import unicodedata
    slug = unicodedata.normalize('NFKD', slug)
    slug = slug.encode('ascii', 'ignore').decode('ascii')
    
    # Replace spaces and special characters with hyphens
    slug = re.sub(r'[^a-z0-9]+', '-', slug)
    
    # Remove leading/trailing hyphens
    slug = slug.strip('-')
    
    return slug


def format_file_size(size_in_bytes):
    """
    Format file size in human-readable format.
    
    Args:
        size_in_bytes: Size in bytes
        
    Returns:
        str: Formatted size
    """
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    elif size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.1f} KB"
    elif size_in_bytes < 1024 * 1024 * 1024:
        return f"{size_in_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_in_bytes / (1024 * 1024 * 1024):.1f} GB"


def calculate_percentage(part, total):
    """
    Calculate percentage.
    
    Args:
        part: Part value
        total: Total value
        
    Returns:
        float: Percentage
    """
    if total == 0:
        return 0
    return (part / total) * 100


def merge_dicts(dict1, dict2):
    """
    Merge two dictionaries recursively.
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary
        
    Returns:
        dict: Merged dictionary
    """
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def chunk_list(lst, chunk_size):
    """
    Split a list into chunks.
    
    Args:
        lst: List to split
        chunk_size: Size of each chunk
        
    Returns:
        list: List of chunks
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def retry_on_failure(max_retries=3, delay=1, backoff=2, exceptions=(Exception,)):
    """
    Decorator to retry a function on failure.
    
    Args:
        max_retries: Maximum number of retries
        delay: Initial delay in seconds
        backoff: Backoff multiplier
        exceptions: Exceptions to catch
        
    Returns:
        Decorated function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_delay = delay
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return f(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt == max_retries:
                        raise
                    time.sleep(current_delay)
                    current_delay *= backoff
            
            raise last_exception
        
        return decorated_function
    return decorator


def timing_decorator(f):
    """
    Decorator to log function execution time.
    
    Args:
        f: Function to decorate
        
    Returns:
        Decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        result = f(*args, **kwargs)
        elapsed_time = time.time() - start_time
        
        current_app.logger.debug(
            f"Function {f.__name__} executed in {elapsed_time:.4f} seconds"
        )
        
        return result
    
    return decorated_function
