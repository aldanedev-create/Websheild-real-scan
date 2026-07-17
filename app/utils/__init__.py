# -*- coding: utf-8 -*-

"""
WebShield Scanner - Utils Package
Contains utility functions, helpers, validators, and constants.
"""

from app.utils.helpers import (
    format_datetime,
    format_currency,
    truncate_text,
    generate_id,
    safe_json_loads,
    clean_html,
    extract_domain,
    is_valid_url,
    get_client_ip,
    get_user_agent,
    sanitize_filename,
    create_slug,
    format_file_size,
    calculate_percentage,
    merge_dicts,
    chunk_list,
    retry_on_failure,
    timing_decorator
)

from app.utils.validators import (
    validate_email,
    validate_username,
    validate_password,
    validate_url,
    validate_domain,
    validate_ip,
    validate_phone,
    validate_postal_code,
    validate_date,
    validate_boolean,
    validate_integer,
    validate_float,
    validate_hex_color,
    validate_credit_card
)

from app.utils.constants import (
    HTTP_STATUS,
    SEVERITY_LEVELS,
    RISK_LEVELS,
    SCAN_STATUS,
    SUBSCRIPTION_PLANS,
    SECURITY_HEADERS,
    COMMON_PORTS,
    FILE_EXTENSIONS,
    API_RESPONSE_MESSAGES,
    REGEX_PATTERNS,
    DEFAULT_SETTINGS
)

from app.utils.response import (
    success_response,
    error_response,
    validation_error,
    unauthorized_response,
    forbidden_response,
    not_found_response,
    rate_limit_response,
    api_response,
    paginated_response
)

__all__ = [
    # Helpers
    'format_datetime',
    'format_currency',
    'truncate_text',
    'generate_id',
    'safe_json_loads',
    'clean_html',
    'extract_domain',
    'is_valid_url',
    'get_client_ip',
    'get_user_agent',
    'sanitize_filename',
    'create_slug',
    'format_file_size',
    'calculate_percentage',
    'merge_dicts',
    'chunk_list',
    'retry_on_failure',
    'timing_decorator',
    
    # Validators
    'validate_email',
    'validate_username',
    'validate_password',
    'validate_url',
    'validate_domain',
    'validate_ip',
    'validate_phone',
    'validate_postal_code',
    'validate_date',
    'validate_boolean',
    'validate_integer',
    'validate_float',
    'validate_hex_color',
    'validate_credit_card',
    
    # Constants
    'HTTP_STATUS',
    'SEVERITY_LEVELS',
    'RISK_LEVELS',
    'SCAN_STATUS',
    'SUBSCRIPTION_PLANS',
    'SECURITY_HEADERS',
    'COMMON_PORTS',
    'FILE_EXTENSIONS',
    'API_RESPONSE_MESSAGES',
    'REGEX_PATTERNS',
    'DEFAULT_SETTINGS',
    
    # Response
    'success_response',
    'error_response',
    'validation_error',
    'unauthorized_response',
    'forbidden_response',
    'not_found_response',
    'rate_limit_response',
    'api_response',
    'paginated_response'
]