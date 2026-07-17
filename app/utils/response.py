# -*- coding: utf-8 -*-

"""
WebShield Scanner - Response Utilities
Standardized API response helpers for consistent JSON responses.
"""

from flask import jsonify, make_response
from app.utils.constants import HTTP_STATUS, API_RESPONSE_MESSAGES


def success_response(data=None, message=None, status_code=200):
    """
    Create a success response.
    
    Args:
        data: Response data
        message: Success message
        status_code: HTTP status code
        
    Returns:
        tuple: (response, status_code)
    """
    response = {
        'success': True,
        'message': message or API_RESPONSE_MESSAGES['SUCCESS']
    }
    
    if data is not None:
        response['data'] = data
    
    return jsonify(response), status_code


def error_response(message=None, error_code=None, status_code=400, details=None):
    """
    Create an error response.
    
    Args:
        message: Error message
        error_code: Error code
        status_code: HTTP status code
        details: Additional error details
        
    Returns:
        tuple: (response, status_code)
    """
    response = {
        'success': False,
        'error': message or API_RESPONSE_MESSAGES['ERROR']
    }
    
    if error_code:
        response['error_code'] = error_code
    
    if details:
        response['details'] = details
    
    return jsonify(response), status_code


def validation_error(errors, message=None):
    """
    Create a validation error response.
    
    Args:
        errors: Validation errors dict
        message: Error message
        
    Returns:
        tuple: (response, status_code)
    """
    return error_response(
        message=message or API_RESPONSE_MESSAGES['VALIDATION_ERROR'],
        error_code='VALIDATION_ERROR',
        status_code=HTTP_STATUS['UNPROCESSABLE_ENTITY'],
        details=errors
    )


def unauthorized_response(message=None):
    """
    Create an unauthorized response.
    
    Args:
        message: Error message
        
    Returns:
        tuple: (response, status_code)
    """
    return error_response(
        message=message or API_RESPONSE_MESSAGES['UNAUTHORIZED'],
        error_code='UNAUTHORIZED',
        status_code=HTTP_STATUS['UNAUTHORIZED']
    )


def forbidden_response(message=None):
    """
    Create a forbidden response.
    
    Args:
        message: Error message
        
    Returns:
        tuple: (response, status_code)
    """
    return error_response(
        message=message or API_RESPONSE_MESSAGES['FORBIDDEN'],
        error_code='FORBIDDEN',
        status_code=HTTP_STATUS['FORBIDDEN']
    )


def not_found_response(message=None, resource=None):
    """
    Create a not found response.
    
    Args:
        message: Error message
        resource: Resource name
        
    Returns:
        tuple: (response, status_code)
    """
    if resource:
        message = f"{resource} not found"
    else:
        message = message or API_RESPONSE_MESSAGES['NOT_FOUND']
    
    return error_response(
        message=message,
        error_code='NOT_FOUND',
        status_code=HTTP_STATUS['NOT_FOUND']
    )


def rate_limit_response(message=None, retry_after=None):
    """
    Create a rate limit response.
    
    Args:
        message: Error message
        retry_after: Retry after seconds
        
    Returns:
        tuple: (response, status_code)
    """
    response = error_response(
        message=message or API_RESPONSE_MESSAGES['RATE_LIMITED'],
        error_code='RATE_LIMITED',
        status_code=HTTP_STATUS['TOO_MANY_REQUESTS']
    )
    
    # Add retry-after header
    if retry_after:
        response[0].headers['Retry-After'] = str(retry_after)
    
    return response


def api_response(data=None, message=None, status_code=200, meta=None):
    """
    Create a standardized API response with meta data.
    
    Args:
        data: Response data
        message: Response message
        status_code: HTTP status code
        meta: Additional meta data
        
    Returns:
        tuple: (response, status_code)
    """
    response = {
        'success': status_code < 400,
        'message': message,
        'data': data
    }
    
    if meta is not None:
        response['meta'] = meta
    
    return jsonify(response), status_code


def paginated_response(items, page, per_page, total, **kwargs):
    """
    Create a paginated response.
    
    Args:
        items: List of items
        page: Current page
        per_page: Items per page
        total: Total items
        **kwargs: Additional data
        
    Returns:
        tuple: (response, status_code)
    """
    pages = (total + per_page - 1) // per_page
    
    meta = {
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': pages,
            'has_next': page < pages,
            'has_prev': page > 1
        }
    }
    
    # Merge additional meta data
    if kwargs:
        meta.update(kwargs)
    
    return api_response(
        data=items,
        message=API_RESPONSE_MESSAGES['SUCCESS'],
        meta=meta
    )


def created_response(data=None, message=None, location=None):
    """
    Create a created response.
    
    Args:
        data: Response data
        message: Success message
        location: Resource location URL
        
    Returns:
        tuple: (response, status_code)
    """
    response = success_response(
        data=data,
        message=message or API_RESPONSE_MESSAGES['CREATED'],
        status_code=HTTP_STATUS['CREATED']
    )
    
    if location:
        response[0].headers['Location'] = location
    
    return response


def no_content_response():
    """
    Create a no content response.
    
    Returns:
        tuple: (response, status_code)
    """
    return jsonify({}), HTTP_STATUS['NO_CONTENT']


def conflict_response(message=None):
    """
    Create a conflict response.
    
    Args:
        message: Error message
        
    Returns:
        tuple: (response, status_code)
    """
    return error_response(
        message=message or API_RESPONSE_MESSAGES['DUPLICATE'],
        error_code='CONFLICT',
        status_code=HTTP_STATUS['CONFLICT']
    )


def server_error_response(message=None):
    """
    Create a server error response.
    
    Args:
        message: Error message
        
    Returns:
        tuple: (response, status_code)
    """
    return error_response(
        message=message or API_RESPONSE_MESSAGES['ERROR'],
        error_code='SERVER_ERROR',
        status_code=HTTP_STATUS['INTERNAL_SERVER_ERROR']
    )


def bad_request_response(message=None, details=None):
    """
    Create a bad request response.
    
    Args:
        message: Error message
        details: Error details
        
    Returns:
        tuple: (response, status_code)
    """
    return error_response(
        message=message or API_RESPONSE_MESSAGES['BAD_REQUEST'],
        error_code='BAD_REQUEST',
        status_code=HTTP_STATUS['BAD_REQUEST'],
        details=details
    )