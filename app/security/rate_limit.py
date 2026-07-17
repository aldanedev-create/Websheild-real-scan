# -*- coding: utf-8 -*-

"""
WebShield Scanner - Rate Limiter
Provides rate limiting functionality to prevent abuse.
"""

import time
from collections import defaultdict
from datetime import datetime
from flask import current_app


class RateLimiter:
    """
    Rate limiter implementation with in-memory storage.
    In production, use Redis for distributed rate limiting.
    """
    
    def __init__(self):
        """Initialize the rate limiter."""
        # In-memory storage (for development)
        # In production, use Redis
        self._storage = defaultdict(lambda: defaultdict(list))
        self._enabled = current_app.config.get('RATELIMIT_ENABLED', True)
    
    def check_rate_limit(self, client_id, action, limit, period=3600):
        """
        Check if a client has exceeded the rate limit.
        
        Args:
            client_id: Unique client identifier (IP, user ID, etc.)
            action: Action being rate limited
            limit: Maximum number of requests in the period
            period: Time period in seconds
            
        Returns:
            tuple: (allowed, remaining, reset_time)
        """
        if not self._enabled:
            return True, float('inf'), 0
        
        # Clean expired entries
        self._clean_expired(client_id, action, period)
        
        # Get request history
        history = self._storage[client_id][action]
        
        # Check if limit exceeded
        if len(history) >= limit:
            # Calculate reset time
            oldest = history[0] if history else time.time()
            reset_time = int(oldest + period - time.time())
            return False, 0, max(0, reset_time)
        
        # Add current request
        history.append(time.time())
        
        # Calculate remaining
        remaining = limit - len(history)
        reset_time = 0
        
        if history:
            oldest = history[0]
            reset_time = int(oldest + period - time.time())
        
        return True, remaining, max(0, reset_time)
    
    def _clean_expired(self, client_id, action, period):
        """
        Remove expired entries from history.
        
        Args:
            client_id: Client identifier
            action: Action being rate limited
            period: Time period in seconds
        """
        if client_id not in self._storage:
            return
        
        if action not in self._storage[client_id]:
            return
        
        now = time.time()
        history = self._storage[client_id][action]
        
        # Keep only entries within the period
        self._storage[client_id][action] = [
            t for t in history if now - t < period
        ]
        
        # Clean up empty actions
        if not self._storage[client_id][action]:
            del self._storage[client_id][action]
        
        # Clean up empty clients
        if not self._storage[client_id]:
            del self._storage[client_id]
    
    def reset_rate_limit(self, client_id, action=None):
        """
        Reset rate limit for a client.
        
        Args:
            client_id: Client identifier
            action: Specific action to reset (optional)
        """
        if action:
            if client_id in self._storage and action in self._storage[client_id]:
                del self._storage[client_id][action]
        else:
            if client_id in self._storage:
                del self._storage[client_id]
    
    def get_rate_limit_status(self, client_id, action, limit, period=3600):
        """
        Get current rate limit status.
        
        Args:
            client_id: Client identifier
            action: Action being rate limited
            limit: Maximum number of requests
            period: Time period in seconds
            
        Returns:
            dict: Rate limit status
        """
        self._clean_expired(client_id, action, period)
        
        history = self._storage.get(client_id, {}).get(action, [])
        remaining = max(0, limit - len(history))
        
        reset_time = 0
        if history:
            oldest = history[0]
            reset_time = int(oldest + period - time.time())
        
        return {
            'limit': limit,
            'remaining': remaining,
            'reset_time': max(0, reset_time),
            'total_requests': len(history)
        }


class RateLimitRule:
    """
    Defines a rate limiting rule.
    """
    
    def __init__(self, endpoint, limit, period=3600, method=None):
        """
        Initialize a rate limit rule.
        
        Args:
            endpoint: Endpoint name or pattern
            limit: Maximum number of requests
            period: Time period in seconds
            method: HTTP method (optional)
        """
        self.endpoint = endpoint
        self.limit = limit
        self.period = period
        self.method = method


# Predefined rate limit rules
RATE_LIMIT_RULES = {
    'register': RateLimitRule('auth.register', 5, 3600),  # 5 registrations per hour
    'login': RateLimitRule('auth.login', 10, 300),  # 10 login attempts per 5 minutes
    'forgot_password': RateLimitRule('auth.forgot_password', 3, 3600),  # 3 requests per hour
    'start_scan': RateLimitRule('scan.start_scan', 50, 10800),  # 50 scans per 3 hours
    'api_request': RateLimitRule('api.default', 100, 3600),  # 100 API requests per hour
}


def get_rate_limit_rule(action):
    """
    Get a rate limit rule by action.
    
    Args:
        action: Action name
        
    Returns:
        RateLimitRule: Rate limit rule or None
    """
    return RATE_LIMIT_RULES.get(action)
