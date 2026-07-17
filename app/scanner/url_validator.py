# -*- coding: utf-8 -*-

"""
WebShield Scanner - URL Validator
Validates and normalizes URLs for scanning.
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse, urljoin
from flask import current_app, has_app_context


class URLValidator:
    """Validates and normalizes URLs for scanning."""
    
    def __init__(self):
        """Initialize URL validator."""
        if has_app_context():
            self.block_private_ips = current_app.config.get('BLOCK_PRIVATE_IPS', True)
            self.allowed_domains = current_app.config.get('ALLOWED_SCAN_DOMAINS', [])
        else:
            self.block_private_ips = True
            self.allowed_domains = []
    
    def validate(self, url):
        """
        Validate a URL for scanning.
        
        Args:
            url: The URL to validate
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if not url:
            return False, "URL is required"
        
        url = url.strip()
        
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception:
            return False, "Invalid URL format"
        
        # Check scheme
        if parsed.scheme not in ['http', 'https']:
            return False, "URL must use HTTP or HTTPS protocol"
        
        # Check hostname
        if not parsed.netloc:
            return False, "Missing hostname in URL"
        if not self._has_valid_hostname(parsed.hostname):
            return False, "Invalid hostname in URL"
        
        # Check for malformed URL
        if len(url) > 500:
            return False, "URL is too long (maximum 500 characters)"
        
        # Check for suspicious characters
        suspicious_patterns = [
            r'[<>"{}|\\^`]',  # Dangerous characters
            r'//.*//',  # Double slashes
            r'\.\./',  # Directory traversal
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url):
                return False, "URL contains suspicious characters or patterns"
        
        # Block private, local, metadata, and otherwise non-public targets.
        if self.block_private_ips:
            if not self._is_public_ip(parsed.hostname):
                return False, "Scanning private IP addresses is not allowed"
        
        # Check allowed domains if configured
        if self.allowed_domains:
            if not self._is_allowed_domain(parsed.hostname):
                return False, f"Domain not in allowed list: {parsed.hostname}"
        
        return True, None
    
    def normalize_url(self, url):
        """
        Normalize a URL by adding scheme, removing trailing slashes, etc.
        
        Args:
            url: The URL to normalize
            
        Returns:
            str: Normalized URL
        """
        url = url.strip()
        
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Parse URL
        parsed = urlparse(url)
        
        # Ensure scheme is lowercase
        scheme = parsed.scheme.lower()
        
        # Ensure hostname is lowercase
        netloc = parsed.netloc.lower()
        
        # Reconstruct URL
        path = '' if parsed.path in ('', '/') else parsed.path
        normalized = urljoin(f"{scheme}://{netloc}", path)
        
        # Add query string if present
        if parsed.query:
            normalized += f"?{parsed.query}"
        
        # Add fragment if present
        if parsed.fragment:
            normalized += f"#{parsed.fragment}"
        
        # Remove trailing slash
        if normalized.endswith('/'):
            normalized = normalized[:-1]
        
        return normalized
    
    def _is_public_ip(self, hostname):
        """
        Check if a hostname resolves to a public IP address.
        
        Args:
            hostname: The hostname to check
            
        Returns:
            bool: True if public IP, False if private
        """
        if not hostname:
            return False

        try:
            return self._is_public_address(ipaddress.ip_address(hostname))
        except ValueError:
            pass

        try:
            resolved = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except Exception:
            # Preserve existing behavior for DNS failures so transient resolver
            # issues do not block otherwise syntactically valid public domains.
            return True

        addresses = {
            item[4][0]
            for item in resolved
            if item and len(item) >= 5 and item[4]
        }

        if not addresses:
            return False

        for address in addresses:
            try:
                if not self._is_public_address(ipaddress.ip_address(address)):
                    return False
            except ValueError:
                return False

        return True

    def _is_public_address(self, ip_obj):
        """Return True only for globally routable addresses."""
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )

    def _has_valid_hostname(self, hostname):
        """Check basic hostname syntax before network resolution."""
        if not hostname:
            return False

        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            pass

        if hostname.lower() == 'localhost':
            return True

        if '.' not in hostname:
            return False

        hostname_pattern = re.compile(
            r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
            r'(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$'
        )
        return bool(hostname_pattern.match(hostname))
    
    def _is_allowed_domain(self, hostname):
        """
        Check if a hostname is in the allowed domains list.
        
        Args:
            hostname: The hostname to check
            
        Returns:
            bool: True if allowed, False if not
        """
        if not self.allowed_domains:
            return True
        
        for domain in self.allowed_domains:
            domain = domain.strip().lower()
            if hostname == domain or hostname.endswith(f".{domain}"):
                return True
        
        return False
    
    def get_domain(self, url):
        """
        Extract domain from URL.
        
        Args:
            url: The URL to extract from
            
        Returns:
            str: Domain name
        """
        parsed = urlparse(url)
        return parsed.netloc
    
    def get_base_url(self, url):
        """
        Get base URL (scheme + domain).
        
        Args:
            url: The URL
            
        Returns:
            str: Base URL
        """
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def is_same_domain(self, url1, url2):
        """
        Check if two URLs are from the same domain.
        
        Args:
            url1: First URL
            url2: Second URL
            
        Returns:
            bool: True if same domain
        """
        domain1 = self.get_domain(url1)
        domain2 = self.get_domain(url2)
        return domain1 == domain2
    
    def is_secure_url(self, url):
        """
        Check if URL uses HTTPS.
        
        Args:
            url: The URL to check
            
        Returns:
            bool: True if HTTPS
        """
        return url.lower().startswith('https://')
