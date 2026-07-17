# -*- coding: utf-8 -*-

"""
WebShield Scanner - Cookie Checker
Analyzes cookie security settings.
"""

import re
from flask import current_app


class CookieChecker:
    """Checks cookie security flags and configuration."""
    
    def __init__(self):
        """Initialize the cookie checker."""
        pass
    
    def check_all_pages(self, pages):
        """
        Check cookies on all pages.
        
        Args:
            pages: List of page data
            
        Returns:
            dict: Cookie analysis results
        """
        if not pages:
            return {'findings': [], 'summary': {'total_cookies_checked': 0}}
        
        findings = []
        cookies_checked = set()
        cookies_present = []
        
        for page in pages:
            headers = page.get('headers', {})
            
            # Look for Set-Cookie headers
            set_cookie_headers = self._get_cookie_headers(headers)
            
            for cookie_header in set_cookie_headers:
                cookie_parsed = self._parse_cookie(cookie_header)
                cookie_key = cookie_parsed.get('name', '')
                cookie_domain = cookie_parsed.get('domain', '')
                cookie_key = f"{cookie_key}@{cookie_domain}"
                
                if cookie_key not in cookies_checked:
                    cookies_checked.add(cookie_key)
                    cookies_present.append(cookie_parsed)
                    
                    # Check cookie security
                    cookie_findings = self._check_cookie_security(cookie_parsed, page.get('url'))
                    findings.extend(cookie_findings)
        
        return {
            'findings': findings,
            'cookies': cookies_present,
            'summary': {
                'total_cookies': len(cookies_present),
                'secure_cookies': sum(1 for c in cookies_present if c.get('secure')),
                'httponly_cookies': sum(1 for c in cookies_present if c.get('httponly')),
                'samesite_cookies': sum(1 for c in cookies_present if c.get('samesite'))
            }
        }
    
    def _get_cookie_headers(self, headers):
        """
        Extract Set-Cookie headers (case-insensitive).
        
        Args:
            headers: Dict of headers
            
        Returns:
            list: Set-Cookie header values
        """
        cookie_headers = []
        for key, value in headers.items():
            if key.lower() == 'set-cookie':
                # Handle multiple cookies in one header
                if isinstance(value, list):
                    cookie_headers.extend(value)
                else:
                    cookie_headers.append(value)
        return cookie_headers
    
    def _parse_cookie(self, cookie_string):
        """
        Parse a cookie string into components.
        
        Args:
            cookie_string: Cookie header value
            
        Returns:
            dict: Parsed cookie data
        """
        cookie = {
            'name': '',
            'value': '',
            'domain': '',
            'path': '/',
            'secure': False,
            'httponly': False,
            'samesite': None,
            'max_age': None,
            'expires': None,
            'raw': cookie_string
        }
        
        # Parse cookie parts
        parts = cookie_string.split(';')
        
        # First part is name=value
        if parts:
            name_value = parts[0].strip()
            if '=' in name_value:
                cookie['name'], cookie['value'] = name_value.split('=', 1)
            else:
                cookie['name'] = name_value
        
        # Parse attributes
        for part in parts[1:]:
            part = part.strip()
            if not part:
                continue
            
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.lower().strip()
                value = value.strip()
                
                if key == 'domain':
                    cookie['domain'] = value
                elif key == 'path':
                    cookie['path'] = value
                elif key == 'max-age':
                    cookie['max_age'] = value
                elif key == 'expires':
                    cookie['expires'] = value
                elif key == 'samesite':
                    cookie['samesite'] = value.lower()
            else:
                key = part.lower()
                if key == 'secure':
                    cookie['secure'] = True
                elif key == 'httponly':
                    cookie['httponly'] = True
        
        return cookie
    
    def _check_cookie_security(self, cookie, url):
        """
        Check cookie security flags.
        
        Args:
            cookie: Parsed cookie data
            url: The URL where the cookie was found
            
        Returns:
            list: Findings for cookie issues
        """
        findings = []
        
        # Check Secure flag
        if not cookie.get('secure', False):
            findings.append({
                'title': f"Cookie '{cookie['name']}' Missing Secure Flag",
                'severity': 'high',
                'url': url,
                'description': f"The cookie '{cookie['name']}' does not have the Secure flag set, making it vulnerable to interception over HTTP connections.",
                'evidence': f"Cookie '{cookie['name']}' is missing the Secure flag",
                'recommendation': 'Set the Secure flag on all cookies to ensure they are only sent over HTTPS.',
                'cwe_id': 'CWE-614',
                'owasp_category': 'Sensitive Data Exposure'
            })
        
        # Check HttpOnly flag
        if not cookie.get('httponly', False):
            findings.append({
                'title': f"Cookie '{cookie['name']}' Missing HttpOnly Flag",
                'severity': 'high',
                'url': url,
                'description': f"The cookie '{cookie['name']}' does not have the HttpOnly flag set, making it accessible to JavaScript and increasing XSS risk.",
                'evidence': f"Cookie '{cookie['name']}' is missing the HttpOnly flag",
                'recommendation': 'Set the HttpOnly flag on session cookies to prevent client-side script access.',
                'cwe_id': 'CWE-1004',
                'owasp_category': 'Sensitive Data Exposure'
            })
        
        # Check SameSite attribute
        samesite = cookie.get('samesite')
        if not samesite:
            findings.append({
                'title': f"Cookie '{cookie['name']}' Missing SameSite Attribute",
                'severity': 'medium',
                'url': url,
                'description': f"The cookie '{cookie['name']}' does not have the SameSite attribute set, making it vulnerable to CSRF attacks.",
                'evidence': f"Cookie '{cookie['name']}' is missing SameSite attribute",
                'recommendation': 'Set SameSite attribute to Lax or Strict for session cookies.',
                'cwe_id': 'CWE-352',
                'owasp_category': 'Security Misconfiguration'
            })
        elif samesite.lower() == 'none' and not cookie.get('secure', False):
            findings.append({
                'title': f"Cookie '{cookie['name']}' Uses SameSite=None Without Secure Flag",
                'severity': 'medium',
                'url': url,
                'description': f"The cookie '{cookie['name']}' uses SameSite=None but does not have the Secure flag set.",
                'evidence': f"Cookie '{cookie['name']}' has SameSite=None but missing Secure flag",
                'recommendation': 'When using SameSite=None, the Secure flag must also be set.',
                'cwe_id': 'CWE-352',
                'owasp_category': 'Security Misconfiguration'
            })
        
        # Check for session cookies without expiration
        if not cookie.get('max_age') and not cookie.get('expires'):
            if cookie.get('name', '').lower() in ['session', 'sessionid', 'jsessionid', 'phpsessid']:
                findings.append({
                    'title': f"Session Cookie '{cookie['name']}' Has No Expiration",
                    'severity': 'medium',
                    'url': url,
                    'description': f"The session cookie '{cookie['name']}' does not have an expiration set, making it a session cookie that may persist indefinitely.",
                    'evidence': f"Cookie '{cookie['name']}' has no max-age or expires attribute",
                    'recommendation': 'Set appropriate expiration for session cookies to limit session lifetime.',
                    'cwe_id': 'CWE-384',
                    'owasp_category': 'Session Management'
                })
        
        return findings