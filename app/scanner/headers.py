# -*- coding: utf-8 -*-

"""
WebShield Scanner - Header Checker
Analyzes HTTP security headers.
"""

import re

from flask import current_app


class HeaderChecker:
    """Checks for proper HTTP security headers."""
    
    def __init__(self):
        """Initialize the header checker."""
        self.important_headers = {
            'content-security-policy': {
                'name': 'Content-Security-Policy',
                'severity': 'medium',
                'description': 'CSP helps prevent XSS and data injection attacks.',
                'recommendation': 'Implement a Content-Security-Policy header to restrict resources.',
                'cwe_id': 'CWE-693',
                'owasp_category': 'Security Misconfiguration'
            },
            'strict-transport-security': {
                'name': 'Strict-Transport-Security',
                'severity': 'medium',
                'description': 'HSTS enforces HTTPS connections.',
                'recommendation': 'Add HSTS header to enforce HTTPS and prevent SSL stripping.',
                'cwe_id': 'CWE-319',
                'owasp_category': 'Cryptographic Failures'
            },
            'x-frame-options': {
                'name': 'X-Frame-Options',
                'severity': 'medium',
                'description': 'X-Frame-Options prevents clickjacking attacks.',
                'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN.',
                'cwe_id': 'CWE-1021',
                'owasp_category': 'Security Misconfiguration'
            },
            'x-content-type-options': {
                'name': 'X-Content-Type-Options',
                'severity': 'low',
                'description': 'Prevents MIME type sniffing attacks.',
                'recommendation': 'Set X-Content-Type-Options to nosniff.',
                'cwe_id': 'CWE-346',
                'owasp_category': 'Security Misconfiguration'
            },
            'referrer-policy': {
                'name': 'Referrer-Policy',
                'severity': 'low',
                'description': 'Controls how much referrer information is sent.',
                'recommendation': 'Set Referrer-Policy to strict-origin-when-cross-origin or similar.',
                'cwe_id': 'CWE-200',
                'owasp_category': 'Information Disclosure'
            },
            'permissions-policy': {
                'name': 'Permissions-Policy',
                'severity': 'low',
                'description': 'Controls which browser features can be used.',
                'recommendation': 'Set Permissions-Policy to restrict unnecessary features.',
                'cwe_id': 'CWE-693',
                'owasp_category': 'Security Misconfiguration'
            }
        }
    
    def check_all_pages(self, pages):
        """
        Check headers on all pages.
        
        Args:
            pages: List of page data
            
        Returns:
            dict: Header analysis results
        """
        if not pages:
            return {'findings': [], 'summary': {'total_headers_checked': 0}}
        
        findings = []
        pages_checked = 0
        headers_present = {}
        
        for page in pages:
            headers = page.get('headers', {})
            pages_checked += 1
            
            for header_key, header_info in self.important_headers.items():
                # Check if header is present
                present = self._check_header_presence(headers, header_key)
                
                if not present:
                    # Create finding if header is missing
                    finding = {
                        'title': f"Missing {header_info['name']} Header",
                        'severity': header_info['severity'],
                        'url': page.get('url'),
                        'description': f"The {header_info['name']} header is missing on this page. {header_info['description']}",
                        'evidence': f"Header '{header_info['name']}' not found in response headers.",
                        'recommendation': header_info['recommendation'],
                        'cwe_id': header_info['cwe_id'],
                        'owasp_category': header_info['owasp_category']
                    }
                    findings.append(finding)
                else:
                    # Check if header is properly configured
                    header_value = self._get_header_value(headers, header_key)
                    if header_value:
                        header_issues = self._check_header_value(header_key, header_value)
                        if header_issues:
                            findings.extend(header_issues)
            
            # Update headers present count
            for header in self.important_headers.keys():
                if self._check_header_presence(headers, header):
                    headers_present[header] = headers_present.get(header, 0) + 1
        
        # Remove duplicate findings (same title and URL)
        unique_findings = []
        seen = set()
        for finding in findings:
            key = (finding['title'], finding.get('url', ''))
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return {
            'findings': unique_findings,
            'summary': {
                'total_pages_checked': pages_checked,
                'headers_present': headers_present,
                'missing_headers': [h for h in self.important_headers.keys() if h not in headers_present]
            }
        }
    
    def _check_header_presence(self, headers, header_key):
        """
        Check if a header is present (case-insensitive).
        
        Args:
            headers: Dict of headers
            header_key: Header key to check
            
        Returns:
            bool: True if present
        """
        for key in headers.keys():
            if key.lower() == header_key.lower():
                return True
        return False
    
    def _get_header_value(self, headers, header_key):
        """
        Get header value (case-insensitive).
        
        Args:
            headers: Dict of headers
            header_key: Header key to get
            
        Returns:
            str: Header value or None
        """
        for key, value in headers.items():
            if key.lower() == header_key.lower():
                return value
        return None
    
    def _check_header_value(self, header_key, header_value):
        """
        Check if header value is properly configured.
        
        Args:
            header_key: Header key
            header_value: Header value
            
        Returns:
            list: Findings for header issues
        """
        findings = []
        
        if header_key == 'strict-transport-security':
            if 'max-age' not in header_value.lower():
                findings.append({
                    'title': 'HSTS Header Missing max-age Directive',
                    'severity': 'medium',
                    'description': 'HSTS header does not include max-age directive.',
                    'evidence': f"Header value: {header_value}",
                    'recommendation': 'Add max-age directive with appropriate value (minimum 31536000 for 1 year).',
                    'cwe_id': 'CWE-319',
                    'owasp_category': 'Cryptographic Failures'
                })
            elif not re.search(r'max-age\s*=\s*[1-9]\d{3,}', header_value):
                findings.append({
                    'title': 'HSTS Header max-age Too Short',
                    'severity': 'low',
                    'description': 'HSTS header max-age is too short or missing.',
                    'evidence': f"Header value: {header_value}",
                    'recommendation': 'Set max-age to at least 31536000 (1 year).',
                    'cwe_id': 'CWE-319',
                    'owasp_category': 'Cryptographic Failures'
                })
        
        elif header_key == 'x-frame-options':
            if header_value.lower() not in ['deny', 'sameorigin']:
                findings.append({
                    'title': 'X-Frame-Options Header Not Set to DENY or SAMEORIGIN',
                    'severity': 'medium',
                    'description': 'X-Frame-Options should be set to DENY or SAMEORIGIN.',
                    'evidence': f"Header value: {header_value}",
                    'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN.',
                    'cwe_id': 'CWE-1021',
                    'owasp_category': 'Security Misconfiguration'
                })
        
        elif header_key == 'x-content-type-options':
            if header_value.lower() != 'nosniff':
                findings.append({
                    'title': 'X-Content-Type-Options Not Set to nosniff',
                    'severity': 'low',
                    'description': 'X-Content-Type-Options should be set to nosniff.',
                    'evidence': f"Header value: {header_value}",
                    'recommendation': 'Set X-Content-Type-Options to nosniff.',
                    'cwe_id': 'CWE-346',
                    'owasp_category': 'Security Misconfiguration'
                })
        
        return findings
