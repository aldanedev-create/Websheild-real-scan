# -*- coding: utf-8 -*-

"""
WebShield Scanner - Form Analyzer
Analyzes forms for security issues.
"""

import re
from urllib.parse import urlparse, urljoin
from flask import current_app


class FormAnalyzer:
    """Analyzes forms for security issues."""
    
    def __init__(self):
        """Initialize the form analyzer."""
        pass
    
    def analyze_all_pages(self, pages):
        """
        Analyze forms on all pages.
        
        Args:
            pages: List of page data
            
        Returns:
            dict: Form analysis results
        """
        if not pages:
            return {'findings': [], 'forms': []}
        
        findings = []
        forms = []
        
        for page in pages:
            page_forms = page.get('forms', [])
            if not page_forms:
                continue
            
            for form in page_forms:
                form_data = {
                    'url': page.get('url'),
                    'action': form.get('action'),
                    'method': form.get('method'),
                    'has_password': form.get('has_password', False),
                    'has_file_upload': form.get('has_file_upload', False),
                    'input_count': len(form.get('inputs', []))
                }
                forms.append(form_data)
                
                # Check form security
                form_findings = self._check_form_security(form, page.get('url'), page.get('html') or '')
                findings.extend(form_findings)
        
        # Remove duplicate findings
        unique_findings = []
        seen = set()
        for finding in findings:
            key = (finding['title'], finding.get('url', ''))
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return {
            'findings': unique_findings,
            'forms': forms,
            'summary': {
                'total_forms': len(forms),
                'forms_with_password': sum(1 for f in forms if f.get('has_password')),
                'forms_with_file_upload': sum(1 for f in forms if f.get('has_file_upload')),
                'forms_without_csrf': self._count_forms_without_csrf(forms, pages)
            }
        }
    
    def _check_form_security(self, form, url, html):
        """
        Check form security issues.
        
        Args:
            form: Form data
            url: Page URL
            html: Page HTML
            
        Returns:
            list: Form security findings
        """
        findings = []
        
        # Check for password fields without HTTPS
        if form.get('has_password', False) and not url.startswith('https://'):
            findings.append({
                'title': 'Login Form Uses HTTP Instead of HTTPS',
                'severity': 'critical',
                'url': url,
                'description': 'A login form with password field is served over HTTP, making credentials vulnerable to interception.',
                'evidence': f"Form action: {form.get('action')}",
                'recommendation': 'Use HTTPS for all forms that handle sensitive data.',
                'cwe_id': 'CWE-311',
                'owasp_category': 'Cryptographic Failures'
            })
        
        # Check for insecure form submission
        action = form.get('action', '')
        if action and not action.startswith(('https://', '//')):
            if form.get('has_password', False):
                findings.append({
                    'title': 'Login Form Submits to HTTP Endpoint',
                    'severity': 'high',
                    'url': url,
                    'description': 'Login form submits data to a non-HTTPS endpoint.',
                    'evidence': f"Form action: {action}",
                    'recommendation': 'Ensure form submission uses HTTPS.',
                    'cwe_id': 'CWE-311',
                    'owasp_category': 'Cryptographic Failures'
                })
        
        # Check for CSRF token in forms with sensitive data
        if form.get('has_password', False) or form.get('has_file_upload', False):
            if not self._has_csrf_token(form, html):
                findings.append({
                    'title': 'Form Missing CSRF Protection',
                    'severity': 'medium',
                    'url': url,
                    'description': 'The form lacks CSRF protection tokens, making it vulnerable to CSRF attacks.',
                    'evidence': 'No CSRF token found in form or hidden inputs',
                    'recommendation': 'Implement CSRF tokens for all forms that perform state-changing actions.',
                    'cwe_id': 'CWE-352',
                    'owasp_category': 'Insecure Design'
                })
        
        # Check for file upload forms with size limits
        if form.get('has_file_upload', False):
            # Check if form has enctype
            if 'enctype' not in form or form.get('enctype', '') != 'multipart/form-data':
                findings.append({
                    'title': 'File Upload Form Missing Correct Encoding',
                    'severity': 'low',
                    'url': url,
                    'description': 'File upload form does not use multipart/form-data encoding.',
                    'evidence': f"Form encoding: {form.get('enctype', 'application/x-www-form-urlencoded')}",
                    'recommendation': 'Set enctype="multipart/form-data" for file upload forms.',
                    'cwe_id': 'CWE-20',
                    'owasp_category': 'Security Misconfiguration'
                })
        
        return findings
    
    def _has_csrf_token(self, form, html):
        """
        Check if a form has CSRF protection.
        
        Args:
            form: Form data
            html: Page HTML
            
        Returns:
            bool: True if CSRF token found
        """
        if not html:
            return False
        
        # Look for common CSRF token patterns
        csrf_patterns = [
            r'csrf', r'csrf_token', r'csrfmiddlewaretoken',
            r'_token', r'__token', r'xsrf', r'xsrf_token',
            r'XSRF-TOKEN', r'x-csrf-token',
            r'csrf-token', r'csrf-token',
            r'<?= csrf_field\(\) ?>', r'{% csrf_token %}'
        ]
        
        for pattern in csrf_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        # Check for hidden input with name containing token patterns
        if form.get('inputs'):
            for input_field in form.get('inputs', []):
                name = input_field.get('name', '').lower()
                for pattern in csrf_patterns:
                    if pattern in name.lower():
                        return True
        
        return False
    
    def _count_forms_without_csrf(self, forms, pages):
        """
        Count forms without CSRF protection.
        
        Args:
            forms: Form data list
            pages: Page data list
            
        Returns:
            int: Count of forms without CSRF
        """
        count = 0
        for page in pages:
            for form in page.get('forms', []):
                if not self._has_csrf_token(form, page.get('html') or ''):
                    count += 1
        return count
