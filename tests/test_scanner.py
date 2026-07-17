# -*- coding: utf-8 -*-

"""
WebShield Scanner - Scanner Tests
Tests for URL validation, scanning, and scanner modules.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from app.models.scan import Scan
from app.models.finding import Finding
from app.scanner.url_validator import URLValidator
from app.scanner.crawler import Crawler
from app.scanner.headers import HeaderChecker
from app.scanner.ssl_check import SSLChecker
from app.scanner.cookies import CookieChecker
from app.scanner.javascript_analyzer import JavaScriptAnalyzer


class TestURLValidator:
    """Test URL validation."""

    def test_valid_https_url(self):
        """Test valid HTTPS URL."""
        validator = URLValidator()
        valid, error = validator.validate('https://example.com')
        assert valid is True
        assert error is None

    def test_valid_http_url(self):
        """Test valid HTTP URL."""
        validator = URLValidator()
        valid, error = validator.validate('http://example.com')
        assert valid is True
        assert error is None

    def test_url_without_scheme(self):
        """Test URL without scheme - should add HTTPS."""
        validator = URLValidator()
        valid, error = validator.validate('example.com')
        assert valid is True
        normalized = validator.normalize_url('example.com')
        assert normalized.startswith('https://')

    def test_invalid_url(self):
        """Test invalid URL."""
        validator = URLValidator()
        valid, error = validator.validate('not-a-url')
        assert valid is False
        assert error is not None

    def test_url_with_suspicious_patterns(self):
        """Test URL with suspicious patterns."""
        validator = URLValidator()
        valid, error = validator.validate('https://example.com/../../../etc/passwd')
        assert valid is False
        assert 'suspicious' in error.lower()

    def test_private_ip_blocked(self):
        """Test private IP is blocked."""
        # Temporarily override block_private_ips
        validator = URLValidator()
        validator.block_private_ips = True
        valid, error = validator.validate('http://192.168.1.1')
        assert valid is False
        assert 'private ip' in error.lower()

    def test_metadata_ip_blocked(self):
        """Test cloud metadata/link-local IP is blocked."""
        validator = URLValidator()
        validator.block_private_ips = True
        valid, error = validator.validate('http://169.254.169.254')
        assert valid is False
        assert 'private ip' in error.lower()

    def test_unspecified_ip_blocked(self):
        """Test unspecified IP is blocked."""
        validator = URLValidator()
        validator.block_private_ips = True
        valid, error = validator.validate('http://0.0.0.0')
        assert valid is False
        assert 'private ip' in error.lower()

    def test_ipv6_loopback_blocked(self):
        """Test IPv6 loopback is blocked."""
        validator = URLValidator()
        validator.block_private_ips = True
        valid, error = validator.validate('http://[::1]')
        assert valid is False
        assert 'private ip' in error.lower()

    def test_hostname_resolving_to_private_ip_blocked(self, monkeypatch):
        """Test DNS rebinding-style private resolution is blocked."""
        import socket

        def fake_getaddrinfo(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]

        monkeypatch.setattr(socket, 'getaddrinfo', fake_getaddrinfo)
        validator = URLValidator()
        validator.block_private_ips = True
        valid, error = validator.validate('https://public.example.test')
        assert valid is False
        assert 'private ip' in error.lower()

    def test_normalize_url(self):
        """Test URL normalization."""
        validator = URLValidator()
        normalized = validator.normalize_url('Example.com/path/')
        assert normalized == 'https://example.com/path'

    def test_get_domain(self):
        """Test domain extraction."""
        validator = URLValidator()
        domain = validator.get_domain('https://sub.example.com/path')
        assert domain == 'sub.example.com'


class TestScanner:
    """Test scanner functionality."""

    def test_validate_url_endpoint(self, client, auth_headers):
        """Test URL validation endpoint."""
        response = client.post('/api/scan/validate',
            headers=auth_headers,
            json={'url': 'https://example.com'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['valid'] is True
        assert data['normalized_url'] == 'https://example.com'

    def test_validate_invalid_url_endpoint(self, client, auth_headers):
        """Test URL validation with invalid URL."""
        response = client.post('/api/scan/validate',
            headers=auth_headers,
            json={'url': 'not-a-url'})

        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False

    def test_start_scan_without_auth(self, client, auth_headers):
        """Test starting scan without authorization confirmation."""
        response = client.post('/api/scan/start',
            headers=auth_headers,
            json={
                'url': 'https://example.com',
                'confirm_authorization': False
            })

        assert response.status_code == 403
        data = response.get_json()
        assert 'authorization' in data['message'].lower()

    def test_start_scan_success(self, client, auth_headers, test_user):
        """Test successful scan start."""
        response = client.post('/api/scan/start',
            headers=auth_headers,
            json={
                'url': 'https://example.com',
                'confirm_authorization': True,
                'crawl_depth': 2,
                'max_pages': 50
            })

        assert response.status_code == 202
        data = response.get_json()
        assert data['success'] is True
        assert 'scan_id' in data

        # Verify scan was created
        scan = Scan.query.get(data['scan_id'])
        assert scan is not None
        assert scan.target_url == 'https://example.com'
        assert scan.user_id == test_user.id
        assert scan.scan_status == 'pending'

    def test_start_scan_rate_limit(self, client, auth_headers, test_user):
        """Test scan rate limiting."""
        # Make multiple scan requests
        for i in range(6):  # Assuming limit is 5 per day for free users
            response = client.post('/api/scan/start',
                headers=auth_headers,
                json={
                    'url': f'https://example{i}.com',
                    'confirm_authorization': True
                })
            if i >= 5:
                assert response.status_code == 429
                break

    def test_get_scan_status(self, client, auth_headers, test_scan):
        """Test getting scan status."""
        response = client.get(f'/api/scan/{test_scan.id}/status',
            headers=auth_headers)

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['scan']['id'] == test_scan.id
        assert data['scan']['target_url'] == test_scan.target_url
        assert data['scan']['scan_status'] == test_scan.scan_status

    def test_cancel_scan(self, client, auth_headers, test_running_scan):
        """Test cancelling a running scan."""
        response = client.post(f'/api/scan/{test_running_scan.id}/cancel',
            headers=auth_headers)

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

        # Verify scan was cancelled
        db.session.refresh(test_running_scan)
        assert test_running_scan.scan_status == 'cancelled'

    def test_cancel_completed_scan(self, client, auth_headers, test_scan):
        """Test cancelling a completed scan."""
        response = client.post(f'/api/scan/{test_scan.id}/cancel',
            headers=auth_headers)

        assert response.status_code == 400
        data = response.get_json()
        assert 'already' in data['message'].lower()

    def test_delete_finished_scan(self, client, auth_headers, test_scan):
        """Test deleting a finished scan."""
        response = client.post(f'/api/scan/{test_scan.id}/delete',
            headers=auth_headers)

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert Scan.query.get(test_scan.id) is None


class TestJavaScriptAnalyzer:
    """Test JavaScript security analysis."""

    def test_detects_localstorage_bearer_and_csrf_gap(self, app):
        """Detect token storage and state-changing fetch without CSRF."""
        analyzer = JavaScriptAnalyzer()
        pages = [{
            'url': 'https://example.com',
            'scripts': [],
            'inline_scripts': [{
                'content': """
                    const token = localStorage.getItem('access_token');
                    fetch('/api/profile', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + token
                        },
                        body: JSON.stringify({ name: 'Ada' })
                    });
                """
            }]
        }]

        result = analyzer.scan(pages, 'https://example.com')
        titles = {finding['title'] for finding in result['findings']}

        assert 'Authentication Token Stored in localStorage' in titles
        assert 'Bearer Authorization Header Built from Browser Storage' in titles
        assert 'State-Changing Fetch Without CSRF Token' in titles

    def test_detects_shadowed_catch_and_stale_validation(self, app):
        """Detect catch shadowing and stale async validation patterns."""
        analyzer = JavaScriptAnalyzer()
        pages = [{
            'url': 'https://example.com',
            'scripts': [],
            'inline_scripts': [{
                'content': """
                    function validateUrl(url) {
                        const error = document.getElementById('url-error');
                        const submitBtn = document.getElementById('scan-btn');
                        fetch('/api/scan/validate', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ url: url })
                        })
                        .then(response => response.json())
                        .then(data => {
                            submitBtn.dataset.urlValid = 'true';
                            submitBtn.dataset.normalizedUrl = data.normalized_url;
                        })
                        .catch(error => {
                            error.textContent = 'Could not validate URL';
                        });
                    }
                    document.getElementById('scan-url').addEventListener('input', debounce(function() {
                        validateUrl(this.value);
                    }, 500));
                    function handleScanSubmit() {
                        const url = document.getElementById('scan-btn').dataset.normalizedUrl;
                    }
                """
            }]
        }]

        result = analyzer.scan(pages, 'https://example.com')
        titles = {finding['title'] for finding in result['findings']}

        assert 'Catch Handler Shadows Error DOM Element' in titles
        assert 'Async Validation Lacks Stale Response Protection' in titles
        assert 'Cached URL Validation Can Become Stale' in titles

    def test_detects_modern_client_side_risks(self, app):
        """Detect modern browser and client-code security patterns."""
        analyzer = JavaScriptAnalyzer()
        pages = [{
            'url': 'https://example.com',
            'scripts': [],
            'inline_scripts': [{
                'content': """
                    const firebaseKey = 'AIzaSyDabcdefghijklmnopqrstuvwxyz123456';
                    const name = new URLSearchParams(location.search).get('name');
                    document.querySelector('#profile').innerHTML = name;
                    window.parent.postMessage({ token: window.token }, '*');
                    window.addEventListener('message', function(event) {
                        document.body.dataset.message = event.data;
                    });
                    const next = new URLSearchParams(location.search).get('next');
                    window.location.href = next;
                    const csrfToken = Math.random().toString(36).slice(2);
                    console.log('token', csrfToken);
                    const claims = JSON.parse(atob(token.split('.')[1]));
                    eval(location.hash.slice(1));
                    //# sourceMappingURL=app.js.map
                """
            }]
        }]

        result = analyzer.scan(pages, 'https://example.com')
        titles = {finding['title'] for finding in result['findings']}

        assert 'Google or Firebase API Key Exposed in JavaScript' in titles
        assert 'URL-Derived Data Written to HTML Sink' in titles
        assert 'postMessage Uses Wildcard Target Origin' in titles
        assert 'message Event Listener Missing Origin Check' in titles
        assert 'Client-Side Redirect Uses URL Parameter' in titles
        assert 'Security-Sensitive Value Uses Math.random' in titles
        assert 'Sensitive Data May Be Logged to Browser Console' in titles
        assert 'JWT Decoded Client-Side Without Verification Context' in titles
        assert 'Dynamic Code Execution in Client JavaScript' in titles
        assert 'JavaScript Source Map Reference Exposed' in titles

    def test_lowercase_function_callback_is_not_dynamic_execution(self, app):
        """Do not confuse normal callback syntax with the Function constructor."""
        analyzer = JavaScriptAnalyzer()
        pages = [{
            'url': 'https://example.com',
            'scripts': [],
            'inline_scripts': [{
                'content': """
                    document.addEventListener('DOMContentLoaded', function () {
                        const main = document.querySelector('main');
                        main.classList.add('ready');
                    });
                """
            }]
        }]

        result = analyzer.scan(pages, 'https://example.com')
        titles = {finding['title'] for finding in result['findings']}

        assert 'Dynamic Code Execution in Client JavaScript' not in titles


class TestHeaderChecker:
    """Test header checking module."""

    def test_check_security_headers(self):
        """Test security header checking."""
        checker = HeaderChecker()

        # Mock page data with headers
        pages = [{
            'url': 'https://example.com',
            'headers': {
                'Content-Security-Policy': "default-src 'self'",
                'Strict-Transport-Security': 'max-age=31536000',
                'X-Frame-Options': 'DENY',
                'X-Content-Type-Options': 'nosniff',
                'Referrer-Policy': 'strict-origin-when-cross-origin'
            }
        }]

        result = checker.check_all_pages(pages)
        assert 'findings' in result
        # Should not have findings for missing headers
        assert len(result['findings']) == 0

    def test_missing_security_headers(self):
        """Test detection of missing security headers."""
        checker = HeaderChecker()

        pages = [{
            'url': 'https://example.com',
            'headers': {
                'Server': 'nginx'
            }
        }]

        result = checker.check_all_pages(pages)
        assert 'findings' in result
        # Should detect missing CSP header
        csp_findings = [f for f in result['findings'] if 'CSP' in f['title']]
        assert len(csp_findings) > 0

    def test_hsts_missing_max_age(self):
        """Test HSTS header without max-age."""
        checker = HeaderChecker()

        pages = [{
            'url': 'https://example.com',
            'headers': {
                'Strict-Transport-Security': 'includeSubDomains'
            }
        }]

        result = checker.check_all_pages(pages)
        # Should find issue with HSTS
        hsts_findings = [f for f in result['findings'] if 'HSTS' in f['title']]
        assert len(hsts_findings) > 0


class TestSSLChecker:
    """Test SSL checker module."""

    @patch('app.scanner.ssl_check.ssl.create_default_context')
    def test_valid_ssl(self, mock_ssl, test_scan):
        """Test SSL validation for valid certificate."""
        # Mock SSL context
        mock_context = MagicMock()
        mock_ssl.return_value = mock_context

        mock_sock = MagicMock()
        mock_context.wrap_socket.return_value = mock_sock
        mock_sock.getpeercert.return_value = {
            'subject': [[('commonName', 'example.com')]],
            'issuer': [[('commonName', 'Let\'s Encrypt')]],
            'notAfter': 'Jan 15 23:59:59 2025 GMT'
        }

        checker = SSLChecker()
        result = checker.check('https://example.com')

        assert result['uses_https'] is True
        assert 'findings' in result
        # Should not have critical findings for valid cert
        critical = [f for f in result['findings'] if f['severity'] == 'critical']
        assert len(critical) == 0

    @patch('app.scanner.ssl_check.ssl.create_default_context')
    def test_expired_ssl(self, mock_ssl):
        """Test SSL validation for expired certificate."""
        mock_context = MagicMock()
        mock_ssl.return_value = mock_context

        mock_sock = MagicMock()
        mock_context.wrap_socket.return_value = mock_sock
        mock_sock.getpeercert.return_value = {
            'subject': [[('commonName', 'example.com')]],
            'issuer': [[('commonName', 'Let\'s Encrypt')]],
            'notAfter': 'Jan 15 23:59:59 2020 GMT'  # Expired
        }

        checker = SSLChecker()
        result = checker.check('https://example.com')

        # Should have expired certificate finding
        expired = [f for f in result['findings'] if 'expired' in f['title'].lower()]
        assert len(expired) > 0

    def test_http_url(self):
        """Test SSL check for HTTP URL."""
        checker = SSLChecker()
        result = checker.check('http://example.com')

        assert result['uses_https'] is False
        findings = result.get('findings', [])
        assert len(findings) > 0
        assert 'HTTPS' in findings[0]['title']


class TestCookieChecker:
    """Test cookie checker module."""

    def test_secure_cookie(self):
        """Test cookie with all security flags."""
        checker = CookieChecker()

        pages = [{
            'url': 'https://example.com',
            'headers': {
                'Set-Cookie': 'sessionid=abc123; Secure; HttpOnly; SameSite=Strict'
            }
        }]

        result = checker.check_all_pages(pages)
        # Should not have cookie findings for secure cookie
        cookie_findings = [f for f in result['findings'] if 'cookie' in f['title'].lower()]
        assert len(cookie_findings) == 0

    def test_missing_secure_flag(self):
        """Test cookie without Secure flag."""
        checker = CookieChecker()

        pages = [{
            'url': 'https://example.com',
            'headers': {
                'Set-Cookie': 'sessionid=abc123; HttpOnly'
            }
        }]

        result = checker.check_all_pages(pages)
        # Should detect missing Secure flag
        secure_findings = [f for f in result['findings'] if 'Secure' in f['title']]
        assert len(secure_findings) > 0

    def test_missing_httponly_flag(self):
        """Test cookie without HttpOnly flag."""
        checker = CookieChecker()

        pages = [{
            'url': 'https://example.com',
            'headers': {
                'Set-Cookie': 'sessionid=abc123; Secure'
            }
        }]

        result = checker.check_all_pages(pages)
        # Should detect missing HttpOnly flag
        httponly_findings = [f for f in result['findings'] if 'HttpOnly' in f['title']]
        assert len(httponly_findings) > 0

    def test_missing_samesite(self):
        """Test cookie without SameSite attribute."""
        checker = CookieChecker()

        pages = [{
            'url': 'https://example.com',
            'headers': {
                'Set-Cookie': 'sessionid=abc123; Secure; HttpOnly'
            }
        }]

        result = checker.check_all_pages(pages)
        # Should detect missing SameSite
        samesite_findings = [f for f in result['findings'] if 'SameSite' in f['title']]
        assert len(samesite_findings) > 0
