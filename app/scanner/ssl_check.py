# -*- coding: utf-8 -*-

"""
WebShield Scanner - SSL/TLS Checker
Validates SSL/TLS certificates and configuration.
"""

import ssl
import socket
import datetime
import re
from urllib.parse import urlparse
import requests
from flask import current_app


class SSLChecker:
    """Checks SSL/TLS certificate validity and configuration."""
    
    def __init__(self):
        """Initialize the SSL checker."""
        self.session = requests.Session()
        self.timeout = current_app.config.get('REQUEST_TIMEOUT', 30)
    
    def check(self, url):
        """
        Check SSL/TLS for the given URL.
        
        Args:
            url: The URL to check
            
        Returns:
            dict: SSL analysis results
        """
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        findings = []
        
        # Check if URL uses HTTPS
        if parsed.scheme != 'https':
            return {
                'uses_https': False,
                'findings': [{
                    'title': 'Website Does Not Use HTTPS',
                    'severity': 'high',
                    'description': 'The website is not using HTTPS, making all data transmissions insecure.',
                    'evidence': f"URL uses {parsed.scheme} instead of HTTPS",
                    'recommendation': 'Enable HTTPS by installing an SSL/TLS certificate and redirecting HTTP to HTTPS.',
                    'cwe_id': 'CWE-311',
                    'owasp_category': 'Cryptographic Failures'
                }]
            }
        
        # Get certificate information
        cert_info = self._get_cert_info(hostname, port)
        
        if not cert_info:
            return {
                'uses_https': True,
                'findings': [{
                    'title': 'Unable to Retrieve SSL Certificate',
                    'severity': 'high',
                    'description': 'Could not retrieve SSL certificate information.',
                    'evidence': f"Unable to connect to {hostname}:{port}",
                    'recommendation': 'Check SSL/TLS configuration and ensure certificate is valid.',
                    'cwe_id': 'CWE-295',
                    'owasp_category': 'Cryptographic Failures'
                }]
            }
        
        # Check certificate validity
        if not cert_info.get('valid', False):
            findings.append({
                'title': 'Invalid SSL Certificate',
                'severity': 'critical',
                'description': 'SSL certificate is invalid or self-signed.',
                'evidence': f"Certificate validation failed: {cert_info.get('error', 'Unknown error')}",
                'recommendation': 'Install a valid SSL certificate from a trusted Certificate Authority.',
                'cwe_id': 'CWE-295',
                'owasp_category': 'Cryptographic Failures'
            })
        
        # Check expiration
        if cert_info.get('expires_at'):
            days_until_expiry = (cert_info['expires_at'] - datetime.datetime.utcnow()).days
            
            if days_until_expiry < 0:
                findings.append({
                    'title': 'SSL Certificate Expired',
                    'severity': 'critical',
                    'description': 'SSL certificate has already expired.',
                    'evidence': f"Certificate expired on {cert_info['expires_at'].strftime('%Y-%m-%d')}",
                    'recommendation': 'Renew the SSL certificate immediately.',
                    'cwe_id': 'CWE-295',
                    'owasp_category': 'Cryptographic Failures'
                })
            elif days_until_expiry < 7:
                findings.append({
                    'title': 'SSL Certificate About to Expire',
                    'severity': 'high',
                    'description': 'SSL certificate expires within 7 days.',
                    'evidence': f"Certificate expires on {cert_info['expires_at'].strftime('%Y-%m-%d')} ({days_until_expiry} days remaining)",
                    'recommendation': 'Renew the SSL certificate before it expires.',
                    'cwe_id': 'CWE-295',
                    'owasp_category': 'Cryptographic Failures'
                })
            elif days_until_expiry < 30:
                findings.append({
                    'title': 'SSL Certificate Expiring Soon',
                    'severity': 'medium',
                    'description': 'SSL certificate expires within 30 days.',
                    'evidence': f"Certificate expires on {cert_info['expires_at'].strftime('%Y-%m-%d')} ({days_until_expiry} days remaining)",
                    'recommendation': 'Plan to renew the SSL certificate in the coming weeks.',
                    'cwe_id': 'CWE-295',
                    'owasp_category': 'Cryptographic Failures'
                })
        
        # Check issuer
        if cert_info.get('issuer'):
            issuer = cert_info['issuer']
            if 'self-signed' in issuer.lower() or 'self signed' in issuer.lower():
                findings.append({
                    'title': 'Self-Signed SSL Certificate',
                    'severity': 'high',
                    'description': 'Self-signed certificates are not trusted by browsers.',
                    'evidence': f"Issuer: {issuer}",
                    'recommendation': 'Replace self-signed certificate with one from a trusted Certificate Authority.',
                    'cwe_id': 'CWE-295',
                    'owasp_category': 'Cryptographic Failures'
                })
        
        # Check for wildcard certificate issues
        if cert_info.get('subject'):
            subject = cert_info['subject']
            if '*.' in subject and not self._validate_wildcard(subject, hostname):
                findings.append({
                    'title': 'Wildcard Certificate Mismatch',
                    'severity': 'medium',
                    'description': 'Wildcard certificate does not cover the current domain.',
                    'evidence': f"Certificate for {subject}, accessed at {hostname}",
                    'recommendation': 'Obtain a certificate that covers this specific domain.',
                    'cwe_id': 'CWE-295',
                    'owasp_category': 'Cryptographic Failures'
                })
        
        return {
            'uses_https': True,
            'certificate': cert_info,
            'findings': findings,
            'summary': {
                'valid': cert_info.get('valid', False),
                'expires_at': cert_info.get('expires_at'),
                'issuer': cert_info.get('issuer'),
                'subject': cert_info.get('subject'),
                'days_until_expiry': cert_info.get('days_until_expiry')
            }
        }
    
    def _get_cert_info(self, hostname, port=443):
        """
        Get SSL certificate information.
        
        Args:
            hostname: The hostname to check
            port: The port to connect to
            
        Returns:
            dict: Certificate information
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if not cert:
                        return None
                    
                    # Parse certificate
                    return self._parse_certificate(cert)
                    
        except ssl.SSLCertVerificationError as e:
            # Still try to get certificate info even if validation fails
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            info = self._parse_certificate(cert)
                            info['valid'] = False
                            info['error'] = str(e)
                            return info
            except Exception:
                pass
            
            return None
            
        except Exception as e:
            current_app.logger.debug(f"SSL check error for {hostname}: {str(e)}")
            return None
    
    def _parse_certificate(self, cert):
        """
        Parse certificate data.
        
        Args:
            cert: Certificate data from SSL context
            
        Returns:
            dict: Parsed certificate information
        """
        info = {
            'valid': True,
            'subject': cert.get('subject', []),
            'issuer': cert.get('issuer', []),
            'version': cert.get('version'),
            'serial_number': cert.get('serialNumber'),
            'not_before': None,
            'not_after': None,
            'expires_at': None,
            'days_until_expiry': None
        }
        
        # Parse subject
        if info['subject']:
            subject_parts = []
            for item in info['subject']:
                for key, value in item:
                    if key == 'commonName':
                        subject_parts.append(value)
            info['subject'] = ', '.join(subject_parts)
        
        # Parse issuer
        if info['issuer']:
            issuer_parts = []
            for item in info['issuer']:
                for key, value in item:
                    if key == 'commonName' or key == 'organizationName':
                        issuer_parts.append(value)
            info['issuer'] = ', '.join(issuer_parts)
        
        # Parse dates
        if 'notBefore' in cert:
            try:
                info['not_before'] = datetime.datetime.strptime(
                    cert['notBefore'], '%b %d %H:%M:%S %Y %Z'
                )
            except ValueError:
                pass
        
        if 'notAfter' in cert:
            try:
                info['not_after'] = datetime.datetime.strptime(
                    cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                )
                info['expires_at'] = info['not_after']
                info['days_until_expiry'] = (info['expires_at'] - datetime.datetime.utcnow()).days
            except ValueError:
                pass
        
        return info
    
    def _validate_wildcard(self, subject, hostname):
        """
        Validate wildcard certificate matches hostname.
        
        Args:
            subject: Certificate subject
            hostname: Hostname to validate
            
        Returns:
            bool: True if valid
        """
        # Check if subject contains wildcard pattern
        if '*.' in subject:
            pattern = subject.replace('*.', r'([a-zA-Z0-9-]+\.)')
            return re.match(pattern, hostname) is not None
        return subject == hostname
