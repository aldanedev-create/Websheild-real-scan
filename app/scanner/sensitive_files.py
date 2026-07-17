# -*- coding: utf-8 -*-

"""
WebShield Scanner - Sensitive File Detector
Detects exposed sensitive files and directories.
"""

import re
import requests
from urllib.parse import urljoin, urlparse
from flask import current_app


class SensitiveFileDetector:
    """Detects exposed sensitive files and directories."""
    
    def __init__(self):
        """Initialize the sensitive file detector."""
        self.session = requests.Session()
        self.timeout = current_app.config.get('REQUEST_TIMEOUT', 30)
        
        self.sensitive_paths = [
            # Version control
            '/.git/HEAD',
            '/.git/config',
            '/.gitignore',
            '/.svn/entries',
            '/.hg/',
            
            # Environment files
            '/.env',
            '/.env.local',
            '/.env.production',
            '/.env.example',
            '/env.php',
            
            # Configuration files
            '/config.php',
            '/config.ini',
            '/configuration.php',
            '/wp-config.php',
            '/wp-config-sample.php',
            '/settings.php',
            '/settings.json',
            '/config.yml',
            '/config.yaml',
            '/database.yml',
            '/app.config',
            '/web.config',
            '/application.properties',
            
            # Backup files
            '/backup.sql',
            '/backup.zip',
            '/backup.tar.gz',
            '/db_backup.sql',
            '/database.sql',
            '/dump.sql',
            '/.backup/',
            '/*.bak',
            '/*.old',
            '/*.orig',
            '/*.save',
            
            # Debug files
            '/debug.log',
            '/error.log',
            '/access.log',
            '/logs/',
            '/tmp/',
            '/temp/',
            '/cache/',
            
            # API keys and secrets
            '/api_keys.txt',
            '/secrets.txt',
            '/credentials.txt',
            '/passwords.txt',
            '/.htpasswd',
            '/.htaccess',
            
            # Directory listing sensitive
            '/index/',
            '/dir/',
            
            # SSH keys
            '/id_rsa',
            '/id_dsa',
            '/.ssh/',
            
            # Build files
            '/package.json',
            '/package-lock.json',
            '/composer.json',
            '/composer.lock',
            '/Gemfile',
            '/Gemfile.lock',
            '/requirements.txt',
            '/Pipfile',
            '/Pipfile.lock',
            '/yarn.lock',
            
            # Docker files
            '/Dockerfile',
            '/docker-compose.yml',
            '/.dockerignore',
            
            # CI/CD files
            '/.travis.yml',
            '/.gitlab-ci.yml',
            '/.circleci/',
            '/Jenkinsfile',
            
            # Development files
            '/.vscode/',
            '/.idea/',
            '/*.swp',
            '/*.swo',
            '/*.tmp',
            '/*.temp',
        ]
        
        # Extensions to check for sensitive content
        self.sensitive_extensions = ['.log', '.txt', '.sql', '.json', '.yml', '.yaml', '.ini', '.conf']
    
    def scan(self, pages):
        """
        Scan for sensitive files.
        
        Args:
            pages: List of page data
            
        Returns:
            dict: Sensitive file scan results
        """
        if not pages:
            return {'findings': [], 'sensitive_files': []}
        
        findings = []
        sensitive_files = []
        
        for page in pages:
            url = page.get('url', '')
            html = page.get('html') or ''
            
            # Check for directory listing
            if self._is_directory_listing(html):
                findings.append({
                    'title': 'Directory Listing Enabled',
                    'severity': 'high',
                    'url': url,
                    'description': 'Directory listing is enabled, exposing file structure and potentially sensitive files.',
                    'evidence': 'Directory listing detected in response content',
                    'recommendation': 'Disable directory listing in web server configuration.',
                    'cwe_id': 'CWE-548',
                    'owasp_category': 'Information Disclosure'
                })
            
            # Check for exposed files in HTML
            exposed_files = self._find_exposed_files(html, url)
            for file_path, file_url in exposed_files:
                if self._is_public_web_manifest(file_path):
                    continue

                sensitive_files.append({
                    'url': file_url,
                    'path': file_path,
                    'found_in': url
                })
                
                findings.append({
                    'title': f'Exposed File: {file_path}',
                    'severity': self._get_severity_for_file(file_path),
                    'url': file_url,
                    'description': f'A sensitive file "{file_path}" was found exposed on the website.',
                    'evidence': f'File referenced in page: {file_path}',
                    'recommendation': 'Remove or protect sensitive files from public access.',
                    'cwe_id': 'CWE-552',
                    'owasp_category': 'Information Disclosure'
                })
        
        # Check for sensitive files by path probing
        base_url = self._get_base_url(pages)
        if base_url:
            probed_files = self._probe_sensitive_paths(base_url)
            for file_info in probed_files:
                sensitive_files.append(file_info)
                
                findings.append({
                    'title': f'Exposed File: {file_info["path"]}',
                    'severity': self._get_severity_for_file(file_info["path"]),
                    'url': file_info["url"],
                    'description': f'A sensitive file "{file_info["path"]}" was found exposed.',
                    'evidence': f'File accessible at: {file_info["url"]}',
                    'recommendation': 'Remove or protect sensitive files from public access.',
                    'cwe_id': 'CWE-552',
                    'owasp_category': 'Information Disclosure'
                })
        
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
            'sensitive_files': sensitive_files,
            'summary': {
                'total_sensitive_files': len(sensitive_files),
                'severity_breakdown': self._get_severity_breakdown(findings)
            }
        }
    
    def _is_directory_listing(self, html):
        """
        Check if HTML contains directory listing.
        
        Args:
            html: HTML content
            
        Returns:
            bool: True if directory listing detected
        """
        if not html:
            return False
        
        patterns = [
            r'<title>Index of /',
            r'<h1>Index of /',
            r'<title>Directory Listing',
            r'<h1>Directory Listing',
            r'Parent Directory',
            r'<pre>.*<a href=".*?">.*?</a>',
        ]
        
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        return False
    
    def _find_exposed_files(self, html, base_url):
        """
        Find exposed files in HTML content.
        
        Args:
            html: HTML content
            base_url: Base URL
            
        Returns:
            list: List of (file_path, file_url) tuples
        """
        if not html:
            return []
        
        exposed = []
        
        # Look for file references in HTML
        patterns = [
            r'href=[\'"]([^\'"]*\.(?:log|txt|sql|json|yml|yaml|ini|conf|bak|old|orig|save))[\'"]',
            r'src=[\'"]([^\'"]*\.(?:log|txt|sql|json|yml|yaml|ini|conf|bak|old|orig|save))[\'"]',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if match and not match.startswith(('http://', 'https://')):
                    # It's a relative path
                    full_url = urljoin(base_url, match)
                    exposed.append((match, full_url))
                elif match and match.startswith(('http://', 'https://')):
                    exposed.append((match, match))
        
        return exposed

    def _is_public_web_manifest(self, file_path):
        """
        Check for ordinary browser app manifests that are meant to be public.

        Args:
            file_path: Referenced file path or URL

        Returns:
            bool: True if the path is a standard web app manifest
        """
        parsed_path = urlparse(file_path).path if file_path.startswith(('http://', 'https://')) else file_path
        clean_path = parsed_path.split('?', 1)[0].lower()
        return clean_path.endswith('/manifest.json') or clean_path == 'manifest.json'
    
    def _probe_sensitive_paths(self, base_url):
        """
        Probe for sensitive files by checking common paths.
        
        Args:
            base_url: Base URL
            
        Returns:
            list: Found sensitive file info
        """
        found = []
        
        for path in self.sensitive_paths:
            test_url = urljoin(base_url, path)
            try:
                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False
                )
                
                if response.status_code == 200:
                    found.append({
                        'url': test_url,
                        'path': path,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('Content-Type', ''),
                        'size': len(response.content)
                    })
                elif response.status_code in [301, 302, 303, 307, 308]:
                    # Check if redirect points to existing file
                    location = response.headers.get('Location', '')
                    if location and not location.startswith(('http://', 'https://')):
                        # Internal redirect
                        pass
                    else:
                        # Might be valid
                        found.append({
                            'url': test_url,
                            'path': path,
                            'status_code': response.status_code,
                            'redirect_to': location
                        })
            except Exception:
                continue
        
        return found
    
    def _get_base_url(self, pages):
        """
        Get base URL from pages.
        
        Args:
            pages: List of page data
            
        Returns:
            str: Base URL
        """
        for page in pages:
            url = page.get('url', '')
            if url:
                parsed = urlparse(url)
                return f"{parsed.scheme}://{parsed.netloc}"
        return None
    
    def _get_severity_for_file(self, file_path):
        """
        Get severity level for a file type.
        
        Args:
            file_path: File path
            
        Returns:
            str: Severity level
        """
        file_path_lower = file_path.lower()
        
        # Critical severity files
        if any(pattern in file_path_lower for pattern in ['.env', 'wp-config', 'config.php', 'id_rsa', '.htpasswd']):
            return 'critical'
        
        # High severity files
        if any(pattern in file_path_lower for pattern in ['password', 'secret', 'credential', 'api_key']):
            return 'high'
        
        # Medium severity files
        if any(pattern in file_path_lower for pattern in ['.git', '.svn', '.hg', 'backup', 'dump', '.log']):
            return 'medium'
        
        return 'low'
    
    def _get_severity_breakdown(self, findings):
        """
        Get severity breakdown of findings.
        
        Args:
            findings: List of findings
            
        Returns:
            dict: Severity counts
        """
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in findings:
            severity = finding.get('severity', 'low')
            if severity in breakdown:
                breakdown[severity] += 1
        return breakdown
