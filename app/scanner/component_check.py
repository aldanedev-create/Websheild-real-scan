# -*- coding: utf-8 -*-

"""
WebShield Scanner - Component Checker
Detects web technologies and checks for outdated components.
"""

import re
import hashlib
from flask import current_app


class ComponentChecker:
    """Detects technologies and checks for outdated components."""
    
    def __init__(self):
        """Initialize the component checker."""
        self.components = {
            'jquery': {
                'name': 'jQuery',
                'patterns': [
                    r'jquery[.-]?(\d+\.\d+\.\d+)',
                    r'jQuery\s+v?(\d+\.\d+\.\d+)',
                ],
                'latest_version': '3.7.1',
                'security_versions': ['<1.9.0', '<2.2.0', '<3.0.0', '<3.4.0', '<3.5.0', '<3.7.1']
            },
            'bootstrap': {
                'name': 'Bootstrap',
                'patterns': [
                    r'bootstrap[.-]?(\d+\.\d+\.\d+)',
                    r'Bootstrap\s+v?(\d+\.\d+\.\d+)',
                ],
                'latest_version': '5.3.2',
                'security_versions': ['<3.0.0', '<3.3.7', '<4.0.0', '<4.3.0', '<5.0.0']
            },
            'wordpress': {
                'name': 'WordPress',
                'patterns': [
                    r'wp-content/themes/.*?/.*?(\d+\.\d+\.\d+)',
                    r'WordPress\s+(\d+\.\d+\.\d+)',
                    r'wp-includes/js/wp-emoji-release.min.js\?ver=(\d+\.\d+\.\d+)',
                ],
                'latest_version': '6.4.2',
                'security_versions': ['<4.7.0', '<5.0.0', '<5.1.0', '<5.2.0', '<5.3.0', '<5.4.0', '<5.5.0']
            },
            'laravel': {
                'name': 'Laravel',
                'patterns': [
                    r'Laravel\s+v?(\d+\.\d+\.\d+)',
                    r'name="csrf-token".*?content="(.+?)"',
                ],
                'latest_version': '10.35.0',
                'security_versions': ['<5.5.0', '<5.6.0', '<5.7.0', '<5.8.0', '<6.0.0', '<8.0.0']
            },
            'django': {
                'name': 'Django',
                'patterns': [
                    r'Django\s+v?(\d+\.\d+\.\d+)',
                    r'csrfmiddlewaretoken.*?value="(.+?)"',
                ],
                'latest_version': '5.0.0',
                'security_versions': ['<2.2.0', '<3.0.0', '<3.1.0', '<3.2.0', '<4.0.0']
            },
            'angular': {
                'name': 'Angular',
                'patterns': [
                    r'angular[.-]?(\d+\.\d+\.\d+)',
                    r'Angular\s+v?(\d+\.\d+\.\d+)',
                    r'@angular/core.*?(\d+\.\d+\.\d+)',
                ],
                'latest_version': '17.0.0',
                'security_versions': ['<1.5.0', '<1.6.0', '<1.7.0', '<1.8.0', '<1.9.0']
            },
            'react': {
                'name': 'React',
                'patterns': [
                    r'react[.-]?(\d+\.\d+\.\d+)',
                    r'React\s+v?(\d+\.\d+\.\d+)',
                    r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
                ],
                'latest_version': '18.2.0',
                'security_versions': ['<15.0.0', '<16.0.0', '<16.8.0', '<17.0.0']
            },
            'vue': {
                'name': 'Vue.js',
                'patterns': [
                    r'vue[.-]?(\d+\.\d+\.\d+)',
                    r'Vue\.js\s+v?(\d+\.\d+\.\d+)',
                    r'data-v-',
                ],
                'latest_version': '3.3.8',
                'security_versions': ['<2.0.0', '<2.1.0', '<2.2.0', '<2.5.0', '<2.6.0', '<3.0.0']
            },
            'nginx': {
                'name': 'Nginx',
                'patterns': [
                    r'nginx/(\d+\.\d+\.\d+)',
                ],
                'latest_version': '1.25.3',
                'security_versions': ['<1.8.0', '<1.10.0', '<1.12.0', '<1.14.0', '<1.16.0']
            },
            'apache': {
                'name': 'Apache',
                'patterns': [
                    r'Apache/(\d+\.\d+\.\d+)',
                    r'Apache\s+(\d+\.\d+\.\d+)',
                ],
                'latest_version': '2.4.58',
                'security_versions': ['<2.2.0', '<2.4.0', '<2.4.29', '<2.4.37']
            },
            'php': {
                'name': 'PHP',
                'patterns': [
                    r'PHP/(\d+\.\d+\.\d+)',
                    r'X-Powered-By:\s*PHP/(\d+\.\d+\.\d+)',
                ],
                'latest_version': '8.3.0',
                'security_versions': ['<5.6.0', '<7.0.0', '<7.1.0', '<7.2.0', '<7.3.0', '<8.0.0']
            }
        }
    
    def scan(self, pages):
        """
        Scan for components and check versions.
        
        Args:
            pages: List of page data
            
        Returns:
            dict: Component scan results
        """
        if not pages:
            return {'findings': [], 'components': []}
        
        findings = []
        detected_components = []
        
        for page in pages:
            html = page.get('html') or ''
            headers = page.get('headers', {})
            url = page.get('url', '')
            
            # Check for components in HTML and headers
            for comp_key, comp_info in self.components.items():
                version = None
                
                # Check patterns in HTML
                for pattern in comp_info['patterns']:
                    if pattern.startswith(r'X-Powered-By') or pattern.startswith(r'Server') or pattern.startswith(r'nginx/'):
                        # Header patterns
                        for header_key, header_value in headers.items():
                            if re.search(pattern, f"{header_key}: {header_value}", re.IGNORECASE):
                                version_match = re.search(r'(\d+\.\d+\.\d+)', header_value)
                                if version_match:
                                    version = version_match.group(1)
                                    break
                    else:
                        # HTML patterns
                        matches = re.findall(pattern, html, re.IGNORECASE)
                        if matches:
                            # Take the first match
                            if isinstance(matches[0], tuple):
                                version = matches[0][0]
                            else:
                                version = matches[0]
                            break
                
                if version:
                    # Clean version string
                    version = version.strip()
                    
                    # Check if detected
                    component_data = {
                        'name': comp_info['name'],
                        'key': comp_key,
                        'version': version,
                        'url': url,
                        'latest_version': comp_info['latest_version'],
                        'is_outdated': self._is_version_outdated(version, comp_info['latest_version']),
                        'has_security_issues': self._has_security_issues(version, comp_info)
                    }
                    
                    detected_components.append(component_data)
                    
                    # Create finding if component has security issues
                    if component_data['has_security_issues']:
                        findings.append({
                            'title': f"Outdated {comp_info['name']} Version ({version})",
                            'severity': 'medium',
                            'url': url,
                            'description': f"The website is using {comp_info['name']} version {version}, which may have known security vulnerabilities.",
                            'evidence': f"Detected {comp_info['name']} version {version}",
                            'recommendation': f'Update {comp_info["name"]} to version {comp_info["latest_version"]} or later.',
                            'cwe_id': 'CWE-1104',
                            'owasp_category': 'Vulnerable Components'
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
            'components': detected_components,
            'summary': {
                'total_components': len(detected_components),
                'outdated_count': sum(1 for c in detected_components if c.get('is_outdated')),
                'security_issues': sum(1 for c in detected_components if c.get('has_security_issues'))
            }
        }
    
    def _is_version_outdated(self, current_version, latest_version):
        """
        Check if version is outdated.
        
        Args:
            current_version: Current version string
            latest_version: Latest version string
            
        Returns:
            bool: True if outdated
        """
        try:
            current_parts = [int(x) for x in current_version.split('.')]
            latest_parts = [int(x) for x in latest_version.split('.')]
            
            # Compare version parts
            for i in range(min(len(current_parts), len(latest_parts))):
                if current_parts[i] < latest_parts[i]:
                    return True
                elif current_parts[i] > latest_parts[i]:
                    return False
            
            return len(current_parts) < len(latest_parts)
            
        except (AttributeError, TypeError, ValueError):
            return False
    
    def _has_security_issues(self, version, comp_info):
        """
        Check if version has known security issues.
        
        Args:
            version: Version string
            comp_info: Component information
            
        Returns:
            bool: True if security issues exist
        """
        if not comp_info.get('security_versions'):
            return False
        
        for security_range in comp_info['security_versions']:
            if self._version_in_range(version, security_range):
                return True
        
        return False
    
    def _version_in_range(self, version, version_range):
        """
        Check if version is in a security range.
        
        Args:
            version: Version string
            version_range: Range string (e.g., '<1.9.0')
            
        Returns:
            bool: True if version in range
        """
        try:
            if version_range.startswith('<'):
                # Less than
                compare_version = version_range[1:]
                compare_parts = [int(x) for x in compare_version.split('.')]
                current_parts = [int(x) for x in version.split('.')]
                
                for i in range(min(len(current_parts), len(compare_parts))):
                    if current_parts[i] < compare_parts[i]:
                        return True
                    elif current_parts[i] > compare_parts[i]:
                        return False
                
                return len(current_parts) < len(compare_parts)
            
            return False
            
        except (AttributeError, TypeError, ValueError):
            return False
