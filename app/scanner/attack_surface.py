# -*- coding: utf-8 -*-

"""
WebShield Scanner - Attack Surface Mapper
Maps the attack surface of a website including endpoints, directories, and resources.
"""

import re
from urllib.parse import urlparse, urljoin
from flask import current_app


class AttackSurfaceMapper:
    """Maps website attack surface including endpoints, directories, and resources."""
    
    def __init__(self):
        """Initialize the attack surface mapper."""
        pass
    
    def analyze(self, pages):
        """
        Analyze pages to map the attack surface.
        
        Args:
            pages: List of crawled page data
            
        Returns:
            dict: Attack surface data
        """
        if not pages:
            return self._empty_surface()
        
        surface = {
            'total_pages': len(pages),
            'endpoints': self._extract_endpoints(pages),
            'directories': self._extract_directories(pages),
            'login_pages': self._find_login_pages(pages),
            'api_endpoints': self._find_api_endpoints(pages),
            'admin_pages': self._find_admin_pages(pages),
            'file_types': self._count_file_types(pages),
            'technologies': self._detect_technologies(pages),
            'forms': self._extract_forms(pages),
            'parameters': self._extract_parameters(pages)
        }

        surface.update(self._build_pentest_analysis(surface, pages))
        
        return surface

    def _empty_surface(self):
        """Return an empty attack surface with the full analysis shape."""
        return {
            'total_pages': 0,
            'endpoints': [],
            'directories': [],
            'login_pages': [],
            'api_endpoints': [],
            'admin_pages': [],
            'file_types': {},
            'technologies': [],
            'forms': [],
            'parameters': [],
            'entry_points': [],
            'exit_points': [],
            'owasp_buckets': [],
            'attack_paths': [],
            'review_priorities': [],
            'trust_boundaries': [],
            'sensitive_data_signals': [],
            'honeypot_assessment': {
                'likelihood': 'unknown',
                'score': 0,
                'indicators': [],
                'notes': [
                    'No crawl data was available, so deception or honeypot behavior could not be assessed.'
                ]
            },
            'risk_score': 0,
            'risk_level': 'unknown',
            'exposure_summary': 'No attack surface data was collected.'
        }
    
    def _extract_endpoints(self, pages):
        """
        Extract all unique endpoints from pages.
        
        Args:
            pages: List of page data
            
        Returns:
            list: Unique endpoints
        """
        endpoints = set()
        
        for page in pages:
            url = page.get('url', '')
            if url:
                parsed = urlparse(url)
                endpoint = parsed.path or '/'
                endpoints.add(endpoint)
            
            # Add links
            for link in page.get('links', []):
                parsed = urlparse(link)
                endpoint = parsed.path or '/'
                if endpoint and endpoint != '/':
                    endpoints.add(endpoint)
        
        return sorted(list(endpoints))
    
    def _extract_directories(self, pages):
        """
        Extract directories from endpoints.
        
        Args:
            pages: List of page data
            
        Returns:
            list: Unique directories
        """
        directories = set()
        
        endpoints = self._extract_endpoints(pages)
        for endpoint in endpoints:
            parts = endpoint.split('/')
            path = ''
            for i, part in enumerate(parts):
                if part:
                    path += '/' + part
                    if i < len(parts) - 1:
                        directories.add(path + '/')
        
        return sorted(list(directories))
    
    def _find_login_pages(self, pages):
        """
        Find login pages.
        
        Args:
            pages: List of page data
            
        Returns:
            list: Login page URLs
        """
        login_pages = []
        login_patterns = [
            r'login', r'signin', r'sign-in', r'log-in', 
            r'auth', r'authenticate', r'oauth', r'sso'
        ]
        
        for page in pages:
            url = page.get('url', '').lower()
            title = (page.get('title') or '').lower()
            
            # Check URL patterns
            for pattern in login_patterns:
                if re.search(pattern, url) or re.search(pattern, title):
                    login_pages.append(page.get('url'))
                    break
            
            # Check for password fields in forms
            for form in page.get('forms', []):
                if form.get('has_password', False):
                    login_pages.append(page.get('url'))
                    break
        
        return list(set(login_pages))
    
    def _find_api_endpoints(self, pages):
        """
        Find API endpoints.
        
        Args:
            pages: List of page data
            
        Returns:
            list: API endpoint URLs
        """
        api_endpoints = []
        api_patterns = [
            r'/api/', r'/v\d+/', r'/rest/', r'/graphql',
            r'/soap/', r'/rpc/', r'/json/', r'/xmlrpc'
        ]
        
        for page in pages:
            url = page.get('url', '')
            
            # Check URL patterns
            for pattern in api_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    api_endpoints.append(url)
                    break
            
            # Check links for API patterns
            for link in page.get('links', []):
                for pattern in api_patterns:
                    if re.search(pattern, link, re.IGNORECASE):
                        api_endpoints.append(link)
                        break
        
        return list(set(api_endpoints))
    
    def _find_admin_pages(self, pages):
        """
        Find admin pages.
        
        Args:
            pages: List of page data
            
        Returns:
            list: Admin page URLs
        """
        admin_pages = []
        admin_patterns = [
            r'/admin', r'/administrator', r'/cp', r'/dashboard',
            r'/manage', r'/moderator', r'/sys', r'/system',
            r'/wp-admin', r'/wp-login', r'/cpanel'
        ]
        
        for page in pages:
            url = page.get('url', '').lower()
            title = (page.get('title') or '').lower()
            
            for pattern in admin_patterns:
                if re.search(pattern, url) or re.search(pattern, title):
                    admin_pages.append(page.get('url'))
                    break
        
        return list(set(admin_pages))
    
    def _count_file_types(self, pages):
        """
        Count file types found.
        
        Args:
            pages: List of page data
            
        Returns:
            dict: File type counts
        """
        file_types = {}
        
        for page in pages:
            url = page.get('url', '')
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            if '.' in path:
                ext = path.split('.')[-1]
                file_types[ext] = file_types.get(ext, 0) + 1
        
        return file_types
    
    def _detect_technologies(self, pages):
        """
        Detect technologies used on the website.
        
        Args:
            pages: List of page data
            
        Returns:
            list: Detected technologies
        """
        technologies = []
        
        # Check for common CMS and frameworks
        cms_patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'wordpress', r'wp-json'],
            'Joomla': [r'joomla', r'com_content', r'com_modules'],
            'Drupal': [r'drupal', r'sites/default'],
            'Magento': [r'magento', r'skin/frontend'],
            'Shopify': [r'shopify', r'myshopify'],
            'Laravel': [r'laravel', r'csrf-token', r'_token'],
            'Django': [r'django', r'csrfmiddlewaretoken'],
            'Ruby on Rails': [r'rails', r'authenticity_token'],
            'Node.js': [r'node_modules', r'express'],
            'Angular': [r'ng-app', r'angular'],
            'React': [r'react', r'__REACT_'],
            'Vue.js': [r'vue', r'data-v-'],
            'jQuery': [r'jquery', r'jQuery']
        }
        
        # Check headers for server info
        for page in pages:
            headers = page.get('headers', {})
            server = headers.get('server', '').lower()
            
            if 'nginx' in server:
                technologies.append('Nginx')
            if 'apache' in server:
                technologies.append('Apache')
            if 'iis' in server:
                technologies.append('IIS')
            if 'cloudflare' in str(headers):
                technologies.append('Cloudflare')
            
            # Check HTML for CMS patterns
            html = page.get('html') or ''
            for tech, patterns in cms_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, html, re.IGNORECASE):
                        technologies.append(tech)
                        break
        
        return list(set(technologies))
    
    def _extract_forms(self, pages):
        """
        Extract all forms from pages.
        
        Args:
            pages: List of page data
            
        Returns:
            list: Form data
        """
        forms = []
        for page in pages:
            for form in page.get('forms', []):
                forms.append({
                    'url': page.get('url'),
                    'action': form.get('action'),
                    'method': form.get('method'),
                    'has_password': form.get('has_password', False),
                    'has_file_upload': form.get('has_file_upload', False),
                    'input_count': len(form.get('inputs', []))
                })
        return forms
    
    def _extract_parameters(self, pages):
        """
        Extract URL parameters from pages.
        
        Args:
            pages: List of page data
            
        Returns:
            list: Parameter data
        """
        parameters = {}
        
        for page in pages:
            url = page.get('url', '')
            parsed = urlparse(url)
            if parsed.query:
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key = param.split('=')[0]
                        parameters[key] = parameters.get(key, 0) + 1
        
        return [{'name': k, 'count': v} for k, v in sorted(parameters.items(), key=lambda x: x[1], reverse=True)]

    def _build_pentest_analysis(self, surface, pages):
        """Build OWASP-inspired attack-surface analysis for pentesters."""
        buckets = self._build_owasp_buckets(surface)
        attack_paths = self._build_attack_paths(surface, pages)
        entry_points = self._build_entry_points(surface)
        exit_points = self._build_exit_points(surface, pages)
        trust_boundaries = self._build_trust_boundaries(surface, pages)
        sensitive_data = self._find_sensitive_data_signals(surface, pages)
        honeypot = self._assess_honeypot_or_deception(surface, pages)
        review_priorities = self._build_review_priorities(surface, buckets, attack_paths, honeypot)
        risk_score = self._calculate_surface_score(surface, buckets, attack_paths, sensitive_data, honeypot)

        return {
            'entry_points': entry_points,
            'exit_points': exit_points,
            'owasp_buckets': buckets,
            'attack_paths': attack_paths,
            'review_priorities': review_priorities,
            'trust_boundaries': trust_boundaries,
            'sensitive_data_signals': sensitive_data,
            'honeypot_assessment': honeypot,
            'risk_score': risk_score,
            'risk_level': self._risk_level(risk_score),
            'exposure_summary': self._summarize_exposure(surface, risk_score, honeypot),
            'methodology': {
                'source': 'OWASP Attack Surface Analysis Cheat Sheet',
                'focus': [
                    'Map data and command entry/exit points',
                    'Group exposed functionality into risk buckets',
                    'Prioritize anonymous internet-facing and privileged interfaces',
                    'Flag changes that should trigger threat modeling'
                ]
            }
        }

    def _build_owasp_buckets(self, surface):
        """Group discovered attack points into OWASP-style review buckets."""
        buckets = []

        def add(name, items, risk, description, testing_focus):
            examples = self._sample(items)
            buckets.append({
                'name': name,
                'count': len(items),
                'risk': risk,
                'description': description,
                'examples': examples,
                'testing_focus': testing_focus
            })

        forms = surface.get('forms', [])
        upload_forms = [f for f in forms if f.get('has_file_upload')]
        write_forms = [f for f in forms if str(f.get('method', 'GET')).upper() not in {'GET', ''}]
        parameters = surface.get('parameters', [])

        add(
            'Login and authentication entry points',
            surface.get('login_pages', []),
            'high',
            'Authentication paths protect identity, session creation, and account access.',
            ['credential stuffing resistance', 'MFA/session behavior', 'lockout and rate limiting', 'password reset abuse']
        )
        add(
            'Admin and privileged interfaces',
            surface.get('admin_pages', []),
            'critical',
            'Privileged UI or management routes can lead to full application compromise if exposed or weakly protected.',
            ['access control', 'default credentials', 'forced browsing', 'admin action audit logging']
        )
        add(
            'Custom APIs and transactional interfaces',
            surface.get('api_endpoints', []),
            'high',
            'APIs accept structured commands and data from clients or other systems.',
            ['authorization per object', 'mass assignment', 'schema validation', 'rate limiting', 'CORS and auth boundaries']
        )
        add(
            'Data entry and workflow forms',
            write_forms,
            'medium',
            'Forms are direct user-controlled data entry points into business logic.',
            ['server-side validation', 'CSRF', 'stored/reflected XSS', 'business logic abuse']
        )
        add(
            'File upload or external file intake',
            upload_forms,
            'critical',
            'File inputs can cross trust boundaries and reach parsers, storage, or execution paths.',
            ['extension/content validation', 'malware handling', 'storage isolation', 'public file execution controls']
        )
        add(
            'Query/search/inquiry parameters',
            parameters,
            'medium',
            'URL parameters often drive searches, filters, identifiers, redirects, or data lookup.',
            ['injection', 'IDOR', 'open redirect', 'pagination abuse', 'error handling']
        )
        add(
            'Static files, downloads, and backup-looking resources',
            self._interesting_file_endpoints(surface),
            'medium',
            'Files may expose source, backups, exports, documents, maps, or configuration data.',
            ['sensitive file exposure', 'backup leakage', 'cache controls', 'source map review']
        )

        return buckets

    def _build_attack_paths(self, surface, pages):
        """Create likely attack-path hypotheses from mapped surface features."""
        paths = []

        def add(title, severity, entry, idea, test_steps, signals):
            paths.append({
                'title': title,
                'severity': severity,
                'entry': entry,
                'how_it_could_be_hacked': idea,
                'pentest_steps': test_steps,
                'signals': signals
            })

        if surface.get('admin_pages'):
            add(
                'Forced browsing into admin functionality',
                'high',
                self._sample(surface.get('admin_pages'), 3),
                'An attacker may enumerate admin routes and attempt weak authentication, missing authorization, or exposed panels.',
                ['Check every admin URL while unauthenticated', 'Try low-privilege access', 'Verify redirects are not the only control', 'Look for default framework/admin credentials'],
                ['admin-like path discovered', f"{len(surface.get('admin_pages', []))} privileged-looking route(s)"]
            )

        if surface.get('login_pages'):
            add(
                'Account takeover through authentication surface',
                'high',
                self._sample(surface.get('login_pages'), 3),
                'Login and auth endpoints may be attacked through credential stuffing, weak recovery flows, session fixation, or missing brute-force controls.',
                ['Test lockout/rate limit behavior', 'Inspect password reset and registration flows', 'Check secure cookie flags after login', 'Verify MFA or compensating controls'],
                ['login form or password input discovered']
            )

        if surface.get('api_endpoints'):
            add(
                'API authorization and object access abuse',
                'high',
                self._sample(surface.get('api_endpoints'), 5),
                'APIs often expose object IDs and state-changing operations that can be abused through IDOR, broken function-level auth, or mass assignment.',
                ['Map HTTP methods and schemas', 'Replay requests as another user', 'Change object IDs and role fields', 'Test CORS/auth behavior'],
                ['API route discovered', 'custom protocol boundary']
            )

        upload_forms = [f for f in surface.get('forms', []) if f.get('has_file_upload')]
        if upload_forms:
            add(
                'File upload to stored payload or server-side parser',
                'critical',
                self._sample([f.get('action') or f.get('url') for f in upload_forms], 4),
                'Uploaded files can become stored XSS, parser exploits, public executable files, or data-exfiltration pivots.',
                ['Upload polyglot and renamed files safely', 'Check content-type and extension validation', 'Verify files cannot execute', 'Confirm private storage and malware scanning'],
                ['file input discovered']
            )

        sensitive_files = self._interesting_file_endpoints(surface)
        if sensitive_files:
            add(
                'Sensitive file or backup disclosure',
                'medium',
                self._sample(sensitive_files, 5),
                'Public files with backup/source/config extensions may leak credentials, source code, documents, or internal paths.',
                ['Request backup/config/source-map files', 'Check directory indexing', 'Review cache headers', 'Look for secrets in downloaded files'],
                ['interesting file extension discovered']
            )

        if surface.get('parameters'):
            add(
                'Parameter-driven injection or IDOR',
                'medium',
                self._sample([p.get('name') for p in surface.get('parameters', [])], 8),
                'Parameters can influence queries, object lookups, redirects, templates, or command paths.',
                ['Classify parameter purpose', 'Test type confusion and boundary values', 'Check object ownership', 'Watch response differences and errors'],
                ['query parameters discovered']
            )

        external_hosts = self._external_hosts(pages)
        if external_hosts:
            add(
                'Third-party dependency and supply-chain boundary',
                'medium',
                self._sample(external_hosts, 6),
                'External scripts, styles, images, or links extend trust to other domains and can affect integrity or privacy.',
                ['Review third-party scripts', 'Check SRI/CSP coverage', 'Validate redirect destinations', 'Assess analytics/chat/payment widgets if present'],
                ['external host referenced']
            )

        return paths

    def _build_entry_points(self, surface):
        """List command/data entry points discovered by the crawl."""
        points = []
        for item in surface.get('login_pages', []):
            points.append(self._point('auth', item, 'high', 'Login/authentication route'))
        for item in surface.get('admin_pages', []):
            points.append(self._point('admin', item, 'critical', 'Privileged or management-looking route'))
        for item in surface.get('api_endpoints', []):
            points.append(self._point('api', item, 'high', 'API endpoint'))
        for form in surface.get('forms', []):
            risk = 'critical' if form.get('has_file_upload') else 'medium'
            label = 'File upload form' if form.get('has_file_upload') else 'User input form'
            points.append(self._point('form', form.get('action') or form.get('url'), risk, label, {
                'method': form.get('method'),
                'inputs': form.get('input_count')
            }))
        for param in surface.get('parameters', []):
            points.append(self._point('parameter', param.get('name'), 'medium', 'URL/query parameter', {
                'observed_count': param.get('count')
            }))
        return points[:120]

    def _build_exit_points(self, surface, pages):
        """List likely data-out paths."""
        exits = []
        for item in surface.get('api_endpoints', []):
            exits.append(self._point('api_response', item, 'medium', 'API response/data egress path'))
        for item in self._interesting_file_endpoints(surface):
            exits.append(self._point('file_download', item, 'medium', 'Public file/download path'))
        for host in self._external_hosts(pages):
            exits.append(self._point('external_domain', host, 'medium', 'Browser can navigate or load resources from external host'))
        return exits[:120]

    def _build_trust_boundaries(self, surface, pages):
        """Identify likely trust boundaries crossed by users, APIs, files, and third parties."""
        boundaries = []
        if surface.get('forms'):
            boundaries.append({
                'name': 'Browser user input -> server application',
                'risk': 'medium',
                'evidence': f"{len(surface.get('forms', []))} form(s) discovered",
                'controls_to_verify': ['server-side validation', 'CSRF protection', 'output encoding', 'audit logging for sensitive actions']
            })
        if surface.get('api_endpoints'):
            boundaries.append({
                'name': 'Client/API consumer -> application API',
                'risk': 'high',
                'evidence': f"{len(surface.get('api_endpoints', []))} API endpoint(s) discovered",
                'controls_to_verify': ['authentication', 'object-level authorization', 'schema validation', 'rate limiting']
            })
        if any(f.get('has_file_upload') for f in surface.get('forms', [])):
            boundaries.append({
                'name': 'Untrusted file -> server storage/parser',
                'risk': 'critical',
                'evidence': 'File upload form discovered',
                'controls_to_verify': ['content validation', 'malware scanning', 'non-executable storage', 'download authorization']
            })
        external = self._external_hosts(pages)
        if external:
            boundaries.append({
                'name': 'Application/browser -> third-party domains',
                'risk': 'medium',
                'evidence': ', '.join(self._sample(external, 5)),
                'controls_to_verify': ['CSP', 'SRI for scripts', 'privacy review', 'redirect allowlists']
            })
        return boundaries

    def _find_sensitive_data_signals(self, surface, pages):
        """Infer high-value data areas from paths, fields, and content names."""
        signals = []
        patterns = {
            'credentials/session data': r'login|signin|password|token|session|oauth|sso|reset',
            'personal data/profile': r'profile|account|user|member|student|customer|email|phone|address',
            'admin/operational data': r'admin|dashboard|manage|settings|config|system|logs',
            'documents/reports/exports': r'report|export|download|invoice|receipt|pdf|doc|backup|csv|xlsx',
            'payments/orders': r'payment|billing|checkout|order|cart|subscription|invoice'
        }

        haystack = []
        haystack.extend(surface.get('endpoints', []))
        haystack.extend(surface.get('directories', []))
        haystack.extend([f.get('action') or '' for f in surface.get('forms', [])])
        for page in pages:
            haystack.append(page.get('url', ''))
            haystack.append(page.get('title') or '')

        joined_items = [str(item).lower() for item in haystack if item]
        for label, pattern in patterns.items():
            matches = [item for item in joined_items if re.search(pattern, item)]
            if matches:
                signals.append({
                    'data_type': label,
                    'confidence': 'medium',
                    'evidence': self._sample(matches, 5),
                    'review_focus': ['access control', 'data minimization', 'transport protection', 'logging of sensitive access']
                })

        return signals

    def _assess_honeypot_or_deception(self, surface, pages):
        """Flag possible WAF, bot defense, or honeypot/deception indicators."""
        indicators = []
        score = 0

        suspicious_terms = [
            'honeypot', 'canary', 'trap', 'decoy', 'tarpit', 'bot-trap',
            'hidden-admin', 'fake-login'
        ]
        all_urls = []
        for page in pages:
            all_urls.append(page.get('url', ''))
            all_urls.extend(page.get('links', []))

            headers_text = ' '.join([f'{k}: {v}' for k, v in (page.get('headers') or {}).items()]).lower()
            if any(term in headers_text for term in ['cloudflare', 'akamai', 'sucuri', 'imperva', 'incapsula', 'fastly', 'datadome']):
                indicators.append({
                    'type': 'bot_defense_or_waf',
                    'evidence': self._short(headers_text),
                    'meaning': 'A WAF/CDN/bot defense may change scan visibility or intentionally challenge automated clients.'
                })
                score += 1

        suspicious_urls = [url for url in all_urls if any(term in str(url).lower() for term in suspicious_terms)]
        if suspicious_urls:
            indicators.append({
                'type': 'deception_keyword',
                'evidence': self._sample(suspicious_urls, 5),
                'meaning': 'Routes or links contain names often used for traps, canaries, or bot detection.'
            })
            score += 3

        admin_count = len(surface.get('admin_pages', []))
        login_count = len(surface.get('login_pages', []))
        if admin_count >= 5 and login_count >= 3:
            indicators.append({
                'type': 'many_privileged_decoys_possible',
                'evidence': f'{admin_count} admin-looking pages and {login_count} login-looking pages discovered',
                'meaning': 'A site with many admin/login-like paths may include decoys, legacy panels, or intentionally exposed traps.'
            })
            score += 2

        if not indicators:
            likelihood = 'low'
            notes = ['No clear honeypot/deception indicators were detected from passive crawl data. This is not proof that none exist.']
        elif score >= 4:
            likelihood = 'medium'
            notes = ['Possible defensive deception or bot-management behavior. Treat findings as indicators and verify manually before concluding the site is a honeypot.']
        else:
            likelihood = 'low-medium'
            notes = ['Some WAF/CDN/bot-defense signals were found. These are common on normal production websites and do not by themselves mean honeypot.']

        return {
            'likelihood': likelihood,
            'score': score,
            'indicators': indicators[:12],
            'notes': notes
        }

    def _build_review_priorities(self, surface, buckets, attack_paths, honeypot):
        """Prioritize what a tester should review first."""
        priorities = []
        for bucket in buckets:
            if bucket.get('count') and bucket.get('risk') in {'critical', 'high'}:
                priorities.append({
                    'priority': bucket.get('risk'),
                    'area': bucket.get('name'),
                    'why': bucket.get('description'),
                    'start_with': bucket.get('examples', []),
                    'test_for': bucket.get('testing_focus', [])
                })

        if honeypot.get('indicators'):
            priorities.append({
                'priority': 'medium',
                'area': 'Honeypot/WAF/deception verification',
                'why': 'Defensive controls can hide routes, alter responses, or intentionally expose traps.',
                'start_with': [i.get('type') for i in honeypot.get('indicators', [])],
                'test_for': ['manual browser verification', 'header comparison', 'rate/challenge behavior', 'avoid destructive probes']
            })

        if not priorities and attack_paths:
            for path in attack_paths[:3]:
                priorities.append({
                    'priority': path.get('severity'),
                    'area': path.get('title'),
                    'why': path.get('how_it_could_be_hacked'),
                    'start_with': path.get('entry', []),
                    'test_for': path.get('pentest_steps', [])
                })

        return priorities[:10]

    def _calculate_surface_score(self, surface, buckets, attack_paths, sensitive_data, honeypot):
        """Calculate a simple relative attack-surface score from exposure count and risk."""
        weights = {'critical': 16, 'high': 10, 'medium': 5, 'low': 2}
        score = 0
        score += min(len(surface.get('endpoints', [])), 100) * 0.4
        score += min(len(surface.get('directories', [])), 50) * 0.5
        score += len(surface.get('forms', [])) * 3
        score += len(surface.get('parameters', [])) * 2

        for bucket in buckets:
            score += min(bucket.get('count', 0), 20) * weights.get(bucket.get('risk'), 1)
        for path in attack_paths:
            score += weights.get(path.get('severity'), 1) * 1.5
        score += len(sensitive_data) * 4
        if honeypot.get('likelihood') in {'medium', 'high'}:
            score += 4

        return int(max(0, min(round(score), 100)))

    def _risk_level(self, score):
        if score >= 80:
            return 'critical'
        if score >= 60:
            return 'high'
        if score >= 35:
            return 'medium'
        if score >= 15:
            return 'low'
        return 'minimal'

    def _summarize_exposure(self, surface, score, honeypot):
        pieces = [
            f"{surface.get('total_pages', 0)} page(s)",
            f"{len(surface.get('endpoints', []))} endpoint(s)",
            f"{len(surface.get('forms', []))} form(s)",
            f"{len(surface.get('api_endpoints', []))} API endpoint(s)",
            f"{len(surface.get('admin_pages', []))} admin-looking route(s)"
        ]
        summary = f"Relative attack-surface score is {score}/100 based on " + ', '.join(pieces) + '.'
        if honeypot.get('indicators'):
            summary += f" Honeypot/WAF/deception likelihood: {honeypot.get('likelihood')}."
        return summary

    def _interesting_file_endpoints(self, surface):
        interesting_exts = {
            'bak', 'old', 'backup', 'zip', 'tar', 'gz', '7z', 'sql', 'db', 'sqlite',
            'env', 'config', 'ini', 'log', 'txt', 'csv', 'json', 'xml', 'map',
            'pdf', 'doc', 'docx', 'xls', 'xlsx'
        }
        endpoints = surface.get('endpoints', [])
        return [
            item for item in endpoints
            if '.' in str(item) and str(item).rsplit('.', 1)[-1].lower() in interesting_exts
        ]

    def _external_hosts(self, pages):
        hosts = set()
        base_host = None
        for page in pages:
            page_host = urlparse(page.get('url', '')).hostname
            if page_host and not base_host:
                base_host = page_host
            urls = []
            urls.extend(page.get('links', []))
            urls.extend(page.get('scripts', []))
            urls.extend(page.get('styles', []))
            urls.extend(page.get('images', []))
            for value in urls:
                host = urlparse(value).hostname
                if host and host != base_host:
                    hosts.add(host)
        return sorted(hosts)

    def _point(self, point_type, value, risk, reason, extra=None):
        point = {
            'type': point_type,
            'value': value or '',
            'risk': risk,
            'reason': reason
        }
        if extra:
            point.update(extra)
        return point

    def _sample(self, items, limit=5):
        sample = []
        seen = set()
        for item in items:
            if not item:
                continue
            marker = str(item)
            if marker in seen:
                continue
            seen.add(marker)
            sample.append(item)
            if len(sample) >= limit:
                break
        return sample

    def _short(self, value, limit=240):
        value = re.sub(r'\s+', ' ', str(value or '')).strip()
        return value[:limit]
