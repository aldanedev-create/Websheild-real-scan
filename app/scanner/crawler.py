# -*- coding: utf-8 -*-

"""
WebShield Scanner - Web Crawler
Crawls websites to discover pages, links, and resources.
"""

import time
import re
import requests
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup
from flask import current_app
from app.scanner.url_validator import URLValidator


class Crawler:
    """Web crawler for discovering website content."""
    
    def __init__(self):
        """Initialize the crawler."""
        self.validator = URLValidator()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': current_app.config.get('USER_AGENT', 'WebShield-Scanner/1.0'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.timeout = current_app.config.get('REQUEST_TIMEOUT', 30)
        self.max_redirects = current_app.config.get('MAX_SCAN_REDIRECTS', 5)
    
    def crawl(
        self,
        start_url,
        max_depth=3,
        max_pages=100,
        auth_cookie=None,
        should_cancel=None,
    ):
        """
        Crawl a website starting from the given URL.
        
        Args:
            start_url: The URL to start crawling from
            max_depth: Maximum crawl depth
            max_pages: Maximum number of pages to crawl
            auth_cookie: Authentication cookie for protected pages
            should_cancel: Optional callback checked between crawl operations
            
        Returns:
            list: List of crawled page data
        """
        if auth_cookie:
            try:
                cookie_name, cookie_value = auth_cookie.split('=', 1)
                if cookie_name.strip() and cookie_value:
                    self.session.cookies.set(cookie_name.strip(), cookie_value.strip())
            except ValueError:
                current_app.logger.warning("Ignoring malformed auth cookie for scan")
        
        start_url = self.validator.normalize_url(start_url)
        base_domain = self.validator.get_domain(start_url)
        
        visited = set()
        pages = []
        queue = [(start_url, 0)]
        
        while queue and len(pages) < max_pages:
            if should_cancel and should_cancel():
                break

            url, depth = queue.pop(0)
            
            # Skip if already visited or depth exceeded
            if url in visited or depth > max_depth:
                continue
            
            visited.add(url)
            
            try:
                # Fetch page
                response = self._fetch_page(url, should_cancel=should_cancel)

                if should_cancel and should_cancel():
                    break
                
                if not response:
                    continue
                
                # Parse page
                page_data = self._parse_page(response.url or url, response, depth)
                pages.append(page_data)
                
                # Extract links for further crawling
                if depth < max_depth:
                    links = self._extract_links(url, response.text, base_domain)
                    
                    # Add new links to queue
                    for link in links:
                        if should_cancel and should_cancel():
                            break
                        if link not in visited and len(pages) < max_pages:
                            queue.append((link, depth + 1))
                
                # Be respectful - add delay
                # Keep cancellation responsive without creating a busy loop.
                time.sleep(0.1)
                
            except Exception as e:
                current_app.logger.debug(f"Error crawling {url}: {str(e)}")
                continue
        
        return pages
    
    def _fetch_page(self, url, should_cancel=None):
        """
        Fetch a page from the web.
        
        Args:
            url: The URL to fetch
            
        Returns:
            Response object or None
        """
        redirects = 0
        current_url = url

        try:
            while True:
                if should_cancel and should_cancel():
                    return None

                is_valid, error = self.validator.validate(current_url)
                if not is_valid:
                    current_app.logger.debug(f"Blocked crawl target {current_url}: {error}")
                    return None

                response = self.session.get(
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False  # Allow self-signed certificates for scanning
                )

                if should_cancel and should_cancel():
                    return None

                if 300 <= response.status_code < 400:
                    if redirects >= self.max_redirects:
                        current_app.logger.debug(f"Redirect limit reached fetching {url}")
                        return None
                    location = response.headers.get('Location')
                    if not location:
                        return None
                    current_url = self.validator.normalize_url(urljoin(response.url or current_url, location))
                    redirects += 1
                    continue

                response.raise_for_status()
                return response
            
        except requests.exceptions.Timeout:
            current_app.logger.debug(f"Timeout fetching {url}")
        except requests.exceptions.ConnectionError:
            current_app.logger.debug(f"Connection error fetching {url}")
        except requests.exceptions.HTTPError as e:
            current_app.logger.debug(f"HTTP error fetching {url}: {str(e)}")
        except Exception as e:
            current_app.logger.debug(f"Error fetching {url}: {str(e)}")
        
        return None
    
    def _parse_page(self, url, response, depth):
        """
        Parse a page and extract relevant information.
        
        Args:
            url: The page URL
            response: The response object
            depth: The crawl depth
            
        Returns:
            dict: Page data
        """
        content_type = response.headers.get('Content-Type', '')
        is_html = 'text/html' in content_type or 'text/xhtml' in content_type
        
        page_data = {
            'url': url,
            'status_code': response.status_code,
            'depth': depth,
            'headers': dict(response.headers),
            'content_type': content_type,
            'is_html': is_html,
            'content_length': len(response.content),
            'html': response.text if is_html else None,
            'title': None,
            'meta_description': None,
            'forms': [],
            'scripts': [],
            'inline_scripts': [],
            'styles': [],
            'images': [],
            'links': []
        }
        
        if is_html and response.text:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract title
            title_tag = soup.find('title')
            if title_tag:
                page_data['title'] = title_tag.get_text().strip()
            
            # Extract meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc:
                page_data['meta_description'] = meta_desc.get('content', '')
            
            # Extract forms
            for form in soup.find_all('form'):
                page_data['forms'].append(self._parse_form(form, url))
            
            # Extract scripts
            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    page_data['scripts'].append(urljoin(url, src))
                else:
                    script_content = script.string or script.get_text() or ''
                    if script_content.strip():
                        page_data['inline_scripts'].append({
                            'content': script_content,
                            'source': 'inline'
                        })
            
            # Extract styles
            for link in soup.find_all('link', rel='stylesheet'):
                href = link.get('href')
                if href:
                    page_data['styles'].append(urljoin(url, href))
            
            # Extract images
            for img in soup.find_all('img'):
                src = img.get('src')
                if src:
                    page_data['images'].append(urljoin(url, src))
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if href:
                    page_data['links'].append(urljoin(url, href))
        
        return page_data
    
    def _parse_form(self, form, base_url):
        """
        Parse a form element.
        
        Args:
            form: BeautifulSoup form element
            base_url: The base URL
            
        Returns:
            dict: Form data
        """
        form_data = {
            'action': urljoin(base_url, form.get('action', '')),
            'method': form.get('method', 'GET').upper(),
            'inputs': [],
            'has_password': False,
            'has_file_upload': False
        }
        
        for input_tag in form.find_all('input'):
            input_type = input_tag.get('type', 'text').lower()
            input_name = input_tag.get('name', '')
            
            form_data['inputs'].append({
                'type': input_type,
                'name': input_name,
                'value': input_tag.get('value', '')
            })
            
            if input_type == 'password':
                form_data['has_password'] = True
            if input_type == 'file':
                form_data['has_file_upload'] = True
        
        return form_data
    
    def _extract_links(self, url, html, base_domain):
        """
        Extract links from HTML content.
        
        Args:
            url: The current URL
            html: The HTML content
            base_domain: The base domain
            
        Returns:
            list: List of extracted links
        """
        if not html:
            return []
        
        links = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if href:
                full_url = urljoin(url, href)
                normalized = self._normalize_link(full_url)
                
                if normalized and self._should_crawl(normalized, base_domain):
                    links.add(normalized)
        
        return list(links)
    
    def _normalize_link(self, link):
        """
        Normalize a link for crawling.
        
        Args:
            link: The link to normalize
            
        Returns:
            str: Normalized link or None
        """
        # Skip empty links
        if not link or link.startswith(('mailto:', 'tel:', 'javascript:', '#')):
            return None
        
        # Remove fragments
        parsed = urlparse(link)
        normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', parsed.query, ''))
        
        # Remove trailing slash
        if normalized.endswith('/'):
            normalized = normalized[:-1]
        
        # Add scheme if missing
        if not normalized.startswith(('http://', 'https://')):
            if normalized.startswith('//'):
                normalized = 'https:' + normalized
            else:
                return None
        
        return normalized
    
    def _should_crawl(self, url, base_domain):
        """
        Check if a URL should be crawled.
        
        Args:
            url: The URL to check
            base_domain: The base domain
            
        Returns:
            bool: True if should crawl
        """
        # Skip non-HTTP protocols
        if not url.startswith(('http://', 'https://')):
            return False
        
        # Skip different domains
        domain = self.validator.get_domain(url)
        if domain != base_domain:
            return False
        
        # Skip common file extensions
        skip_extensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.tar', '.gz', '.7z',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv',
            '.exe', '.msi', '.dmg', '.iso'
        ]
        for ext in skip_extensions:
            if url.lower().endswith(ext):
                return False
        
        return True
