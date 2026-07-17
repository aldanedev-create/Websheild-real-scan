# -*- coding: utf-8 -*-

"""
WebShield Scanner - Scan Service
Handles scan creation, execution, and management.
"""

from datetime import datetime
from flask import current_app, request
from extensions import db
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.audit_log import AuditLog
from app.scanner.url_validator import URLValidator
from app.scanner.crawler import Crawler
from app.scanner.attack_surface import AttackSurfaceMapper
from app.scanner.headers import HeaderChecker
from app.scanner.ssl_check import SSLChecker
from app.scanner.cookies import CookieChecker
from app.scanner.forms import FormAnalyzer
from app.scanner.sensitive_files import SensitiveFileDetector
from app.scanner.component_check import ComponentChecker
from app.scanner.javascript_analyzer import JavaScriptAnalyzer
from app.scanner.safe_vulnerability_checks import SafeVulnerabilityChecker
from app.scanner.score_engine import ScoreEngine
from app.services.audit_service import AuditService


class ScanService:
    """Service for handling scan operations."""

    @staticmethod
    def _bounded_int(value, default, minimum, maximum):
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = default
        return max(minimum, min(parsed, maximum))

    @staticmethod
    def _validate_auth_cookie(value):
        if not value:
            return None
        if not isinstance(value, str) or len(value) > 4096 or '=' not in value:
            raise ValueError("auth_cookie must be a simple name=value cookie string")
        name, cookie_value = value.split('=', 1)
        if not name.strip() or not cookie_value or any(ch in value for ch in '\r\n'):
            raise ValueError("auth_cookie must be a simple name=value cookie string")
        return value.strip()
    
    @staticmethod
    def validate_url(url):
        """
        Validate a URL for scanning.
        
        Args:
            url: URL to validate
            
        Returns:
            dict: Validation result
            
        Raises:
            ValueError: Validation errors
        """
        validator = URLValidator()
        is_valid, error_message = validator.validate(url)
        
        if not is_valid:
            raise ValueError(error_message)
        
        return {
            'valid': True,
            'normalized_url': validator.normalize_url(url)
        }
    
    @staticmethod
    def start_scan(user_id, url, confirm_authorization=False, auth_cookie=None, crawl_depth=3, max_pages=100):
        """
        Start a new scan.
        
        Args:
            user_id: User ID
            url: Target URL
            confirm_authorization: Authorization confirmation
            auth_cookie: Authentication cookie (optional)
            crawl_depth: Crawl depth
            max_pages: Maximum pages to crawl
            
        Returns:
            dict: Scan data
            
        Raises:
            ValueError: Validation errors
        """
        user = User.query.get(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        # Check authorization confirmation
        if not confirm_authorization:
            raise ValueError("You must confirm authorization to scan this website")
        
        # Validate URL
        validator = URLValidator()
        is_valid, error_message = validator.validate(url)
        
        if not is_valid:
            raise ValueError(error_message)
        
        normalized_url = validator.normalize_url(url)
        crawl_depth = ScanService._bounded_int(
            crawl_depth,
            current_app.config.get('MAX_CRAWL_DEPTH', 3),
            0,
            current_app.config.get('MAX_CRAWL_DEPTH', 3),
        )
        max_pages = ScanService._bounded_int(
            max_pages,
            current_app.config.get('MAX_PAGES_TO_CRAWL', 100),
            1,
            current_app.config.get('MAX_PAGES_TO_CRAWL', 100),
        )
        ScanService._validate_auth_cookie(auth_cookie)
        
        # Create scan record
        scan = Scan(
            user_id=user_id,
            target_url=normalized_url,
            crawl_depth=crawl_depth,
            max_pages=max_pages
        )
        
        db.session.add(scan)
        db.session.commit()
        
        # Increment user scan count
        user.increment_scans()
        db.session.commit()
        
        # Log scan start
        AuditService.log(
            user_id=user.id,
            action='scan_started',
            details=f'Started scan of {normalized_url}',
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None,
            metadata={'scan_id': scan.id, 'url': normalized_url}
        )
        
        return {
            'scan_id': scan.id,
            'target_url': normalized_url,
            'status': 'pending'
        }
    
    @staticmethod
    def execute_scan(scan_id):
        """
        Execute a scan asynchronously.
        
        Args:
            scan_id: Scan ID
        """
        from app import create_app
        
        app = create_app()
        with app.app_context():
            try:
                scan = Scan.query.get(scan_id)
                if not scan:
                    return
                
                scan.start_scan()
                db.session.commit()
                
                # Initialize scanner components
                validator = URLValidator()
                crawler = Crawler()
                surface_mapper = AttackSurfaceMapper()
                header_checker = HeaderChecker()
                ssl_checker = SSLChecker()
                cookie_checker = CookieChecker()
                form_analyzer = FormAnalyzer()
                sensitive_detector = SensitiveFileDetector()
                component_checker = ComponentChecker()
                javascript_analyzer = JavaScriptAnalyzer()
                vuln_checker = SafeVulnerabilityChecker()
                score_engine = ScoreEngine()
                
                # Crawl the website
                pages = crawler.crawl(
                    scan.target_url,
                    max_depth=scan.crawl_depth,
                    max_pages=scan.max_pages,
                    auth_cookie=scan.auth_cookie
                )
                
                if not pages:
                    scan.fail_scan('No pages could be crawled')
                    scan.auth_cookie = None
                    db.session.commit()
                    return
                
                scan.pages_crawled = len(pages)
                
                # Map attack surface
                surface_data = surface_mapper.analyze(pages)
                scan.attack_surface_data = surface_data
                
                # Check headers
                headers_data = header_checker.check_all_pages(pages)
                scan.headers_data = headers_data
                
                # Check SSL
                ssl_data = ssl_checker.check(scan.target_url)
                
                # Check cookies
                cookies_data = cookie_checker.check_all_pages(pages)
                scan.cookies_data = cookies_data
                
                # Analyze forms
                forms_data = form_analyzer.analyze_all_pages(pages)
                scan.forms_data = forms_data
                
                # Detect sensitive files
                sensitive_data = sensitive_detector.scan(pages)
                
                # Check components
                component_data = component_checker.scan(pages)

                # Analyze browser-visible JavaScript for client-side security issues
                javascript_data = javascript_analyzer.scan(
                    pages,
                    scan.target_url,
                    auth_cookie=scan.auth_cookie
                )
                
                # Run vulnerability checks
                vuln_data = vuln_checker.scan(pages)
                
                # Collect all findings
                all_findings = []
                
                # Add findings from each scanner
                for data in [headers_data, ssl_data, cookies_data, forms_data, 
                            sensitive_data, component_data, javascript_data, vuln_data]:
                    if data and 'findings' in data:
                        for finding_data in data.get('findings', []):
                            category = finding_data.get('category', 'general')
                            finding = Finding(
                                scan_id=scan.id,
                                title=finding_data['title'],
                                severity=finding_data['severity'],
                                category=category,
                                affected_url=finding_data.get('url'),
                                description=finding_data.get('description'),
                                evidence=finding_data.get('evidence'),
                                recommendation=finding_data.get('recommendation'),
                                cwe_id=finding_data.get('cwe_id'),
                                owasp_category=finding_data.get('owasp_category')
                            )
                            db.session.add(finding)
                            all_findings.append(finding)
                
                db.session.commit()
                
                # Update scan statistics
                scan.total_findings = len(all_findings)
                scan.critical_findings = sum(1 for f in all_findings if f.severity == 'critical')
                scan.high_findings = sum(1 for f in all_findings if f.severity == 'high')
                scan.medium_findings = sum(1 for f in all_findings if f.severity == 'medium')
                scan.low_findings = sum(1 for f in all_findings if f.severity == 'low')
                scan.info_findings = sum(1 for f in all_findings if f.severity == 'info')
                
                # Calculate score
                score_engine.calculate_score(scan)
                
                # Generate summary
                scan.summary = ScanService._generate_summary(scan)
                
                scan.complete_scan()
                scan.auth_cookie = None
                db.session.commit()
                
                # Log completion
                AuditService.log(
                    user_id=scan.user_id,
                    action='scan_completed',
                    details=f'Scan of {scan.target_url} completed with {scan.total_findings} findings',
                    ip_address=request.remote_addr if hasattr(request, 'remote_addr') else None,
                    metadata={'scan_id': scan.id, 'findings': scan.total_findings}
                )
                
                current_app.logger.info(f'Scan {scan.id} completed successfully')
                
            except Exception as e:
                current_app.logger.error(f'Scan execution error: {str(e)}')
                try:
                    scan = Scan.query.get(scan_id)
                    if scan:
                        scan.fail_scan(str(e))
                        scan.auth_cookie = None
                        db.session.commit()
                except Exception as rollback_error:
                    db.session.rollback()
                    current_app.logger.error(
                        f'Could not mark scan {scan_id} as failed: {rollback_error}'
                    )
    
    @staticmethod
    def _generate_summary(scan):
        """
        Generate a scan summary.
        
        Args:
            scan: Scan object
            
        Returns:
            str: Summary text
        """
        parts = []
        
        if scan.total_findings == 0:
            parts.append("No security issues were found. The website appears to be well-configured.")
        else:
            parts.append(f"Found {scan.total_findings} security issues:")
            
            if scan.critical_findings > 0:
                parts.append(f"- {scan.critical_findings} critical issues")
            if scan.high_findings > 0:
                parts.append(f"- {scan.high_findings} high severity issues")
            if scan.medium_findings > 0:
                parts.append(f"- {scan.medium_findings} medium severity issues")
            if scan.low_findings > 0:
                parts.append(f"- {scan.low_findings} low severity issues")
            
            parts.append(f"\nSecurity Score: {scan.security_score}/100")
            parts.append(f"Risk Level: {scan.risk_level.upper()}")
            
            if scan.risk_level in ['critical', 'high']:
                parts.append("\n⚠️ Immediate action recommended to address critical and high severity issues.")
            elif scan.risk_level == 'medium':
                parts.append("\n📋 Plan to address medium severity issues in the near future.")
            else:
                parts.append("\n✅ Continue monitoring and addressing low severity issues as part of regular maintenance.")
        
        return "\n".join(parts)
    
    @staticmethod
    def get_scan(user_id, scan_id):
        """
        Get a scan by ID.
        
        Args:
            user_id: User ID
            scan_id: Scan ID
            
        Returns:
            Scan: Scan object or None
        """
        return Scan.query.filter_by(id=scan_id, user_id=user_id).first()
    
    @staticmethod
    def get_user_scans(user_id, status=None, page=1, per_page=10):
        """
        Get user's scans with pagination.
        
        Args:
            user_id: User ID
            status: Filter by status (optional)
            page: Page number
            per_page: Items per page
            
        Returns:
            dict: Paginated scan list
        """
        query = Scan.query.filter_by(user_id=user_id)
        
        if status and status != 'all':
            query = query.filter_by(scan_status=status)
        
        total = query.count()
        scans = query.order_by(Scan.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
        
        return {
            'scans': [s.to_dict() for s in scans],
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        }
    
    @staticmethod
    def cancel_scan(user_id, scan_id):
        """
        Cancel a running scan.
        
        Args:
            user_id: User ID
            scan_id: Scan ID
            
        Returns:
            bool: Success status
            
        Raises:
            ValueError: Validation errors
        """
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            raise ValueError("Scan not found")
        
        if scan.scan_status in ['completed', 'failed', 'cancelled']:
            raise ValueError(f"Scan is already {scan.scan_status}")
        
        scan.cancel_scan()
        db.session.commit()
        
        AuditService.log(
            user_id=user_id,
            action='scan_cancelled',
            details=f'Scan of {scan.target_url} cancelled',
            metadata={'scan_id': scan.id}
        )
        
        return True
    
    @staticmethod
    def get_scan_status(scan_id):
        """
        Get scan status.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            dict: Scan status data
        """
        scan = Scan.query.get(scan_id)
        
        if not scan:
            return None
        
        return scan.to_dict()
    
    @staticmethod
    def get_scan_statistics(user_id):
        """
        Get scan statistics for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            dict: Statistics
        """
        total_scans = Scan.query.filter_by(user_id=user_id).count()
        completed_scans = Scan.query.filter_by(user_id=user_id, scan_status='completed').count()
        
        # Get average security score
        from sqlalchemy import func
        avg_score = db.session.query(func.avg(Scan.security_score)).filter(
            Scan.user_id == user_id,
            Scan.scan_status == 'completed',
            Scan.security_score.isnot(None)
        ).first()[0]
        
        # Get findings counts
        findings_by_severity = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        scans = Scan.query.filter_by(user_id=user_id, scan_status='completed').all()
        for scan in scans:
            findings_by_severity['critical'] += scan.critical_findings or 0
            findings_by_severity['high'] += scan.high_findings or 0
            findings_by_severity['medium'] += scan.medium_findings or 0
            findings_by_severity['low'] += scan.low_findings or 0
            findings_by_severity['info'] += scan.info_findings or 0
        
        return {
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'average_score': round(avg_score, 1) if avg_score is not None else None,
            'findings_by_severity': findings_by_severity
        }
