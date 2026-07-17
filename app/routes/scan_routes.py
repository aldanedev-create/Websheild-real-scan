# -*- coding: utf-8 -*-

"""
WebShield Scanner - Scan Routes
Handles scan creation, management, and execution.
"""

import json
import re
import threading
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from extensions import db, limiter
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
from app.services.scan_service import ScanService

scan_bp = Blueprint('scan', __name__)


# Scan workers run in-process, so keep a cancellation signal for each active
# scan.  The database status remains the source of truth for reloads or a
# second web worker, while the event makes cancellation immediate in the
# current worker.
_scan_cancel_events = {}
_scan_cancel_events_lock = threading.Lock()


def _register_scan_cancel_event(scan_id):
    event = threading.Event()
    with _scan_cancel_events_lock:
        _scan_cancel_events[scan_id] = event
    return event


def _get_scan_cancel_event(scan_id):
    with _scan_cancel_events_lock:
        return _scan_cancel_events.get(scan_id)


def _release_scan_cancel_event(scan_id):
    with _scan_cancel_events_lock:
        _scan_cancel_events.pop(scan_id, None)


def _scan_is_cancelled(scan_id, cancel_event=None):
    if cancel_event is not None and cancel_event.is_set():
        return True

    try:
        status = db.session.query(Scan.scan_status).filter(Scan.id == scan_id).scalar()
        return status == 'cancelled'
    except Exception:
        return False


def _mark_scan_cancelled(scan):
    if scan.scan_status != 'cancelled':
        scan.cancel_scan()
    scan.summary = 'Scan cancelled by user.'
    scan.auth_cookie = None
    db.session.commit()


def _scan_rate_limit():
    """Build the configured per-user scan-start quota for Flask-Limiter."""
    limit = current_app.config.get('SCAN_RATE_LIMIT', 50)
    window_hours = current_app.config.get('SCAN_RATE_LIMIT_WINDOW_HOURS', 3)
    return f'{limit} per {window_hours} hours'


def _scan_rate_limit_key():
    """Keep one account from consuming another account's scan allocation."""
    return f'scan-user:{get_jwt_identity()}'


def _bounded_int(value, default, minimum, maximum):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _get_valid_auth_cookie(value):
    if not value:
        return None
    if not isinstance(value, str) or len(value) > 4096 or '=' not in value:
        raise ValueError('auth_cookie must be a simple name=value cookie string')
    name, cookie_value = value.split('=', 1)
    if not name.strip() or not cookie_value or any(ch in value for ch in '\r\n'):
        raise ValueError('auth_cookie must be a simple name=value cookie string')
    return value.strip()


@scan_bp.route('/validate', methods=['POST'])
@jwt_required()
def validate_url():
    """Validate a URL before scanning."""
    try:
        data = request.get_json(silent=True) or {}
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'error': 'missing_url',
                'message': 'URL is required'
            }), 400
        
        # Validate URL
        validator = URLValidator()
        is_valid, error_message = validator.validate(url)
        
        if not is_valid:
            return jsonify({
                'success': False,
                'valid': False,
                'error': error_message
            }), 400
        
        return jsonify({
            'success': True,
            'valid': True,
            'normalized_url': validator.normalize_url(url)
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'URL validation error: {str(e)}')
        return jsonify({
            'error': 'validation_failed',
            'message': 'Could not validate URL'
        }), 500


@scan_bp.route('/start', methods=['POST'])
@jwt_required()
@limiter.limit(
    _scan_rate_limit,
    key_func=_scan_rate_limit_key,
    # Count scans that were actually accepted, not malformed requests.
    deduct_when=lambda response: response.status_code == 202,
)
def start_scan():
    """
    Start a new website scan.
    
    Request body:
        url: str
        crawl_depth: int (optional)
        max_pages: int (optional)
        auth_cookie: str (optional)
        confirm_authorization: bool
    """
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        data = request.get_json(silent=True) or {}
        url = data.get('url', '').strip()
        confirm_authorization = data.get('confirm_authorization', False)
        
        if not url:
            return jsonify({
                'error': 'missing_url',
                'message': 'URL is required'
            }), 400
        
        # Check authorization confirmation
        if not confirm_authorization:
            return jsonify({
                'error': 'authorization_required',
                'message': 'You must confirm authorization to scan this website'
            }), 403
        
        # Validate URL
        validator = URLValidator()
        is_valid, error_message = validator.validate(url)
        
        if not is_valid:
            return jsonify({
                'error': 'invalid_url',
                'message': error_message
            }), 400
        
        normalized_url = validator.normalize_url(url)
        crawl_depth = _bounded_int(
            data.get('crawl_depth'),
            current_app.config.get('MAX_CRAWL_DEPTH', 3),
            0,
            current_app.config.get('MAX_CRAWL_DEPTH', 3),
        )
        max_pages = _bounded_int(
            data.get('max_pages'),
            current_app.config.get('MAX_PAGES_TO_CRAWL', 100),
            1,
            current_app.config.get('MAX_PAGES_TO_CRAWL', 100),
        )
        try:
            auth_cookie = _get_valid_auth_cookie(data.get('auth_cookie'))
        except ValueError as cookie_error:
            return jsonify({
                'error': 'invalid_auth_cookie',
                'message': str(cookie_error)
            }), 400
        
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
        AuditLog.log(
            user_id=user.id,
            action='scan_started',
            details=f'Started scan of {normalized_url}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                'scan_id': scan.id,
                'url': normalized_url,
                'confirmed_authorization': bool(confirm_authorization),
                'crawl_depth': crawl_depth,
                'max_pages': max_pages
            }
        )
        
        if not current_app.config.get('TESTING'):
            app = current_app._get_current_object()
            remote_addr = request.remote_addr
            cancel_event = _register_scan_cancel_event(scan.id)
            worker = threading.Thread(
                target=run_scan,
                args=(scan.id, app, remote_addr, auth_cookie, cancel_event),
                daemon=True
            )
            worker.start()
        
        return jsonify({
            'success': True,
            'message': 'Scan started successfully',
            'scan_id': scan.id
        }), 202
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Start scan error: {str(e)}')
        return jsonify({
            'error': 'scan_start_failed',
            'message': 'Could not start scan'
        }), 500


def run_scan(
    scan_id,
    app=None,
    remote_addr=None,
    auth_cookie=None,
    cancel_event=None,
):
    """Execute the scan process."""
    if app is None:
        from app import create_app
        app = create_app()

    with app.app_context():
        cancel_event = cancel_event or _get_scan_cancel_event(scan_id)
        scan = None

        def stop_if_cancelled():
            if scan is not None and _scan_is_cancelled(scan_id, cancel_event):
                _mark_scan_cancelled(scan)
                return True
            return False

        try:
            scan = Scan.query.get(scan_id)
            if not scan:
                return

            if stop_if_cancelled():
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
                auth_cookie=auth_cookie or scan.auth_cookie,
                should_cancel=lambda: _scan_is_cancelled(scan_id, cancel_event),
            )

            if stop_if_cancelled():
                return
            
            if not pages:
                if stop_if_cancelled():
                    return
                scan.fail_scan('No pages could be crawled')
                scan.auth_cookie = None
                db.session.commit()
                return
            
            scan.pages_crawled = len(pages)
            
            # Map attack surface
            surface_data = surface_mapper.analyze(pages)
            scan.attack_surface_data = surface_data
            if stop_if_cancelled():
                return
            
            # Check headers
            headers_data = header_checker.check_all_pages(pages)
            scan.headers_data = headers_data
            if stop_if_cancelled():
                return
            
            # Check SSL
            ssl_data = ssl_checker.check(scan.target_url)
            if stop_if_cancelled():
                return
            
            # Check cookies
            cookies_data = cookie_checker.check_all_pages(pages)
            scan.cookies_data = cookies_data
            if stop_if_cancelled():
                return
            
            # Analyze forms
            forms_data = form_analyzer.analyze_all_pages(pages)
            scan.forms_data = forms_data
            if stop_if_cancelled():
                return
            
            # Detect sensitive files
            sensitive_data = sensitive_detector.scan(pages)
            if stop_if_cancelled():
                return
            
            # Check components
            component_data = component_checker.scan(pages)
            if stop_if_cancelled():
                return

            # Analyze browser-visible JavaScript for client-side security issues
            javascript_data = javascript_analyzer.scan(
                pages,
                scan.target_url,
                auth_cookie=auth_cookie or scan.auth_cookie
            )
            if stop_if_cancelled():
                return
            
            # Run vulnerability checks
            vuln_data = vuln_checker.scan(pages)
            if stop_if_cancelled():
                return
            
            # Generate findings
            findings = []
            
            # Add header findings
            for finding_data in headers_data.get('findings', []):
                finding = Finding(
                    scan_id=scan.id,
                    title=finding_data['title'],
                    severity=finding_data['severity'],
                    category='security_headers',
                    affected_url=finding_data.get('url'),
                    description=finding_data.get('description'),
                    evidence=finding_data.get('evidence'),
                    recommendation=finding_data.get('recommendation'),
                    cwe_id=finding_data.get('cwe_id'),
                    owasp_category=finding_data.get('owasp_category', 'Security Misconfiguration')
                )
                findings.append(finding)
            
            # Add SSL findings
            for finding_data in ssl_data.get('findings', []):
                finding = Finding(
                    scan_id=scan.id,
                    title=finding_data['title'],
                    severity=finding_data['severity'],
                    category='ssl',
                    affected_url=scan.target_url,
                    description=finding_data.get('description'),
                    evidence=finding_data.get('evidence'),
                    recommendation=finding_data.get('recommendation'),
                    cwe_id=finding_data.get('cwe_id'),
                    owasp_category=finding_data.get('owasp_category', 'Cryptographic Failures')
                )
                findings.append(finding)
            
            # Add cookie findings
            for finding_data in cookies_data.get('findings', []):
                finding = Finding(
                    scan_id=scan.id,
                    title=finding_data['title'],
                    severity=finding_data['severity'],
                    category='cookies',
                    affected_url=finding_data.get('url'),
                    description=finding_data.get('description'),
                    evidence=finding_data.get('evidence'),
                    recommendation=finding_data.get('recommendation'),
                    cwe_id=finding_data.get('cwe_id'),
                    owasp_category=finding_data.get('owasp_category', 'Sensitive Data Exposure')
                )
                findings.append(finding)

            # Add form findings
            for finding_data in forms_data.get('findings', []):
                finding = Finding(
                    scan_id=scan.id,
                    title=finding_data['title'],
                    severity=finding_data['severity'],
                    category=finding_data.get('category', 'forms'),
                    affected_url=finding_data.get('url'),
                    description=finding_data.get('description'),
                    evidence=finding_data.get('evidence'),
                    recommendation=finding_data.get('recommendation'),
                    cwe_id=finding_data.get('cwe_id'),
                    owasp_category=finding_data.get('owasp_category', 'Insecure Design')
                )
                findings.append(finding)
            
            # Add sensitive file findings
            for finding_data in sensitive_data.get('findings', []):
                finding = Finding(
                    scan_id=scan.id,
                    title=finding_data['title'],
                    severity=finding_data['severity'],
                    category='sensitive_data',
                    affected_url=finding_data.get('url'),
                    description=finding_data.get('description'),
                    evidence=finding_data.get('evidence'),
                    recommendation=finding_data.get('recommendation'),
                    cwe_id=finding_data.get('cwe_id'),
                    owasp_category=finding_data.get('owasp_category', 'Sensitive Data Exposure')
                )
                findings.append(finding)
            
            # Add component findings
            for finding_data in component_data.get('findings', []):
                finding = Finding(
                    scan_id=scan.id,
                    title=finding_data['title'],
                    severity=finding_data['severity'],
                    category='components',
                    affected_url=finding_data.get('url'),
                    description=finding_data.get('description'),
                    evidence=finding_data.get('evidence'),
                    recommendation=finding_data.get('recommendation'),
                    cwe_id=finding_data.get('cwe_id'),
                    owasp_category=finding_data.get('owasp_category', 'Vulnerable Components')
                )
                findings.append(finding)

            # Add client-side JavaScript findings
            for finding_data in javascript_data.get('findings', []):
                finding = Finding(
                    scan_id=scan.id,
                    title=finding_data['title'],
                    severity=finding_data['severity'],
                    category=finding_data.get('category', 'client_code'),
                    affected_url=finding_data.get('url'),
                    description=finding_data.get('description'),
                    evidence=finding_data.get('evidence'),
                    recommendation=finding_data.get('recommendation'),
                    cwe_id=finding_data.get('cwe_id'),
                    owasp_category=finding_data.get('owasp_category', 'Insecure Design')
                )
                findings.append(finding)
            
            # Add vulnerability findings
            for finding_data in vuln_data.get('findings', []):
                finding = Finding(
                    scan_id=scan.id,
                    title=finding_data['title'],
                    severity=finding_data['severity'],
                    category='vulnerabilities',
                    affected_url=finding_data.get('url'),
                    description=finding_data.get('description'),
                    evidence=finding_data.get('evidence'),
                    recommendation=finding_data.get('recommendation'),
                    cwe_id=finding_data.get('cwe_id'),
                    owasp_category=finding_data.get('owasp_category', 'Injection')
                )
                findings.append(finding)
            
            # Save all findings
            if stop_if_cancelled():
                return
            for finding in findings:
                db.session.add(finding)
            
            db.session.commit()
            
            # Update scan statistics
            scan.total_findings = len(findings)
            scan.critical_findings = sum(1 for f in findings if f.severity == 'critical')
            scan.high_findings = sum(1 for f in findings if f.severity == 'high')
            scan.medium_findings = sum(1 for f in findings if f.severity == 'medium')
            scan.low_findings = sum(1 for f in findings if f.severity == 'low')
            scan.info_findings = sum(1 for f in findings if f.severity == 'info')
            
            # Calculate score
            score_engine.calculate_score(scan)
            
            # Generate summary
            scan.summary = generate_summary(scan)
            
            if stop_if_cancelled():
                return

            scan.complete_scan()
            scan.auth_cookie = None
            db.session.commit()
            
            # Log completion
            AuditLog.log(
                user_id=scan.user_id,
                action='scan_completed',
                details=f'Scan of {scan.target_url} completed with {scan.total_findings} findings',
                ip_address=remote_addr,
                metadata={'scan_id': scan.id, 'findings': scan.total_findings}
            )
            
            current_app.logger.info(f'Scan {scan.id} completed successfully')
            
        except Exception as e:
            current_app.logger.error(f'Scan execution error: {str(e)}')
            try:
                scan = Scan.query.get(scan_id)
                if scan and _scan_is_cancelled(scan_id, cancel_event):
                    _mark_scan_cancelled(scan)
                elif scan:
                    scan.fail_scan(str(e))
                    scan.auth_cookie = None
                    db.session.commit()
            except Exception as rollback_error:
                db.session.rollback()
                current_app.logger.error(
                    f'Could not mark scan {scan_id} as failed: {rollback_error}'
                )
        finally:
            _release_scan_cancel_event(scan_id)
            db.session.remove()


def generate_summary(scan):
    """Generate a scan summary."""
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


@scan_bp.route('/<int:scan_id>/status', methods=['GET'])
@jwt_required()
def get_scan_status(scan_id):
    """Get scan status and progress."""
    try:
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({
                'error': 'scan_not_found',
                'message': 'Scan not found'
            }), 404
        
        return jsonify({
            'success': True,
            'scan': scan.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get scan status error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch scan status'
        }), 500


@scan_bp.route('/<int:scan_id>/cancel', methods=['POST'])
@jwt_required()
def cancel_scan(scan_id):
    """Cancel a running scan."""
    try:
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({
                'error': 'scan_not_found',
                'message': 'Scan not found'
            }), 404
        
        if scan.scan_status in ['completed', 'failed']:
            return jsonify({
                'error': 'scan_already_finished',
                'message': f'Scan is already {scan.scan_status}'
            }), 400
        
        cancel_event = _get_scan_cancel_event(scan.id)
        if cancel_event is not None:
            cancel_event.set()

        if scan.scan_status == 'cancelled':
            return jsonify({
                'success': True,
                'message': 'Scan is already cancelled',
                'scan': scan.to_dict()
            }), 200

        scan.cancel_scan()
        scan.summary = 'Scan cancelled by user.'
        db.session.commit()
        
        AuditLog.log(
            user_id=user_id,
            action='scan_cancelled',
            details=f'Scan of {scan.target_url} cancelled',
            metadata={'scan_id': scan.id}
        )
        
        return jsonify({
            'success': True,
            'message': 'Scan cancelled successfully',
            'scan': scan.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Cancel scan error: {str(e)}')
        return jsonify({
            'error': 'cancel_failed',
            'message': 'Could not cancel scan'
        }), 500


@scan_bp.route('/<int:scan_id>/delete', methods=['POST'])
@jwt_required()
def delete_scan(scan_id):
    """Delete a finished scan owned by the current user."""
    try:
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()

        if not scan:
            return jsonify({
                'error': 'scan_not_found',
                'message': 'Scan not found'
            }), 404

        if scan.scan_status in ['pending', 'running']:
            return jsonify({
                'error': 'scan_active',
                'message': 'Cancel the scan before deleting it'
            }), 400

        target_url = scan.target_url
        db.session.delete(scan)
        db.session.commit()

        AuditLog.log(
            user_id=user_id,
            action='scan_deleted',
            details=f'Deleted scan of {target_url}',
            metadata={'scan_id': scan_id}
        )

        return jsonify({
            'success': True,
            'message': 'Scan deleted successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Delete scan error: {str(e)}')
        return jsonify({
            'error': 'delete_failed',
            'message': 'Could not delete scan'
        }), 500
