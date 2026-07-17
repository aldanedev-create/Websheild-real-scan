# -*- coding: utf-8 -*-

"""
WebShield Scanner - Report Routes
Handles report generation, export, and management.
"""

import json
import os
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app, send_file, render_template
from flask_jwt_extended import jwt_required, get_jwt_identity
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from extensions import db
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.audit_log import AuditLog
from app.services.report_service import ReportService
from app.services.pdf_service import PDFService
from app.services.report_triage import build_report_data

report_bp = Blueprint('report', __name__)
REPORT_SHARE_MAX_AGE = 7 * 24 * 60 * 60


def _share_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])


@report_bp.route('/<int:scan_id>', methods=['GET'])
@jwt_required()
def get_report(scan_id):
    """Get full scan report."""
    try:
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({
                'error': 'scan_not_found',
                'message': 'Scan not found'
            }), 404
        
        findings = scan.findings.filter_by(is_false_positive=False).all()
        report = build_report_data(scan, findings)
        
        return jsonify({
            'success': True,
            'report': report
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get report error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch report'
        }), 500


def get_findings_by_category(findings):
    """Group findings by category."""
    categories = {}
    for finding in findings:
        category = finding.category
        if category not in categories:
            categories[category] = {
                'count': 0,
                'severities': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            }
        categories[category]['count'] += 1
        categories[category]['severities'][finding.severity] = \
            categories[category]['severities'].get(finding.severity, 0) + 1
    return categories


@report_bp.route('/shared/<token>', methods=['GET'])
def get_shared_report(token):
    """Get a shared report by signed token."""
    try:
        payload = _share_serializer().loads(
            token,
            salt='report-share',
            max_age=REPORT_SHARE_MAX_AGE,
        )
    except SignatureExpired:
        return jsonify({
            'error': 'share_expired',
            'message': 'This shared report link has expired'
        }), 410
    except BadSignature:
        return jsonify({
            'error': 'invalid_share_token',
            'message': 'Invalid shared report link'
        }), 404

    scan = Scan.query.get(payload.get('scan_id'))
    if not scan:
        return jsonify({
            'error': 'scan_not_found',
            'message': 'Scan not found'
        }), 404

    findings = scan.findings.filter_by(is_false_positive=False).all()
    return jsonify({
        'success': True,
        'report': build_report_data(scan, findings, include_user=False)
    }), 200


@report_bp.route('/<int:scan_id>/export/html', methods=['GET'])
@jwt_required()
def export_html(scan_id):
    """Export report as HTML."""
    try:
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({
                'error': 'scan_not_found',
                'message': 'Scan not found'
            }), 404
        
        findings = scan.findings.filter_by(is_false_positive=False).all()
        report = build_report_data(scan, findings)
        
        # Render HTML template
        html_content = render_template(
            'reports/report_print.html',
            scan=scan,
            findings=findings,
            report=report,
            triage=report['triage'],
            summary=report['summary'],
            generated_at=datetime.utcnow()
        )
        
        # Log export
        AuditLog.log(
            user_id=user_id,
            action='report_exported',
            details=f'Exported HTML report for scan {scan_id}',
            metadata={'scan_id': scan_id, 'format': 'html'}
        )
        
        return html_content, 200, {'Content-Type': 'text/html'}
        
    except Exception as e:
        current_app.logger.error(f'Export HTML error: {str(e)}')
        return jsonify({
            'error': 'export_failed',
            'message': 'Could not export HTML report'
        }), 500


@report_bp.route('/<int:scan_id>/export/pdf', methods=['GET'])
@jwt_required()
def export_pdf(scan_id):
    """Export report as PDF."""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({
                'error': 'scan_not_found',
                'message': 'Scan not found'
            }), 404
        
        findings = scan.findings.filter_by(is_false_positive=False).all()
        
        # Generate PDF
        pdf_service = PDFService()
        pdf_data = pdf_service.generate_report(scan, findings)
        
        # Log export
        AuditLog.log(
            user_id=user_id,
            action='report_exported',
            details=f'Exported PDF report for scan {scan_id}',
            metadata={'scan_id': scan_id, 'format': 'pdf'}
        )
        
        # Save PDF to file
        filename = f"webshield_report_{scan_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        report_folder = current_app.config.get('REPORT_FOLDER')
        os.makedirs(report_folder, exist_ok=True)
        filepath = os.path.abspath(os.path.join(report_folder, filename))
        
        with open(filepath, 'wb') as f:
            f.write(pdf_data)
        
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )
        
    except Exception as e:
        current_app.logger.error(f'Export PDF error: {str(e)}')
        return jsonify({
            'error': 'export_failed',
            'message': 'Could not export PDF report'
        }), 500


@report_bp.route('/<int:scan_id>/export/json', methods=['GET'])
@jwt_required()
def export_json(scan_id):
    """Export report as JSON."""
    try:
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({
                'error': 'scan_not_found',
                'message': 'Scan not found'
            }), 404
        
        findings = scan.findings.filter_by(is_false_positive=False).all()
        
        report_data = build_report_data(scan, findings)
        report_data['generated_at'] = datetime.utcnow().isoformat()
        
        # Log export
        AuditLog.log(
            user_id=user_id,
            action='report_exported',
            details=f'Exported JSON report for scan {scan_id}',
            metadata={'scan_id': scan_id, 'format': 'json'}
        )
        
        return jsonify({
            'success': True,
            'data': report_data
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Export JSON error: {str(e)}')
        return jsonify({
            'error': 'export_failed',
            'message': 'Could not export JSON report'
        }), 500


@report_bp.route('/<int:scan_id>/findings', methods=['GET'])
@jwt_required()
def get_findings(scan_id):
    """Get findings for a scan with filtering."""
    try:
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({
                'error': 'scan_not_found',
                'message': 'Scan not found'
            }), 404
        
        # Get filter parameters
        severity = request.args.get('severity')
        category = request.args.get('category')
        
        query = scan.findings.filter_by(is_false_positive=False)
        
        if severity:
            query = query.filter_by(severity=severity.lower())
        if category:
            query = query.filter_by(category=category.lower())
        
        findings = query.all()
        
        return jsonify({
            'success': True,
            'findings': [f.to_dict() for f in findings]
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get findings error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch findings'
        }), 500


@report_bp.route('/<int:scan_id>/findings/<int:finding_id>', methods=['PUT'])
@jwt_required()
def update_finding(scan_id, finding_id):
    """Update a finding (e.g., mark as false positive or fixed)."""
    try:
        user_id = get_jwt_identity()
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({
                'error': 'scan_not_found',
                'message': 'Scan not found'
            }), 404
        
        finding = Finding.query.filter_by(id=finding_id, scan_id=scan_id).first()
        
        if not finding:
            return jsonify({
                'error': 'finding_not_found',
                'message': 'Finding not found'
            }), 404
        
        data = request.get_json(silent=True) or {}
        action = data.get('action')
        
        if action == 'mark_fixed':
            finding.mark_fixed()
        elif action == 'mark_false_positive':
            finding.mark_false_positive()
        elif action == 'add_note':
            finding.notes = data.get('notes', data.get('note', ''))
        else:
            return jsonify({
                'error': 'invalid_action',
                'message': 'Invalid action. Use: mark_fixed, mark_false_positive, add_note'
            }), 400
        
        db.session.commit()
        
        AuditLog.log(
            user_id=user_id,
            action='finding_updated',
            details=f'Updated finding {finding_id} with action {action}',
            metadata={'finding_id': finding_id, 'action': action}
        )
        
        return jsonify({
            'success': True,
            'message': 'Finding updated successfully',
            'finding': finding.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Update finding error: {str(e)}')
        return jsonify({
            'error': 'update_failed',
            'message': 'Could not update finding'
        }), 500


@report_bp.route('/<int:scan_id>/share', methods=['POST'])
@jwt_required()
def share_report(scan_id):
    """Generate a shareable link for the report."""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({
                'error': 'scan_not_found',
                'message': 'Scan not found'
            }), 404
        
        share_token = _share_serializer().dumps(
            {'scan_id': scan.id},
            salt='report-share',
        )
        share_url = f"/api/report/shared/{share_token}"
        
        AuditLog.log(
            user_id=user_id,
            action='report_shared',
            details=f'Created shareable report for scan {scan_id}',
            metadata={'scan_id': scan_id, 'expires_in': REPORT_SHARE_MAX_AGE}
        )
        
        return jsonify({
            'success': True,
            'share_url': share_url,
            'share_token': share_token,
            'expires_in': REPORT_SHARE_MAX_AGE
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Share report error: {str(e)}')
        return jsonify({
            'error': 'share_failed',
            'message': 'Could not generate shareable link'
        }), 500
