# -*- coding: utf-8 -*-

"""
WebShield Scanner - Report Service
Handles report generation and export.
"""

import json
import os
from datetime import datetime
from flask import current_app, render_template
from itsdangerous import URLSafeTimedSerializer
from extensions import db
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.audit_log import AuditLog
from app.services.pdf_service import PDFService
from app.services.audit_service import AuditService
from app.services.report_triage import (
    build_report_data,
    build_summary_data,
    build_triage_data,
)

REPORT_SHARE_MAX_AGE = 7 * 24 * 60 * 60


class ReportService:
    """Service for handling report operations."""
    
    @staticmethod
    def get_report(user_id, scan_id):
        """
        Get a full scan report.
        
        Args:
            user_id: User ID
            scan_id: Scan ID
            
        Returns:
            dict: Report data
            
        Raises:
            ValueError: Validation errors
        """
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            raise ValueError("Scan not found")
        
        findings = scan.findings.filter_by(is_false_positive=False).all()
        
        return build_report_data(scan, findings)
    
    @staticmethod
    def _get_summary_data(scan, findings):
        """
        Get summary data for report.
        
        Args:
            scan: Scan object
            findings: List of findings
            
        Returns:
            dict: Summary data
        """
        return build_summary_data(scan, findings)

    @staticmethod
    def _get_triage_data(scan, findings):
        """Get grouped triage data for report."""
        return build_triage_data(scan, findings)
    
    @staticmethod
    def _get_findings_by_category(findings):
        """
        Group findings by category.
        
        Args:
            findings: List of findings
            
        Returns:
            dict: Findings by category
        """
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
    
    @staticmethod
    def export_html(user_id, scan_id):
        """
        Export report as HTML.
        
        Args:
            user_id: User ID
            scan_id: Scan ID
            
        Returns:
            str: HTML content
            
        Raises:
            ValueError: Validation errors
        """
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            raise ValueError("Scan not found")
        
        findings = scan.findings.filter_by(is_false_positive=False).all()
        
        # Render HTML template
        html_content = render_template(
            'reports/report_print.html',
            scan=scan,
            findings=findings,
            generated_at=datetime.utcnow()
        )
        
        # Log export
        AuditService.log(
            user_id=user_id,
            action='report_exported',
            details=f'Exported HTML report for scan {scan_id}',
            metadata={'scan_id': scan_id, 'format': 'html'}
        )
        
        return html_content
    
    @staticmethod
    def export_pdf(user_id, scan_id):
        """
        Export report as PDF.
        
        Args:
            user_id: User ID
            scan_id: Scan ID
            
        Returns:
            bytes: PDF data
            
        Raises:
            ValueError: Validation errors
        """
        user = User.query.get(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            raise ValueError("Scan not found")
        
        findings = scan.findings.filter_by(is_false_positive=False).all()
        
        # Generate PDF
        pdf_service = PDFService()
        pdf_data = pdf_service.generate_report(scan, findings)
        
        # Log export
        AuditService.log(
            user_id=user_id,
            action='report_exported',
            details=f'Exported PDF report for scan {scan_id}',
            metadata={'scan_id': scan_id, 'format': 'pdf'}
        )
        
        return pdf_data
    
    @staticmethod
    def export_json(user_id, scan_id):
        """
        Export report as JSON.
        
        Args:
            user_id: User ID
            scan_id: Scan ID
            
        Returns:
            dict: Report data
            
        Raises:
            ValueError: Validation errors
        """
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            raise ValueError("Scan not found")
        
        findings = scan.findings.filter_by(is_false_positive=False).all()
        
        report_data = build_report_data(scan, findings)
        report_data['generated_at'] = datetime.utcnow().isoformat()
        
        # Log export
        AuditService.log(
            user_id=user_id,
            action='report_exported',
            details=f'Exported JSON report for scan {scan_id}',
            metadata={'scan_id': scan_id, 'format': 'json'}
        )
        
        return report_data
    
    @staticmethod
    def get_findings(user_id, scan_id, severity=None, category=None):
        """
        Get findings for a scan with filters.
        
        Args:
            user_id: User ID
            scan_id: Scan ID
            severity: Filter by severity (optional)
            category: Filter by category (optional)
            
        Returns:
            list: Filtered findings
            
        Raises:
            ValueError: Validation errors
        """
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            raise ValueError("Scan not found")
        
        query = scan.findings.filter_by(is_false_positive=False)
        
        if severity:
            query = query.filter_by(severity=severity.lower())
        if category:
            query = query.filter_by(category=category.lower())
        
        return [f.to_dict() for f in query.all()]
    
    @staticmethod
    def update_finding(user_id, scan_id, finding_id, action, note=None):
        """
        Update a finding (mark fixed, false positive, or add note).
        
        Args:
            user_id: User ID
            scan_id: Scan ID
            finding_id: Finding ID
            action: Action to perform (mark_fixed, mark_false_positive, add_note)
            note: Note to add (optional)
            
        Returns:
            dict: Updated finding
            
        Raises:
            ValueError: Validation errors
        """
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            raise ValueError("Scan not found")
        
        finding = Finding.query.filter_by(id=finding_id, scan_id=scan_id).first()
        
        if not finding:
            raise ValueError("Finding not found")
        
        if action == 'mark_fixed':
            finding.mark_fixed()
        elif action == 'mark_false_positive':
            finding.mark_false_positive()
        elif action == 'add_note':
            if not note:
                raise ValueError("Note is required for add_note action")
            finding.notes = note
        else:
            raise ValueError("Invalid action. Use: mark_fixed, mark_false_positive, add_note")
        
        db.session.commit()
        
        AuditService.log(
            user_id=user_id,
            action='finding_updated',
            details=f'Updated finding {finding_id} with action {action}',
            metadata={'finding_id': finding_id, 'action': action}
        )
        
        return finding.to_dict()
    
    @staticmethod
    def share_report(user_id, scan_id):
        """
        Generate a shareable link for the report.
        
        Args:
            user_id: User ID
            scan_id: Scan ID
            
        Returns:
            dict: Share data
            
        Raises:
            ValueError: Validation errors
        """
        user = User.query.get(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        scan = Scan.query.filter_by(id=scan_id, user_id=user_id).first()
        
        if not scan:
            raise ValueError("Scan not found")
        
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        share_token = serializer.dumps({'scan_id': scan.id}, salt='report-share')
        share_url = f"/api/report/shared/{share_token}"
        
        AuditService.log(
            user_id=user_id,
            action='report_shared',
            details=f'Created shareable report for scan {scan_id}',
            metadata={'scan_id': scan_id, 'expires_in': REPORT_SHARE_MAX_AGE}
        )
        
        return {
            'share_url': share_url,
            'share_token': share_token,
            'expires_in': REPORT_SHARE_MAX_AGE
        }
