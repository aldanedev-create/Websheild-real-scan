# -*- coding: utf-8 -*-

"""
WebShield Scanner - Report Tests
Tests for report generation and export functionality.
"""

import json
import pytest
from datetime import datetime
from extensions import db
from app.models.scan import Scan
from app.models.finding import Finding
from app.services.report_service import ReportService


class TestReports:
    """Test report functionality."""

    def test_get_report(self, client, auth_headers, test_scan_with_findings):
        """Test getting a report."""
        response = client.get(f'/api/report/{test_scan_with_findings.id}',
            headers=auth_headers)

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['report']['scan']['id'] == test_scan_with_findings.id
        assert 'findings' in data['report']
        assert 'triage' in data['report']
        assert data['report']['triage']['total_groups'] > 0
        assert len(data['report']['findings']) > 0

    def test_get_report_not_found(self, client, auth_headers):
        """Test getting report for non-existent scan."""
        response = client.get('/api/report/99999',
            headers=auth_headers)

        assert response.status_code == 404
        data = response.get_json()
        assert data['success'] is False
        assert 'not found' in data['message'].lower()

    def test_get_report_unauthorized(self, client, auth_headers, test_scan, test_user2):
        """Test getting report for scan belonging to another user."""
        # Change the scan's user to test_user2
        test_scan.user_id = test_user2.id
        db.session.commit()

        response = client.get(f'/api/report/{test_scan.id}',
            headers=auth_headers)

        assert response.status_code == 404
        data = response.get_json()
        assert data['success'] is False

    def test_export_html(self, client, auth_headers, test_scan_with_findings):
        """Test exporting report as HTML."""
        response = client.get(f'/api/report/{test_scan_with_findings.id}/export/html',
            headers=auth_headers)

        assert response.status_code == 200
        assert 'text/html' in response.content_type
        assert '<html' in response.get_data(as_text=True).lower()

    def test_export_json(self, client, auth_headers, test_scan_with_findings):
        """Test exporting report as JSON."""
        response = client.get(f'/api/report/{test_scan_with_findings.id}/export/json',
            headers=auth_headers)

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'data' in data
        assert data['data']['scan']['id'] == test_scan_with_findings.id
        assert 'summary' in data['data']
        assert 'triage' in data['data']
        assert data['data']['triage']['total_instances'] == len(data['data']['findings'])

    def test_export_pdf_premium_only(self, client, auth_headers, test_scan_with_findings, test_user):
        """Test PDF export requires premium."""
        # User is free, should be denied
        response = client.get(f'/api/report/{test_scan_with_findings.id}/export/pdf',
            headers=auth_headers)

        assert response.status_code == 403
        data = response.get_json()
        assert data['success'] is False
        assert 'premium' in data['message'].lower()

    def test_export_pdf_premium_user(self, client, auth_headers_premium, test_scan_with_findings, test_premium_user):
        """Test PDF export for premium user."""
        test_scan_with_findings.user_id = test_premium_user.id
        db.session.commit()

        response = client.get(f'/api/report/{test_scan_with_findings.id}/export/pdf',
            headers=auth_headers_premium)

        # Should return PDF file
        assert response.status_code == 200
        assert 'application/pdf' in response.content_type
        assert len(response.data) > 100

    def test_get_findings(self, client, auth_headers, test_scan_with_findings):
        """Test getting findings with filters."""
        response = client.get(f'/api/report/{test_scan_with_findings.id}/findings',
            headers=auth_headers)

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'findings' in data
        assert len(data['findings']) > 0

    def test_get_findings_filter_severity(self, client, auth_headers, test_scan_with_findings):
        """Test getting findings filtered by severity."""
        # Get first finding's severity
        first_finding = test_scan_with_findings.findings.first()
        severity = first_finding.severity

        response = client.get(
            f'/api/report/{test_scan_with_findings.id}/findings?severity={severity}',
            headers=auth_headers)

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        for finding in data['findings']:
            assert finding['severity'] == severity

    def test_update_finding_mark_fixed(self, client, auth_headers, test_scan_with_findings):
        """Test marking a finding as fixed."""
        finding = test_scan_with_findings.findings.first()

        response = client.put(
            f'/api/report/{test_scan_with_findings.id}/findings/{finding.id}',
            headers=auth_headers,
            json={'action': 'mark_fixed'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

        # Verify finding was updated
        db.session.refresh(finding)
        assert finding.is_fixed is True

    def test_update_finding_mark_false_positive(self, client, auth_headers, test_scan_with_findings):
        """Test marking a finding as false positive."""
        finding = test_scan_with_findings.findings.first()

        response = client.put(
            f'/api/report/{test_scan_with_findings.id}/findings/{finding.id}',
            headers=auth_headers,
            json={'action': 'mark_false_positive'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

        # Verify finding was updated
        db.session.refresh(finding)
        assert finding.is_false_positive is True

    def test_update_finding_add_note(self, client, auth_headers, test_scan_with_findings):
        """Test adding a note to a finding."""
        finding = test_scan_with_findings.findings.first()

        response = client.put(
            f'/api/report/{test_scan_with_findings.id}/findings/{finding.id}',
            headers=auth_headers,
            json={'action': 'add_note', 'note': 'This is a test note'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

        # Verify note was added
        db.session.refresh(finding)
        assert finding.notes == 'This is a test note'

    def test_share_report_premium_only(self, client, auth_headers, test_scan):
        """Test report sharing requires premium."""
        response = client.post(f'/api/report/{test_scan.id}/share',
            headers=auth_headers)

        assert response.status_code == 403
        data = response.get_json()
        assert data['success'] is False
        assert 'premium' in data['message'].lower()

    def test_share_report_premium_user(self, client, auth_headers_premium, test_scan, test_premium_user):
        """Test report sharing for premium user."""
        test_scan.user_id = test_premium_user.id
        db.session.commit()

        response = client.post(f'/api/report/{test_scan.id}/share',
            headers=auth_headers_premium)

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'share_url' in data
        assert 'share_token' in data
