# -*- coding: utf-8 -*-

"""
WebShield Scanner - Report Builder
Builds comprehensive security reports from scan data.
"""

import json
from datetime import datetime
from flask import current_app


class ReportBuilder:
    """Builds security reports from scan data."""
    
    def __init__(self):
        """Initialize the report builder."""
        pass
    
    def build_report(self, scan, findings):
        """
        Build a comprehensive report from scan data.
        
        Args:
            scan: Scan object
            findings: List of findings
            
        Returns:
            dict: Report data
        """
        report = {
            'meta': self._get_meta_data(scan),
            'summary': self._get_summary(scan, findings),
            'findings': self._get_findings_data(findings),
            'statistics': self._get_statistics(scan, findings),
            'recommendations': self._get_recommendations(findings),
            'raw_data': {
                'attack_surface': scan.attack_surface_data,
                'headers': scan.headers_data,
                'cookies': scan.cookies_data,
                'forms': scan.forms_data
            }
        }
        
        return report
    
    def _get_meta_data(self, scan):
        """
        Get report meta data.
        
        Args:
            scan: Scan object
            
        Returns:
            dict: Meta data
        """
        return {
            'report_id': f"WS-{scan.id}-{datetime.utcnow().strftime('%Y%m%d')}",
            'generated_at': datetime.utcnow().isoformat(),
            'target_url': scan.target_url,
            'scan_started': scan.started_at.isoformat() if scan.started_at else None,
            'scan_completed': scan.completed_at.isoformat() if scan.completed_at else None,
            'scan_duration': scan.get_duration(),
            'app_version': current_app.config.get('APP_VERSION', '1.0.0'),
            'app_name': current_app.config.get('APP_NAME', 'WebShield Scanner')
        }
    
    def _get_summary(self, scan, findings):
        """
        Get report summary.
        
        Args:
            scan: Scan object
            findings: List of findings
            
        Returns:
            dict: Summary data
        """
        total_findings = len(findings)
        critical = sum(1 for f in findings if f.severity == 'critical')
        high = sum(1 for f in findings if f.severity == 'high')
        medium = sum(1 for f in findings if f.severity == 'medium')
        low = sum(1 for f in findings if f.severity == 'low')
        info = sum(1 for f in findings if f.severity == 'info')
        
        return {
            'security_score': scan.security_score,
            'risk_level': scan.risk_level,
            'total_findings': total_findings,
            'severity_breakdown': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
                'info': info
            },
            'pages_crawled': scan.pages_crawled or 0,
            'overall_assessment': self._get_overall_assessment(scan.security_score, scan.risk_level)
        }
    
    def _get_overall_assessment(self, score, risk_level):
        """
        Get overall assessment text.
        
        Args:
            score: Security score
            risk_level: Risk level
            
        Returns:
            str: Assessment text
        """
        if risk_level == 'critical':
            return "The website has critical security issues that require immediate attention. There are severe vulnerabilities that could lead to complete system compromise."
        elif risk_level == 'high':
            return "The website has significant security issues that need to be addressed urgently. Several high-severity vulnerabilities were detected."
        elif risk_level == 'medium':
            return "The website has moderate security issues that should be addressed. While not critical, these issues could lead to security incidents."
        elif risk_level == 'low':
            return "The website is generally secure with minor issues. Continue monitoring and maintain security best practices."
        else:
            return "No significant issues were found. The website appears to be well-configured."
    
    def _get_findings_data(self, findings):
        """
        Get detailed findings data.
        
        Args:
            findings: List of findings
            
        Returns:
            list: Findings data
        """
        findings_data = []
        
        for finding in findings:
            findings_data.append({
                'id': finding.id,
                'title': finding.title,
                'severity': finding.severity,
                'category': finding.category,
                'affected_url': finding.affected_url,
                'description': finding.description,
                'evidence': finding.evidence,
                'recommendation': finding.recommendation,
                'cwe_id': finding.cwe_id,
                'owasp_category': finding.owasp_category,
                'is_fixed': finding.is_fixed,
                'is_false_positive': finding.is_false_positive
            })
        
        return findings_data
    
    def _get_statistics(self, scan, findings):
        """
        Get detailed statistics.
        
        Args:
            scan: Scan object
            findings: List of findings
            
        Returns:
            dict: Statistics
        """
        # Group findings by category
        categories = {}
        for finding in findings:
            category = finding.category
            if category not in categories:
                categories[category] = {
                    'count': 0,
                    'severities': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
                }
            categories[category]['count'] += 1
            severity = finding.severity.lower()
            if severity in categories[category]['severities']:
                categories[category]['severities'][severity] += 1
        
        # Group by CWE
        cwe_counts = {}
        for finding in findings:
            if finding.cwe_id:
                cwe_counts[finding.cwe_id] = cwe_counts.get(finding.cwe_id, 0) + 1
        
        return {
            'total_pages_crawled': scan.pages_crawled or 0,
            'total_findings': len(findings),
            'findings_by_category': categories,
            'findings_by_cwe': cwe_counts,
            'average_score': scan.security_score,
            'risk_level': scan.risk_level
        }
    
    def _get_recommendations(self, findings):
        """
        Get prioritized recommendations.
        
        Args:
            findings: List of findings
            
        Returns:
            list: Recommendations
        """
        recommendations = []
        
        # Group recommendations by severity
        severity_order = ['critical', 'high', 'medium', 'low']
        
        for severity in severity_order:
            severity_findings = [f for f in findings if f.severity == severity]
            
            if not severity_findings:
                continue
            
            # Collect unique recommendations
            recs = {}
            for finding in severity_findings:
                if finding.recommendation and finding.recommendation not in recs:
                    recs[finding.recommendation] = {
                        'finding_id': finding.id,
                        'title': finding.title,
                        'severity': severity
                    }
            
            for recommendation, info in recs.items():
                recommendations.append({
                    'priority': severity,
                    'finding_id': info['finding_id'],
                    'finding_title': info['title'],
                    'recommendation': recommendation
                })
        
        return recommendations
    
    def to_json(self, report):
        """
        Convert report to JSON.
        
        Args:
            report: Report data
            
        Returns:
            str: JSON string
        """
        return json.dumps(report, indent=2, default=str)
    
    def to_html(self, report):
        """
        Convert report to HTML.
        
        Args:
            report: Report data
            
        Returns:
            str: HTML string
        """
        # This would be rendered with a template
        # For now, return a simple HTML structure
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>WebShield Scanner Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #1a1a2e; color: #00f0ff; padding: 20px; }}
                .score {{ font-size: 48px; font-weight: bold; }}
                .finding {{ margin: 10px 0; padding: 15px; border: 1px solid #ddd; }}
                .critical {{ border-left: 5px solid #ff0000; }}
                .high {{ border-left: 5px solid #ff6600; }}
                .medium {{ border-left: 5px solid #ffcc00; }}
                .low {{ border-left: 5px solid #66ccff; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>WebShield Security Report</h1>
                <p>Report ID: {report['meta']['report_id']}</p>
                <p>Target: {report['meta']['target_url']}</p>
                <div class="score">Security Score: {report['summary']['security_score']}/100</div>
                <div>Risk Level: {report['summary']['risk_level']}</div>
            </div>
            
            <h2>Summary</h2>
            <p>{report['summary']['overall_assessment']}</p>
            
            <h2>Findings ({report['summary']['total_findings']})</h2>
        """
        
        for finding in report['findings']:
            severity_class = finding['severity'].lower()
            html += f"""
                <div class="finding {severity_class}">
                    <h3>{finding['title']}</h3>
                    <p><strong>Severity:</strong> {finding['severity']}</p>
                    <p><strong>Category:</strong> {finding['category']}</p>
                    <p><strong>URL:</strong> {finding.get('affected_url', 'N/A')}</p>
                    <p><strong>Description:</strong> {finding['description']}</p>
                    <p><strong>Recommendation:</strong> {finding['recommendation']}</p>
                </div>
            """
        
        html += """
            <div style="margin-top: 40px; font-size: 12px; color: #888;">
                <p>Generated by WebShield Scanner v1.0.0</p>
                <p>For educational and authorized security testing only.</p>
            </div>
        </body>
        </html>
        """
        
        return html