# -*- coding: utf-8 -*-

"""
WebShield Scanner - PDF Service
Generates PDF reports from scan data.
"""

from datetime import datetime
from html import escape
from flask import current_app
from app.services.report_triage import build_triage_data


class PDFService:
    """Service for generating PDF reports."""
    
    def __init__(self):
        """Initialize the PDF service."""
        self.base_url = current_app.root_path
    
    def generate_report(self, scan, findings):
        """
        Generate a PDF report from scan data.
        
        Args:
            scan: Scan object
            findings: List of findings
            
        Returns:
            bytes: PDF data
            
        Raises:
            Exception: PDF generation failed
        """
        try:
            # Generate HTML content
            html_content = self._generate_html(scan, findings)
            
            try:
                from weasyprint import HTML
                pdf_data = HTML(string=html_content, base_url=self.base_url).write_pdf()
            except (ImportError, OSError) as exc:
                current_app.logger.warning(
                    "WeasyPrint is unavailable; using ReportLab PDF fallback: %s",
                    str(exc),
                )
                pdf_data = self._generate_reportlab_pdf(scan, findings)
            
            return pdf_data
            
        except Exception as e:
            current_app.logger.error(f'PDF generation error: {str(e)}')
            raise Exception(f'Could not generate PDF: {str(e)}')
    
    def _generate_html(self, scan, findings):
        """
        Generate HTML content for the PDF.
        
        Args:
            scan: Scan object
            findings: List of findings
            
        Returns:
            str: HTML content
        """
        # Get severity counts
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1

        triage = build_triage_data(scan, findings)
        priority_html = self._render_priority_html(triage)
        category_html = self._render_category_html(triage)
        
        # Build HTML
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>WebShield Security Report</title>
            <style>
                body {{
                    font-family: Arial, Helvetica, sans-serif;
                    margin: 40px;
                    color: #333;
                    line-height: 1.6;
                }}
                .header {{
                    background: #1a1a2e;
                    color: #00f0ff;
                    padding: 30px;
                    border-radius: 5px;
                    margin-bottom: 30px;
                }}
                .header h1 {{
                    margin: 0 0 10px 0;
                    font-size: 28px;
                }}
                .header .subtitle {{
                    color: #aaa;
                    font-size: 14px;
                }}
                .score-section {{
                    background: #f5f5f5;
                    padding: 20px;
                    border-radius: 5px;
                    margin-bottom: 30px;
                    text-align: center;
                }}
                .score {{
                    font-size: 48px;
                    font-weight: bold;
                    color: {self._get_score_color(scan.security_score)};
                }}
                .risk-level {{
                    font-size: 20px;
                    font-weight: bold;
                    color: {self._get_risk_color(scan.risk_level)};
                }}
                .section {{
                    margin-bottom: 30px;
                }}
                .section h2 {{
                    border-bottom: 2px solid #00f0ff;
                    padding-bottom: 10px;
                    color: #1a1a2e;
                }}
                .finding {{
                    margin: 15px 0;
                    padding: 15px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    page-break-inside: avoid;
                }}
                .finding .severity {{
                    font-weight: bold;
                    padding: 3px 10px;
                    border-radius: 3px;
                    display: inline-block;
                    font-size: 12px;
                    text-transform: uppercase;
                }}
                .severity-critical {{
                    background: #ff0000;
                    color: white;
                }}
                .severity-high {{
                    background: #ff6600;
                    color: white;
                }}
                .severity-medium {{
                    background: #ffcc00;
                    color: black;
                }}
                .severity-low {{
                    background: #66ccff;
                    color: black;
                }}
                .severity-info {{
                    background: #999;
                    color: white;
                }}
                .finding .title {{
                    font-size: 16px;
                    font-weight: bold;
                    margin: 5px 0;
                }}
                .finding .url {{
                    color: #666;
                    font-size: 12px;
                    word-break: break-all;
                }}
                .finding .description {{
                    margin: 10px 0;
                }}
                .finding .recommendation {{
                    background: #f0f8ff;
                    padding: 10px;
                    border-left: 4px solid #00f0ff;
                    margin: 10px 0;
                }}
                .summary-box {{
                    display: inline-block;
                    padding: 10px 20px;
                    margin: 5px;
                    background: #f5f5f5;
                    border-radius: 5px;
                    text-align: center;
                }}
                .summary-box .number {{
                    font-size: 24px;
                    font-weight: bold;
                }}
                .priority-grid {{
                    display: grid;
                    grid-template-columns: repeat(2, minmax(0, 1fr));
                    gap: 12px;
                    margin: 15px 0;
                }}
                .priority-card {{
                    border: 1px solid #ddd;
                    border-left: 5px solid #999;
                    border-radius: 5px;
                    padding: 12px;
                    page-break-inside: avoid;
                }}
                .priority-card.critical {{ border-left-color: #ff0000; }}
                .priority-card.high {{ border-left-color: #ff6600; }}
                .priority-card.medium {{ border-left-color: #ffcc00; }}
                .priority-card.low {{ border-left-color: #66ccff; }}
                .priority-card .rank {{
                    color: #666;
                    font-size: 11px;
                    text-transform: uppercase;
                }}
                .priority-card .title {{
                    font-size: 14px;
                    font-weight: bold;
                    margin: 4px 0;
                }}
                .priority-card .meta {{
                    color: #666;
                    font-size: 11px;
                    word-break: break-word;
                }}
                .priority-card .fix {{
                    background: #f0f8ff;
                    border-left: 4px solid #00f0ff;
                    margin-top: 8px;
                    padding: 8px;
                    font-size: 11px;
                }}
                .category-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 12px 0;
                    font-size: 12px;
                }}
                .category-table th,
                .category-table td {{
                    border-bottom: 1px solid #ddd;
                    padding: 7px 6px;
                    text-align: left;
                }}
                .affected-list {{
                    margin: 8px 0 0 16px;
                    padding: 0;
                    font-size: 11px;
                    color: #666;
                }}
                .affected-list li {{
                    margin-bottom: 3px;
                    word-break: break-all;
                }}
                .footer {{
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    font-size: 12px;
                    color: #888;
                    text-align: center;
                }}
                .badge {{
                    display: inline-block;
                    padding: 2px 8px;
                    border-radius: 3px;
                    font-size: 11px;
                    font-weight: bold;
                }}
                .badge-critical {{ background: #ff0000; color: white; }}
                .badge-high {{ background: #ff6600; color: white; }}
                .badge-medium {{ background: #ffcc00; color: black; }}
                .badge-low {{ background: #66ccff; color: black; }}
                .badge-info {{ background: #999; color: white; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>WebShield Security Report</h1>
                <div class="subtitle">Report ID: WS-{scan.id}-{datetime.utcnow().strftime('%Y%m%d')}</div>
                <div class="subtitle">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
                <div class="subtitle">Target: {escape(str(scan.target_url or ''))}</div>
            </div>
            
            <div class="score-section">
                <div class="score">{self._format_score(scan.security_score)}</div>
                <div class="risk-level">Risk Level: {(scan.risk_level or 'unknown').upper()}</div>
                <div style="margin-top: 10px;">
                    <span class="summary-box">
                        <div class="number">{len(findings)}</div>
                        <div>Total Findings</div>
                    </span>
                    <span class="summary-box">
                        <div class="number">{scan.pages_crawled or 0}</div>
                        <div>Pages Crawled</div>
                    </span>
                    <span class="summary-box">
                        <div class="number">{scan.get_duration() or 0}s</div>
                        <div>Scan Duration</div>
                    </span>
                </div>
            </div>
            
            <div class="section">
                <h2>Summary</h2>
                <p>{escape(self._get_summary_text(scan))}</p>
                
                <div style="margin: 20px 0;">
                    <h3>Findings by Severity</h3>
                    <div>
                        <span class="summary-box">
                            <div class="number" style="color: #ff0000;">{severity_counts['critical']}</div>
                            <div>Critical</div>
                        </span>
                        <span class="summary-box">
                            <div class="number" style="color: #ff6600;">{severity_counts['high']}</div>
                            <div>High</div>
                        </span>
                        <span class="summary-box">
                            <div class="number" style="color: #ffcc00;">{severity_counts['medium']}</div>
                            <div>Medium</div>
                        </span>
                        <span class="summary-box">
                            <div class="number" style="color: #66ccff;">{severity_counts['low']}</div>
                            <div>Low</div>
                        </span>
                        <span class="summary-box">
                            <div class="number" style="color: #999;">{severity_counts['info']}</div>
                            <div>Info</div>
                        </span>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>Priority Triage</h2>
                {priority_html}
                {category_html}
            </div>
            
            <div class="section">
                <h2>Grouped Findings</h2>
        """
        
        for group in triage['grouped_findings']:
            severity = group.get('severity') or 'info'
            severity_class = f"severity-{severity}"
            affected_items = ''.join(
                f"<li>{escape(str(url))}</li>"
                for url in group.get('affected_urls', [])[:8]
            )
            affected_html = (
                f"<ul class=\"affected-list\">{affected_items}</ul>"
                if affected_items else ''
            )
            evidence = ''
            if group.get('evidence_samples'):
                evidence = f"""
                    <div style="background:#f6f6f6;padding:8px;border-radius:4px;font-family:monospace;font-size:11px;margin:8px 0;word-break:break-all;">
                        <strong>Evidence:</strong> {escape(str(group['evidence_samples'][0]))}
                    </div>
                """
            html += f"""
                <div class="finding">
                    <div>
                        <span class="severity {severity_class}">{severity.upper()}</span>
                        <span class="badge badge-{severity}">{escape(str(group.get('category_label') or group.get('category') or 'Uncategorized'))}</span>
                    </div>
                    <div class="title">{escape(str(group.get('title') or 'Untitled finding'))}</div>
                    <div class="url">{group.get('count', 0)} finding(s), {group.get('affected_url_count', 0)} affected URL(s)</div>
                    <div class="description"><strong>Description:</strong> {escape(str(group.get('description') or 'No description provided.'))}</div>
                    {evidence}
                    <div class="recommendation"><strong>Recommendation:</strong> {escape(str(group.get('recommendation') or 'No recommendation provided.'))}</div>
                    {affected_html}
                    <div style="font-size: 12px; color: #888; margin-top: 5px;">
                        CWE-{escape(str(group.get('cwe_id') or 'N/A'))} | OWASP: {escape(str(group.get('owasp_category') or 'N/A'))}
                    </div>
                </div>
            """
        
        html += f"""
            </div>
            
            <div class="footer">
                <p>Generated by WebShield Scanner v{current_app.config.get('APP_VERSION', '1.0.0')}</p>
                <p>For educational and authorized security testing only.</p>
                <p>Copyright {datetime.utcnow().year} WebShield Scanner. All rights reserved.</p>
            </div>
        </body>
        </html>
        """
        
        return html

    def _generate_reportlab_pdf(self, scan, findings):
        """Generate a compact PDF with ReportLab when WeasyPrint is unavailable."""
        from io import BytesIO
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        triage = build_triage_data(scan, findings)
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.55 * inch,
            leftMargin=0.55 * inch,
            topMargin=0.55 * inch,
            bottomMargin=0.55 * inch,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'WebShieldTitle',
            parent=styles['Title'],
            textColor=colors.HexColor('#1a1a2e'),
            alignment=TA_CENTER,
            spaceAfter=10,
        )
        section_style = ParagraphStyle(
            'WebShieldSection',
            parent=styles['Heading2'],
            textColor=colors.HexColor('#1a1a2e'),
            spaceBefore=14,
            spaceAfter=8,
        )
        finding_title_style = ParagraphStyle(
            'WebShieldFindingTitle',
            parent=styles['Heading3'],
            fontSize=10,
            leading=13,
            spaceBefore=8,
            spaceAfter=3,
        )
        body_style = ParagraphStyle(
            'WebShieldBody',
            parent=styles['BodyText'],
            fontSize=8.5,
            leading=11,
            spaceAfter=5,
            wordWrap='CJK',
        )
        small_style = ParagraphStyle(
            'WebShieldSmall',
            parent=styles['BodyText'],
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor('#555555'),
            wordWrap='CJK',
        )

        story = [
            Paragraph('WebShield Security Report', title_style),
            Paragraph(f"Report ID: WS-{scan.id}-{datetime.utcnow().strftime('%Y%m%d')}", small_style),
            Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", small_style),
            Paragraph(f"Target: {escape(str(scan.target_url or ''))}", small_style),
            Spacer(1, 10),
        ]

        story.append(Paragraph('Executive Summary', section_style))
        summary_rows = [
            ['Score', 'Risk', 'Findings', 'Groups', 'Pages', 'Duration'],
            [
                self._format_score(scan.security_score),
                (scan.risk_level or 'unknown').upper(),
                str(len(findings)),
                str(triage.get('total_groups', 0)),
                str(scan.pages_crawled or 0),
                f"{scan.get_duration() or 0}s",
            ],
        ]
        story.append(self._table(summary_rows, [0.9, 0.9, 0.9, 0.9, 0.9, 0.9]))
        story.append(Paragraph(escape(self._get_summary_text(scan)), body_style))

        severity_rows = [
            ['Critical', 'High', 'Medium', 'Low', 'Info'],
            [
                str(scan.critical_findings or 0),
                str(scan.high_findings or 0),
                str(scan.medium_findings or 0),
                str(scan.low_findings or 0),
                str(scan.info_findings or 0),
            ],
        ]
        story.append(self._table(severity_rows, [1.08, 1.08, 1.08, 1.08, 1.08]))

        story.append(Paragraph('Priority Triage', section_style))
        priority = triage.get('priority_findings') or []
        if priority:
            priority_rows = [['Priority', 'Severity', 'Finding', 'Count', 'First URL']]
            for group in priority[:8]:
                priority_rows.append([
                    str(group.get('priority_rank') or ''),
                    (group.get('severity') or 'info').upper(),
                    Paragraph(escape(str(group.get('title') or 'Untitled finding')), small_style),
                    str(group.get('count') or 0),
                    Paragraph(escape(str(group.get('first_seen_url') or '')), small_style),
                ])
            story.append(self._table(priority_rows, [0.55, 0.7, 2.1, 0.55, 1.8]))
        else:
            story.append(Paragraph('No high-priority findings were detected.', body_style))

        categories = triage.get('category_overview') or []
        if categories:
            story.append(Paragraph('Category Overview', section_style))
            category_rows = [['Category', 'Instances', 'Groups', 'Highest']]
            for category in categories:
                category_rows.append([
                    Paragraph(escape(str(category.get('label') or category.get('category') or 'Uncategorized')), small_style),
                    str(category.get('count') or 0),
                    str(category.get('group_count') or 0),
                    (category.get('highest_severity') or 'info').upper(),
                ])
            story.append(self._table(category_rows, [2.4, 0.9, 0.9, 1.0]))

        story.append(PageBreak())
        story.append(Paragraph('Grouped Findings', section_style))
        for index, group in enumerate(triage.get('grouped_findings') or [], start=1):
            severity = (group.get('severity') or 'info').upper()
            title = escape(str(group.get('title') or 'Untitled finding'))
            story.append(Paragraph(f"{index}. [{severity}] {title}", finding_title_style))
            story.append(Paragraph(
                f"{group.get('count', 0)} finding(s), {group.get('affected_url_count', 0)} affected URL(s)",
                small_style,
            ))

            if group.get('description'):
                story.append(Paragraph(f"<b>Description:</b> {escape(str(group.get('description')))}", body_style))
            if group.get('evidence_samples'):
                story.append(Paragraph(f"<b>Evidence:</b> {escape(str(group['evidence_samples'][0]))}", small_style))
            if group.get('recommendation'):
                story.append(Paragraph(f"<b>Recommendation:</b> {escape(str(group.get('recommendation')))}", body_style))

            urls = group.get('affected_urls') or []
            if urls:
                visible_urls = '<br/>'.join(escape(str(url)) for url in urls[:6])
                remaining = len(urls) - min(len(urls), 6)
                if remaining:
                    visible_urls += f"<br/>+{remaining} more affected URL(s)"
                story.append(Paragraph(f"<b>Affected URLs:</b><br/>{visible_urls}", small_style))

            story.append(Spacer(1, 6))

        story.append(Spacer(1, 14))
        story.append(Paragraph(
            f"Generated by WebShield Scanner v{current_app.config.get('APP_VERSION', '1.0.0')}",
            small_style,
        ))
        story.append(Paragraph('For educational and authorized security testing only.', small_style))

        doc.build(story)
        return buffer.getvalue()

    def _table(self, rows, column_widths):
        """Build a compact ReportLab table."""
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.platypus import Table, TableStyle

        table = Table(rows, colWidths=[width * inch for width in column_widths], repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#dddddd')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7f7f7')]),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        return table

    def _render_priority_html(self, triage):
        """Render the PDF priority triage section."""
        groups = triage.get('priority_findings') or []
        if not groups:
            return '<p>No high-priority findings were detected.</p>'

        cards = []
        for group in groups[:8]:
            severity = group.get('severity') or 'info'
            title = escape(str(group.get('title') or 'Untitled finding'))
            category = escape(str(group.get('category_label') or group.get('category') or 'Uncategorized'))
            recommendation = escape(str(
                group.get('recommendation') or 'Review the evidence and apply the recommended control.'
            ))
            first_url = escape(str(group.get('first_seen_url') or ''))
            cards.append(f"""
                <div class="priority-card {severity}">
                    <div class="rank">Priority {group.get('priority_rank', '')} - {category}</div>
                    <div class="title">{title}</div>
                    <div class="meta">
                        {escape(str(group.get('severity_label') or severity.title()))}
                        - {group.get('count', 0)} finding(s)
                        {'<br>' + first_url if first_url else ''}
                    </div>
                    <div class="fix">{recommendation}</div>
                </div>
            """)

        return f'<div class="priority-grid">{"".join(cards)}</div>'

    def _render_category_html(self, triage):
        """Render category counts for the PDF."""
        categories = triage.get('category_overview') or []
        if not categories:
            return ''

        rows = []
        for category in categories:
            rows.append(f"""
                <tr>
                    <td>{escape(str(category.get('label') or category.get('category') or 'Uncategorized'))}</td>
                    <td>{category.get('count', 0)}</td>
                    <td>{category.get('group_count', 0)}</td>
                    <td>{escape(str(category.get('highest_severity') or 'info')).upper()}</td>
                </tr>
            """)

        return f"""
            <h3>Category Overview</h3>
            <table class="category-table">
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Instances</th>
                        <th>Groups</th>
                        <th>Highest</th>
                    </tr>
                </thead>
                <tbody>{"".join(rows)}</tbody>
            </table>
        """
    
    def _get_score_color(self, score):
        """
        Get color for score.
        
        Args:
            score: Security score
            
        Returns:
            str: Color code
        """
        if score is None:
            return '#999'
        if score >= 80:
            return '#00cc00'
        elif score >= 60:
            return '#ffcc00'
        elif score >= 40:
            return '#ff6600'
        else:
            return '#ff0000'

    def _format_score(self, score):
        """Format a score without converting missing values to zero."""
        return '--/100' if score is None else f'{score}/100'
    
    def _get_risk_color(self, risk_level):
        """
        Get color for risk level.
        
        Args:
            risk_level: Risk level
            
        Returns:
            str: Color code
        """
        colors = {
            'critical': '#ff0000',
            'high': '#ff6600',
            'medium': '#ffcc00',
            'low': '#00cc00',
            'info': '#999'
        }
        return colors.get(risk_level, '#999')
    
    def _get_summary_text(self, scan):
        """
        Get summary text for report.
        
        Args:
            scan: Scan object
            
        Returns:
            str: Summary text
        """
        if scan.risk_level == 'critical':
            return "The website has critical security issues that require immediate attention. There are severe vulnerabilities that could lead to complete system compromise."
        elif scan.risk_level == 'high':
            return "The website has significant security issues that need to be addressed urgently. Several high-severity vulnerabilities were detected."
        elif scan.risk_level == 'medium':
            return "The website has moderate security issues that should be addressed. While not critical, these issues could lead to security incidents."
        elif scan.risk_level == 'low':
            return "The website is generally secure with minor issues. Continue monitoring and maintain security best practices."
        else:
            return "No significant issues were found. The website appears to be well-configured."
