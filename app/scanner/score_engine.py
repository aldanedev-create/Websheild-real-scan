# -*- coding: utf-8 -*-

"""
WebShield Scanner - Score Engine
Calculates security scores based on scan findings.
"""

from collections import defaultdict


class ScoreEngine:
    """Calculates security scores and risk levels."""
    
    def __init__(self):
        """Initialize the score engine."""
        self.severity_weights = {
            'critical': 24,
            'high': 12,
            'medium': 6,
            'low': 2,
            'info': 0
        }

        # Repeated instances of the same issue should raise urgency without
        # turning every multi-page scan into an automatic 0/100.
        self.repeat_factors = {
            1: 1.0,
            2: 0.35
        }
        self.default_repeat_factor = 0.15

        self.category_caps = {
            'security_headers': 22,
            'headers': 22,
            'cookies': 22,
            'ssl': 30,
            'tls': 30,
            'sensitive_data': 45,
            'vulnerabilities': 50,
            'forms': 22,
            'client_code': 35,
            'components': 18,
            'misconfiguration': 30,
            'information_disclosure': 18
        }
        self.default_category_cap = 35
        
        self.max_score = 100
        self.min_score = 0
        self.minimum_finding_score = 5
    
    def calculate_score(self, scan):
        """
        Calculate security score for a scan.
        
        Args:
            scan: Scan object with findings
            
        Returns:
            int: Security score (0-100)
        """
        findings = self._active_findings(scan.findings)
        
        if not findings:
            score = 100
            risk_level = 'low'
        else:
            score = self.calculate_findings_score(findings)
            risk_level = self._determine_risk_level(score, findings)
        
        # Update scan object
        scan.security_score = int(score)
        scan.risk_level = risk_level
        
        return int(score)

    def calculate_findings_score(self, findings):
        """
        Calculate a bounded score for a list of findings.

        The score keeps the first occurrence of an issue meaningful, applies a
        smaller deduction for repeats, and caps each category so duplicated
        header/page findings do not dominate the entire report.
        """
        if not findings:
            return self.max_score

        category_deductions = defaultdict(float)
        issue_counts = defaultdict(int)

        for finding in findings:
            severity = self._normalize(getattr(finding, 'severity', ''))
            base_deduction = self.severity_weights.get(severity, 0)
            if base_deduction <= 0:
                continue

            category = self._normalize(getattr(finding, 'category', 'general')) or 'general'
            issue_key = self._issue_key(finding)
            issue_counts[issue_key] += 1

            occurrence = issue_counts[issue_key]
            repeat_factor = self.repeat_factors.get(occurrence, self.default_repeat_factor)
            category_deductions[category] += base_deduction * repeat_factor

        total_deduction = 0
        for category, deduction in category_deductions.items():
            cap = self.category_caps.get(category, self.default_category_cap)
            total_deduction += min(deduction, cap)

        score = self.max_score - total_deduction
        if total_deduction > 0:
            score = max(self.minimum_finding_score, score)

        return max(self.min_score, min(self.max_score, int(round(score))))
    
    def _determine_risk_level(self, score, findings):
        """
        Determine risk level based on score and findings.
        
        Args:
            score: Security score
            findings: List of findings
            
        Returns:
            str: Risk level (critical, high, medium, low)
        """
        severities = [self._normalize(getattr(f, 'severity', '')) for f in findings]
        critical_count = sum(1 for severity in severities if severity == 'critical')
        high_count = sum(1 for severity in severities if severity == 'high')
        medium_count = sum(1 for severity in severities if severity == 'medium')

        # Reserve critical risk for actual critical findings.
        if critical_count:
            return 'critical'

        if high_count >= 3 or score < 40:
            return 'high'

        if high_count > 0 or medium_count >= 5 or score < 70:
            return 'medium'

        return 'low'
    
    def calculate_category_score(self, findings, category):
        """
        Calculate score for a specific category.
        
        Args:
            findings: List of findings
            category: Category to filter by
            
        Returns:
            int: Category score (0-100)
        """
        normalized_category = self._normalize(category)
        category_findings = [
            f for f in findings
            if self._normalize(getattr(f, 'category', '')) == normalized_category
        ]

        return self.calculate_findings_score(category_findings)
    
    def get_finding_counts_by_severity(self, findings):
        """
        Get finding counts by severity.
        
        Args:
            findings: List of findings
            
        Returns:
            dict: Severity counts
        """
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            severity = self._normalize(getattr(finding, 'severity', ''))
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def get_weighted_score(self, findings):
        """
        Calculate weighted score based on severity distribution.
        
        Args:
            findings: List of findings
            
        Returns:
            int: Weighted score
        """
        return self.calculate_findings_score(findings)

    def _active_findings(self, findings_relation):
        """Return findings that are still counted toward score."""
        if hasattr(findings_relation, 'filter_by'):
            return findings_relation.filter_by(is_false_positive=False).all()

        return [
            finding for finding in findings_relation
            if not getattr(finding, 'is_false_positive', False)
        ]

    def _issue_key(self, finding):
        return (
            self._normalize(getattr(finding, 'severity', '')),
            self._normalize(getattr(finding, 'category', '')),
            self._normalize(getattr(finding, 'title', '')),
            self._normalize(getattr(finding, 'affected_parameter', ''))
        )

    def _normalize(self, value):
        return str(value or '').strip().lower()
    
    def get_security_grade(self, score):
        """
        Get letter grade based on security score.
        
        Args:
            score: Security score (0-100)
            
        Returns:
            str: Letter grade (A, B, C, D, F)
        """
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def get_grade_description(self, grade):
        """
        Get description for a grade.
        
        Args:
            grade: Letter grade
            
        Returns:
            str: Grade description
        """
        descriptions = {
            'A': 'Excellent security posture. Continue monitoring and maintaining best practices.',
            'B': 'Good security. Minor improvements recommended.',
            'C': 'Fair security. Several issues need attention.',
            'D': 'Poor security. Significant vulnerabilities require immediate action.',
            'F': 'Critical security issues detected. Urgent action required.'
        }
        return descriptions.get(grade, 'Unknown grade')
