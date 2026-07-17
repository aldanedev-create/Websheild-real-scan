# -*- coding: utf-8 -*-

"""
WebShield Scanner - Finding Model
Manages security findings detected during scans.
"""

from datetime import datetime
from extensions import db


class Finding(db.Model):
    """Finding model for security vulnerabilities and issues."""
    
    __tablename__ = 'findings'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Relationship
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    
    # Finding details
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False, index=True)
    # critical, high, medium, low, info
    
    # Categorization
    category = db.Column(db.String(50), nullable=False, index=True)
    # security_headers, cookies, ssl, sensitive_data, components,
    # vulnerabilities, misconfiguration, information_disclosure, etc.
    
    # Location
    affected_url = db.Column(db.String(500), index=True)
    affected_parameter = db.Column(db.String(100))
    
    # Description and evidence
    description = db.Column(db.Text)
    evidence = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    
    # Additional metadata
    cwe_id = db.Column(db.String(20))  # CWE identifier
    owasp_category = db.Column(db.String(50))  # OWASP Top 10 category
    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.String(50))
    
    # Reference links
    reference_urls = db.Column(db.JSON)  # List of reference URLs
    
    # Evidence files
    screenshot_path = db.Column(db.String(500))
    raw_response = db.Column(db.Text)
    
    # Status
    is_false_positive = db.Column(db.Boolean, default=False, index=True)
    is_fixed = db.Column(db.Boolean, default=False, index=True)
    fixed_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, scan_id, title, severity, category, **kwargs):
        """Initialize a new finding."""
        self.scan_id = scan_id
        self.title = title.strip()
        self.severity = severity.lower()
        self.category = category.lower()
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def mark_fixed(self):
        """Mark the finding as fixed."""
        self.is_fixed = True
        self.fixed_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def mark_false_positive(self):
        """Mark the finding as a false positive."""
        self.is_false_positive = True
        self.updated_at = datetime.utcnow()
    
    def to_dict(self):
        """Convert finding to dictionary."""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'title': self.title,
            'severity': self.severity,
            'category': self.category,
            'affected_url': self.affected_url,
            'affected_parameter': self.affected_parameter,
            'description': self.description,
            'evidence': self.evidence,
            'recommendation': self.recommendation,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'reference_urls': self.reference_urls,
            'is_false_positive': self.is_false_positive,
            'is_fixed': self.is_fixed,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def get_severity_level(self):
        """Get the numeric severity level for sorting."""
        levels = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        return levels.get(self.severity, 0)
    
    def get_severity_badge(self):
        """Get the severity badge class for UI."""
        badges = {
            'critical': 'danger',
            'high': 'danger',
            'medium': 'warning',
            'low': 'info',
            'info': 'secondary'
        }
        return badges.get(self.severity, 'secondary')
    
    def __repr__(self):
        return f'<Finding {self.id}: {self.title} ({self.severity})>'
