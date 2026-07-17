# -*- coding: utf-8 -*-

"""
WebShield Scanner - Scan Model
Manages website scan records and their status.
"""

from datetime import datetime
from extensions import db


class Scan(db.Model):
    """Scan model for tracking security scans."""
    
    __tablename__ = 'scans'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Relationship
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Scan details
    target_url = db.Column(db.String(500), nullable=False, index=True)
    scan_status = db.Column(db.String(20), default='pending', index=True)
    # pending, running, completed, failed, cancelled
    
    # Results
    security_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(10), index=True)
    summary = db.Column(db.Text)
    
    # Statistics
    pages_crawled = db.Column(db.Integer, default=0)
    total_findings = db.Column(db.Integer, default=0)
    critical_findings = db.Column(db.Integer, default=0)
    high_findings = db.Column(db.Integer, default=0)
    medium_findings = db.Column(db.Integer, default=0)
    low_findings = db.Column(db.Integer, default=0)
    info_findings = db.Column(db.Integer, default=0)
    
    # Attack surface data (JSON)
    attack_surface_data = db.Column(db.JSON)
    forms_data = db.Column(db.JSON)
    endpoints_data = db.Column(db.JSON)
    headers_data = db.Column(db.JSON)
    cookies_data = db.Column(db.JSON)
    
    # Scanner configuration
    auth_cookie = db.Column(db.Text)
    crawl_depth = db.Column(db.Integer, default=3)
    max_pages = db.Column(db.Integer, default=100)
    
    # Timestamps
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    findings = db.relationship('Finding', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    
    def __init__(self, user_id, target_url, **kwargs):
        """Initialize a new scan."""
        self.user_id = user_id
        self.target_url = target_url.strip()
        self.scan_status = 'pending'
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def start_scan(self):
        """Mark the scan as started."""
        self.scan_status = 'running'
        self.started_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def complete_scan(self):
        """Mark the scan as completed."""
        self.scan_status = 'completed'
        self.completed_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def fail_scan(self, error_message=None):
        """Mark the scan as failed."""
        self.scan_status = 'failed'
        self.completed_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        if error_message:
            self.summary = f"Scan failed: {error_message}"
    
    def cancel_scan(self):
        """Mark the scan as cancelled."""
        self.scan_status = 'cancelled'
        self.summary = 'Scan cancelled by user.'
        self.completed_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def update_score(self):
        """Update the security score based on findings."""
        from app.scanner.score_engine import ScoreEngine

        ScoreEngine().calculate_score(self)
    
    def to_dict(self):
        """Convert scan to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'target_url': self.target_url,
            'scan_status': self.scan_status,
            'security_score': self.security_score,
            'risk_level': self.risk_level,
            'summary': self.summary,
            'pages_crawled': self.pages_crawled,
            'total_findings': self.total_findings,
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'medium_findings': self.medium_findings,
            'low_findings': self.low_findings,
            'info_findings': self.info_findings,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'duration': self.get_duration()
        }
    
    def get_duration(self):
        """Get scan duration in seconds."""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return None
    
    def __repr__(self):
        return f'<Scan {self.id}: {self.target_url} ({self.scan_status})>'
