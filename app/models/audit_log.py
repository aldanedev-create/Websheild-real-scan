# -*- coding: utf-8 -*-

"""
WebShield Scanner - Audit Log Model
Tracks user activities and system events for security and compliance.
"""

from datetime import datetime
from extensions import db


class AuditLog(db.Model):
    """Audit log model for tracking user and system activities."""
    
    __tablename__ = 'audit_logs'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Relationship
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    
    # Event details
    action = db.Column(db.String(50), nullable=False, index=True)
    # login, logout, scan_started, scan_completed, report_generated,
    # premium_upgrade, settings_updated, password_changed, etc.
    
    # Additional data
    details = db.Column(db.Text)
    event_metadata = db.Column('metadata', db.JSON)
    
    # Context information
    ip_address = db.Column(db.String(45), index=True)
    user_agent = db.Column(db.String(255))
    referer = db.Column(db.String(500))
    session_id = db.Column(db.String(100))
    
    # Severity
    severity = db.Column(db.String(20), default='info', index=True)
    # info, warning, error, critical
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def __init__(self, user_id=None, action=None, **kwargs):
        """Initialize a new audit log entry."""
        self.user_id = user_id
        self.action = action
        self.created_at = datetime.utcnow()
        
        for key, value in kwargs.items():
            if key == 'metadata':
                key = 'event_metadata'
            setattr(self, key, value)
    
    @classmethod
    def log(cls, user_id, action, details=None, metadata=None, 
            ip_address=None, user_agent=None, severity='info'):
        """Create a new audit log entry."""
        log = cls(
            user_id=user_id,
            action=action,
            details=details,
            event_metadata=metadata,
            ip_address=ip_address,
            user_agent=user_agent,
            severity=severity
        )
        db.session.add(log)
        db.session.commit()
        return log
    
    def to_dict(self):
        """Convert audit log to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'details': self.details,
            'metadata': self.event_metadata,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'referer': self.referer,
            'severity': self.severity,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def get_severity_badge(self):
        """Get the severity badge class for UI."""
        badges = {
            'critical': 'danger',
            'error': 'danger',
            'warning': 'warning',
            'info': 'info',
            'debug': 'secondary'
        }
        return badges.get(self.severity, 'secondary')
    
    def __repr__(self):
        return f'<AuditLog {self.id}: {self.action} by user {self.user_id}>'
