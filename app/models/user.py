# -*- coding: utf-8 -*-

"""
WebShield Scanner - User Model
Manages user accounts, authentication, and user profiles.
"""

from datetime import datetime, timedelta
from flask import current_app
from flask_login import UserMixin
from extensions import db, bcrypt


class User(UserMixin, db.Model):
    """User model for authentication and profile management."""
    
    __tablename__ = 'users'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # User identification
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    
    # Authentication
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Profile information
    full_name = db.Column(db.String(150))
    avatar_url = db.Column(db.String(500))
    bio = db.Column(db.Text)
    
    # Account status
    is_active = db.Column(db.Boolean, default=True, index=True)
    is_admin = db.Column(db.Boolean, default=False, index=True)
    is_verified = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    
    # Plan information
    plan = db.Column(db.String(20), default='free', index=True)  # free, premium
    plan_updated_at = db.Column(db.DateTime)
    
    # Scan limits
    scans_today = db.Column(db.Integer, default=0)
    last_scan_date = db.Column(db.DateTime)
    total_scans = db.Column(db.Integer, default=0)
    
    # Preferences
    notifications_enabled = db.Column(db.Boolean, default=True)
    marketing_emails = db.Column(db.Boolean, default=False)
    theme = db.Column(db.String(20), default='dark')
    language = db.Column(db.String(10), default='en')
    
    # Security
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_login_at = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scans = db.relationship('Scan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def __init__(self, email, username, full_name=None, password=None, **kwargs):
        """Initialize a new user."""
        self.email = email.lower().strip()
        self.username = username.lower().strip()
        self.full_name = full_name
        valid_fields = set(self.__mapper__.attrs.keys())
        for key, value in kwargs.items():
            if key not in valid_fields:
                raise TypeError(f"{key!r} is an invalid keyword argument for User")
            setattr(self, key, value)
        if password:
            self.set_password(password)
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = datetime.utcnow()
    
    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Check if the provided password matches the hash."""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def is_premium(self):
        """All installed features are included in the open-source build."""
        return True
    
    def can_scan(self):
        """Check if user can perform a new scan."""
        return True
    
    def increment_scans(self):
        """Increment scan count for the user."""
        today = datetime.utcnow().date()
        if self.last_scan_date and self.last_scan_date.date() != today:
            self.scans_today = 0
        
        self.scans_today += 1
        self.total_scans += 1
        self.last_scan_date = datetime.utcnow()
    
    def get_remaining_scans(self):
        """Get remaining scans for today."""
        return None

    @staticmethod
    def _free_scan_limit():
        """Read the free scan quota from config, with a safe model fallback."""
        try:
            return int(current_app.config.get('FREE_SCAN_LIMIT', 5))
        except (RuntimeError, TypeError, ValueError):
            return 5
    
    def record_login(self, ip_address):
        """Record a successful login."""
        self.last_login_at = datetime.utcnow()
        self.last_login_ip = ip_address
        self.login_attempts = 0
        self.locked_until = None
    
    def increment_login_attempts(self):
        """Increment login attempts and lock if necessary."""
        self.login_attempts += 1
        if self.login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)
            return True
        return False
    
    def is_locked(self):
        """Check if the account is locked."""
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        self.locked_until = None
        return False
    
    def to_dict(self):
        """Convert user to dictionary."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'avatar_url': self.avatar_url,
            'plan': self.plan,
            'is_admin': self.is_admin,
            'is_verified': self.is_verified,
            'is_premium': self.is_premium(),
            'remaining_scans': self.get_remaining_scans(),
            'total_scans': self.total_scans,
            'theme': self.theme,
            'language': 'en',
            'notifications_enabled': self.notifications_enabled,
            'marketing_emails': self.marketing_emails,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None
        }
    
    def to_public_dict(self):
        """Convert user to public dictionary (limited info)."""
        return {
            'id': self.id,
            'username': self.username,
            'full_name': self.full_name,
            'avatar_url': self.avatar_url,
            'plan': self.plan,
            'is_premium': self.is_premium(),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<User {self.username} ({self.email})>'
