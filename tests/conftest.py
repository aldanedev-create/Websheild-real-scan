# -*- coding: utf-8 -*-

"""
WebShield Scanner - Test Configuration
Shared fixtures for all tests.
"""

import pytest
from datetime import datetime, timedelta
from flask_jwt_extended import create_access_token
from app import create_app
from extensions import db
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding


@pytest.fixture
def app():
    """Create and configure a test Flask application."""
    app = create_app('testing')

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


@pytest.fixture
def db_session(app):
    """Get a database session."""
    return db.session


@pytest.fixture
def test_user(db_session):
    """Create a test user."""
    user = User(
        username='testuser',
        email='test@example.com',
        full_name='Test User'
    )
    user.set_password('TestPass123!')
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def test_user2(db_session):
    """Create a second test user."""
    user = User(
        username='testuser2',
        email='test2@example.com',
        full_name='Test User 2'
    )
    user.set_password('TestPass123!')
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def test_admin_user(db_session):
    """Create a test admin user."""
    user = User(
        username='adminuser',
        email='admin@test.com',
        full_name='Admin User',
        is_admin=True
    )
    user.set_password('AdminPass123!')
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def test_premium_user(db_session):
    """Create a test premium user."""
    user = User(
        username='premiumuser',
        email='premium@example.com',
        full_name='Premium User',
        plan='premium'
    )
    user.set_password('TestPass123!')
    db_session.add(user)
    db_session.commit()

    # Add subscription
    subscription = Subscription(
        user_id=user.id,
        plan='premium',
        status='active',
        started_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=30)
    )
    db_session.add(subscription)
    db_session.commit()

    return user


@pytest.fixture
def auth_headers(test_user):
    """Get authentication headers for test user."""
    token = create_access_token(identity=test_user.id)
    return {'Authorization': f'Bearer {token}'}


@pytest.fixture
def auth_headers_premium(test_premium_user):
    """Get authentication headers for premium user."""
    token = create_access_token(identity=test_premium_user.id)
    return {'Authorization': f'Bearer {token}'}


@pytest.fixture
def auth_headers_admin(test_admin_user):
    """Get authentication headers for admin user."""
    token = create_access_token(identity=test_admin_user.id)
    return {'Authorization': f'Bearer {token}'}


@pytest.fixture
def test_scan(db_session, test_user):
    """Create a test scan."""
    scan = Scan(
        user_id=test_user.id,
        target_url='https://example.com',
        scan_status='completed',
        security_score=75,
        risk_level='medium',
        pages_crawled=10,
        total_findings=3,
        critical_findings=0,
        high_findings=1,
        medium_findings=1,
        low_findings=1,
        started_at=datetime.utcnow() - timedelta(hours=1),
        completed_at=datetime.utcnow()
    )
    db_session.add(scan)
    db_session.commit()
    return scan


@pytest.fixture
def test_running_scan(db_session, test_user):
    """Create a test scan in running state."""
    scan = Scan(
        user_id=test_user.id,
        target_url='https://example.com',
        scan_status='running',
        started_at=datetime.utcnow()
    )
    db_session.add(scan)
    db_session.commit()
    return scan


@pytest.fixture
def test_scan_with_findings(db_session, test_user):
    """Create a test scan with findings."""
    scan = Scan(
        user_id=test_user.id,
        target_url='https://example.com',
        scan_status='completed',
        security_score=68,
        risk_level='medium',
        pages_crawled=24,
        total_findings=5,
        critical_findings=0,
        high_findings=2,
        medium_findings=2,
        low_findings=1,
        started_at=datetime.utcnow() - timedelta(hours=2),
        completed_at=datetime.utcnow() - timedelta(hours=1)
    )
    db_session.add(scan)
    db_session.flush()

    # Add findings
    findings = [
        Finding(
            scan_id=scan.id,
            title='Missing Content-Security-Policy Header',
            severity='medium',
            category='security_headers',
            affected_url='https://example.com',
            description='CSP header is missing',
            recommendation='Add CSP header',
            cwe_id='CWE-693',
            owasp_category='Security Misconfiguration'
        ),
        Finding(
            scan_id=scan.id,
            title='Cookie Missing Secure Flag',
            severity='high',
            category='cookies',
            affected_url='https://example.com/login',
            description='Cookie missing Secure flag',
            recommendation='Set Secure flag',
            cwe_id='CWE-614',
            owasp_category='Sensitive Data Exposure'
        ),
        Finding(
            scan_id=scan.id,
            title='Server Version Exposed',
            severity='low',
            category='information_disclosure',
            affected_url='https://example.com',
            description='Server version is exposed',
            recommendation='Hide server version',
            cwe_id='CWE-200',
            owasp_category='Information Disclosure'
        )
    ]

    for finding in findings:
        db_session.add(finding)

    db_session.commit()
    return scan
