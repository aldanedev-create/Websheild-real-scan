#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WebShield Scanner - Database Seeder
Populates the database with initial data including:
- Admin user
- Learning lessons
- Demo scan data
- Configuration settings
"""

import os
import sys
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Flask application and extensions
from app import create_app
from app.models.user import User
from app.models.learning_lesson import LearningLesson
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.audit_log import AuditLog
from extensions import db

# Create application context
app = create_app()


def create_admin_user():
    """Create the admin user if it doesn't exist."""
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@webshield.com')

    # Check if admin already exists
    admin = User.query.filter_by(email=admin_email).first()

    if admin:
        print(f"Admin user already exists: {admin_email}")
        return admin

    # Create admin user
    admin = User(
        email=admin_email,
        username='admin',
        full_name='System Administrator',
        plan='admin',
        is_admin=True,
        is_active=True,
        email_verified=True,
        created_at=datetime.utcnow()
    )
    admin.set_password(os.getenv('ADMIN_PASSWORD', 'admin123!@#'))

    db.session.add(admin)
    db.session.commit()

    print(f"Admin user created: {admin_email}")
    return admin


def seed_learning_lessons():
    """Seed learning center lessons."""

    # Check if lessons already exist
    count = LearningLesson.query.count()
    if count > 0:
        print(f"Learning lessons already exist ({count} lessons found)")
        return

    lessons = [
        {
            'title': 'OWASP Top 10 - Introduction',
            'category': 'owasp',
            'difficulty': 'beginner',
            'content': """# OWASP Top 10 - Introduction

The OWASP Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications.

## The Top 10 List

1. **Broken Access Control** - Failures in enforcing user permissions
2. **Cryptographic Failures** - Weak encryption or sensitive data exposure
3. **Injection Flaws** - SQL, NoSQL, OS command injection
4. **Insecure Design** - Security flaws in application architecture
5. **Security Misconfiguration** - Improper security settings
6. **Vulnerable Components** - Outdated or insecure libraries
7. **Identification Failures** - Weak authentication mechanisms
8. **Software Integrity Failures** - Insecure updates and CI/CD
9. **Logging Failures** - Insufficient monitoring and alerting
10. **Server-Side Request Forgery** - SSRF vulnerabilities

## Why This Matters

Understanding the OWASP Top 10 is essential for:
- Building secure applications
- Identifying common vulnerabilities
- Prioritizing security efforts
- Compliance and governance

## Next Steps

Review each vulnerability category and learn how to prevent them.""",
            'order': 1,
            'image_url': '/static/images/owasp-top10.png',
            'estimated_time': 15,
            'is_premium': False
        },
        {
            'title': 'Understanding Injection Attacks',
            'category': 'owasp',
            'difficulty': 'intermediate',
            'content': """# Understanding Injection Attacks

Injection attacks occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands.

## SQL Injection

SQL Injection is the most common injection attack. It occurs when user input is concatenated directly into SQL queries.

### Vulnerable Example:
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

### Secure Example (Parameterized):
```python
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```

## Other Injection Types

- NoSQL Injection - Targeting NoSQL databases
- Command Injection - OS command execution
- LDAP Injection - LDAP query manipulation
- XPath Injection - XML query injection

## Prevention

- Use parameterized queries (prepared statements)
- Validate and sanitize all user input
- Use an ORM that handles SQL injection
- Apply principle of least privilege
- Regular security testing and code reviews

## Example

WebShield Scanner can detect SQL injection risks by analyzing URL parameters and form inputs for suspicious patterns.""",
            'order': 2,
            'image_url': '/static/images/injection-attacks.png',
            'estimated_time': 20,
            'is_premium': False
        },
        {
            'title': 'Cross-Site Scripting (XSS)',
            'category': 'owasp',
            'difficulty': 'intermediate',
            'content': """# Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users.

## Types of XSS

### 1. Reflected XSS
The script is reflected off a web server, such as in search results or error messages.

### 2. Stored XSS
The script is stored on the server (e.g., in a database) and executed when users view the stored data.

### 3. DOM-based XSS
The vulnerability exists in client-side code rather than server-side.

## Example Vulnerable Code
```html
<div>Welcome, {{ user_input }}</div>
```

## Secure Code
```html
<div>Welcome, {{ escape(user_input) }}</div>
```

## Prevention

- Input Validation - Validate all user input
- Output Encoding - Encode data before rendering
- Content Security Policy - Implement CSP headers
- Use Auto-escaping Templates - Use frameworks that auto-escape
- Cookie Security - Use HttpOnly flags on cookies

## How WebShield Detects XSS

WebShield Scanner checks for:
- Missing Content-Security-Policy headers
- Forms without CSRF protection
- DOM manipulation without sanitization
- Reflected parameter handling""",
            'order': 3,
            'image_url': '/static/images/xss-attack.png',
            'estimated_time': 20,
            'is_premium': False
        },
        {
            'title': 'Security Headers Explained',
            'category': 'web_security',
            'difficulty': 'beginner',
            'content': """# Security Headers Explained

HTTP security headers are crucial for protecting web applications against various attacks.

## Essential Security Headers

### 1. Content-Security-Policy (CSP)
Prevents XSS and data injection attacks by controlling what resources can be loaded.
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
```

### 2. Strict-Transport-Security (HSTS)
Enforces HTTPS connections and prevents SSL stripping.
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### 3. X-Frame-Options
Prevents clickjacking by controlling iframe embedding.
```
X-Frame-Options: DENY
```

### 4. X-Content-Type-Options
Prevents MIME type sniffing attacks.
```
X-Content-Type-Options: nosniff
```

### 5. Referrer-Policy
Controls how much referrer information is sent.
```
Referrer-Policy: strict-origin-when-cross-origin
```

### 6. Permissions-Policy
Controls which browser features can be used.
```
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

## Testing with WebShield

WebShield Scanner automatically checks for these headers and reports missing or misconfigured ones.""",
            'order': 4,
            'image_url': '/static/images/security-headers.png',
            'estimated_time': 15,
            'is_premium': False
        },
        {
            'title': 'Cookie Security Best Practices',
            'category': 'web_security',
            'difficulty': 'intermediate',
            'content': """# Cookie Security Best Practices

Cookies are widely used for session management but can be a security risk if not properly secured.

## Cookie Security Flags

### Secure Flag
Ensures cookies are only sent over HTTPS connections.
```python
response.set_cookie('session', value, secure=True)
```

### HttpOnly Flag
Prevents JavaScript from accessing the cookie, mitigating XSS attacks.
```python
response.set_cookie('session', value, httponly=True)
```

### SameSite Attribute
Controls when cookies are sent with cross-site requests.
```python
response.set_cookie('session', value, samesite='Lax')
# Options: 'Strict', 'Lax', 'None'
```

## Session Cookie Best Practices

- Always use Secure and HttpOnly flags
- Set appropriate expiration times
- Implement session rotation
- Use strong session identifiers
- Invalidate sessions on logout

## How WebShield Evaluates Cookies

WebShield Scanner checks:
- Presence of Secure flag
- Presence of HttpOnly flag
- SameSite attribute setting
- Cookie domain and path restrictions
- Session expiration time""",
            'order': 5,
            'image_url': '/static/images/cookie-security.png',
            'estimated_time': 15,
            'is_premium': False
        },
        {
            'title': 'SSL/TLS Fundamentals',
            'category': 'web_security',
            'difficulty': 'beginner',
            'content': """# SSL/TLS Fundamentals

SSL/TLS protocols secure communications between clients and servers through encryption and authentication.

## Key Concepts

### Encryption
Protects data in transit from eavesdropping.

### Authentication
Verifies the server's identity through digital certificates.

### Integrity
Ensures data hasn't been tampered with during transmission.

## Common Issues

- Weak Ciphers - Using outdated or insecure encryption algorithms
- Self-Signed Certificates - Certificates not trusted by browsers
- Mixed Content - Combining HTTPS and HTTP resources
- Expired Certificates - Certificates past their validity period
- Vulnerable TLS Versions - Using TLS 1.0 or 1.1 (deprecated)

## What WebShield Checks

- Valid SSL/TLS certificate
- Certificate expiration date
- Trusted Certificate Authority
- TLS version compatibility
- Cipher suite strength
- Mixed content warnings
- HSTS implementation

## Best Practices

- Use TLS 1.3 or 1.2
- Use strong cipher suites
- Enable HSTS
- Keep certificates updated
- Test SSL configuration regularly""",
            'order': 6,
            'image_url': '/static/images/ssl-certificate.png',
            'estimated_time': 15,
            'is_premium': False
        },
        {
            'title': 'Secure Coding - Input Validation',
            'category': 'secure_coding',
            'difficulty': 'intermediate',
            'content': """# Secure Coding - Input Validation

Input validation is the first line of defense against injection attacks and other security vulnerabilities.

## Why Input Validation Matters

- Prevents injection attacks (SQL, XSS, command)
- Prevents buffer overflows
- Ensures data integrity
- Improves application stability

## Types of Validation

### Whitelist Validation
Only allow known good values.
```python
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg'}
if file_extension not in ALLOWED_EXTENSIONS:
    raise ValueError("Invalid file type")
```

### Blacklist Validation
Block known bad values (less secure).
```python
BLOCKED_SQL_KEYWORDS = ['DROP', 'DELETE', 'INSERT']
if any(keyword in input for keyword in BLOCKED_SQL_KEYWORDS):
    raise ValueError("Suspicious input detected")
```

### Sanitization
Clean or escape input.
```python
import html
safe_input = html.escape(user_input)
```

## Best Practices

1. Validate All Input - From all sources (forms, URLs, APIs)
2. Use Type Validation - Ensure correct data types
3. Set Length Limits - Prevent buffer overflows
4. Use Regular Expressions - Pattern validation
5. Validate on Server - Never trust client-side validation alone

## Common Pitfalls

- Validating input only once
- Forgetting to validate internal inputs
- Using inadequate validation rules
- Trusting client-side validation""",
            'order': 7,
            'image_url': '/static/images/input-validation.png',
            'estimated_time': 20,
            'is_premium': False
        },
        {
            'title': 'Understanding CSRF Attacks',
            'category': 'owasp',
            'difficulty': 'intermediate',
            'content': """# Understanding CSRF Attacks

Cross-Site Request Forgery (CSRF) is an attack that tricks users into performing unintended actions.

## How CSRF Works

1. User authenticates to a website
2. User visits a malicious site
3. Malicious site sends a forged request
4. Browser automatically includes authentication cookies
5. Website executes the forged request

## Example
```html
<!-- Malicious site causes GET request -->
<img src="https://bank.com/transfer?to=attacker&amount=1000">
```

## Prevention Methods

### 1. CSRF Tokens
Include a unique token in forms that the server validates.
```html
<form>
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
</form>
```

### 2. SameSite Cookies
Use SameSite attribute to restrict cross-site requests.

### 3. Require Re-authentication
Request password for sensitive operations.

### 4. Custom Request Headers
Use headers like X-Requested-With to verify legitimate requests.

## How WebShield Detects CSRF

WebShield Scanner checks:
- Presence of CSRF tokens in forms
- SameSite cookie configuration
- Implemented security headers
- Form submission methods""",
            'order': 8,
            'image_url': '/static/images/csrf-attack.png',
            'estimated_time': 20,
            'is_premium': False
        },
        {
            'title': 'Web Security Testing Methodology',
            'category': 'testing',
            'difficulty': 'advanced',
            'content': """# Web Security Testing Methodology

A systematic approach to web application security testing.

## Testing Phases

### 1. Reconnaissance
- Gather information about the target
- Identify technologies and components
- Map attack surface

### 2. Vulnerability Scanning
- Automated scanning for common vulnerabilities
- Use tools like WebShield Scanner
- Identify potential security issues

### 3. Manual Testing
- Validate automated findings
- Test complex vulnerabilities
- Business logic testing

### 4. Exploitation (Authorized Only)
- Verify vulnerabilities
- Demonstrate impact
- Document proof of concepts

### 5. Reporting
- Document all findings
- Provide remediation guidance
- Prioritize vulnerabilities

## WebShield Scanner Capabilities

- Automated vulnerability detection
- Attack surface mapping
- Security header analysis
- Component identification
- Report generation

## Best Practices

- Always get written authorization
- Test in isolated environments
- Document all findings
- Validate automated results manually
- Provide actionable recommendations""",
            'order': 9,
            'image_url': '/static/images/testing-methodology.png',
            'estimated_time': 25,
            'is_premium': True
        },
        {
            'title': 'API Security Fundamentals',
            'category': 'secure_coding',
            'difficulty': 'advanced',
            'content': """# API Security Fundamentals

API security is critical for modern applications.

## Common API Vulnerabilities

### 1. Broken Object Level Authorization (BOLA)
Users accessing objects they shouldn't.

### 2. Broken Authentication
Weak or vulnerable authentication mechanisms.

### 3. Excessive Data Exposure
API returning more data than necessary.

### 4. Lack of Rate Limiting
API vulnerable to brute force and DoS attacks.

### 5. Improper Asset Management
Exposed API endpoints due to poor versioning.

## Security Best Practices

### Authentication
- Use OAuth 2.0 or JWT
- Implement proper token validation
- Use secure password hashing

### Authorization
- Implement role-based access control
- Validate permissions per endpoint
- Use principle of least privilege

### Input Validation
- Validate all API inputs
- Use schemas for validation
- Sanitize input data

### Rate Limiting
- Implement per-IP and per-user limits
- Use exponential backoff
- Monitor for abuse

## WebShield API Security Checks

- Endpoint exposure detection
- Authentication method assessment
- Rate limiting implementation
- Response data analysis
- Security header evaluation""",
            'order': 10,
            'image_url': '/static/images/api-security.png',
            'estimated_time': 25,
            'is_premium': True
        }
    ]

    # Add lessons to database
    for index, lesson_data in enumerate(lessons):
        lesson = LearningLesson(
            title=lesson_data['title'],
            category=lesson_data['category'],
            difficulty=lesson_data['difficulty'],
            content=lesson_data['content'],
            order=lesson_data.get('order', index + 1),
            image_url=lesson_data.get('image_url'),
            estimated_time=lesson_data.get('estimated_time', 15),
            is_premium=lesson_data.get('is_premium', False),
            created_at=datetime.utcnow()
        )
        db.session.add(lesson)

    db.session.commit()
    print(f"Created {len(lessons)} learning lessons")


def seed_demo_scan(admin_user):
    """Seed a demo scan for the admin user."""

    # Check if demo scan exists
    demo_scan = Scan.query.filter_by(target_url='https://demo.webshield.com').first()
    if demo_scan:
        print("Demo scan already exists")
        return

    # Create demo scan
    scan = Scan(
        user_id=admin_user.id,
        target_url='https://demo.webshield.com',
        scan_status='completed',
        security_score=68,
        risk_level='medium',
        summary='Found 5 security issues including missing CSP header and insecure cookies.',
        pages_crawled=24,
        total_findings=5,
        critical_findings=0,
        high_findings=2,
        medium_findings=2,
        low_findings=1,
        started_at=datetime.utcnow() - timedelta(hours=2),
        completed_at=datetime.utcnow() - timedelta(hours=1),
        created_at=datetime.utcnow() - timedelta(hours=2)
    )

    db.session.add(scan)
    db.session.flush()

    # Create demo findings
    findings = [
        {
            'scan_id': scan.id,
            'title': 'Missing Content-Security-Policy Header',
            'severity': 'medium',
            'category': 'security_headers',
            'affected_url': 'https://demo.webshield.com',
            'description': 'The website does not implement a Content-Security-Policy header, which may increase the risk of XSS and data injection attacks.',
            'evidence': 'HTTP response headers lack CSP directive.',
            'recommendation': 'Add a Content-Security-Policy header to restrict resources that can be loaded by the page.',
            'cwe_id': 'CWE-693',
            'owasp_category': 'Security Misconfiguration'
        },
        {
            'scan_id': scan.id,
            'title': 'Cookie Missing Secure Flag',
            'severity': 'high',
            'category': 'cookies',
            'affected_url': 'https://demo.webshield.com/login',
            'description': 'Session cookies do not have the Secure flag set, making them vulnerable to interception over HTTP connections.',
            'evidence': 'Cookie "sessionid" is missing Secure flag.',
            'recommendation': 'Set the Secure flag on all session cookies and enforce HTTPS connections.',
            'cwe_id': 'CWE-614',
            'owasp_category': 'Sensitive Data Exposure'
        },
        {
            'scan_id': scan.id,
            'title': 'Cookie Missing HttpOnly Flag',
            'severity': 'high',
            'category': 'cookies',
            'affected_url': 'https://demo.webshield.com/dashboard',
            'description': 'Session cookies do not have the HttpOnly flag set, making them accessible to JavaScript and increasing XSS risk.',
            'evidence': 'Cookie "sessionid" is missing HttpOnly flag.',
            'recommendation': 'Add the HttpOnly flag to session cookies to prevent client-side script access.',
            'cwe_id': 'CWE-1004',
            'owasp_category': 'Sensitive Data Exposure'
        },
        {
            'scan_id': scan.id,
            'title': 'Server Version Information Exposed',
            'severity': 'low',
            'category': 'information_disclosure',
            'affected_url': 'https://demo.webshield.com',
            'description': 'The server exposes version information in HTTP headers.',
            'evidence': 'Server header: nginx/1.18.0',
            'recommendation': 'Remove or obfuscate server version information from HTTP headers.',
            'cwe_id': 'CWE-200',
            'owasp_category': 'Information Disclosure'
        },
        {
            'scan_id': scan.id,
            'title': 'Missing X-Frame-Options Header',
            'severity': 'medium',
            'category': 'security_headers',
            'affected_url': 'https://demo.webshield.com',
            'description': 'The X-Frame-Options header is missing, potentially allowing clickjacking attacks.',
            'evidence': 'X-Frame-Options header not present.',
            'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN to prevent framing.',
            'cwe_id': 'CWE-1021',
            'owasp_category': 'Security Misconfiguration'
        }
    ]

    for finding_data in findings:
        finding = Finding(**finding_data)
        db.session.add(finding)

    db.session.commit()
    print("Demo scan and findings created")


def seed_audit_log(admin_user):
    """Seed audit log entries."""

    log_entries = [
        AuditLog(
            user_id=admin_user.id,
            action='login',
            details='Admin user logged in',
            ip_address='127.0.0.1',
            user_agent='WebShield Demo',
            created_at=datetime.utcnow() - timedelta(hours=2)
        ),
        AuditLog(
            user_id=admin_user.id,
            action='scan_started',
            details='Started scan of https://demo.webshield.com',
            ip_address='127.0.0.1',
            user_agent='WebShield Demo',
            created_at=datetime.utcnow() - timedelta(hours=1, minutes=45)
        ),
        AuditLog(
            user_id=admin_user.id,
            action='report_generated',
            details='Generated PDF report for scan #1',
            ip_address='127.0.0.1',
            user_agent='WebShield Demo',
            created_at=datetime.utcnow() - timedelta(hours=1, minutes=30)
        ),
        AuditLog(
            user_id=admin_user.id,
            action='settings_updated',
            details='User updated notification preferences',
            ip_address='127.0.0.1',
            user_agent='WebShield Demo',
            created_at=datetime.utcnow() - timedelta(hours=1)
        ),
        AuditLog(
            user_id=admin_user.id,
            action='premium_upgrade',
            details='User upgraded to premium plan',
            ip_address='127.0.0.1',
            user_agent='WebShield Demo',
            created_at=datetime.utcnow() - timedelta(minutes=30)
        )
    ]

    for log_entry in log_entries:
        db.session.add(log_entry)

    db.session.commit()
    print(f"Created {len(log_entries)} audit log entries")


def main():
    """Main seeding function."""
    print("Starting WebShield Scanner database seeding...")

    with app.app_context():
        try:
            # Create tables if they don't exist
            db.create_all()
            print("Database tables verified")

            # Seed data
            admin_user = create_admin_user()
            seed_learning_lessons()
            seed_demo_scan(admin_user)
            seed_audit_log(admin_user)

            print("\n✅ Database seeding completed successfully!")
            print(f"Admin credentials: {os.getenv('ADMIN_EMAIL', 'admin@webshield.com')} / admin123!@#")
            print("Please change the admin password on first login.")

        except Exception as e:
            db.session.rollback()
            print(f"❌ Error during seeding: {str(e)}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == '__main__':
    main()
