# -*- coding: utf-8 -*-

"""
WebShield Scanner - Constants
Application-wide constants and configuration values.
"""

# HTTP Status Codes
HTTP_STATUS = {
    # Success
    'OK': 200,
    'CREATED': 201,
    'ACCEPTED': 202,
    'NO_CONTENT': 204,
    
    # Client Errors
    'BAD_REQUEST': 400,
    'UNAUTHORIZED': 401,
    'FORBIDDEN': 403,
    'NOT_FOUND': 404,
    'METHOD_NOT_ALLOWED': 405,
    'CONFLICT': 409,
    'UNPROCESSABLE_ENTITY': 422,
    'TOO_MANY_REQUESTS': 429,
    
    # Server Errors
    'INTERNAL_SERVER_ERROR': 500,
    'BAD_GATEWAY': 502,
    'SERVICE_UNAVAILABLE': 503,
}

# Severity Levels for Findings
SEVERITY_LEVELS = {
    'CRITICAL': {
        'value': 'critical',
        'weight': 25,
        'color': '#FF0000',
        'badge': 'danger'
    },
    'HIGH': {
        'value': 'high',
        'weight': 15,
        'color': '#FF6600',
        'badge': 'danger'
    },
    'MEDIUM': {
        'value': 'medium',
        'weight': 8,
        'color': '#FFCC00',
        'badge': 'warning'
    },
    'LOW': {
        'value': 'low',
        'weight': 3,
        'color': '#66CCFF',
        'badge': 'info'
    },
    'INFO': {
        'value': 'info',
        'weight': 0,
        'color': '#999999',
        'badge': 'secondary'
    }
}

# Risk Levels
RISK_LEVELS = {
    'CRITICAL': 'critical',
    'HIGH': 'high',
    'MEDIUM': 'medium',
    'LOW': 'low'
}

# Scan Status
SCAN_STATUS = {
    'PENDING': 'pending',
    'RUNNING': 'running',
    'COMPLETED': 'completed',
    'FAILED': 'failed',
    'CANCELLED': 'cancelled'
}

# Subscription Plans
SUBSCRIPTION_PLANS = {
    'FREE': {
        'id': 'free',
        'name': 'Free',
        'price': 0,
        'currency': 'USD',
        'scans_per_day': 5,
        'features': [
            'Basic security scanning',
            'Attack surface mapping',
            'HTML report export',
            'Learning center access (basic)',
            'Ad supported'
        ]
    },
    'PREMIUM': {
        'id': 'premium',
        'name': 'Premium',
        'price': 5.00,
        'currency': 'USD',
        'scans_per_day': None,  # Unlimited
        'features': [
            'Unlimited scans',
            'Advanced security scanning',
            'PDF report export',
            'Scan history',
            'Authenticated scanning',
            'Advanced crawling',
            'Security trend tracking',
            'Ad-free experience',
            'Full learning center access',
            'Priority support'
        ]
    }
}

# Security Headers
SECURITY_HEADERS = {
    'CONTENT_SECURITY_POLICY': 'Content-Security-Policy',
    'STRICT_TRANSPORT_SECURITY': 'Strict-Transport-Security',
    'X_FRAME_OPTIONS': 'X-Frame-Options',
    'X_CONTENT_TYPE_OPTIONS': 'X-Content-Type-Options',
    'REFERRER_POLICY': 'Referrer-Policy',
    'PERMISSIONS_POLICY': 'Permissions-Policy',
    'X_XSS_PROTECTION': 'X-XSS-Protection'
}

# Common Ports
COMMON_PORTS = {
    'HTTP': 80,
    'HTTPS': 443,
    'SSH': 22,
    'FTP': 21,
    'SMTP': 25,
    'DNS': 53,
    'MYSQL': 3306,
    'POSTGRESQL': 5432,
    'MONGODB': 27017,
    'REDIS': 6379,
    'ELASTICSEARCH': 9200,
    'KAFKA': 9092
}

# File Extensions
FILE_EXTENSIONS = {
    # Web files
    'HTML': ['.html', '.htm', '.xhtml'],
    'CSS': ['.css', '.scss', '.sass', '.less'],
    'JS': ['.js', '.mjs', '.jsx', '.ts', '.tsx'],
    'JSON': ['.json'],
    'XML': ['.xml', '.rss', '.atom'],
    
    # Images
    'IMAGE': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico'],
    
    # Documents
    'PDF': ['.pdf'],
    'DOC': ['.doc', '.docx'],
    'XLS': ['.xls', '.xlsx'],
    'PPT': ['.ppt', '.pptx'],
    'TXT': ['.txt', '.log', '.md'],
    
    # Archives
    'ZIP': ['.zip'],
    'RAR': ['.rar'],
    'TAR': ['.tar', '.tar.gz', '.tgz'],
    'GZIP': ['.gz'],
    '7ZIP': ['.7z'],
    
    # Configuration
    'CONFIG': ['.yml', '.yaml', '.ini', '.conf', '.cfg', '.json'],
    'ENV': ['.env', '.env.local', '.env.production'],
    
    # Code
    'PY': ['.py', '.pyc', '.pyd'],
    'PHP': ['.php', '.phtml'],
    'JAVA': ['.java', '.class', '.jar'],
    'C': ['.c', '.cpp', '.h', '.hpp'],
    'RUBY': ['.rb', '.erb'],
    'GO': ['.go'],
    'RUST': ['.rs'],
    
    # Sensitive
    'SENSITIVE': ['.log', '.bak', '.old', '.orig', '.save', '.tmp']
}

# API Response Messages
API_RESPONSE_MESSAGES = {
    'SUCCESS': 'Operation completed successfully',
    'CREATED': 'Resource created successfully',
    'UPDATED': 'Resource updated successfully',
    'DELETED': 'Resource deleted successfully',
    
    'ERROR': 'An error occurred',
    'BAD_REQUEST': 'Invalid request parameters',
    'UNAUTHORIZED': 'Authentication required',
    'FORBIDDEN': 'Access forbidden',
    'NOT_FOUND': 'Resource not found',
    'VALIDATION_ERROR': 'Validation error',
    'DUPLICATE': 'Resource already exists',
    
    'RATE_LIMITED': 'Rate limit exceeded',
    'MAINTENANCE': 'System under maintenance',
    'SERVICE_UNAVAILABLE': 'Service temporarily unavailable'
}

# Regular Expression Patterns
REGEX_PATTERNS = {
    'EMAIL': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    'USERNAME': r'^[a-zA-Z0-9_]{3,30}$',
    'PASSWORD': r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
    'URL': r'^https?://[^\s/$.?#].[^\s]*$',
    'DOMAIN': r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$',
    'IP_ADDRESS': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    'UUID': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    'HEX_COLOR': r'^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$',
    'PHONE': r'^\+?[1-9]\d{1,14}$',
    'SLUG': r'^[a-z0-9]+(?:-[a-z0-9]+)*$',
    'POSTAL_US': r'^\d{5}(-\d{4})?$'
}

# Default Settings
DEFAULT_SETTINGS = {
    'APP_NAME': 'WebShield Scanner',
    'APP_VERSION': '1.0.0',
    'LANGUAGE': 'en',
    'THEME': 'dark',
    'TIMEZONE': 'UTC',
    'DATE_FORMAT': '%Y-%m-%d',
    'TIME_FORMAT': '%H:%M:%S',
    'DATETIME_FORMAT': '%Y-%m-%d %H:%M:%S',
    
    'PAGINATION_DEFAULT': 20,
    'PAGINATION_MAX': 100,
    
    'MAX_UPLOAD_SIZE': 10 * 1024 * 1024,  # 10MB
    'ALLOWED_IMAGE_TYPES': ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    
    'SESSION_TIMEOUT': 3600,  # 1 hour
    'REMEMBER_ME_DAYS': 7,
    
    'SCAN_TIMEOUT': 300,  # 5 minutes
    'MAX_CRAWL_DEPTH': 3,
    'MAX_PAGES_TO_CRAWL': 100,
    
    'RATE_LIMIT_DEFAULT': '100 per hour',
    'RATE_LIMIT_LOGIN': '10 per 5 minutes',
    'RATE_LIMIT_REGISTER': '5 per hour',
    'RATE_LIMIT_SCAN': '50 per 3 hours',
    
    'LOG_LEVEL': 'INFO',
    'LOG_RETENTION_DAYS': 90
}
