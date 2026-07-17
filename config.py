# -*- coding: utf-8 -*-

"""
WebShield Scanner - Configuration Module
Manages all application configuration settings.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, os.pardir))


def _strip_quotes(value):
    """Trim whitespace and one layer of matching quotes from env values."""
    if value is None:
        return None
    value = str(value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _get_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return _strip_quotes(value).lower() in {"1", "true", "yes", "on"}


def _get_int(name, default, minimum=None):
    raw_value = os.getenv(name)
    value = default if raw_value is None or str(raw_value).strip() == "" else raw_value
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return parsed


def _get_float(name, default, minimum=None):
    raw_value = os.getenv(name)
    value = default if raw_value is None or str(raw_value).strip() == "" else raw_value
    try:
        parsed = float(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number") from exc
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return parsed


def _get_csv(name, default=""):
    value = os.getenv(name, default)
    return [
        _strip_quotes(item).strip()
        for item in str(value).split(",")
        if _strip_quotes(item).strip()
    ]


def _database_url(default, include_dev=True):
    fallback = os.getenv("DEV_DATABASE_URL", default) if include_dev else default
    url = _strip_quotes(os.getenv("DATABASE_URL", fallback))
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://"):]
    if url.startswith("postgresql://") and "+psycopg" not in url.split("://", 1)[0]:
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    if url.startswith("sqlite:///") and url != "sqlite:///:memory:":
        database_path = url.replace("sqlite:///", "", 1)
        if database_path and not os.path.isabs(database_path):
            database_path = os.path.abspath(os.path.join(PROJECT_ROOT, database_path))
        return "sqlite:///" + database_path.replace("\\", "/")
    return url


def _engine_options(database_uri):
    if database_uri.startswith("sqlite"):
        return {"pool_pre_ping": True}
    return {
        "pool_size": _get_int("DB_POOL_SIZE", 10, minimum=1),
        "pool_recycle": _get_int("DB_POOL_RECYCLE", 3600, minimum=1),
        "pool_pre_ping": True,
        "max_overflow": _get_int("DB_MAX_OVERFLOW", 20, minimum=0),
        "pool_timeout": _get_int("DB_POOL_TIMEOUT", 30, minimum=1),
    }


def _resolve_backend_path(value):
    path = _strip_quotes(value)
    if os.path.isabs(path):
        return path
    return os.path.join(BASE_DIR, path)


def _is_unsafe_secret(value):
    if not value:
        return True
    normalized = _strip_quotes(value).lower()
    unsafe_values = {
        "secret",
        "password",
        "changeme",
        "change-me",
        "dev-secret-key-change-in-production",
        "jwt-secret-key-change-in-production",
        "your-super-secret-key-change-this-in-production",
        "your-jwt-secret-key",
        "your-jwt-secret-key-change-this-in-production",
    }
    return normalized in unsafe_values


def _is_placeholder_value(value):
    if not value:
        return False
    normalized = _strip_quotes(value).lower()
    placeholder_markers = (
        "your-",
        "example.com",
        "your-app-domain.com",
        "username:password@",
        "sk_test_...",
        "whsec_...",
    )
    return any(marker in normalized for marker in placeholder_markers)


def _secret_needs_rotation(value):
    if not value:
        return True
    normalized = _strip_quotes(value).lower()
    return len(value) < 32 or any(
        marker in normalized
        for marker in ("change", "placeholder", "example", "default")
    )


class Config:
    """Base configuration class."""
    
    # Application Settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = _get_bool('DEBUG', False)
    TESTING = _get_bool('TESTING', False)
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    
    # Application Name
    APP_NAME = 'WebShield Scanner'
    APP_VERSION = '1.0.0'
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = _database_url('sqlite:///instance/webshield.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = _engine_options(SQLALCHEMY_DATABASE_URI)
    
    # Session Configuration
    SESSION_TYPE = os.getenv('SESSION_TYPE', 'filesystem')
    SESSION_PERMANENT = _get_bool('SESSION_PERMANENT', False)
    SESSION_USE_SIGNER = _get_bool('SESSION_USE_SIGNER', True)
    SESSION_COOKIE_SECURE = _get_bool('SESSION_COOKIE_SECURE', True)
    SESSION_COOKIE_HTTPONLY = _get_bool('SESSION_COOKIE_HTTPONLY', True)
    SESSION_COOKIE_SAMESITE = _strip_quotes(os.getenv('SESSION_COOKIE_SAMESITE', 'Lax'))
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # JWT Configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=_get_int('JWT_ACCESS_TOKEN_EXPIRES', 3600, minimum=60))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(seconds=_get_int('JWT_REFRESH_TOKEN_EXPIRES', 2592000, minimum=300))
    JWT_TOKEN_LOCATION = ['headers']
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'
    JWT_VERIFY_SUB = False
    
    # CORS Configuration
    CORS_ORIGINS = _get_csv(
        'CORS_ORIGINS',
        'http://localhost:3000,http://localhost:5173',
    )
    CORS_SUPPORTS_CREDENTIALS = True
    
    # Security Configuration
    BCRYPT_ROUNDS = _get_int('BCRYPT_ROUNDS', 12, minimum=4)
    BCRYPT_LOG_ROUNDS = BCRYPT_ROUNDS
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_MAX_LENGTH = 128
    
    # Rate Limiting
    RATELIMIT_ENABLED = _get_bool('RATELIMIT_ENABLED', True)
    RATELIMIT_DEFAULT = _strip_quotes(os.getenv('RATELIMIT_DEFAULT', '100 per hour'))
    RATELIMIT_STORAGE_URI = _strip_quotes(
        os.getenv('RATELIMIT_STORAGE_URI', os.getenv('RATELIMIT_STORAGE_URL', 'memory://'))
    )
    RATELIMIT_STORAGE_URL = RATELIMIT_STORAGE_URI
    RATELIMIT_STRATEGY = 'fixed-window'
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = _get_int('MAX_CONTENT_LENGTH', 16 * 1024 * 1024, minimum=1024)
    UPLOAD_FOLDER = _resolve_backend_path(
        os.getenv('UPLOAD_FOLDER', 'app/static/uploads/')
    )
    REPORT_FOLDER = _resolve_backend_path(
        os.getenv('REPORT_FOLDER', 'app/static/reports/')
    )
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt', 'json', 'html'}
    
    # Scanner Configuration
    MAX_CRAWL_DEPTH = _get_int('MAX_CRAWL_DEPTH', 3, minimum=0)
    MAX_PAGES_TO_CRAWL = _get_int('MAX_PAGES_TO_CRAWL', 100, minimum=1)
    REQUEST_TIMEOUT = _get_int('REQUEST_TIMEOUT', 30, minimum=1)
    MAX_SCAN_REDIRECTS = _get_int('MAX_SCAN_REDIRECTS', 100, minimum=0)
    USER_AGENT = os.getenv('USER_AGENT', 'WebShield-Scanner/1.0')
    # Per-account scan throttle. The route reads both values so deployments can
    # tune the quota without changing code.
    SCAN_RATE_LIMIT = _get_int('SCAN_RATE_LIMIT', 50, minimum=1)
    SCAN_RATE_LIMIT_WINDOW_HOURS = _get_int(
        'SCAN_RATE_LIMIT_WINDOW_HOURS', 3, minimum=1
    )
    BLOCK_PRIVATE_IPS = _get_bool('BLOCK_PRIVATE_IPS', True)
    ALLOWED_SCAN_DOMAINS = [domain.lower() for domain in _get_csv('ALLOWED_SCAN_DOMAINS')]
    
    # Premium Plan Configuration
    FREE_SCAN_LIMIT = _get_int('FREE_SCAN_LIMIT', 5, minimum=0)
    
    # Email Configuration
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = _get_int('MAIL_PORT', 587, minimum=1)
    MAIL_USE_TLS = _get_bool('MAIL_USE_TLS', True)
    MAIL_USE_SSL = _get_bool('MAIL_USE_SSL', False)
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@webshield-scanner.com')
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/webshield.log')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    
    # Feature Flags
    ENABLE_LEARNING_CENTER = _get_bool('ENABLE_LEARNING_CENTER', True)
    ENABLE_AUTHENTICATED_SCANS = _get_bool('ENABLE_AUTHENTICATED_SCANS', True)
    ENABLE_PDF_EXPORT = _get_bool('ENABLE_PDF_EXPORT', True)
    ENABLE_ADVANCED_CRAWLING = _get_bool('ENABLE_ADVANCED_CRAWLING', True)
    
    # Security Headers
    HSTS_ENABLED = _get_bool('HSTS_ENABLED', True)
    HSTS_MAX_AGE = _get_int('HSTS_MAX_AGE', 31536000, minimum=0)
    CSP_ENABLED = _get_bool('CSP_ENABLED', True)
    CSP_POLICY = os.getenv(
        'CSP_POLICY',
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "connect-src 'self'"
    )
    
    # Admin Configuration
    ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@webshield.com')
    ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH', '')
    
    # Celery Configuration
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_TIMEZONE = 'UTC'
    CELERY_ENABLE_UTC = True
    CELERY_TASK_TRACK_STARTED = True
    CELERY_TASK_TIME_LIMIT = 600
    CELERY_TASK_SOFT_TIME_LIMIT = 300
    CELERY_WORKER_PREFETCH_MULTIPLIER = 1
    CELERY_WORKER_MAX_TASKS_PER_CHILD = 100
    
    # Redis Configuration
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    REDIS_MAX_CONNECTIONS = _get_int('REDIS_MAX_CONNECTIONS', 10, minimum=1)
    REDIS_SOCKET_TIMEOUT = _get_int('REDIS_SOCKET_TIMEOUT', 5, minimum=1)
    REDIS_SOCKET_CONNECT_TIMEOUT = _get_int('REDIS_SOCKET_CONNECT_TIMEOUT', 5, minimum=1)
    
    # Cache Configuration
    CACHE_TYPE = os.getenv('CACHE_TYPE', 'simple')
    CACHE_DEFAULT_TIMEOUT = 300
    CACHE_KEY_PREFIX = 'webshield_'
    
    # Monitoring
    SENTRY_DSN = os.getenv('SENTRY_DSN', '')
    
    @staticmethod
    def init_app(app):
        """Initialize application with configuration."""
        valid_samesite = {'Lax', 'Strict', 'None'}
        samesite = app.config.get('SESSION_COOKIE_SAMESITE')
        if samesite not in valid_samesite:
            raise ValueError(
                "SESSION_COOKIE_SAMESITE must be one of Lax, Strict, or None"
            )


class DevelopmentConfig(Config):
    """Development configuration."""
    
    DEBUG = True
    TESTING = False
    
    # SQLite for development
    SQLALCHEMY_DATABASE_URI = _database_url('sqlite:///instance/webshield.db')
    SQLALCHEMY_ENGINE_OPTIONS = _engine_options(SQLALCHEMY_DATABASE_URI)
    
    # Session for development
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # CORS for development
    CORS_ORIGINS = [
        'http://localhost:3000',
        'http://localhost:5173',
        'http://localhost:5000',
        'http://10.0.2.2:5000',
        'capacitor://localhost',
        'https://localhost',
    ]
    
    # Rate limiting disabled for development
    RATELIMIT_ENABLED = False
    
    # Logging for development
    LOG_LEVEL = 'DEBUG'
    
    # Email for development (console output)
    MAIL_SUPPRESS_SEND = True
    
    # Disable SSL verification for development
    SSL_VERIFY = False


class TestingConfig(Config):
    """Testing configuration."""
    
    TESTING = True
    DEBUG = True
    
    # In-memory database for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_ENGINE_OPTIONS = {}
    
    # Disable rate limiting for testing
    RATELIMIT_ENABLED = False
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False

    # Keep password hashing fast in unit tests
    BCRYPT_ROUNDS = 4
    BCRYPT_LOG_ROUNDS = 4
    
    # Testing flags
    SSL_VERIFY = False
    MAIL_SUPPRESS_SEND = True
    
    # Test data
    TESTING_USER_EMAIL = 'test@example.com'
    TESTING_USER_PASSWORD = 'testpassword123'
    TESTING_API_KEY = 'test-api-key-123'


class ProductionConfig(Config):
    """Production configuration."""
    
    DEBUG = False
    TESTING = False
    
    # PostgreSQL for production
    SQLALCHEMY_DATABASE_URI = _database_url('', include_dev=False)
    SQLALCHEMY_ENGINE_OPTIONS = _engine_options(SQLALCHEMY_DATABASE_URI) if SQLALCHEMY_DATABASE_URI else {}
    
    # Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # CORS for production
    CORS_ORIGINS = _get_csv('CORS_ORIGINS')
    
    # Rate limiting enabled
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URI = _strip_quotes(
        os.getenv('RATELIMIT_STORAGE_URI', os.getenv('REDIS_URL', 'memory://'))
    )
    RATELIMIT_STORAGE_URL = RATELIMIT_STORAGE_URI
    
    # Logging for production
    LOG_LEVEL = 'INFO'
    
    # SSL verification
    SSL_VERIFY = True
    
    # Security headers
    HSTS_ENABLED = True
    CSP_ENABLED = True
    
    # Sentry for error tracking
    if os.getenv('SENTRY_DSN'):
        SENTRY_DSN = os.getenv('SENTRY_DSN')

    @staticmethod
    def init_app(app):
        Config.init_app(app)

        required_values = {
            'SECRET_KEY': app.config.get('SECRET_KEY'),
            'JWT_SECRET_KEY': app.config.get('JWT_SECRET_KEY'),
            'SQLALCHEMY_DATABASE_URI': app.config.get('SQLALCHEMY_DATABASE_URI'),
        }
        missing = [name for name, value in required_values.items() if not value]
        if missing:
            raise RuntimeError(
                'Missing required production configuration: ' + ', '.join(missing)
            )

        placeholders = [
            name
            for name, value in {
                'SQLALCHEMY_DATABASE_URI': app.config.get('SQLALCHEMY_DATABASE_URI'),
                'CORS_ORIGINS': ','.join(app.config.get('CORS_ORIGINS') or []),
            }.items()
            if _is_placeholder_value(value)
        ]
        if placeholders:
            raise RuntimeError(
                'Placeholder production configuration values must be replaced: '
                + ', '.join(placeholders)
            )

        unsafe = [
            name
            for name in ('SECRET_KEY', 'JWT_SECRET_KEY')
            if _is_unsafe_secret(app.config.get(name, ''))
        ]
        if unsafe:
            raise RuntimeError(
                'Unsafe placeholder production secrets: ' + ', '.join(unsafe)
            )

        for name in ('SECRET_KEY', 'JWT_SECRET_KEY'):
            if _secret_needs_rotation(app.config.get(name, '')):
                app.logger.warning('%s should be rotated before production launch', name)

        if not app.config.get('CORS_ORIGINS'):
            raise RuntimeError('CORS_ORIGINS must be set in production')

        if app.config.get('RATELIMIT_STORAGE_URI') == 'memory://':
            app.logger.warning(
                'RATELIMIT_STORAGE_URI is memory://; use Redis in multi-worker production'
            )


class StagingConfig(ProductionConfig):
    """Staging configuration."""
    
    DEBUG = True
    TESTING = False
    
    # Use production-like settings but with more logging
    LOG_LEVEL = 'DEBUG'
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = '200'
    
    # Session for staging
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Lax'


# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'staging': StagingConfig,
    'default': DevelopmentConfig
}


def get_config(env=None):
    """Get configuration based on FLASK_ENV."""
    env = env or os.getenv('FLASK_ENV', 'development')
    return config.get(env, DevelopmentConfig)
