# -*- coding: utf-8 -*-

"""
WebShield Scanner - Extensions Module
Initializes and manages Flask extensions.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from celery import Celery
import redis

# Database
db = SQLAlchemy()

# Database migrations
migrate = Migrate()

# CORS
cors = CORS()

# Login manager
login_manager = LoginManager()
login_manager.login_view = 'page.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'
login_manager.session_protection = 'strong'

# Bcrypt for password hashing
bcrypt = Bcrypt()

# JWT manager
jwt = JWTManager()

# Mail
mail = Mail()

# Session
session = Session()

# CSRF Protection
csrf = CSRFProtect()

# Rate Limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    storage_uri=None,
    strategy="fixed-window",
    enabled=True
)

# Celery for background tasks
celery = Celery(
    __name__,
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0'
)

# Redis client
redis_client = None


def init_redis(app):
    """Initialize Redis client."""
    global redis_client
    if app.config.get('TESTING'):
        redis_client = None
        return redis_client

    try:
        redis_url = app.config.get('REDIS_URL', 'redis://localhost:6379/0')
        redis_client = redis.from_url(redis_url)
        redis_client.ping()
        app.logger.info("Redis connected successfully")
    except Exception as e:
        app.logger.warning(f"Redis connection failed: {e}")
        redis_client = None
    return redis_client


def init_extensions(app):
    """Initialize all extensions with the app."""
    
    # Initialize SQLAlchemy
    db.init_app(app)
    
    # Initialize migrations
    migrate.init_app(app, db)
    
    # Initialize CORS
    cors.init_app(app, supports_credentials=True)
    
    # Initialize login manager
    login_manager.init_app(app)
    
    # Initialize Bcrypt
    bcrypt.init_app(app)
    
    # Initialize JWT
    jwt.init_app(app)
    
    # Initialize Mail
    mail.init_app(app)
    
    # Initialize Session
    session.init_app(app)
    
    # Initialize CSRF
    csrf.init_app(app)
    
    # Initialize Rate Limiter
    limiter.init_app(app)
    
    # Initialize Celery
    celery.conf.update(app.config)
    
    # Initialize Redis
    init_redis(app)
    
    # JWT error handlers
    @jwt.unauthorized_loader
    def unauthorized_response(callback):
        """Handle unauthorized JWT requests."""
        from flask import jsonify
        return jsonify({
            'error': 'unauthorized',
            'message': 'Missing or invalid authorization token'
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_response(callback):
        """Handle invalid JWT tokens."""
        from flask import jsonify
        return jsonify({
            'error': 'invalid_token',
            'message': 'Invalid authorization token'
        }), 422
    
    @jwt.expired_token_loader
    def expired_token_response(jwt_header, jwt_payload):
        """Handle expired JWT tokens."""
        from flask import jsonify
        return jsonify({
            'error': 'token_expired',
            'message': 'Authorization token has expired'
        }), 401
    
    @jwt.revoked_token_loader
    def revoked_token_response(jwt_header, jwt_payload):
        """Handle revoked JWT tokens."""
        from flask import jsonify
        return jsonify({
            'error': 'token_revoked',
            'message': 'Authorization token has been revoked'
        }), 401
    
    # Login manager user loader
    @login_manager.user_loader
    def load_user(user_id):
        """Load user by ID for Flask-Login."""
        from app.models.user import User
        return User.query.get(int(user_id))
    
    app.logger.info("All extensions initialized successfully")
    
    return app
