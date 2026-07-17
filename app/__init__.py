# -*- coding: utf-8 -*-

"""
WebShield Scanner - Application Factory
Creates and configures the Flask application instance.
"""

import os
import sys
import json
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_migrate import Migrate
from werkzeug.middleware.proxy_fix import ProxyFix

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from config import get_config
from extensions import (
    db, migrate, cors, login_manager, bcrypt, jwt,
    mail, session, csrf, limiter, celery, init_redis
)


def create_app(config_name=None):
    """
    Application factory function.
    
    Args:
        config_name: Configuration environment (development, testing, production)
    
    Returns:
        Flask application instance
    """
    # Create Flask app
    app = Flask(
        __name__,
        template_folder='templates',
        static_folder='static'
    )
    
    # Load configuration
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    config_class = get_config(config_name)
    app.config.from_object(config_class)
    app.config['FLASK_ENV'] = config_name
    config_class.init_app(app)
    
    # Configure proxy fix for reverse proxy setups
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    
    # Initialize extensions
    initialize_extensions(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers
    register_error_handlers(app)

    # Normalize API error payloads
    register_api_response_normalizer(app)

    # Register production security headers
    register_security_headers(app)
    
    # Register context processors
    register_context_processors(app)
    
    # Configure logging
    configure_logging(app)
    
    # Create upload directories if they don't exist
    create_directories(app)
    
    app.logger.info(f"WebShield Scanner started in {app.config.get('FLASK_ENV', 'unknown')} mode")
    
    return app


def initialize_extensions(app):
    """Initialize all Flask extensions."""
    
    # Database
    db.init_app(app)
    
    # Migrations
    migrate.init_app(app, db)
    
    # CORS
    cors.init_app(
        app,
        origins=app.config.get('CORS_ORIGINS', ['*']),
        supports_credentials=True,
        allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
        methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    )
    
    # Login Manager
    login_manager.init_app(app)
    login_manager.login_view = 'page.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'
    login_manager.session_protection = 'strong'

    @login_manager.user_loader
    def load_user(user_id):
        from app.models.user import User

        try:
            return User.query.get(int(user_id))
        except (TypeError, ValueError):
            return None
    
    # Bcrypt
    bcrypt.init_app(app)
    
    # JWT
    jwt.init_app(app)
    
    # Mail
    mail.init_app(app)
    
    # Session
    session.init_app(app)
    
    # CSRF
    csrf.init_app(app)
    
    # Rate Limiter
    limiter.init_app(app)
    
    # Redis
    init_redis(app)
    
    # Celery
    celery.conf.update(app.config)
    
    # Add JWT error handlers
    configure_jwt_handlers(app)


def configure_jwt_handlers(app):
    """Configure JWT error handlers."""
    from flask import jsonify
    
    @jwt.unauthorized_loader
    def unauthorized_response(callback):
        return jsonify({
            'error': 'unauthorized',
            'message': 'Missing or invalid authorization token'
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_response(callback):
        return jsonify({
            'error': 'invalid_token',
            'message': 'Invalid authorization token'
        }), 422
    
    @jwt.expired_token_loader
    def expired_token_response(jwt_header, jwt_payload):
        return jsonify({
            'error': 'token_expired',
            'message': 'Authorization token has expired'
        }), 401
    
    @jwt.revoked_token_loader
    def revoked_token_response(jwt_header, jwt_payload):
        return jsonify({
            'error': 'token_revoked',
            'message': 'Authorization token has been revoked'
        }), 401


def register_blueprints(app):
    """Register all route blueprints."""
    
    from app.routes.page_routes import page_bp
    from app.routes.auth_routes import auth_bp
    from app.routes.dashboard_routes import dashboard_bp
    from app.routes.scan_routes import scan_bp
    from app.routes.report_routes import report_bp
    from app.routes.learning_routes import learning_bp
    from app.routes.settings_routes import settings_bp
    from app.routes.admin_routes import admin_bp
    
    # Register blueprints with URL prefixes
    app.register_blueprint(page_bp)  # Root routes
    api_blueprints = [
        auth_bp,
        dashboard_bp,
        scan_bp,
        report_bp,
        learning_bp,
        settings_bp,
        admin_bp,
    ]
    for blueprint in api_blueprints:
        csrf.exempt(blueprint)

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(scan_bp, url_prefix='/api/scan')
    app.register_blueprint(report_bp, url_prefix='/api/report')
    app.register_blueprint(learning_bp, url_prefix='/api/learning')
    app.register_blueprint(settings_bp, url_prefix='/api/settings')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    
    app.logger.info("Blueprints registered successfully")


def register_error_handlers(app):
    """Register custom error handlers."""
    
    @app.errorhandler(404)
    def not_found(error):
        from flask import jsonify, render_template, request
        if request.path.startswith('/api/'):
            return jsonify({'error': 'not_found', 'message': 'Resource not found'}), 404
        return render_template('pages/404.html'), 404
    
    @app.errorhandler(403)
    def forbidden(error):
        from flask import jsonify, render_template, request
        if request.path.startswith('/api/'):
            return jsonify({'error': 'forbidden', 'message': 'Access forbidden'}), 403
        return render_template('pages/403.html'), 403
    
    @app.errorhandler(500)
    def internal_error(error):
        from flask import jsonify, render_template, request
        app.logger.error(f"Internal server error: {str(error)}")
        if request.path.startswith('/api/'):
            return jsonify({'error': 'internal_error', 'message': 'Internal server error'}), 500
        return render_template('pages/500.html'), 500
    
    @app.errorhandler(429)
    def ratelimit_error(error):
        from flask import jsonify, render_template, request
        if request.path.startswith('/api/'):
            if request.endpoint == 'scan.start_scan':
                scan_limit = app.config.get('SCAN_RATE_LIMIT', 50)
                window_hours = app.config.get('SCAN_RATE_LIMIT_WINDOW_HOURS', 3)
                return jsonify({
                    'error': 'scan_rate_limited',
                    'message': (
                        f'You can start up to {scan_limit} scans every '
                        f'{window_hours} hours. Please try again later.'
                    ),
                    'scan_limit': scan_limit,
                    'window_hours': window_hours,
                }), 429
            return jsonify({'error': 'rate_limited', 'message': 'Rate limit exceeded'}), 429
        return render_template('pages/429.html'), 429


def register_security_headers(app):
    """Apply configured security headers to outgoing responses."""

    @app.after_request
    def apply_security_headers(response):
        from app.security.policy import SecurityPolicy

        return SecurityPolicy.apply_security_headers(response)


def register_api_response_normalizer(app):
    """Ensure API errors use a consistent JSON shape for mobile clients."""

    @app.after_request
    def normalize_api_error(response):
        from flask import request

        if (
            request.path.startswith('/api/')
            and response.status_code >= 400
            and response.is_json
        ):
            data = response.get_json(silent=True)
            if isinstance(data, dict):
                changed = False
                if 'success' not in data:
                    data['success'] = False
                    changed = True
                if 'message' not in data:
                    data['message'] = data.get('error') or response.status
                    changed = True
                if changed:
                    response.set_data(json.dumps(data))
                    response.content_type = 'application/json'

        return response


def register_context_processors(app):
    """Register template context processors."""
    
    @app.context_processor
    def utility_processor():
        from datetime import datetime
        from app.utils.helpers import format_datetime, format_currency, truncate_text
        
        return {
            'app_name': app.config.get('APP_NAME', 'WebShield Scanner'),
            'app_version': app.config.get('APP_VERSION', '1.0.0'),
            'now': datetime.utcnow,
            'format_datetime': format_datetime,
            'format_currency': format_currency,
            'truncate_text': truncate_text
        }
    
    @app.context_processor
    def user_processor():
        from flask_login import current_user
        return {
            'current_user': current_user,
            'is_authenticated': current_user.is_authenticated if hasattr(current_user, 'is_authenticated') else False
        }


def configure_logging(app):
    """Configure application logging."""
    
    if not app.debug:
        # Create logs directory if it doesn't exist
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        log_file = os.path.join(log_dir, 'webshield.log')
        
        # Configure file handler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10485760,  # 10MB
            backupCount=10
        )
        file_handler.setLevel(logging.INFO)
        
        # Configure formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        # Add handler to app
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('WebShield Scanner startup')


def create_directories(app):
    """Create necessary directories."""
    database_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    database_dir = None
    if database_uri.startswith('sqlite:///') and database_uri != 'sqlite:///:memory:':
        database_path = database_uri.replace('sqlite:///', '', 1)
        if database_path:
            if not os.path.isabs(database_path):
                database_path = os.path.abspath(database_path)
            database_dir = os.path.dirname(database_path)

    directories = [
        app.config.get('UPLOAD_FOLDER', 'app/static/uploads/'),
        app.config.get('REPORT_FOLDER', 'app/static/reports/'),
        'logs',
        database_dir,
    ]
    
    for directory in directories:
        if directory and not os.path.exists(directory):
            try:
                os.makedirs(directory)
                app.logger.info(f"Created directory: {directory}")
            except OSError as e:
                app.logger.warning(f"Could not create directory {directory}: {e}")
