# -*- coding: utf-8 -*-

"""
WebShield Scanner - Routes Package
Contains all route blueprints for the application.
"""

from app.routes.page_routes import page_bp
from app.routes.auth_routes import auth_bp
from app.routes.dashboard_routes import dashboard_bp
from app.routes.scan_routes import scan_bp
from app.routes.report_routes import report_bp
from app.routes.learning_routes import learning_bp
from app.routes.settings_routes import settings_bp
from app.routes.admin_routes import admin_bp

__all__ = [
    'page_bp',
    'auth_bp',
    'dashboard_bp',
    'scan_bp',
    'report_bp',
    'learning_bp',
    'settings_bp',
    'admin_bp'
]
