# -*- coding: utf-8 -*-

"""
WebShield Scanner - Page Routes
Serves the main frontend pages for the application.
"""

from flask import Blueprint, abort, render_template, redirect, url_for, request, session
from flask_login import login_required, current_user, logout_user
from datetime import datetime
from markdown import markdown
from markupsafe import Markup, escape

page_bp = Blueprint('page', __name__)


@page_bp.route('/')
def index():
    """Home page - redirect to dashboard or splash."""
    if current_user.is_authenticated:
        return redirect(url_for('page.dashboard'))
    return redirect(url_for('page.splash'))


@page_bp.route('/splash')
def splash():
    """Splash screen with app introduction."""
    if current_user.is_authenticated:
        return redirect(url_for('page.dashboard'))
    return render_template('pages/splash.html')


@page_bp.route('/login')
def login():
    """Render the browser login page."""
    if current_user.is_authenticated:
        return redirect(url_for('page.dashboard'))
    return render_template('auth/login.html')


@page_bp.route('/register')
@page_bp.route('/create-account')
def register():
    """Render the browser account creation page."""
    if current_user.is_authenticated:
        return redirect(url_for('page.dashboard'))
    return render_template('auth/register.html')


@page_bp.route('/forgot-password')
def forgot_password():
    """Render the browser password reset request page."""
    if current_user.is_authenticated:
        return redirect(url_for('page.dashboard'))
    return render_template('auth/forgot_password.html')


@page_bp.route('/reset-password/<token>')
def reset_password(token):
    """Render the browser password reset page for a token."""
    if current_user.is_authenticated:
        return redirect(url_for('page.dashboard'))
    return render_template('auth/reset_password.html', token=token)


@page_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """Log out of the browser session and return to the splash page."""
    if current_user.is_authenticated:
        logout_user()
    return redirect(url_for('page.splash', logged_out='1'))


@page_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with scan history and stats."""
    return render_template('pages/dashboard.html')


@page_bp.route('/scan-history')
@login_required
def scan_history():
    """Full scan history page."""
    return render_template('pages/scan_history.html')


@page_bp.route('/admin')
@page_bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    """Admin dashboard page."""
    if not current_user.is_admin:
        abort(403)
    return render_template('pages/admin_dashboard.html')


@page_bp.route('/new-scan')
@login_required
def new_scan():
    """New scan page with URL input and settings."""
    return render_template('pages/new_scan.html')


@page_bp.route('/scan-progress/<int:scan_id>')
@login_required
def scan_progress(scan_id):
    """Real-time scan progress page."""
    return render_template('pages/scan_progress.html', scan_id=scan_id)


@page_bp.route('/report/<int:scan_id>')
@login_required
def report_details(scan_id):
    """Detailed scan report page."""
    return render_template('pages/report_details.html', scan_id=scan_id)


@page_bp.route('/attack-surface/<int:scan_id>')
@login_required
def attack_surface_map(scan_id):
    """Attack surface visualization page."""
    return render_template('pages/attack_surface_map.html', scan_id=scan_id)


@page_bp.route('/learning-center')
def learning_center():
    """Learning center with security lessons."""
    return render_template('pages/learning_center.html')


@page_bp.route('/learning/<int:lesson_id>')
def learning_lesson(lesson_id):
    """Individual learning lesson page."""
    from app.models.learning_lesson import LearningLesson

    lesson = LearningLesson.query.filter_by(id=lesson_id, is_published=True).first()
    lesson_html = None
    can_access = bool(lesson and lesson.is_accessible(current_user if current_user.is_authenticated else None))
    if lesson and can_access:
        escaped_content = escape(lesson.content or '')
        lesson_html = Markup(markdown(
            str(escaped_content),
            extensions=['fenced_code', 'tables', 'sane_lists'],
            output_format='html5',
        ))
    return render_template('learning/lesson_details.html', lesson=lesson, lesson_html=lesson_html)


@page_bp.route('/settings')
@login_required
def settings():
    """User settings page."""
    return render_template('pages/settings.html')


@page_bp.route('/privacy')
def privacy_policy():
    """Privacy policy page."""
    return render_template('pages/privacy_policy.html')


@page_bp.route('/terms')
def terms_of_service():
    """Terms of service page."""
    return render_template('pages/terms_of_service.html')


@page_bp.route('/legal')
def legal_policy():
    """Legal and ethical policy page."""
    return render_template('pages/legal_policy.html')


@page_bp.route('/about')
def about():
    """About page."""
    return render_template('pages/about.html')


@page_bp.route('/contact')
def contact():
    """Contact page."""
    return render_template('pages/contact.html')


@page_bp.route('/health')
def health_check():
    """Health check endpoint for monitoring."""
    from flask import jsonify
    return jsonify({
        'status': 'healthy',
        'app': 'WebShield Scanner',
        'version': '1.0.0'
    })


@page_bp.route('/api/health')
def api_health_check():
    """API health check endpoint for deployment monitoring."""
    from flask import jsonify
    return jsonify({
        'success': True,
        'status': 'healthy',
        'app': 'WebShield Scanner',
        'version': '1.0.0',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    })


@page_bp.errorhandler(404)
def page_not_found(error):
    """Custom 404 error page."""
    return render_template('pages/404.html'), 404


@page_bp.errorhandler(403)
def forbidden(error):
    """Custom 403 error page."""
    return render_template('pages/403.html'), 403


@page_bp.errorhandler(500)
def internal_error(error):
    """Custom 500 error page."""
    return render_template('pages/500.html'), 500
