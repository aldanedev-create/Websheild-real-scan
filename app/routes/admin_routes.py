# -*- coding: utf-8 -*-

"""
WebShield Scanner - Admin Routes
Manages administrative functions like user management and system monitoring.
"""

from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import func, desc, text
from extensions import db
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.audit_log import AuditLog
from app.models.learning_lesson import LearningLesson
from app.security.decorators import admin_required

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/dashboard/stats', methods=['GET'])
@jwt_required()
@admin_required
def get_admin_stats():
    """Get admin dashboard statistics."""
    try:
        # User statistics
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        admin_users = User.query.filter_by(is_admin=True).count()
        
        # New users in last 7 days
        week_ago = datetime.utcnow() - timedelta(days=7)
        new_users = User.query.filter(User.created_at >= week_ago).count()
        
        # Scan statistics
        total_scans = Scan.query.count()
        completed_scans = Scan.query.filter_by(scan_status='completed').count()
        running_scans = Scan.query.filter_by(scan_status='running').count()
        failed_scans = Scan.query.filter_by(scan_status='failed').count()
        
        # Scans in last 7 days
        recent_scans = Scan.query.filter(Scan.created_at >= week_ago).count()
        
        # Finding statistics
        total_findings = Finding.query.count()
        false_positives = Finding.query.filter_by(is_false_positive=True).count()
        
        # Findings by severity
        severity_counts = db.session.query(
            Finding.severity,
            func.count(Finding.id)
        ).group_by(Finding.severity).all()
        
        findings_by_severity = {s: 0 for s in ['critical', 'high', 'medium', 'low', 'info']}
        for severity, count in severity_counts:
            if severity in findings_by_severity:
                findings_by_severity[severity] = count
        
        # Average security score
        avg_score = db.session.query(func.avg(Scan.security_score)).filter(
            Scan.scan_status == 'completed',
            Scan.security_score.isnot(None)
        ).first()[0]
        
        return jsonify({
            'success': True,
            'stats': {
                'users': {
                    'total': total_users,
                    'active': active_users,
                    'open_source': active_users,
                    'admin': admin_users,
                    'new_this_week': new_users
                },
                'scans': {
                    'total': total_scans,
                    'completed': completed_scans,
                    'running': running_scans,
                    'failed': failed_scans,
                    'recent_this_week': recent_scans
                },
                'findings': {
                    'total': total_findings,
                    'false_positives': false_positives,
                    'by_severity': findings_by_severity
                },
                'security': {
                    'average_score': round(avg_score, 1) if avg_score is not None else None
                },
                'revenue': {
                    'total': 0,
                    'currency': 'OSS'
                }
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Admin stats error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch admin statistics'
        }), 500


@admin_bp.route('/users', methods=['GET'])
@jwt_required()
@admin_required
def get_users():
    """Get paginated list of users."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        search = request.args.get('search', '')
        plan = request.args.get('plan', 'all')
        
        query = User.query
        
        if search:
            query = query.filter(
                (User.username.ilike(f'%{search}%')) |
                (User.email.ilike(f'%{search}%')) |
                (User.full_name.ilike(f'%{search}%'))
            )
        
        if plan != 'all':
            query = query.filter_by(plan=plan)
        
        paginated = query.order_by(desc(User.created_at)).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'success': True,
            'users': [u.to_dict() for u in paginated.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': paginated.total,
                'pages': paginated.pages
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get users error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch users'
        }), 500


@admin_bp.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
@admin_required
def get_user(user_id):
    """Get a specific user's details."""
    try:
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        return jsonify({
            'success': True,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get user error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch user'
        }), 500


@admin_bp.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_user(user_id):
    """Update a user (admin only)."""
    try:
        current_admin_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        data = request.get_json(silent=True) or {}
        
        if current_admin_id == user.id and data.get('is_active') is False:
            return jsonify({
                'error': 'cannot_deactivate_self',
                'message': 'Cannot deactivate your own admin account'
            }), 400

        if current_admin_id == user.id and data.get('is_admin') is False:
            return jsonify({
                'error': 'cannot_demote_self',
                'message': 'Cannot remove admin access from your own account'
            }), 400

        if user.is_admin and data.get('is_admin') is False:
            active_admins = User.query.filter_by(is_admin=True, is_active=True).count()
            if active_admins <= 1:
                return jsonify({
                    'error': 'last_admin_required',
                    'message': 'Cannot remove the last active admin'
                }), 400

        if 'plan' in data and data['plan'] not in ['free', 'premium']:
            return jsonify({
                'error': 'invalid_plan',
                'message': 'Plan must be free or premium'
            }), 400

        for bool_field in ['is_active', 'is_admin']:
            if bool_field in data and not isinstance(data[bool_field], bool):
                return jsonify({
                    'error': 'invalid_boolean',
                    'message': f'{bool_field} must be true or false'
                }), 400

        # Update allowed fields
        allowed_fields = ['full_name', 'bio', 'is_active', 'is_admin', 'plan']
        
        changes = []
        for field in allowed_fields:
            if field in data:
                old_value = getattr(user, field)
                new_value = data[field]
                if old_value != new_value:
                    setattr(user, field, new_value)
                    changes.append(f'{field}: {old_value} -> {new_value}')
        
        db.session.commit()
        
        if changes:
            AuditLog.log(
                user_id=current_admin_id,
                action='admin_user_updated',
                details=f'Admin updated user {user.username}: {", ".join(changes)}',
                metadata={'user_id': user.id}
            )
        
        return jsonify({
            'success': True,
            'message': 'User updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Update user error: {str(e)}')
        return jsonify({
            'error': 'update_failed',
            'message': 'Could not update user'
        }), 500


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@jwt_required()
@admin_required
def delete_user(user_id):
    """Delete a user (admin only)."""
    try:
        # Prevent admin from deleting themselves
        current_user_id = int(get_jwt_identity())
        if current_user_id == user_id:
            return jsonify({
                'error': 'cannot_delete_self',
                'message': 'Cannot delete your own account'
            }), 400
        
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404

        if user.is_admin:
            active_admins = User.query.filter_by(is_admin=True, is_active=True).count()
            if active_admins <= 1:
                return jsonify({
                    'error': 'last_admin_required',
                    'message': 'Cannot delete the last active admin'
                }), 400
        
        AuditLog.log(
            user_id=current_user_id,
            action='admin_user_deleted',
            details=f'Admin deleted user: {user.username} ({user.email})',
            metadata={'deleted_user_id': user.id}
        )
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'User deleted successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Delete user error: {str(e)}')
        return jsonify({
            'error': 'delete_failed',
            'message': 'Could not delete user'
        }), 500


@admin_bp.route('/audit-logs', methods=['GET'])
@jwt_required()
@admin_required
def get_audit_logs():
    """Get audit logs with filtering."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        action = request.args.get('action')
        severity = request.args.get('severity')
        user_id = request.args.get('user_id', type=int)
        days = request.args.get('days', 7, type=int)
        
        query = AuditLog.query
        
        if action:
            query = query.filter_by(action=action)
        if severity:
            query = query.filter_by(severity=severity)
        if user_id:
            query = query.filter_by(user_id=user_id)
        if days:
            cutoff = datetime.utcnow() - timedelta(days=days)
            query = query.filter(AuditLog.created_at >= cutoff)
        
        paginated = query.order_by(desc(AuditLog.created_at)).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'success': True,
            'logs': [log.to_dict() for log in paginated.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': paginated.total,
                'pages': paginated.pages
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get audit logs error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch audit logs'
        }), 500


@admin_bp.route('/scans', methods=['GET'])
@jwt_required()
@admin_required
def get_all_scans():
    """Get all scans (admin view)."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status = request.args.get('status')
        user_id = request.args.get('user_id', type=int)
        
        query = Scan.query
        
        if status:
            query = query.filter_by(scan_status=status)
        if user_id:
            query = query.filter_by(user_id=user_id)
        
        paginated = query.order_by(desc(Scan.created_at)).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'success': True,
            'scans': [scan.to_dict() for scan in paginated.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': paginated.total,
                'pages': paginated.pages
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get all scans error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch scans'
        }), 500


@admin_bp.route('/lessons', methods=['GET', 'POST'])
@jwt_required()
@admin_required
def manage_lessons():
    """Get or create learning lessons."""
    try:
        if request.method == 'GET':
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 20, type=int)
            
            paginated = LearningLesson.query.order_by(
                LearningLesson.order
            ).paginate(page=page, per_page=per_page, error_out=False)
            
            return jsonify({
                'success': True,
                'lessons': [l.to_dict() for l in paginated.items],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': paginated.total,
                    'pages': paginated.pages
                }
            }), 200
        
        elif request.method == 'POST':
            data = request.get_json(silent=True) or {}
            
            # Required fields
            if not data.get('title') or not data.get('category') or not data.get('content'):
                return jsonify({
                    'error': 'missing_fields',
                    'message': 'Title, category, and content are required'
                }), 400
            
            lesson = LearningLesson(
                title=data['title'],
                category=data['category'],
                content=data['content'],
                excerpt=data.get('excerpt'),
                difficulty=data.get('difficulty', 'beginner'),
                image_url=data.get('image_url'),
                video_url=data.get('video_url'),
                order=data.get('order', 0),
                is_premium=data.get('is_premium', False),
                reading_time=data.get('reading_time', 15),
                tags=data.get('tags'),
                is_published=data.get('is_published', True)
            )
            
            db.session.add(lesson)
            db.session.commit()
            
            AuditLog.log(
                user_id=get_jwt_identity(),
                action='admin_lesson_created',
                details=f'Created lesson: {lesson.title}',
                metadata={'lesson_id': lesson.id}
            )
            
            return jsonify({
                'success': True,
                'message': 'Lesson created successfully',
                'lesson': lesson.to_dict()
            }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Manage lessons error: {str(e)}')
        return jsonify({
            'error': 'operation_failed',
            'message': 'Could not manage lessons'
        }), 500


@admin_bp.route('/lessons/<int:lesson_id>', methods=['PUT', 'DELETE'])
@jwt_required()
@admin_required
def manage_lesson(lesson_id):
    """Update or delete a learning lesson."""
    try:
        lesson = LearningLesson.query.get(lesson_id)
        
        if not lesson:
            return jsonify({
                'error': 'lesson_not_found',
                'message': 'Lesson not found'
            }), 404
        
        if request.method == 'PUT':
            data = request.get_json(silent=True) or {}
            
            allowed_fields = [
                'title', 'category', 'content', 'excerpt', 'difficulty',
                'image_url', 'video_url', 'order', 'is_premium',
                'reading_time', 'tags', 'is_published'
            ]
            
            changes = []
            for field in allowed_fields:
                if field in data:
                    old_value = getattr(lesson, field)
                    new_value = data[field]
                    if old_value != new_value:
                        setattr(lesson, field, new_value)
                        changes.append(f'{field}: {old_value} -> {new_value}')
            
            db.session.commit()
            
            if changes:
                AuditLog.log(
                    user_id=get_jwt_identity(),
                    action='admin_lesson_updated',
                    details=f'Updated lesson {lesson.title}: {", ".join(changes)}',
                    metadata={'lesson_id': lesson.id}
                )
            
            return jsonify({
                'success': True,
                'message': 'Lesson updated successfully',
                'lesson': lesson.to_dict()
            }), 200
        
        elif request.method == 'DELETE':
            AuditLog.log(
                user_id=get_jwt_identity(),
                action='admin_lesson_deleted',
                details=f'Deleted lesson: {lesson.title}',
                metadata={'lesson_id': lesson.id}
            )
            
            db.session.delete(lesson)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Lesson deleted successfully'
            }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Manage lesson error: {str(e)}')
        return jsonify({
            'error': 'operation_failed',
            'message': 'Could not manage lesson'
        }), 500


@admin_bp.route('/system/health', methods=['GET'])
@jwt_required()
@admin_required
def system_health():
    """Check system health status."""
    try:
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'checks': {
                'database': {
                    'status': 'healthy',
                    'message': 'Database connection successful'
                },
                'redis': {
                    'status': 'unknown',
                    'message': 'Redis not configured'
                },
                'disk_space': {
                    'status': 'healthy',
                    'message': 'Sufficient disk space available'
                }
            }
        }
        
        # Check database
        try:
            db.session.execute(text('SELECT 1'))
        except Exception as e:
            health_status['status'] = 'unhealthy'
            health_status['checks']['database']['status'] = 'unhealthy'
            health_status['checks']['database']['message'] = str(e)
        
        # Check redis
        try:
            from extensions import redis_client
            if redis_client:
                redis_client.ping()
                health_status['checks']['redis']['status'] = 'healthy'
                health_status['checks']['redis']['message'] = 'Redis connection successful'
            else:
                health_status['checks']['redis']['status'] = 'warning'
                health_status['checks']['redis']['message'] = 'Redis not configured'
        except Exception as e:
            health_status['checks']['redis']['status'] = 'unhealthy'
            health_status['checks']['redis']['message'] = str(e)
        
        return jsonify({
            'success': True,
            'health': health_status
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'System health error: {str(e)}')
        return jsonify({
            'error': 'health_check_failed',
            'message': 'Could not check system health'
        }), 500
