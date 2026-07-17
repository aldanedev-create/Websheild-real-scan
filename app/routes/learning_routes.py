# -*- coding: utf-8 -*-

"""
WebShield Scanner - Learning Routes
Manages learning center content and lessons.
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request
from extensions import db
from app.models.user import User
from app.models.learning_lesson import LearningLesson
from app.models.audit_log import AuditLog

learning_bp = Blueprint('learning', __name__)


def _get_optional_user_id():
    try:
        verify_jwt_in_request(optional=True)
        return get_jwt_identity()
    except Exception:
        return None


@learning_bp.route('/lessons', methods=['GET'])
def get_lessons():
    """Get all learning lessons with filtering."""
    try:
        # Get query parameters
        category = request.args.get('category')
        difficulty = request.args.get('difficulty')
        search = request.args.get('search')
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        # Build query
        query = LearningLesson.query.filter_by(is_published=True)
        
        if category:
            query = query.filter_by(category=category)
        if difficulty:
            query = query.filter_by(difficulty=difficulty)
        if search:
            query = query.filter(
                LearningLesson.title.ilike(f'%{search}%') |
                LearningLesson.content.ilike(f'%{search}%')
            )
        
        # Get total count
        total = query.count()
        
        # Get lessons
        lessons = query.order_by(LearningLesson.order).offset(offset).limit(limit).all()
        
        # Format response
        lessons_data = []
        for lesson in lessons:
            lesson_dict = lesson.to_preview_dict()
            lesson_dict['is_locked'] = False
            lessons_data.append(lesson_dict)
        
        return jsonify({
            'success': True,
            'lessons': lessons_data,
            'pagination': {
                'total': total,
                'limit': limit,
                'offset': offset,
                'has_more': offset + limit < total
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get lessons error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch lessons'
        }), 500


@learning_bp.route('/lessons/<int:lesson_id>', methods=['GET'])
def get_lesson(lesson_id):
    """Get a specific lesson by ID."""
    try:
        lesson = LearningLesson.query.get(lesson_id)
        
        if not lesson or not lesson.is_published:
            return jsonify({
                'error': 'lesson_not_found',
                'message': 'Lesson not found'
            }), 404
        
        # Increment view count
        lesson.increment_views()
        db.session.commit()
        
        # Log view
        if user_id:
            AuditLog.log(
                user_id=user_id,
                action='lesson_viewed',
                details=f'Viewed lesson: {lesson.title}',
                metadata={'lesson_id': lesson.id}
            )
        
        return jsonify({
            'success': True,
            'lesson': lesson.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get lesson error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch lesson'
        }), 500


@learning_bp.route('/lessons/<int:lesson_id>/like', methods=['POST'])
@jwt_required()
def like_lesson(lesson_id):
    """Like a lesson."""
    try:
        user_id = get_jwt_identity()
        lesson = LearningLesson.query.get(lesson_id)
        
        if not lesson or not lesson.is_published:
            return jsonify({
                'error': 'lesson_not_found',
                'message': 'Lesson not found'
            }), 404
        
        lesson.increment_likes()
        db.session.commit()
        
        AuditLog.log(
            user_id=user_id,
            action='lesson_liked',
            details=f'Liked lesson: {lesson.title}',
            metadata={'lesson_id': lesson.id}
        )
        
        return jsonify({
            'success': True,
            'message': 'Lesson liked',
            'likes': lesson.likes
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Like lesson error: {str(e)}')
        return jsonify({
            'error': 'like_failed',
            'message': 'Could not like lesson'
        }), 500


@learning_bp.route('/categories', methods=['GET'])
def get_categories():
    """Get all lesson categories with counts."""
    try:
        from sqlalchemy import func
        
        categories = db.session.query(
            LearningLesson.category,
            func.count(LearningLesson.id).label('count')
        ).filter_by(is_published=True).group_by(LearningLesson.category).all()
        
        return jsonify({
            'success': True,
            'categories': [
                {'name': cat, 'count': count}
                for cat, count in categories
            ]
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get categories error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch categories'
        }), 500


@learning_bp.route('/search', methods=['GET'])
def search_lessons():
    """Search lessons by keyword."""
    try:
        query = request.args.get('q', '').strip()
        
        if not query:
            return jsonify({
                'success': True,
                'lessons': []
            }), 200
        
        results = LearningLesson.query.filter(
            LearningLesson.is_published == True,
            (
                LearningLesson.title.ilike(f'%{query}%') |
                LearningLesson.content.ilike(f'%{query}%') |
                LearningLesson.tags.cast(db.String).ilike(f'%{query}%')
            )
        ).order_by(LearningLesson.order).limit(10).all()
        
        return jsonify({
            'success': True,
            'results': [
                {
                    'id': r.id,
                    'title': r.title,
                    'slug': r.slug,
                    'category': r.category,
                    'excerpt': r.excerpt,
                    'is_premium': False,
                    'is_locked': False
                }
                for r in results
            ]
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Search lessons error: {str(e)}')
        return jsonify({
            'error': 'search_failed',
            'message': 'Could not search lessons'
        }), 500
