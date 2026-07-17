# -*- coding: utf-8 -*-

"""
WebShield Scanner - Dashboard Routes
Provides dashboard statistics and data for authenticated users.
"""

from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import func, desc
from extensions import db
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding

dashboard_bp = Blueprint('dashboard', __name__)


def _serialize_date(value):
    return value.isoformat() if hasattr(value, 'isoformat') else str(value)


@dashboard_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    """Get user dashboard statistics."""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        # Get scan statistics
        total_scans = Scan.query.filter_by(user_id=user_id).count()
        completed_scans = Scan.query.filter_by(user_id=user_id, scan_status='completed').count()
        
        # Get scans from last 7 days
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_scans = Scan.query.filter(
            Scan.user_id == user_id,
            Scan.created_at >= week_ago
        ).count()
        
        # Get average security score
        avg_score_result = db.session.query(func.avg(Scan.security_score)).filter(
            Scan.user_id == user_id,
            Scan.scan_status == 'completed',
            Scan.security_score.isnot(None)
        ).first()
        avg_score = round(avg_score_result[0], 1) if avg_score_result[0] is not None else None
        
        # Get findings summary
        finding_counts = db.session.query(
            Finding.severity,
            func.count(Finding.id)
        ).join(Scan).filter(
            Scan.user_id == user_id,
            Finding.is_false_positive == False
        ).group_by(Finding.severity).all()
        
        findings_by_severity = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        for severity, count in finding_counts:
            if severity in findings_by_severity:
                findings_by_severity[severity] = count
        
        total_findings = sum(findings_by_severity.values())
        
        # Get recent scans
        recent_scans_list = Scan.query.filter_by(
            user_id=user_id
        ).order_by(
            desc(Scan.created_at)
        ).limit(5).all()
        
        # Get scan trends (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        scan_trends = db.session.query(
            func.date(Scan.created_at).label('date'),
            func.count(Scan.id).label('count')
        ).filter(
            Scan.user_id == user_id,
            Scan.created_at >= thirty_days_ago
        ).group_by(
            func.date(Scan.created_at)
        ).order_by(
            func.date(Scan.created_at)
        ).all()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_scans': total_scans,
                'completed_scans': completed_scans,
                'recent_scans': recent_scans,
                'average_score': avg_score,
                'total_findings': total_findings,
                'findings_by_severity': findings_by_severity,
                'remaining_scans': user.get_remaining_scans(),
                'is_premium': False,
                'plan': 'open_source',
                'premium_days_remaining': None,
                'scan_trends': [
                    {'date': _serialize_date(trend.date), 'count': trend.count}
                    for trend in scan_trends
                ],
                'recent_scans': [scan.to_dict() for scan in recent_scans_list]
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Dashboard stats error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch dashboard statistics'
        }), 500


@dashboard_bp.route('/scan-history', methods=['GET'])
@jwt_required()
def get_scan_history():
    """Get paginated scan history."""
    try:
        user_id = get_jwt_identity()
        
        page = request.args.get('page', 1, type=int)
        per_page = min(max(request.args.get('per_page', 10, type=int), 1), 50)
        status = request.args.get('status', 'all')
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        search = (request.args.get('q') or '').strip()

        allowed_sort = {
            'created_at': Scan.created_at,
            'completed_at': Scan.completed_at,
            'security_score': Scan.security_score,
            'total_findings': Scan.total_findings,
            'scan_status': Scan.scan_status,
            'target_url': Scan.target_url,
        }
        sort_column = allowed_sort.get(sort_by, Scan.created_at)
        
        # Build query
        query = Scan.query.filter_by(user_id=user_id)
        
        if status != 'all':
            query = query.filter_by(scan_status=status)

        if search:
            query = query.filter(Scan.target_url.ilike(f'%{search}%'))
        
        # Apply sorting
        if sort_order == 'desc':
            query = query.order_by(desc(sort_column))
        else:
            query = query.order_by(sort_column)
        
        # Paginate results
        paginated = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'success': True,
            'scans': [scan.to_dict() for scan in paginated.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': paginated.total,
                'pages': paginated.pages,
                'has_prev': paginated.has_prev,
                'has_next': paginated.has_next
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Scan history error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch scan history'
        }), 500


@dashboard_bp.route('/weekly-summary', methods=['GET'])
@jwt_required()
def get_weekly_summary():
    """Get weekly scan summary."""
    try:
        user_id = get_jwt_identity()
        
        week_ago = datetime.utcnow() - timedelta(days=7)
        
        # Get scans from last week
        scans = Scan.query.filter(
            Scan.user_id == user_id,
            Scan.created_at >= week_ago,
            Scan.scan_status == 'completed'
        ).all()
        
        if not scans:
            return jsonify({
                'success': True,
                'summary': {
                    'has_data': False,
                    'message': 'No scans in the last 7 days'
                }
            }), 200
        
        total_scans = len(scans)
        scored_scans = [s.security_score for s in scans if s.security_score is not None]
        avg_score = sum(scored_scans) / len(scored_scans) if scored_scans else None
        
        # Count findings
        total_findings = sum(s.total_findings or 0 for s in scans)
        
        # Get top vulnerabilities
        vulnerability_counts = {}
        for scan in scans:
            for finding in scan.findings:
                if not finding.is_false_positive:
                    key = finding.category
                    vulnerability_counts[key] = vulnerability_counts.get(key, 0) + 1
        
        top_vulnerabilities = sorted(
            [{'category': k, 'count': v} for k, v in vulnerability_counts.items()],
            key=lambda x: x['count'],
            reverse=True
        )[:5]
        
        return jsonify({
            'success': True,
            'summary': {
                'has_data': True,
                'total_scans': total_scans,
                'average_score': round(avg_score, 1) if avg_score is not None else None,
                'total_findings': total_findings,
                'top_vulnerabilities': top_vulnerabilities,
                'week_start': week_ago.isoformat(),
                'week_end': datetime.utcnow().isoformat()
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Weekly summary error: {str(e)}')
        return jsonify({
            'error': 'fetch_failed',
            'message': 'Could not fetch weekly summary'
        }), 500
