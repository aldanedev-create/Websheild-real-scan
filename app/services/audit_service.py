# -*- coding: utf-8 -*-

"""
WebShield Scanner - Audit Service
Handles audit logging and activity tracking.
"""

from datetime import datetime, timedelta
from flask import current_app, request
from extensions import db
from app.models.audit_log import AuditLog
from app.models.user import User


class AuditService:
    """Service for handling audit logging."""
    
    @staticmethod
    def log(user_id, action, details=None, metadata=None, ip_address=None, user_agent=None, severity='info'):
        """
        Create an audit log entry.
        
        Args:
            user_id: User ID (can be None for unauthenticated actions)
            action: Action name
            details: Action details (optional)
            metadata: Additional metadata (optional)
            ip_address: IP address (optional)
            user_agent: User agent (optional)
            severity: Severity level (info, warning, error, critical)
            
        Returns:
            AuditLog: Created audit log entry
        """
        try:
            # Get IP address if not provided
            if not ip_address and request:
                ip_address = request.remote_addr
                # Handle proxy headers
                if request.headers.get('X-Forwarded-For'):
                    ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
                elif request.headers.get('X-Real-IP'):
                    ip_address = request.headers.get('X-Real-IP')
            
            # Get user agent if not provided
            if not user_agent and request:
                user_agent = request.headers.get('User-Agent')
            
            # Create log entry
            log = AuditLog(
                user_id=user_id,
                action=action,
                details=details,
                metadata=metadata,
                ip_address=ip_address,
                user_agent=user_agent,
                severity=severity
            )
            
            db.session.add(log)
            db.session.commit()
            
            return log
            
        except Exception as e:
            current_app.logger.error(f'Audit log error: {str(e)}')
            db.session.rollback()
            return None
    
    @staticmethod
    def get_logs(user_id=None, action=None, severity=None, start_date=None, end_date=None, page=1, per_page=50):
        """
        Get audit logs with filters.
        
        Args:
            user_id: Filter by user ID (optional)
            action: Filter by action (optional)
            severity: Filter by severity (optional)
            start_date: Filter by start date (optional)
            end_date: Filter by end date (optional)
            page: Page number
            per_page: Items per page
            
        Returns:
            dict: Paginated logs
        """
        query = AuditLog.query
        
        if user_id:
            query = query.filter_by(user_id=user_id)
        
        if action:
            query = query.filter_by(action=action)
        
        if severity:
            query = query.filter_by(severity=severity)
        
        if start_date:
            query = query.filter(AuditLog.created_at >= start_date)
        
        if end_date:
            query = query.filter(AuditLog.created_at <= end_date)
        
        total = query.count()
        logs = query.order_by(AuditLog.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
        
        return {
            'logs': [log.to_dict() for log in logs],
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        }
    
    @staticmethod
    def get_user_activity(user_id, days=7):
        """
        Get user activity summary.
        
        Args:
            user_id: User ID
            days: Number of days to look back
            
        Returns:
            dict: Activity summary
        """
        start_date = datetime.utcnow() - timedelta(days=days)
        
        logs = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.created_at >= start_date
        ).all()
        
        # Group by action
        actions = {}
        for log in logs:
            actions[log.action] = actions.get(log.action, 0) + 1
        
        return {
            'total_actions': len(logs),
            'days': days,
            'actions': actions,
            'latest_activity': logs[0].created_at.isoformat() if logs else None
        }
    
    @staticmethod
    def get_system_audit_summary(days=7):
        """
        Get system-wide audit summary.
        
        Args:
            days: Number of days to look back
            
        Returns:
            dict: System audit summary
        """
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Total logs
        total = AuditLog.query.filter(AuditLog.created_at >= start_date).count()
        
        # Logs by severity
        severity_counts = {}
        for severity in ['info', 'warning', 'error', 'critical']:
            count = AuditLog.query.filter(
                AuditLog.created_at >= start_date,
                AuditLog.severity == severity
            ).count()
            severity_counts[severity] = count
        
        # Most active users
        active_users = db.session.query(
            AuditLog.user_id,
            db.func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.created_at >= start_date,
            AuditLog.user_id.isnot(None)
        ).group_by(
            AuditLog.user_id
        ).order_by(
            db.func.count(AuditLog.id).desc()
        ).limit(10).all()
        
        # Get user names
        user_ids = [u[0] for u in active_users]
        users = User.query.filter(User.id.in_(user_ids)).all() if user_ids else []
        user_map = {u.id: u.username for u in users}
        
        top_users = [
            {'user_id': uid, 'username': user_map.get(uid, 'Unknown'), 'count': count}
            for uid, count in active_users
        ]
        
        # Most common actions
        action_counts = db.session.query(
            AuditLog.action,
            db.func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.created_at >= start_date
        ).group_by(
            AuditLog.action
        ).order_by(
            db.func.count(AuditLog.id).desc()
        ).limit(10).all()
        
        return {
            'period_days': days,
            'total_logs': total,
            'severity_counts': severity_counts,
            'top_users': top_users,
            'top_actions': [{'action': a, 'count': c} for a, c in action_counts]
        }
    
    @staticmethod
    def cleanup_old_logs(days=90):
        """
        Clean up old audit logs.
        
        Args:
            days: Number of days to keep
            
        Returns:
            int: Number of logs deleted
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        deleted = AuditLog.query.filter(AuditLog.created_at < cutoff).delete()
        db.session.commit()
        
        current_app.logger.info(f'Cleaned up {deleted} audit logs older than {days} days')
        return deleted
    
    @staticmethod
    def get_log_by_id(log_id):
        """
        Get a specific log entry.
        
        Args:
            log_id: Log ID
            
        Returns:
            AuditLog: Log entry or None
        """
        return AuditLog.query.get(log_id)
    
    @staticmethod
    def get_user_login_history(user_id, limit=10):
        """
        Get user login history.
        
        Args:
            user_id: User ID
            limit: Maximum number of entries
            
        Returns:
            list: Login history
        """
        logs = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.action == 'login'
        ).order_by(
            AuditLog.created_at.desc()
        ).limit(limit).all()
        
        return [log.to_dict() for log in logs]