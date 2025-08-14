from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from models import db, NotificationHistory, Device
from sqlalchemy import and_, desc

notifications_bp = Blueprint('notifications', __name__)

@notifications_bp.route('/history', methods=['GET'])
def get_notification_history():
    """Get notification history with optional filtering"""
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)  # Max 100 per page
        device_id = request.args.get('device_id', type=int)
        notification_type = request.args.get('type')
        delivery_status = request.args.get('status')
        hours = request.args.get('hours', type=int, default=24)
        
        # Build query
        query = NotificationHistory.query
        
        # Filter by time range
        if hours:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            query = query.filter(NotificationHistory.sent_at >= cutoff)
        
        # Filter by device
        if device_id:
            query = query.filter(NotificationHistory.device_id == device_id)
        
        # Filter by notification type
        if notification_type:
            query = query.filter(NotificationHistory.notification_type == notification_type)
        
        # Filter by delivery status
        if delivery_status:
            query = query.filter(NotificationHistory.delivery_status == delivery_status)
        
        # Order by most recent first
        query = query.order_by(desc(NotificationHistory.sent_at))
        
        # Paginate
        pagination = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        notifications = [notification.to_dict() for notification in pagination.items]
        
        return jsonify({
            'notifications': notifications,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/stats', methods=['GET'])
def get_notification_stats():
    """Get notification statistics"""
    try:
        hours = request.args.get('hours', type=int, default=24)
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get all notifications in time range
        notifications = NotificationHistory.query.filter(
            NotificationHistory.sent_at >= cutoff
        ).all()
        
        stats = {
            'total_notifications': len(notifications),
            'by_type': {},
            'by_status': {'success': 0, 'failed': 0, 'unknown': 0},
            'by_priority': {'min': 0, 'low': 0, 'default': 0, 'high': 0, 'urgent': 0},
            'recent_notifications': [],
            'failure_rate': 0.0,
            'most_active_devices': []
        }
        
        # Count by type, status, and priority
        device_counts = {}
        for notification in notifications:
            # Count by type
            notification_type = notification.notification_type
            stats['by_type'][notification_type] = stats['by_type'].get(notification_type, 0) + 1
            
            # Count by status
            status = notification.delivery_status or 'unknown'
            stats['by_status'][status] = stats['by_status'].get(status, 0) + 1
            
            # Count by priority
            priority = notification.priority or 'default'
            stats['by_priority'][priority] = stats['by_priority'].get(priority, 0) + 1
            
            # Count by device
            if notification.device_id:
                device_name = notification.device.display_name if notification.device else f"Device {notification.device_id}"
                device_counts[device_name] = device_counts.get(device_name, 0) + 1
        
        # Calculate failure rate
        total_known_status = stats['by_status']['success'] + stats['by_status']['failed']
        if total_known_status > 0:
            stats['failure_rate'] = (stats['by_status']['failed'] / total_known_status) * 100
        
        # Get most active devices
        stats['most_active_devices'] = sorted(
            device_counts.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:5]
        
        # Get recent notifications (last 10)
        recent = NotificationHistory.query.filter(
            NotificationHistory.sent_at >= cutoff
        ).order_by(desc(NotificationHistory.sent_at)).limit(10).all()
        
        stats['recent_notifications'] = [notification.to_dict() for notification in recent]
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/types', methods=['GET'])
def get_notification_types():
    """Get available notification types"""
    try:
        types = db.session.query(NotificationHistory.notification_type.distinct()).all()
        type_list = [t[0] for t in types if t[0]]
        
        return jsonify({
            'types': sorted(type_list),
            'descriptions': {
                'device_down': 'Device went offline',
                'device_up': 'Device came back online',
                'new_device': 'New device discovered',
                'scan_complete': 'Network scan completed',
                'high_latency': 'High network latency detected',
                'anomaly': 'AI anomaly detected',
                'security': 'Security issue found',
                'test': 'Test notification',
                'general': 'General notification'
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/clear', methods=['DELETE'])
def clear_notification_history():
    """Clear old notification history"""
    try:
        days = request.args.get('days', type=int, default=30)
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        deleted_count = NotificationHistory.query.filter(
            NotificationHistory.sent_at < cutoff
        ).delete()
        
        db.session.commit()
        
        return jsonify({
            'message': f'Cleared {deleted_count} old notifications (older than {days} days)',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500