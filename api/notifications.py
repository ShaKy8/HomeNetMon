import hashlib
import logging
import secrets
import statistics
from collections import defaultdict
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request
from sqlalchemy import and_, desc, func

from api.rate_limited_endpoints import create_endpoint_limiter
from models import NotificationHistory, db

logger = logging.getLogger(__name__)

notifications_bp = Blueprint('notifications', __name__)

@notifications_bp.route('/history', methods=['GET'])
@create_endpoint_limiter('relaxed')
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


# Read Receipt Tracking Endpoints
