from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from models import db, NotificationHistory, Device, NotificationReceipt
from sqlalchemy import and_, desc, func
import statistics
from collections import defaultdict
import secrets
import hashlib
from api.rate_limited_endpoints import create_endpoint_limiter

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

@notifications_bp.route('/stats', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_notification_stats():
    """Get notification statistics"""
    try:
        hours = request.args.get('hours', type=int, default=24)
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get all notifications in time range with eager loading to prevent N+1 queries
        from sqlalchemy.orm import joinedload
        notifications = NotificationHistory.query.options(
            joinedload(NotificationHistory.device)
        ).filter(
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
@create_endpoint_limiter('relaxed')
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
@create_endpoint_limiter('critical')
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

@notifications_bp.route('/retry/<int:notification_id>', methods=['POST'])
@create_endpoint_limiter('strict')
def retry_notification(notification_id):
    """Retry a failed notification"""
    try:
        # Get the notification record
        notification = NotificationHistory.query.get_or_404(notification_id)
        
        # Only retry failed notifications
        if notification.delivery_status != 'failed':
            return jsonify({
                'success': False,
                'error': 'Can only retry failed notifications'
            }), 400
        
        # Import push notification service
        try:
            from services.push_notifications import PushNotificationService
            push_service = PushNotificationService()
            
            # Attempt to resend notification
            success = push_service.send_notification(
                title=notification.title,
                message=notification.message,
                priority=notification.priority,
                tags=notification.tags
            )
            
            if success:
                # Update notification status
                notification.delivery_status = 'success'
                notification.error_message = None
                notification.sent_at = datetime.utcnow()  # Update retry timestamp
                
                # Update corresponding alert if linked
                if notification.alert_id:
                    alert = Alert.query.get(notification.alert_id)
                    if alert:
                        alert.notification_status = 'sent'
                        alert.last_notification_at = datetime.utcnow()
                
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'message': 'Notification resent successfully',
                    'notification': notification.to_dict()
                })
            else:
                # Trigger escalation for repeated failure
                try:
                    from flask import current_app
                    escalation_service = current_app.escalation_service
                    
                    escalation_context = {
                        'triggered_by_type': 'notification',
                        'triggered_by_id': notification.id,
                        'notification_type': notification.notification_type,
                        'device_id': notification.device_id,
                        'device_type': notification.device.device_type if notification.device else None,
                        'failure_count': 2,  # Original failure + retry failure
                        'error_message': 'Retry failed'
                    }
                    
                    escalation_service.trigger_escalation('notification_failure', escalation_context)
                    
                except Exception as e:
                    logger.warning(f"Error triggering escalation for notification retry failure: {e}")
                
                return jsonify({
                    'success': False,
                    'error': 'Failed to resend notification'
                }), 500
                
        except ImportError:
            return jsonify({
                'success': False,
                'error': 'Push notification service not available'
            }), 503
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/alert/<int:alert_id>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_notifications_for_alert(alert_id):
    """Get all notifications sent for a specific alert"""
    try:
        # Verify alert exists
        from models import Alert
        alert = Alert.query.get_or_404(alert_id)
        
        # Get notifications for this alert
        notifications = NotificationHistory.query.filter_by(alert_id=alert_id)\
                                                 .order_by(NotificationHistory.sent_at.desc())\
                                                 .all()
        
        return jsonify({
            'alert_id': alert_id,
            'alert_message': alert.message,
            'notifications': [notification.to_dict() for notification in notifications],
            'total_count': len(notifications),
            'delivery_summary': {
                'success': len([n for n in notifications if n.delivery_status == 'success']),
                'failed': len([n for n in notifications if n.delivery_status == 'failed']),
                'unknown': len([n for n in notifications if n.delivery_status == 'unknown'])
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/send-test', methods=['POST'])
@create_endpoint_limiter('critical')
def send_test_notification():
    """Send a test notification"""
    try:
        # Import push notification service
        try:
            from services.push_notifications import PushNotificationService
            push_service = PushNotificationService()
            
            title = "Test Notification - HomeNetMon"
            message = "This is a test notification to verify the push notification system is working."
            
            success = push_service.send_notification(
                title=title,
                message=message,
                priority='default',
                tags='🧪'
            )
            
            # Log the test notification
            notification = NotificationHistory.log_notification(
                device_id=None,
                alert_id=None,
                notification_type='test',
                title=title,
                message=message,
                priority='default',
                tags='🧪',
                delivery_status='success' if success else 'failed',
                error_message=None if success else 'Test notification failed'
            )
            
            return jsonify({
                'success': success,
                'message': 'Test notification sent successfully' if success else 'Test notification failed',
                'notification_id': notification.id if notification else None
            })
            
        except ImportError:
            return jsonify({
                'success': False,
                'error': 'Push notification service not available'
            }), 503
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/failure-analysis', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_notification_failure_analysis():
    """Get detailed failure analysis for notifications"""
    try:
        hours = request.args.get('hours', type=int, default=24)
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get all failed notifications in time range
        failed_notifications = NotificationHistory.query.filter(
            NotificationHistory.sent_at >= cutoff,
            NotificationHistory.delivery_status == 'failed'
        ).all()
        
        # Analyze failure patterns
        analysis = {
            'total_failed': len(failed_notifications),
            'failure_by_type': {},
            'failure_by_device': {},
            'failure_by_hour': {},
            'common_errors': {},
            'failure_rate_trend': [],
            'recommendations': []
        }
        
        # Count failures by type
        for notification in failed_notifications:
            notification_type = notification.notification_type
            analysis['failure_by_type'][notification_type] = analysis['failure_by_type'].get(notification_type, 0) + 1
            
            # Count failures by device
            if notification.device_id:
                device_name = notification.device.display_name if notification.device else f"Device {notification.device_id}"
                analysis['failure_by_device'][device_name] = analysis['failure_by_device'].get(device_name, 0) + 1
            
            # Count failures by hour
            hour = notification.sent_at.hour
            analysis['failure_by_hour'][hour] = analysis['failure_by_hour'].get(hour, 0) + 1
            
            # Count common error messages
            if notification.error_message:
                error_key = notification.error_message[:100]  # First 100 chars
                analysis['common_errors'][error_key] = analysis['common_errors'].get(error_key, 0) + 1
        
        # Sort dictionaries by count (descending)
        analysis['failure_by_type'] = dict(sorted(analysis['failure_by_type'].items(), key=lambda x: x[1], reverse=True))
        analysis['failure_by_device'] = dict(sorted(analysis['failure_by_device'].items(), key=lambda x: x[1], reverse=True))
        analysis['common_errors'] = dict(sorted(analysis['common_errors'].items(), key=lambda x: x[1], reverse=True))
        
        # Generate failure rate trend (by 4-hour blocks)
        block_size = 4  # hours
        blocks = hours // block_size
        for i in range(blocks):
            block_start = cutoff + timedelta(hours=i * block_size)
            block_end = block_start + timedelta(hours=block_size)
            
            block_failed = NotificationHistory.query.filter(
                NotificationHistory.sent_at >= block_start,
                NotificationHistory.sent_at < block_end,
                NotificationHistory.delivery_status == 'failed'
            ).count()
            
            block_total = NotificationHistory.query.filter(
                NotificationHistory.sent_at >= block_start,
                NotificationHistory.sent_at < block_end
            ).count()
            
            failure_rate = (block_failed / block_total * 100) if block_total > 0 else 0
            
            analysis['failure_rate_trend'].append({
                'time_block': block_start.isoformat() + 'Z',
                'failed_count': block_failed,
                'total_count': block_total,
                'failure_rate': round(failure_rate, 1)
            })
        
        # Generate recommendations based on analysis
        if analysis['total_failed'] > 0:
            # High failure rate
            total_notifications = NotificationHistory.query.filter(
                NotificationHistory.sent_at >= cutoff
            ).count()
            failure_rate = (analysis['total_failed'] / total_notifications * 100) if total_notifications > 0 else 0
            
            if failure_rate > 20:
                analysis['recommendations'].append({
                    'type': 'critical',
                    'title': 'High Failure Rate',
                    'description': f'Notification failure rate is {failure_rate:.1f}%, which is above the recommended 5% threshold.',
                    'action': 'Check notification service configuration and network connectivity.'
                })
            
            # Most problematic type
            if analysis['failure_by_type']:
                top_failing_type = list(analysis['failure_by_type'].keys())[0]
                top_failing_count = analysis['failure_by_type'][top_failing_type]
                analysis['recommendations'].append({
                    'type': 'warning',
                    'title': 'Problematic Notification Type',
                    'description': f'"{top_failing_type}" notifications are failing most frequently ({top_failing_count} failures).',
                    'action': 'Review alert rules and notification templates for this type.'
                })
            
            # Most problematic device
            if analysis['failure_by_device']:
                top_failing_device = list(analysis['failure_by_device'].keys())[0]
                top_failing_device_count = analysis['failure_by_device'][top_failing_device]
                analysis['recommendations'].append({
                    'type': 'info',
                    'title': 'Device with Most Failures',
                    'description': f'Device "{top_failing_device}" has the most notification failures ({top_failing_device_count}).',
                    'action': 'Check if this device requires special handling or has connectivity issues.'
                })
        else:
            analysis['recommendations'].append({
                'type': 'success',
                'title': 'No Recent Failures',
                'description': 'All notifications in the selected time range were delivered successfully.',
                'action': 'No action required. Continue monitoring.'
            })
        
        return jsonify(analysis)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/analytics/trends', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_notification_trends():
    """Get detailed notification trends analysis"""
    try:
        hours = request.args.get('hours', type=int, default=168)  # Default to 1 week
        granularity = request.args.get('granularity', default='hour')  # hour, day, week
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Determine time bucket size based on granularity
        if granularity == 'hour':
            bucket_size = 1
            date_format = '%Y-%m-%d %H:00'
        elif granularity == 'day':
            bucket_size = 24
            date_format = '%Y-%m-%d'
        else:  # week
            bucket_size = 168
            date_format = '%Y-W%U'
        
        # Get all notifications in time range
        notifications = NotificationHistory.query.filter(
            NotificationHistory.sent_at >= cutoff
        ).order_by(NotificationHistory.sent_at).all()
        
        # Initialize buckets
        buckets = defaultdict(lambda: {
            'total': 0,
            'success': 0,
            'failed': 0,
            'by_type': defaultdict(int),
            'by_priority': defaultdict(int),
            'by_device': defaultdict(int),
            'response_times': []
        })
        
        # Process notifications into time buckets
        for notification in notifications:
            if granularity == 'hour':
                bucket_key = notification.sent_at.strftime('%Y-%m-%d %H:00')
            elif granularity == 'day':
                bucket_key = notification.sent_at.strftime('%Y-%m-%d')
            else:  # week
                bucket_key = notification.sent_at.strftime('%Y-W%U')
            
            bucket = buckets[bucket_key]
            bucket['total'] += 1
            
            # Count by status
            if notification.delivery_status == 'success':
                bucket['success'] += 1
            elif notification.delivery_status == 'failed':
                bucket['failed'] += 1
            
            # Count by type and priority
            bucket['by_type'][notification.notification_type] += 1
            bucket['by_priority'][notification.priority or 'default'] += 1
            
            # Count by device
            if notification.device:
                bucket['by_device'][notification.device.display_name] += 1
        
        # Convert to list format with calculated metrics
        trend_data = []
        for bucket_key in sorted(buckets.keys()):
            bucket = buckets[bucket_key]
            success_rate = (bucket['success'] / bucket['total'] * 100) if bucket['total'] > 0 else 0
            
            trend_data.append({
                'time_bucket': bucket_key,
                'total_notifications': bucket['total'],
                'success_count': bucket['success'],
                'failed_count': bucket['failed'],
                'success_rate': round(success_rate, 2),
                'top_types': dict(sorted(bucket['by_type'].items(), key=lambda x: x[1], reverse=True)[:5]),
                'priority_breakdown': dict(bucket['by_priority']),
                'top_devices': dict(sorted(bucket['by_device'].items(), key=lambda x: x[1], reverse=True)[:3])
            })
        
        # Calculate overall trends
        if len(trend_data) >= 2:
            recent_avg = statistics.mean([d['success_rate'] for d in trend_data[-3:]])
            earlier_avg = statistics.mean([d['success_rate'] for d in trend_data[:3]])
            trend_direction = 'improving' if recent_avg > earlier_avg else 'declining' if recent_avg < earlier_avg else 'stable'
        else:
            trend_direction = 'insufficient_data'
        
        return jsonify({
            'time_range_hours': hours,
            'granularity': granularity,
            'trend_direction': trend_direction,
            'data_points': len(trend_data),
            'trends': trend_data,
            'summary': {
                'total_notifications': sum(d['total_notifications'] for d in trend_data),
                'overall_success_rate': round(
                    statistics.mean([d['success_rate'] for d in trend_data if d['total_notifications'] > 0]) 
                    if any(d['total_notifications'] > 0 for d in trend_data) else 0, 2
                ),
                'peak_hour': max(trend_data, key=lambda x: x['total_notifications'])['time_bucket'] if trend_data else None
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/analytics/performance', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_notification_performance():
    """Get delivery performance metrics"""
    try:
        hours = request.args.get('hours', type=int, default=24)
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get notifications with timing data
        notifications = NotificationHistory.query.filter(
            NotificationHistory.sent_at >= cutoff
        ).all()
        
        if not notifications:
            return jsonify({
                'error': 'No notifications found in time range',
                'time_range_hours': hours
            }), 404
        
        # Analyze performance by type
        performance_by_type = defaultdict(lambda: {
            'total': 0,
            'success': 0,
            'failed': 0,
            'retry_count': 0,
            'avg_delivery_time': 0
        })
        
        # Analyze performance by priority
        performance_by_priority = defaultdict(lambda: {
            'total': 0,
            'success': 0,
            'failed': 0
        })
        
        retry_patterns = defaultdict(int)
        hourly_performance = defaultdict(lambda: {'total': 0, 'success': 0})
        
        for notification in notifications:
            notification_type = notification.notification_type
            priority = notification.priority or 'default'
            hour = notification.sent_at.hour
            
            # Performance by type
            perf_type = performance_by_type[notification_type]
            perf_type['total'] += 1
            if notification.delivery_status == 'success':
                perf_type['success'] += 1
            elif notification.delivery_status == 'failed':
                perf_type['failed'] += 1
            
            # Performance by priority
            perf_priority = performance_by_priority[priority]
            perf_priority['total'] += 1
            if notification.delivery_status == 'success':
                perf_priority['success'] += 1
            elif notification.delivery_status == 'failed':
                perf_priority['failed'] += 1
            
            # Hourly performance
            hourly_perf = hourly_performance[hour]
            hourly_perf['total'] += 1
            if notification.delivery_status == 'success':
                hourly_perf['success'] += 1
        
        # Calculate success rates
        for perf in performance_by_type.values():
            perf['success_rate'] = (perf['success'] / perf['total'] * 100) if perf['total'] > 0 else 0
        
        for perf in performance_by_priority.values():
            perf['success_rate'] = (perf['success'] / perf['total'] * 100) if perf['total'] > 0 else 0
        
        # Calculate hourly success rates
        hourly_rates = {}
        for hour, perf in hourly_performance.items():
            hourly_rates[f"{hour:02d}:00"] = (perf['success'] / perf['total'] * 100) if perf['total'] > 0 else 0
        
        # Find best and worst performing metrics
        best_type = max(performance_by_type.items(), key=lambda x: x[1]['success_rate']) if performance_by_type else None
        worst_type = min(performance_by_type.items(), key=lambda x: x[1]['success_rate']) if performance_by_type else None
        
        best_hour = max(hourly_rates.items(), key=lambda x: x[1]) if hourly_rates else None
        worst_hour = min(hourly_rates.items(), key=lambda x: x[1]) if hourly_rates else None
        
        return jsonify({
            'time_range_hours': hours,
            'total_notifications': len(notifications),
            'performance_by_type': dict(performance_by_type),
            'performance_by_priority': dict(performance_by_priority),
            'hourly_performance': hourly_rates,
            'insights': {
                'best_performing_type': best_type[0] if best_type else None,
                'best_type_success_rate': round(best_type[1]['success_rate'], 2) if best_type else None,
                'worst_performing_type': worst_type[0] if worst_type else None,
                'worst_type_success_rate': round(worst_type[1]['success_rate'], 2) if worst_type else None,
                'best_hour': best_hour[0] if best_hour else None,
                'best_hour_success_rate': round(best_hour[1], 2) if best_hour else None,
                'worst_hour': worst_hour[0] if worst_hour else None,
                'worst_hour_success_rate': round(worst_hour[1], 2) if worst_hour else None
            },
            'recommendations': generate_performance_recommendations(performance_by_type, hourly_rates)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/analytics/predictions', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_notification_predictions():
    """Get predictive analytics and forecasting"""
    try:
        # Get historical data for analysis (last 30 days)
        cutoff = datetime.utcnow() - timedelta(days=30)
        notifications = NotificationHistory.query.filter(
            NotificationHistory.sent_at >= cutoff
        ).all()
        
        if len(notifications) < 50:  # Need minimum data for predictions
            return jsonify({
                'error': 'Insufficient historical data for predictions',
                'minimum_required': 50,
                'current_count': len(notifications)
            }), 422
        
        # Analyze patterns by day of week and hour
        patterns = {
            'hourly': defaultdict(int),
            'daily': defaultdict(int),
            'failure_patterns': defaultdict(int)
        }
        
        failure_sequences = []
        
        for notification in notifications:
            hour = notification.sent_at.hour
            day = notification.sent_at.strftime('%A')
            
            patterns['hourly'][hour] += 1
            patterns['daily'][day] += 1
            
            if notification.delivery_status == 'failed':
                patterns['failure_patterns'][notification.notification_type] += 1
                failure_sequences.append(notification.sent_at)
        
        # Predict next 24 hours volume
        current_hour = datetime.utcnow().hour
        predicted_volume = []
        
        for i in range(24):
            hour = (current_hour + i) % 24
            avg_for_hour = patterns['hourly'].get(hour, 0) / 30  # Average per day for this hour
            predicted_volume.append({
                'hour': f"{hour:02d}:00",
                'predicted_count': round(avg_for_hour),
                'confidence': 'high' if patterns['hourly'][hour] > 10 else 'medium' if patterns['hourly'][hour] > 3 else 'low'
            })
        
        # Identify risk periods (hours with high failure rates)
        risk_hours = []
        for hour, count in patterns['hourly'].items():
            if count > 0:
                failures_this_hour = sum(1 for n in notifications 
                                       if n.sent_at.hour == hour and n.delivery_status == 'failed')
                failure_rate = failures_this_hour / count * 100
                if failure_rate > 15:  # More than 15% failure rate
                    risk_hours.append({
                        'hour': f"{hour:02d}:00",
                        'failure_rate': round(failure_rate, 2),
                        'total_count': count
                    })
        
        # Capacity planning recommendations
        max_hourly = max(patterns['hourly'].values()) if patterns['hourly'] else 0
        avg_hourly = statistics.mean(patterns['hourly'].values()) if patterns['hourly'] else 0
        
        capacity_recommendations = []
        if max_hourly > avg_hourly * 3:
            capacity_recommendations.append({
                'type': 'peak_handling',
                'description': f'Peak hour volume ({max_hourly}) is {max_hourly/avg_hourly:.1f}x average. Consider rate limiting or queuing.',
                'priority': 'medium'
            })
        
        if len(risk_hours) > 3:
            capacity_recommendations.append({
                'type': 'reliability',
                'description': f'{len(risk_hours)} hours show high failure rates. Review notification service stability.',
                'priority': 'high'
            })
        
        return jsonify({
            'analysis_period_days': 30,
            'total_notifications_analyzed': len(notifications),
            'predicted_24h_volume': predicted_volume,
            'seasonal_patterns': {
                'peak_hour': max(patterns['hourly'].items(), key=lambda x: x[1])[0] if patterns['hourly'] else None,
                'quietest_hour': min(patterns['hourly'].items(), key=lambda x: x[1])[0] if patterns['hourly'] else None,
                'busiest_day': max(patterns['daily'].items(), key=lambda x: x[1])[0] if patterns['daily'] else None,
                'daily_distribution': dict(patterns['daily'])
            },
            'risk_analysis': {
                'high_risk_hours': risk_hours,
                'failure_prone_types': dict(sorted(patterns['failure_patterns'].items(), key=lambda x: x[1], reverse=True)[:5])
            },
            'capacity_planning': {
                'max_hourly_volume': max_hourly,
                'average_hourly_volume': round(avg_hourly, 2),
                'recommendations': capacity_recommendations
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_performance_recommendations(performance_by_type, hourly_rates):
    """Generate performance improvement recommendations"""
    recommendations = []
    
    # Check for types with low success rates
    for notification_type, perf in performance_by_type.items():
        if perf['success_rate'] < 90 and perf['total'] > 5:
            recommendations.append({
                'type': 'performance',
                'severity': 'high' if perf['success_rate'] < 70 else 'medium',
                'title': f'Low Success Rate for {notification_type}',
                'description': f'{notification_type} notifications have {perf["success_rate"]:.1f}% success rate',
                'action': 'Review notification templates and delivery configuration for this type'
            })
    
    # Check for poor performing hours
    poor_hours = [(hour, rate) for hour, rate in hourly_rates.items() if rate < 85]
    if poor_hours:
        recommendations.append({
            'type': 'timing',
            'severity': 'medium',
            'title': 'Poor Performance During Specific Hours',
            'description': f'{len(poor_hours)} hours show sub-optimal delivery rates',
            'action': 'Consider adjusting notification timing or implementing retry delays'
        })
    
    return recommendations

# Read Receipt Tracking Endpoints
@notifications_bp.route('/receipt/generate', methods=['POST'])
@create_endpoint_limiter('strict')
def generate_read_receipt_token():
    """Generate a unique tracking token for read receipt tracking"""
    try:
        data = request.get_json()
        notification_id = data.get('notification_id')
        
        if not notification_id:
            return jsonify({'error': 'notification_id is required'}), 400
        
        # Verify notification exists
        notification = NotificationHistory.query.get_or_404(notification_id)
        
        # Generate unique tracking token
        tracking_token = secrets.token_urlsafe(32)
        
        # Create receipt record
        receipt = NotificationReceipt(
            notification_id=notification_id,
            tracking_token=tracking_token,
            interaction_type='generated',
            created_at=datetime.utcnow(),
            user_agent=request.headers.get('User-Agent'),
            ip_address=_anonymize_ip(request.remote_addr),
            privacy_compliant=True
        )
        
        db.session.add(receipt)
        db.session.commit()
        
        return jsonify({
            'tracking_token': tracking_token,
            'notification_id': notification_id,
            'expires_at': (datetime.utcnow() + timedelta(days=30)).isoformat() + 'Z'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/receipt/track', methods=['POST'])
@create_endpoint_limiter('strict')
def track_read_receipt():
    """Track a read receipt interaction"""
    try:
        data = request.get_json()
        tracking_token = data.get('tracking_token')
        interaction_type = data.get('interaction_type', 'opened')
        metadata = data.get('metadata', {})
        
        if not tracking_token:
            return jsonify({'error': 'tracking_token is required'}), 400
        
        if interaction_type not in ['opened', 'clicked', 'dismissed', 'delivered']:
            return jsonify({'error': 'Invalid interaction_type'}), 400
        
        # Find existing receipt by token
        receipt = NotificationReceipt.query.filter_by(tracking_token=tracking_token).first()
        if not receipt:
            return jsonify({'error': 'Invalid tracking token'}), 404
        
        # Update receipt with interaction
        receipt.interaction_type = interaction_type
        receipt.interaction_timestamp = datetime.utcnow()
        receipt.metadata = metadata
        receipt.user_agent = request.headers.get('User-Agent')
        receipt.ip_address = _anonymize_ip(request.remote_addr)
        
        # Update notification engagement metrics
        notification = receipt.notification
        if interaction_type == 'opened':
            notification.read_count = (notification.read_count or 0) + 1
            if not notification.first_read_at:
                notification.first_read_at = datetime.utcnow()
            notification.last_read_at = datetime.utcnow()
        elif interaction_type == 'clicked':
            notification.click_count = (notification.click_count or 0) + 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'interaction_type': interaction_type,
            'timestamp': receipt.interaction_timestamp.isoformat() + 'Z'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/receipt/pixel/<tracking_token>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def read_receipt_pixel(tracking_token):
    """Tracking pixel endpoint for email-based read receipts"""
    try:
        # Find receipt by token
        receipt = NotificationReceipt.query.filter_by(tracking_token=tracking_token).first()
        if receipt and not receipt.interaction_timestamp:
            # Update receipt with 'opened' interaction
            receipt.interaction_type = 'opened'
            receipt.interaction_timestamp = datetime.utcnow()
            receipt.user_agent = request.headers.get('User-Agent')
            receipt.ip_address = _anonymize_ip(request.remote_addr)
            
            # Update notification read metrics
            notification = receipt.notification
            notification.read_count = (notification.read_count or 0) + 1
            if not notification.first_read_at:
                notification.first_read_at = datetime.utcnow()
            notification.last_read_at = datetime.utcnow()
            
            db.session.commit()
        
        # Return 1x1 transparent pixel
        from flask import Response
        pixel_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xdb\x00\x00\x00\x00IEND\xaeB`\x82'
        
        response = Response(pixel_data, mimetype='image/png')
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
        
    except Exception as e:
        # Return pixel even on error to avoid breaking email display
        from flask import Response
        pixel_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xdb\x00\x00\x00\x00IEND\xaeB`\x82'
        return Response(pixel_data, mimetype='image/png')

@notifications_bp.route('/receipt/analytics', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_read_receipt_analytics():
    """Get read receipt analytics and engagement metrics"""
    try:
        hours = request.args.get('hours', type=int, default=24)
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get notifications with read receipt data
        notifications_with_receipts = db.session.query(NotificationHistory)\
            .join(NotificationReceipt, NotificationHistory.id == NotificationReceipt.notification_id)\
            .filter(NotificationHistory.sent_at >= cutoff)\
            .all()
        
        total_notifications = NotificationHistory.query.filter(
            NotificationHistory.sent_at >= cutoff
        ).count()
        
        analytics = {
            'time_range_hours': hours,
            'total_notifications': total_notifications,
            'notifications_with_tracking': len(notifications_with_receipts),
            'tracking_coverage': (len(notifications_with_receipts) / total_notifications * 100) if total_notifications > 0 else 0,
            'engagement_metrics': {
                'total_opens': 0,
                'total_clicks': 0,
                'unique_readers': 0,
                'avg_read_time': 0
            },
            'interaction_breakdown': {
                'opened': 0,
                'clicked': 0,
                'dismissed': 0,
                'delivered': 0
            },
            'top_performing_types': {},
            'engagement_timeline': []
        }
        
        # Calculate engagement metrics
        total_read_time = 0
        unique_readers = set()
        type_engagement = defaultdict(lambda: {'sent': 0, 'opened': 0, 'clicked': 0})
        
        for notification in notifications_with_receipts:
            # Count engagement
            if notification.read_count:
                analytics['engagement_metrics']['total_opens'] += notification.read_count
                unique_readers.add(notification.id)
            
            if notification.click_count:
                analytics['engagement_metrics']['total_clicks'] += notification.click_count
            
            if notification.total_read_time_seconds:
                total_read_time += notification.total_read_time_seconds
            
            # Count by type
            type_stats = type_engagement[notification.notification_type]
            type_stats['sent'] += 1
            if notification.read_count and notification.read_count > 0:
                type_stats['opened'] += 1
            if notification.click_count and notification.click_count > 0:
                type_stats['clicked'] += 1
        
        analytics['engagement_metrics']['unique_readers'] = len(unique_readers)
        analytics['engagement_metrics']['avg_read_time'] = (total_read_time / len(unique_readers)) if unique_readers else 0
        
        # Get interaction breakdown from receipts
        receipt_interactions = db.session.query(NotificationReceipt.interaction_type, func.count(NotificationReceipt.id))\
            .join(NotificationHistory, NotificationReceipt.notification_id == NotificationHistory.id)\
            .filter(NotificationHistory.sent_at >= cutoff)\
            .filter(NotificationReceipt.interaction_timestamp.isnot(None))\
            .group_by(NotificationReceipt.interaction_type)\
            .all()
        
        for interaction_type, count in receipt_interactions:
            analytics['interaction_breakdown'][interaction_type] = count
        
        # Calculate engagement rates by type
        for notification_type, stats in type_engagement.items():
            if stats['sent'] > 0:
                analytics['top_performing_types'][notification_type] = {
                    'sent': stats['sent'],
                    'open_rate': (stats['opened'] / stats['sent'] * 100),
                    'click_rate': (stats['clicked'] / stats['sent'] * 100)
                }
        
        # Sort by open rate
        analytics['top_performing_types'] = dict(sorted(
            analytics['top_performing_types'].items(),
            key=lambda x: x[1]['open_rate'],
            reverse=True
        ))
        
        return jsonify(analytics)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/receipt/notification/<int:notification_id>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_notification_receipts(notification_id):
    """Get all read receipts for a specific notification"""
    try:
        # Verify notification exists
        notification = NotificationHistory.query.get_or_404(notification_id)
        
        # Get all receipts for this notification
        receipts = NotificationReceipt.query.filter_by(notification_id=notification_id)\
                                           .order_by(NotificationReceipt.created_at.desc())\
                                           .all()
        
        receipt_data = []
        for receipt in receipts:
            receipt_data.append({
                'id': receipt.id,
                'tracking_token': receipt.tracking_token[:8] + '...' if receipt.tracking_token else None,  # Partial token for security
                'interaction_type': receipt.interaction_type,
                'created_at': receipt.created_at.isoformat() + 'Z',
                'interaction_timestamp': receipt.interaction_timestamp.isoformat() + 'Z' if receipt.interaction_timestamp else None,
                'anonymized_ip': receipt.ip_address,
                'user_agent': receipt.user_agent,
                'metadata': receipt.metadata,
                'privacy_compliant': receipt.privacy_compliant
            })
        
        return jsonify({
            'notification_id': notification_id,
            'notification_title': notification.title,
            'notification_sent_at': notification.sent_at.isoformat() + 'Z',
            'receipts': receipt_data,
            'engagement_summary': {
                'total_receipts': len(receipts),
                'read_count': notification.read_count or 0,
                'click_count': notification.click_count or 0,
                'first_read_at': notification.first_read_at.isoformat() + 'Z' if notification.first_read_at else None,
                'last_read_at': notification.last_read_at.isoformat() + 'Z' if notification.last_read_at else None,
                'total_read_time_seconds': notification.total_read_time_seconds or 0,
                'unique_readers': notification.unique_readers or 0
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def _anonymize_ip(ip_address):
    """Anonymize IP address for privacy compliance"""
    if not ip_address:
        return None
    
    try:
        # Simple anonymization: hash the IP with a salt
        salt = "homeNetMon_privacy_salt"
        hashed = hashlib.sha256((ip_address + salt).encode()).hexdigest()
        return hashed[:16]  # Return first 16 chars of hash
    except:
        return "anonymous"

@notifications_bp.route('/alert/<int:alert_id>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_alert_notification_status(alert_id):
    """Get notification status and history for a specific alert"""
    try:
        # Import Alert model to avoid circular imports
        from models import Alert
        
        # Verify alert exists
        alert = Alert.query.get_or_404(alert_id)
        
        # Get notification history for this alert
        notification_history = NotificationHistory.query.filter_by(alert_id=alert_id)\
                                                        .order_by(NotificationHistory.sent_at.desc())\
                                                        .all()
        
        # Calculate summary statistics
        total_notifications = len(notification_history)
        successful_notifications = sum(1 for n in notification_history if n.delivery_status == 'success')
        failed_notifications = sum(1 for n in notification_history if n.delivery_status == 'failed')
        pending_notifications = sum(1 for n in notification_history if n.delivery_status == 'pending')
        
        # Get delivery methods used
        delivery_methods = list(set(n.notification_type for n in notification_history))
        
        # Get latest notification attempt
        latest_notification = notification_history[0] if notification_history else None
        
        # Calculate retry information
        retry_count = len([n for n in notification_history if 'retry' in (n.notification_metadata or '')])
        
        return jsonify({
            'alert_id': alert_id,
            'alert_type': alert.alert_type,
            'alert_severity': alert.severity,
            'alert_created_at': alert.created_at.isoformat() + 'Z',
            'notification_status': alert.notification_status,
            'notification_count': alert.notification_count,
            'last_notification_at': alert.last_notification_at.isoformat() + 'Z' if alert.last_notification_at else None,
            'summary': {
                'total_notifications': total_notifications,
                'successful_notifications': successful_notifications,
                'failed_notifications': failed_notifications,
                'pending_notifications': pending_notifications,
                'success_rate': (successful_notifications / total_notifications * 100) if total_notifications > 0 else 0,
                'retry_count': retry_count,
                'delivery_methods': delivery_methods
            },
            'latest_notification': {
                'id': latest_notification.id,
                'notification_type': latest_notification.notification_type,
                'title': latest_notification.title,
                'message': latest_notification.message,
                'delivery_status': latest_notification.delivery_status,
                'sent_at': latest_notification.sent_at.isoformat() + 'Z',
                'error_message': latest_notification.error_message
            } if latest_notification else None,
            'notification_history': [n.to_dict() for n in notification_history],
            'can_retry': failed_notifications > 0 and alert.resolved == False
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500