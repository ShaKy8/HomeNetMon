"""
Read Receipt Tracking Service

Provides high-level interface for managing read receipt tracking,
engagement analytics, and privacy-compliant user interaction monitoring.
"""

from datetime import datetime, timedelta
from models import db, NotificationHistory, NotificationReceipt
from sqlalchemy import and_, desc, func
import secrets
import hashlib
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

class ReadReceiptService:
    """Service for managing notification read receipts and engagement tracking"""
    
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize service with Flask app"""
        self.app = app
        
        # Configure privacy settings
        self.privacy_salt = app.config.get('READ_RECEIPT_PRIVACY_SALT', 'homeNetMon_default_salt')
        self.tracking_enabled = app.config.get('READ_RECEIPT_TRACKING_ENABLED', True)
        self.retention_days = app.config.get('READ_RECEIPT_RETENTION_DAYS', 365)
        self.anonymize_ips = app.config.get('READ_RECEIPT_ANONYMIZE_IPS', True)
    
    def generate_tracking_token(self, notification_id, metadata=None):
        """
        Generate a unique tracking token for a notification
        
        Args:
            notification_id: ID of the notification to track
            metadata: Optional metadata to store with the receipt
            
        Returns:
            dict: Contains tracking_token and expiration info
        """
        try:
            if not self.tracking_enabled:
                logger.info("Read receipt tracking is disabled")
                return None
            
            # Verify notification exists
            notification = NotificationHistory.query.get(notification_id)
            if not notification:
                raise ValueError(f"Notification {notification_id} not found")
            
            # Generate secure token
            tracking_token = secrets.token_urlsafe(32)
            
            # Create receipt record
            receipt = NotificationReceipt(
                notification_id=notification_id,
                tracking_token=tracking_token,
                interaction_type='generated',
                created_at=datetime.utcnow(),
                metadata=metadata or {},
                privacy_compliant=True
            )
            
            db.session.add(receipt)
            db.session.commit()
            
            logger.info(f"Generated tracking token for notification {notification_id}")
            
            return {
                'tracking_token': tracking_token,
                'notification_id': notification_id,
                'expires_at': datetime.utcnow() + timedelta(days=self.retention_days)
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error generating tracking token: {e}")
            raise
    
    def track_interaction(self, tracking_token, interaction_type, user_agent=None, ip_address=None, metadata=None):
        """
        Track a user interaction with a notification
        
        Args:
            tracking_token: Unique token identifying the receipt
            interaction_type: Type of interaction (opened, clicked, dismissed, delivered)
            user_agent: Browser user agent string
            ip_address: User's IP address (will be anonymized if enabled)
            metadata: Additional interaction metadata
            
        Returns:
            dict: Result of tracking operation
        """
        try:
            if not self.tracking_enabled:
                return {'success': False, 'reason': 'tracking_disabled'}
            
            if interaction_type not in ['opened', 'clicked', 'dismissed', 'delivered']:
                raise ValueError(f"Invalid interaction type: {interaction_type}")
            
            # Find receipt by token
            receipt = NotificationReceipt.query.filter_by(tracking_token=tracking_token).first()
            if not receipt:
                return {'success': False, 'reason': 'invalid_token'}
            
            # Check if receipt is expired
            if receipt.created_at < datetime.utcnow() - timedelta(days=self.retention_days):
                return {'success': False, 'reason': 'token_expired'}
            
            # Update receipt
            receipt.interaction_type = interaction_type
            receipt.interaction_timestamp = datetime.utcnow()
            receipt.user_agent = user_agent
            receipt.ip_address = self._anonymize_ip(ip_address) if self.anonymize_ips else ip_address
            receipt.metadata = {**(receipt.metadata or {}), **(metadata or {})}
            
            # Update notification engagement metrics
            notification = receipt.notification
            if interaction_type == 'opened':
                notification.read_count = (notification.read_count or 0) + 1
                if not notification.first_read_at:
                    notification.first_read_at = datetime.utcnow()
                notification.last_read_at = datetime.utcnow()
                
                # Update unique readers count
                existing_opened = NotificationReceipt.query.filter(
                    NotificationReceipt.notification_id == notification.id,
                    NotificationReceipt.interaction_type == 'opened',
                    NotificationReceipt.ip_address == receipt.ip_address
                ).count()
                
                if existing_opened == 1:  # First time this IP opened it
                    notification.unique_readers = (notification.unique_readers or 0) + 1
                    
            elif interaction_type == 'clicked':
                notification.click_count = (notification.click_count or 0) + 1
            
            db.session.commit()
            
            logger.info(f"Tracked {interaction_type} interaction for notification {notification.id}")
            
            return {
                'success': True,
                'interaction_type': interaction_type,
                'timestamp': receipt.interaction_timestamp,
                'notification_id': notification.id
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error tracking interaction: {e}")
            raise
    
    def get_notification_engagement(self, notification_id):
        """
        Get engagement metrics for a specific notification
        
        Args:
            notification_id: ID of the notification
            
        Returns:
            dict: Engagement metrics and receipt data
        """
        try:
            notification = NotificationHistory.query.get(notification_id)
            if not notification:
                raise ValueError(f"Notification {notification_id} not found")
            
            receipts = NotificationReceipt.query.filter_by(notification_id=notification_id)\
                                               .order_by(NotificationReceipt.created_at.desc())\
                                               .all()
            
            # Calculate engagement metrics
            interactions = defaultdict(int)
            unique_ips = set()
            
            for receipt in receipts:
                if receipt.interaction_timestamp:
                    interactions[receipt.interaction_type] += 1
                    if receipt.ip_address:
                        unique_ips.add(receipt.ip_address)
            
            return {
                'notification_id': notification_id,
                'notification_title': notification.title,
                'sent_at': notification.sent_at,
                'engagement_metrics': {
                    'total_receipts': len(receipts),
                    'read_count': notification.read_count or 0,
                    'click_count': notification.click_count or 0,
                    'unique_readers': len(unique_ips),
                    'first_read_at': notification.first_read_at,
                    'last_read_at': notification.last_read_at,
                    'total_read_time_seconds': notification.total_read_time_seconds or 0
                },
                'interaction_breakdown': dict(interactions),
                'receipts': [{
                    'id': r.id,
                    'interaction_type': r.interaction_type,
                    'created_at': r.created_at,
                    'interaction_timestamp': r.interaction_timestamp,
                    'metadata': r.metadata,
                    'privacy_compliant': r.privacy_compliant
                } for r in receipts]
            }
            
        except Exception as e:
            logger.error(f"Error getting notification engagement: {e}")
            raise
    
    def get_engagement_analytics(self, hours=24):
        """
        Get comprehensive engagement analytics for a time period
        
        Args:
            hours: Number of hours to analyze
            
        Returns:
            dict: Detailed engagement analytics
        """
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            
            # Get notifications with tracking data
            notifications_with_receipts = db.session.query(NotificationHistory)\
                .join(NotificationReceipt, NotificationHistory.id == NotificationReceipt.notification_id)\
                .filter(NotificationHistory.sent_at >= cutoff)\
                .all()
            
            total_notifications = NotificationHistory.query.filter(
                NotificationHistory.sent_at >= cutoff
            ).count()
            
            # Calculate metrics
            analytics = {
                'time_range_hours': hours,
                'total_notifications': total_notifications,
                'notifications_with_tracking': len(notifications_with_receipts),
                'tracking_coverage_percent': (len(notifications_with_receipts) / total_notifications * 100) if total_notifications > 0 else 0,
                'engagement_metrics': {
                    'total_opens': 0,
                    'total_clicks': 0,
                    'unique_readers': 0,
                    'avg_read_time_seconds': 0,
                    'open_rate_percent': 0,
                    'click_rate_percent': 0
                },
                'interaction_breakdown': defaultdict(int),
                'type_performance': {},
                'hourly_engagement': defaultdict(lambda: {'opens': 0, 'clicks': 0})
            }
            
            # Process notifications
            total_read_time = 0
            unique_readers = set()
            type_stats = defaultdict(lambda: {'sent': 0, 'opened': 0, 'clicked': 0})
            
            for notification in notifications_with_receipts:
                # Update totals
                if notification.read_count:
                    analytics['engagement_metrics']['total_opens'] += notification.read_count
                if notification.click_count:
                    analytics['engagement_metrics']['total_clicks'] += notification.click_count
                if notification.total_read_time_seconds:
                    total_read_time += notification.total_read_time_seconds
                if notification.unique_readers:
                    unique_readers.add(notification.id)
                
                # Track by type
                type_key = notification.notification_type
                type_stats[type_key]['sent'] += 1
                if notification.read_count and notification.read_count > 0:
                    type_stats[type_key]['opened'] += 1
                if notification.click_count and notification.click_count > 0:
                    type_stats[type_key]['clicked'] += 1
                
                # Track by hour
                hour = notification.sent_at.hour
                if notification.read_count:
                    analytics['hourly_engagement'][hour]['opens'] += notification.read_count
                if notification.click_count:
                    analytics['hourly_engagement'][hour]['clicks'] += notification.click_count
            
            # Calculate final metrics
            analytics['engagement_metrics']['unique_readers'] = len(unique_readers)
            analytics['engagement_metrics']['avg_read_time_seconds'] = (
                total_read_time / len(unique_readers) if unique_readers else 0
            )
            
            if len(notifications_with_receipts) > 0:
                analytics['engagement_metrics']['open_rate_percent'] = (
                    analytics['engagement_metrics']['total_opens'] / len(notifications_with_receipts) * 100
                )
                analytics['engagement_metrics']['click_rate_percent'] = (
                    analytics['engagement_metrics']['total_clicks'] / len(notifications_with_receipts) * 100
                )
            
            # Calculate type performance
            for notification_type, stats in type_stats.items():
                if stats['sent'] > 0:
                    analytics['type_performance'][notification_type] = {
                        'sent': stats['sent'],
                        'open_rate_percent': (stats['opened'] / stats['sent'] * 100),
                        'click_rate_percent': (stats['clicked'] / stats['sent'] * 100),
                        'engagement_score': (stats['opened'] + stats['clicked'] * 2) / stats['sent']
                    }
            
            # Get interaction breakdown from receipts
            receipt_interactions = db.session.query(
                NotificationReceipt.interaction_type, 
                func.count(NotificationReceipt.id)
            ).join(
                NotificationHistory, 
                NotificationReceipt.notification_id == NotificationHistory.id
            ).filter(
                NotificationHistory.sent_at >= cutoff,
                NotificationReceipt.interaction_timestamp.isnot(None)
            ).group_by(NotificationReceipt.interaction_type).all()
            
            for interaction_type, count in receipt_interactions:
                analytics['interaction_breakdown'][interaction_type] = count
            
            return analytics
            
        except Exception as e:
            logger.error(f"Error getting engagement analytics: {e}")
            raise
    
    def cleanup_old_receipts(self, days=None):
        """
        Clean up old read receipt records for privacy compliance
        
        Args:
            days: Number of days to retain (uses configured retention if None)
            
        Returns:
            int: Number of records cleaned up
        """
        try:
            retention_days = days or self.retention_days
            cutoff = datetime.utcnow() - timedelta(days=retention_days)
            
            deleted_count = NotificationReceipt.query.filter(
                NotificationReceipt.created_at < cutoff
            ).delete()
            
            db.session.commit()
            
            logger.info(f"Cleaned up {deleted_count} old read receipt records")
            return deleted_count
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error cleaning up old receipts: {e}")
            raise
    
    def generate_tracking_pixel_url(self, tracking_token, base_url):
        """
        Generate URL for tracking pixel
        
        Args:
            tracking_token: Token to track
            base_url: Base URL of the application
            
        Returns:
            str: Complete tracking pixel URL
        """
        return f"{base_url}/api/notifications/receipt/pixel/{tracking_token}"
    
    def _anonymize_ip(self, ip_address):
        """Anonymize IP address for privacy compliance"""
        if not ip_address:
            return None
        
        try:
            # Hash IP with privacy salt
            hashed = hashlib.sha256((ip_address + self.privacy_salt).encode()).hexdigest()
            return hashed[:16]  # Return first 16 chars of hash
        except:
            return "anonymous"

# Global service instance
read_receipt_service = ReadReceiptService()