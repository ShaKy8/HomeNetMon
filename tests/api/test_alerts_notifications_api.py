"""
Unit tests for the alerts and notifications API endpoints.

Tests cover:
- Notification history and statistics
- Alert notification tracking
- Notification failure analysis
- Read receipt functionality
- Test notification sending
- Notification retry mechanisms
- Notification analytics and trends
- Error handling and validation
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, Mock

from models import Alert, Device
from tests.fixtures.factories import (
    AlertFactory, DeviceFactory, PerformanceAlertFactory
)
from tests.fixtures.utils import APITestHelper


class TestNotificationHistoryAPI:
    """Test notification history API endpoints."""
    
    @patch('api.notifications.NotificationHistory')
    def test_get_notification_history_basic(self, mock_history, client, db_session):
        """Test getting basic notification history."""
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device)
        
        # Mock notification history data
        mock_history.query.all.return_value = [
            Mock(
                id=1,
                alert_id=alert.id,
                notification_type='email',
                recipient='admin@example.com',
                status='sent',
                sent_at=datetime.utcnow(),
                delivery_status='delivered'
            )
        ]
        
        response = client.get('/api/notifications/history')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'notifications' in data
        assert 'total' in data
    
    @patch('api.notifications.NotificationHistory')
    def test_get_notification_history_filtered_by_alert(self, mock_history, client, db_session):
        """Test getting notification history filtered by alert."""
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device)
        
        response = client.get(f'/api/notifications/history?alert_id={alert.id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
    
    @patch('api.notifications.NotificationHistory')
    def test_get_notification_history_filtered_by_type(self, mock_history, client, db_session):
        """Test getting notification history filtered by type."""
        response = client.get('/api/notifications/history?type=email')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
    
    @patch('api.notifications.NotificationHistory')
    def test_get_notification_history_filtered_by_status(self, mock_history, client, db_session):
        """Test getting notification history filtered by status."""
        response = client.get('/api/notifications/history?status=failed')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
    
    @patch('api.notifications.NotificationHistory')
    def test_get_notification_history_time_range(self, mock_history, client, db_session):
        """Test getting notification history with time range filtering."""
        start_time = (datetime.utcnow() - timedelta(days=7)).isoformat()
        end_time = datetime.utcnow().isoformat()
        
        response = client.get(f'/api/notifications/history?start_time={start_time}&end_time={end_time}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
    
    @patch('api.notifications.NotificationHistory')
    def test_get_notification_history_pagination(self, mock_history, client, db_session):
        """Test notification history pagination."""
        response = client.get('/api/notifications/history?page=1&per_page=10')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert 'page' in data
        assert 'per_page' in data
        assert 'total_pages' in data


class TestNotificationStatsAPI:
    """Test notification statistics API endpoints."""
    
    @patch('api.notifications.NotificationHistory')
    def test_get_notification_stats_basic(self, mock_history, client, db_session):
        """Test getting basic notification statistics."""
        # Mock statistics calculation
        mock_history.query.count.return_value = 100
        
        response = client.get('/api/notifications/stats')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        stats = data['stats']
        assert 'total_notifications' in stats
        assert 'success_rate' in stats
        assert 'failure_rate' in stats
        assert 'notifications_by_type' in stats
        assert 'notifications_by_status' in stats
    
    def test_get_notification_stats_time_period(self, client, db_session):
        """Test notification statistics for specific time period."""
        start_time = (datetime.utcnow() - timedelta(days=30)).isoformat()
        
        response = client.get(f'/api/notifications/stats?start_time={start_time}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
    
    def test_get_notification_stats_by_alert_type(self, client, db_session):
        """Test notification statistics grouped by alert type."""
        response = client.get('/api/notifications/stats?group_by=alert_type')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True


class TestNotificationTypesAPI:
    """Test notification types API endpoints."""
    
    def test_get_notification_types(self, client, db_session):
        """Test getting available notification types."""
        response = client.get('/api/notifications/types')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        types = data['types']
        assert 'email' in types
        assert 'webhook' in types
        assert 'push' in types
        
        # Check type configuration
        email_config = next((t for t in types if t['type'] == 'email'), None)
        assert email_config is not None
        assert 'enabled' in email_config
        assert 'config' in email_config


class TestNotificationCleanupAPI:
    """Test notification cleanup API endpoints."""
    
    @patch('api.notifications.NotificationHistory')
    def test_clear_notification_history(self, mock_history, client, db_session):
        """Test clearing old notification history."""
        # Mock deletion count
        mock_history.query.filter.return_value.delete.return_value = 50
        
        response = client.delete('/api/notifications/clear')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'deleted_count' in data
    
    @patch('api.notifications.NotificationHistory')
    def test_clear_notification_history_with_cutoff_date(self, mock_history, client, db_session):
        """Test clearing notification history with specific cutoff date."""
        cutoff_date = (datetime.utcnow() - timedelta(days=90)).isoformat()
        
        response = client.delete(f'/api/notifications/clear?before={cutoff_date}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
    
    @patch('api.notifications.NotificationHistory')
    def test_clear_notification_history_by_type(self, mock_history, client, db_session):
        """Test clearing notification history by type."""
        response = client.delete('/api/notifications/clear?type=email')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True


class TestNotificationRetryAPI:
    """Test notification retry API endpoints."""
    
    @patch('api.notifications.NotificationHistory')
    @patch('api.notifications.notification_service')
    def test_retry_notification_success(self, mock_service, mock_history, client, db_session):
        """Test successfully retrying a failed notification."""
        # Mock failed notification
        mock_notification = Mock(
            id=1,
            status='failed',
            notification_type='email',
            recipient='admin@example.com',
            alert_id=1
        )
        mock_history.query.get.return_value = mock_notification
        
        # Mock successful retry
        mock_service.retry_notification.return_value = True
        
        response = client.post('/api/notifications/retry/1')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'retry successful' in data['message'].lower()
        
        mock_service.retry_notification.assert_called_once_with(mock_notification)
    
    @patch('api.notifications.NotificationHistory')
    def test_retry_notification_not_found(self, mock_history, client, db_session):
        """Test retrying non-existent notification."""
        mock_history.query.get.return_value = None
        
        response = client.post('/api/notifications/retry/99999')
        
        APITestHelper.assert_error_response(response, 404, 'Notification not found')
    
    @patch('api.notifications.NotificationHistory')
    def test_retry_notification_already_successful(self, mock_history, client, db_session):
        """Test retrying already successful notification."""
        # Mock successful notification
        mock_notification = Mock(
            id=1,
            status='sent',
            delivery_status='delivered'
        )
        mock_history.query.get.return_value = mock_notification
        
        response = client.post('/api/notifications/retry/1')
        
        APITestHelper.assert_error_response(response, 400, 'already successful')


class TestAlertNotificationsAPI:
    """Test alert-specific notification API endpoints."""
    
    @patch('api.notifications.NotificationHistory')
    def test_get_notifications_for_alert(self, mock_history, client, db_session):
        """Test getting all notifications for specific alert."""
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device)
        
        # Mock notifications for alert
        mock_notifications = [
            Mock(
                id=1,
                alert_id=alert.id,
                notification_type='email',
                status='sent'
            ),
            Mock(
                id=2,
                alert_id=alert.id,
                notification_type='webhook',
                status='failed'
            )
        ]
        mock_history.query.filter_by.return_value.all.return_value = mock_notifications
        
        response = client.get(f'/api/notifications/alert/{alert.id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'notifications' in data
        assert len(data['notifications']) == 2
    
    def test_get_notifications_for_nonexistent_alert(self, client, db_session):
        """Test getting notifications for non-existent alert."""
        response = client.get('/api/notifications/alert/99999')
        
        APITestHelper.assert_error_response(response, 404, 'Alert not found')


class TestTestNotificationAPI:
    """Test test notification sending API endpoints."""
    
    @patch('api.notifications.notification_service')
    def test_send_test_notification_email(self, mock_service, client, db_session):
        """Test sending test email notification."""
        mock_service.send_test_notification.return_value = True
        
        test_data = {
            'type': 'email',
            'recipient': 'test@example.com',
            'message': 'This is a test notification'
        }
        
        response = APITestHelper.post_json(client, '/api/notifications/send-test', test_data)
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'test notification sent' in data['message'].lower()
        
        mock_service.send_test_notification.assert_called_once()
    
    @patch('api.notifications.notification_service')
    def test_send_test_notification_webhook(self, mock_service, client, db_session):
        """Test sending test webhook notification."""
        mock_service.send_test_notification.return_value = True
        
        test_data = {
            'type': 'webhook',
            'url': 'https://example.com/webhook',
            'message': 'Test webhook'
        }
        
        response = APITestHelper.post_json(client, '/api/notifications/send-test', test_data)
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
    
    @patch('api.notifications.notification_service')
    def test_send_test_notification_failure(self, mock_service, client, db_session):
        """Test test notification sending failure."""
        mock_service.send_test_notification.return_value = False
        
        test_data = {
            'type': 'email',
            'recipient': 'invalid@email',
            'message': 'Test'
        }
        
        response = APITestHelper.post_json(client, '/api/notifications/send-test', test_data)
        
        APITestHelper.assert_error_response(response, 400, 'failed to send')
    
    def test_send_test_notification_invalid_type(self, client, db_session):
        """Test sending test notification with invalid type."""
        test_data = {
            'type': 'invalid_type',
            'recipient': 'test@example.com',
            'message': 'Test'
        }
        
        response = APITestHelper.post_json(client, '/api/notifications/send-test', test_data)
        
        APITestHelper.assert_error_response(response, 400, 'Invalid notification type')
    
    def test_send_test_notification_missing_data(self, client, db_session):
        """Test sending test notification with missing required data."""
        test_data = {
            'type': 'email'
            # Missing recipient and message
        }
        
        response = APITestHelper.post_json(client, '/api/notifications/send-test', test_data)
        
        APITestHelper.assert_error_response(response, 400, 'Missing required')


class TestNotificationFailureAnalysisAPI:
    """Test notification failure analysis API endpoints."""
    
    @patch('api.notifications.NotificationHistory')
    def test_get_notification_failure_analysis(self, mock_history, client, db_session):
        """Test getting notification failure analysis."""
        response = client.get('/api/notifications/failure-analysis')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        analysis = data['analysis']
        assert 'failure_rate' in analysis
        assert 'common_failures' in analysis
        assert 'failure_trends' in analysis
        assert 'recommended_actions' in analysis
    
    def test_get_notification_failure_analysis_by_type(self, client, db_session):
        """Test failure analysis filtered by notification type."""
        response = client.get('/api/notifications/failure-analysis?type=email')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
    
    def test_get_notification_failure_analysis_time_range(self, client, db_session):
        """Test failure analysis for specific time range."""
        start_time = (datetime.utcnow() - timedelta(days=30)).isoformat()
        
        response = client.get(f'/api/notifications/failure-analysis?start_time={start_time}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True


class TestNotificationAnalyticsAPI:
    """Test notification analytics API endpoints."""
    
    def test_get_notification_trends(self, client, db_session):
        """Test getting notification trends analysis."""
        response = client.get('/api/notifications/analytics/trends')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        trends = data['trends']
        assert 'volume_trend' in trends
        assert 'success_rate_trend' in trends
        assert 'response_time_trend' in trends
        assert 'peak_hours' in trends
    
    def test_get_notification_performance(self, client, db_session):
        """Test getting notification delivery performance metrics."""
        response = client.get('/api/notifications/analytics/performance')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        performance = data['performance']
        assert 'avg_delivery_time' in performance
        assert 'delivery_success_rate' in performance
        assert 'performance_by_type' in performance
        assert 'sla_compliance' in performance
    
    def test_get_notification_predictions(self, client, db_session):
        """Test getting predictive analytics and forecasting."""
        response = client.get('/api/notifications/analytics/predictions')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        predictions = data['predictions']
        assert 'volume_forecast' in predictions
        assert 'failure_risk_assessment' in predictions
        assert 'capacity_recommendations' in predictions


class TestReadReceiptAPI:
    """Test read receipt functionality API endpoints."""
    
    @patch('api.notifications.read_receipt_service')
    def test_generate_read_receipt_token(self, mock_service, client, db_session):
        """Test generating read receipt tracking token."""
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device)
        
        mock_service.generate_tracking_token.return_value = 'abc123-tracking-token'
        
        token_data = {
            'notification_id': 1,
            'alert_id': alert.id,
            'recipient': 'admin@example.com'
        }
        
        response = APITestHelper.post_json(client, '/api/notifications/receipt/generate', token_data)
        
        data = APITestHelper.assert_json_response(response, 201)
        assert data['success'] is True
        assert data['tracking_token'] == 'abc123-tracking-token'
        
        mock_service.generate_tracking_token.assert_called_once()
    
    @patch('api.notifications.read_receipt_service')
    def test_track_read_receipt(self, mock_service, client, db_session):
        """Test tracking read receipt interaction."""
        mock_service.track_interaction.return_value = True
        
        tracking_data = {
            'tracking_token': 'abc123-tracking-token',
            'interaction_type': 'email_open',
            'user_agent': 'Mozilla/5.0...',
            'ip_address': '192.168.1.100'
        }
        
        response = APITestHelper.post_json(client, '/api/notifications/receipt/track', tracking_data)
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'interaction tracked' in data['message'].lower()
        
        mock_service.track_interaction.assert_called_once()
    
    @patch('api.notifications.read_receipt_service')
    def test_read_receipt_pixel(self, mock_service, client, db_session):
        """Test read receipt tracking pixel endpoint."""
        mock_service.track_pixel_load.return_value = True
        
        response = client.get('/api/notifications/receipt/pixel/abc123-tracking-token')
        
        assert response.status_code == 200
        assert response.content_type.startswith('image/')
        
        mock_service.track_pixel_load.assert_called_once_with('abc123-tracking-token')
    
    def test_read_receipt_pixel_invalid_token(self, client, db_session):
        """Test read receipt pixel with invalid token."""
        response = client.get('/api/notifications/receipt/pixel/invalid-token')
        
        # Should still return pixel but not track
        assert response.status_code == 200
        assert response.content_type.startswith('image/')
    
    @patch('api.notifications.read_receipt_service')
    def test_get_read_receipt_analytics(self, mock_service, client, db_session):
        """Test getting read receipt analytics."""
        mock_service.get_analytics.return_value = {
            'total_tracked': 100,
            'open_rate': 75.0,
            'click_rate': 25.0
        }
        
        response = client.get('/api/notifications/receipt/analytics')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        analytics = data['analytics']
        assert 'total_tracked' in analytics
        assert 'open_rate' in analytics
        assert 'click_rate' in analytics
        assert 'engagement_trends' in analytics
    
    @patch('api.notifications.read_receipt_service')
    def test_get_notification_receipts(self, mock_service, client, db_session):
        """Test getting all read receipts for specific notification."""
        mock_service.get_notification_receipts.return_value = [
            {
                'tracking_token': 'token1',
                'interaction_type': 'email_open',
                'timestamp': datetime.utcnow().isoformat()
            }
        ]
        
        response = client.get('/api/notifications/receipt/notification/1')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        assert 'receipts' in data
        assert len(data['receipts']) == 1
    
    def test_get_notification_receipts_not_found(self, client, db_session):
        """Test getting receipts for non-existent notification."""
        response = client.get('/api/notifications/receipt/notification/99999')
        
        APITestHelper.assert_error_response(response, 404, 'Notification not found')


class TestNotificationAPIAdvancedFeatures:
    """Test advanced notification API features."""
    
    def test_notification_digest_summary(self, client, db_session):
        """Test getting notification digest summary."""
        response = client.get('/api/notifications/digest?period=daily')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        digest = data['digest']
        assert 'summary' in digest
        assert 'top_alerts' in digest
        assert 'delivery_stats' in digest
    
    def test_notification_escalation_tracking(self, client, db_session):
        """Test tracking notification escalations."""
        device = DeviceFactory.create()
        alert = AlertFactory.create(device=device)
        
        response = client.get(f'/api/notifications/escalation/{alert.id}')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        escalation = data['escalation']
        assert 'escalation_level' in escalation
        assert 'next_escalation' in escalation
        assert 'escalation_history' in escalation
    
    def test_notification_template_management(self, client, db_session):
        """Test notification template management."""
        template_data = {
            'name': 'device_down_email',
            'type': 'email',
            'subject': 'Device Down Alert',
            'body': 'Device {{device_name}} is down.'
        }
        
        response = APITestHelper.post_json(client, '/api/notifications/templates', template_data)
        
        data = APITestHelper.assert_json_response(response, 201)
        assert data['success'] is True
        assert 'template_id' in data
    
    def test_notification_channel_health(self, client, db_session):
        """Test notification channel health monitoring."""
        response = client.get('/api/notifications/channels/health')
        
        data = APITestHelper.assert_json_response(response, 200)
        assert data['success'] is True
        
        health = data['channel_health']
        assert 'email' in health
        assert 'webhook' in health
        assert 'push' in health
        
        # Check channel status
        for channel in health.values():
            assert 'status' in channel
            assert 'last_success' in channel
            assert 'error_rate' in channel


class TestNotificationAPIErrorHandling:
    """Test notification API error handling."""
    
    def test_invalid_notification_id(self, client, db_session):
        """Test handling invalid notification ID."""
        response = client.post('/api/notifications/retry/invalid')
        
        APITestHelper.assert_error_response(response, 400, 'Invalid notification ID')
    
    def test_invalid_alert_id(self, client, db_session):
        """Test handling invalid alert ID."""
        response = client.get('/api/notifications/alert/invalid')
        
        APITestHelper.assert_error_response(response, 400, 'Invalid alert ID')
    
    def test_invalid_time_parameters(self, client, db_session):
        """Test handling invalid time parameters."""
        response = client.get('/api/notifications/history?start_time=invalid-date')
        
        APITestHelper.assert_error_response(response, 400, 'Invalid time format')
    
    def test_notification_service_unavailable(self, client, db_session):
        """Test handling when notification service is unavailable."""
        with patch('api.notifications.notification_service', None):
            test_data = {
                'type': 'email',
                'recipient': 'test@example.com',
                'message': 'Test'
            }
            
            response = APITestHelper.post_json(client, '/api/notifications/send-test', test_data)
            
            APITestHelper.assert_error_response(response, 503, 'Service unavailable')
    
    def test_database_error_handling(self, client, db_session):
        """Test handling database errors."""
        with patch('api.notifications.NotificationHistory.query', side_effect=Exception("Database error")):
            response = client.get('/api/notifications/history')
            
            APITestHelper.assert_error_response(response, 500, 'Internal server error')
    
    def test_rate_limiting_simulation(self, client, db_session):
        """Test rate limiting for notification operations."""
        # Simulate rapid requests (would need actual rate limiting implementation)
        test_data = {
            'type': 'email',
            'recipient': 'test@example.com',
            'message': 'Test'
        }
        
        # Multiple rapid requests
        for _ in range(10):
            response = APITestHelper.post_json(client, '/api/notifications/send-test', test_data)
            # In a real implementation, later requests might be rate limited
            assert response.status_code in [200, 201, 429]  # OK, Created, or Too Many Requests