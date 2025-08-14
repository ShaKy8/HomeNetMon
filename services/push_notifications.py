import requests
import logging
from typing import Optional, Dict, Any
from config import Config

logger = logging.getLogger(__name__)

class PushNotificationService:
    """Service for sending push notifications via ntfy.sh or compatible servers"""
    
    def __init__(self):
        self.enabled = Config.NTFY_ENABLED
        self.server = Config.NTFY_SERVER
        self.topic = Config.NTFY_TOPIC
        self.username = Config.NTFY_USERNAME
        self.password = Config.NTFY_PASSWORD
        
    def update_config_from_database(self):
        """Update configuration from database settings"""
        try:
            from models import Configuration
            self.enabled = Configuration.get_value('push_notifications_enabled', 'false').lower() == 'true'
            self.topic = Configuration.get_value('ntfy_topic', '')
            self.server = Configuration.get_value('ntfy_server', 'https://ntfy.sh')
            logger.debug(f"Updated push service config: enabled={self.enabled}, topic={self.topic}, server={self.server}")
        except Exception as e:
            logger.error(f"Error updating push service config from database: {e}")
        
    def is_configured(self) -> bool:
        """Check if push notifications are properly configured"""
        return (
            self.enabled and 
            self.topic is not None and 
            self.server is not None
        )
    
    def send_notification(
        self,
        title: str,
        message: str,
        priority: str = "default",
        tags: Optional[str] = None,
        click_url: Optional[str] = None,
        icon_url: Optional[str] = None
    ) -> bool:
        """Send a push notification
        
        Args:
            title: Notification title
            message: Notification message body
            priority: Priority level (min, low, default, high, urgent)
            tags: Emoji tags (e.g., "warning,red_circle")
            click_url: URL to open when notification is clicked
            icon_url: Custom icon URL
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        # Update config from database before sending
        self.update_config_from_database()
        
        if not self.is_configured():
            logger.debug("Push notifications not configured, skipping")
            return False
            
        try:
            # Build notification URL
            url = f"{self.server.rstrip('/')}/{self.topic}"
            
            # Build headers with proper UTF-8 encoding
            # Ensure all header values are properly encoded for HTTP transmission
            headers = {
                "Title": title.encode('utf-8').decode('latin-1') if any(ord(c) > 127 for c in title) else title,
                "Priority": priority,
                "Content-Type": "text/plain; charset=utf-8"
            }
            
            if tags:
                headers["Tags"] = tags.encode('utf-8').decode('latin-1') if any(ord(c) > 127 for c in tags) else tags
                
            if click_url:
                headers["Click"] = click_url
                
            if icon_url:
                headers["Icon"] = icon_url
            
            # Authentication if configured
            auth = None
            if self.username and self.password:
                auth = (self.username, self.password)
            
            # Send notification with proper UTF-8 handling
            response = requests.post(
                url,
                data=message.encode('utf-8'),
                headers=headers,
                auth=auth,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Push notification sent successfully: {title}")
                self._log_notification(title, message, priority, tags, 'success')
                return True
            else:
                logger.error(f"Failed to send push notification: HTTP {response.status_code}")
                self._log_notification(title, message, priority, tags, 'failed', f"HTTP {response.status_code}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Error sending push notification: {e}")
            self._log_notification(title, message, priority, tags, 'failed', str(e))
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending push notification: {e}")
            self._log_notification(title, message, priority, tags, 'failed', str(e))
            return False
    
    def send_device_down_alert(self, device_name: str, ip_address: str, dashboard_url: str = None) -> bool:
        """Send notification when a device goes down"""
        title = f"🔴 Device Offline: {device_name}"
        message = f"Device {device_name} ({ip_address}) is no longer responding to ping requests."
        
        return self.send_notification(
            title=title,
            message=message,
            priority="high",
            tags="warning,red_circle,rotating_light",
            click_url=dashboard_url
        )
    
    def send_device_up_alert(self, device_name: str, ip_address: str, dashboard_url: str = None) -> bool:
        """Send notification when a device comes back online"""
        title = f"🟢 Device Online: {device_name}"
        message = f"Device {device_name} ({ip_address}) is back online and responding."
        
        return self.send_notification(
            title=title,
            message=message,
            priority="default",
            tags="white_check_mark,green_circle",
            click_url=dashboard_url
        )
    
    def send_new_device_alert(self, device_name: str, ip_address: str, device_type: str = None, dashboard_url: str = None) -> bool:
        """Send notification when a new device is discovered"""
        title = f"🆕 New Device: {device_name}"
        device_type_text = f" ({device_type})" if device_type else ""
        message = f"New device discovered: {device_name} ({ip_address}){device_type_text}"
        
        return self.send_notification(
            title=title,
            message=message,
            priority="default",
            tags="new,blue_circle,computer",
            click_url=dashboard_url
        )
    
    def send_network_scan_complete(self, new_devices: int, total_devices: int, dashboard_url: str = None) -> bool:
        """Send notification when network scan completes"""
        if new_devices > 0:
            title = f"🔍 Network Scan Complete"
            message = f"Found {new_devices} new devices. Total: {total_devices} devices on network."
            tags = "magnifying_glass_tilted_left,green_circle"
        else:
            title = f"🔍 Network Scan Complete"
            message = f"Network scan completed. Confirmed {total_devices} devices."
            tags = "magnifying_glass_tilted_left,blue_circle"
        
        return self.send_notification(
            title=title,
            message=message,
            priority="low",
            tags=tags,
            click_url=dashboard_url
        )
    
    def send_high_latency_alert(self, device_name: str, ip_address: str, avg_latency: float, dashboard_url: str = None) -> bool:
        """Send notification for high latency alert"""
        title = f"⚠️ High Latency: {device_name}"
        message = f"Device {device_name} ({ip_address}) has high network latency: {avg_latency:.0f}ms average."
        
        return self.send_notification(
            title=title,
            message=message,
            priority="default",
            tags="warning,yellow_circle,hourglass_not_done",
            click_url=dashboard_url
        )
    
    def send_anomaly_alert(self, device_name: str, ip_address: str, anomaly_type: str, message: str, severity: str = "medium", dashboard_url: str = None) -> bool:
        """Send notification for AI anomaly detection"""
        severity_emoji = {
            "low": "🔵",
            "medium": "🟡", 
            "high": "🟠",
            "critical": "🔴"
        }.get(severity, "⚪")
        
        title = f"{severity_emoji} AI Alert: {device_name}"
        full_message = f"Anomaly detected on {device_name} ({ip_address}): {message}"
        
        priority = "high" if severity in ["high", "critical"] else "default"
        tags = f"robot_face,{severity}_circle,warning"
        
        return self.send_notification(
            title=title,
            message=full_message,
            priority=priority,
            tags=tags,
            click_url=dashboard_url
        )
    
    def send_security_alert(self, device_name: str, ip_address: str, vulnerability: str, risk_score: float, dashboard_url: str = None) -> bool:
        """Send notification for security vulnerability"""
        risk_emoji = "🔴" if risk_score >= 7.0 else "🟡" if risk_score >= 4.0 else "🔵"
        
        title = f"{risk_emoji} Security Alert: {device_name}"
        message = f"Security issue detected on {device_name} ({ip_address}): {vulnerability} (Risk: {risk_score:.1f}/10)"
        
        priority = "high" if risk_score >= 7.0 else "default"
        tags = "shield,warning,lock"
        
        return self.send_notification(
            title=title,
            message=message,
            priority=priority,
            tags=tags,
            click_url=dashboard_url
        )
    
    def send_test_notification(self) -> bool:
        """Send a test notification to verify configuration"""
        title = "🧪 HomeNetMon Test"
        message = "This is a test notification from your HomeNetMon system. If you received this, push notifications are working correctly!"
        
        return self.send_notification(
            title=title,
            message=message,
            priority="default",
            tags="test_tube,white_check_mark"
        )
    
    def _log_notification(self, title: str, message: str, priority: str, tags: str, 
                         delivery_status: str, error_message: str = None, 
                         device_id: int = None, notification_type: str = None):
        """Log notification to history table"""
        try:
            from models import NotificationHistory
            
            # Extract notification type from title if not provided
            if not notification_type:
                if "Device Offline" in title:
                    notification_type = "device_down"
                elif "Device Online" in title:
                    notification_type = "device_up"
                elif "New Device" in title:
                    notification_type = "new_device"
                elif "Network Scan" in title:
                    notification_type = "scan_complete"
                elif "High Latency" in title:
                    notification_type = "high_latency"
                elif "AI Alert" in title:
                    notification_type = "anomaly"
                elif "Security Alert" in title:
                    notification_type = "security"
                elif "Test" in title:
                    notification_type = "test"
                else:
                    notification_type = "general"
            
            NotificationHistory.log_notification(
                device_id=device_id,
                notification_type=notification_type,
                title=title,
                message=message,
                priority=priority,
                tags=tags,
                delivery_status=delivery_status,
                error_message=error_message
            )
        except Exception as e:
            logger.error(f"Error logging notification to history: {e}")

# Global instance
push_service = PushNotificationService()