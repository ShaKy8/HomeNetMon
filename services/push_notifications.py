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
        if not self.is_configured():
            logger.warning("Push notifications not configured, skipping")
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
                return True
            else:
                logger.error(f"Failed to send push notification: HTTP {response.status_code}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Error sending push notification: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending push notification: {e}")
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

# Global instance
push_service = PushNotificationService()