import time
import threading
import logging
import smtplib
import requests
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from models import db, Device, Alert, MonitoringData, Configuration
from config import Config
from services.push_notifications import push_service

logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self, app=None):
        self.app = app
        self.is_running = False
        self._stop_event = threading.Event()
        self.alert_thresholds = {
            'device_down_minutes': 3,  # Alert if device down for 3+ minutes
            'high_latency_ms': 1000,   # Alert if ping > 1000ms
            'packet_loss_threshold': 50  # Alert if packet loss > 50%
        }
        
    def check_device_down_alerts(self):
        """Check for devices that have been down for too long"""
        try:
            threshold_minutes = self.alert_thresholds['device_down_minutes']
            cutoff_time = datetime.utcnow() - timedelta(minutes=threshold_minutes)
            
            # Find devices that haven't responded recently
            devices = Device.query.filter(
                Device.is_monitored == True,
                Device.last_seen < cutoff_time
            ).all()
            
            for device in devices:
                # Check if we already have an active alert for this device
                existing_alert = Alert.query.filter(
                    Alert.device_id == device.id,
                    Alert.alert_type == 'device_down',
                    Alert.resolved == False
                ).first()
                
                if not existing_alert:
                    # Create new alert
                    alert = Alert(
                        device_id=device.id,
                        alert_type='device_down',
                        severity='critical',
                        message=f"Device {device.display_name} ({device.ip_address}) has been down for over {threshold_minutes} minutes"
                    )
                    
                    db.session.add(alert)
                    db.session.commit()
                    
                    # Send notifications
                    self.send_alert_notifications(alert)
                    
                    logger.warning(f"Device down alert created for {device.display_name}")
                    
        except Exception as e:
            logger.error(f"Error checking device down alerts: {e}")
            db.session.rollback()
    
    def check_high_latency_alerts(self):
        """Check for devices with consistently high latency"""
        try:
            threshold_ms = self.alert_thresholds['high_latency_ms']
            
            # Check last 5 minutes of data
            cutoff_time = datetime.utcnow() - timedelta(minutes=5)
            
            # Find devices with recent high latency measurements
            subquery = db.session.query(MonitoringData.device_id).filter(
                MonitoringData.timestamp >= cutoff_time,
                MonitoringData.response_time > threshold_ms
            ).group_by(MonitoringData.device_id).having(
                db.func.count(MonitoringData.id) >= 3  # At least 3 high latency measurements
            ).subquery()
            
            devices = Device.query.filter(
                Device.id.in_(subquery),
                Device.is_monitored == True
            ).all()
            
            for device in devices:
                # Check if we already have an active alert
                existing_alert = Alert.query.filter(
                    Alert.device_id == device.id,
                    Alert.alert_type == 'high_latency',
                    Alert.resolved == False
                ).first()
                
                if not existing_alert:
                    # Get average latency for alert message
                    avg_latency = db.session.query(
                        db.func.avg(MonitoringData.response_time)
                    ).filter(
                        MonitoringData.device_id == device.id,
                        MonitoringData.timestamp >= cutoff_time,
                        MonitoringData.response_time.isnot(None)
                    ).scalar()
                    
                    alert = Alert(
                        device_id=device.id,
                        alert_type='high_latency',
                        severity='warning',
                        message=f"Device {device.display_name} ({device.ip_address}) has high latency: {avg_latency:.0f}ms average"
                    )
                    
                    db.session.add(alert)
                    db.session.commit()
                    
                    # Send notifications
                    self.send_alert_notifications(alert)
                    
                    logger.warning(f"High latency alert created for {device.display_name}")
                    
        except Exception as e:
            logger.error(f"Error checking high latency alerts: {e}")
            db.session.rollback()
    
    def resolve_alerts(self):
        """Resolve alerts for devices that are back to normal"""
        try:
            # Resolve device down alerts for devices that are back up
            threshold_minutes = self.alert_thresholds['device_down_minutes']
            recent_time = datetime.utcnow() - timedelta(minutes=threshold_minutes // 2)
            
            # Find active device down alerts where device is now responding
            active_down_alerts = Alert.query.filter(
                Alert.alert_type == 'device_down',
                Alert.resolved == False
            ).all()
            
            for alert in active_down_alerts:
                device = alert.device
                if device and device.last_seen and device.last_seen >= recent_time:
                    alert.resolve()
                    logger.info(f"Resolved device down alert for {device.display_name}")
            
            # Resolve high latency alerts for devices with normal latency
            threshold_ms = self.alert_thresholds['high_latency_ms']
            cutoff_time = datetime.utcnow() - timedelta(minutes=3)
            
            active_latency_alerts = Alert.query.filter(
                Alert.alert_type == 'high_latency',
                Alert.resolved == False
            ).all()
            
            for alert in active_latency_alerts:
                device = alert.device
                if device:
                    # Check recent latency measurements
                    recent_high_latency = MonitoringData.query.filter(
                        MonitoringData.device_id == device.id,
                        MonitoringData.timestamp >= cutoff_time,
                        MonitoringData.response_time > threshold_ms
                    ).count()
                    
                    if recent_high_latency == 0:
                        alert.resolve()
                        logger.info(f"Resolved high latency alert for {device.display_name}")
            
            db.session.commit()
            
        except Exception as e:
            logger.error(f"Error resolving alerts: {e}")
            db.session.rollback()
    
    def send_email_alert(self, alert):
        """Send email notification for alert"""
        try:
            if not all([Config.SMTP_SERVER, Config.SMTP_USERNAME, Config.SMTP_PASSWORD, 
                       Config.ALERT_FROM_EMAIL, Config.ALERT_TO_EMAILS]):
                logger.debug("Email configuration incomplete, skipping email alert")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = Config.ALERT_FROM_EMAIL
            msg['To'] = ', '.join(Config.ALERT_TO_EMAILS)
            msg['Subject'] = f"[HomeNetMon] {alert.severity.upper()}: {alert.alert_type.replace('_', ' ').title()}"
            
            # Email body
            body = f"""
HomeNetMon Alert

Device: {alert.device.display_name} ({alert.device.ip_address})
Alert Type: {alert.alert_type.replace('_', ' ').title()}
Severity: {alert.severity.upper()}
Time: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}

Message: {alert.message}

Dashboard: http://{Config.HOST}:{Config.PORT}
Device Details: http://{Config.HOST}:{Config.PORT}/device/{alert.device.id}

This is an automated message from HomeNetMon.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT)
            if Config.SMTP_USE_TLS:
                server.starttls()
            server.login(Config.SMTP_USERNAME, Config.SMTP_PASSWORD)
            text = msg.as_string()
            server.sendmail(Config.ALERT_FROM_EMAIL, Config.ALERT_TO_EMAILS, text)
            server.quit()
            
            logger.info(f"Email alert sent for {alert.device.display_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending email alert: {e}")
            return False
    
    def send_webhook_alert(self, alert):
        """Send webhook notification for alert"""
        try:
            if not Config.WEBHOOK_URL:
                logger.debug("No webhook URL configured, skipping webhook alert")
                return False
            
            payload = {
                'alert_id': alert.id,
                'device_name': alert.device.display_name,
                'device_ip': alert.device.ip_address,
                'alert_type': alert.alert_type,
                'severity': alert.severity,
                'message': alert.message,
                'timestamp': alert.created_at.isoformat(),
                'dashboard_url': f"http://{Config.HOST}:{Config.PORT}",
                'device_url': f"http://{Config.HOST}:{Config.PORT}/device/{alert.device.id}"
            }
            
            response = requests.post(
                Config.WEBHOOK_URL,
                json=payload,
                timeout=Config.WEBHOOK_TIMEOUT
            )
            
            if response.status_code == 200:
                logger.info(f"Webhook alert sent for {alert.device.display_name}")
                return True
            else:
                logger.error(f"Webhook alert failed with status {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending webhook alert: {e}")
            return False
    
    def send_alert_notifications(self, alert):
        """Send all configured alert notifications"""
        try:
            # Check configuration for enabled notification methods
            email_enabled = Configuration.get_value('alert_email_enabled', 'false').lower() == 'true'
            webhook_enabled = Configuration.get_value('alert_webhook_enabled', 'false').lower() == 'true'
            push_enabled = Configuration.get_value('push_notifications_enabled', 'false').lower() == 'true'
            
            if email_enabled:
                self.send_email_alert(alert)
            
            if webhook_enabled:
                self.send_webhook_alert(alert)
                
            if push_enabled:
                self.send_push_notification(alert)
                
        except Exception as e:
            logger.error(f"Error sending alert notifications: {e}")
    
    def send_push_notification(self, alert):
        """Send push notification for alert"""
        try:
            if not push_service.is_configured():
                logger.debug("Push notifications not configured")
                return False
            
            device = alert.device
            dashboard_url = f"http://{Config.HOST}:{Config.PORT}"
            
            if alert.alert_type == 'device_down':
                success = push_service.send_device_down_alert(
                    device_name=device.display_name,
                    ip_address=device.ip_address,
                    dashboard_url=dashboard_url
                )
            elif alert.alert_type == 'high_latency':
                # For high latency, send a generic notification
                title = f"⚠️ High Latency: {device.display_name}"
                success = push_service.send_notification(
                    title=title,
                    message=alert.message,
                    priority="default",
                    tags="warning,yellow_circle,slow",
                    click_url=dashboard_url
                )
            else:
                # Generic alert
                title = f"🚨 Alert: {device.display_name}"
                success = push_service.send_notification(
                    title=title,
                    message=alert.message,
                    priority="default",
                    tags="warning,exclamation",
                    click_url=dashboard_url
                )
            
            if success:
                logger.info(f"Push notification sent for alert: {alert.alert_type}")
            else:
                logger.error(f"Failed to send push notification for alert: {alert.alert_type}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending push notification: {e}")
            return False
    
    def cleanup_old_alerts(self, days=30):
        """Clean up resolved alerts older than specified days"""
        if not self.app:
            return
            
        try:
            with self.app.app_context():
                cutoff_date = datetime.utcnow() - timedelta(days=days)
                
                deleted_count = db.session.query(Alert).filter(
                    Alert.resolved == True,
                    Alert.resolved_at < cutoff_date
                ).delete()
                
                db.session.commit()
                
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old resolved alerts")
                    
        except Exception as e:
            logger.error(f"Error cleaning up old alerts: {e}")
            if self.app:
                with self.app.app_context():
                    db.session.rollback()
    
    def get_active_alerts(self):
        """Get all active (unresolved) alerts"""
        try:
            return Alert.query.filter(Alert.resolved == False).order_by(Alert.created_at.desc()).all()
        except Exception as e:
            logger.error(f"Error getting active alerts: {e}")
            return []
    
    def start_monitoring(self):
        """Start the alert monitoring process"""
        self.is_running = True
        logger.info("Starting alert monitoring")
        
        # Cleanup old alerts on startup
        self.cleanup_old_alerts()
        
        while not self._stop_event.is_set():
            try:
                # Check for new alerts
                self.check_device_down_alerts()
                self.check_high_latency_alerts()
                
                # Resolve alerts that are no longer valid
                self.resolve_alerts()
                
                # Periodic cleanup (every 10 cycles)
                if hasattr(self, '_cleanup_counter'):
                    self._cleanup_counter += 1
                else:
                    self._cleanup_counter = 1
                
                if self._cleanup_counter >= 10:
                    self.cleanup_old_alerts()
                    self._cleanup_counter = 0
                
                # Wait before next check (check more frequently than monitoring)
                self._stop_event.wait(Config.PING_INTERVAL // 2)
                
            except Exception as e:
                logger.error(f"Error in alert monitoring loop: {e}")
                time.sleep(60)  # Wait before retrying
        
        self.is_running = False
        logger.info("Alert monitoring stopped")
    
    def stop(self):
        """Stop the alert monitoring process"""
        logger.info("Stopping alert manager")
        self._stop_event.set()
        self.is_running = False