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
        self.rule_engine_service = None
        self.correlation_service = None
        # Optimized alert thresholds with adaptive logic
        self.alert_thresholds = {
            'device_down_minutes_critical': 15,   # Faster alert for critical devices
            'device_down_minutes_regular': 45,    # Balanced threshold for regular devices
            'high_latency_ms': 1500,              # More responsive to network issues
            'packet_loss_threshold': 60,          # Earlier detection of connectivity issues
            'consecutive_failures_required': 3,   # More responsive while reducing false positives
            'recovery_validation_count': 2,       # Require 2 successful pings before recovery alert
            'high_latency_consecutive_required': 3, # Consecutive high latency measurements
            'anomaly_detection_threshold': 0.8,   # Threshold for statistical anomaly detection
            'burst_alert_window_minutes': 10,     # Window for burst alert detection
            'max_alerts_per_burst_window': 2      # Limit alerts per burst window
        }
        
    def is_critical_device(self, device):
        """Determine if a device is critical infrastructure (same logic as monitor)"""
        return (
            device.ip_address.endswith('.1') or  # Router/Gateway
            device.ip_address.endswith('.64') or  # Server
            ('router' in device.device_type.lower() if device.device_type else False) or
            ('server' in device.device_type.lower() if device.device_type else False) or
            ('nuc' in (device.hostname or '').lower()) or
            ('gateway' in (device.hostname or '').lower())
        )
    
    def has_consecutive_failures(self, device, required_failures=3):
        """Check if device has the required number of consecutive monitoring failures"""
        if not device.last_seen:
            logger.debug(f"Device {device.display_name}: Never seen, considering as down")
            return True  # Never seen = definitely down
        
        # Get recent monitoring data - use 4 hour window to align better with uptime calculation
        recent_cutoff = datetime.utcnow() - timedelta(hours=4)
        monitoring_data = MonitoringData.query.filter(
            MonitoringData.device_id == device.id,
            MonitoringData.timestamp >= recent_cutoff
        ).order_by(MonitoringData.timestamp.desc()).limit(required_failures * 5).all()
        
        if len(monitoring_data) < required_failures:
            logger.debug(f"Device {device.display_name}: Not enough monitoring data ({len(monitoring_data)} < {required_failures})")
            return False  # Not enough data to determine
        
        # Check if the most recent records are all failures
        consecutive_count = 0
        for data_point in monitoring_data:
            if data_point.response_time is None:
                consecutive_count += 1
            else:
                break  # Found a success, reset count
        
        result = consecutive_count >= required_failures
        logger.debug(f"Device {device.display_name}: Consecutive failures check: {consecutive_count}/{required_failures} = {result}")
        return result
    
    def check_device_down_alerts(self):
        """Check for devices that have been down for too long with intelligent thresholds"""
        if not self.app:
            logger.error("No Flask app context available for alert checking")
            return
            
        with self.app.app_context():
            try:
                # Get all monitored devices
                all_devices = Device.query.filter_by(is_monitored=True).all()
                consecutive_failures_required = self.alert_thresholds['consecutive_failures_required']
                
                for device in all_devices:
                    # Determine threshold based on device criticality
                    if self.is_critical_device(device):
                        threshold_minutes = self.alert_thresholds['device_down_minutes_critical']
                    else:
                        threshold_minutes = self.alert_thresholds['device_down_minutes_regular']
                    
                    cutoff_time = datetime.utcnow() - timedelta(minutes=threshold_minutes)
                    
                    # Only alert if device hasn't been seen AND has consecutive failures AND has poor recent uptime
                    # This prevents alerts for devices with good long-term uptime but temporary issues
                    try:
                        device_uptime = device.uptime_percentage()
                    except Exception:
                        device_uptime = 100  # Default to good uptime if calculation fails
                        
                    should_alert = (device.last_seen and device.last_seen < cutoff_time and 
                                  self.has_consecutive_failures(device, consecutive_failures_required) and
                                  device_uptime < 90)  # Only alert if recent uptime is very poor (< 90%)
                    
                    logger.debug(f"Alert decision for {device.display_name}: last_seen={device.last_seen < cutoff_time if device.last_seen else 'Never'}, consecutive_failures={self.has_consecutive_failures(device, consecutive_failures_required)}, uptime={device_uptime}%, should_alert={should_alert}")
                    
                    if should_alert:
                        
                        # Check if we already have an active alert for this device
                        existing_alert = Alert.query.filter(
                            Alert.device_id == device.id,
                            Alert.alert_type == 'device_down',
                            Alert.resolved == False
                        ).first()
                        
                        logger.debug(f"Device {device.display_name}: last_seen={device.last_seen}, cutoff={cutoff_time}, consecutive_failures={self.has_consecutive_failures(device, consecutive_failures_required)}, existing_alert={'Yes' if existing_alert else 'No'}")
                        
                        if not existing_alert:
                            device_type = "critical" if self.is_critical_device(device) else "regular"
                            
                            # Check correlation before creating alert
                            message = f"{device_type.title()} device {device.display_name} ({device.ip_address}) has been down for over {threshold_minutes} minutes with {consecutive_failures_required}+ consecutive monitoring failures"
                            
                            severity = 'critical' if self.is_critical_device(device) else 'warning'
                            if self._should_create_alert('device_down', device.id, message, severity):
                                # Create new alert
                                alert = Alert(
                                    device_id=device.id,
                                    alert_type='device_down',
                                    severity=severity,
                                    message=message
                                )
                                
                                # Calculate priority score
                                alert.calculate_and_update_priority(self.app)
                                
                                db.session.add(alert)
                                db.session.commit()
                                
                                # Send notifications
                                self.send_alert_notifications(alert)
                                
                                # Emit real-time update
                                self._emit_alert_update(alert, 'created')
                                
                                # Trigger rule engine for device down event
                                self._trigger_rule_engine_for_alert(alert, device, 'device_down')
                            
                                logger.warning(f"ALERT CREATED: Device down alert for {device.display_name} (threshold: {threshold_minutes}min, type: {device_type}, last_seen: {device.last_seen}, cutoff: {cutoff_time})")
                            else:
                                logger.debug(f"ALERT SUPPRESSED: Device down alert for {device.display_name} due to correlation rules")
                        
            except Exception as e:
                logger.error(f"Error checking device down alerts: {e}")
                db.session.rollback()
    
    def check_high_latency_alerts(self):
        """Check for devices with consistently high latency"""
        if not self.app:
            logger.error("No Flask app context available for alert checking")
            return
            
        with self.app.app_context():
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
                )
                
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
                        
                        # Calculate priority score
                        alert.calculate_and_update_priority(self.app)
                        
                        db.session.add(alert)
                        db.session.commit()
                        
                        # Send notifications
                        self.send_alert_notifications(alert)
                        
                        # Emit real-time update
                        self._emit_alert_update(alert, 'created')
                        
                        # Send enhanced push notification for high latency
                        self._send_high_latency_push_notification(device, avg_latency)
                        
                        # Trigger rule engine for high latency event
                        self._trigger_rule_engine_for_alert(alert, device, 'high_latency', {'avg_latency': avg_latency})
                        
                        logger.warning(f"High latency alert created for {device.display_name}")
                        
            except Exception as e:
                logger.error(f"Error checking high latency alerts: {e}")
                db.session.rollback()
                
    def check_device_recovery_alerts(self):
        """Check for devices that have recently come back online"""
        if not self.app:
            logger.error("No Flask app context available for device recovery checking")
            return
            
        with self.app.app_context():
            try:
                # Use the critical device threshold as baseline for recovery detection
                threshold_minutes = self.alert_thresholds['device_down_minutes_critical']
                recent_time = datetime.utcnow() - timedelta(minutes=threshold_minutes // 2)
                
                # Find active device down alerts with eager loading to prevent N+1 queries
                from sqlalchemy.orm import joinedload
                active_down_alerts = Alert.query.options(joinedload(Alert.device)).filter(
                    Alert.alert_type == 'device_down',
                    Alert.resolved == False
                ).all()
                
                for alert in active_down_alerts:
                    device = alert.device
                    if device and device.last_seen and device.last_seen >= recent_time:
                        # Device is back up - create recovery alert
                        existing_recovery_alert = Alert.query.filter(
                            Alert.device_id == device.id,
                            Alert.alert_type == 'device_recovery',
                            Alert.created_at >= recent_time
                        ).first()
                        
                        if not existing_recovery_alert:
                            # Create recovery alert - auto-resolve since it's informational
                            recovery_alert = Alert(
                                device_id=device.id,
                                alert_type='device_recovery',
                                severity='info',
                                message=f"Device {device.display_name} ({device.ip_address}) is back online after being down",
                                resolved=True,  # Auto-resolve recovery alerts since they're informational
                                resolved_at=datetime.utcnow()
                            )

                            # Calculate priority score
                            recovery_alert.calculate_and_update_priority(self.app)

                            db.session.add(recovery_alert)
                            db.session.commit()
                            
                            # Send notifications
                            self.send_alert_notifications(recovery_alert)
                            
                            # Emit real-time update
                            self._emit_alert_update(recovery_alert, 'created')
                            
                            # Send dedicated device recovery push notification
                            self._send_device_recovery_push_notification(device)
                            
                            # Trigger rule engine for device recovery event
                            self._trigger_rule_engine_for_alert(recovery_alert, device, 'device_recovery')
                            
                            logger.info(f"Device recovery alert created for {device.display_name}")
                            
                        # Note: The down alert will be resolved by the resolve_alerts() function
                        # to avoid duplicate resolution logic and race conditions
                        
            except Exception as e:
                logger.error(f"Error checking device recovery alerts: {e}")
                db.session.rollback()
    
    def resolve_alerts(self):
        """Resolve alerts for devices that are back to normal"""
        if not self.app:
            logger.error("No Flask app context available for alert resolving")
            return
            
        with self.app.app_context():
            try:
                # Resolve device down alerts for devices that are back up
                # Use shorter threshold for resolution to resolve alerts faster
                recent_time = datetime.utcnow() - timedelta(minutes=5)  # If seen in last 5 minutes, resolve alert
                
                # Find active device down alerts where device is now responding
                # Use eager loading to prevent N+1 queries
                from sqlalchemy.orm import joinedload
                active_down_alerts = Alert.query.options(joinedload(Alert.device)).filter(
                    Alert.alert_type == 'device_down',
                    Alert.resolved == False
                ).all()
                
                for alert in active_down_alerts:
                    device = alert.device
                    if device and device.last_seen and device.last_seen >= recent_time:
                        alert.resolve()
                        self._emit_alert_update(alert, 'resolved')
                        logger.info(f"ALERT RESOLVED: Device down alert for {device.display_name} (last_seen: {device.last_seen}, recent_time: {recent_time})")
                    else:
                        logger.debug(f"Alert NOT resolved for {device.display_name}: device={device is not None}, last_seen={device.last_seen if device else None}, recent_time={recent_time}")
                
                # Resolve high latency alerts for devices with normal latency
                threshold_ms = self.alert_thresholds['high_latency_ms']
                cutoff_time = datetime.utcnow() - timedelta(minutes=5)  # Check last 5 minutes
                
                active_latency_alerts = Alert.query.options(joinedload(Alert.device)).filter(
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
                            self._emit_alert_update(alert, 'resolved')
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
            elif alert.alert_type == 'device_recovery':
                # For device recovery, send a positive notification
                title = f"✅ Device Online: {device.display_name}"
                success = push_service.send_notification(
                    title=title,
                    message=alert.message,
                    priority="default",
                    tags="success,green_circle,check",
                    click_url=dashboard_url
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
    
    def _send_device_recovery_push_notification(self, device):
        """Send enhanced push notification for device recovery"""
        try:
            dashboard_url = f"http://{Config.HOST}:{Config.PORT}"
            
            # Update push service configuration from database
            push_service.enabled = Configuration.get_value('push_notifications_enabled', 'false').lower() == 'true'
            push_service.topic = Configuration.get_value('ntfy_topic', '')
            push_service.server = Configuration.get_value('ntfy_server', 'https://ntfy.sh')
            
            if push_service.is_configured():
                success = push_service.send_device_up_alert(
                    device_name=device.display_name,
                    ip_address=device.ip_address,
                    dashboard_url=dashboard_url
                )
                if success:
                    logger.info(f"Sent device recovery push notification for {device.display_name}")
                else:
                    logger.warning(f"Failed to send device recovery push notification for {device.display_name}")
            else:
                logger.debug("Push notifications not configured, skipping device recovery notification")
                
        except Exception as e:
            logger.error(f"Error sending device recovery push notification: {e}")
    
    def _send_high_latency_push_notification(self, device, avg_latency):
        """Send enhanced push notification for high latency"""
        try:
            dashboard_url = f"http://{Config.HOST}:{Config.PORT}"
            
            # Update push service configuration from database
            push_service.enabled = Configuration.get_value('push_notifications_enabled', 'false').lower() == 'true'
            push_service.topic = Configuration.get_value('ntfy_topic', '')
            push_service.server = Configuration.get_value('ntfy_server', 'https://ntfy.sh')
            
            if push_service.is_configured():
                success = push_service.send_high_latency_alert(
                    device_name=device.display_name,
                    ip_address=device.ip_address,
                    avg_latency=avg_latency,
                    dashboard_url=dashboard_url
                )
                if success:
                    logger.info(f"Sent high latency push notification for {device.display_name}")
                else:
                    logger.warning(f"Failed to send high latency push notification for {device.display_name}")
            else:
                logger.debug("Push notifications not configured, skipping high latency notification")
                
        except Exception as e:
            logger.error(f"Error sending high latency push notification: {e}")
    
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
        if not self.app:
            logger.error("No Flask app context available for getting alerts")
            return []
            
        with self.app.app_context():
            try:
                return Alert.query.filter(Alert.resolved == False).order_by(Alert.created_at.desc()).all()
            except Exception as e:
                logger.error(f"Error getting active alerts: {e}")
                return []
    
    def set_alert_pause(self, minutes):
        """Pause alert generation for specified minutes (called after bulk deletion)"""
        self.alert_pause_until = datetime.utcnow() + timedelta(minutes=minutes)
        logger.info(f"Alert generation paused for {minutes} minutes until {self.alert_pause_until}")
    
    def is_alert_generation_paused(self):
        """Check if alert generation is currently paused"""
        if hasattr(self, 'alert_pause_until') and self.alert_pause_until:
            if datetime.utcnow() < self.alert_pause_until:
                return True
            else:
                # Pause period expired, clear it
                self.alert_pause_until = None
        return False
    
    def start_monitoring(self):
        """Start the alert monitoring process with intelligent timing"""
        self.is_running = True
        self.alert_pause_until = None
        logger.info("Starting alert monitoring")
        
        # Setup default suppression rules to reduce alert noise
        self.setup_default_suppressions()

        # Cleanup old alerts on startup
        self.cleanup_old_alerts()

        # Clean up orphaned recovery alerts on startup
        self.cleanup_orphaned_recovery_alerts()
        
        while not self._stop_event.is_set():
            try:
                # Check if alert generation is paused
                if self.is_alert_generation_paused():
                    logger.debug("Alert generation is paused, skipping alert checks")
                else:
                    # Check for new alerts
                    self.check_device_down_alerts()
                    self.check_high_latency_alerts()
                    self.check_device_recovery_alerts()
                
                # Always resolve alerts (even when paused)
                self.resolve_alerts()
                
                # Run alert correlation and escalation
                self.run_alert_correlation()
                
                # Periodic cleanup (every 10 cycles)
                if hasattr(self, '_cleanup_counter'):
                    self._cleanup_counter += 1
                else:
                    self._cleanup_counter = 1
                
                if self._cleanup_counter >= 10:
                    self.cleanup_old_alerts()
                    self._cleanup_counter = 0
                
                # Wait before next check - run much less frequently to reduce alert noise
                # Check every 10 minutes instead of every 2 minutes
                self._stop_event.wait(600)  # 10 minutes between checks
                
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
    
    def _trigger_rule_engine_for_alert(self, alert, device, event_type, metadata=None):
        """Trigger rule engine evaluation for alert events"""
        try:
            # Get rule engine service from app if available
            if self.app and hasattr(self.app, 'rule_engine_service'):
                rule_engine_service = self.app.rule_engine_service
                
                # Import here to avoid circular imports
                from services.rule_engine import TriggerContext
                
                # Create trigger context for the alert event
                context = TriggerContext(
                    event_type=f'alert_{event_type}',
                    device_id=device.id,
                    device={
                        'id': device.id,
                        'display_name': device.display_name,
                        'ip_address': device.ip_address,
                        'status': device.status,
                        'device_type': device.device_type,
                        'is_monitored': device.is_monitored
                    },
                    alert={
                        'id': alert.id,
                        'alert_type': alert.alert_type,
                        'severity': alert.severity,
                        'message': alert.message,
                        'created_at': alert.created_at.isoformat()
                    },
                    metadata=metadata or {}
                )
                
                # Evaluate rules in background thread to avoid blocking alert processing
                import threading
                rule_thread = threading.Thread(
                    target=rule_engine_service.evaluate_rules,
                    args=(context,),
                    daemon=True,
                    name=f'RuleEngine-Alert-{event_type}'
                )
                rule_thread.start()
                
                logger.debug(f"Triggered rule engine for {event_type} alert on device {device.display_name}")
                
        except Exception as e:
            logger.error(f"Error triggering rule engine for alert: {e}")
            # Don't let rule engine errors affect alert processing
    
    def _should_create_alert(self, alert_type: str, device_id: int, message: str, severity: str = 'warning') -> bool:
        """Check if alert should be created based on correlation rules and suppressions"""
        try:
            # Check suppression rules first
            if self._is_alert_suppressed(device_id, alert_type, severity):
                logger.debug(f"Alert suppressed: {alert_type} for device {device_id} (severity: {severity})")
                return False
            
            # Initialize correlation service if not already done
            if not self.correlation_service:
                from services.alert_correlation import AlertCorrelationService
                self.correlation_service = AlertCorrelationService(self.app)
            
            # Check if alert should be suppressed by correlation rules
            should_suppress = self.correlation_service.should_suppress_alert(alert_type, device_id, message)
            return not should_suppress
            
        except Exception as e:
            logger.error(f"Error checking alert correlation: {e}")
            # If correlation check fails, allow the alert to be created
            return True
    
    def _is_alert_suppressed(self, device_id: int, alert_type: str, severity: str) -> bool:
        """Check if alert is suppressed by suppression rules"""
        try:
            if not self.app:
                return False
                
            with self.app.app_context():
                from models import AlertSuppression
                
                # Get all enabled suppression rules
                suppressions = AlertSuppression.query.filter_by(enabled=True).all()
                
                # Check if any suppression rule matches this alert
                for suppression in suppressions:
                    if suppression.matches_alert(device_id, alert_type, severity):
                        logger.info(f"Alert suppressed by rule '{suppression.name}': {alert_type} for device {device_id}")
                        return True
                
                return False
                
        except Exception as e:
            logger.error(f"Error checking alert suppression: {e}")
            return False
    
    def run_alert_correlation(self):
        """Run alert correlation and escalation checks"""
        try:
            if not self.correlation_service:
                from services.alert_correlation import AlertCorrelationService
                self.correlation_service = AlertCorrelationService(self.app)
            
            self.correlation_service.correlate_and_escalate_alerts()
            
        except Exception as e:
            logger.error(f"Error running alert correlation: {e}")
    
    def cleanup_duplicate_alerts(self):
        """Clean up duplicate alerts (one-time operation)"""
        try:
            if not self.correlation_service:
                from services.alert_correlation import AlertCorrelationService
                self.correlation_service = AlertCorrelationService(self.app)

            self.correlation_service.cleanup_duplicate_alerts()

        except Exception as e:
            logger.error(f"Error cleaning up duplicate alerts: {e}")

    def cleanup_orphaned_recovery_alerts(self):
        """Clean up orphaned recovery alerts that should be auto-resolved"""
        try:
            if not self.app:
                return

            with self.app.app_context():
                # Find all unresolved recovery alerts - these should be auto-resolved
                unresolved_recovery_alerts = Alert.query.filter_by(
                    alert_type='device_recovery',
                    resolved=False
                ).all()

                if unresolved_recovery_alerts:
                    logger.info(f"Cleaning up {len(unresolved_recovery_alerts)} orphaned recovery alerts")

                    for alert in unresolved_recovery_alerts:
                        alert.resolved = True
                        alert.resolved_at = datetime.utcnow()
                        alert.resolution_message = "Auto-resolved: Recovery alerts are informational and should not remain unresolved"

                        logger.debug(f"Auto-resolved recovery alert for {alert.device.display_name}")

                    db.session.commit()
                    logger.info(f"Successfully cleaned up {len(unresolved_recovery_alerts)} orphaned recovery alerts")

        except Exception as e:
            logger.error(f"Error cleaning up orphaned recovery alerts: {e}")
            if self.app:
                with self.app.app_context():
                    db.session.rollback()

    def _emit_alert_update(self, alert, action='created'):
        """Emit real-time alert update via WebSocket"""
        try:
            if self.app and hasattr(self.app, 'emit_alert_update'):
                self.app.emit_alert_update(alert, action)
        except Exception as e:
            logger.error(f"Error emitting alert update: {e}")

    def setup_default_suppressions(self):
        """Setup default alert suppression rules to reduce noise"""
        try:
            if not self.app:
                return
                
            with self.app.app_context():
                from models import AlertSuppression
                
                # Enhanced default suppression rules to dramatically reduce alert noise
                default_suppressions = [
                    {
                        'name': 'Quiet Hours - Night Time',
                        'description': 'Suppress non-critical alerts during night hours (11PM-7AM)',
                        'enabled': True,
                        'alert_type': None,  # All alert types
                        'severity': 'info',  # Only info level alerts
                        'daily_start_hour': 23,  # 11 PM
                        'daily_end_hour': 7,   # 7 AM
                        'suppression_type': 'silence'
                    },
                    {
                        'name': 'Performance Warning Suppression',
                        'description': 'Suppress performance warning alerts to reduce noise - only show critical performance issues',
                        'enabled': True,
                        'alert_type': 'performance',
                        'severity': 'warning',
                        'suppression_type': 'silence'
                    },
                    {
                        'name': 'Performance Reliability Rate Limiting',
                        'description': 'Limit performance reliability alerts to max 1 per device per hour',
                        'enabled': True,
                        'alert_type': 'performance',
                        'alert_subtype': 'performance_reliability',
                        'suppression_type': 'rate_limit',
                        'rate_limit_window_minutes': 60,
                        'max_alerts_per_window': 1
                    },
                    {
                        'name': 'Performance Responsiveness Rate Limiting',
                        'description': 'Limit performance responsiveness alerts to max 1 per device per hour',
                        'enabled': True,
                        'alert_type': 'performance',
                        'alert_subtype': 'performance_responsiveness',
                        'suppression_type': 'rate_limit',
                        'rate_limit_window_minutes': 60,
                        'max_alerts_per_window': 1
                    },
                    {
                        'name': 'Recurring Performance Alert Suppression',
                        'description': 'Suppress recurring performance alerts for same device within 4 hours',
                        'enabled': True,
                        'alert_type': 'performance',
                        'suppression_type': 'duplicate_window',
                        'duplicate_window_hours': 4
                    },
                    {
                        'name': 'Anomaly Alert Suppression',
                        'description': 'Suppress noisy anomaly detection alerts',
                        'enabled': True,
                        'alert_type': 'anomaly',
                        'severity': None,  # All severities
                        'suppression_type': 'silence'
                    },
                    {
                        'name': 'Info Level Recovery Alert Suppression',
                        'description': 'Suppress info-level recovery alerts during business hours to reduce noise',
                        'enabled': True,
                        'alert_type': 'device_recovery',
                        'severity': 'info',
                        'daily_start_hour': 8,   # 8 AM
                        'daily_end_hour': 18,    # 6 PM
                        'suppression_type': 'silence'
                    },
                    {
                        'name': 'Performance Alert Burst Protection',
                        'description': 'Prevent performance alert storms - max 3 performance alerts per device per 30 minutes',
                        'enabled': True,
                        'alert_type': 'performance',
                        'suppression_type': 'burst_protection',
                        'burst_window_minutes': 30,
                        'max_alerts_per_burst': 3
                    }
                ]
                
                # Create suppression rules if they don't exist
                for suppression_data in default_suppressions:
                    existing = AlertSuppression.query.filter_by(name=suppression_data['name']).first()
                    if not existing:
                        suppression = AlertSuppression(**suppression_data)
                        db.session.add(suppression)
                        logger.info(f"Created default suppression rule: {suppression_data['name']}")
                
                db.session.commit()
                
        except Exception as e:
            logger.error(f"Error setting up default suppression rules: {e}")
            if self.app:
                with self.app.app_context():
                    db.session.rollback()

    def reload_config(self):
        """Reload configuration for hot-reload support"""
        try:
            logger.info("Reloading AlertManager configuration")
            # Configuration is loaded dynamically via get_config_value calls
            # Log current alert configuration
            if self.app:
                with self.app.app_context():
                    email_enabled = Configuration.get_value('alert_email_enabled', 'false').lower() == 'true'
                    webhook_enabled = Configuration.get_value('alert_webhook_enabled', 'false').lower() == 'true'
                    push_enabled = Configuration.get_value('push_notifications_enabled', 'false').lower() == 'true'
                    
                    logger.info(f"AlertManager config reloaded - email: {email_enabled}, "
                              f"webhook: {webhook_enabled}, push: {push_enabled}")
        except Exception as e:
            logger.error(f"Error reloading AlertManager configuration: {e}")