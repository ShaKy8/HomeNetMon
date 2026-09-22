import time
import threading
import logging
import smtplib
import requests
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from models import db, Device, Alert, MonitoringData, Configuration, PerformanceMetrics
from config import Config
from constants import ALERT_STARTUP_GRACE_SECONDS, DEFAULT_DEVICE_DOWN_MINUTES, DEFAULT_HIGH_LATENCY_MS
from monitoring.notification_policy import NotificationPolicy
from services.push_notifications import push_service

logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self, app=None):
        self.app = app
        self.is_running = False
        self._stop_event = threading.Event()
        self.correlation_service = None
        self._started_at = None
        # Settings (device_down_threshold_minutes, high_latency_threshold_ms) override the
        # regular / latency values at runtime; these are the code defaults.
        self.alert_thresholds = {
            'device_down_minutes_critical': 15,
            'device_down_minutes_regular': DEFAULT_DEVICE_DOWN_MINUTES,
            'high_latency_ms': DEFAULT_HIGH_LATENCY_MS,
            'consecutive_failures_required': 3,
        }

    @staticmethod
    def runtime_setting(key, default):
        """Runtime Configuration value with fallback (must run inside an app context)."""
        value = Configuration.get_value(key)
        return default if value in (None, '') else value

    def runtime_int(self, key, default):
        try:
            return int(self.runtime_setting(key, default))
        except (TypeError, ValueError):
            return default

    def is_critical_device(self, device):
        """Critical infrastructure (one definition: Device.is_critical)."""
        return device.is_critical

    def _in_startup_grace(self):
        """True for ALERT_STARTUP_GRACE_SECONDS after start_monitoring(): recoveries are recorded, not pushed."""
        return self._started_at is not None and \
            (datetime.utcnow() - self._started_at).total_seconds() < ALERT_STARTUP_GRACE_SECONDS

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
                # Settings UI writes device_down_threshold_minutes; critical devices alert sooner.
                regular_minutes = self.runtime_int('device_down_threshold_minutes',
                                                   self.alert_thresholds['device_down_minutes_regular'])
                critical_minutes = min(regular_minutes, self.alert_thresholds['device_down_minutes_critical'])

                for device in all_devices:
                    if not device.alerts_on_down:
                        continue        # phones, Apple devices, unknowns: presence is tracked, silence is policy
                    # Determine threshold based on device criticality
                    threshold_minutes = critical_minutes if self.is_critical_device(device) else regular_minutes

                    cutoff_time = datetime.utcnow() - timedelta(minutes=threshold_minutes)

                    # Only alert if device hasn't been seen AND has consecutive failures AND has poor recent uptime.
                    # Short-circuit: the cheap last_seen check gates the two DB-heavy checks, and each
                    # heavy check runs at most once per device per cycle.
                    not_seen_recently = bool(device.last_seen and device.last_seen < cutoff_time)
                    consecutive = None
                    device_uptime = None
                    should_alert = False
                    if not_seen_recently:
                        consecutive = self.has_consecutive_failures(device, consecutive_failures_required)
                        if consecutive:
                            try:
                                device_uptime = device.uptime_percentage()
                            except Exception:
                                device_uptime = 100  # Default to good uptime if calculation fails
                            should_alert = device_uptime < 90  # Only alert if recent uptime is very poor (< 90%)

                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Alert decision for {device.display_name}: not_seen_recently={not_seen_recently}, "
                                     f"consecutive_failures={consecutive}, uptime={device_uptime}, should_alert={should_alert}")

                    if should_alert:
                        device_type = "critical" if self.is_critical_device(device) else "regular"
                        message = (f"{device_type.title()} device {device.display_name} ({device.ip_address}) has been down "
                                   f"for over {threshold_minutes} minutes with {consecutive_failures_required}+ consecutive "
                                   f"monitoring failures")
                        severity = 'critical' if self.is_critical_device(device) else 'warning'
                        # create_alert() dedups on the open alert and applies suppression rules
                        alert = self.create_alert(device.id, 'device_down', severity, message)
                        if alert is not None:
                            logger.warning(f"ALERT CREATED: Device down alert for {device.display_name} (threshold: {threshold_minutes}min, type: {device_type}, last_seen: {device.last_seen}, cutoff: {cutoff_time})")

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
                threshold_ms = self.runtime_int('high_latency_threshold_ms', self.alert_thresholds['high_latency_ms'])

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
                    avg_latency = db.session.query(
                        db.func.avg(MonitoringData.response_time)
                    ).filter(
                        MonitoringData.device_id == device.id,
                        MonitoringData.timestamp >= cutoff_time,
                        MonitoringData.response_time.isnot(None)
                    ).scalar() or 0
                    message = f"Device {device.display_name} ({device.ip_address}) has high latency: {avg_latency:.0f}ms average"
                    # create_alert() dedups on the open alert, applies suppression rules and notifies once
                    alert = self.create_alert(device.id, 'high_latency', 'warning', message)
                    if alert is not None:
                        logger.warning(f"High latency alert created for {device.display_name}")

            except Exception as e:
                logger.error(f"Error checking high latency alerts: {e}")
                db.session.rollback()

    def _create_recovery_alert(self, down_alert, device):
        """One informational, already-resolved device_recovery alert per device_down alert,
        created when resolve_alerts() closes the down alert. Notified like any other alert
        (send_alert_notifications pushes "Device Online" once); there is no second,
        dedicated push any more."""
        existing = Alert.query.filter(
            Alert.device_id == device.id,
            Alert.alert_type == 'device_recovery',
            Alert.created_at >= down_alert.created_at,
        ).first()
        if existing:
            return None
        recovery_alert = self.create_alert(
            device.id, 'device_recovery', 'info',
            f"Device {device.display_name} ({device.ip_address}) is back online after being down",
            notify=not self._in_startup_grace(), resolved=True)
        if recovery_alert is not None:
            logger.info(f"Device recovery alert created for {device.display_name}")
        return recovery_alert

    def resolve_alerts(self, dry_run=False):
        """Resolve open alerts whose condition has cleared.

        Runs once per AlertManager cycle (every 10 minutes) inside an app
        context. This is the single owner of alert auto-resolution; the old
        alert_auto_resolver / alert_retention_policy services were invoked
        without an app context and never completed a cycle.

        Rules:
        - device_down: the device has been seen since the alert was raised; the single
          device_recovery alert (and "device online" push) is created here.
        - high_latency: no sample above the latency threshold in the last 5 minutes.
        - performance: the device is unmonitored or gone, has produced no
          PerformanceMetrics row in 24 h, or its latest scores are back above the
          recovery thresholds used by services/performance_monitor.py.
        - new_device (informational): older than 24 h.
        - stale: any open alert older than ``alert_max_open_days`` (default 30).

        Returns a dict of counts per rule. With ``dry_run=True`` nothing is
        written or emitted; the counts say what a real run would do.
        """
        counts = {'device_down': 0, 'high_latency': 0, 'performance': 0, 'new_device': 0, 'stale': 0}
        if not self.app:
            logger.error("No Flask app context available for alert resolving")
            return counts

        with self.app.app_context():
            try:
                from sqlalchemy.orm import joinedload

                now = datetime.utcnow()
                recent_time = now - timedelta(minutes=5)
                max_open_days = max(1, self.runtime_int('alert_max_open_days', 30))
                stale_cutoff = now - timedelta(days=max_open_days)
                resolved_ids = set()

                def _resolve(alert, rule, note=None):
                    if alert.id in resolved_ids:
                        return
                    resolved_ids.add(alert.id)
                    counts[rule] += 1
                    if dry_run:
                        return
                    alert.resolved = True
                    alert.resolved_at = now
                    if note and note not in (alert.message or ''):
                        alert.message = f"{alert.message} {note}".strip()
                    self._emit_alert_update(alert, 'resolved')

                def _open(alert_type):
                    return Alert.query.options(joinedload(Alert.device)).filter(
                        Alert.alert_type == alert_type,
                        Alert.resolved == False,
                        Alert.created_at >= stale_cutoff,
                    ).all()

                # device_down: the device has been seen (ping or ARP) since the alert was raised
                for alert in _open('device_down'):
                    device = alert.device
                    if device and device.last_seen and alert.created_at and device.last_seen > alert.created_at:
                        _resolve(alert, 'device_down')
                        logger.info(f"ALERT RESOLVED: Device down alert for {device.display_name}")
                        if not dry_run:
                            self._create_recovery_alert(alert, device)

                # high_latency: no recent sample above threshold
                threshold_ms = self.runtime_int('high_latency_threshold_ms', self.alert_thresholds['high_latency_ms'])
                for alert in _open('high_latency'):
                    device = alert.device
                    if not device:
                        continue
                    recent_high = MonitoringData.query.filter(
                        MonitoringData.device_id == device.id,
                        MonitoringData.timestamp >= recent_time,
                        MonitoringData.response_time > threshold_ms,
                    ).count()
                    if recent_high == 0:
                        _resolve(alert, 'high_latency')
                        logger.info(f"Resolved high latency alert for {device.display_name}")

                # performance: scores recovered, or nothing left to measure
                recovery_threshold = float(self.runtime_setting('performance_alert_recovery_threshold', 40))
                metrics_cutoff = now - timedelta(hours=24)
                for alert in _open('performance'):
                    device = alert.device
                    if device is None or not device.is_monitored:
                        _resolve(alert, 'performance', '[auto-resolved: device no longer monitored]')
                        continue
                    latest = PerformanceMetrics.query.filter_by(device_id=device.id)\
                        .order_by(PerformanceMetrics.timestamp.desc()).first()
                    if latest is None or latest.timestamp is None or latest.timestamp < metrics_cutoff:
                        _resolve(alert, 'performance', '[auto-resolved: no recent performance data]')
                        continue
                    subtype = alert.alert_subtype or ''
                    if subtype == 'performance_responsiveness':
                        recovered = (latest.responsiveness_score or 0) >= 25
                    elif subtype == 'performance_reliability':
                        recovered = (latest.reliability_score or 0) >= 30
                    else:
                        recovered = (latest.health_score or 0) >= recovery_threshold
                    if recovered:
                        _resolve(alert, 'performance')
                        logger.info(f"Resolved performance alert for {device.display_name} (health {latest.health_score})")

                # new_device: informational, self-expires after a day
                for alert in _open('new_device'):
                    if alert.created_at and alert.created_at < now - timedelta(hours=24):
                        _resolve(alert, 'new_device')

                # stale: nothing should stay open for more than alert_max_open_days
                stale_alerts = Alert.query.filter(
                    Alert.resolved == False,
                    Alert.created_at < stale_cutoff,
                ).all()
                for alert in stale_alerts:
                    _resolve(alert, 'stale', '[auto-resolved: stale]')

                if dry_run:
                    db.session.rollback()
                else:
                    db.session.commit()

                total = sum(counts.values())
                if total:
                    logger.info(f"Alert resolution{' (dry run)' if dry_run else ''}: {counts}")

            except Exception as e:
                logger.error(f"Error resolving alerts: {e}")
                db.session.rollback()

        return counts

    def send_email_alert(self, alert):
        """Send email notification for alert"""
        try:
            # Recipients/sender may be set in Settings (runtime) or .env (fallback).
            from_email = self.runtime_setting('alert_from_email', Config.ALERT_FROM_EMAIL)
            to_setting = self.runtime_setting('alert_to_emails', None)
            to_emails = ([e.strip() for e in to_setting.split(',') if e.strip()]
                         if isinstance(to_setting, str) else (Config.ALERT_TO_EMAILS or []))
            smtp_server = self.runtime_setting('smtp_server', Config.SMTP_SERVER)
            smtp_port = self.runtime_int('smtp_port', Config.SMTP_PORT or 587)
            smtp_username = self.runtime_setting('smtp_username', Config.SMTP_USERNAME)
            smtp_password = self.runtime_setting('smtp_password', Config.SMTP_PASSWORD)
            smtp_use_tls = str(self.runtime_setting('smtp_use_tls', Config.SMTP_USE_TLS)).lower() == 'true'
            if not all([smtp_server, smtp_username, smtp_password, from_email, to_emails]):
                logger.debug("Email configuration incomplete, skipping email alert")
                return False

            # Create message
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = ', '.join(to_emails)
            msg['Subject'] = f"[HomeNetMon] {alert.severity.upper()}: {getattr(alert, 'title', alert.alert_type)}"

            # Email body
            body = f"""
HomeNetMon Alert

Device: {alert.device.display_name} ({alert.device.ip_address})
Alert Type: {alert.alert_type.replace('_', ' ').title()}
Severity: {alert.severity.upper()}
Time: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}

Message: {alert.message}

Dashboard: {Config.BASE_URL}
Device Details: {Config.BASE_URL}/device/{alert.device.id}

This is an automated message from HomeNetMon.
            """

            msg.attach(MIMEText(body, 'plain'))

            # Send email
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=15)
            if smtp_use_tls:
                server.starttls()
            server.login(smtp_username, smtp_password)
            text = msg.as_string()
            server.sendmail(from_email, to_emails, text)
            server.quit()

            logger.info(f"Email alert sent for {alert.device.display_name}")
            return True

        except Exception as e:
            logger.error(f"Error sending email alert: {e}")
            return False

    def send_webhook_alert(self, alert):
        """Send webhook notification for alert"""
        try:
            webhook_url = self.runtime_setting('alert_webhook_url', Config.WEBHOOK_URL)
            if not webhook_url:
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
                'dashboard_url': f"{Config.BASE_URL}",
                'device_url': f"{Config.BASE_URL}/device/{alert.device.id}"
            }

            response = requests.post(
                webhook_url,
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

    def send_discord_alert(self, alert, webhook_url=None):
        """Send alert via Discord webhook.

        Configured via the ``discord_webhook_url`` runtime setting (Settings UI
        or ``Configuration.set_value``); ``webhook_url`` overrides it (used by
        the Settings "send test" button). Best-effort; logs and returns False on
        any failure so a Discord outage never blocks the dispatch chain.
        """
        try:
            webhook_url = (webhook_url or Configuration.get_value('discord_webhook_url', '') or '').strip()
            if not webhook_url:
                logger.debug("No Discord webhook URL configured, skipping Discord alert")
                return False

            colors = {
                'critical': 0xE74C3C,  # red
                'warning':  0xF39C12,  # orange
                'info':     0x3498DB,  # blue
            }
            embed = {
                'title': f"{alert.severity.title()}: {getattr(alert, 'title', alert.alert_type)}",
                'description': alert.message,
                'color': colors.get(alert.severity, 0x95A5A6),
                'timestamp': alert.created_at.isoformat() + 'Z',
                'fields': [
                    {'name': 'Device', 'value': alert.device.display_name, 'inline': True},
                    {'name': 'IP',     'value': alert.device.ip_address,   'inline': True},
                ],
                'footer': {'text': f"HomeNetMon · alert #{alert.id}"},
            }
            response = requests.post(
                webhook_url,
                json={'embeds': [embed]},
                timeout=Config.WEBHOOK_TIMEOUT,
            )
            # Discord returns 204 No Content on success.
            if response.status_code in (200, 204):
                logger.info(f"Discord alert sent for {alert.device.display_name}")
                return True
            logger.error(
                f"Discord alert failed with status {response.status_code}: "
                f"{response.text[:200]}"
            )
            return False
        except Exception as e:
            logger.error(f"Error sending Discord alert: {e}")
            return False

    def send_alert_notifications(self, alert):
        """Notify every enabled channel about ``alert`` if the notification policy allows it.

        The alert row already exists; this only decides who hears about it. The outcome
        is written back to the alert (notification_status: sent / failed / none /
        suppressed) so the Alerts page can show it.
        """
        try:
            allowed, reason = NotificationPolicy.load().allows(alert.alert_type, alert.severity)
            if not allowed:
                alert.notification_status = 'suppressed'
                db.session.commit()
                logger.info(f"Notification for {alert.alert_type} on device {alert.device_id} not sent: {reason}")
                return False

            channels = {
                'email': Configuration.get_value('alert_email_enabled', 'false').lower() == 'true',
                'webhook': Configuration.get_value('alert_webhook_enabled', 'false').lower() == 'true',
                'push': Configuration.get_value('push_notifications_enabled', 'false').lower() == 'true',
                'discord': Configuration.get_value('alert_discord_enabled', 'false').lower() == 'true',
            }
            senders = {'email': self.send_email_alert, 'webhook': self.send_webhook_alert,
                       'push': self.send_push_notification, 'discord': self.send_discord_alert}
            results = {}
            for name, enabled in channels.items():
                if not enabled:
                    continue
                try:
                    results[name] = bool(senders[name](alert))
                except Exception as e:
                    logger.error(f"{name} notification failed for alert {alert.id}: {e}")
                    results[name] = False

            if not results:
                alert.notification_status = 'none'
            elif any(results.values()):
                alert.notification_status = 'sent'
                alert.notification_sent = True
                alert.notification_count = (alert.notification_count or 0) + 1
                alert.last_notification_at = datetime.utcnow()
            else:
                alert.notification_status = 'failed'
            db.session.commit()
            return alert.notification_status == 'sent'

        except Exception as e:
            logger.error(f"Error sending alert notifications: {e}")
            return False

    # alert_type -> (title prefix, ntfy priority, tags); severity may raise the priority
    PUSH_STYLE = {
        'device_down': ('🔴 Device Offline', 'high', 'warning,red_circle,rotating_light'),
        'device_recovery': ('✅ Device Online', 'default', 'white_check_mark,green_circle'),
        'high_latency': ('⚠️ High Latency', 'default', 'warning,yellow_circle,hourglass_not_done'),
        'new_device': ('🆕 New Device', 'default', 'new,blue_circle,computer'),
        'security_new_service': ('🔵 New open port', 'default', 'shield,lock'),
        'security_suspicious_port': ('🟡 Suspicious port', 'high', 'shield,warning,lock'),
        'wan_down': ('🌐 Internet down', 'urgent', 'rotating_light,globe_with_meridians'),
        'gateway_down': ('🌐 Gateway unreachable', 'urgent', 'rotating_light,globe_with_meridians'),
        'wan_recovery': ('🌐 Internet restored', 'default', 'white_check_mark,globe_with_meridians'),
        'performance': ('📉 Performance degraded', 'default', 'chart_with_downwards_trend'),
    }

    @staticmethod
    def _click_url(alert):
        """Where a tap on the push lands: the device page, or the page that owns the alert type."""
        base = (Config.BASE_URL or '').rstrip('/')
        if alert.alert_type.startswith('security_'):
            return f"{base}/security"
        if alert.alert_type in ('wan_down', 'wan_recovery', 'gateway_down'):
            return f"{base}/alerts"
        return f"{base}/device/{alert.device_id}" if alert.device_id else f"{base}/alerts"

    def send_push_notification(self, alert):
        """One ntfy push per alert, styled by type, deep-linked, logged with the alert id."""
        try:
            push_service.update_config_from_database()     # Settings win over .env
            if not push_service.is_configured():
                logger.debug("Push notifications not configured")
                return False
            device = alert.device
            name = device.display_name if device else 'network'
            prefix, priority, tags = self.PUSH_STYLE.get(alert.alert_type, ('🚨 Alert', 'default', 'warning,exclamation'))
            if alert.severity == 'critical' and priority in ('default', 'low'):
                priority = 'high'
            success = push_service.send_notification(
                title=f"{prefix}: {name}",
                message=alert.message,
                priority=priority,
                tags=tags,
                click_url=self._click_url(alert),
                device_id=alert.device_id,
                alert_id=alert.id,
                notification_type=alert.alert_type,
            )
            if success:
                logger.info(f"Push notification sent for alert: {alert.alert_type}")
            else:
                logger.error(f"Failed to send push notification for alert: {alert.alert_type}")
            return success
        except Exception as e:
            logger.error(f"Error sending push notification: {e}")
            return False

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
        self._started_at = datetime.utcnow()
        logger.info("Starting alert monitoring")

        # Clean up orphaned recovery alerts on startup. (Resolved-alert retention
        # is handled by services/retention.py.)
        self.cleanup_orphaned_recovery_alerts()

        from core.health import record_heartbeat
        while not self._stop_event.is_set():
            record_heartbeat('AlertManager')
            try:
                # Check if alert generation is paused
                if self.is_alert_generation_paused():
                    logger.debug("Alert generation is paused, skipping alert checks")
                else:
                    # Check for new alerts
                    self.check_device_down_alerts()
                    self.check_high_latency_alerts()

                # Always resolve alerts (even when paused)
                self.resolve_alerts()

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

    def create_alert(self, device_id, alert_type, severity, message, subtype=None, notify=True, resolved=False):
        """Create an alert through the shared pipeline: dedup, suppression rules,
        correlation, priority, commit, notifications (per NotificationPolicy), WebSocket emit.

        Returns the new Alert, or None if an identical unresolved alert exists or a
        rule suppressed it. Must be called inside an app context. Every producer
        (device down/latency/recovery, new device, performance, security, WAN) uses
        this so suppression windows, dedup and the notification policy apply uniformly.
        ``resolved=True`` records an informational, already-closed alert (recoveries).
        """
        existing = Alert.query.filter_by(device_id=device_id, alert_type=alert_type,
                                         alert_subtype=subtype, resolved=False).first()
        if existing:
            logger.debug(f"Alert {alert_type}/{subtype} already active for device {device_id}")
            return None
        if not self._should_create_alert(alert_type, device_id, message, severity):
            logger.debug(f"Alert {alert_type}/{subtype} for device {device_id} suppressed")
            return None

        alert = Alert(device_id=device_id, alert_type=alert_type, alert_subtype=subtype,
                      severity=severity, message=message)
        if resolved:
            alert.resolved = True
            alert.resolved_at = datetime.utcnow()
        try:
            alert.calculate_and_update_priority(self.app)
        except Exception as e:
            logger.debug(f"Priority calculation skipped: {e}")
        db.session.add(alert)
        db.session.commit()

        if notify:
            try:
                self.send_alert_notifications(alert)
            except Exception as e:
                logger.error(f"Notification dispatch failed for alert {alert.id}: {e}")
        self._emit_alert_update(alert, 'created')
        return alert

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
