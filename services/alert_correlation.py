import logging
from datetime import datetime, timedelta
from typing import List, Optional
from dataclasses import dataclass
from models import Alert

logger = logging.getLogger(__name__)

@dataclass
class AlertCorrelationRule:
    """Rule for correlating alerts"""
    alert_types: List[str]
    device_id: Optional[int] = None  # None means any device
    time_window_minutes: int = 60
    max_similar_alerts: int = 3
    suppress_duplicates: bool = True

class AlertCorrelationService:
    """Per-type rate windows consulted by AlertManager.create_alert (the only caller)."""

    def __init__(self, app=None):
        self.app = app
        self.correlation_rules = self._get_default_rules()

    def _get_default_rules(self) -> List[AlertCorrelationRule]:
        """Define default correlation rules"""
        return [
            # Smart device status correlation with flap detection
            AlertCorrelationRule(
                alert_types=['device_down'],
                time_window_minutes=60,   # 1 hour window
                max_similar_alerts=1,    # Single down alert per hour
                suppress_duplicates=True
            ),
            AlertCorrelationRule(
                alert_types=['device_recovery'],
                time_window_minutes=30,   # 30 minutes for recovery
                max_similar_alerts=2,    # Allow multiple recovery notifications
                suppress_duplicates=False
            ),

            # Adaptive high latency correlation
            AlertCorrelationRule(
                alert_types=['high_latency'],
                time_window_minutes=45,   # 45 minutes - more responsive
                max_similar_alerts=2,    # Allow 2 alerts for visibility
                suppress_duplicates=True
            ),

            # Performance alert correlation with burst detection
            AlertCorrelationRule(
                alert_types=['performance'],
                time_window_minutes=120,  # 2 hours
                max_similar_alerts=2,    # Allow up to 2 for trending
                suppress_duplicates=True
            ),

            # Enhanced security alert correlation
            AlertCorrelationRule(
                alert_types=['security_suspicious_port', 'security_new_service'],
                time_window_minutes=240,  # 4 hours
                max_similar_alerts=3,    # Allow more security alerts
                suppress_duplicates=True
            ),

            # Network-wide correlation rules
            AlertCorrelationRule(
                alert_types=['wan_down', 'gateway_down'],
                time_window_minutes=30,   # Short window for critical network issues
                max_similar_alerts=1,    # Single alert for network-wide issues
                suppress_duplicates=True
            )
        ]

    def should_suppress_alert(self, alert_type: str, device_id: int, message: str) -> bool:
        """Check if an alert should be suppressed due to correlation rules"""
        if not self.app:
            return False

        with self.app.app_context():
            try:
                # Find applicable rules
                applicable_rules = [
                    rule for rule in self.correlation_rules
                    if alert_type in rule.alert_types and
                    (rule.device_id is None or rule.device_id == device_id)
                ]

                for rule in applicable_rules:
                    if self._should_suppress_by_rule(alert_type, device_id, message, rule):
                        logger.info(f"Suppressing alert {alert_type} for device {device_id} due to correlation rule")
                        return True

                return False

            except Exception as e:
                logger.error(f"Error checking alert suppression: {e}")
                return False

    def _should_suppress_by_rule(self, alert_type: str, device_id: int, message: str, rule: AlertCorrelationRule) -> bool:
        """Check if alert should be suppressed by specific rule"""
        try:
            # Get recent alerts of same type for this device
            cutoff_time = datetime.utcnow() - timedelta(minutes=rule.time_window_minutes)

            recent_alerts = Alert.query.filter(
                Alert.device_id == device_id,
                Alert.alert_type == alert_type,
                Alert.created_at >= cutoff_time,
                Alert.resolved == False
            ).count()

            # Check if we exceed the maximum allowed alerts
            if recent_alerts >= rule.max_similar_alerts:
                logger.debug(f"Suppressing alert due to rate limit: {recent_alerts} >= {rule.max_similar_alerts}")
                return True

            return False

        except Exception as e:
            logger.error(f"Error evaluating suppression rule: {e}")
            return False
