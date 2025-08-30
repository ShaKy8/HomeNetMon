import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from collections import defaultdict
from models import db, Alert, Device

logger = logging.getLogger(__name__)

@dataclass
class AlertCorrelationRule:
    """Rule for correlating alerts"""
    alert_types: List[str]
    device_id: Optional[int] = None  # None means any device
    time_window_minutes: int = 60
    max_similar_alerts: int = 3
    escalation_severity: Optional[str] = None
    suppress_duplicates: bool = True

class AlertCorrelationService:
    """Service for correlating and deduplicating alerts"""
    
    def __init__(self, app=None):
        self.app = app
        self.correlation_rules = self._get_default_rules()
        
    def _get_default_rules(self) -> List[AlertCorrelationRule]:
        """Define default correlation rules"""
        return [
            # Optimized anomaly alert correlation with adaptive thresholds
            AlertCorrelationRule(
                alert_types=['anomaly_connectivity_pattern'],
                time_window_minutes=180,  # 3 hours - more responsive
                max_similar_alerts=1,  # Maintain single alert per window
                suppress_duplicates=True
            ),
            AlertCorrelationRule(
                alert_types=['anomaly_uptime_pattern'],
                time_window_minutes=360,  # 6 hours - balanced response
                max_similar_alerts=1,
                suppress_duplicates=True
            ),
            AlertCorrelationRule(
                alert_types=['anomaly_response_time'],
                time_window_minutes=90,   # 1.5 hours - more responsive
                max_similar_alerts=2,    # Allow up to 2 for better visibility
                escalation_severity='medium'  # Escalate to medium first
            ),
            
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
                alert_types=['performance', 'bandwidth_issue', 'cpu_high'],
                time_window_minutes=120,  # 2 hours
                max_similar_alerts=2,    # Allow up to 2 for trending
                suppress_duplicates=True
            ),
            
            # Enhanced security alert correlation
            AlertCorrelationRule(
                alert_types=['security_suspicious_port', 'security_vulnerability', 'security_new_service'],
                time_window_minutes=240,  # 4 hours
                max_similar_alerts=3,    # Allow more security alerts
                suppress_duplicates=True
            ),
            
            # Network-wide correlation rules
            AlertCorrelationRule(
                alert_types=['network_outage', 'gateway_down', 'dns_failure'],
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
            
            # For anomaly alerts, also check for similar messages (more aggressive deduplication)
            if alert_type.startswith('anomaly_') and rule.suppress_duplicates:
                # Check for alerts with very similar messages
                similar_message_alerts = Alert.query.filter(
                    Alert.device_id == device_id,
                    Alert.alert_type == alert_type,
                    Alert.created_at >= cutoff_time,
                    Alert.resolved == False,
                    Alert.message.like(f"%{self._extract_anomaly_pattern(message)}%")
                ).count()
                
                if similar_message_alerts > 0:
                    logger.debug(f"Suppressing duplicate anomaly alert for device {device_id}: {message}")
                    return True
            
            # Check if we exceed the maximum allowed alerts
            if recent_alerts >= rule.max_similar_alerts:
                logger.debug(f"Suppressing alert due to rate limit: {recent_alerts} >= {rule.max_similar_alerts}")
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating suppression rule: {e}")
            return False
    
    def _extract_anomaly_pattern(self, message: str) -> str:
        """Extract the core pattern from an anomaly message for duplicate detection"""
        # For anomaly messages, extract the key pattern
        if "high connection frequency" in message:
            return "high connection frequency"
        elif "unexpected" in message and "uptime" in message:
            return "unexpected uptime"
        elif "response time" in message and "above normal" in message:
            return "response time above normal"
        else:
            # Fallback: use first 30 characters
            return message[:30]
    
    def correlate_and_escalate_alerts(self):
        """Find correlated alerts and escalate severity if needed"""
        if not self.app:
            return
            
        with self.app.app_context():
            try:
                for rule in self.correlation_rules:
                    if rule.escalation_severity:
                        self._check_escalation_by_rule(rule)
                        
            except Exception as e:
                logger.error(f"Error correlating alerts: {e}")
    
    def _check_escalation_by_rule(self, rule: AlertCorrelationRule):
        """Check if alerts should be escalated based on correlation rule"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(minutes=rule.time_window_minutes)
            
            # Group alerts by device
            device_alert_counts = defaultdict(int)
            
            for alert_type in rule.alert_types:
                alerts = Alert.query.filter(
                    Alert.alert_type == alert_type,
                    Alert.created_at >= cutoff_time,
                    Alert.resolved == False
                ).all()
                
                for alert in alerts:
                    device_alert_counts[alert.device_id] += 1
            
            # Check for escalation
            for device_id, count in device_alert_counts.items():
                if count > rule.max_similar_alerts:
                    self._create_escalation_alert(device_id, rule, count)
                    
        except Exception as e:
            logger.error(f"Error checking escalation: {e}")
    
    def _create_escalation_alert(self, device_id: int, rule: AlertCorrelationRule, alert_count: int):
        """Create an escalated alert for correlated issues"""
        try:
            device = Device.query.get(device_id)
            if not device:
                return
                
            # Check if we already have an escalation alert
            existing_escalation = Alert.query.filter(
                Alert.device_id == device_id,
                Alert.alert_type == 'escalated_alert',
                Alert.created_at >= datetime.utcnow() - timedelta(minutes=rule.time_window_minutes),
                Alert.resolved == False
            ).first()
            
            if existing_escalation:
                return  # Don't create duplicate escalation alerts
            
            escalation_alert = Alert(
                device_id=device_id,
                alert_type='escalated_alert',
                severity=rule.escalation_severity,
                message=f"Multiple {'/'.join(rule.alert_types)} alerts detected for {device.display_name} ({alert_count} alerts in {rule.time_window_minutes} minutes)"
            )
            
            db.session.add(escalation_alert)
            db.session.commit()
            
            logger.warning(f"Created escalated alert for device {device.display_name}: {alert_count} alerts")
            
        except Exception as e:
            logger.error(f"Error creating escalation alert: {e}")
            db.session.rollback()
    
    def cleanup_duplicate_alerts(self):
        """Clean up existing duplicate alerts (one-time operation)"""
        if not self.app:
            return
            
        with self.app.app_context():
            try:
                logger.info("Starting duplicate alert cleanup")
                
                # Focus on anomaly alerts which are the main source of duplicates
                anomaly_types = ['anomaly_connectivity_pattern', 'anomaly_uptime_pattern', 'anomaly_response_time']
                
                for alert_type in anomaly_types:
                    cleaned_count = self._cleanup_alerts_by_type(alert_type)
                    logger.info(f"Cleaned up {cleaned_count} duplicate {alert_type} alerts")
                
            except Exception as e:
                logger.error(f"Error during duplicate cleanup: {e}")
                
    def _cleanup_alerts_by_type(self, alert_type: str) -> int:
        """Clean up duplicate alerts of a specific type"""
        try:
            # Get all unresolved alerts of this type, grouped by device
            alerts_by_device = defaultdict(list)
            
            alerts = Alert.query.filter(
                Alert.alert_type == alert_type,
                Alert.resolved == False
            ).order_by(Alert.created_at.desc()).all()
            
            for alert in alerts:
                alerts_by_device[alert.device_id].append(alert)
            
            cleaned_count = 0
            
            # For each device, keep only the most recent alert and resolve the rest
            for device_id, device_alerts in alerts_by_device.items():
                if len(device_alerts) > 1:
                    # Keep the most recent, resolve the rest
                    alerts_to_resolve = device_alerts[1:]  # Skip the first (most recent)
                    
                    for alert in alerts_to_resolve:
                        alert.resolve()
                        cleaned_count += 1
            
            db.session.commit()
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Error cleaning up alerts of type {alert_type}: {e}")
            db.session.rollback()
            return 0
    
    def get_correlation_stats(self) -> Dict:
        """Get statistics about alert correlation"""
        if not self.app:
            return {}
            
        with self.app.app_context():
            try:
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
                
                stats = {
                    'total_alerts_24h': Alert.query.filter(Alert.created_at >= cutoff_time).count(),
                    'active_alerts': Alert.query.filter(Alert.resolved == False).count(),
                    'alerts_by_type': {},
                    'devices_with_multiple_alerts': 0
                }
                
                # Count by type
                for alert_type in ['anomaly_connectivity_pattern', 'anomaly_uptime_pattern', 'device_down', 'high_latency']:
                    count = Alert.query.filter(
                        Alert.alert_type == alert_type,
                        Alert.resolved == False
                    ).count()
                    stats['alerts_by_type'][alert_type] = count
                
                # Count devices with multiple active alerts
                device_alert_counts = db.session.query(Alert.device_id, db.func.count(Alert.id)).filter(
                    Alert.resolved == False
                ).group_by(Alert.device_id).having(db.func.count(Alert.id) > 1).all()
                
                stats['devices_with_multiple_alerts'] = len(device_alert_counts)
                
                return stats
                
            except Exception as e:
                logger.error(f"Error getting correlation stats: {e}")
                return {}
    
    def detect_network_wide_issues(self) -> List[Dict]:
        """Detect network-wide issues that affect multiple devices"""
        if not self.app:
            return []
            
        with self.app.app_context():
            try:
                issues = []
                cutoff_time = datetime.utcnow() - timedelta(minutes=30)
                
                # Check for widespread connectivity issues
                down_devices = Alert.query.filter(
                    Alert.alert_type == 'device_down',
                    Alert.created_at >= cutoff_time,
                    Alert.resolved == False
                ).count()
                
                total_monitored = Device.query.filter_by(is_monitored=True).count()
                if total_monitored > 0:
                    down_percentage = (down_devices / total_monitored) * 100
                    
                    if down_percentage > 25:  # More than 25% of devices down
                        issues.append({
                            'type': 'network_outage',
                            'severity': 'critical' if down_percentage > 50 else 'high',
                            'affected_devices': down_devices,
                            'total_devices': total_monitored,
                            'percentage': round(down_percentage, 1),
                            'message': f'Potential network outage: {down_devices}/{total_monitored} devices down ({down_percentage:.1f}%)'
                        })
                
                # Check for widespread latency issues
                high_latency_devices = Alert.query.filter(
                    Alert.alert_type == 'high_latency',
                    Alert.created_at >= cutoff_time,
                    Alert.resolved == False
                ).count()
                
                if high_latency_devices > 5:  # More than 5 devices with high latency
                    issues.append({
                        'type': 'network_degradation',
                        'severity': 'medium',
                        'affected_devices': high_latency_devices,
                        'message': f'Network performance degradation: {high_latency_devices} devices experiencing high latency'
                    })
                
                return issues
                
            except Exception as e:
                logger.error(f"Error detecting network-wide issues: {e}")
                return []
    
    def get_alert_trends(self, hours: int = 24) -> Dict:
        """Get alert trends over specified time period"""
        if not self.app:
            return {}
            
        with self.app.app_context():
            try:
                cutoff_time = datetime.utcnow() - timedelta(hours=hours)
                
                # Get hourly alert counts
                hourly_counts = []
                for i in range(hours):
                    hour_start = datetime.utcnow() - timedelta(hours=i+1)
                    hour_end = datetime.utcnow() - timedelta(hours=i)
                    
                    count = Alert.query.filter(
                        Alert.created_at >= hour_start,
                        Alert.created_at < hour_end
                    ).count()
                    
                    hourly_counts.append({
                        'hour': hour_start.strftime('%H:00'),
                        'count': count
                    })
                
                # Calculate trend
                recent_6h = sum(h['count'] for h in hourly_counts[:6])
                previous_6h = sum(h['count'] for h in hourly_counts[6:12])
                
                trend = 'stable'
                if recent_6h > previous_6h * 1.5:
                    trend = 'increasing'
                elif recent_6h < previous_6h * 0.5:
                    trend = 'decreasing'
                
                return {
                    'hourly_counts': list(reversed(hourly_counts)),
                    'trend': trend,
                    'recent_6h_total': recent_6h,
                    'previous_6h_total': previous_6h,
                    'total_24h': sum(h['count'] for h in hourly_counts)
                }
                
            except Exception as e:
                logger.error(f"Error getting alert trends: {e}")
                return {}
    
    def optimize_thresholds_based_on_history(self) -> Dict:
        """Analyze alert history to suggest threshold optimizations"""
        if not self.app:
            return {}
            
        with self.app.app_context():
            try:
                recommendations = {}
                cutoff_time = datetime.utcnow() - timedelta(days=7)
                
                # Analyze false positive patterns
                resolved_quickly = Alert.query.filter(
                    Alert.created_at >= cutoff_time,
                    Alert.resolved == True,
                    Alert.resolved_at.isnot(None)
                ).all()
                
                quick_resolutions = [
                    alert for alert in resolved_quickly
                    if alert.resolved_at and 
                    (alert.resolved_at - alert.created_at).total_seconds() < 300  # Resolved within 5 minutes
                ]
                
                if len(quick_resolutions) > 10:
                    most_common_quick = defaultdict(int)
                    for alert in quick_resolutions:
                        most_common_quick[alert.alert_type] += 1
                    
                    for alert_type, count in most_common_quick.items():
                        if count > 3:
                            recommendations[alert_type] = {
                                'issue': 'high_false_positive_rate',
                                'quick_resolutions': count,
                                'suggestion': 'Consider increasing threshold or extending validation period'
                            }
                
                return recommendations
                
            except Exception as e:
                logger.error(f"Error optimizing thresholds: {e}")
                return {}