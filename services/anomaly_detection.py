import numpy as np
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from models import db, Device, MonitoringData
from sqlalchemy import func, and_
import json

logger = logging.getLogger(__name__)

@dataclass
class AnomalyAlert:
    """Represents an anomaly detection alert"""
    device_id: int
    device_name: str
    anomaly_type: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    confidence: float  # 0.0 to 1.0
    message: str
    detected_at: datetime
    baseline_value: Optional[float] = None
    current_value: Optional[float] = None
    threshold: Optional[float] = None

class AnomalyDetectionEngine:
    """AI-powered anomaly detection for network monitoring"""
    
    def __init__(self, app=None):
        self.app = app
        self.running = False
        self.detection_interval = 300  # 5 minutes
        self.rule_engine_service = None
        
        # Configuration
        self.min_data_points = 20  # Minimum data points needed for baseline
        self.baseline_hours = 168  # 7 days for baseline calculation
        self.anomaly_threshold = 2.5  # Standard deviations for anomaly detection
        
        # Anomaly detection settings per metric
        self.detection_settings = {
            'response_time': {
                'enabled': True,
                'threshold_multiplier': 2.0,
                'min_change_threshold': 50,  # ms
                'severity_thresholds': {
                    'low': 1.5,
                    'medium': 2.0, 
                    'high': 3.0,
                    'critical': 4.0
                }
            },
            'uptime_pattern': {
                'enabled': True,
                'unexpected_down_threshold': 0.8,  # Confidence threshold
                'unexpected_up_threshold': 0.8
            },
            'connectivity_pattern': {
                'enabled': True,
                'unusual_pattern_threshold': 0.7
            }
        }
    
    def start_monitoring(self):
        """Start the anomaly detection monitoring loop"""
        if self.running:
            logger.warning("Anomaly detection already running")
            return
            
        self.running = True
        logger.info("Starting anomaly detection engine")
        
        import threading
        import time
        
        def detection_loop():
            while self.running:
                try:
                    self.run_detection_cycle()
                    time.sleep(self.detection_interval)
                except Exception as e:
                    logger.error(f"Error in anomaly detection cycle: {e}")
                    time.sleep(60)  # Wait 1 minute on error
        
        detection_thread = threading.Thread(
            target=detection_loop,
            daemon=True,
            name='AnomalyDetection'
        )
        detection_thread.start()
        
    def stop_monitoring(self):
        """Stop the anomaly detection monitoring"""
        self.running = False
        logger.info("Anomaly detection engine stopped")
    
    def run_detection_cycle(self):
        """Run a complete anomaly detection cycle"""
        logger.info("Running anomaly detection cycle")
        
        if not self.app:
            logger.error("No Flask app context available")
            return
            
        with self.app.app_context():
            devices = Device.query.filter_by(is_monitored=True).all()
            anomalies = []
            
            for device in devices:
                try:
                    device_anomalies = self.detect_device_anomalies(device)
                    anomalies.extend(device_anomalies)
                except Exception as e:
                    logger.error(f"Error detecting anomalies for device {device.id}: {e}")
            
            if anomalies:
                logger.info(f"Detected {len(anomalies)} anomalies")
                self.process_anomalies(anomalies)
            else:
                logger.info("No anomalies detected")
    
    def detect_device_anomalies(self, device: Device) -> List[AnomalyAlert]:
        """Detect anomalies for a specific device"""
        anomalies = []
        
        # Get baseline data (last 7 days)
        baseline_start = datetime.utcnow() - timedelta(hours=self.baseline_hours)
        recent_start = datetime.utcnow() - timedelta(hours=1)  # Last hour for current analysis
        
        # Response time anomaly detection
        if self.detection_settings['response_time']['enabled']:
            response_anomaly = self.detect_response_time_anomaly(
                device, baseline_start, recent_start
            )
            if response_anomaly:
                anomalies.append(response_anomaly)
        
        # Uptime pattern anomaly detection
        if self.detection_settings['uptime_pattern']['enabled']:
            uptime_anomaly = self.detect_uptime_pattern_anomaly(
                device, baseline_start, recent_start
            )
            if uptime_anomaly:
                anomalies.append(uptime_anomaly)
        
        # Connectivity pattern detection
        if self.detection_settings['connectivity_pattern']['enabled']:
            connectivity_anomaly = self.detect_connectivity_pattern_anomaly(
                device, baseline_start, recent_start
            )
            if connectivity_anomaly:
                anomalies.append(connectivity_anomaly)
        
        return anomalies
    
    def detect_response_time_anomaly(self, device: Device, baseline_start: datetime, recent_start: datetime) -> Optional[AnomalyAlert]:
        """Detect response time anomalies using statistical analysis"""
        
        # Get baseline response times (successful pings only)
        baseline_query = db.session.query(MonitoringData.response_time).filter(
            and_(
                MonitoringData.device_id == device.id,
                MonitoringData.timestamp >= baseline_start,
                MonitoringData.timestamp < recent_start,
                MonitoringData.response_time.isnot(None),
                MonitoringData.response_time > 0
            )
        ).all()
        
        if len(baseline_query) < self.min_data_points:
            return None  # Not enough data for baseline
        
        baseline_times = [r[0] for r in baseline_query]
        baseline_mean = np.mean(baseline_times)
        baseline_std = np.std(baseline_times)
        
        if baseline_std == 0:
            return None  # No variation in baseline
        
        # Get recent response times
        recent_query = db.session.query(MonitoringData.response_time).filter(
            and_(
                MonitoringData.device_id == device.id,
                MonitoringData.timestamp >= recent_start,
                MonitoringData.response_time.isnot(None),
                MonitoringData.response_time > 0
            )
        ).all()
        
        if not recent_query:
            return None
        
        recent_times = [r[0] for r in recent_query]
        recent_mean = np.mean(recent_times)
        
        # Calculate z-score
        z_score = abs(recent_mean - baseline_mean) / baseline_std
        
        # Check if it's an anomaly
        settings = self.detection_settings['response_time']
        if z_score < settings['threshold_multiplier']:
            return None
        
        # Check minimum change threshold
        change_ms = abs(recent_mean - baseline_mean)
        if change_ms < settings['min_change_threshold']:
            return None
        
        # Determine severity
        severity = 'low'
        for sev, threshold in settings['severity_thresholds'].items():
            if z_score >= threshold:
                severity = sev
        
        confidence = min(z_score / 4.0, 1.0)  # Cap at 1.0
        
        direction = "increased" if recent_mean > baseline_mean else "decreased"
        message = f"Response time {direction} significantly from {baseline_mean:.1f}ms to {recent_mean:.1f}ms (z-score: {z_score:.2f})"
        
        return AnomalyAlert(
            device_id=device.id,
            device_name=device.display_name,
            anomaly_type='response_time',
            severity=severity,
            confidence=confidence,
            message=message,
            detected_at=datetime.utcnow(),
            baseline_value=baseline_mean,
            current_value=recent_mean,
            threshold=baseline_mean + (settings['threshold_multiplier'] * baseline_std)
        )
    
    def detect_uptime_pattern_anomaly(self, device: Device, baseline_start: datetime, recent_start: datetime) -> Optional[AnomalyAlert]:
        """Detect unusual uptime patterns"""
        
        # Get hourly uptime patterns for baseline (group by hour of day)
        baseline_uptime = self.get_hourly_uptime_pattern(device, baseline_start, recent_start)
        recent_uptime = self.get_hourly_uptime_pattern(device, recent_start, datetime.utcnow())
        
        if not baseline_uptime or not recent_uptime:
            return None
        
        # Calculate expected uptime for current hour
        current_hour = datetime.utcnow().hour
        expected_uptime = baseline_uptime.get(current_hour, 0.95)  # Default 95% if no data
        current_uptime = recent_uptime.get(current_hour, 0.0)
        
        # Check for significant deviation
        uptime_diff = abs(current_uptime - expected_uptime)
        threshold = self.detection_settings['uptime_pattern']['unexpected_down_threshold']
        
        if uptime_diff < (1 - threshold):
            return None
        
        if current_uptime < expected_uptime * threshold and expected_uptime > 0.8:
            # Device is down when it's usually up
            severity = 'high' if expected_uptime > 0.95 else 'medium'
            confidence = min(uptime_diff / 0.5, 1.0)
            
            message = f"Device unexpectedly down during typical uptime period (expected {expected_uptime*100:.1f}% uptime, got {current_uptime*100:.1f}%)"
            
            return AnomalyAlert(
                device_id=device.id,
                device_name=device.display_name,
                anomaly_type='uptime_pattern',
                severity=severity,
                confidence=confidence,
                message=message,
                detected_at=datetime.utcnow(),
                baseline_value=expected_uptime,
                current_value=current_uptime
            )
        
        return None
    
    def detect_connectivity_pattern_anomaly(self, device: Device, baseline_start: datetime, recent_start: datetime) -> Optional[AnomalyAlert]:
        """Detect unusual connectivity patterns"""
        
        # Get connection frequency patterns
        baseline_freq = self.get_connection_frequency(device, baseline_start, recent_start)
        recent_freq = self.get_connection_frequency(device, recent_start, datetime.utcnow())
        
        if baseline_freq == 0 or recent_freq == 0:
            return None
        
        # Calculate frequency change ratio
        freq_ratio = recent_freq / baseline_freq if baseline_freq > 0 else 0
        
        threshold = self.detection_settings['connectivity_pattern']['unusual_pattern_threshold']
        
        # Check for significant changes in connection frequency
        if freq_ratio < (1 - threshold) or freq_ratio > (1 + threshold):
            if freq_ratio < 0.5:
                severity = 'medium'
                message = f"Unusually low connection frequency ({recent_freq:.1f} vs baseline {baseline_freq:.1f} connections/hour)"
            elif freq_ratio > 2.0:
                severity = 'low'
                message = f"Unusually high connection frequency ({recent_freq:.1f} vs baseline {baseline_freq:.1f} connections/hour)"
            else:
                return None
            
            confidence = min(abs(freq_ratio - 1.0), 1.0)
            
            return AnomalyAlert(
                device_id=device.id,
                device_name=device.display_name,
                anomaly_type='connectivity_pattern',
                severity=severity,
                confidence=confidence,
                message=message,
                detected_at=datetime.utcnow(),
                baseline_value=baseline_freq,
                current_value=recent_freq
            )
        
        return None
    
    def get_hourly_uptime_pattern(self, device: Device, start_time: datetime, end_time: datetime) -> Dict[int, float]:
        """Get uptime percentage by hour of day"""
        
        # Query monitoring data grouped by hour
        from sqlalchemy import case
        
        query = db.session.query(
            func.extract('hour', MonitoringData.timestamp).label('hour'),
            func.count(MonitoringData.id).label('total_checks'),
            func.sum(case((MonitoringData.response_time.isnot(None), 1), else_=0)).label('successful_checks')
        ).filter(
            and_(
                MonitoringData.device_id == device.id,
                MonitoringData.timestamp >= start_time,
                MonitoringData.timestamp < end_time
            )
        ).group_by(
            func.extract('hour', MonitoringData.timestamp)
        ).all()
        
        uptime_by_hour = {}
        for hour, total, successful in query:
            if total > 0:
                uptime_by_hour[int(hour)] = successful / total
        
        return uptime_by_hour
    
    def get_connection_frequency(self, device: Device, start_time: datetime, end_time: datetime) -> float:
        """Get average connections per hour"""
        
        hours_diff = (end_time - start_time).total_seconds() / 3600
        if hours_diff <= 0:
            return 0.0
        
        total_checks = db.session.query(func.count(MonitoringData.id)).filter(
            and_(
                MonitoringData.device_id == device.id,
                MonitoringData.timestamp >= start_time,
                MonitoringData.timestamp < end_time
            )
        ).scalar()
        
        return (total_checks or 0) / hours_diff
    
    def process_anomalies(self, anomalies: List[AnomalyAlert]):
        """Process detected anomalies - send alerts, store in database, etc."""
        
        for anomaly in anomalies:
            try:
                # Log the anomaly
                logger.warning(
                    f"ANOMALY DETECTED - Device: {anomaly.device_name}, "
                    f"Type: {anomaly.anomaly_type}, Severity: {anomaly.severity}, "
                    f"Confidence: {anomaly.confidence:.2f}, Message: {anomaly.message}"
                )
                
                # Store it as a special alert type
                self.create_anomaly_alert(anomaly)
                
                # Send push notification for the anomaly
                self.send_anomaly_push_notification(anomaly)
                
                # Trigger rule engine for anomaly detection
                self._trigger_rule_engine_for_anomaly(anomaly)
                
            except Exception as e:
                logger.error(f"Error processing anomaly: {e}")
    
    def create_anomaly_alert(self, anomaly: AnomalyAlert):
        """Create an alert record for the anomaly"""
        try:
            from models import Alert
            
            # Create alert with anomaly-specific data
            alert_data = {
                'baseline_value': anomaly.baseline_value,
                'current_value': anomaly.current_value,
                'confidence': anomaly.confidence,
                'anomaly_type': anomaly.anomaly_type,
                'threshold': anomaly.threshold
            }
            
            alert = Alert(
                device_id=anomaly.device_id,
                alert_type=f'anomaly_{anomaly.anomaly_type}',
                severity=anomaly.severity,
                message=f"[AI] {anomaly.message}",
                metadata=json.dumps(alert_data),
                created_at=anomaly.detected_at
            )
            
            db.session.add(alert)
            db.session.commit()
            
            logger.info(f"Created anomaly alert for device {anomaly.device_name}")
            
        except Exception as e:
            logger.error(f"Error creating anomaly alert: {e}")
            db.session.rollback()
    
    def send_anomaly_push_notification(self, anomaly: AnomalyAlert):
        """Send push notification for detected anomaly"""
        try:
            from services.push_notifications import push_service
            from models import Configuration, Device
            from config import Config
            
            # Update push service configuration from database
            push_service.enabled = Configuration.get_value('push_notifications_enabled', 'false').lower() == 'true'
            push_service.topic = Configuration.get_value('ntfy_topic', '')
            push_service.server = Configuration.get_value('ntfy_server', 'https://ntfy.sh')
            
            if not push_service.is_configured():
                logger.debug("Push notifications not configured, skipping anomaly notification")
                return
            
            # Get device information
            device = Device.query.filter_by(id=anomaly.device_id).first()
            if not device:
                logger.error(f"Device {anomaly.device_id} not found for anomaly notification")
                return
            
            # Build dashboard URL
            dashboard_url = f"http://{Config.HOST}:{Config.PORT}/device/{device.id}"
            
            # Send anomaly push notification
            success = push_service.send_anomaly_alert(
                device_name=anomaly.device_name,
                ip_address=device.ip_address,
                anomaly_type=anomaly.anomaly_type,
                message=anomaly.message,
                severity=anomaly.severity,
                dashboard_url=dashboard_url
            )
            
            if success:
                logger.info(f"Sent anomaly push notification for {anomaly.device_name}: {anomaly.anomaly_type}")
            else:
                logger.warning(f"Failed to send anomaly push notification for {anomaly.device_name}")
                
        except Exception as e:
            logger.error(f"Error sending anomaly push notification: {e}")
    
    def get_anomaly_statistics(self, hours: int = 24) -> Dict:
        """Get anomaly detection statistics"""
        try:
            from models import Alert
            
            start_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Count anomaly alerts by type and severity
            anomaly_alerts = db.session.query(Alert).filter(
                and_(
                    Alert.alert_type.like('anomaly_%'),
                    Alert.created_at >= start_time
                )
            ).all()
            
            stats = {
                'total_anomalies': len(anomaly_alerts),
                'by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                'by_type': {},
                'avg_confidence': 0.0,
                'most_affected_devices': []
            }
            
            confidences = []
            device_counts = {}
            
            for alert in anomaly_alerts:
                # Count by severity
                stats['by_severity'][alert.severity] += 1
                
                # Count by type
                alert_type = alert.alert_type.replace('anomaly_', '')
                stats['by_type'][alert_type] = stats['by_type'].get(alert_type, 0) + 1
                
                # Track confidence scores
                try:
                    metadata = json.loads(alert.metadata or '{}')
                    confidence = metadata.get('confidence', 0.0)
                    confidences.append(confidence)
                except:
                    pass
                
                # Count by device
                device_name = alert.device.display_name if alert.device else f"Device {alert.device_id}"
                device_counts[device_name] = device_counts.get(device_name, 0) + 1
            
            # Calculate average confidence
            if confidences:
                stats['avg_confidence'] = sum(confidences) / len(confidences)
            
            # Most affected devices
            stats['most_affected_devices'] = sorted(
                device_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting anomaly statistics: {e}")
            return {'error': str(e)}
    
    def _trigger_rule_engine_for_anomaly(self, anomaly: AnomalyAlert):
        """Trigger rule engine evaluation for anomaly detection"""
        try:
            # Get rule engine service from app if available
            if self.app and hasattr(self.app, 'rule_engine_service'):
                rule_engine_service = self.app.rule_engine_service
                
                # Import here to avoid circular imports
                from services.rule_engine import TriggerContext
                
                # Get device information
                device = None
                if self.app:
                    with self.app.app_context():
                        device = Device.query.get(anomaly.device_id)
                
                # Create trigger context for the anomaly detection event
                context = TriggerContext(
                    event_type='anomaly_detected',
                    device_id=anomaly.device_id,
                    device={
                        'id': anomaly.device_id,
                        'display_name': anomaly.device_name,
                        'ip_address': device.ip_address if device else 'unknown',
                        'mac_address': device.mac_address if device else None,
                        'hostname': device.hostname if device else None,
                        'vendor': device.vendor if device else None,
                        'device_type': device.device_type if device else 'unknown',
                        'status': device.status if device else 'unknown',
                        'is_monitored': device.is_monitored if device else True
                    },
                    metadata={
                        'anomaly_type': anomaly.anomaly_type,
                        'severity': anomaly.severity,
                        'confidence': anomaly.confidence,
                        'baseline_value': anomaly.baseline_value,
                        'current_value': anomaly.current_value,
                        'threshold': anomaly.threshold,
                        'detected_at': anomaly.detected_at.isoformat(),
                        'message': anomaly.message
                    }
                )
                
                # Evaluate rules in background thread to avoid blocking anomaly processing
                import threading
                rule_thread = threading.Thread(
                    target=rule_engine_service.evaluate_rules,
                    args=(context,),
                    daemon=True,
                    name=f'RuleEngine-Anomaly-{anomaly.anomaly_type}'
                )
                rule_thread.start()
                
                logger.debug(f"Triggered rule engine for anomaly: {anomaly.device_name} - {anomaly.anomaly_type} ({anomaly.severity})")
                
        except Exception as e:
            logger.error(f"Error triggering rule engine for anomaly: {e}")
            # Don't let rule engine errors affect anomaly processing

# Global anomaly detection service instance
anomaly_detection_service = AnomalyDetectionEngine()