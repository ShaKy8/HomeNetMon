import numpy as np
import logging
import threading
import time
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from enum import Enum
from models import db, Device, MonitoringData, Alert, Configuration
from sqlalchemy import func, and_
import json

from services.device_analytics import DeviceBehaviorAnalytics
from services.predictive_failure import FailurePredictionEngine

logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """Types of anomalies that can be detected"""
    RESPONSE_TIME = "response_time_anomaly"
    AVAILABILITY = "availability_anomaly"
    BEHAVIORAL = "behavioral_anomaly"
    NETWORK_WIDE = "network_wide_anomaly"
    TEMPORAL = "temporal_anomaly"
    STATISTICAL = "statistical_anomaly"
    PATTERN = "pattern_anomaly"
    TRAFFIC = "traffic_anomaly"
    SECURITY = "security_anomaly"


class AnomalySeverity(Enum):
    """Severity levels for detected anomalies"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AnomalyEvent:
    """Enhanced data class for representing detected anomalies"""
    anomaly_id: str
    device_id: int
    device_name: str
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    confidence: float
    description: str
    detected_at: datetime
    affected_metrics: List[str]
    baseline_values: Dict[str, float]
    anomaly_values: Dict[str, float]
    context: Dict[str, Any]
    recommendations: List[str]
    impact_assessment: str = "medium"
    correlation_id: Optional[str] = None


@dataclass
class AnomalyAlert:
    """Legacy alert class for backward compatibility"""
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
    """Enhanced AI-powered anomaly detection for network monitoring"""
    
    def __init__(self, app=None):
        self.app = app
        self.running = False
        self.detection_interval = 300  # 5 minutes
        self.rule_engine_service = None
        
        # Initialize advanced analytics services
        self.device_analytics = DeviceBehaviorAnalytics()
        self.failure_prediction = FailurePredictionEngine()
        
        # Enhanced anomaly detection configuration
        self.enhanced_detection_config = {
            'statistical_algorithms': {
                'z_score_threshold': 2.5,
                'isolation_forest_contamination': 0.1,
                'local_outlier_factor_neighbors': 20,
                'confidence_threshold': 0.7
            },
            'behavioral_analysis': {
                'pattern_deviation_threshold': 0.4,
                'usage_pattern_sensitivity': 0.3,
                'communication_pattern_sensitivity': 0.5,
                'baseline_days': 14
            },
            'network_wide_detection': {
                'correlation_threshold': 0.3,
                'cascade_detection_enabled': True,
                'distributed_anomaly_threshold': 0.25
            },
            'real_time_monitoring': {
                'sliding_window_minutes': 15,
                'rapid_detection_threshold': 3.0,
                'alert_debouncing_seconds': 300
            }
        }
        
        # Real-time anomaly tracking and correlation
        self.active_anomalies = {}
        self.anomaly_history = deque(maxlen=10000)
        self.anomaly_correlations = defaultdict(list)
        self.baseline_cache = {}
        self.pattern_cache = {}
        
        # Advanced statistical models
        self.device_baselines = {}
        self.network_baselines = {}
        self.seasonal_patterns = {}
        self.anomaly_patterns = defaultdict(list)
        
        # Monitoring and alerting systems
        self.anomaly_callbacks = []
        self.alert_thresholds = {
            AnomalySeverity.LOW: 0.7,
            AnomalySeverity.MEDIUM: 0.8,
            AnomalySeverity.HIGH: 0.9,
            AnomalySeverity.CRITICAL: 0.95
        }
        
        # Performance tracking
        self._monitoring_active = False
        self._last_baseline_update = datetime.utcnow()
        self._detection_statistics = {
            'total_anomalies_detected': 0,
            'false_positives': 0,
            'true_positives': 0,
            'detection_accuracy': 0.0
        }
        
        # Load legacy configuration for backward compatibility
        self.load_configuration()
    
    def load_configuration(self):
        """Load anomaly detection configuration from database or use defaults"""
        try:
            if self.app:
                with self.app.app_context():
                    from models import Configuration
                    
                    # Configuration - More conservative settings to reduce false positives
                    self.min_data_points = int(Configuration.get_value('anomaly_min_data_points', '50'))
                    self.baseline_hours = int(Configuration.get_value('anomaly_baseline_hours', '168'))  # 7 days
                    self.anomaly_threshold = float(Configuration.get_value('anomaly_threshold', '3.0'))
                    
                    # Load detection settings
                    self.detection_settings = {
                        'response_time': {
                            'enabled': Configuration.get_value('anomaly_response_time_enabled', 'true').lower() == 'true',
                            'threshold_multiplier': float(Configuration.get_value('anomaly_response_time_threshold', '2.5')),
                            'min_change_threshold': float(Configuration.get_value('anomaly_response_time_min_change', '100')),
                            'severity_thresholds': {
                                'low': float(Configuration.get_value('anomaly_response_time_low_threshold', '2.0')),
                                'medium': float(Configuration.get_value('anomaly_response_time_medium_threshold', '2.5')),
                                'high': float(Configuration.get_value('anomaly_response_time_high_threshold', '3.5')),
                                'critical': float(Configuration.get_value('anomaly_response_time_critical_threshold', '5.0'))
                            }
                        },
                        'uptime_pattern': {
                            'enabled': Configuration.get_value('anomaly_uptime_pattern_enabled', 'true').lower() == 'true',
                            'unexpected_down_threshold': float(Configuration.get_value('anomaly_uptime_down_threshold', '0.9')),
                            'unexpected_up_threshold': float(Configuration.get_value('anomaly_uptime_up_threshold', '0.9'))
                        },
                        'connectivity_pattern': {
                            'enabled': Configuration.get_value('anomaly_connectivity_pattern_enabled', 'true').lower() == 'true',
                            'unusual_pattern_threshold': float(Configuration.get_value('anomaly_connectivity_threshold', '1.5'))
                        }
                    }
            else:
                # Fallback to hardcoded defaults if no app context
                self._load_default_configuration()
                
        except Exception as e:
            logger.error(f"Error loading anomaly detection configuration: {e}")
            # Fallback to defaults
            self._load_default_configuration()
    
    def _load_default_configuration(self):
        """Load default configuration values"""
        # Configuration - More conservative settings to reduce false positives
        self.min_data_points = 50  # Increased minimum data points for more stable baselines
        self.baseline_hours = 168  # 7 days for baseline calculation
        self.anomaly_threshold = 3.0  # Increased standard deviations for anomaly detection
        
        # Anomaly detection settings per metric - Tuned to reduce false positives
        self.detection_settings = {
            'response_time': {
                'enabled': True,
                'threshold_multiplier': 2.5,  # Increased from 2.0 - more conservative
                'min_change_threshold': 100,  # Increased from 50ms - only alert on significant changes
                'severity_thresholds': {
                    'low': 2.0,      # Increased from 1.5
                    'medium': 2.5,   # Increased from 2.0 
                    'high': 3.5,     # Increased from 3.0
                    'critical': 5.0  # Increased from 4.0
                }
            },
            'uptime_pattern': {
                'enabled': True,
                'unexpected_down_threshold': 0.9,  # Increased from 0.8 - more conservative
                'unexpected_up_threshold': 0.9     # Increased from 0.8 - more conservative
            },
            'connectivity_pattern': {
                'enabled': True,
                'unusual_pattern_threshold': 1.5  # Increased from 0.7 - requires 150% change (vs 70%) to trigger
            }
        }
    
    def reload_configuration(self):
        """Reload configuration from database for hot-reload support"""
        logger.info("Reloading anomaly detection configuration")
        self.load_configuration()
    
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
        
        # Check baseline stability - if coefficient of variation is too high, baseline is too variable
        baseline_cv = baseline_std / baseline_mean if baseline_mean > 0 else float('inf')
        if baseline_cv > 1.0:  # Coefficient of variation > 100% indicates unstable baseline
            return None
        
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
        
        # Add minimum baseline frequency requirement to reduce noise
        min_baseline_freq = 2.0  # connections/hour - ignore devices with very low baseline activity
        if baseline_freq < min_baseline_freq:
            return None
        
        # Check for significant changes in connection frequency
        # threshold of 1.5 means we need 150% increase or 50% decrease to trigger
        if freq_ratio < (1.0 / threshold) or freq_ratio > threshold:
            if freq_ratio < 0.3:  # More than 70% decrease
                severity = 'medium'
                message = f"Unusually low connection frequency ({recent_freq:.1f} vs baseline {baseline_freq:.1f} connections/hour)"
            elif freq_ratio > 3.0:  # More than 300% increase  
                severity = 'low'
                message = f"Unusually high connection frequency ({recent_freq:.1f} vs baseline {baseline_freq:.1f} connections/hour)"
            else:
                return None  # Not significant enough change
            
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
            
            # Calculate priority score
            alert.calculate_and_update_priority(self.app)
            
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
    
    # ===== ENHANCED ANOMALY DETECTION METHODS =====
    
    def detect_enhanced_anomalies(self, device_id: Optional[int] = None, hours: int = 24) -> Dict[str, Any]:
        """Perform comprehensive enhanced anomaly detection"""
        try:
            logger.info(f"Starting enhanced anomaly detection for device_id={device_id}, hours={hours}")
            
            with self.app.app_context():
                # Get devices to analyze
                if device_id:
                    devices = [Device.query.get(device_id)]
                    if not devices[0]:
                        return {'error': f'Device {device_id} not found'}
                else:
                    devices = Device.query.filter_by(is_monitored=True).all()
                
                if not devices:
                    return {'error': 'No devices found for analysis'}
                
                # Initialize enhanced detection results
                detection_results = {
                    'detection_metadata': {
                        'analysis_timestamp': datetime.utcnow().isoformat(),
                        'analysis_period_hours': hours,
                        'devices_analyzed': len(devices),
                        'detection_algorithms': ['statistical', 'behavioral', 'temporal', 'network_wide', 'ml_based']
                    },
                    'anomalies': [],
                    'device_summaries': {},
                    'network_summary': {},
                    'correlation_analysis': {},
                    'recommendations': [],
                    'confidence_distribution': defaultdict(int)
                }
                
                # Perform enhanced anomaly detection for each device
                for device in devices:
                    if not device:
                        continue
                    
                    try:
                        device_anomalies = self._detect_enhanced_device_anomalies(device, hours)
                        
                        detection_results['device_summaries'][device.id] = {
                            'device_name': device.display_name,
                            'ip_address': device.ip_address,
                            'anomalies_detected': len(device_anomalies),
                            'anomaly_types': list(set([a.anomaly_type.value for a in device_anomalies])),
                            'max_severity': max([a.severity.value for a in device_anomalies]) if device_anomalies else 'none',
                            'avg_confidence': round(statistics.mean([a.confidence for a in device_anomalies]), 3) if device_anomalies else 0.0
                        }
                        
                        # Convert anomaly objects to dictionaries and track confidence
                        for anomaly in device_anomalies:
                            anomaly_dict = self._enhanced_anomaly_to_dict(anomaly)
                            detection_results['anomalies'].append(anomaly_dict)
                            
                            # Track confidence distribution
                            confidence_bucket = f"{int(anomaly.confidence * 10) * 10}%"
                            detection_results['confidence_distribution'][confidence_bucket] += 1
                        
                    except Exception as e:
                        logger.error(f"Error detecting enhanced anomalies for device {device.id}: {e}")
                        continue
                
                # Perform network-wide and correlation analysis
                network_anomalies = self._detect_enhanced_network_anomalies(hours)
                for anomaly in network_anomalies:
                    detection_results['anomalies'].append(self._enhanced_anomaly_to_dict(anomaly))
                
                # Perform anomaly correlation analysis
                correlation_analysis = self._analyze_anomaly_correlations(detection_results['anomalies'])
                detection_results['correlation_analysis'] = correlation_analysis
                
                # Generate enhanced network summary
                detection_results['network_summary'] = self._generate_enhanced_network_summary(
                    detection_results['anomalies'], devices
                )
                
                # Generate enhanced recommendations
                detection_results['recommendations'] = self._generate_enhanced_recommendations(
                    detection_results['anomalies'], correlation_analysis
                )
                
                # Update detection statistics
                self._detection_statistics['total_anomalies_detected'] += len(detection_results['anomalies'])
                
                logger.info(f"Enhanced anomaly detection completed: {len(detection_results['anomalies'])} anomalies found")
                
                return detection_results
                
        except Exception as e:
            logger.error(f"Error in enhanced anomaly detection: {e}")
            return {'error': str(e)}
    
    def _detect_enhanced_device_anomalies(self, device: Device, hours: int) -> List[AnomalyEvent]:
        """Detect enhanced anomalies for a specific device using advanced algorithms"""
        anomalies = []
        
        try:
            # Get monitoring data for analysis period
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            monitoring_data = MonitoringData.query.filter(
                MonitoringData.device_id == device.id,
                MonitoringData.timestamp >= cutoff
            ).order_by(MonitoringData.timestamp.desc()).all()
            
            if len(monitoring_data) < 20:  # Need sufficient data for enhanced analysis
                return anomalies
            
            # Statistical anomaly detection with multiple algorithms
            statistical_anomalies = self._detect_advanced_statistical_anomalies(device, monitoring_data)
            anomalies.extend(statistical_anomalies)
            
            # Behavioral anomaly detection using ML patterns
            behavioral_anomalies = self._detect_advanced_behavioral_anomalies(device, monitoring_data)
            anomalies.extend(behavioral_anomalies)
            
            # Temporal pattern anomalies with seasonal adjustment
            temporal_anomalies = self._detect_advanced_temporal_anomalies(device, monitoring_data)
            anomalies.extend(temporal_anomalies)
            
            # Traffic and communication pattern anomalies
            traffic_anomalies = self._detect_traffic_anomalies(device, monitoring_data)
            anomalies.extend(traffic_anomalies)
            
            # Security-related anomalies
            security_anomalies = self._detect_security_anomalies(device, monitoring_data)
            anomalies.extend(security_anomalies)
            
        except Exception as e:
            logger.error(f"Error detecting enhanced device anomalies for {device.id}: {e}")
        
        return anomalies
    
    def _detect_advanced_statistical_anomalies(self, device: Device, monitoring_data: List) -> List[AnomalyEvent]:
        """Advanced statistical anomaly detection using multiple algorithms"""
        anomalies = []
        
        try:
            response_times = [data.response_time for data in monitoring_data if data.response_time is not None]
            
            if len(response_times) >= 30:
                # Z-score based detection
                mean_response = statistics.mean(response_times)
                std_response = statistics.stdev(response_times) if len(response_times) > 1 else 0
                
                if std_response > 0:
                    # Calculate rolling z-scores for recent data
                    recent_data = response_times[-10:]  # Last 10 measurements
                    z_scores = [(rt - mean_response) / std_response for rt in recent_data]
                    max_z_score = max([abs(z) for z in z_scores])
                    
                    threshold = self.enhanced_detection_config['statistical_algorithms']['z_score_threshold']
                    if max_z_score > threshold:
                        confidence = min(0.99, max_z_score / 5.0)
                        severity = self._calculate_enhanced_severity(confidence)
                        
                        anomaly = AnomalyEvent(
                            anomaly_id=f"stat_zscore_{device.id}_{int(datetime.utcnow().timestamp())}",
                            device_id=device.id,
                            device_name=device.display_name,
                            anomaly_type=AnomalyType.STATISTICAL,
                            severity=severity,
                            confidence=confidence,
                            description=f"Statistical anomaly detected using Z-score analysis (max z-score: {max_z_score:.2f})",
                            detected_at=datetime.utcnow(),
                            affected_metrics=['response_time', 'statistical_deviation'],
                            baseline_values={'mean_response_time': mean_response, 'std_response_time': std_response},
                            anomaly_values={'max_z_score': max_z_score, 'recent_avg': statistics.mean(recent_data)},
                            context={
                                'algorithm': 'z_score',
                                'threshold_used': threshold,
                                'data_points_analyzed': len(response_times),
                                'recent_measurements': len(recent_data)
                            },
                            recommendations=[
                                "Investigate recent network changes or performance issues",
                                "Check device resource utilization and health",
                                "Verify network path stability and routing"
                            ]
                        )
                        anomalies.append(anomaly)
                
                # Isolation Forest detection for outliers
                if len(response_times) >= 50:
                    anomalies.extend(self._detect_isolation_forest_anomalies(device, response_times))
                
                # Local Outlier Factor detection
                if len(response_times) >= 30:
                    anomalies.extend(self._detect_local_outlier_anomalies(device, response_times))
            
        except Exception as e:
            logger.error(f"Error in advanced statistical anomaly detection for device {device.id}: {e}")
        
        return anomalies
    
    def _detect_isolation_forest_anomalies(self, device: Device, response_times: List[float]) -> List[AnomalyEvent]:
        """Detect anomalies using Isolation Forest algorithm"""
        anomalies = []
        
        try:
            from sklearn.ensemble import IsolationForest
            
            # Prepare data for Isolation Forest
            data = np.array(response_times).reshape(-1, 1)
            contamination = self.enhanced_detection_config['statistical_algorithms']['isolation_forest_contamination']
            
            # Fit Isolation Forest
            iso_forest = IsolationForest(contamination=contamination, random_state=42)
            outlier_labels = iso_forest.fit_predict(data)
            outlier_scores = iso_forest.decision_function(data)
            
            # Find outliers (labeled as -1)
            outlier_indices = [i for i, label in enumerate(outlier_labels) if label == -1]
            
            if outlier_indices:
                # Calculate confidence based on outlier scores
                outlier_score_values = [abs(outlier_scores[i]) for i in outlier_indices]
                max_outlier_score = max(outlier_score_values)
                confidence = min(0.99, max_outlier_score * 2)  # Scale appropriately
                
                if confidence >= self.enhanced_detection_config['statistical_algorithms']['confidence_threshold']:
                    severity = self._calculate_enhanced_severity(confidence)
                    
                    anomaly = AnomalyEvent(
                        anomaly_id=f"iso_forest_{device.id}_{int(datetime.utcnow().timestamp())}",
                        device_id=device.id,
                        device_name=device.display_name,
                        anomaly_type=AnomalyType.STATISTICAL,
                        severity=severity,
                        confidence=confidence,
                        description=f"Isolation Forest detected {len(outlier_indices)} outlier measurements",
                        detected_at=datetime.utcnow(),
                        affected_metrics=['response_time', 'outlier_detection'],
                        baseline_values={'normal_measurements': len(response_times) - len(outlier_indices)},
                        anomaly_values={
                            'outlier_count': len(outlier_indices),
                            'max_outlier_score': max_outlier_score,
                            'outlier_values': [response_times[i] for i in outlier_indices[-5:]]  # Last 5 outliers
                        },
                        context={
                            'algorithm': 'isolation_forest',
                            'contamination_rate': contamination,
                            'total_measurements': len(response_times)
                        },
                        recommendations=[
                            "Review outlier response time measurements for patterns",
                            "Check for intermittent network issues or interference",
                            "Monitor device performance during peak usage times"
                        ]
                    )
                    anomalies.append(anomaly)
            
        except ImportError:
            logger.debug("scikit-learn not available for Isolation Forest detection")
        except Exception as e:
            logger.error(f"Error in Isolation Forest anomaly detection: {e}")
        
        return anomalies
    
    def _detect_local_outlier_anomalies(self, device: Device, response_times: List[float]) -> List[AnomalyEvent]:
        """Detect anomalies using Local Outlier Factor algorithm"""
        anomalies = []
        
        try:
            from sklearn.neighbors import LocalOutlierFactor
            
            # Prepare data
            data = np.array(response_times).reshape(-1, 1)
            n_neighbors = min(
                self.enhanced_detection_config['statistical_algorithms']['local_outlier_factor_neighbors'],
                len(response_times) // 2
            )
            
            # Fit Local Outlier Factor
            lof = LocalOutlierFactor(n_neighbors=n_neighbors, contamination=0.1)
            outlier_labels = lof.fit_predict(data)
            outlier_scores = lof.negative_outlier_factor_
            
            # Find outliers
            outlier_indices = [i for i, label in enumerate(outlier_labels) if label == -1]
            
            if outlier_indices:
                # Calculate confidence from LOF scores
                outlier_lof_scores = [abs(outlier_scores[i]) for i in outlier_indices]
                max_lof_score = max(outlier_lof_scores)
                confidence = min(0.99, (max_lof_score - 1.0) * 0.5)  # LOF scores around 1 are normal
                
                if confidence >= self.enhanced_detection_config['statistical_algorithms']['confidence_threshold']:
                    severity = self._calculate_enhanced_severity(confidence)
                    
                    anomaly = AnomalyEvent(
                        anomaly_id=f"lof_{device.id}_{int(datetime.utcnow().timestamp())}",
                        device_id=device.id,
                        device_name=device.display_name,
                        anomaly_type=AnomalyType.STATISTICAL,
                        severity=severity,
                        confidence=confidence,
                        description=f"Local Outlier Factor detected {len(outlier_indices)} local outliers",
                        detected_at=datetime.utcnow(),
                        affected_metrics=['response_time', 'local_outlier_detection'],
                        baseline_values={'neighbors_analyzed': n_neighbors},
                        anomaly_values={
                            'outlier_count': len(outlier_indices),
                            'max_lof_score': max_lof_score,
                            'outlier_values': [response_times[i] for i in outlier_indices[-3:]]  # Last 3 outliers
                        },
                        context={
                            'algorithm': 'local_outlier_factor',
                            'neighbors_used': n_neighbors,
                            'total_measurements': len(response_times)
                        },
                        recommendations=[
                            "Investigate local network conditions during outlier periods",
                            "Check for device-specific performance issues",
                            "Review network topology for potential bottlenecks"
                        ]
                    )
                    anomalies.append(anomaly)
            
        except ImportError:
            logger.debug("scikit-learn not available for Local Outlier Factor detection")
        except Exception as e:
            logger.error(f"Error in Local Outlier Factor anomaly detection: {e}")
        
        return anomalies
    
    def _detect_advanced_behavioral_anomalies(self, device: Device, monitoring_data: List) -> List[AnomalyEvent]:
        """Advanced behavioral anomaly detection using ML patterns"""
        anomalies = []
        
        try:
            # Get detailed behavioral analysis from device analytics
            behavior_analysis = self.device_analytics.analyze_device_behavior(device.id, days=14)
            
            if 'error' in behavior_analysis:
                return anomalies
            
            # Analyze communication patterns
            communication_anomalies = self._detect_communication_pattern_anomalies(device, behavior_analysis)
            anomalies.extend(communication_anomalies)
            
            # Analyze usage pattern changes
            usage_anomalies = self._detect_usage_pattern_anomalies(device, behavior_analysis)
            anomalies.extend(usage_anomalies)
            
            # Analyze device role deviations
            role_anomalies = self._detect_device_role_anomalies(device, behavior_analysis)
            anomalies.extend(role_anomalies)
            
        except Exception as e:
            logger.error(f"Error in advanced behavioral anomaly detection for device {device.id}: {e}")
        
        return anomalies
    
    def _detect_communication_pattern_anomalies(self, device: Device, behavior_analysis: Dict) -> List[AnomalyEvent]:
        """Detect anomalies in device communication patterns"""
        anomalies = []
        
        try:
            response_characteristics = behavior_analysis.get('response_time_characteristics', {})
            pattern_consistency = response_characteristics.get('consistency_score', 1.0)
            
            threshold = self.enhanced_detection_config['behavioral_analysis']['communication_pattern_sensitivity']
            
            if pattern_consistency < (1.0 - threshold):
                confidence = 1.0 - pattern_consistency
                severity = self._calculate_enhanced_severity(confidence)
                
                anomaly = AnomalyEvent(
                    anomaly_id=f"comm_pattern_{device.id}_{int(datetime.utcnow().timestamp())}",
                    device_id=device.id,
                    device_name=device.display_name,
                    anomaly_type=AnomalyType.BEHAVIORAL,
                    severity=severity,
                    confidence=confidence,
                    description=f"Communication pattern anomaly: consistency dropped to {pattern_consistency:.2f}",
                    detected_at=datetime.utcnow(),
                    affected_metrics=['communication_pattern', 'consistency_score'],
                    baseline_values={'expected_consistency': 1.0 - threshold},
                    anomaly_values={'actual_consistency': pattern_consistency},
                    context={
                        'pattern_type': response_characteristics.get('pattern', 'unknown'),
                        'variance': response_characteristics.get('variance', 0),
                        'analysis_period': '14 days'
                    },
                    recommendations=[
                        "Monitor device for configuration changes",
                        "Check for software updates or patches",
                        "Investigate potential security issues or unauthorized access"
                    ]
                )
                anomalies.append(anomaly)
            
        except Exception as e:
            logger.error(f"Error detecting communication pattern anomalies: {e}")
        
        return anomalies
    
    def _detect_usage_pattern_anomalies(self, device: Device, behavior_analysis: Dict) -> List[AnomalyEvent]:
        """Detect anomalies in device usage patterns"""
        anomalies = []
        
        try:
            uptime_patterns = behavior_analysis.get('uptime_patterns', {})
            pattern_score = uptime_patterns.get('pattern_score', 1.0)
            
            threshold = self.enhanced_detection_config['behavioral_analysis']['usage_pattern_sensitivity']
            
            if pattern_score < (1.0 - threshold):
                confidence = 1.0 - pattern_score
                severity = self._calculate_enhanced_severity(confidence)
                
                anomaly = AnomalyEvent(
                    anomaly_id=f"usage_pattern_{device.id}_{int(datetime.utcnow().timestamp())}",
                    device_id=device.id,
                    device_name=device.display_name,
                    anomaly_type=AnomalyType.BEHAVIORAL,
                    severity=severity,
                    confidence=confidence,
                    description=f"Usage pattern anomaly: pattern score dropped to {pattern_score:.2f}",
                    detected_at=datetime.utcnow(),
                    affected_metrics=['usage_pattern', 'uptime_behavior'],
                    baseline_values={'expected_pattern_score': 1.0 - threshold},
                    anomaly_values={'actual_pattern_score': pattern_score},
                    context={
                        'pattern_type': uptime_patterns.get('pattern_type', 'unknown'),
                        'regularity': uptime_patterns.get('regularity', 0),
                        'typical_hours': uptime_patterns.get('typical_hours', [])
                    },
                    recommendations=[
                        "Review device usage schedules and patterns",
                        "Check for changes in user behavior or device purpose",
                        "Verify device power management and scheduling settings"
                    ]
                )
                anomalies.append(anomaly)
            
        except Exception as e:
            logger.error(f"Error detecting usage pattern anomalies: {e}")
        
        return anomalies
    
    def _detect_device_role_anomalies(self, device: Device, behavior_analysis: Dict) -> List[AnomalyEvent]:
        """Detect anomalies in device role and expected behavior"""
        anomalies = []
        
        try:
            # Compare actual behavior with expected behavior for device type
            device_type = device.device_type or 'unknown'
            
            # Get behavior expectations based on device type
            expected_patterns = self._get_expected_patterns_for_device_type(device_type)
            
            if expected_patterns:
                actual_patterns = behavior_analysis.get('uptime_patterns', {})
                
                # Check for role deviations
                role_deviation_score = self._calculate_role_deviation(expected_patterns, actual_patterns)
                
                if role_deviation_score > 0.6:  # Significant role deviation
                    confidence = role_deviation_score
                    severity = self._calculate_enhanced_severity(confidence)
                    
                    anomaly = AnomalyEvent(
                        anomaly_id=f"role_deviation_{device.id}_{int(datetime.utcnow().timestamp())}",
                        device_id=device.id,
                        device_name=device.display_name,
                        anomaly_type=AnomalyType.BEHAVIORAL,
                        severity=severity,
                        confidence=confidence,
                        description=f"Device role anomaly: behavior doesn't match expected {device_type} patterns",
                        detected_at=datetime.utcnow(),
                        affected_metrics=['device_role', 'behavioral_consistency'],
                        baseline_values=expected_patterns,
                        anomaly_values={'role_deviation_score': role_deviation_score},
                        context={
                            'expected_device_type': device_type,
                            'actual_patterns': actual_patterns,
                            'deviation_factors': self._analyze_deviation_factors(expected_patterns, actual_patterns)
                        },
                        recommendations=[
                            f"Verify device classification as {device_type}",
                            "Check for device repurposing or configuration changes",
                            "Update device type if role has legitimately changed"
                        ]
                    )
                    anomalies.append(anomaly)
            
        except Exception as e:
            logger.error(f"Error detecting device role anomalies: {e}")
        
        return anomalies
    
    def _detect_advanced_temporal_anomalies(self, device: Device, monitoring_data: List) -> List[AnomalyEvent]:
        """Advanced temporal pattern anomaly detection with seasonal adjustment"""
        anomalies = []
        
        try:
            # Analyze temporal patterns with enhanced algorithms
            temporal_analysis = self._perform_temporal_analysis(device, monitoring_data)
            
            # Detect seasonal anomalies
            seasonal_anomalies = self._detect_seasonal_anomalies(device, temporal_analysis)
            anomalies.extend(seasonal_anomalies)
            
            # Detect cyclical pattern breaks
            cyclical_anomalies = self._detect_cyclical_anomalies(device, temporal_analysis)
            anomalies.extend(cyclical_anomalies)
            
        except Exception as e:
            logger.error(f"Error in advanced temporal anomaly detection for device {device.id}: {e}")
        
        return anomalies
    
    def _detect_traffic_anomalies(self, device: Device, monitoring_data: List) -> List[AnomalyEvent]:
        """Detect traffic and load-related anomalies"""
        anomalies = []
        
        try:
            # Analyze request frequency patterns
            frequency_anomalies = self._detect_frequency_anomalies(device, monitoring_data)
            anomalies.extend(frequency_anomalies)
            
            # Detect load spikes and unusual traffic patterns
            load_anomalies = self._detect_load_anomalies(device, monitoring_data)
            anomalies.extend(load_anomalies)
            
        except Exception as e:
            logger.error(f"Error detecting traffic anomalies for device {device.id}: {e}")
        
        return anomalies
    
    def _detect_security_anomalies(self, device: Device, monitoring_data: List) -> List[AnomalyEvent]:
        """Detect security-related anomalies"""
        anomalies = []
        
        try:
            # Detect unusual access patterns that might indicate security issues
            access_anomalies = self._detect_access_pattern_anomalies(device, monitoring_data)
            anomalies.extend(access_anomalies)
            
            # Detect potential scanning or probing activities
            scanning_anomalies = self._detect_scanning_anomalies(device, monitoring_data)
            anomalies.extend(scanning_anomalies)
            
        except Exception as e:
            logger.error(f"Error detecting security anomalies for device {device.id}: {e}")
        
        return anomalies
    
    def _detect_enhanced_network_anomalies(self, hours: int) -> List[AnomalyEvent]:
        """Detect enhanced network-wide anomalies"""
        anomalies = []
        
        try:
            with self.app.app_context():
                # Detect distributed anomalies
                distributed_anomalies = self._detect_distributed_anomalies(hours)
                anomalies.extend(distributed_anomalies)
                
                # Detect cascade failures
                cascade_anomalies = self._detect_cascade_anomalies(hours)
                anomalies.extend(cascade_anomalies)
                
                # Detect network-wide performance degradation
                performance_anomalies = self._detect_network_performance_anomalies(hours)
                anomalies.extend(performance_anomalies)
                
        except Exception as e:
            logger.error(f"Error detecting enhanced network anomalies: {e}")
        
        return anomalies
    
    def _calculate_enhanced_severity(self, confidence: float) -> AnomalySeverity:
        """Calculate enhanced anomaly severity based on confidence score"""
        if confidence >= self.alert_thresholds[AnomalySeverity.CRITICAL]:
            return AnomalySeverity.CRITICAL
        elif confidence >= self.alert_thresholds[AnomalySeverity.HIGH]:
            return AnomalySeverity.HIGH
        elif confidence >= self.alert_thresholds[AnomalySeverity.MEDIUM]:
            return AnomalySeverity.MEDIUM
        else:
            return AnomalySeverity.LOW
    
    def _enhanced_anomaly_to_dict(self, anomaly: AnomalyEvent) -> Dict[str, Any]:
        """Convert enhanced AnomalyEvent to dictionary for JSON serialization"""
        return {
            'anomaly_id': anomaly.anomaly_id,
            'device_id': anomaly.device_id,
            'device_name': anomaly.device_name,
            'anomaly_type': anomaly.anomaly_type.value,
            'severity': anomaly.severity.value,
            'confidence': round(anomaly.confidence, 3),
            'description': anomaly.description,
            'detected_at': anomaly.detected_at.isoformat(),
            'affected_metrics': anomaly.affected_metrics,
            'baseline_values': anomaly.baseline_values,
            'anomaly_values': anomaly.anomaly_values,
            'context': anomaly.context,
            'recommendations': anomaly.recommendations,
            'impact_assessment': anomaly.impact_assessment,
            'correlation_id': anomaly.correlation_id
        }
    
    def _analyze_anomaly_correlations(self, anomalies: List[Dict]) -> Dict[str, Any]:
        """Analyze correlations between detected anomalies"""
        correlation_analysis = {
            'temporal_correlations': [],
            'device_correlations': [],
            'type_correlations': [],
            'severity_patterns': {},
            'cascade_indicators': []
        }
        
        try:
            # Group anomalies by time windows for temporal correlation
            time_windows = defaultdict(list)
            
            for anomaly in anomalies:
                detected_time = datetime.fromisoformat(anomaly['detected_at'].replace('Z', '+00:00'))
                time_window = detected_time.replace(minute=0, second=0, microsecond=0)  # Hour buckets
                time_windows[time_window].append(anomaly)
            
            # Find temporal correlations
            for time_window, window_anomalies in time_windows.items():
                if len(window_anomalies) > 1:
                    correlation_analysis['temporal_correlations'].append({
                        'time_window': time_window.isoformat(),
                        'anomaly_count': len(window_anomalies),
                        'affected_devices': list(set([a['device_id'] for a in window_anomalies])),
                        'anomaly_types': list(set([a['anomaly_type'] for a in window_anomalies])),
                        'correlation_strength': min(1.0, len(window_anomalies) / 10)  # Scale correlation strength
                    })
            
            # Analyze device correlations
            device_anomaly_counts = defaultdict(int)
            for anomaly in anomalies:
                device_anomaly_counts[anomaly['device_id']] += 1
            
            # Find devices with multiple anomalies
            multi_anomaly_devices = {device_id: count for device_id, count in device_anomaly_counts.items() if count > 1}
            correlation_analysis['device_correlations'] = [
                {'device_id': device_id, 'anomaly_count': count}
                for device_id, count in sorted(multi_anomaly_devices.items(), key=lambda x: x[1], reverse=True)
            ]
            
            # Analyze anomaly type correlations
            type_combinations = defaultdict(int)
            for time_window, window_anomalies in time_windows.items():
                if len(window_anomalies) > 1:
                    types = sorted(set([a['anomaly_type'] for a in window_anomalies]))
                    if len(types) > 1:
                        combo = ' + '.join(types)
                        type_combinations[combo] += 1
            
            correlation_analysis['type_correlations'] = [
                {'combination': combo, 'frequency': freq}
                for combo, freq in sorted(type_combinations.items(), key=lambda x: x[1], reverse=True)
            ]
            
        except Exception as e:
            logger.error(f"Error analyzing anomaly correlations: {e}")
        
        return correlation_analysis
    
    def _generate_enhanced_network_summary(self, anomalies: List[Dict], devices: List[Device]) -> Dict[str, Any]:
        """Generate enhanced network-wide summary of detected anomalies"""
        summary = {
            'total_anomalies': len(anomalies),
            'severity_distribution': defaultdict(int),
            'type_distribution': defaultdict(int),
            'affected_devices': set(),
            'network_health_score': 0.0,
            'critical_issues': [],
            'trends': {},
            'risk_assessment': 'low',
            'impact_analysis': {}
        }
        
        try:
            high_confidence_anomalies = 0
            total_confidence = 0
            
            # Analyze anomaly distribution and calculate metrics
            for anomaly in anomalies:
                summary['severity_distribution'][anomaly['severity']] += 1
                summary['type_distribution'][anomaly['anomaly_type']] += 1
                
                if anomaly['device_id'] > 0:
                    summary['affected_devices'].add(anomaly['device_id'])
                
                # Track confidence metrics
                confidence = anomaly.get('confidence', 0)
                total_confidence += confidence
                if confidence > 0.8:
                    high_confidence_anomalies += 1
                
                # Collect critical issues
                if anomaly['severity'] in ['critical', 'high']:
                    summary['critical_issues'].append({
                        'device_id': anomaly['device_id'],
                        'device_name': anomaly['device_name'],
                        'type': anomaly['anomaly_type'],
                        'severity': anomaly['severity'],
                        'confidence': confidence,
                        'description': anomaly['description']
                    })
            
            # Calculate enhanced network health score
            total_devices = len(devices)
            affected_devices = len(summary['affected_devices'])
            
            if total_devices > 0:
                device_health = 1.0 - (affected_devices / total_devices)
                
                # Weight by severity and confidence
                severity_penalty = (
                    summary['severity_distribution']['critical'] * 0.5 +
                    summary['severity_distribution']['high'] * 0.3 +
                    summary['severity_distribution']['medium'] * 0.15 +
                    summary['severity_distribution']['low'] * 0.05
                ) / max(1, len(anomalies))
                
                confidence_factor = (total_confidence / max(1, len(anomalies))) * 0.2
                
                summary['network_health_score'] = max(0.0, min(1.0, 
                    device_health - severity_penalty - confidence_factor))
            
            # Determine overall risk assessment
            critical_count = summary['severity_distribution']['critical']
            high_count = summary['severity_distribution']['high']
            
            if critical_count > 0 or high_count > 2:
                summary['risk_assessment'] = 'critical'
            elif high_count > 0 or summary['severity_distribution']['medium'] > 3:
                summary['risk_assessment'] = 'high'
            elif summary['severity_distribution']['medium'] > 0 or summary['severity_distribution']['low'] > 5:
                summary['risk_assessment'] = 'medium'
            else:
                summary['risk_assessment'] = 'low'
            
            # Impact analysis
            summary['impact_analysis'] = {
                'devices_at_risk_percentage': round((affected_devices / max(1, total_devices)) * 100, 1),
                'high_confidence_anomalies': high_confidence_anomalies,
                'average_confidence': round(total_confidence / max(1, len(anomalies)), 3),
                'network_stability': 'unstable' if affected_devices > total_devices * 0.3 else 'stable'
            }
            
            # Convert sets to lists for JSON serialization
            summary['affected_devices'] = list(summary['affected_devices'])
            summary['severity_distribution'] = dict(summary['severity_distribution'])
            summary['type_distribution'] = dict(summary['type_distribution'])
            
        except Exception as e:
            logger.error(f"Error generating enhanced network summary: {e}")
        
        return summary
    
    def _generate_enhanced_recommendations(self, anomalies: List[Dict], 
                                         correlation_analysis: Dict) -> List[str]:
        """Generate enhanced actionable recommendations"""
        recommendations = set()
        
        try:
            severity_counts = defaultdict(int)
            type_counts = defaultdict(int)
            
            for anomaly in anomalies:
                severity_counts[anomaly['severity']] += 1
                type_counts[anomaly['anomaly_type']] += 1
                
                # Add specific recommendations from each anomaly
                for rec in anomaly.get('recommendations', []):
                    recommendations.add(rec)
            
            # Add correlation-based recommendations
            if correlation_analysis.get('temporal_correlations'):
                recommendations.add("Investigate time-based correlation patterns indicating systematic issues")
            
            if correlation_analysis.get('device_correlations'):
                recommendations.add("Review devices with multiple anomalies for common configuration issues")
            
            # Add enhanced recommendations based on patterns
            if severity_counts['critical'] > 0:
                recommendations.add("URGENT: Address critical anomalies immediately to prevent service disruption")
                recommendations.add("Implement emergency response procedures for critical network issues")
            
            if type_counts.get('network_wide_anomaly', 0) > 0:
                recommendations.add("Perform comprehensive network infrastructure assessment")
                recommendations.add("Review network monitoring and alerting thresholds")
            
            if type_counts.get('statistical_anomaly', 0) > 3:
                recommendations.add("Investigate underlying performance issues affecting multiple devices")
                recommendations.add("Consider network capacity and bandwidth analysis")
            
            if type_counts.get('behavioral_anomaly', 0) > 0:
                recommendations.add("Review device configurations and usage patterns")
                recommendations.add("Check for unauthorized access or security incidents")
            
            if type_counts.get('security_anomaly', 0) > 0:
                recommendations.add("Conduct security audit and vulnerability assessment")
                recommendations.add("Review access logs and authentication patterns")
            
            if len(anomalies) > 15:
                recommendations.add("Consider implementing automated anomaly response procedures")
                recommendations.add("Review anomaly detection thresholds to reduce false positives")
            
            # Add ML-specific recommendations
            recommendations.add("Monitor anomaly detection accuracy and adjust ML models as needed")
            recommendations.add("Use anomaly correlation analysis for proactive issue prevention")
            
        except Exception as e:
            logger.error(f"Error generating enhanced recommendations: {e}")
        
        return sorted(list(recommendations))
    
    # Helper methods for advanced detection algorithms (stubs for complex implementations)
    
    def _perform_temporal_analysis(self, device: Device, monitoring_data: List) -> Dict:
        """Perform detailed temporal analysis (implementation placeholder)"""
        return {'temporal_patterns': {}, 'seasonal_indicators': {}}
    
    def _detect_seasonal_anomalies(self, device: Device, temporal_analysis: Dict) -> List[AnomalyEvent]:
        """Detect seasonal pattern anomalies (implementation placeholder)"""
        return []
    
    def _detect_cyclical_anomalies(self, device: Device, temporal_analysis: Dict) -> List[AnomalyEvent]:
        """Detect cyclical pattern breaks (implementation placeholder)"""
        return []
    
    def _detect_frequency_anomalies(self, device: Device, monitoring_data: List) -> List[AnomalyEvent]:
        """Detect request frequency anomalies (implementation placeholder)"""
        return []
    
    def _detect_load_anomalies(self, device: Device, monitoring_data: List) -> List[AnomalyEvent]:
        """Detect load and traffic anomalies (implementation placeholder)"""
        return []
    
    def _detect_access_pattern_anomalies(self, device: Device, monitoring_data: List) -> List[AnomalyEvent]:
        """Detect access pattern security anomalies (implementation placeholder)"""
        return []
    
    def _detect_scanning_anomalies(self, device: Device, monitoring_data: List) -> List[AnomalyEvent]:
        """Detect scanning/probing anomalies (implementation placeholder)"""
        return []
    
    def _detect_distributed_anomalies(self, hours: int) -> List[AnomalyEvent]:
        """Detect distributed network anomalies (implementation placeholder)"""
        return []
    
    def _detect_cascade_anomalies(self, hours: int) -> List[AnomalyEvent]:
        """Detect cascade failure patterns (implementation placeholder)"""
        return []
    
    def _detect_network_performance_anomalies(self, hours: int) -> List[AnomalyEvent]:
        """Detect network-wide performance anomalies (implementation placeholder)"""
        return []
    
    def _get_expected_patterns_for_device_type(self, device_type: str) -> Dict:
        """Get expected behavioral patterns for device type (implementation placeholder)"""
        return {}
    
    def _calculate_role_deviation(self, expected: Dict, actual: Dict) -> float:
        """Calculate role deviation score (implementation placeholder)"""
        return 0.0
    
    def _analyze_deviation_factors(self, expected: Dict, actual: Dict) -> List[str]:
        """Analyze factors contributing to role deviation (implementation placeholder)"""
        return []

# Global anomaly detection service instance
anomaly_detection_service = AnomalyDetectionEngine()