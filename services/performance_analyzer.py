"""
Network Performance Analyzer

This module provides comprehensive network performance analysis and optimization
for the HomeNetMon system. It includes:

1. Real-time performance monitoring and metrics collection
2. Bandwidth utilization analysis and trending
3. Network latency measurement and analysis
4. Performance optimization recommendations
5. Quality of Service (QoS) monitoring
6. Network bottleneck detection and analysis
7. Historical performance trend analysis
8. Performance alert generation and management
"""

import threading
import time
import logging
import statistics
import subprocess
import psutil
import speedtest
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import json
import socket
import struct

from models import db, Device, MonitoringData
from services.notification import notification_service

logger = logging.getLogger(__name__)


class PerformanceMetric(Enum):
    """Performance metrics tracked by the analyzer"""
    BANDWIDTH_UTILIZATION = "bandwidth_utilization"
    LATENCY = "latency"
    JITTER = "jitter"
    PACKET_LOSS = "packet_loss"
    THROUGHPUT = "throughput"
    RESPONSE_TIME = "response_time"
    CONNECTION_COUNT = "connection_count"
    ERROR_RATE = "error_rate"


class PerformanceLevel(Enum):
    """Performance level classifications"""
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    CRITICAL = "critical"


class OptimizationCategory(Enum):
    """Categories of optimization recommendations"""
    NETWORK_CONFIGURATION = "network_configuration"
    BANDWIDTH_OPTIMIZATION = "bandwidth_optimization"
    LATENCY_REDUCTION = "latency_reduction"
    QOS_CONFIGURATION = "qos_configuration"
    DEVICE_OPTIMIZATION = "device_optimization"
    INFRASTRUCTURE_UPGRADE = "infrastructure_upgrade"


@dataclass
class PerformanceSnapshot:
    """Represents a point-in-time performance measurement"""
    timestamp: datetime
    device_id: int
    metric_type: PerformanceMetric
    value: float
    unit: str
    metadata: Dict[str, Any]


@dataclass
class BandwidthMeasurement:
    """Bandwidth measurement data"""
    timestamp: datetime
    download_mbps: float
    upload_mbps: float
    ping_ms: float
    server_info: Dict[str, Any]
    test_duration: float


@dataclass
class LatencyAnalysis:
    """Network latency analysis results"""
    device_id: int
    min_latency: float
    max_latency: float
    avg_latency: float
    jitter: float
    packet_loss_percent: float
    sample_count: int
    analysis_period: timedelta


@dataclass
class PerformanceAlert:
    """Performance-related alert"""
    alert_id: str
    device_id: int
    metric_type: PerformanceMetric
    severity: str
    threshold_value: float
    actual_value: float
    description: str
    recommendations: List[str]
    detected_at: datetime


@dataclass
class OptimizationRecommendation:
    """Network optimization recommendation"""
    recommendation_id: str
    category: OptimizationCategory
    priority: int  # 1-5, 5 being highest
    title: str
    description: str
    impact_assessment: str
    implementation_effort: str
    estimated_improvement: str
    steps: List[str]
    devices_affected: List[int]
    cost_estimate: Optional[str] = None


class NetworkPerformanceAnalyzer:
    """
    Comprehensive network performance analyzer that monitors, analyzes, and optimizes
    network performance across all monitored devices.
    """
    
    def __init__(self, app=None):
        self.app = app
        self.running = False
        self.analysis_thread = None
        self.bandwidth_thread = None
        
        # Performance data storage
        self.performance_snapshots = deque(maxlen=10000)
        self.bandwidth_history = deque(maxlen=1000)
        self.latency_cache = defaultdict(lambda: deque(maxlen=100))
        
        # Analysis configuration
        self.analysis_config = {
            'snapshot_interval': 60,  # seconds
            'bandwidth_test_interval': 3600,  # 1 hour
            'alert_thresholds': {
                PerformanceMetric.LATENCY: 100.0,  # ms
                PerformanceMetric.PACKET_LOSS: 1.0,  # percent
                PerformanceMetric.JITTER: 50.0,  # ms
                PerformanceMetric.BANDWIDTH_UTILIZATION: 90.0,  # percent
                PerformanceMetric.ERROR_RATE: 5.0  # percent
            },
            'optimization_check_interval': 86400,  # 24 hours
            'historical_retention_days': 90
        }
        
        # Performance baselines
        self.performance_baselines = {}
        self.optimization_recommendations = {}
        self.active_alerts = {}
        
        # Statistics tracking
        self.performance_statistics = {
            'total_snapshots': 0,
            'bandwidth_tests_completed': 0,
            'alerts_generated': 0,
            'optimizations_recommended': 0,
            'last_analysis': None,
            'analysis_duration': 0
        }
    
    def start_analysis(self):
        """Start the performance analysis engine"""
        if self.running:
            logger.warning("Performance analyzer is already running")
            return
        
        self.running = True
        
        # Start analysis thread
        self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self.analysis_thread.start()
        
        # Start bandwidth monitoring thread
        self.bandwidth_thread = threading.Thread(target=self._bandwidth_monitoring_loop, daemon=True)
        self.bandwidth_thread.start()
        
        logger.info("Network performance analyzer started")
    
    def stop_analysis(self):
        """Stop the performance analysis engine"""
        self.running = False
        
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=30)
        
        if self.bandwidth_thread and self.bandwidth_thread.is_alive():
            self.bandwidth_thread.join(timeout=30)
        
        logger.info("Network performance analyzer stopped")
    
    def _analysis_loop(self):
        """Main analysis loop that continuously monitors performance"""
        logger.info("Starting performance analysis loop")
        
        while self.running:
            try:
                start_time = time.time()
                
                # Collect performance snapshots
                self._collect_performance_snapshots()
                
                # Analyze latency and network quality
                self._analyze_network_latency()
                
                # Check for performance alerts
                self._check_performance_alerts()
                
                # Generate optimization recommendations (less frequent)
                if int(time.time()) % self.analysis_config['optimization_check_interval'] == 0:
                    self._generate_optimization_recommendations()
                
                # Update statistics
                analysis_duration = time.time() - start_time
                self.performance_statistics['analysis_duration'] = analysis_duration
                self.performance_statistics['last_analysis'] = datetime.utcnow()
                
                # Sleep until next interval
                sleep_time = max(0, self.analysis_config['snapshot_interval'] - analysis_duration)
                time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Error in performance analysis loop: {e}")
                time.sleep(30)  # Wait before retrying
    
    def _bandwidth_monitoring_loop(self):
        """Dedicated loop for bandwidth testing"""
        logger.info("Starting bandwidth monitoring loop")
        
        while self.running:
            try:
                # Perform bandwidth test
                self._perform_bandwidth_test()
                
                # Sleep until next test
                time.sleep(self.analysis_config['bandwidth_test_interval'])
                
            except Exception as e:
                logger.error(f"Error in bandwidth monitoring loop: {e}")
                time.sleep(300)  # Wait 5 minutes before retrying
    
    def _collect_performance_snapshots(self):
        """Collect performance data snapshots from all devices"""
        try:
            devices = Device.query.filter_by(active=True).all()
            current_time = datetime.utcnow()
            
            for device in devices:
                # Get recent monitoring data
                recent_data = MonitoringData.query.filter(
                    MonitoringData.device_id == device.id,
                    MonitoringData.timestamp >= current_time - timedelta(minutes=5)
                ).order_by(MonitoringData.timestamp.desc()).limit(10).all()
                
                if recent_data:
                    # Calculate performance metrics
                    response_times = [d.response_time for d in recent_data if d.response_time is not None]
                    
                    if response_times:
                        # Response time metrics
                        avg_response_time = statistics.mean(response_times)
                        self._add_performance_snapshot(
                            device.id, PerformanceMetric.RESPONSE_TIME,
                            avg_response_time, "ms", {
                                'sample_count': len(response_times),
                                'min': min(response_times),
                                'max': max(response_times)
                            }
                        )
                        
                        # Jitter calculation
                        if len(response_times) > 1:
                            jitter = statistics.stdev(response_times)
                            self._add_performance_snapshot(
                                device.id, PerformanceMetric.JITTER,
                                jitter, "ms", {'sample_count': len(response_times)}
                            )
                    
                    # Packet loss calculation
                    total_pings = len(recent_data)
                    failed_pings = sum(1 for d in recent_data if d.response_time is None)
                    packet_loss = (failed_pings / total_pings) * 100 if total_pings > 0 else 0
                    
                    self._add_performance_snapshot(
                        device.id, PerformanceMetric.PACKET_LOSS,
                        packet_loss, "%", {
                            'total_pings': total_pings,
                            'failed_pings': failed_pings
                        }
                    )
            
            self.performance_statistics['total_snapshots'] += len(devices)
            
        except Exception as e:
            logger.error(f"Error collecting performance snapshots: {e}")
    
    def _add_performance_snapshot(self, device_id: int, metric_type: PerformanceMetric, 
                                 value: float, unit: str, metadata: Dict[str, Any]):
        """Add a performance snapshot to the collection"""
        snapshot = PerformanceSnapshot(
            timestamp=datetime.utcnow(),
            device_id=device_id,
            metric_type=metric_type,
            value=value,
            unit=unit,
            metadata=metadata
        )
        self.performance_snapshots.append(snapshot)
    
    def _perform_bandwidth_test(self):
        """Perform internet bandwidth test"""
        try:
            logger.info("Starting bandwidth test")
            
            # Initialize speedtest
            st = speedtest.Speedtest()
            st.get_best_server()
            
            start_time = time.time()
            
            # Perform download test
            download_speed = st.download() / 1_000_000  # Convert to Mbps
            
            # Perform upload test
            upload_speed = st.upload() / 1_000_000  # Convert to Mbps
            
            # Get ping
            ping_result = st.results.ping
            
            test_duration = time.time() - start_time
            
            # Store bandwidth measurement
            measurement = BandwidthMeasurement(
                timestamp=datetime.utcnow(),
                download_mbps=download_speed,
                upload_mbps=upload_speed,
                ping_ms=ping_result,
                server_info=st.results.server,
                test_duration=test_duration
            )
            
            self.bandwidth_history.append(measurement)
            self.performance_statistics['bandwidth_tests_completed'] += 1
            
            logger.info(f"Bandwidth test completed: {download_speed:.2f} Mbps down, {upload_speed:.2f} Mbps up, {ping_result:.2f} ms ping")
            
        except Exception as e:
            logger.error(f"Error performing bandwidth test: {e}")
    
    def _analyze_network_latency(self):
        """Analyze network latency patterns and trends"""
        try:
            devices = Device.query.filter_by(active=True).all()
            
            for device in devices:
                # Get recent latency data
                recent_snapshots = [
                    s for s in self.performance_snapshots
                    if s.device_id == device.id and 
                    s.metric_type == PerformanceMetric.RESPONSE_TIME and
                    s.timestamp >= datetime.utcnow() - timedelta(hours=1)
                ]
                
                if len(recent_snapshots) >= 5:
                    latencies = [s.value for s in recent_snapshots]
                    
                    analysis = LatencyAnalysis(
                        device_id=device.id,
                        min_latency=min(latencies),
                        max_latency=max(latencies),
                        avg_latency=statistics.mean(latencies),
                        jitter=statistics.stdev(latencies) if len(latencies) > 1 else 0,
                        packet_loss_percent=self._get_recent_packet_loss(device.id),
                        sample_count=len(latencies),
                        analysis_period=timedelta(hours=1)
                    )
                    
                    self.latency_cache[device.id].append(analysis)
        
        except Exception as e:
            logger.error(f"Error analyzing network latency: {e}")
    
    def _get_recent_packet_loss(self, device_id: int) -> float:
        """Get recent packet loss percentage for a device"""
        recent_snapshots = [
            s for s in self.performance_snapshots
            if s.device_id == device_id and 
            s.metric_type == PerformanceMetric.PACKET_LOSS and
            s.timestamp >= datetime.utcnow() - timedelta(hours=1)
        ]
        
        if recent_snapshots:
            return statistics.mean([s.value for s in recent_snapshots])
        return 0.0
    
    def _check_performance_alerts(self):
        """Check for performance issues and generate alerts"""
        try:
            for snapshot in list(self.performance_snapshots)[-100:]:  # Check recent snapshots
                metric_type = snapshot.metric_type
                
                if metric_type in self.analysis_config['alert_thresholds']:
                    threshold = self.analysis_config['alert_thresholds'][metric_type]
                    
                    # Check if threshold is exceeded
                    if self._is_threshold_exceeded(snapshot.value, threshold, metric_type):
                        alert_id = f"{snapshot.device_id}_{metric_type.value}_{int(snapshot.timestamp.timestamp())}"
                        
                        if alert_id not in self.active_alerts:
                            alert = self._create_performance_alert(snapshot, threshold)
                            self.active_alerts[alert_id] = alert
                            self._send_performance_alert(alert)
                            
                            self.performance_statistics['alerts_generated'] += 1
        
        except Exception as e:
            logger.error(f"Error checking performance alerts: {e}")
    
    def _is_threshold_exceeded(self, value: float, threshold: float, metric_type: PerformanceMetric) -> bool:
        """Check if a performance value exceeds the threshold"""
        # For metrics where higher is worse
        if metric_type in [PerformanceMetric.LATENCY, PerformanceMetric.PACKET_LOSS, 
                          PerformanceMetric.JITTER, PerformanceMetric.ERROR_RATE]:
            return value > threshold
        
        # For metrics where lower is worse (bandwidth utilization is special case)
        if metric_type == PerformanceMetric.BANDWIDTH_UTILIZATION:
            return value > threshold  # High utilization is bad
        
        return False
    
    def _create_performance_alert(self, snapshot: PerformanceSnapshot, threshold: float) -> PerformanceAlert:
        """Create a performance alert from a snapshot"""
        device = Device.query.get(snapshot.device_id)
        device_name = device.name if device else f"Device {snapshot.device_id}"
        
        # Generate recommendations based on metric type
        recommendations = self._get_metric_recommendations(snapshot.metric_type, snapshot.value)
        
        # Determine severity
        severity = self._calculate_alert_severity(snapshot.value, threshold, snapshot.metric_type)
        
        return PerformanceAlert(
            alert_id=f"{snapshot.device_id}_{snapshot.metric_type.value}_{int(snapshot.timestamp.timestamp())}",
            device_id=snapshot.device_id,
            metric_type=snapshot.metric_type,
            severity=severity,
            threshold_value=threshold,
            actual_value=snapshot.value,
            description=f"{device_name} {snapshot.metric_type.value} is {snapshot.value:.2f} {snapshot.unit} (threshold: {threshold:.2f} {snapshot.unit})",
            recommendations=recommendations,
            detected_at=snapshot.timestamp
        )
    
    def _get_metric_recommendations(self, metric_type: PerformanceMetric, value: float) -> List[str]:
        """Get recommendations based on the metric type and value"""
        recommendations = []
        
        if metric_type == PerformanceMetric.LATENCY:
            recommendations = [
                "Check network congestion and bandwidth utilization",
                "Verify physical network connections and cable quality",
                "Consider upgrading network infrastructure",
                "Optimize device placement and wireless signal strength"
            ]
        elif metric_type == PerformanceMetric.PACKET_LOSS:
            recommendations = [
                "Inspect physical network connections",
                "Check for network congestion",
                "Verify switch and router configurations",
                "Consider replacing faulty network hardware"
            ]
        elif metric_type == PerformanceMetric.JITTER:
            recommendations = [
                "Implement Quality of Service (QoS) policies",
                "Reduce network congestion",
                "Prioritize critical traffic",
                "Consider dedicated network paths for sensitive applications"
            ]
        elif metric_type == PerformanceMetric.BANDWIDTH_UTILIZATION:
            recommendations = [
                "Monitor bandwidth usage patterns",
                "Implement traffic shaping policies",
                "Consider upgrading internet connection",
                "Optimize application bandwidth usage"
            ]
        
        return recommendations
    
    def _calculate_alert_severity(self, value: float, threshold: float, metric_type: PerformanceMetric) -> str:
        """Calculate alert severity based on how much the threshold is exceeded"""
        ratio = value / threshold if threshold > 0 else 1.0
        
        if ratio <= 1.2:
            return "low"
        elif ratio <= 1.5:
            return "medium"
        elif ratio <= 2.0:
            return "high"
        else:
            return "critical"
    
    def _send_performance_alert(self, alert: PerformanceAlert):
        """Send performance alert through notification system"""
        try:
            notification_service.send_notification(
                subject=f"Performance Alert: {alert.description}",
                message=f"""
Performance Alert Details:
- Device ID: {alert.device_id}
- Metric: {alert.metric_type.value}
- Current Value: {alert.actual_value:.2f}
- Threshold: {alert.threshold_value:.2f}
- Severity: {alert.severity}
- Detected: {alert.detected_at.strftime('%Y-%m-%d %H:%M:%S')}

Recommendations:
{chr(10).join(['- ' + rec for rec in alert.recommendations])}
                """.strip(),
                level="warning" if alert.severity in ["low", "medium"] else "error"
            )
        except Exception as e:
            logger.error(f"Error sending performance alert: {e}")
    
    def _generate_optimization_recommendations(self):
        """Generate network optimization recommendations"""
        try:
            logger.info("Generating performance optimization recommendations")
            
            recommendations = []
            
            # Analyze bandwidth utilization trends
            recommendations.extend(self._analyze_bandwidth_optimization())
            
            # Analyze latency patterns
            recommendations.extend(self._analyze_latency_optimization())
            
            # Analyze network configuration
            recommendations.extend(self._analyze_network_configuration())
            
            # Store recommendations
            for rec in recommendations:
                self.optimization_recommendations[rec.recommendation_id] = rec
            
            self.performance_statistics['optimizations_recommended'] += len(recommendations)
            
            logger.info(f"Generated {len(recommendations)} optimization recommendations")
            
        except Exception as e:
            logger.error(f"Error generating optimization recommendations: {e}")
    
    def _analyze_bandwidth_optimization(self) -> List[OptimizationRecommendation]:
        """Analyze bandwidth usage and generate optimization recommendations"""
        recommendations = []
        
        if len(self.bandwidth_history) < 5:
            return recommendations
        
        # Analyze recent bandwidth trends
        recent_measurements = list(self.bandwidth_history)[-10:]
        avg_download = statistics.mean([m.download_mbps for m in recent_measurements])
        avg_upload = statistics.mean([m.upload_mbps for m in recent_measurements])
        
        # Check for consistently low bandwidth
        if avg_download < 50:  # Less than 50 Mbps
            recommendations.append(OptimizationRecommendation(
                recommendation_id=f"bandwidth_upgrade_{int(time.time())}",
                category=OptimizationCategory.INFRASTRUCTURE_UPGRADE,
                priority=4,
                title="Internet Bandwidth Upgrade Recommended",
                description=f"Current average download speed is {avg_download:.1f} Mbps, which may be insufficient for modern usage",
                impact_assessment="High - Will improve overall network performance",
                implementation_effort="Medium - Requires ISP coordination",
                estimated_improvement="50-200% bandwidth increase",
                steps=[
                    "Contact internet service provider",
                    "Evaluate available upgrade plans",
                    "Consider fiber optic connection if available",
                    "Schedule installation with minimal downtime"
                ],
                devices_affected=[],
                cost_estimate="$20-100/month additional"
            ))
        
        return recommendations
    
    def _analyze_latency_optimization(self) -> List[OptimizationRecommendation]:
        """Analyze latency patterns and generate optimization recommendations"""
        recommendations = []
        
        # Analyze devices with consistently high latency
        high_latency_devices = []
        
        for device_id, analyses in self.latency_cache.items():
            if analyses:
                recent_analysis = analyses[-1]
                if recent_analysis.avg_latency > 100:  # High latency threshold
                    high_latency_devices.append((device_id, recent_analysis))
        
        if high_latency_devices:
            device_ids = [d[0] for d in high_latency_devices]
            
            recommendations.append(OptimizationRecommendation(
                recommendation_id=f"latency_optimization_{int(time.time())}",
                category=OptimizationCategory.LATENCY_REDUCTION,
                priority=3,
                title="High Latency Devices Detected",
                description=f"{len(high_latency_devices)} devices showing consistently high latency",
                impact_assessment="Medium - Will improve response times for affected devices",
                implementation_effort="Low - Configuration changes",
                estimated_improvement="20-50% latency reduction",
                steps=[
                    "Check physical connections for affected devices",
                    "Verify wireless signal strength for WiFi devices",
                    "Consider wired connections for critical devices",
                    "Optimize wireless channel selection",
                    "Update device network drivers"
                ],
                devices_affected=device_ids
            ))
        
        return recommendations
    
    def _analyze_network_configuration(self) -> List[OptimizationRecommendation]:
        """Analyze network configuration and generate recommendations"""
        recommendations = []
        
        # This would analyze network configuration files, router settings, etc.
        # For now, we'll generate some general recommendations
        
        recommendations.append(OptimizationRecommendation(
            recommendation_id=f"qos_configuration_{int(time.time())}",
            category=OptimizationCategory.QOS_CONFIGURATION,
            priority=2,
            title="Quality of Service (QoS) Configuration",
            description="Implement QoS policies to prioritize critical network traffic",
            impact_assessment="Medium - Will improve performance for priority applications",
            implementation_effort="Medium - Requires router configuration",
            estimated_improvement="Improved consistency for priority traffic",
            steps=[
                "Access router/switch administrative interface",
                "Identify critical applications and devices",
                "Configure traffic prioritization rules",
                "Set bandwidth allocation policies",
                "Monitor and adjust based on performance"
            ],
            devices_affected=[]
        ))
        
        return recommendations
    
    # Public API methods
    
    def get_performance_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive performance summary"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            recent_snapshots = [s for s in self.performance_snapshots if s.timestamp >= cutoff_time]
            
            summary = {
                'time_period_hours': hours,
                'total_snapshots': len(recent_snapshots),
                'devices_monitored': len(set(s.device_id for s in recent_snapshots)),
                'metrics': {},
                'alerts': {
                    'active_count': len(self.active_alerts),
                    'recent_alerts': []
                },
                'bandwidth': {},
                'recommendations': {
                    'total_count': len(self.optimization_recommendations),
                    'high_priority': len([r for r in self.optimization_recommendations.values() if r.priority >= 4])
                }
            }
            
            # Calculate metrics summaries
            for metric_type in PerformanceMetric:
                metric_snapshots = [s for s in recent_snapshots if s.metric_type == metric_type]
                if metric_snapshots:
                    values = [s.value for s in metric_snapshots]
                    summary['metrics'][metric_type.value] = {
                        'count': len(values),
                        'average': statistics.mean(values),
                        'min': min(values),
                        'max': max(values),
                        'latest': values[-1] if values else None
                    }
            
            # Recent bandwidth data
            if self.bandwidth_history:
                latest_bandwidth = self.bandwidth_history[-1]
                summary['bandwidth'] = {
                    'download_mbps': latest_bandwidth.download_mbps,
                    'upload_mbps': latest_bandwidth.upload_mbps,
                    'ping_ms': latest_bandwidth.ping_ms,
                    'test_time': latest_bandwidth.timestamp.isoformat()
                }
            
            # Recent alerts
            recent_alerts = [
                asdict(alert) for alert in self.active_alerts.values()
                if alert.detected_at >= cutoff_time
            ][:10]  # Last 10 alerts
            summary['alerts']['recent_alerts'] = recent_alerts
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting performance summary: {e}")
            return {'error': str(e)}
    
    def get_device_performance_analysis(self, device_id: int, hours: int = 24) -> Dict[str, Any]:
        """Get detailed performance analysis for a specific device"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            device_snapshots = [
                s for s in self.performance_snapshots 
                if s.device_id == device_id and s.timestamp >= cutoff_time
            ]
            
            device = Device.query.get(device_id)
            device_name = device.name if device else f"Device {device_id}"
            
            analysis = {
                'device_id': device_id,
                'device_name': device_name,
                'time_period_hours': hours,
                'total_measurements': len(device_snapshots),
                'metrics': {},
                'latency_analysis': None,
                'performance_level': PerformanceLevel.GOOD.value,
                'alerts': [],
                'recommendations': []
            }
            
            # Analyze each metric type
            for metric_type in PerformanceMetric:
                metric_snapshots = [s for s in device_snapshots if s.metric_type == metric_type]
                if metric_snapshots:
                    values = [s.value for s in metric_snapshots]
                    analysis['metrics'][metric_type.value] = {
                        'count': len(values),
                        'average': statistics.mean(values),
                        'min': min(values),
                        'max': max(values),
                        'trend': self._calculate_trend(values),
                        'latest': values[-1],
                        'data_points': [
                            {'timestamp': s.timestamp.isoformat(), 'value': s.value}
                            for s in metric_snapshots[-20:]  # Last 20 points
                        ]
                    }
            
            # Get latest latency analysis
            if device_id in self.latency_cache and self.latency_cache[device_id]:
                latest_analysis = self.latency_cache[device_id][-1]
                analysis['latency_analysis'] = asdict(latest_analysis)
            
            # Calculate overall performance level
            analysis['performance_level'] = self._calculate_device_performance_level(device_snapshots)
            
            # Get device-specific alerts
            device_alerts = [
                asdict(alert) for alert in self.active_alerts.values()
                if alert.device_id == device_id and alert.detected_at >= cutoff_time
            ]
            analysis['alerts'] = device_alerts
            
            # Get device-specific recommendations
            device_recommendations = [
                asdict(rec) for rec in self.optimization_recommendations.values()
                if device_id in rec.devices_affected or not rec.devices_affected
            ]
            analysis['recommendations'] = device_recommendations
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error getting device performance analysis: {e}")
            return {'error': str(e)}
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction for a series of values"""
        if len(values) < 3:
            return "stable"
        
        # Calculate simple linear trend
        x = list(range(len(values)))
        y = values
        
        # Simple correlation coefficient
        n = len(values)
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(x[i] * y[i] for i in range(n))
        sum_x2 = sum(xi * xi for xi in x)
        
        correlation = (n * sum_xy - sum_x * sum_y) / ((n * sum_x2 - sum_x * sum_x) ** 0.5 * (n * sum(yi * yi for yi in y) - sum_y * sum_y) ** 0.5)
        
        if correlation > 0.3:
            return "improving"
        elif correlation < -0.3:
            return "degrading"
        else:
            return "stable"
    
    def _calculate_device_performance_level(self, snapshots: List[PerformanceSnapshot]) -> str:
        """Calculate overall performance level for a device"""
        if not snapshots:
            return PerformanceLevel.GOOD.value
        
        # Score based on different metrics
        score = 100  # Start with perfect score
        
        # Check latency
        latency_snapshots = [s for s in snapshots if s.metric_type == PerformanceMetric.RESPONSE_TIME]
        if latency_snapshots:
            avg_latency = statistics.mean([s.value for s in latency_snapshots])
            if avg_latency > 200:
                score -= 30
            elif avg_latency > 100:
                score -= 15
            elif avg_latency > 50:
                score -= 5
        
        # Check packet loss
        packet_loss_snapshots = [s for s in snapshots if s.metric_type == PerformanceMetric.PACKET_LOSS]
        if packet_loss_snapshots:
            avg_packet_loss = statistics.mean([s.value for s in packet_loss_snapshots])
            if avg_packet_loss > 5:
                score -= 40
            elif avg_packet_loss > 2:
                score -= 20
            elif avg_packet_loss > 1:
                score -= 10
        
        # Check jitter
        jitter_snapshots = [s for s in snapshots if s.metric_type == PerformanceMetric.JITTER]
        if jitter_snapshots:
            avg_jitter = statistics.mean([s.value for s in jitter_snapshots])
            if avg_jitter > 100:
                score -= 25
            elif avg_jitter > 50:
                score -= 10
        
        # Convert score to performance level
        if score >= 90:
            return PerformanceLevel.EXCELLENT.value
        elif score >= 75:
            return PerformanceLevel.GOOD.value
        elif score >= 60:
            return PerformanceLevel.FAIR.value
        elif score >= 40:
            return PerformanceLevel.POOR.value
        else:
            return PerformanceLevel.CRITICAL.value
    
    def get_bandwidth_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get bandwidth test history"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        return [
            asdict(measurement) for measurement in self.bandwidth_history
            if measurement.timestamp >= cutoff_time
        ]
    
    def get_optimization_recommendations(self, category: Optional[str] = None, 
                                       priority_min: int = 1) -> List[Dict[str, Any]]:
        """Get optimization recommendations"""
        recommendations = list(self.optimization_recommendations.values())
        
        # Filter by category
        if category:
            try:
                category_enum = OptimizationCategory(category)
                recommendations = [r for r in recommendations if r.category == category_enum]
            except ValueError:
                pass
        
        # Filter by priority
        recommendations = [r for r in recommendations if r.priority >= priority_min]
        
        # Sort by priority (highest first)
        recommendations.sort(key=lambda r: r.priority, reverse=True)
        
        return [asdict(rec) for rec in recommendations]
    
    def get_performance_alerts(self, device_id: Optional[int] = None, 
                              hours: int = 24) -> List[Dict[str, Any]]:
        """Get performance alerts"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        alerts = [
            alert for alert in self.active_alerts.values()
            if alert.detected_at >= cutoff_time
        ]
        
        if device_id:
            alerts = [alert for alert in alerts if alert.device_id == device_id]
        
        # Sort by detection time (newest first)
        alerts.sort(key=lambda a: a.detected_at, reverse=True)
        
        return [asdict(alert) for alert in alerts]
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge a performance alert"""
        if alert_id in self.active_alerts:
            del self.active_alerts[alert_id]
            return True
        return False
    
    def get_performance_statistics(self) -> Dict[str, Any]:
        """Get performance analyzer statistics"""
        return {
            **self.performance_statistics,
            'active_alerts_count': len(self.active_alerts),
            'recommendations_count': len(self.optimization_recommendations),
            'snapshots_in_memory': len(self.performance_snapshots),
            'bandwidth_measurements': len(self.bandwidth_history),
            'analyzer_running': self.running
        }


# Global performance analyzer instance
performance_analyzer = NetworkPerformanceAnalyzer()