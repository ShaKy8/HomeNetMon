"""
Predictive Failure Analysis Service

This service implements advanced failure prediction and early warning capabilities:
1. Analyze historical failure patterns and trends
2. Detect early warning indicators of device failures
3. Predict potential failures before they occur
4. Generate proactive alerts and recommendations
5. Machine learning-based failure risk scoring
6. Performance degradation trend analysis
"""

import logging
import statistics
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any

from models import db, Device, MonitoringData, Alert, Configuration
from services.device_analytics import DeviceBehaviorAnalytics
from services.push_notifications import push_service

logger = logging.getLogger(__name__)


class FailurePredictionEngine:
    """Advanced predictive failure analysis engine"""
    
    def __init__(self, app=None):
        self.app = app
        self.device_analytics = DeviceBehaviorAnalytics()
        
        # Failure prediction models
        self.failure_indicators = {}
        self.device_risk_scores = {}
        self.trend_analysis = {}
        self.prediction_history = {}
        
        # Prediction configuration
        self.prediction_window_days = 7  # How far ahead to predict
        self.analysis_history_days = 30  # Historical data to analyze
        self.risk_thresholds = {
            'critical': 0.85,
            'high': 0.70,
            'medium': 0.50,
            'low': 0.25
        }
        
        # Early warning indicators
        self.warning_indicators = {
            'response_time_degradation': 0.3,  # 30% increase threshold
            'packet_loss_increase': 0.05,      # 5% increase threshold
            'uptime_decline': 0.10,            # 10% decline threshold
            'variability_increase': 0.5,       # 50% increase in response variance
            'failure_frequency_increase': 2.0  # 2x increase in failures
        }
        
        # Performance tracking
        self.prediction_accuracy = {
            'correct_predictions': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'total_predictions': 0
        }
        
        # Real-time monitoring
        self.monitoring_queues = {}
        self.alert_cooldowns = {}
        
    def analyze_failure_risk(self, device_id: int, days: int = None) -> Dict[str, Any]:
        """Comprehensive failure risk analysis for a device"""
        try:
            days = days or self.analysis_history_days
            
            with self.app.app_context():
                device = Device.query.get(device_id)
                if not device:
                    return {'error': 'Device not found'}
                
                cutoff = datetime.utcnow() - timedelta(days=days)
                monitoring_data = MonitoringData.query.filter(
                    MonitoringData.device_id == device_id,
                    MonitoringData.timestamp >= cutoff
                ).order_by(MonitoringData.timestamp.desc()).all()
                
                if len(monitoring_data) < 50:  # Need sufficient data
                    return {
                        'device_id': device_id,
                        'risk_level': 'unknown',
                        'risk_score': 0.0,
                        'confidence': 0.0,
                        'reason': 'Insufficient historical data for analysis',
                        'data_points': len(monitoring_data)
                    }
                
                # Analyze failure indicators
                indicators = self._analyze_failure_indicators(monitoring_data)
                
                # Calculate trend analysis
                trends = self._analyze_performance_trends(monitoring_data)
                
                # Detect early warning signs
                warnings = self._detect_early_warnings(monitoring_data)
                
                # Calculate overall risk score
                risk_score = self._calculate_failure_risk_score(indicators, trends, warnings)
                
                # Determine risk level
                risk_level = self._determine_risk_level(risk_score)
                
                # Generate prediction reasoning
                reasoning = self._generate_failure_reasoning(indicators, trends, warnings, risk_score)
                
                # Store prediction for accuracy tracking
                prediction_record = {
                    'device_id': device_id,
                    'risk_score': risk_score,
                    'risk_level': risk_level,
                    'predicted_at': datetime.utcnow().isoformat(),
                    'prediction_window_days': self.prediction_window_days,
                    'indicators': indicators,
                    'trends': trends,
                    'warnings': warnings
                }
                
                if device_id not in self.prediction_history:
                    self.prediction_history[device_id] = []
                self.prediction_history[device_id].append(prediction_record)
                
                # Keep only recent predictions
                if len(self.prediction_history[device_id]) > 100:
                    self.prediction_history[device_id] = self.prediction_history[device_id][-50:]
                
                result = {
                    'device_id': device_id,
                    'device_name': device.display_name,
                    'risk_score': round(risk_score, 3),
                    'risk_level': risk_level,
                    'confidence': round(indicators.get('confidence', 0.5), 3),
                    'prediction_window_days': self.prediction_window_days,
                    'failure_indicators': indicators,
                    'performance_trends': trends,
                    'early_warnings': warnings,
                    'reasoning': reasoning,
                    'analysis_period_days': days,
                    'data_points_analyzed': len(monitoring_data),
                    'predicted_at': datetime.utcnow().isoformat()
                }
                
                # Trigger alerts for high-risk devices
                if risk_score >= self.risk_thresholds['high']:
                    self._trigger_failure_alert(device, result)
                
                return result
                
        except Exception as e:
            logger.error(f"Error analyzing failure risk for device {device_id}: {e}")
            return {'error': str(e)}
    
    def _analyze_failure_indicators(self, monitoring_data: List) -> Dict[str, Any]:
        """Analyze key indicators that predict failures"""
        response_times = [data.response_time for data in monitoring_data if data.response_time is not None]
        failed_checks = [data for data in monitoring_data if data.response_time is None]
        
        if not monitoring_data:
            return {'confidence': 0.0, 'indicators': {}}
        
        total_checks = len(monitoring_data)
        success_rate = len(response_times) / total_checks
        failure_rate = len(failed_checks) / total_checks
        
        indicators = {
            'success_rate': round(success_rate, 3),
            'failure_rate': round(failure_rate, 3),
            'total_checks': total_checks
        }
        
        # Response time analysis
        if response_times:
            avg_response = statistics.mean(response_times)
            response_variance = statistics.variance(response_times) if len(response_times) > 1 else 0
            response_stdev = statistics.stdev(response_times) if len(response_times) > 1 else 0
            
            indicators.update({
                'avg_response_time': round(avg_response, 2),
                'response_variance': round(response_variance, 2),
                'response_stdev': round(response_stdev, 2),
                'response_variability': round(response_stdev / avg_response, 3) if avg_response > 0 else 0
            })
            
            # Slow response indicator
            slow_responses = len([r for r in response_times if r > 1000])  # > 1 second
            indicators['slow_response_rate'] = round(slow_responses / len(response_times), 3)
        
        # Failure clustering analysis
        failure_clusters = self._analyze_failure_clusters(monitoring_data)
        indicators.update(failure_clusters)
        
        # Calculate confidence based on data quality
        confidence = min(1.0, total_checks / 200.0)  # Higher confidence with more data
        indicators['confidence'] = confidence
        
        return indicators
    
    def _analyze_failure_clusters(self, monitoring_data: List) -> Dict[str, Any]:
        """Analyze patterns in failure clustering"""
        failures = []
        consecutive_failures = 0
        max_consecutive = 0
        failure_clusters = []
        current_cluster = []
        
        for data in reversed(monitoring_data):  # Newest first
            if data.response_time is None:  # Failed check
                failures.append(data.timestamp)
                consecutive_failures += 1
                current_cluster.append(data.timestamp)
                max_consecutive = max(max_consecutive, consecutive_failures)
            else:
                if current_cluster:
                    failure_clusters.append(current_cluster)
                    current_cluster = []
                consecutive_failures = 0
        
        if current_cluster:
            failure_clusters.append(current_cluster)
        
        # Analyze cluster patterns
        cluster_analysis = {
            'total_failures': len(failures),
            'max_consecutive_failures': max_consecutive,
            'failure_clusters': len(failure_clusters),
            'avg_cluster_size': round(statistics.mean([len(cluster) for cluster in failure_clusters]), 2) if failure_clusters else 0
        }
        
        # Calculate failure frequency trend
        if len(failures) >= 2:
            recent_failures = len([f for f in failures if (datetime.utcnow() - f).total_seconds() < 86400 * 7])  # Last 7 days
            older_failures = len([f for f in failures if 86400 * 14 > (datetime.utcnow() - f).total_seconds() >= 86400 * 7])  # 7-14 days ago
            
            if older_failures > 0:
                failure_trend = recent_failures / older_failures
                cluster_analysis['failure_frequency_trend'] = round(failure_trend, 2)
            else:
                cluster_analysis['failure_frequency_trend'] = 1.0 if recent_failures > 0 else 0.0
        else:
            cluster_analysis['failure_frequency_trend'] = 0.0
        
        return cluster_analysis
    
    def _analyze_performance_trends(self, monitoring_data: List) -> Dict[str, Any]:
        """Analyze performance degradation trends"""
        if len(monitoring_data) < 20:
            return {'trend_confidence': 'low', 'reason': 'insufficient_data'}
        
        # Split data into time periods for trend analysis
        data_by_week = defaultdict(list)
        
        for data in monitoring_data:
            week_key = data.timestamp.strftime('%Y-W%U')  # Year-Week format
            if data.response_time is not None:
                data_by_week[week_key].append(data.response_time)
        
        if len(data_by_week) < 2:
            return {'trend_confidence': 'low', 'reason': 'insufficient_time_span'}
        
        # Calculate weekly averages
        weekly_stats = {}
        for week, response_times in data_by_week.items():
            if response_times:
                weekly_stats[week] = {
                    'avg_response': statistics.mean(response_times),
                    'stdev_response': statistics.stdev(response_times) if len(response_times) > 1 else 0,
                    'count': len(response_times)
                }
        
        # Analyze trends
        weeks = sorted(weekly_stats.keys())
        if len(weeks) < 2:
            return {'trend_confidence': 'low', 'reason': 'insufficient_weeks'}
        
        # Response time trend
        response_trend = self._calculate_trend_direction(
            [weekly_stats[week]['avg_response'] for week in weeks]
        )
        
        # Variability trend
        variability_trend = self._calculate_trend_direction(
            [weekly_stats[week]['stdev_response'] for week in weeks]
        )
        
        # Calculate trend strength
        first_week_avg = weekly_stats[weeks[0]]['avg_response']
        last_week_avg = weekly_stats[weeks[-1]]['avg_response']
        
        response_change_percent = ((last_week_avg - first_week_avg) / first_week_avg * 100) if first_week_avg > 0 else 0
        
        trends = {
            'response_time_trend': response_trend,
            'variability_trend': variability_trend,
            'response_change_percent': round(response_change_percent, 1),
            'trend_confidence': 'high' if len(weeks) >= 4 else 'medium',
            'weeks_analyzed': len(weeks),
            'weekly_stats': weekly_stats
        }
        
        return trends
    
    def _calculate_trend_direction(self, values: List[float]) -> str:
        """Calculate trend direction from a series of values"""
        if len(values) < 2:
            return 'unknown'
        
        # Simple linear trend calculation
        n = len(values)
        x_values = list(range(n))
        
        # Calculate correlation coefficient
        x_mean = statistics.mean(x_values)
        y_mean = statistics.mean(values)
        
        numerator = sum((x_values[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        x_variance = sum((x - x_mean) ** 2 for x in x_values)
        y_variance = sum((y - y_mean) ** 2 for y in values)
        
        if x_variance == 0 or y_variance == 0:
            return 'stable'
        
        correlation = numerator / (x_variance * y_variance) ** 0.5
        
        if correlation > 0.3:
            return 'increasing'
        elif correlation < -0.3:
            return 'decreasing'
        else:
            return 'stable'
    
    def _detect_early_warnings(self, monitoring_data: List) -> Dict[str, Any]:
        """Detect early warning signs of potential failures"""
        warnings = {
            'active_warnings': [],
            'warning_score': 0.0,
            'warning_details': {}
        }
        
        if len(monitoring_data) < 20:
            warnings['warning_details']['insufficient_data'] = True
            return warnings
        
        # Split data into recent and baseline periods
        recent_cutoff = datetime.utcnow() - timedelta(days=3)
        recent_data = [data for data in monitoring_data if data.timestamp >= recent_cutoff]
        baseline_data = [data for data in monitoring_data if data.timestamp < recent_cutoff]
        
        if len(recent_data) < 5 or len(baseline_data) < 10:
            warnings['warning_details']['insufficient_comparison_data'] = True
            return warnings
        
        # Analyze recent vs baseline metrics
        recent_responses = [data.response_time for data in recent_data if data.response_time is not None]
        baseline_responses = [data.response_time for data in baseline_data if data.response_time is not None]
        
        if recent_responses and baseline_responses:
            recent_avg = statistics.mean(recent_responses)
            baseline_avg = statistics.mean(baseline_responses)
            
            # Response time degradation warning
            if baseline_avg > 0:
                response_increase = (recent_avg - baseline_avg) / baseline_avg
                if response_increase > self.warning_indicators['response_time_degradation']:
                    warnings['active_warnings'].append('response_time_degradation')
                    warnings['warning_details']['response_degradation'] = {
                        'increase_percent': round(response_increase * 100, 1),
                        'recent_avg': round(recent_avg, 2),
                        'baseline_avg': round(baseline_avg, 2)
                    }
                    warnings['warning_score'] += 0.3
            
            # Response variability warning
            if len(recent_responses) > 1 and len(baseline_responses) > 1:
                recent_stdev = statistics.stdev(recent_responses)
                baseline_stdev = statistics.stdev(baseline_responses)
                
                if baseline_stdev > 0:
                    variability_increase = (recent_stdev - baseline_stdev) / baseline_stdev
                    if variability_increase > self.warning_indicators['variability_increase']:
                        warnings['active_warnings'].append('variability_increase')
                        warnings['warning_details']['variability_increase'] = {
                            'increase_percent': round(variability_increase * 100, 1),
                            'recent_stdev': round(recent_stdev, 2),
                            'baseline_stdev': round(baseline_stdev, 2)
                        }
                        warnings['warning_score'] += 0.2
        
        # Failure rate increase warning
        recent_failures = len([data for data in recent_data if data.response_time is None])
        baseline_failures = len([data for data in baseline_data if data.response_time is None])
        
        recent_failure_rate = recent_failures / len(recent_data) if recent_data else 0
        baseline_failure_rate = baseline_failures / len(baseline_data) if baseline_data else 0
        
        if baseline_failure_rate > 0:
            failure_rate_increase = recent_failure_rate / baseline_failure_rate
            if failure_rate_increase > self.warning_indicators['failure_frequency_increase']:
                warnings['active_warnings'].append('failure_frequency_increase')
                warnings['warning_details']['failure_rate_increase'] = {
                    'increase_multiplier': round(failure_rate_increase, 2),
                    'recent_failure_rate': round(recent_failure_rate * 100, 1),
                    'baseline_failure_rate': round(baseline_failure_rate * 100, 1)
                }
                warnings['warning_score'] += 0.4
        elif recent_failure_rate > 0.1:  # New failures appearing
            warnings['active_warnings'].append('new_failures_detected')
            warnings['warning_details']['new_failures'] = {
                'recent_failure_rate': round(recent_failure_rate * 100, 1)
            }
            warnings['warning_score'] += 0.3
        
        # Uptime decline warning
        recent_uptime = len(recent_responses) / len(recent_data) if recent_data else 0
        baseline_uptime = len(baseline_responses) / len(baseline_data) if baseline_data else 0
        
        if baseline_uptime > 0:
            uptime_decline = (baseline_uptime - recent_uptime) / baseline_uptime
            if uptime_decline > self.warning_indicators['uptime_decline']:
                warnings['active_warnings'].append('uptime_decline')
                warnings['warning_details']['uptime_decline'] = {
                    'decline_percent': round(uptime_decline * 100, 1),
                    'recent_uptime': round(recent_uptime * 100, 1),
                    'baseline_uptime': round(baseline_uptime * 100, 1)
                }
                warnings['warning_score'] += 0.3
        
        return warnings
    
    def _calculate_failure_risk_score(self, indicators: Dict, trends: Dict, warnings: Dict) -> float:
        """Calculate overall failure risk score"""
        risk_score = 0.0
        
        # Base risk from failure indicators
        failure_rate = indicators.get('failure_rate', 0)
        risk_score += failure_rate * 0.4  # 40% weight for current failure rate
        
        # Response time degradation
        avg_response = indicators.get('avg_response_time', 0)
        if avg_response > 0:
            if avg_response > 2000:  # Very slow
                risk_score += 0.3
            elif avg_response > 1000:  # Slow
                risk_score += 0.2
            elif avg_response > 500:  # Moderately slow
                risk_score += 0.1
        
        # Response variability
        variability = indicators.get('response_variability', 0)
        if variability > 1.0:  # High variability
            risk_score += 0.2
        elif variability > 0.5:  # Moderate variability
            risk_score += 0.1
        
        # Failure clustering
        max_consecutive = indicators.get('max_consecutive_failures', 0)
        if max_consecutive > 5:
            risk_score += 0.3
        elif max_consecutive > 2:
            risk_score += 0.15
        
        # Trend analysis
        response_trend = trends.get('response_time_trend', 'stable')
        if response_trend == 'increasing':
            change_percent = abs(trends.get('response_change_percent', 0))
            if change_percent > 50:
                risk_score += 0.25
            elif change_percent > 20:
                risk_score += 0.15
        
        # Early warnings
        warning_score = warnings.get('warning_score', 0)
        risk_score += warning_score * 0.5  # 50% weight for warning indicators
        
        # Failure frequency trend
        frequency_trend = indicators.get('failure_frequency_trend', 1.0)
        if frequency_trend > 2.0:  # Doubling of failures
            risk_score += 0.3
        elif frequency_trend > 1.5:
            risk_score += 0.2
        
        # Normalize to 0-1 range
        return min(1.0, risk_score)
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score"""
        if risk_score >= self.risk_thresholds['critical']:
            return 'critical'
        elif risk_score >= self.risk_thresholds['high']:
            return 'high'
        elif risk_score >= self.risk_thresholds['medium']:
            return 'medium'
        elif risk_score >= self.risk_thresholds['low']:
            return 'low'
        else:
            return 'minimal'
    
    def _generate_failure_reasoning(self, indicators: Dict, trends: Dict, warnings: Dict, risk_score: float) -> List[str]:
        """Generate human-readable reasoning for failure prediction"""
        reasoning = []
        
        # Failure rate reasoning
        failure_rate = indicators.get('failure_rate', 0)
        if failure_rate > 0.2:
            reasoning.append(f"High failure rate detected: {failure_rate*100:.1f}% of checks failing")
        elif failure_rate > 0.1:
            reasoning.append(f"Elevated failure rate: {failure_rate*100:.1f}% of checks failing")
        
        # Response time reasoning
        avg_response = indicators.get('avg_response_time', 0)
        if avg_response > 2000:
            reasoning.append(f"Very slow response times: {avg_response:.0f}ms average")
        elif avg_response > 1000:
            reasoning.append(f"Slow response times detected: {avg_response:.0f}ms average")
        
        # Trend reasoning
        response_trend = trends.get('response_time_trend', 'stable')
        change_percent = trends.get('response_change_percent', 0)
        if response_trend == 'increasing' and change_percent > 20:
            reasoning.append(f"Performance degrading: {change_percent:.1f}% increase in response time")
        
        # Warning reasoning
        active_warnings = warnings.get('active_warnings', [])
        if 'response_time_degradation' in active_warnings:
            reasoning.append("Recent significant increase in response times")
        if 'failure_frequency_increase' in active_warnings:
            reasoning.append("Failure frequency has increased recently")
        if 'uptime_decline' in active_warnings:
            reasoning.append("Device uptime has declined significantly")
        
        # Clustering reasoning
        max_consecutive = indicators.get('max_consecutive_failures', 0)
        if max_consecutive > 5:
            reasoning.append(f"Extended outage detected: {max_consecutive} consecutive failures")
        
        # Overall assessment
        if risk_score >= 0.8:
            reasoning.append("Multiple critical indicators suggest imminent failure risk")
        elif risk_score >= 0.6:
            reasoning.append("Several warning indicators detected")
        elif len(reasoning) == 0:
            reasoning.append("Device performance appears stable")
        
        return reasoning
    
    def _trigger_failure_alert(self, device: Device, analysis_result: Dict):
        """Trigger failure prediction alert"""
        try:
            device_id = device.id
            current_time = datetime.utcnow()
            
            # Check alert cooldown
            if device_id in self.alert_cooldowns:
                last_alert = self.alert_cooldowns[device_id]
                if (current_time - last_alert).total_seconds() < 3600:  # 1 hour cooldown
                    return
            
            risk_level = analysis_result['risk_level']
            risk_score = analysis_result['risk_score']
            reasoning = analysis_result['reasoning']
            
            # Create alert message
            alert_title = f"🔮 Failure Prediction: {device.display_name}"
            alert_message = f"Risk Level: {risk_level.upper()} ({risk_score:.1%})\n"
            alert_message += f"Device: {device.display_name} ({device.ip_address})\n"
            alert_message += f"Key Issues: {', '.join(reasoning[:2])}"
            
            # Send push notification
            if risk_level in ['critical', 'high']:
                dashboard_url = f"http://{Configuration.get_value('host', 'localhost')}:{Configuration.get_value('port', '5000')}"
                
                success = push_service.send_notification(
                    title=alert_title,
                    message=alert_message,
                    priority="high" if risk_level == 'critical' else "default",
                    tags="warning,crystal_ball" if risk_level == 'high' else "bangbang,crystal_ball",
                    click_url=f"{dashboard_url}/device/{device_id}"
                )
                
                if success:
                    logger.info(f"Sent failure prediction alert for {device.display_name}: {risk_level} risk")
                    self.alert_cooldowns[device_id] = current_time
                
        except Exception as e:
            logger.error(f"Error triggering failure alert: {e}")
    
    def analyze_failure_patterns(self, days: int = 30) -> Dict[str, Any]:
        """Analyze failure patterns across all devices"""
        try:
            with self.app.app_context():
                cutoff = datetime.utcnow() - timedelta(days=days)
                
                # Get all devices with monitoring data
                devices = Device.query.filter_by(is_monitored=True).all()
                
                pattern_analysis = {
                    'temporal_patterns': defaultdict(int),
                    'device_type_patterns': defaultdict(lambda: {'failures': 0, 'total_devices': 0}),
                    'vendor_patterns': defaultdict(lambda: {'failures': 0, 'total_devices': 0}),
                    'failure_cascades': [],
                    'common_failure_sequences': [],
                    'network_impact_analysis': {}
                }
                
                device_failures = {}
                all_failures = []
                
                for device in devices:
                    monitoring_data = MonitoringData.query.filter(
                        MonitoringData.device_id == device.id,
                        MonitoringData.timestamp >= cutoff
                    ).order_by(MonitoringData.timestamp.desc()).all()
                    
                    if not monitoring_data:
                        continue
                    
                    # Extract failure events
                    failures = [data for data in monitoring_data if data.response_time is None]
                    device_failures[device.id] = {
                        'device': device,
                        'failures': failures,
                        'total_checks': len(monitoring_data)
                    }
                    
                    # Add to global failure list
                    for failure in failures:
                        all_failures.append({
                            'device_id': device.id,
                            'device': device,
                            'timestamp': failure.timestamp,
                            'device_type': device.device_type,
                            'vendor': device.vendor
                        })
                    
                    # Analyze by device type
                    device_type = device.device_type or 'unknown'
                    pattern_analysis['device_type_patterns'][device_type]['total_devices'] += 1
                    if failures:
                        pattern_analysis['device_type_patterns'][device_type]['failures'] += 1
                    
                    # Analyze by vendor
                    vendor = device.vendor or 'unknown'
                    pattern_analysis['vendor_patterns'][vendor]['total_devices'] += 1
                    if failures:
                        pattern_analysis['vendor_patterns'][vendor]['failures'] += 1
                
                # Temporal pattern analysis
                pattern_analysis['temporal_patterns'] = self._analyze_temporal_failure_patterns(all_failures)
                
                # Failure cascade detection
                pattern_analysis['failure_cascades'] = self._detect_failure_cascades(all_failures)
                
                # Common failure sequence analysis
                pattern_analysis['common_failure_sequences'] = self._analyze_failure_sequences(device_failures)
                
                # Network impact analysis
                pattern_analysis['network_impact_analysis'] = self._analyze_network_impact(device_failures)
                
                return {
                    'pattern_analysis': pattern_analysis,
                    'analysis_period_days': days,
                    'total_devices_analyzed': len(devices),
                    'total_failures': len(all_failures),
                    'analysis_timestamp': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Error analyzing failure patterns: {e}")
            return {'error': str(e)}
    
    def _analyze_temporal_failure_patterns(self, failures: List[Dict]) -> Dict[str, Any]:
        """Analyze when failures occur most frequently"""
        temporal_patterns = {
            'hourly_distribution': defaultdict(int),
            'daily_distribution': defaultdict(int),
            'monthly_distribution': defaultdict(int),
            'peak_failure_times': [],
            'failure_clustering': {}
        }
        
        for failure in failures:
            timestamp = failure['timestamp']
            
            # Hour of day (0-23)
            temporal_patterns['hourly_distribution'][timestamp.hour] += 1
            
            # Day of week (0=Monday, 6=Sunday)
            temporal_patterns['daily_distribution'][timestamp.weekday()] += 1
            
            # Day of month (1-31)
            temporal_patterns['monthly_distribution'][timestamp.day] += 1
        
        # Find peak failure times
        hourly_dist = temporal_patterns['hourly_distribution']
        if hourly_dist:
            peak_hour = max(hourly_dist.items(), key=lambda x: x[1])
            temporal_patterns['peak_failure_times'].append({
                'type': 'hour',
                'time': f"{peak_hour[0]:02d}:00",
                'failure_count': peak_hour[1]
            })
        
        daily_dist = temporal_patterns['daily_distribution']
        if daily_dist:
            days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            peak_day = max(daily_dist.items(), key=lambda x: x[1])
            temporal_patterns['peak_failure_times'].append({
                'type': 'day',
                'time': days[peak_day[0]],
                'failure_count': peak_day[1]
            })
        
        # Analyze failure clustering in time
        if len(failures) > 1:
            failure_times = sorted([f['timestamp'] for f in failures])
            time_gaps = []
            
            for i in range(1, len(failure_times)):
                gap = (failure_times[i] - failure_times[i-1]).total_seconds() / 3600  # Hours
                time_gaps.append(gap)
            
            if time_gaps:
                temporal_patterns['failure_clustering'] = {
                    'avg_time_between_failures_hours': round(statistics.mean(time_gaps), 2),
                    'min_gap_hours': round(min(time_gaps), 2),
                    'max_gap_hours': round(max(time_gaps), 2),
                    'clustered_failures': len([gap for gap in time_gaps if gap < 1])  # Within 1 hour
                }
        
        return dict(temporal_patterns)
    
    def _detect_failure_cascades(self, failures: List[Dict]) -> List[Dict]:
        """Detect failure cascades where multiple devices fail in sequence"""
        cascades = []
        
        if len(failures) < 2:
            return cascades
        
        # Sort failures by time
        sorted_failures = sorted(failures, key=lambda x: x['timestamp'])
        
        # Group failures that occur within cascade window (30 minutes)
        cascade_window = timedelta(minutes=30)
        current_cascade = []
        
        for i, failure in enumerate(sorted_failures):
            if not current_cascade:
                current_cascade = [failure]
                continue
            
            # Check if this failure is within the cascade window
            time_diff = failure['timestamp'] - current_cascade[-1]['timestamp']
            
            if time_diff <= cascade_window:
                current_cascade.append(failure)
            else:
                # Process completed cascade
                if len(current_cascade) >= 3:  # At least 3 devices for a cascade
                    cascade_info = self._analyze_cascade(current_cascade)
                    if cascade_info:
                        cascades.append(cascade_info)
                
                # Start new cascade
                current_cascade = [failure]
        
        # Process final cascade
        if len(current_cascade) >= 3:
            cascade_info = self._analyze_cascade(current_cascade)
            if cascade_info:
                cascades.append(cascade_info)
        
        return cascades
    
    def _analyze_cascade(self, cascade_failures: List[Dict]) -> Optional[Dict]:
        """Analyze a single failure cascade"""
        if len(cascade_failures) < 3:
            return None
        
        start_time = cascade_failures[0]['timestamp']
        end_time = cascade_failures[-1]['timestamp']
        duration = (end_time - start_time).total_seconds() / 60  # Minutes
        
        # Analyze device types involved
        device_types = [f['device_type'] for f in cascade_failures]
        type_counts = Counter(device_types)
        
        # Analyze vendors involved
        vendors = [f['vendor'] for f in cascade_failures if f['vendor']]
        vendor_counts = Counter(vendors)
        
        # Check for network patterns (IP ranges)
        ip_addresses = [f['device'].ip_address for f in cascade_failures if f['device'].ip_address]
        ip_pattern = self._analyze_ip_pattern(ip_addresses)
        
        cascade_info = {
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_minutes': round(duration, 2),
            'affected_devices': len(cascade_failures),
            'device_types': dict(type_counts),
            'vendors': dict(vendor_counts),
            'ip_pattern': ip_pattern,
            'cascade_speed': round(len(cascade_failures) / max(duration, 1), 2),  # Devices per minute
            'devices': [
                {
                    'device_id': f['device_id'],
                    'device_name': f['device'].display_name,
                    'ip_address': f['device'].ip_address,
                    'failure_time': f['timestamp'].isoformat()
                } for f in cascade_failures
            ]
        }
        
        return cascade_info
    
    def _analyze_ip_pattern(self, ip_addresses: List[str]) -> Dict[str, Any]:
        """Analyze IP address patterns in failures"""
        if not ip_addresses:
            return {'pattern': 'no_ips'}
        
        # Group by subnet
        subnets = defaultdict(int)
        for ip in ip_addresses:
            try:
                parts = ip.split('.')
                if len(parts) == 4:
                    subnet = '.'.join(parts[:3]) + '.0/24'
                    subnets[subnet] += 1
            except:
                continue
        
        # Check for sequential IPs
        sequential_count = 0
        if len(ip_addresses) > 1:
            sorted_ips = sorted(ip_addresses, key=lambda ip: [int(x) for x in ip.split('.')])
            for i in range(1, len(sorted_ips)):
                try:
                    current_parts = [int(x) for x in sorted_ips[i].split('.')]
                    prev_parts = [int(x) for x in sorted_ips[i-1].split('.')]
                    
                    # Check if IPs are sequential
                    if (current_parts[:-1] == prev_parts[:-1] and 
                        current_parts[-1] == prev_parts[-1] + 1):
                        sequential_count += 1
                except:
                    continue
        
        return {
            'subnets_affected': dict(subnets),
            'sequential_ips': sequential_count,
            'pattern': 'sequential' if sequential_count > 0 else 'scattered'
        }
    
    def _analyze_failure_sequences(self, device_failures: Dict) -> List[Dict]:
        """Analyze common failure sequences and patterns"""
        sequences = []
        
        # Find devices that fail together frequently
        failure_correlations = defaultdict(int)
        
        for device_id, data in device_failures.items():
            device_failure_times = [f.timestamp for f in data['failures']]
            
            for other_device_id, other_data in device_failures.items():
                if device_id >= other_device_id:  # Avoid duplicates
                    continue
                
                other_failure_times = [f.timestamp for f in other_data['failures']]
                
                # Count concurrent failures (within 5 minutes)
                concurrent_failures = 0
                for failure_time in device_failure_times:
                    for other_failure_time in other_failure_times:
                        if abs((failure_time - other_failure_time).total_seconds()) <= 300:  # 5 minutes
                            concurrent_failures += 1
                            break
                
                if concurrent_failures > 0:
                    device_pair = tuple(sorted([device_id, other_device_id]))
                    failure_correlations[device_pair] += concurrent_failures
        
        # Convert to sequence information
        for device_pair, correlation_count in failure_correlations.items():
            if correlation_count >= 2:  # At least 2 concurrent failures
                device1 = Device.query.get(device_pair[0])
                device2 = Device.query.get(device_pair[1])
                
                sequences.append({
                    'device_pair': {
                        'device1': {'id': device1.id, 'name': device1.display_name, 'ip': device1.ip_address},
                        'device2': {'id': device2.id, 'name': device2.display_name, 'ip': device2.ip_address}
                    },
                    'concurrent_failures': correlation_count,
                    'correlation_strength': 'high' if correlation_count >= 5 else 'medium'
                })
        
        return sequences
    
    def _analyze_network_impact(self, device_failures: Dict) -> Dict[str, Any]:
        """Analyze network-wide impact of failures"""
        impact_analysis = {
            'critical_device_failures': [],
            'infrastructure_impact': {},
            'cascade_risk_score': 0.0
        }
        
        # Identify critical device failures
        for device_id, data in device_failures.items():
            device = data['device']
            failure_count = len(data['failures'])
            total_checks = data['total_checks']
            
            if failure_count == 0:
                continue
            
            failure_rate = failure_count / total_checks if total_checks > 0 else 0
            
            # Consider device critical if it's infrastructure or has high failure rate
            is_critical = (
                device.ip_address and device.ip_address.endswith('.1') or  # Gateway
                device.device_type in ['router', 'switch', 'gateway'] or
                failure_rate > 0.2  # High failure rate
            )
            
            if is_critical:
                impact_analysis['critical_device_failures'].append({
                    'device_id': device.id,
                    'device_name': device.display_name,
                    'device_type': device.device_type,
                    'ip_address': device.ip_address,
                    'failure_count': failure_count,
                    'failure_rate': round(failure_rate, 3),
                    'impact_level': 'high' if failure_rate > 0.3 else 'medium'
                })
        
        # Calculate cascade risk score
        total_devices = len(device_failures)
        devices_with_failures = len([d for d in device_failures.values() if d['failures']])
        
        if total_devices > 0:
            failure_spread = devices_with_failures / total_devices
            impact_analysis['cascade_risk_score'] = min(1.0, failure_spread * 2)  # 0-1 scale
        
        # Infrastructure impact assessment
        infrastructure_devices = [
            device_id for device_id, data in device_failures.items()
            if data['device'].device_type in ['router', 'switch', 'gateway'] or
            (data['device'].ip_address and data['device'].ip_address.endswith('.1'))
        ]
        
        infrastructure_failures = [
            device_id for device_id in infrastructure_devices
            if device_failures[device_id]['failures']
        ]
        
        impact_analysis['infrastructure_impact'] = {
            'total_infrastructure_devices': len(infrastructure_devices),
            'infrastructure_failures': len(infrastructure_failures),
            'infrastructure_failure_rate': len(infrastructure_failures) / len(infrastructure_devices) 
                                         if infrastructure_devices else 0
        }
        
        return impact_analysis
    
    def predict_device_mtbf(self, device_id: int, days: int = 90) -> Dict[str, Any]:
        """Predict Mean Time Between Failures for a device"""
        try:
            with self.app.app_context():
                device = Device.query.get(device_id)
                if not device:
                    return {'error': 'Device not found'}
                
                cutoff = datetime.utcnow() - timedelta(days=days)
                monitoring_data = MonitoringData.query.filter(
                    MonitoringData.device_id == device_id,
                    MonitoringData.timestamp >= cutoff
                ).order_by(MonitoringData.timestamp.asc()).all()
                
                if len(monitoring_data) < 100:
                    return {
                        'device_id': device_id,
                        'mtbf_prediction': 'insufficient_data',
                        'confidence': 'low',
                        'data_points': len(monitoring_data)
                    }
                
                # Extract failure events
                failures = [data for data in monitoring_data if data.response_time is None]
                
                if len(failures) < 2:
                    return {
                        'device_id': device_id,
                        'device_name': device.display_name,
                        'mtbf_prediction': 'very_reliable',
                        'estimated_mtbf_days': '>90',
                        'confidence': 'medium',
                        'failure_count': len(failures),
                        'analysis_period_days': days
                    }
                
                # Calculate time between failures
                failure_times = [f.timestamp for f in failures]
                failure_times.sort()
                
                time_between_failures = []
                for i in range(1, len(failure_times)):
                    gap = (failure_times[i] - failure_times[i-1]).total_seconds() / 86400  # Days
                    time_between_failures.append(gap)
                
                # Calculate MTBF statistics
                mean_tbf = statistics.mean(time_between_failures)
                median_tbf = statistics.median(time_between_failures)
                stdev_tbf = statistics.stdev(time_between_failures) if len(time_between_failures) > 1 else 0
                
                # Predict future MTBF based on trend
                if len(time_between_failures) >= 3:
                    # Simple trend analysis
                    recent_tbf = statistics.mean(time_between_failures[-3:])
                    trend_factor = recent_tbf / mean_tbf if mean_tbf > 0 else 1
                else:
                    trend_factor = 1.0
                
                predicted_mtbf = mean_tbf * trend_factor
                
                # Determine confidence based on data consistency
                variability = stdev_tbf / mean_tbf if mean_tbf > 0 else 1
                if variability < 0.3:
                    confidence = 'high'
                elif variability < 0.6:
                    confidence = 'medium'
                else:
                    confidence = 'low'
                
                return {
                    'device_id': device_id,
                    'device_name': device.display_name,
                    'mtbf_statistics': {
                        'mean_tbf_days': round(mean_tbf, 2),
                        'median_tbf_days': round(median_tbf, 2),
                        'stdev_tbf_days': round(stdev_tbf, 2),
                        'variability': round(variability, 3)
                    },
                    'predicted_mtbf_days': round(predicted_mtbf, 2),
                    'confidence': confidence,
                    'trend_factor': round(trend_factor, 3),
                    'total_failures': len(failures),
                    'analysis_period_days': days,
                    'reliability_assessment': self._assess_reliability(predicted_mtbf),
                    'predicted_at': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Error predicting MTBF for device {device_id}: {e}")
            return {'error': str(e)}
    
    def _assess_reliability(self, mtbf_days: float) -> str:
        """Assess device reliability based on MTBF"""
        if mtbf_days > 30:
            return 'very_reliable'
        elif mtbf_days > 14:
            return 'reliable'
        elif mtbf_days > 7:
            return 'moderately_reliable'
        elif mtbf_days > 3:
            return 'unreliable'
        else:
            return 'very_unreliable'
    
    def start_early_warning_system(self):
        """Start continuous early warning monitoring"""
        def early_warning_loop():
            while True:
                try:
                    if self.app:
                        with self.app.app_context():
                            # Get all monitored devices
                            devices = Device.query.filter_by(is_monitored=True).all()
                            
                            high_risk_devices = []
                            warnings_sent = 0
                            
                            for device in devices:
                                try:
                                    # Analyze failure risk
                                    risk_analysis = self.analyze_failure_risk(device.id, days=14)
                                    
                                    if 'error' not in risk_analysis:
                                        risk_score = risk_analysis.get('risk_score', 0)
                                        risk_level = risk_analysis.get('risk_level', 'minimal')
                                        
                                        # Track high-risk devices
                                        if risk_score >= self.risk_thresholds['medium']:
                                            high_risk_devices.append({
                                                'device': device,
                                                'risk_analysis': risk_analysis
                                            })
                                        
                                        # Send early warning for critical/high risk
                                        if risk_score >= self.risk_thresholds['high']:
                                            warning_sent = self._send_early_warning(device, risk_analysis)
                                            if warning_sent:
                                                warnings_sent += 1
                                    
                                except Exception as e:
                                    logger.error(f"Error in early warning analysis for device {device.id}: {e}")
                                    continue
                            
                            # Log early warning summary
                            if high_risk_devices:
                                logger.info(f"Early warning scan: {len(high_risk_devices)} high-risk devices, {warnings_sent} warnings sent")
                            
                            # Store system-wide early warning status
                            self._update_early_warning_status(high_risk_devices)
                    
                    # Run every 30 minutes
                    time.sleep(1800)
                    
                except Exception as e:
                    logger.error(f"Error in early warning system loop: {e}")
                    time.sleep(1800)
        
        warning_thread = threading.Thread(target=early_warning_loop, daemon=True, name='EarlyWarning')
        warning_thread.start()
        logger.info("Early warning system started")
    
    def _send_early_warning(self, device: Device, risk_analysis: Dict) -> bool:
        """Send early warning notification for high-risk device"""
        try:
            device_id = device.id
            current_time = datetime.utcnow()
            
            # Check alert cooldown (4 hours for early warnings)
            if device_id in self.alert_cooldowns:
                last_alert = self.alert_cooldowns[device_id]
                if (current_time - last_alert).total_seconds() < 14400:  # 4 hours
                    return False
            
            risk_level = risk_analysis['risk_level']
            risk_score = risk_analysis['risk_score']
            reasoning = risk_analysis['reasoning']
            early_warnings = risk_analysis.get('early_warnings', {})
            
            # Create early warning message
            warning_title = f"⚠️ Early Warning: {device.display_name}"
            
            warning_message = f"Potential failure predicted!\n"
            warning_message += f"Risk Level: {risk_level.upper()} ({risk_score:.1%})\n"
            warning_message += f"Device: {device.display_name} ({device.ip_address})\n"
            
            # Add specific warning indicators
            active_warnings = early_warnings.get('active_warnings', [])
            if active_warnings:
                warning_message += f"Indicators: {', '.join(active_warnings[:2])}\n"
            
            # Add key reasoning
            if reasoning:
                warning_message += f"Concern: {reasoning[0]}"
            
            # Determine alert priority
            priority = "high" if risk_level == 'critical' else "default"
            tags = "warning,triangular_flag_on_post"
            
            if risk_level == 'critical':
                tags = "rotating_light,triangular_flag_on_post"
            
            # Send notification
            dashboard_url = f"http://{Configuration.get_value('host', 'localhost')}:{Configuration.get_value('port', '5000')}"
            
            success = push_service.send_notification(
                title=warning_title,
                message=warning_message,
                priority=priority,
                tags=tags,
                click_url=f"{dashboard_url}/device/{device_id}"
            )
            
            if success:
                logger.info(f"Sent early warning for {device.display_name}: {risk_level} risk")
                self.alert_cooldowns[device_id] = current_time
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error sending early warning: {e}")
            return False
    
    def _update_early_warning_status(self, high_risk_devices: List[Dict]):
        """Update system-wide early warning status"""
        try:
            current_time = datetime.utcnow()
            
            # Store in a simple cache for API access
            self.early_warning_status = {
                'last_scan': current_time.isoformat(),
                'high_risk_device_count': len(high_risk_devices),
                'critical_devices': [
                    {
                        'device_id': item['device'].id,
                        'device_name': item['device'].display_name,
                        'risk_level': item['risk_analysis']['risk_level'],
                        'risk_score': item['risk_analysis']['risk_score']
                    }
                    for item in high_risk_devices 
                    if item['risk_analysis']['risk_level'] in ['critical', 'high']
                ],
                'system_health': 'critical' if any(
                    item['risk_analysis']['risk_level'] == 'critical' 
                    for item in high_risk_devices
                ) else 'warning' if high_risk_devices else 'good'
            }
            
        except Exception as e:
            logger.error(f"Error updating early warning status: {e}")
    
    def get_early_warning_status(self) -> Dict[str, Any]:
        """Get current early warning system status"""
        try:
            if not hasattr(self, 'early_warning_status'):
                return {
                    'status': 'not_initialized',
                    'message': 'Early warning system not yet initialized'
                }
            
            return {
                'status': 'active',
                'early_warning_data': self.early_warning_status,
                'system_configuration': {
                    'risk_thresholds': self.risk_thresholds,
                    'warning_indicators': self.warning_indicators,
                    'prediction_window_days': self.prediction_window_days
                },
                'retrieved_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting early warning status: {e}")
            return {'error': str(e)}
    
    def analyze_network_failure_risk(self, days: int = 14) -> Dict[str, Any]:
        """Analyze overall network failure risk"""
        try:
            with self.app.app_context():
                devices = Device.query.filter_by(is_monitored=True).all()
                
                if not devices:
                    return {'error': 'No monitored devices found'}
                
                network_analysis = {
                    'total_devices': len(devices),
                    'device_risk_distribution': defaultdict(int),
                    'high_risk_devices': [],
                    'infrastructure_risk': {},
                    'overall_network_risk': 0.0,
                    'cascade_probability': 0.0,
                    'recommendations': []
                }
                
                device_risks = []
                infrastructure_at_risk = 0
                total_infrastructure = 0
                
                for device in devices:
                    try:
                        risk_analysis = self.analyze_failure_risk(device.id, days=days)
                        
                        if 'error' not in risk_analysis:
                            risk_level = risk_analysis['risk_level']
                            risk_score = risk_analysis['risk_score']
                            
                            device_risks.append(risk_score)
                            network_analysis['device_risk_distribution'][risk_level] += 1
                            
                            # Track high-risk devices
                            if risk_score >= self.risk_thresholds['medium']:
                                network_analysis['high_risk_devices'].append({
                                    'device_id': device.id,
                                    'device_name': device.display_name,
                                    'device_type': device.device_type,
                                    'ip_address': device.ip_address,
                                    'risk_level': risk_level,
                                    'risk_score': round(risk_score, 3)
                                })
                            
                            # Check infrastructure devices
                            is_infrastructure = (
                                device.device_type in ['router', 'switch', 'gateway'] or
                                (device.ip_address and device.ip_address.endswith('.1'))
                            )
                            
                            if is_infrastructure:
                                total_infrastructure += 1
                                if risk_score >= self.risk_thresholds['medium']:
                                    infrastructure_at_risk += 1
                    
                    except Exception as e:
                        logger.warning(f"Error analyzing device {device.id} for network risk: {e}")
                        continue
                
                # Calculate overall network risk
                if device_risks:
                    avg_risk = statistics.mean(device_risks)
                    max_risk = max(device_risks)
                    risk_variance = statistics.variance(device_risks) if len(device_risks) > 1 else 0
                    
                    # Weight average risk with maximum risk for overall assessment
                    network_analysis['overall_network_risk'] = round((avg_risk * 0.7 + max_risk * 0.3), 3)
                
                # Infrastructure risk analysis
                if total_infrastructure > 0:
                    infrastructure_risk_rate = infrastructure_at_risk / total_infrastructure
                    network_analysis['infrastructure_risk'] = {
                        'total_infrastructure_devices': total_infrastructure,
                        'infrastructure_at_risk': infrastructure_at_risk,
                        'infrastructure_risk_rate': round(infrastructure_risk_rate, 3),
                        'infrastructure_risk_level': self._assess_infrastructure_risk(infrastructure_risk_rate)
                    }
                
                # Cascade probability assessment
                high_risk_count = len(network_analysis['high_risk_devices'])
                cascade_probability = min(1.0, (high_risk_count / len(devices)) * 1.5)
                network_analysis['cascade_probability'] = round(cascade_probability, 3)
                
                # Generate recommendations
                network_analysis['recommendations'] = self._generate_network_recommendations(
                    network_analysis, high_risk_count, infrastructure_at_risk
                )
                
                return {
                    'network_risk_analysis': network_analysis,
                    'analysis_period_days': days,
                    'analyzed_at': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Error analyzing network failure risk: {e}")
            return {'error': str(e)}
    
    def _assess_infrastructure_risk(self, risk_rate: float) -> str:
        """Assess infrastructure risk level"""
        if risk_rate >= 0.5:
            return 'critical'
        elif risk_rate >= 0.3:
            return 'high'
        elif risk_rate >= 0.1:
            return 'medium'
        else:
            return 'low'
    
    def _generate_network_recommendations(self, analysis: Dict, high_risk_count: int, infrastructure_at_risk: int) -> List[str]:
        """Generate network-wide recommendations"""
        recommendations = []
        
        overall_risk = analysis['overall_network_risk']
        cascade_prob = analysis['cascade_probability']
        
        # Overall risk recommendations
        if overall_risk >= 0.7:
            recommendations.append("🚨 Network in critical state - immediate attention required for multiple devices")
        elif overall_risk >= 0.5:
            recommendations.append("⚠️ Network showing concerning trends - review high-risk devices promptly")
        
        # High-risk device recommendations
        if high_risk_count >= 5:
            recommendations.append(f"📊 {high_risk_count} devices at elevated risk - consider staggered maintenance")
        elif high_risk_count >= 2:
            recommendations.append(f"🔍 Monitor {high_risk_count} high-risk devices closely")
        
        # Infrastructure recommendations
        if infrastructure_at_risk > 0:
            recommendations.append(f"🏗️ {infrastructure_at_risk} critical infrastructure device(s) at risk - prioritize immediately")
        
        # Cascade risk recommendations
        if cascade_prob >= 0.6:
            recommendations.append("⛓️ High cascade failure probability - implement redundancy measures")
        elif cascade_prob >= 0.3:
            recommendations.append("🔗 Moderate cascade risk detected - review device dependencies")
        
        # General recommendations
        if analysis['device_risk_distribution']['critical'] > 0:
            recommendations.append("🔧 Schedule immediate maintenance for critical-risk devices")
        
        if len(recommendations) == 0:
            recommendations.append("✅ Network stability appears good - continue regular monitoring")
        
        return recommendations


# Global predictive failure instance
predictive_failure_engine = FailurePredictionEngine()