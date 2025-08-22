"""
Device Behavior Analytics Service

This service implements machine learning and statistical analysis to:
1. Classify devices based on network behavior patterns
2. Learn device fingerprints from traffic characteristics
3. Identify device types using response patterns, timing, and metadata
4. Continuously improve classification accuracy through learning

Key Features:
- Pattern-based device fingerprinting
- Response time characteristic analysis
- Network behavior classification
- MAC vendor correlation
- Hostname pattern matching
- Traffic pattern analysis
"""

import logging
import re
import statistics
import threading
import time
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import json

from models import db, Device, MonitoringData, Configuration
from config import Config

logger = logging.getLogger(__name__)


class DeviceCharacteristics:
    """Container for device behavioral characteristics"""
    
    def __init__(self, device_id: int):
        self.device_id = device_id
        self.response_patterns = []
        self.uptime_patterns = []
        self.failure_patterns = []
        self.timing_characteristics = {}
        self.vendor_info = None
        self.hostname_patterns = []
        self.confidence_scores = {}
        
    def to_dict(self):
        return {
            'device_id': self.device_id,
            'response_patterns': self.response_patterns,
            'uptime_patterns': self.uptime_patterns,
            'failure_patterns': self.failure_patterns,
            'timing_characteristics': self.timing_characteristics,
            'vendor_info': self.vendor_info,
            'hostname_patterns': self.hostname_patterns,
            'confidence_scores': self.confidence_scores
        }


class DeviceBehaviorAnalytics:
    """Advanced analytics service for device behavior analysis and classification"""
    
    def __init__(self, app=None):
        self.app = app
        self.device_profiles = {}  # device_id -> DeviceCharacteristics
        self.classification_rules = self._load_classification_rules()
        self.learning_enabled = True
        self.analysis_cache = {}
        self._cache_expiry = {}
        self._lock = threading.RLock()
        
        # Classification confidence thresholds
        self.confidence_thresholds = {
            'high': 0.85,
            'medium': 0.65,
            'low': 0.45
        }
        
        # Device type patterns and characteristics
        self.device_type_patterns = self._initialize_device_patterns()
        
    def _load_classification_rules(self) -> Dict[str, Any]:
        """Load device classification rules and patterns"""
        return {
            'router': {
                'response_time_range': (0.5, 15.0),  # Routers typically fast but can vary
                'uptime_expectation': 0.99,  # Very high uptime
                'ip_patterns': [r'\.1$', r'\.254$', r'\.0\.1$'],  # Common router IPs
                'hostname_patterns': [
                    r'router', r'gateway', r'gw-', r'rt-', r'fw-', r'firewall',
                    r'linksys', r'netgear', r'dlink', r'tplink', r'asus.*router'
                ],
                'vendor_patterns': [
                    'cisco', 'netgear', 'linksys', 'tp-link', 'asus', 'ubiquiti',
                    'mikrotik', 'dlink', 'buffalo', 'belkin'
                ],
                'behavior_patterns': {
                    'consistent_response': True,
                    'rarely_offline': True,
                    'infrastructure_role': True
                }
            },
            'computer': {
                'response_time_range': (1.0, 50.0),
                'uptime_expectation': 0.75,  # Variable uptime (sleep, shutdown)
                'hostname_patterns': [
                    r'pc-', r'desktop-', r'laptop-', r'workstation', r'computer',
                    r'dell-', r'hp-', r'lenovo-', r'thinkpad', r'macbook',
                    r'imac', r'windows-', r'ubuntu-', r'linux-'
                ],
                'vendor_patterns': [
                    'dell', 'hewlett', 'lenovo', 'asus', 'acer', 'apple',
                    'microsoft', 'msi', 'gigabyte', 'intel'
                ],
                'behavior_patterns': {
                    'variable_response': True,
                    'periodic_offline': True,
                    'user_device': True
                }
            },
            'phone': {
                'response_time_range': (5.0, 100.0),  # Mobile networks can be slower
                'uptime_expectation': 0.80,  # Good uptime but mobile
                'hostname_patterns': [
                    r'iphone', r'android', r'samsung', r'pixel', r'oneplus',
                    r'xiaomi', r'huawei', r'motorola', r'lg.*phone', r'phone'
                ],
                'vendor_patterns': [
                    'apple', 'samsung', 'google', 'oneplus', 'xiaomi',
                    'huawei', 'motorola', 'lg', 'sony', 'nokia'
                ],
                'behavior_patterns': {
                    'mobile_patterns': True,
                    'battery_dependent': True,
                    'wifi_sleep': True
                }
            },
            'iot': {
                'response_time_range': (2.0, 200.0),  # Highly variable
                'uptime_expectation': 0.85,  # Usually always on
                'hostname_patterns': [
                    r'esp\d+', r'arduino', r'raspberry', r'sensor-', r'smart-',
                    r'thermostat', r'camera-', r'bulb-', r'plug-', r'switch-',
                    r'doorbell', r'lock-', r'alarm'
                ],
                'vendor_patterns': [
                    'espressif', 'raspberry', 'arduino', 'philips', 'wemo',
                    'nest', 'ring', 'wyze', 'arlo', 'ecobee'
                ],
                'behavior_patterns': {
                    'always_on': True,
                    'minimal_traffic': True,
                    'embedded_device': True
                }
            },
            'media': {
                'response_time_range': (2.0, 30.0),
                'uptime_expectation': 0.90,  # Usually on when TV is on
                'hostname_patterns': [
                    r'roku', r'appletv', r'chromecast', r'firetv', r'nvidia.*shield',
                    r'xbox', r'playstation', r'ps\d+', r'tv-', r'media-',
                    r'streaming'
                ],
                'vendor_patterns': [
                    'roku', 'apple', 'google', 'amazon', 'nvidia', 'microsoft',
                    'sony', 'lg', 'samsung', 'tcl'
                ],
                'behavior_patterns': {
                    'entertainment_hours': True,
                    'streaming_device': True,
                    'user_controlled': True
                }
            },
            'camera': {
                'response_time_range': (5.0, 50.0),
                'uptime_expectation': 0.95,  # Security devices should be reliable
                'hostname_patterns': [
                    r'camera', r'cam-', r'security', r'doorbell', r'ring',
                    r'wyze', r'arlo', r'nest.*cam', r'surveillance',
                    r'ipcam', r'webcam'
                ],
                'vendor_patterns': [
                    'ring', 'wyze', 'arlo', 'nest', 'hikvision', 'dahua',
                    'axis', 'foscam', 'amcrest', 'reolink'
                ],
                'behavior_patterns': {
                    'security_device': True,
                    'always_on': True,
                    'video_traffic': True
                }
            },
            'printer': {
                'response_time_range': (10.0, 100.0),  # Printers can be slow
                'uptime_expectation': 0.70,  # Often sleep or turned off
                'hostname_patterns': [
                    r'printer', r'print-', r'hp.*printer', r'canon.*printer',
                    r'epson', r'brother', r'lexmark', r'xerox'
                ],
                'vendor_patterns': [
                    'hewlett', 'canon', 'epson', 'brother', 'lexmark',
                    'xerox', 'samsung', 'ricoh', 'kyocera'
                ],
                'behavior_patterns': {
                    'office_device': True,
                    'sleep_mode': True,
                    'periodic_use': True
                }
            }
        }
    
    def _initialize_device_patterns(self) -> Dict[str, Any]:
        """Initialize comprehensive device pattern database"""
        return {
            'mac_oui_patterns': {
                # Apple devices
                '00:1b:63': 'apple', '00:1f:f3': 'apple', '3c:07:54': 'apple',
                '4c:8d:79': 'apple', '8c:2d:aa': 'apple', 'a4:c3:61': 'apple',
                
                # Samsung devices  
                '00:12:fb': 'samsung', '00:15:99': 'samsung', '00:16:32': 'samsung',
                '00:1a:8a': 'samsung', 'a0:02:dc': 'samsung',
                
                # Intel (common in computers)
                '00:13:02': 'intel', '00:15:17': 'intel', '00:16:76': 'intel',
                '00:19:d1': 'intel', '00:1b:77': 'intel',
                
                # Raspberry Pi Foundation
                'b8:27:eb': 'raspberry_pi', 'dc:a6:32': 'raspberry_pi',
                
                # Espressif (ESP32/ESP8266 IoT devices)
                '24:0a:c4': 'espressif', '30:ae:a4': 'espressif', '84:cc:a8': 'espressif',
            },
            
            'port_patterns': {
                'router': [22, 23, 53, 80, 443, 8080],  # SSH, Telnet, DNS, HTTP, HTTPS
                'computer': [22, 135, 139, 445, 3389, 5000, 5900],  # SSH, RPC, SMB, RDP, VNC
                'printer': [9100, 631, 515, 80, 443],  # IPP, LPD, HTTP
                'camera': [80, 443, 554, 1935, 8080],  # HTTP, HTTPS, RTSP, RTMP
                'media': [8080, 32400, 8096, 1900],  # Plex, Jellyfin, UPnP
            },
            
            'response_time_signatures': {
                'embedded_fast': (0.5, 5.0),      # Well-designed embedded devices
                'embedded_slow': (5.0, 50.0),     # Resource-constrained IoT
                'computer_local': (1.0, 10.0),    # Local network computers
                'computer_busy': (10.0, 100.0),   # Busy or slow computers
                'infrastructure': (0.5, 15.0),    # Routers, switches
                'wireless_good': (2.0, 20.0),     # Good WiFi devices
                'wireless_poor': (20.0, 200.0),   # Poor signal/congested
            }
        }
    
    def analyze_device_behavior(self, device_id: int, days: int = 7) -> DeviceCharacteristics:
        """
        Analyze device behavior over the specified time period
        
        Args:
            device_id: ID of device to analyze
            days: Number of days of history to analyze
            
        Returns:
            DeviceCharacteristics object with analysis results
        """
        if not self.app:
            return None
            
        try:
            with self.app.app_context():
                device = Device.query.get(device_id)
                if not device:
                    return None
                
                # Check cache first
                cache_key = f"behavior_{device_id}_{days}"
                if cache_key in self.analysis_cache:
                    cache_time = self._cache_expiry.get(cache_key, 0)
                    if time.time() - cache_time < 3600:  # 1 hour cache
                        return self.analysis_cache[cache_key]
                
                characteristics = DeviceCharacteristics(device_id)
                
                # Get monitoring data for analysis period
                cutoff_date = datetime.utcnow() - timedelta(days=days)
                monitoring_data = MonitoringData.query.filter(
                    MonitoringData.device_id == device_id,
                    MonitoringData.timestamp >= cutoff_date
                ).order_by(MonitoringData.timestamp).all()
                
                if not monitoring_data:
                    return characteristics
                
                # Analyze response time patterns
                characteristics.response_patterns = self._analyze_response_patterns(monitoring_data)
                
                # Analyze uptime patterns
                characteristics.uptime_patterns = self._analyze_uptime_patterns(monitoring_data)
                
                # Analyze failure patterns
                characteristics.failure_patterns = self._analyze_failure_patterns(monitoring_data)
                
                # Analyze timing characteristics
                characteristics.timing_characteristics = self._analyze_timing_characteristics(monitoring_data)
                
                # Analyze vendor and hostname patterns
                characteristics.vendor_info = self._analyze_vendor_patterns(device)
                characteristics.hostname_patterns = self._analyze_hostname_patterns(device)
                
                # Calculate confidence scores for each device type
                characteristics.confidence_scores = self._calculate_classification_confidence(characteristics, device)
                
                # Cache results
                with self._lock:
                    self.analysis_cache[cache_key] = characteristics
                    self._cache_expiry[cache_key] = time.time()
                
                return characteristics
                
        except Exception as e:
            logger.error(f"Error analyzing device behavior for device {device_id}: {e}")
            return DeviceCharacteristics(device_id)
    
    def _analyze_response_patterns(self, monitoring_data: List[MonitoringData]) -> Dict[str, Any]:
        """Analyze response time patterns to identify device characteristics"""
        successful_responses = [data.response_time for data in monitoring_data if data.response_time is not None]
        
        if not successful_responses:
            return {'pattern': 'no_data', 'confidence': 0.0}
        
        patterns = {
            'count': len(successful_responses),
            'mean': statistics.mean(successful_responses),
            'median': statistics.median(successful_responses),
            'std_dev': statistics.stdev(successful_responses) if len(successful_responses) > 1 else 0,
            'min': min(successful_responses),
            'max': max(successful_responses),
            'percentiles': {
                '25': statistics.quantiles(successful_responses, n=4)[0] if len(successful_responses) >= 4 else None,
                '75': statistics.quantiles(successful_responses, n=4)[2] if len(successful_responses) >= 4 else None,
                '95': statistics.quantiles(successful_responses, n=20)[18] if len(successful_responses) >= 20 else None
            }
        }
        
        # Classify response pattern
        mean_response = patterns['mean']
        std_dev = patterns['std_dev']
        
        if mean_response < 5.0 and std_dev < 2.0:
            patterns['classification'] = 'fast_consistent'  # Likely infrastructure
        elif mean_response < 15.0 and std_dev < 10.0:
            patterns['classification'] = 'moderate_consistent'  # Likely computer/server
        elif mean_response > 50.0 or std_dev > 30.0:
            patterns['classification'] = 'slow_variable'  # Likely mobile/IoT
        else:
            patterns['classification'] = 'variable'  # Mixed behavior
        
        return patterns
    
    def _analyze_uptime_patterns(self, monitoring_data: List[MonitoringData]) -> Dict[str, Any]:
        """Analyze uptime patterns to identify device usage characteristics"""
        total_checks = len(monitoring_data)
        successful_checks = len([data for data in monitoring_data if data.response_time is not None])
        
        uptime_percentage = (successful_checks / total_checks * 100) if total_checks > 0 else 0
        
        # Analyze daily patterns
        daily_uptime = defaultdict(list)
        hourly_uptime = defaultdict(list)
        
        for data in monitoring_data:
            day_of_week = data.timestamp.weekday()  # 0=Monday, 6=Sunday
            hour_of_day = data.timestamp.hour
            
            is_up = data.response_time is not None
            daily_uptime[day_of_week].append(is_up)
            hourly_uptime[hour_of_day].append(is_up)
        
        # Calculate daily averages
        daily_averages = {}
        for day, readings in daily_uptime.items():
            daily_averages[day] = sum(readings) / len(readings) * 100 if readings else 0
        
        # Calculate hourly averages
        hourly_averages = {}
        for hour, readings in hourly_uptime.items():
            hourly_averages[hour] = sum(readings) / len(readings) * 100 if readings else 0
        
        patterns = {
            'overall_uptime': uptime_percentage,
            'daily_patterns': daily_averages,
            'hourly_patterns': hourly_averages,
            'total_checks': total_checks,
            'successful_checks': successful_checks
        }
        
        # Classify uptime pattern
        if uptime_percentage > 95:
            patterns['classification'] = 'always_on'  # Infrastructure, servers, IoT
        elif uptime_percentage > 85:
            patterns['classification'] = 'mostly_on'  # Computers, media devices
        elif uptime_percentage > 70:
            patterns['classification'] = 'variable'  # Personal devices
        else:
            patterns['classification'] = 'intermittent'  # Mobile, portable devices
        
        return patterns
    
    def _analyze_failure_patterns(self, monitoring_data: List[MonitoringData]) -> Dict[str, Any]:
        """Analyze failure patterns to identify device reliability characteristics"""
        failures = [data for data in monitoring_data if data.response_time is None]
        
        if not failures:
            return {'pattern': 'no_failures', 'reliability': 'high'}
        
        # Group consecutive failures
        failure_groups = []
        current_group = []
        
        for i, data in enumerate(monitoring_data):
            if data.response_time is None:
                current_group.append(data)
            else:
                if current_group:
                    failure_groups.append(current_group)
                    current_group = []
        
        if current_group:  # Don't forget the last group
            failure_groups.append(current_group)
        
        patterns = {
            'total_failures': len(failures),
            'failure_groups': len(failure_groups),
            'avg_failure_duration': statistics.mean([len(group) for group in failure_groups]) if failure_groups else 0,
            'max_failure_duration': max([len(group) for group in failure_groups]) if failure_groups else 0,
            'failure_rate': len(failures) / len(monitoring_data) * 100 if monitoring_data else 0
        }
        
        # Classify failure pattern
        failure_rate = patterns['failure_rate']
        avg_duration = patterns['avg_failure_duration']
        
        if failure_rate < 2:
            patterns['classification'] = 'highly_reliable'  # Infrastructure
        elif failure_rate < 10 and avg_duration < 3:
            patterns['classification'] = 'reliable_occasional'  # Good devices
        elif failure_rate < 20:
            patterns['classification'] = 'moderate_reliability'  # Typical devices
        else:
            patterns['classification'] = 'unreliable'  # Problematic devices
        
        return patterns
    
    def _analyze_timing_characteristics(self, monitoring_data: List[MonitoringData]) -> Dict[str, Any]:
        """Analyze timing characteristics to identify device behavior patterns"""
        if len(monitoring_data) < 10:
            return {'pattern': 'insufficient_data'}
        
        # Analyze response time trends over time
        timestamps = [data.timestamp for data in monitoring_data]
        response_times = [data.response_time for data in monitoring_data if data.response_time is not None]
        
        if not response_times:
            return {'pattern': 'no_successful_responses'}
        
        # Calculate time-based patterns
        time_patterns = {
            'data_points': len(monitoring_data),
            'successful_points': len(response_times),
            'time_span_hours': (timestamps[-1] - timestamps[0]).total_seconds() / 3600,
            'average_interval': (timestamps[-1] - timestamps[0]).total_seconds() / len(timestamps) if len(timestamps) > 1 else 0
        }
        
        # Analyze response time stability over time
        if len(response_times) > 5:
            # Calculate moving average to detect trends
            window_size = min(10, len(response_times) // 3)
            moving_averages = []
            
            for i in range(len(response_times) - window_size + 1):
                window = response_times[i:i + window_size]
                moving_averages.append(statistics.mean(window))
            
            if len(moving_averages) > 1:
                time_patterns['trend_variance'] = statistics.stdev(moving_averages)
                time_patterns['trend_direction'] = 'improving' if moving_averages[-1] < moving_averages[0] else 'degrading'
            
        return time_patterns
    
    def _analyze_vendor_patterns(self, device: Device) -> Dict[str, Any]:
        """Analyze vendor information for device classification hints"""
        vendor_info = {
            'vendor': device.vendor,
            'mac_prefix': device.mac_address[:8] if device.mac_address else None,
            'vendor_classification': None,
            'confidence': 0.0
        }
        
        if device.mac_address:
            mac_prefix = device.mac_address[:8].replace(':', '').lower()
            oui_patterns = self.device_type_patterns['mac_oui_patterns']
            
            for oui, vendor_type in oui_patterns.items():
                if mac_prefix.startswith(oui.replace(':', '').lower()):
                    vendor_info['vendor_classification'] = vendor_type
                    vendor_info['confidence'] = 0.7
                    break
        
        if device.vendor:
            vendor_lower = device.vendor.lower()
            for device_type, patterns in self.classification_rules.items():
                vendor_patterns = patterns.get('vendor_patterns', [])
                for pattern in vendor_patterns:
                    if pattern.lower() in vendor_lower:
                        vendor_info['vendor_classification'] = device_type
                        vendor_info['confidence'] = max(vendor_info['confidence'], 0.6)
                        break
        
        return vendor_info
    
    def _analyze_hostname_patterns(self, device: Device) -> Dict[str, Any]:
        """Analyze hostname patterns for device classification hints"""
        hostname_info = {
            'hostname': device.hostname,
            'custom_name': device.custom_name,
            'hostname_classification': None,
            'confidence': 0.0,
            'matched_patterns': []
        }
        
        # Analyze hostname if available
        hostname = device.hostname or device.custom_name
        if hostname:
            hostname_lower = hostname.lower()
            
            for device_type, patterns in self.classification_rules.items():
                hostname_patterns = patterns.get('hostname_patterns', [])
                for pattern in hostname_patterns:
                    if re.search(pattern.lower(), hostname_lower):
                        hostname_info['hostname_classification'] = device_type
                        hostname_info['confidence'] = 0.8
                        hostname_info['matched_patterns'].append(pattern)
                        break
                
                if hostname_info['hostname_classification']:
                    break
        
        return hostname_info
    
    def _calculate_classification_confidence(self, characteristics: DeviceCharacteristics, device: Device) -> Dict[str, float]:
        """Calculate confidence scores for each possible device type classification"""
        confidence_scores = {}
        
        for device_type, rules in self.classification_rules.items():
            score = 0.0
            weight_sum = 0.0
            
            # Response time analysis (weight: 0.3)
            if characteristics.response_patterns and 'mean' in characteristics.response_patterns:
                response_range = rules.get('response_time_range', (0, 1000))
                mean_response = characteristics.response_patterns['mean']
                
                if response_range[0] <= mean_response <= response_range[1]:
                    score += 0.3
                else:
                    # Partial score based on how close it is
                    range_size = response_range[1] - response_range[0]
                    distance = min(abs(mean_response - response_range[0]), abs(mean_response - response_range[1]))
                    partial_score = max(0, 0.3 * (1 - distance / range_size))
                    score += partial_score
                weight_sum += 0.3
            
            # Uptime analysis (weight: 0.25)
            if characteristics.uptime_patterns and 'overall_uptime' in characteristics.uptime_patterns:
                expected_uptime = rules.get('uptime_expectation', 0.8) * 100
                actual_uptime = characteristics.uptime_patterns['overall_uptime']
                
                uptime_diff = abs(actual_uptime - expected_uptime)
                uptime_score = max(0, 0.25 * (1 - uptime_diff / 50))  # Normalize to 50% range
                score += uptime_score
                weight_sum += 0.25
            
            # Vendor analysis (weight: 0.2)
            if characteristics.vendor_info and characteristics.vendor_info.get('vendor_classification') == device_type:
                score += 0.2 * characteristics.vendor_info.get('confidence', 0.5)
                weight_sum += 0.2
            
            # Hostname analysis (weight: 0.15)
            if characteristics.hostname_patterns and characteristics.hostname_patterns.get('hostname_classification') == device_type:
                score += 0.15 * characteristics.hostname_patterns.get('confidence', 0.5)
                weight_sum += 0.15
            
            # IP pattern analysis (weight: 0.1)
            ip_patterns = rules.get('ip_patterns', [])
            if ip_patterns and device.ip_address:
                for pattern in ip_patterns:
                    if re.search(pattern, device.ip_address):
                        score += 0.1
                        break
                weight_sum += 0.1
            
            # Normalize score
            if weight_sum > 0:
                confidence_scores[device_type] = min(1.0, score / weight_sum)
            else:
                confidence_scores[device_type] = 0.0
        
        return confidence_scores
    
    def classify_device(self, device_id: int, days: int = 7) -> Dict[str, Any]:
        """
        Classify a device based on behavioral analysis
        
        Returns:
            Classification result with device type, confidence, and reasoning
        """
        characteristics = self.analyze_device_behavior(device_id, days)
        if not characteristics:
            return {'error': 'Could not analyze device'}
        
        confidence_scores = characteristics.confidence_scores
        if not confidence_scores:
            return {'device_type': 'unknown', 'confidence': 0.0, 'reason': 'Insufficient data'}
        
        # Find best match
        best_type = max(confidence_scores.keys(), key=lambda k: confidence_scores[k])
        best_confidence = confidence_scores[best_type]
        
        # Determine confidence level
        if best_confidence >= self.confidence_thresholds['high']:
            confidence_level = 'high'
        elif best_confidence >= self.confidence_thresholds['medium']:
            confidence_level = 'medium'
        elif best_confidence >= self.confidence_thresholds['low']:
            confidence_level = 'low'
        else:
            confidence_level = 'very_low'
        
        # Generate reasoning
        reasoning = self._generate_classification_reasoning(characteristics, best_type)
        
        return {
            'device_type': best_type,
            'confidence': best_confidence,
            'confidence_level': confidence_level,
            'all_scores': confidence_scores,
            'reasoning': reasoning,
            'characteristics': characteristics.to_dict()
        }
    
    def _generate_classification_reasoning(self, characteristics: DeviceCharacteristics, device_type: str) -> List[str]:
        """Generate human-readable reasoning for classification decision"""
        reasoning = []
        
        # Response time reasoning
        if characteristics.response_patterns and 'mean' in characteristics.response_patterns:
            mean_response = characteristics.response_patterns['mean']
            classification = characteristics.response_patterns.get('classification', 'unknown')
            reasoning.append(f"Average response time: {mean_response:.1f}ms ({classification})")
        
        # Uptime reasoning
        if characteristics.uptime_patterns and 'overall_uptime' in characteristics.uptime_patterns:
            uptime = characteristics.uptime_patterns['overall_uptime']
            classification = characteristics.uptime_patterns.get('classification', 'unknown')
            reasoning.append(f"Uptime: {uptime:.1f}% ({classification})")
        
        # Vendor reasoning
        if characteristics.vendor_info and characteristics.vendor_info.get('vendor_classification'):
            vendor_type = characteristics.vendor_info['vendor_classification']
            reasoning.append(f"Vendor signature suggests: {vendor_type}")
        
        # Hostname reasoning
        if characteristics.hostname_patterns and characteristics.hostname_patterns.get('hostname_classification'):
            hostname_type = characteristics.hostname_patterns['hostname_classification']
            patterns = characteristics.hostname_patterns.get('matched_patterns', [])
            reasoning.append(f"Hostname pattern indicates: {hostname_type} (matched: {', '.join(patterns)})")
        
        # Failure pattern reasoning
        if characteristics.failure_patterns and 'classification' in characteristics.failure_patterns:
            failure_class = characteristics.failure_patterns['classification']
            failure_rate = characteristics.failure_patterns.get('failure_rate', 0)
            reasoning.append(f"Reliability: {failure_class} ({failure_rate:.1f}% failure rate)")
        
        return reasoning
    
    def get_device_insights(self, device_id: int) -> Dict[str, Any]:
        """Get comprehensive insights about a device"""
        try:
            classification = self.classify_device(device_id)
            
            if 'error' in classification:
                return classification
            
            # Add additional insights
            insights = {
                'classification': classification,
                'recommendations': self._generate_recommendations(classification),
                'monitoring_suggestions': self._generate_monitoring_suggestions(classification),
                'performance_analysis': self._analyze_performance_trends(device_id)
            }
            
            return insights
            
        except Exception as e:
            logger.error(f"Error generating device insights for device {device_id}: {e}")
            return {'error': str(e)}
    
    def _generate_recommendations(self, classification: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on classification"""
        recommendations = []
        device_type = classification.get('device_type', 'unknown')
        confidence = classification.get('confidence', 0.0)
        
        if confidence < 0.5:
            recommendations.append("Consider providing more specific hostname or custom name for better classification")
        
        if device_type == 'router':
            recommendations.append("Monitor this device closely as network infrastructure")
            recommendations.append("Consider setting up alerts for extended downtime")
        elif device_type == 'computer':
            recommendations.append("Monitor during business hours for optimal insights")
            recommendations.append("Consider power management monitoring")
        elif device_type == 'iot':
            recommendations.append("Monitor for consistent connectivity patterns")
            recommendations.append("Check for firmware updates regularly")
        elif device_type == 'camera':
            recommendations.append("Ensure reliable power and network connectivity")
            recommendations.append("Monitor for security and firmware updates")
        
        characteristics = classification.get('characteristics', {})
        uptime_patterns = characteristics.get('uptime_patterns', {})
        
        if uptime_patterns.get('overall_uptime', 100) < 80:
            recommendations.append("Investigate connectivity issues - uptime below expected levels")
        
        response_patterns = characteristics.get('response_patterns', {})
        if response_patterns.get('std_dev', 0) > 50:
            recommendations.append("High response time variance detected - check network stability")
        
        return recommendations
    
    def _generate_monitoring_suggestions(self, classification: Dict[str, Any]) -> Dict[str, Any]:
        """Generate monitoring configuration suggestions"""
        device_type = classification.get('device_type', 'unknown')
        
        suggestions = {
            'ping_interval': 60,  # Default
            'alert_thresholds': {
                'response_time': 100,
                'uptime': 80
            },
            'monitoring_priority': 'normal'
        }
        
        if device_type == 'router':
            suggestions.update({
                'ping_interval': 30,  # More frequent for infrastructure
                'alert_thresholds': {'response_time': 50, 'uptime': 95},
                'monitoring_priority': 'high'
            })
        elif device_type == 'camera':
            suggestions.update({
                'ping_interval': 45,  # Security devices need good monitoring
                'alert_thresholds': {'response_time': 75, 'uptime': 90},
                'monitoring_priority': 'high'
            })
        elif device_type == 'iot':
            suggestions.update({
                'ping_interval': 120,  # Less frequent for simple IoT
                'alert_thresholds': {'response_time': 200, 'uptime': 85},
                'monitoring_priority': 'normal'
            })
        elif device_type == 'phone':
            suggestions.update({
                'ping_interval': 300,  # Less frequent for mobile devices
                'alert_thresholds': {'response_time': 150, 'uptime': 70},
                'monitoring_priority': 'low'
            })
        
        return suggestions
    
    def _analyze_performance_trends(self, device_id: int) -> Dict[str, Any]:
        """Analyze performance trends over time"""
        if not self.app:
            return {}
        
        try:
            with self.app.app_context():
                # Get 30 days of data for trend analysis
                cutoff_date = datetime.utcnow() - timedelta(days=30)
                monitoring_data = MonitoringData.query.filter(
                    MonitoringData.device_id == device_id,
                    MonitoringData.timestamp >= cutoff_date
                ).order_by(MonitoringData.timestamp).all()
                
                if len(monitoring_data) < 20:
                    return {'trend': 'insufficient_data'}
                
                # Group by weeks
                weekly_stats = defaultdict(list)
                for data in monitoring_data:
                    week = data.timestamp.isocalendar()[1]
                    if data.response_time is not None:
                        weekly_stats[week].append(data.response_time)
                
                if len(weekly_stats) < 2:
                    return {'trend': 'insufficient_timespan'}
                
                # Calculate weekly averages
                weekly_averages = {}
                for week, response_times in weekly_stats.items():
                    if response_times:
                        weekly_averages[week] = statistics.mean(response_times)
                
                if len(weekly_averages) < 2:
                    return {'trend': 'no_data'}
                
                # Calculate trend
                weeks = sorted(weekly_averages.keys())
                first_week_avg = weekly_averages[weeks[0]]
                last_week_avg = weekly_averages[weeks[-1]]
                
                trend_change = ((last_week_avg - first_week_avg) / first_week_avg) * 100
                
                trend_analysis = {
                    'trend_direction': 'improving' if trend_change < -5 else 'degrading' if trend_change > 5 else 'stable',
                    'trend_change_percent': trend_change,
                    'weekly_averages': weekly_averages,
                    'first_week_avg': first_week_avg,
                    'last_week_avg': last_week_avg
                }
                
                return trend_analysis
                
        except Exception as e:
            logger.error(f"Error analyzing performance trends for device {device_id}: {e}")
            return {'error': str(e)}
    
    def generate_device_fingerprint(self, device_id: int, days: int = 14) -> Dict[str, Any]:
        """Generate unique device fingerprint based on behavioral patterns"""
        try:
            with self.app.app_context():
                device = Device.query.get(device_id)
                if not device:
                    return {'error': 'Device not found'}
                
                cutoff = datetime.utcnow() - timedelta(days=days)
                monitoring_data = MonitoringData.query.filter(
                    MonitoringData.device_id == device_id,
                    MonitoringData.timestamp >= cutoff
                ).order_by(MonitoringData.timestamp.desc()).all()
                
                if not monitoring_data:
                    return {'error': 'No monitoring data available'}
                
                # Calculate response time fingerprint
                response_fingerprint = self._calculate_response_fingerprint(monitoring_data)
                
                # Calculate temporal patterns
                temporal_fingerprint = self._calculate_temporal_fingerprint(monitoring_data)
                
                # Calculate failure pattern fingerprint
                failure_fingerprint = self._calculate_failure_fingerprint(monitoring_data)
                
                # Calculate network behavior fingerprint
                network_fingerprint = self._calculate_network_fingerprint(device, monitoring_data)
                
                # Generate composite fingerprint hash
                fingerprint_components = {
                    'response_signature': response_fingerprint,
                    'temporal_signature': temporal_fingerprint,
                    'failure_signature': failure_fingerprint,
                    'network_signature': network_fingerprint
                }
                
                # Create unique device signature
                device_signature = self._create_device_signature(fingerprint_components)
                
                return {
                    'device_id': device_id,
                    'device_name': device.display_name,
                    'fingerprint_hash': device_signature,
                    'components': fingerprint_components,
                    'confidence': self._calculate_fingerprint_confidence(fingerprint_components),
                    'generated_at': datetime.utcnow().isoformat(),
                    'data_points': len(monitoring_data),
                    'analysis_period_days': days
                }
                
        except Exception as e:
            logger.error(f"Error generating device fingerprint for device {device_id}: {e}")
            return {'error': str(e)}
    
    def _calculate_response_fingerprint(self, monitoring_data: List) -> Dict[str, Any]:
        """Calculate unique response time signature"""
        response_times = [data.response_time for data in monitoring_data if data.response_time is not None]
        
        if not response_times:
            return {'type': 'no_response_data'}
        
        # Statistical characteristics
        avg_response = statistics.mean(response_times)
        median_response = statistics.median(response_times)
        stdev_response = statistics.stdev(response_times) if len(response_times) > 1 else 0
        
        # Response time distribution buckets
        buckets = {
            'fast': len([r for r in response_times if r < 10]),
            'normal': len([r for r in response_times if 10 <= r < 50]),
            'slow': len([r for r in response_times if 50 <= r < 200]),
            'very_slow': len([r for r in response_times if r >= 200])
        }
        
        # Calculate percentiles
        response_times_sorted = sorted(response_times)
        n = len(response_times_sorted)
        p25 = response_times_sorted[int(n * 0.25)] if n > 0 else 0
        p75 = response_times_sorted[int(n * 0.75)] if n > 0 else 0
        p95 = response_times_sorted[int(n * 0.95)] if n > 0 else 0
        
        # Response pattern classification
        pattern_type = 'unknown'
        if avg_response < 20 and stdev_response < 10:
            pattern_type = 'consistent_fast'
        elif avg_response < 50 and stdev_response < 20:
            pattern_type = 'consistent_normal'
        elif stdev_response > avg_response * 0.5:
            pattern_type = 'variable'
        elif avg_response > 100:
            pattern_type = 'consistently_slow'
        else:
            pattern_type = 'standard'
        
        return {
            'avg_response': round(avg_response, 2),
            'median_response': round(median_response, 2),
            'stdev_response': round(stdev_response, 2),
            'distribution_buckets': buckets,
            'percentiles': {'p25': p25, 'p75': p75, 'p95': p95},
            'pattern_type': pattern_type,
            'variability_coefficient': round(stdev_response / avg_response, 3) if avg_response > 0 else 0
        }
    
    def _calculate_temporal_fingerprint(self, monitoring_data: List) -> Dict[str, Any]:
        """Calculate temporal usage patterns"""
        if not monitoring_data:
            return {'type': 'no_temporal_data'}
        
        # Hour-of-day analysis
        hourly_activity = defaultdict(int)
        hourly_responses = defaultdict(list)
        
        # Day-of-week analysis
        daily_activity = defaultdict(int)
        
        for data in monitoring_data:
            hour = data.timestamp.hour
            day_of_week = data.timestamp.weekday()
            
            hourly_activity[hour] += 1
            daily_activity[day_of_week] += 1
            
            if data.response_time is not None:
                hourly_responses[hour].append(data.response_time)
        
        # Find peak activity patterns
        peak_hours = sorted(hourly_activity.items(), key=lambda x: x[1], reverse=True)[:3]
        quiet_hours = sorted(hourly_activity.items(), key=lambda x: x[1])[:3]
        
        # Business hours vs off-hours activity
        business_hours = sum(hourly_activity[h] for h in range(9, 17))
        off_hours = sum(hourly_activity[h] for h in list(range(0, 9)) + list(range(17, 24)))
        
        # Weekday vs weekend activity
        weekday_activity = sum(daily_activity[d] for d in range(0, 5))  # Mon-Fri
        weekend_activity = sum(daily_activity[d] for d in range(5, 7))  # Sat-Sun
        
        # Classify temporal pattern
        temporal_type = 'unknown'
        if business_hours > off_hours * 2:
            temporal_type = 'business_device'
        elif weekend_activity > weekday_activity:
            temporal_type = 'personal_device'
        elif off_hours > business_hours:
            temporal_type = 'always_on'
        else:
            temporal_type = 'mixed_usage'
        
        return {
            'peak_hours': [(hour, count) for hour, count in peak_hours],
            'quiet_hours': [(hour, count) for hour, count in quiet_hours],
            'business_vs_off_hours': {'business': business_hours, 'off_hours': off_hours},
            'weekday_vs_weekend': {'weekday': weekday_activity, 'weekend': weekend_activity},
            'temporal_pattern_type': temporal_type,
            'activity_distribution': dict(hourly_activity)
        }
    
    def _calculate_failure_fingerprint(self, monitoring_data: List) -> Dict[str, Any]:
        """Calculate failure and downtime patterns"""
        total_checks = len(monitoring_data)
        failed_checks = len([data for data in monitoring_data if data.response_time is None])
        
        if total_checks == 0:
            return {'type': 'no_failure_data'}
        
        success_rate = ((total_checks - failed_checks) / total_checks) * 100
        
        # Analyze failure clustering
        failure_clusters = []
        current_cluster = []
        
        for data in reversed(monitoring_data):  # Newest first
            if data.response_time is None:  # Failed check
                current_cluster.append(data.timestamp)
            else:
                if current_cluster:
                    failure_clusters.append(current_cluster)
                    current_cluster = []
        
        if current_cluster:
            failure_clusters.append(current_cluster)
        
        # Failure pattern analysis
        avg_failure_duration = 0
        if failure_clusters:
            durations = []
            for cluster in failure_clusters:
                if len(cluster) > 1:
                    duration = (max(cluster) - min(cluster)).total_seconds() / 60  # minutes
                    durations.append(duration)
            avg_failure_duration = statistics.mean(durations) if durations else 0
        
        # Classify failure pattern
        failure_type = 'unknown'
        if success_rate >= 99:
            failure_type = 'highly_reliable'
        elif success_rate >= 95:
            failure_type = 'reliable'
        elif len(failure_clusters) > 10:
            failure_type = 'intermittent_issues'
        elif avg_failure_duration > 60:  # > 1 hour average
            failure_type = 'sustained_outages'
        else:
            failure_type = 'unreliable'
        
        return {
            'success_rate': round(success_rate, 2),
            'total_checks': total_checks,
            'failed_checks': failed_checks,
            'failure_clusters': len(failure_clusters),
            'avg_failure_duration_minutes': round(avg_failure_duration, 2),
            'failure_pattern_type': failure_type
        }
    
    def _calculate_network_fingerprint(self, device: Device, monitoring_data: List) -> Dict[str, Any]:
        """Calculate network-specific behavioral signature"""
        # MAC vendor analysis
        mac_vendor_score = 0
        vendor_confidence = 0
        if device.vendor:
            # Known reliable vendors get higher scores
            reliable_vendors = ['Apple', 'Intel', 'Cisco', 'HP', 'Dell', 'Ubiquiti']
            if any(vendor in device.vendor for vendor in reliable_vendors):
                mac_vendor_score = 0.8
                vendor_confidence = 0.9
            else:
                mac_vendor_score = 0.5
                vendor_confidence = 0.6
        
        # Hostname analysis
        hostname_pattern = 'unknown'
        hostname_confidence = 0
        if device.hostname:
            hostname_lower = device.hostname.lower()
            if any(pattern in hostname_lower for pattern in ['android', 'iphone', 'samsung']):
                hostname_pattern = 'mobile_device'
                hostname_confidence = 0.8
            elif any(pattern in hostname_lower for pattern in ['macbook', 'imac', 'mac']):
                hostname_pattern = 'apple_computer'
                hostname_confidence = 0.9
            elif any(pattern in hostname_lower for pattern in ['pc', 'desktop', 'laptop']):
                hostname_pattern = 'windows_computer'
                hostname_confidence = 0.7
            elif any(pattern in hostname_lower for pattern in ['router', 'gateway', 'access']):
                hostname_pattern = 'network_infrastructure'
                hostname_confidence = 0.9
            else:
                hostname_pattern = 'custom_named'
                hostname_confidence = 0.4
        
        # IP address pattern analysis
        ip_pattern = 'unknown'
        if device.ip_address:
            if device.ip_address.endswith('.1'):
                ip_pattern = 'gateway_router'
            elif device.ip_address.endswith(('.2', '.3', '.4', '.5')):
                ip_pattern = 'infrastructure_range'
            elif int(device.ip_address.split('.')[-1]) > 100:
                ip_pattern = 'dhcp_client'
            else:
                ip_pattern = 'static_assignment'
        
        # Calculate network behavior score
        network_score = (mac_vendor_score + hostname_confidence + vendor_confidence) / 3
        
        return {
            'mac_vendor_analysis': {
                'vendor': device.vendor,
                'score': mac_vendor_score,
                'confidence': vendor_confidence
            },
            'hostname_analysis': {
                'hostname': device.hostname,
                'pattern': hostname_pattern,
                'confidence': hostname_confidence
            },
            'ip_pattern': ip_pattern,
            'network_behavior_score': round(network_score, 3)
        }
    
    def _create_device_signature(self, components: Dict[str, Any]) -> str:
        """Create unique device signature hash"""
        import hashlib
        
        # Extract key characteristics for signature
        response_sig = components['response_signature']
        temporal_sig = components['temporal_signature']
        failure_sig = components['failure_signature']
        network_sig = components['network_signature']
        
        signature_data = {
            'response_pattern': response_sig.get('pattern_type', 'unknown'),
            'avg_response_bucket': 'fast' if response_sig.get('avg_response', 999) < 50 else 'slow',
            'temporal_pattern': temporal_sig.get('temporal_pattern_type', 'unknown'),
            'failure_pattern': failure_sig.get('failure_pattern_type', 'unknown'),
            'vendor': network_sig.get('mac_vendor_analysis', {}).get('vendor', 'unknown'),
            'hostname_pattern': network_sig.get('hostname_analysis', {}).get('pattern', 'unknown')
        }
        
        # Create hash from signature data
        signature_str = json.dumps(signature_data, sort_keys=True)
        signature_hash = hashlib.md5(signature_str.encode()).hexdigest()[:12]
        
        return f"fp_{signature_hash}"
    
    def _calculate_fingerprint_confidence(self, components: Dict[str, Any]) -> float:
        """Calculate overall fingerprint confidence"""
        confidences = []
        
        # Response signature confidence
        response_sig = components['response_signature']
        if response_sig.get('type') != 'no_response_data':
            confidences.append(0.8)
        
        # Temporal signature confidence
        temporal_sig = components['temporal_signature']
        if temporal_sig.get('type') != 'no_temporal_data':
            confidences.append(0.7)
        
        # Network signature confidence
        network_sig = components['network_signature']
        network_conf = network_sig.get('mac_vendor_analysis', {}).get('confidence', 0)
        hostname_conf = network_sig.get('hostname_analysis', {}).get('confidence', 0)
        confidences.extend([network_conf, hostname_conf])
        
        return round(statistics.mean(confidences) if confidences else 0, 3)
    
    def compare_device_fingerprints(self, device_id1: int, device_id2: int, days: int = 14) -> Dict[str, Any]:
        """Compare fingerprints between two devices to detect similar patterns"""
        try:
            fp1 = self.generate_device_fingerprint(device_id1, days)
            fp2 = self.generate_device_fingerprint(device_id2, days)
            
            if 'error' in fp1 or 'error' in fp2:
                return {'error': 'Cannot generate fingerprints for comparison'}
            
            # Calculate similarity scores
            response_similarity = self._calculate_response_similarity(
                fp1['components']['response_signature'],
                fp2['components']['response_signature']
            )
            
            temporal_similarity = self._calculate_temporal_similarity(
                fp1['components']['temporal_signature'],
                fp2['components']['temporal_signature']
            )
            
            network_similarity = self._calculate_network_similarity(
                fp1['components']['network_signature'],
                fp2['components']['network_signature']
            )
            
            overall_similarity = (response_similarity + temporal_similarity + network_similarity) / 3
            
            return {
                'device1': {'id': device_id1, 'fingerprint': fp1['fingerprint_hash']},
                'device2': {'id': device_id2, 'fingerprint': fp2['fingerprint_hash']},
                'similarity_scores': {
                    'response_pattern': round(response_similarity, 3),
                    'temporal_pattern': round(temporal_similarity, 3),
                    'network_pattern': round(network_similarity, 3),
                    'overall': round(overall_similarity, 3)
                },
                'match_level': 'high' if overall_similarity > 0.8 else 'medium' if overall_similarity > 0.6 else 'low',
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error comparing device fingerprints: {e}")
            return {'error': str(e)}
    
    def _calculate_response_similarity(self, sig1: Dict, sig2: Dict) -> float:
        """Calculate similarity between response signatures"""
        if sig1.get('type') == 'no_response_data' or sig2.get('type') == 'no_response_data':
            return 0.0
        
        # Compare pattern types
        pattern_match = 1.0 if sig1.get('pattern_type') == sig2.get('pattern_type') else 0.0
        
        # Compare response time ranges
        avg1 = sig1.get('avg_response', 0)
        avg2 = sig2.get('avg_response', 0)
        if avg1 > 0 and avg2 > 0:
            avg_similarity = 1.0 - min(abs(avg1 - avg2) / max(avg1, avg2), 1.0)
        else:
            avg_similarity = 0.0
        
        return (pattern_match * 0.6 + avg_similarity * 0.4)
    
    def _calculate_temporal_similarity(self, sig1: Dict, sig2: Dict) -> float:
        """Calculate similarity between temporal signatures"""
        if sig1.get('type') == 'no_temporal_data' or sig2.get('type') == 'no_temporal_data':
            return 0.0
        
        # Compare temporal pattern types
        pattern_match = 1.0 if sig1.get('temporal_pattern_type') == sig2.get('temporal_pattern_type') else 0.0
        
        return pattern_match
    
    def _calculate_network_similarity(self, sig1: Dict, sig2: Dict) -> float:
        """Calculate similarity between network signatures"""
        similarities = []
        
        # Vendor similarity
        vendor1 = sig1.get('mac_vendor_analysis', {}).get('vendor', '')
        vendor2 = sig2.get('mac_vendor_analysis', {}).get('vendor', '')
        vendor_match = 1.0 if vendor1 and vendor2 and vendor1 == vendor2 else 0.0
        similarities.append(vendor_match)
        
        # Hostname pattern similarity
        pattern1 = sig1.get('hostname_analysis', {}).get('pattern', '')
        pattern2 = sig2.get('hostname_analysis', {}).get('pattern', '')
        pattern_match = 1.0 if pattern1 and pattern2 and pattern1 == pattern2 else 0.0
        similarities.append(pattern_match)
        
        return statistics.mean(similarities) if similarities else 0.0
    
    def start_continuous_analysis(self):
        """Start background thread for continuous device analysis"""
        def analysis_loop():
            while True:
                try:
                    if self.app:
                        with self.app.app_context():
                            # Analyze devices that haven't been analyzed recently
                            devices = Device.query.filter_by(is_monitored=True).all()
                            
                            for device in devices:
                                # Check if device needs analysis
                                cache_key = f"behavior_{device.id}_7"
                                last_analysis = self._cache_expiry.get(cache_key, 0)
                                
                                if time.time() - last_analysis > 86400:  # 24 hours
                                    logger.info(f"Performing scheduled analysis for device {device.display_name}")
                                    self.analyze_device_behavior(device.id)
                                    
                                    # Generate fingerprint for learning
                                    if time.time() - last_analysis > 172800:  # 48 hours for fingerprint
                                        fingerprint = self.generate_device_fingerprint(device.id)
                                        if 'error' not in fingerprint:
                                            logger.debug(f"Generated fingerprint for {device.display_name}: {fingerprint['fingerprint_hash']}")
                    
                    time.sleep(3600)  # Run every hour
                    
                except Exception as e:
                    logger.error(f"Error in continuous analysis loop: {e}")
                    time.sleep(3600)
        
        analysis_thread = threading.Thread(target=analysis_loop, daemon=True, name='DeviceAnalytics')
        analysis_thread.start()
        logger.info("Device analytics continuous analysis started")


# Global analytics instance
device_analytics = DeviceBehaviorAnalytics()