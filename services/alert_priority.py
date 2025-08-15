"""
Alert Priority Scoring System

This service calculates priority scores for alerts based on multiple factors:
- Alert type and severity
- Device criticality and importance
- Historical frequency and patterns
- Network impact and dependencies
- Time-based factors (business hours, weekends)
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)

class AlertPriority(Enum):
    """Alert priority levels with numeric scores"""
    CRITICAL = 100
    HIGH = 80
    MEDIUM = 60
    LOW = 40
    MINIMAL = 20

class AlertPriorityScorer:
    """Calculate priority scores for alerts based on multiple factors"""
    
    def __init__(self, app=None):
        self.app = app
        
        # Base scores for alert types
        self.alert_type_scores = {
            'device_down': 70,
            'device_recovery': 30,
            'high_latency': 50,
            'anomaly_connectivity_pattern': 40,
            'anomaly_uptime_pattern': 45,
            'anomaly_response_time': 35,
            'security_vulnerability': 85,
            'new_device': 25,
            'network_scan_complete': 15
        }
        
        # Severity multipliers
        self.severity_multipliers = {
            'critical': 1.5,
            'high': 1.3,
            'warning': 1.0,
            'info': 0.8,
            'low': 0.6
        }
        
        # Device type importance scores
        self.device_importance_scores = {
            'router': 90,
            'gateway': 90,
            'server': 85,
            'network_switch': 80,
            'access_point': 75,
            'nas': 70,
            'smart_tv': 40,
            'mobile': 30,
            'iot': 25,
            'unknown': 50
        }
        
    def calculate_priority_score(self, alert, device=None) -> Tuple[int, str, Dict]:
        """
        Calculate comprehensive priority score for an alert
        
        Returns:
            Tuple of (score, priority_level, breakdown)
        """
        try:
            if not device and hasattr(alert, 'device'):
                device = alert.device
                
            breakdown = {
                'base_score': 0,
                'severity_modifier': 0,
                'device_criticality': 0,
                'frequency_penalty': 0,
                'time_modifier': 0,
                'network_impact': 0,
                'final_score': 0
            }
            
            # 1. Base score from alert type
            base_score = self.alert_type_scores.get(alert.alert_type, 50)
            breakdown['base_score'] = base_score
            
            # 2. Severity modifier
            severity_multiplier = self.severity_multipliers.get(alert.severity, 1.0)
            severity_modifier = base_score * (severity_multiplier - 1.0)
            breakdown['severity_modifier'] = severity_modifier
            
            # 3. Device criticality score
            device_criticality = self._calculate_device_criticality(device) if device else 50
            breakdown['device_criticality'] = device_criticality
            
            # 4. Frequency penalty (reduce priority for repeated alerts)
            frequency_penalty = self._calculate_frequency_penalty(alert, device) if device else 0
            breakdown['frequency_penalty'] = frequency_penalty
            
            # 5. Time-based modifier (business hours, etc.)
            time_modifier = self._calculate_time_modifier()
            breakdown['time_modifier'] = time_modifier
            
            # 6. Network impact score
            network_impact = self._calculate_network_impact(alert, device) if device else 0
            breakdown['network_impact'] = network_impact
            
            # Calculate final score
            final_score = (
                base_score + 
                severity_modifier + 
                (device_criticality * 0.3) +  # Weight device criticality at 30%
                frequency_penalty +
                time_modifier +
                network_impact
            )
            
            # Ensure score is within bounds
            final_score = max(0, min(100, final_score))
            breakdown['final_score'] = int(final_score)
            
            # Determine priority level
            priority_level = self._score_to_priority_level(final_score)
            
            return int(final_score), priority_level, breakdown
            
        except Exception as e:
            logger.error(f"Error calculating priority score: {e}")
            # Return medium priority as fallback
            return 60, "MEDIUM", {"error": str(e)}
    
    def _calculate_device_criticality(self, device) -> float:
        """Calculate device criticality score based on type and network position"""
        if not device:
            return 50
            
        score = 50  # Base score
        
        # Check device type importance
        device_type = (device.device_type or '').lower()
        for type_key, type_score in self.device_importance_scores.items():
            if type_key in device_type:
                score = type_score
                break
        
        # Check for critical IP addresses (routers, gateways)
        if device.ip_address:
            ip = device.ip_address
            if ip.endswith('.1'):  # Likely router/gateway
                score = max(score, 90)
            elif ip.endswith('.64'):  # Server convention
                score = max(score, 85)
        
        # Check hostname for critical services
        hostname = (device.hostname or '').lower()
        critical_keywords = ['router', 'gateway', 'server', 'nuc', 'nas', 'switch']
        for keyword in critical_keywords:
            if keyword in hostname:
                score = max(score, 80)
                break
        
        # Check if device is monitored (monitored devices are more important)
        if hasattr(device, 'is_monitored') and device.is_monitored:
            score += 10
        
        # Check uptime reliability (devices with good uptime are more critical when they fail)
        try:
            if hasattr(device, 'uptime_percentage'):
                uptime = device.uptime_percentage
                if uptime > 99:
                    score += 5  # Very reliable devices get higher priority when they fail
                elif uptime < 95:
                    score -= 5  # Unreliable devices get lower priority
        except:
            pass
        
        return min(100, score)
    
    def _calculate_frequency_penalty(self, alert, device) -> float:
        """Calculate penalty for frequently alerting devices"""
        if not self.app or not device:
            return 0
            
        try:
            with self.app.app_context():
                from models import Alert
                
                # Count similar alerts for this device in the last 24 hours
                recent_time = datetime.utcnow() - timedelta(hours=24)
                similar_alerts = Alert.query.filter(
                    Alert.device_id == device.id,
                    Alert.alert_type == alert.alert_type,
                    Alert.created_at >= recent_time
                ).count()
                
                # Apply penalty for frequent alerts (max -20 points)
                if similar_alerts > 5:
                    return -20
                elif similar_alerts > 3:
                    return -10
                elif similar_alerts > 1:
                    return -5
                
                return 0
                
        except Exception as e:
            logger.error(f"Error calculating frequency penalty: {e}")
            return 0
    
    def _calculate_time_modifier(self) -> float:
        """Calculate time-based priority modifier"""
        now = datetime.now()
        hour = now.hour
        weekday = now.weekday()  # 0 = Monday, 6 = Sunday
        
        # Business hours boost (9 AM - 5 PM, Monday-Friday)
        if weekday < 5 and 9 <= hour <= 17:
            return 5
        
        # Evening hours (6 PM - 10 PM) - moderate priority
        elif weekday < 5 and 18 <= hour <= 22:
            return 2
        
        # Night hours (11 PM - 6 AM) - reduced priority
        elif hour >= 23 or hour <= 6:
            return -5
        
        # Weekend - slightly reduced priority
        elif weekday >= 5:
            return -2
        
        return 0
    
    def _calculate_network_impact(self, alert, device) -> float:
        """Calculate network impact score based on device role and alert type"""
        if not device:
            return 0
            
        impact_score = 0
        
        # High impact for infrastructure failures
        if alert.alert_type == 'device_down':
            device_type = (device.device_type or '').lower()
            ip = device.ip_address or ''
            
            # Critical infrastructure down = high impact
            if any(keyword in device_type for keyword in ['router', 'gateway', 'switch']):
                impact_score += 15
            elif ip.endswith('.1'):  # Gateway/router IP
                impact_score += 15
            elif 'server' in device_type or ip.endswith('.64'):
                impact_score += 10
            
        # Medium impact for performance issues
        elif alert.alert_type == 'high_latency':
            impact_score += 5
            
        # Lower impact for anomalies (depends on severity)
        elif 'anomaly' in alert.alert_type:
            if alert.severity == 'critical':
                impact_score += 8
            elif alert.severity == 'high':
                impact_score += 5
            else:
                impact_score += 2
        
        return impact_score
    
    def _score_to_priority_level(self, score: float) -> str:
        """Convert numeric score to priority level string"""
        if score >= 85:
            return "CRITICAL"
        elif score >= 70:
            return "HIGH"
        elif score >= 50:
            return "MEDIUM"
        elif score >= 30:
            return "LOW"
        else:
            return "MINIMAL"
    
    def get_priority_summary(self, alerts: List) -> Dict:
        """Get priority summary for a list of alerts"""
        if not alerts:
            return {
                'total': 0,
                'by_priority': {},
                'average_score': 0
            }
        
        priority_counts = {}
        total_score = 0
        
        for alert in alerts:
            score, priority, _ = self.calculate_priority_score(alert)
            priority_counts[priority] = priority_counts.get(priority, 0) + 1
            total_score += score
        
        return {
            'total': len(alerts),
            'by_priority': priority_counts,
            'average_score': round(total_score / len(alerts), 1)
        }
    
    def sort_alerts_by_priority(self, alerts: List) -> List:
        """Sort alerts by priority score (highest first)"""
        def get_score(alert):
            score, _, _ = self.calculate_priority_score(alert)
            return score
        
        return sorted(alerts, key=get_score, reverse=True)

# Global instance
alert_priority_scorer = AlertPriorityScorer()