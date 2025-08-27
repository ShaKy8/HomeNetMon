"""
Alert Auto-Resolution Service
Automatically resolves alerts when conditions are met (e.g., device comes back online)
"""

import logging
from datetime import datetime, timedelta
from typing import List, Set
from models import db, Alert, Device, MonitoringData
from sqlalchemy import and_, desc

logger = logging.getLogger(__name__)

class AlertAutoResolver:
    """Service to automatically resolve alerts when conditions are resolved"""
    
    def __init__(self, app=None):
        self.app = app
        self.enabled = True
        
        # Auto-resolution rules configuration
        self.resolution_rules = {
            'device_down': {
                'enabled': True,
                'required_consecutive_successes': 3,  # Device must be up for 3+ consecutive checks
                'max_alert_age_hours': 72,           # Only auto-resolve alerts less than 3 days old
                'message_patterns': [
                    'Device is down',
                    'Device offline',
                    'No response from device',
                    'Device unexpectedly down',
                    'Connection lost',
                    'Ping timeout'
                ]
            },
            'response_time': {
                'enabled': True,
                'required_consecutive_normal': 5,     # Response time must be normal for 5+ checks
                'max_alert_age_hours': 24,          # Only auto-resolve alerts less than 1 day old
                'normal_threshold_multiplier': 1.2,  # Response time must be within 120% of baseline
                'message_patterns': [
                    'Response time anomaly',
                    'High response time',
                    'Slow response',
                    'Performance degradation'
                ]
            },
            'connectivity': {
                'enabled': True,
                'required_stable_hours': 2,         # Connectivity must be stable for 2+ hours
                'max_alert_age_hours': 48,          # Only auto-resolve alerts less than 2 days old
                'message_patterns': [
                    'Unusually low connection frequency',
                    'Unusually high connection frequency',
                    'Connection pattern anomaly',
                    'Connectivity issues'
                ]
            }
        }
        
        # Statistics tracking
        self.stats = {
            'last_run': None,
            'alerts_resolved': 0,
            'alerts_checked': 0,
            'resolution_by_type': {},
            'errors': 0
        }
    
    def run_auto_resolution_cycle(self):
        """Run the auto-resolution cycle for all active alerts"""
        if not self.enabled:
            logger.debug("Auto-resolution disabled, skipping cycle")
            return
            
        try:
            self.stats['last_run'] = datetime.utcnow()
            logger.info("Starting alert auto-resolution cycle")
            
            # Get all unresolved alerts
            unresolved_alerts = Alert.query.filter_by(resolved=False).all()
            self.stats['alerts_checked'] = len(unresolved_alerts)
            
            resolved_count = 0
            
            for alert in unresolved_alerts:
                try:
                    if self._should_auto_resolve_alert(alert):
                        self._resolve_alert(alert, auto_resolved=True)
                        resolved_count += 1
                        
                        # Track resolution by type
                        rule_type = self._get_alert_rule_type(alert)
                        if rule_type:
                            self.stats['resolution_by_type'][rule_type] = \
                                self.stats['resolution_by_type'].get(rule_type, 0) + 1
                                
                except Exception as e:
                    logger.error(f"Error processing alert {alert.id} for auto-resolution: {e}")
                    self.stats['errors'] += 1
            
            self.stats['alerts_resolved'] += resolved_count
            
            if resolved_count > 0:
                logger.info(f"Auto-resolved {resolved_count} alerts")
            else:
                logger.debug("No alerts qualified for auto-resolution")
                
        except Exception as e:
            logger.error(f"Error in auto-resolution cycle: {e}")
            self.stats['errors'] += 1
    
    def _should_auto_resolve_alert(self, alert: Alert) -> bool:
        """Check if an alert should be auto-resolved"""
        rule_type = self._get_alert_rule_type(alert)
        if not rule_type or not self.resolution_rules[rule_type]['enabled']:
            return False
        
        rule = self.resolution_rules[rule_type]
        
        # Check alert age
        if alert.created_at:
            age_hours = (datetime.utcnow() - alert.created_at).total_seconds() / 3600
            if age_hours > rule['max_alert_age_hours']:
                logger.debug(f"Alert {alert.id} too old ({age_hours:.1f}h) for auto-resolution")
                return False
        
        # Check specific conditions based on rule type
        if rule_type == 'device_down':
            return self._check_device_recovery(alert, rule)
        elif rule_type == 'response_time':
            return self._check_response_time_recovery(alert, rule)
        elif rule_type == 'connectivity':
            return self._check_connectivity_recovery(alert, rule)
        
        return False
    
    def _get_alert_rule_type(self, alert: Alert) -> str:
        """Determine which auto-resolution rule applies to this alert"""
        message = alert.message.lower()
        
        # Check device down patterns
        for pattern in self.resolution_rules['device_down']['message_patterns']:
            if pattern.lower() in message:
                return 'device_down'
        
        # Check response time patterns
        for pattern in self.resolution_rules['response_time']['message_patterns']:
            if pattern.lower() in message:
                return 'response_time'
        
        # Check connectivity patterns
        for pattern in self.resolution_rules['connectivity']['message_patterns']:
            if pattern.lower() in message:
                return 'connectivity'
        
        return None
    
    def _check_device_recovery(self, alert: Alert, rule: dict) -> bool:
        """Check if device has recovered from being down"""
        device = Device.query.get(alert.device_id)
        if not device:
            return False
        
        # Get recent monitoring data
        required_successes = rule['required_consecutive_successes']
        recent_data = MonitoringData.query.filter(
            MonitoringData.device_id == alert.device_id,
            MonitoringData.timestamp >= datetime.utcnow() - timedelta(minutes=30)
        ).order_by(desc(MonitoringData.timestamp)).limit(required_successes).all()
        
        if len(recent_data) < required_successes:
            return False
        
        # Check if all recent checks were successful
        all_successful = all(data.response_time is not None for data in recent_data)
        
        if all_successful:
            logger.info(f"Device {device.display_name} has recovered - {required_successes} consecutive successful checks")
            return True
        
        return False
    
    def _check_response_time_recovery(self, alert: Alert, rule: dict) -> bool:
        """Check if device response time has returned to normal"""
        device = Device.query.get(alert.device_id)
        if not device:
            return False
        
        # Get recent monitoring data
        required_normal = rule['required_consecutive_normal']
        recent_data = MonitoringData.query.filter(
            MonitoringData.device_id == alert.device_id,
            MonitoringData.timestamp >= datetime.utcnow() - timedelta(hours=1),
            MonitoringData.response_time.isnot(None)
        ).order_by(desc(MonitoringData.timestamp)).limit(required_normal).all()
        
        if len(recent_data) < required_normal:
            return False
        
        # Calculate baseline response time (average from past week, excluding recent hour)
        baseline_cutoff = datetime.utcnow() - timedelta(days=7)
        recent_cutoff = datetime.utcnow() - timedelta(hours=1)
        
        baseline_data = MonitoringData.query.filter(
            MonitoringData.device_id == alert.device_id,
            MonitoringData.timestamp >= baseline_cutoff,
            MonitoringData.timestamp <= recent_cutoff,
            MonitoringData.response_time.isnot(None)
        ).all()
        
        if not baseline_data:
            return False
        
        baseline_avg = sum(d.response_time for d in baseline_data) / len(baseline_data)
        threshold = baseline_avg * rule['normal_threshold_multiplier']
        
        # Check if all recent response times are within normal range
        recent_times = [d.response_time for d in recent_data]
        all_normal = all(rt <= threshold for rt in recent_times)
        
        if all_normal:
            avg_recent = sum(recent_times) / len(recent_times)
            logger.info(f"Device {device.display_name} response time normalized - "
                       f"recent avg: {avg_recent:.1f}ms, baseline: {baseline_avg:.1f}ms")
            return True
        
        return False
    
    def _check_connectivity_recovery(self, alert: Alert, rule: dict) -> bool:
        """Check if device connectivity has stabilized"""
        device = Device.query.get(alert.device_id)
        if not device:
            return False
        
        # For connectivity issues, check if device has been consistently responsive
        stable_hours = rule['required_stable_hours']
        cutoff = datetime.utcnow() - timedelta(hours=stable_hours)
        
        recent_data = MonitoringData.query.filter(
            MonitoringData.device_id == alert.device_id,
            MonitoringData.timestamp >= cutoff
        ).order_by(desc(MonitoringData.timestamp)).all()
        
        if not recent_data:
            return False
        
        # Check connectivity stability (>80% success rate in recent period)
        successful = sum(1 for d in recent_data if d.response_time is not None)
        success_rate = successful / len(recent_data)
        
        if success_rate >= 0.8:
            logger.info(f"Device {device.display_name} connectivity stabilized - "
                       f"{success_rate:.1%} success rate over {stable_hours}h")
            return True
        
        return False
    
    def _resolve_alert(self, alert: Alert, auto_resolved: bool = True):
        """Resolve an alert and mark it as auto-resolved"""
        try:
            alert.resolved = True
            alert.resolved_at = datetime.utcnow()
            
            # Add auto-resolution note if supported
            if hasattr(alert, 'resolution_notes'):
                alert.resolution_notes = "Auto-resolved: Condition no longer detected"
            
            # Add auto-resolved metadata to message if not already present
            if auto_resolved and "[AUTO-RESOLVED]" not in alert.message:
                alert.message = f"[AUTO-RESOLVED] {alert.message}"
            
            db.session.commit()
            
            device = Device.query.get(alert.device_id)
            device_name = device.display_name if device else f"Device ID {alert.device_id}"
            
            logger.info(f"Auto-resolved alert {alert.id} for {device_name}: {alert.message}")
            
        except Exception as e:
            logger.error(f"Error resolving alert {alert.id}: {e}")
            db.session.rollback()
            raise
    
    def get_stats(self) -> dict:
        """Get auto-resolution statistics"""
        return {
            'enabled': self.enabled,
            'last_run': self.stats['last_run'].isoformat() if self.stats['last_run'] else None,
            'alerts_resolved': self.stats['alerts_resolved'],
            'alerts_checked': self.stats['alerts_checked'],
            'resolution_by_type': self.stats['resolution_by_type'].copy(),
            'errors': self.stats['errors'],
            'rules': {
                rule_name: {
                    'enabled': rule_config['enabled'],
                    'max_alert_age_hours': rule_config['max_alert_age_hours']
                }
                for rule_name, rule_config in self.resolution_rules.items()
            }
        }
    
    def enable(self):
        """Enable auto-resolution"""
        self.enabled = True
        logger.info("Alert auto-resolution enabled")
    
    def disable(self):
        """Disable auto-resolution"""
        self.enabled = False
        logger.info("Alert auto-resolution disabled")

# Global instance
alert_auto_resolver = AlertAutoResolver()