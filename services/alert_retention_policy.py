"""
Alert Retention Policy Service
Automatically cleans up old alerts based on configurable retention rules
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List
from models import db, Alert, Configuration
from sqlalchemy import and_, func

logger = logging.getLogger(__name__)

class AlertRetentionPolicy:
    """Service to automatically clean up old alerts based on retention policies"""
    
    def __init__(self, app=None):
        self.app = app
        self.enabled = True
        
        # Default retention policies (in days)
        self.default_policies = {
            'resolved_alerts': {
                'retention_days': 30,      # Keep resolved alerts for 30 days
                'description': 'Resolved alerts retention period'
            },
            'low_severity_alerts': {
                'retention_days': 14,      # Keep low severity alerts for 2 weeks
                'description': 'Low severity unresolved alerts retention period'
            },
            'medium_severity_alerts': {
                'retention_days': 60,      # Keep medium severity alerts for 2 months
                'description': 'Medium severity unresolved alerts retention period'
            },
            'high_severity_alerts': {
                'retention_days': 90,      # Keep high severity alerts for 3 months
                'description': 'High severity unresolved alerts retention period'
            },
            'critical_alerts': {
                'retention_days': 365,     # Keep critical alerts for 1 year
                'description': 'Critical alerts retention period (always keep longest)'
            },
            'auto_resolved_alerts': {
                'retention_days': 7,       # Keep auto-resolved alerts for 1 week only
                'description': 'Auto-resolved alerts retention period'
            }
        }
        
        # Load configuration or use defaults
        self.policies = self._load_retention_policies()
        
        # Statistics tracking
        self.stats = {
            'last_cleanup': None,
            'total_cleaned': 0,
            'cleanup_by_policy': {},
            'errors': 0
        }
    
    def _load_retention_policies(self) -> Dict:
        """Load retention policies from configuration or use defaults"""
        policies = {}
        
        for policy_name, default_config in self.default_policies.items():
            try:
                # Try to load from database configuration
                config_key = f'alert_retention_{policy_name}'
                retention_days = int(Configuration.get_value(config_key, str(default_config['retention_days'])))
                
                policies[policy_name] = {
                    'retention_days': retention_days,
                    'description': default_config['description']
                }
                
            except Exception:
                # Fall back to default if configuration loading fails
                policies[policy_name] = default_config.copy()
        
        return policies
    
    def run_retention_cleanup(self):
        """Run the retention cleanup cycle"""
        if not self.enabled:
            logger.debug("Alert retention cleanup disabled, skipping")
            return
        
        try:
            self.stats['last_cleanup'] = datetime.utcnow()
            logger.info("Starting alert retention cleanup")
            
            total_cleaned = 0
            
            # Clean up resolved alerts
            cleaned = self._cleanup_resolved_alerts()
            total_cleaned += cleaned
            
            # Clean up old unresolved alerts by severity
            for severity in ['low', 'medium', 'high', 'critical']:
                cleaned = self._cleanup_old_alerts_by_severity(severity)
                total_cleaned += cleaned
            
            # Clean up auto-resolved alerts (special case - shorter retention)
            cleaned = self._cleanup_auto_resolved_alerts()
            total_cleaned += cleaned
            
            self.stats['total_cleaned'] += total_cleaned
            
            if total_cleaned > 0:
                logger.info(f"Alert retention cleanup completed - removed {total_cleaned} old alerts")
            else:
                logger.debug("Alert retention cleanup completed - no old alerts to remove")
            
        except Exception as e:
            logger.error(f"Error in alert retention cleanup: {e}")
            self.stats['errors'] += 1
    
    def _cleanup_resolved_alerts(self) -> int:
        """Clean up old resolved alerts"""
        try:
            retention_days = self.policies['resolved_alerts']['retention_days']
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            
            # Delete resolved alerts older than retention period
            deleted_count = Alert.query.filter(
                Alert.resolved == True,
                Alert.resolved_at < cutoff_date
            ).delete(synchronize_session=False)
            
            db.session.commit()
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} resolved alerts older than {retention_days} days")
                self.stats['cleanup_by_policy']['resolved_alerts'] = \
                    self.stats['cleanup_by_policy'].get('resolved_alerts', 0) + deleted_count
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error cleaning up resolved alerts: {e}")
            db.session.rollback()
            return 0
    
    def _cleanup_old_alerts_by_severity(self, severity: str) -> int:
        """Clean up old unresolved alerts by severity level"""
        try:
            policy_key = f'{severity}_severity_alerts'
            if policy_key not in self.policies:
                return 0
            
            retention_days = self.policies[policy_key]['retention_days']
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            
            # Delete unresolved alerts of this severity older than retention period
            deleted_count = Alert.query.filter(
                Alert.resolved == False,
                Alert.severity == severity,
                Alert.created_at < cutoff_date
            ).delete(synchronize_session=False)
            
            db.session.commit()
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} unresolved {severity} severity alerts older than {retention_days} days")
                self.stats['cleanup_by_policy'][policy_key] = \
                    self.stats['cleanup_by_policy'].get(policy_key, 0) + deleted_count
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error cleaning up {severity} severity alerts: {e}")
            db.session.rollback()
            return 0
    
    def _cleanup_auto_resolved_alerts(self) -> int:
        """Clean up auto-resolved alerts (shorter retention period)"""
        try:
            retention_days = self.policies['auto_resolved_alerts']['retention_days']
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            
            # Delete auto-resolved alerts (identified by message prefix)
            deleted_count = Alert.query.filter(
                Alert.resolved == True,
                Alert.message.like('[AUTO-RESOLVED]%'),
                Alert.resolved_at < cutoff_date
            ).delete(synchronize_session=False)
            
            db.session.commit()
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} auto-resolved alerts older than {retention_days} days")
                self.stats['cleanup_by_policy']['auto_resolved_alerts'] = \
                    self.stats['cleanup_by_policy'].get('auto_resolved_alerts', 0) + deleted_count
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error cleaning up auto-resolved alerts: {e}")
            db.session.rollback()
            return 0
    
    def get_retention_summary(self) -> Dict:
        """Get summary of current alert counts and retention policies"""
        try:
            summary = {
                'policies': self.policies.copy(),
                'current_counts': {},
                'cleanup_candidates': {},
                'stats': self.stats.copy()
            }
            
            # Get current alert counts
            summary['current_counts'] = {
                'total_alerts': Alert.query.count(),
                'resolved_alerts': Alert.query.filter_by(resolved=True).count(),
                'unresolved_alerts': Alert.query.filter_by(resolved=False).count(),
                'by_severity': {}
            }
            
            # Get counts by severity
            for severity in ['low', 'medium', 'high', 'critical']:
                count = Alert.query.filter_by(severity=severity, resolved=False).count()
                summary['current_counts']['by_severity'][severity] = count
            
            # Get auto-resolved count
            auto_resolved_count = Alert.query.filter(
                Alert.resolved == True,
                Alert.message.like('[AUTO-RESOLVED]%')
            ).count()
            summary['current_counts']['auto_resolved'] = auto_resolved_count
            
            # Calculate cleanup candidates (alerts that would be deleted)
            for policy_name, policy_config in self.policies.items():
                cutoff_date = datetime.utcnow() - timedelta(days=policy_config['retention_days'])
                
                if policy_name == 'resolved_alerts':
                    candidate_count = Alert.query.filter(
                        Alert.resolved == True,
                        Alert.resolved_at < cutoff_date
                    ).count()
                elif policy_name == 'auto_resolved_alerts':
                    candidate_count = Alert.query.filter(
                        Alert.resolved == True,
                        Alert.message.like('[AUTO-RESOLVED]%'),
                        Alert.resolved_at < cutoff_date
                    ).count()
                elif policy_name.endswith('_severity_alerts'):
                    severity = policy_name.replace('_severity_alerts', '')
                    candidate_count = Alert.query.filter(
                        Alert.resolved == False,
                        Alert.severity == severity,
                        Alert.created_at < cutoff_date
                    ).count()
                else:
                    candidate_count = 0
                
                summary['cleanup_candidates'][policy_name] = candidate_count
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating retention summary: {e}")
            return {'error': str(e)}
    
    def update_retention_policy(self, policy_name: str, retention_days: int):
        """Update a retention policy"""
        if policy_name not in self.default_policies:
            raise ValueError(f"Unknown retention policy: {policy_name}")
        
        if retention_days < 1:
            raise ValueError("Retention days must be at least 1")
        
        # Update in memory
        self.policies[policy_name]['retention_days'] = retention_days
        
        # Update in database configuration
        config_key = f'alert_retention_{policy_name}'
        Configuration.set_value(config_key, str(retention_days), self.policies[policy_name]['description'])
        
        logger.info(f"Updated retention policy {policy_name} to {retention_days} days")
    
    def force_cleanup_by_age(self, days: int) -> int:
        """Force cleanup of all alerts older than specified days (emergency cleanup)"""
        if days < 1:
            raise ValueError("Days must be at least 1")
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Delete ALL alerts (resolved and unresolved) older than cutoff
            deleted_count = Alert.query.filter(
                Alert.created_at < cutoff_date
            ).delete(synchronize_session=False)
            
            db.session.commit()
            
            logger.warning(f"FORCE CLEANUP: Removed {deleted_count} alerts older than {days} days")
            self.stats['total_cleaned'] += deleted_count
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error in force cleanup: {e}")
            db.session.rollback()
            raise
    
    def get_stats(self) -> Dict:
        """Get retention policy statistics"""
        return {
            'enabled': self.enabled,
            'policies': self.policies.copy(),
            'stats': self.stats.copy()
        }
    
    def enable(self):
        """Enable retention policy cleanup"""
        self.enabled = True
        logger.info("Alert retention policy cleanup enabled")
    
    def disable(self):
        """Disable retention policy cleanup"""
        self.enabled = False
        logger.info("Alert retention policy cleanup disabled")

# Global instance
alert_retention_policy = AlertRetentionPolicy()