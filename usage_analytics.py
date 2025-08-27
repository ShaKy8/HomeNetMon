# HomeNetMon Usage Analytics and Quota Management System
from flask import Flask, current_app, g
from sqlalchemy import func, and_, or_, desc, asc, text, case
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta, date
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading
import time
from collections import defaultdict, deque
import redis
from tenant_models import *
from tenant_manager import get_current_tenant, tenant_context, track_usage, enforce_quota
from cloud_config import get_config

logger = logging.getLogger(__name__)

class AnalyticsAggregation(Enum):
    """Analytics aggregation levels"""
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    YEAR = "year"

class QuotaEnforcement(Enum):
    """Quota enforcement strategies"""
    HARD_LIMIT = "hard_limit"      # Block when quota exceeded
    SOFT_LIMIT = "soft_limit"      # Allow but charge overage
    WARNING_ONLY = "warning_only"  # Log warning, allow usage
    DISABLED = "disabled"          # No enforcement

@dataclass
class UsageMetrics:
    """Current usage metrics for a tenant"""
    tenant_id: str
    metric_type: UsageMetricType
    current_usage: float
    quota_limit: Optional[float]
    percentage_used: float
    is_over_quota: bool
    time_until_reset: Optional[timedelta]
    overage_amount: float
    overage_cost_cents: int

@dataclass
class AnalyticsDataPoint:
    """Single analytics data point"""
    timestamp: datetime
    metric_type: UsageMetricType
    value: float
    metadata: Dict[str, Any]

@dataclass
class TrendAnalysis:
    """Usage trend analysis"""
    metric_type: UsageMetricType
    period_days: int
    current_average: float
    previous_average: float
    growth_rate: float
    projected_monthly: float
    trend_direction: str  # "increasing", "decreasing", "stable"

class UsageAnalyticsManager:
    """Comprehensive usage analytics and quota management"""
    
    def __init__(self, app: Flask = None):
        self.app = app
        self.redis_client = None
        self.quota_enforcement = {}
        self.usage_cache = {}
        self.analytics_cache = {}
        self.background_tasks = []
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize analytics manager with Flask app"""
        self.app = app
        
        # Initialize Redis for caching
        redis_url = get_config('REDIS_URL')
        if redis_url:
            self.redis_client = redis.from_url(redis_url, decode_responses=True)
        
        # Set up quota enforcement strategies
        self.setup_quota_enforcement()
        
        # Start background analytics processing
        self.start_background_processing()
        
        logger.info("UsageAnalyticsManager initialized")
    
    def setup_quota_enforcement(self):
        """Configure quota enforcement strategies per metric type"""
        self.quota_enforcement = {
            UsageMetricType.DEVICES_MONITORED: QuotaEnforcement.HARD_LIMIT,
            UsageMetricType.API_CALLS: QuotaEnforcement.SOFT_LIMIT,
            UsageMetricType.STORAGE_GB: QuotaEnforcement.SOFT_LIMIT,
            UsageMetricType.BANDWIDTH_GB: QuotaEnforcement.SOFT_LIMIT,
            UsageMetricType.ALERTS_PER_MONTH: QuotaEnforcement.WARNING_ONLY,
            UsageMetricType.USERS_PER_TENANT: QuotaEnforcement.HARD_LIMIT,
            UsageMetricType.DATA_RETENTION_DAYS: QuotaEnforcement.DISABLED,
            UsageMetricType.CUSTOM_INTEGRATIONS: QuotaEnforcement.HARD_LIMIT
        }
    
    def start_background_processing(self):
        """Start background analytics processing tasks"""
        if get_config('ENABLE_BACKGROUND_ANALYTICS', True):
            # Start analytics aggregation task
            aggregation_task = threading.Thread(
                target=self._background_analytics_aggregation,
                daemon=True
            )
            aggregation_task.start()
            
            # Start quota monitoring task
            quota_task = threading.Thread(
                target=self._background_quota_monitoring,
                daemon=True
            )
            quota_task.start()
            
            logger.info("Started background analytics processing")
    
    # ========================================================================
    # Usage Tracking and Recording
    # ========================================================================
    
    def record_usage(self, tenant_id: str, metric_type: UsageMetricType, 
                    quantity: float, metadata: Dict = None) -> bool:
        """Record usage and enforce quotas"""
        try:
            # Check quota before recording
            if not self.check_quota_allowance(tenant_id, metric_type, quantity):
                enforcement = self.quota_enforcement.get(metric_type, QuotaEnforcement.WARNING_ONLY)
                
                if enforcement == QuotaEnforcement.HARD_LIMIT:
                    logger.warning(f"Quota exceeded for {tenant_id}: {metric_type.value}")
                    return False
            
            # Record usage
            usage_record = UsageRecord(
                tenant_id=tenant_id,
                metric_type=metric_type,
                quantity=quantity,
                metadata=metadata or {},
                source='analytics_manager'
            )
            
            db.session.add(usage_record)
            
            # Update cached usage
            self.update_usage_cache(tenant_id, metric_type, quantity)
            
            # Update subscription usage
            self.update_subscription_usage(tenant_id, metric_type, quantity)
            
            db.session.commit()
            
            # Trigger quota alerts if needed
            self.check_quota_alerts(tenant_id, metric_type)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to record usage: {e}")
            db.session.rollback()
            return False
    
    def check_quota_allowance(self, tenant_id: str, metric_type: UsageMetricType, 
                            requested_quantity: float) -> bool:
        """Check if usage is within quota limits"""
        tenant = Tenant.query.get(tenant_id)
        if not tenant or not tenant.subscription:
            return True
        
        quota = tenant.subscription.get_quota(metric_type)
        if quota is None:
            return True  # No limit
        
        current_usage = self.get_current_usage(tenant_id, metric_type)
        return (current_usage + requested_quantity) <= quota
    
    def update_usage_cache(self, tenant_id: str, metric_type: UsageMetricType, quantity: float):
        """Update usage cache for real-time quota checking"""
        if not self.redis_client:
            return
        
        cache_key = f"usage:{tenant_id}:{metric_type.value}"
        
        # Get billing period
        tenant = Tenant.query.get(tenant_id)
        if tenant and tenant.subscription:
            period_key = tenant.subscription.current_period_start.strftime('%Y-%m')
            cache_key = f"{cache_key}:{period_key}"
        
        # Increment usage
        self.redis_client.incrbyfloat(cache_key, quantity)
        
        # Set expiration (end of current billing period + 1 day)
        if tenant and tenant.subscription:
            expires_at = tenant.subscription.current_period_end + timedelta(days=1)
            ttl = int((expires_at - datetime.utcnow()).total_seconds())
            self.redis_client.expire(cache_key, ttl)
    
    def update_subscription_usage(self, tenant_id: str, metric_type: UsageMetricType, quantity: float):
        """Update subscription current usage"""
        tenant = Tenant.query.get(tenant_id)
        if not tenant or not tenant.subscription:
            return
        
        subscription = tenant.subscription
        current_usage = subscription.current_usage.copy()
        current_usage[metric_type.value] = current_usage.get(metric_type.value, 0) + quantity
        subscription.current_usage = current_usage
    
    def get_current_usage(self, tenant_id: str, metric_type: UsageMetricType) -> float:
        """Get current usage for a metric, checking cache first"""
        if self.redis_client:
            # Try cache first
            tenant = Tenant.query.get(tenant_id)
            if tenant and tenant.subscription:
                period_key = tenant.subscription.current_period_start.strftime('%Y-%m')
                cache_key = f"usage:{tenant_id}:{metric_type.value}:{period_key}"
                cached_usage = self.redis_client.get(cache_key)
                
                if cached_usage:
                    return float(cached_usage)
        
        # Fall back to database
        if tenant and tenant.subscription:
            return tenant.subscription.get_current_usage(metric_type)
        
        return 0.0
    
    # ========================================================================
    # Usage Analytics and Reporting
    # ========================================================================
    
    def get_usage_analytics(self, tenant_id: str, metric_type: UsageMetricType = None,
                          start_date: datetime = None, end_date: datetime = None,
                          aggregation: AnalyticsAggregation = AnalyticsAggregation.DAY) -> Dict[str, Any]:
        """Get comprehensive usage analytics"""
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)
        
        # Build query
        query = UsageRecord.query.filter(
            UsageRecord.tenant_id == tenant_id,
            UsageRecord.recorded_at >= start_date,
            UsageRecord.recorded_at <= end_date
        )
        
        if metric_type:
            query = query.filter(UsageRecord.metric_type == metric_type)
        
        # Get raw usage records
        usage_records = query.all()
        
        # Aggregate data
        aggregated_data = self.aggregate_usage_data(usage_records, aggregation)
        
        # Calculate statistics
        statistics = self.calculate_usage_statistics(usage_records, metric_type)
        
        # Get quota information
        quota_info = self.get_quota_information(tenant_id, metric_type)
        
        # Trend analysis
        trend_analysis = self.analyze_usage_trends(tenant_id, metric_type, start_date, end_date)
        
        return {
            'tenant_id': tenant_id,
            'metric_type': metric_type.value if metric_type else 'all',
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat(),
                'aggregation': aggregation.value
            },
            'aggregated_data': aggregated_data,
            'statistics': statistics,
            'quota_info': quota_info,
            'trend_analysis': trend_analysis,
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def aggregate_usage_data(self, usage_records: List[UsageRecord], 
                           aggregation: AnalyticsAggregation) -> Dict[str, Any]:
        """Aggregate usage data by time period"""
        aggregated = defaultdict(lambda: defaultdict(float))
        
        # Define aggregation format
        time_formats = {
            AnalyticsAggregation.MINUTE: '%Y-%m-%d %H:%M',
            AnalyticsAggregation.HOUR: '%Y-%m-%d %H:00',
            AnalyticsAggregation.DAY: '%Y-%m-%d',
            AnalyticsAggregation.WEEK: '%Y-W%U',
            AnalyticsAggregation.MONTH: '%Y-%m',
            AnalyticsAggregation.YEAR: '%Y'
        }
        
        time_format = time_formats[aggregation]
        
        for record in usage_records:
            time_key = record.recorded_at.strftime(time_format)
            metric_key = record.metric_type.value
            aggregated[time_key][metric_key] += record.quantity
        
        # Convert to list format
        result = []
        for time_key in sorted(aggregated.keys()):
            data_point = {
                'timestamp': time_key,
                'metrics': dict(aggregated[time_key])
            }
            result.append(data_point)
        
        return result
    
    def calculate_usage_statistics(self, usage_records: List[UsageRecord], 
                                 metric_type: UsageMetricType = None) -> Dict[str, Any]:
        """Calculate comprehensive usage statistics"""
        if not usage_records:
            return {'total_records': 0}
        
        # Group by metric type
        by_metric = defaultdict(list)
        for record in usage_records:
            if not metric_type or record.metric_type == metric_type:
                by_metric[record.metric_type.value].append(record.quantity)
        
        statistics = {}
        
        for metric, quantities in by_metric.items():
            if quantities:
                statistics[metric] = {
                    'total': sum(quantities),
                    'average': sum(quantities) / len(quantities),
                    'min': min(quantities),
                    'max': max(quantities),
                    'count': len(quantities),
                    'median': sorted(quantities)[len(quantities) // 2]
                }
        
        statistics['total_records'] = len(usage_records)
        statistics['date_range'] = {
            'start': min(r.recorded_at for r in usage_records).isoformat(),
            'end': max(r.recorded_at for r in usage_records).isoformat()
        }
        
        return statistics
    
    def get_quota_information(self, tenant_id: str, 
                            metric_type: UsageMetricType = None) -> Dict[str, Any]:
        """Get quota information for tenant"""
        tenant = Tenant.query.get(tenant_id)
        if not tenant or not tenant.subscription:
            return {}
        
        quota_info = {}
        
        # Get all metrics or specific metric
        metrics = [metric_type] if metric_type else list(UsageMetricType)
        
        for metric in metrics:
            quota = tenant.subscription.get_quota(metric)
            current_usage = self.get_current_usage(tenant_id, metric)
            
            if quota is not None:
                percentage = (current_usage / quota * 100) if quota > 0 else 0
                overage = max(0, current_usage - quota)
                
                quota_info[metric.value] = {
                    'quota': quota,
                    'current_usage': current_usage,
                    'percentage_used': round(percentage, 2),
                    'remaining': max(0, quota - current_usage),
                    'is_over_quota': current_usage > quota,
                    'overage': overage,
                    'enforcement': self.quota_enforcement.get(metric, QuotaEnforcement.WARNING_ONLY).value
                }
        
        return quota_info
    
    def analyze_usage_trends(self, tenant_id: str, metric_type: UsageMetricType = None,
                           start_date: datetime = None, end_date: datetime = None) -> List[TrendAnalysis]:
        """Analyze usage trends and predict future usage"""
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=60)  # 2 months for trend analysis
        
        # Split period in half for comparison
        mid_point = start_date + (end_date - start_date) / 2
        
        metrics = [metric_type] if metric_type else list(UsageMetricType)
        trends = []
        
        for metric in metrics:
            # Get usage for both periods
            first_period = UsageRecord.query.filter(
                UsageRecord.tenant_id == tenant_id,
                UsageRecord.metric_type == metric,
                UsageRecord.recorded_at >= start_date,
                UsageRecord.recorded_at < mid_point
            ).all()
            
            second_period = UsageRecord.query.filter(
                UsageRecord.tenant_id == tenant_id,
                UsageRecord.metric_type == metric,
                UsageRecord.recorded_at >= mid_point,
                UsageRecord.recorded_at <= end_date
            ).all()
            
            if not first_period and not second_period:
                continue
            
            # Calculate averages
            first_total = sum(r.quantity for r in first_period) if first_period else 0
            second_total = sum(r.quantity for r in second_period) if second_period else 0
            
            first_days = (mid_point - start_date).days
            second_days = (end_date - mid_point).days
            
            first_avg = first_total / first_days if first_days > 0 else 0
            second_avg = second_total / second_days if second_days > 0 else 0
            
            # Calculate growth rate
            if first_avg > 0:
                growth_rate = ((second_avg - first_avg) / first_avg) * 100
            else:
                growth_rate = 0 if second_avg == 0 else 100
            
            # Determine trend direction
            if abs(growth_rate) < 5:
                trend_direction = "stable"
            elif growth_rate > 0:
                trend_direction = "increasing"
            else:
                trend_direction = "decreasing"
            
            # Project monthly usage
            projected_monthly = second_avg * 30 if second_avg > 0 else first_avg * 30
            
            trend = TrendAnalysis(
                metric_type=metric,
                period_days=(end_date - start_date).days,
                current_average=second_avg,
                previous_average=first_avg,
                growth_rate=round(growth_rate, 2),
                projected_monthly=round(projected_monthly, 2),
                trend_direction=trend_direction
            )
            
            trends.append(asdict(trend))
        
        return trends
    
    # ========================================================================
    # Quota Management
    # ========================================================================
    
    def get_tenant_quotas(self, tenant_id: str) -> Dict[str, UsageMetrics]:
        """Get comprehensive quota status for tenant"""
        tenant = Tenant.query.get(tenant_id)
        if not tenant or not tenant.subscription:
            return {}
        
        quota_status = {}
        
        for metric_type in UsageMetricType:
            quota = tenant.subscription.get_quota(metric_type)
            current_usage = self.get_current_usage(tenant_id, metric_type)
            
            if quota is not None:
                percentage_used = (current_usage / quota * 100) if quota > 0 else 0
                is_over_quota = current_usage > quota
                overage_amount = max(0, current_usage - quota)
                
                # Calculate overage cost
                overage_cost = self.calculate_overage_cost(tenant.subscription.plan, metric_type, overage_amount)
                
                # Calculate time until reset (next billing period)
                time_until_reset = None
                if tenant.subscription.current_period_end:
                    time_until_reset = tenant.subscription.current_period_end - datetime.utcnow()
                
                usage_metrics = UsageMetrics(
                    tenant_id=tenant_id,
                    metric_type=metric_type,
                    current_usage=current_usage,
                    quota_limit=quota,
                    percentage_used=round(percentage_used, 2),
                    is_over_quota=is_over_quota,
                    time_until_reset=time_until_reset,
                    overage_amount=overage_amount,
                    overage_cost_cents=overage_cost
                )
                
                quota_status[metric_type.value] = asdict(usage_metrics)
        
        return quota_status
    
    def calculate_overage_cost(self, plan: SubscriptionPlan, metric_type: UsageMetricType, 
                             overage_amount: float) -> int:
        """Calculate cost of overage usage in cents"""
        if overage_amount <= 0:
            return 0
        
        # Base overage pricing (cents per unit)
        base_pricing = {
            UsageMetricType.DEVICES_MONITORED: 200,  # $2.00 per device
            UsageMetricType.API_CALLS: 0.1,         # $0.001 per call
            UsageMetricType.STORAGE_GB: 50,         # $0.50 per GB
            UsageMetricType.BANDWIDTH_GB: 10,       # $0.10 per GB
            UsageMetricType.ALERTS_PER_MONTH: 1,    # $0.01 per alert
            UsageMetricType.USERS_PER_TENANT: 500,  # $5.00 per user
            UsageMetricType.CUSTOM_INTEGRATIONS: 1000  # $10.00 per integration
        }
        
        unit_cost = base_pricing.get(metric_type, 0)
        
        # Apply plan-based multiplier
        multipliers = {
            SubscriptionTier.FREE: 1.5,
            SubscriptionTier.STARTER: 1.2,
            SubscriptionTier.PROFESSIONAL: 1.0,
            SubscriptionTier.ENTERPRISE: 0.8
        }
        
        multiplier = multipliers.get(plan.tier, 1.0)
        
        return int(overage_amount * unit_cost * multiplier)
    
    def check_quota_alerts(self, tenant_id: str, metric_type: UsageMetricType):
        """Check if quota alerts should be triggered"""
        quota_info = self.get_quota_information(tenant_id, metric_type)
        metric_info = quota_info.get(metric_type.value)
        
        if not metric_info:
            return
        
        percentage_used = metric_info['percentage_used']
        
        # Define alert thresholds
        alert_thresholds = [75, 90, 100, 110]  # 75%, 90%, 100%, 110%
        
        for threshold in alert_thresholds:
            if percentage_used >= threshold:
                self.send_quota_alert(tenant_id, metric_type, percentage_used, threshold)
    
    def send_quota_alert(self, tenant_id: str, metric_type: UsageMetricType, 
                        percentage_used: float, threshold: int):
        """Send quota alert notification"""
        # Check if alert was already sent recently (avoid spam)
        alert_key = f"quota_alert:{tenant_id}:{metric_type.value}:{threshold}"
        
        if self.redis_client:
            if self.redis_client.get(alert_key):
                return  # Alert already sent recently
            
            # Set alert flag for 24 hours
            self.redis_client.setex(alert_key, 86400, "sent")
        
        tenant = Tenant.query.get(tenant_id)
        if not tenant:
            return
        
        # Log quota alert
        logger.warning(
            f"Quota alert for {tenant.name}: {metric_type.value} usage at {percentage_used:.1f}% "
            f"(threshold: {threshold}%)"
        )
        
        # Send notification through existing alert system
        self._send_quota_alert_notification(tenant, metric_type, percentage_used, threshold)
    
    def _send_quota_alert_notification(self, tenant, metric_type: UsageMetricType, 
                                      percentage_used: float, threshold: int):
        """Send quota alert notification through existing alert system"""
        try:
            # Import here to avoid circular imports
            from monitoring.alerts import AlertManager
            from models import Alert
            
            # Create alert record in database
            alert_message = (
                f"[QUOTA ALERT] {tenant.name}: {metric_type.value.replace('_', ' ').title()} "
                f"usage at {percentage_used:.1f}% (threshold: {threshold}%)"
            )
            
            alert = Alert(
                device_id=None,  # This is a system/tenant alert, not device-specific
                alert_type='quota_exceeded',
                message=alert_message,
                severity='warning' if threshold < 90 else 'critical',
                created_at=datetime.utcnow(),
                resolved=False,
                metadata={
                    'tenant_id': tenant.id,
                    'tenant_name': tenant.name,
                    'metric_type': metric_type.value,
                    'percentage_used': percentage_used,
                    'threshold': threshold,
                    'alert_category': 'usage_quota'
                }
            )
            
            db.session.add(alert)
            db.session.commit()
            
            # Send notifications through AlertManager
            alert_manager = AlertManager()
            alert_manager.send_alert_notifications(alert)
            
            logger.info(f"Quota alert notification sent for {tenant.name}: {metric_type.value}")
            
        except Exception as e:
            logger.error(f"Failed to send quota alert notification: {e}")
    
    # ========================================================================
    # Background Processing
    # ========================================================================
    
    def _background_analytics_aggregation(self):
        """Background task for analytics data aggregation"""
        while True:
            try:
                # Aggregate hourly data
                self.aggregate_hourly_usage()
                
                # Aggregate daily data
                self.aggregate_daily_usage()
                
                # Clean up old usage records
                self.cleanup_old_usage_records()
                
                # Sleep for 1 hour
                time.sleep(3600)
                
            except Exception as e:
                logger.error(f"Background analytics aggregation error: {e}")
                time.sleep(300)  # Sleep 5 minutes on error
    
    def _background_quota_monitoring(self):
        """Background task for quota monitoring"""
        while True:
            try:
                # Check all tenants for quota violations
                self.monitor_all_tenant_quotas()
                
                # Update usage caches
                self.refresh_usage_caches()
                
                # Sleep for 5 minutes
                time.sleep(300)
                
            except Exception as e:
                logger.error(f"Background quota monitoring error: {e}")
                time.sleep(60)  # Sleep 1 minute on error
    
    def aggregate_hourly_usage(self):
        """Aggregate usage data by hour for faster queries"""
        # This would create aggregated tables for better performance
        # Implementation depends on specific requirements
        pass
    
    def aggregate_daily_usage(self):
        """Aggregate usage data by day for reporting"""
        # This would create daily summaries
        pass
    
    def cleanup_old_usage_records(self):
        """Clean up old usage records to manage database size"""
        retention_days = get_config('USAGE_RECORD_RETENTION_DAYS', 365)
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        # Delete old usage records
        deleted_count = UsageRecord.query.filter(
            UsageRecord.recorded_at < cutoff_date
        ).delete()
        
        if deleted_count > 0:
            db.session.commit()
            logger.info(f"Cleaned up {deleted_count} old usage records")
    
    def monitor_all_tenant_quotas(self):
        """Monitor quotas for all active tenants"""
        active_tenants = Tenant.query.filter(
            Tenant.status.in_([TenantStatus.ACTIVE, TenantStatus.TRIAL])
        ).all()
        
        for tenant in active_tenants:
            for metric_type in UsageMetricType:
                try:
                    self.check_quota_alerts(tenant.id, metric_type)
                except Exception as e:
                    logger.error(f"Error checking quota for {tenant.id}: {e}")
    
    def refresh_usage_caches(self):
        """Refresh Redis usage caches"""
        if not self.redis_client:
            return
        
        # This would update cached usage data from database
        # Implementation depends on caching strategy
        pass

# Global analytics manager instance
usage_analytics = UsageAnalyticsManager()

# Convenience functions
def record_usage(metric_type: UsageMetricType, quantity: float = 1, metadata: Dict = None) -> bool:
    """Record usage for current tenant"""
    tenant = get_current_tenant()
    if tenant:
        return usage_analytics.record_usage(tenant.id, metric_type, quantity, metadata)
    return False

def get_tenant_usage_analytics(tenant_id: str = None, **kwargs) -> Dict[str, Any]:
    """Get usage analytics for tenant"""
    if not tenant_id:
        tenant = get_current_tenant()
        tenant_id = tenant.id if tenant else None
    
    if tenant_id:
        return usage_analytics.get_usage_analytics(tenant_id, **kwargs)
    return {}

def get_quota_status(tenant_id: str = None) -> Dict[str, UsageMetrics]:
    """Get quota status for tenant"""
    if not tenant_id:
        tenant = get_current_tenant()
        tenant_id = tenant.id if tenant else None
    
    if tenant_id:
        return usage_analytics.get_tenant_quotas(tenant_id)
    return {}

def check_quota(metric_type: UsageMetricType, quantity: float = 1) -> bool:
    """Check if usage is within quota for current tenant"""
    tenant = get_current_tenant()
    if tenant:
        return usage_analytics.check_quota_allowance(tenant.id, metric_type, quantity)
    return True

# Decorators for automatic usage tracking
def track_api_call(func):
    """Decorator to automatically track API calls"""
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        record_usage(UsageMetricType.API_CALLS, 1, {'endpoint': func.__name__})
        return result
    return wrapper

def track_device_monitoring(func):
    """Decorator to track device monitoring usage"""
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        # This would track when devices are being monitored
        return result
    return wrapper