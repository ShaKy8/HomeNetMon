# HomeNetMon Usage Analytics API
from flask import Blueprint, request, jsonify, abort, current_app
from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_, desc
from typing import Dict, Any, List, Optional
import logging
import json
import csv
import io
from functools import wraps
from api.rate_limited_endpoints import create_endpoint_limiter

from tenant_models import *
from tenant_manager import get_current_tenant, require_tenant, enforce_quota, track_usage
from usage_analytics import usage_analytics, UsageMetricType, AnalyticsAggregation

logger = logging.getLogger(__name__)

# Create blueprint
usage_analytics_api = Blueprint('usage_analytics_api', __name__, url_prefix='/api/analytics')

def require_analytics_access(f):
    """Require analytics access permissions"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        tenant = get_current_tenant()
        if not tenant:
            abort(400, description="Tenant context required")
        
        # Check if tenant has analytics feature
        if tenant.subscription and not tenant.subscription.plan.has_feature('advanced_analytics'):
            abort(403, description="Advanced analytics not available in your plan")
        
        return f(*args, **kwargs)
    
    return decorated_function

# ============================================================================
# Usage Analytics Endpoints
# ============================================================================

@usage_analytics_api.route('/usage', methods=['GET'])
@create_endpoint_limiter('relaxed')
@require_analytics_access
@enforce_quota(UsageMetricType.API_CALLS)
def get_usage_analytics():
    """Get comprehensive usage analytics for tenant"""
    try:
        tenant = require_tenant()
        
        # Parse query parameters
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        metric_type_str = request.args.get('metric_type')
        aggregation_str = request.args.get('aggregation', 'day')
        
        # Parse dates
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)  # Default to 30 days
        
        if start_date_str:
            try:
                start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid start_date format'}), 400
        
        if end_date_str:
            try:
                end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid end_date format'}), 400
        
        # Parse metric type
        metric_type = None
        if metric_type_str:
            try:
                metric_type = UsageMetricType(metric_type_str)
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid metric_type'}), 400
        
        # Parse aggregation
        try:
            aggregation = AnalyticsAggregation(aggregation_str)
        except ValueError:
            aggregation = AnalyticsAggregation.DAY
        
        # Get analytics data
        analytics_data = usage_analytics.get_usage_analytics(
            tenant_id=tenant.id,
            metric_type=metric_type,
            start_date=start_date,
            end_date=end_date,
            aggregation=aggregation
        )
        
        return jsonify({
            'success': True,
            'data': analytics_data
        })
        
    except Exception as e:
        logger.error(f"Error getting usage analytics: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@usage_analytics_api.route('/quota-status', methods=['GET'])
@create_endpoint_limiter('relaxed')
@enforce_quota(UsageMetricType.API_CALLS)
def get_quota_status():
    """Get current quota status for tenant"""
    try:
        tenant = require_tenant()
        
        # Get quota status
        quota_status = usage_analytics.get_tenant_quotas(tenant.id)
        
        return jsonify({
            'success': True,
            'data': quota_status
        })
        
    except Exception as e:
        logger.error(f"Error getting quota status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@usage_analytics_api.route('/metrics', methods=['GET'])
@create_endpoint_limiter('relaxed')
@enforce_quota(UsageMetricType.API_CALLS)
def get_available_metrics():
    """Get list of available usage metrics"""
    try:
        metrics = []
        
        for metric_type in UsageMetricType:
            metrics.append({
                'value': metric_type.value,
                'name': metric_type.value.replace('_', ' ').title(),
                'description': get_metric_description(metric_type)
            })
        
        return jsonify({
            'success': True,
            'metrics': metrics
        })
        
    except Exception as e:
        logger.error(f"Error getting available metrics: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@usage_analytics_api.route('/trends', methods=['GET'])
@create_endpoint_limiter('relaxed')
@require_analytics_access
@enforce_quota(UsageMetricType.API_CALLS)
def get_usage_trends():
    """Get usage trend analysis for tenant"""
    try:
        tenant = require_tenant()
        
        # Parse query parameters
        period_days = request.args.get('period_days', 60, type=int)
        metric_type_str = request.args.get('metric_type')
        
        # Parse metric type
        metric_type = None
        if metric_type_str:
            try:
                metric_type = UsageMetricType(metric_type_str)
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid metric_type'}), 400
        
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=period_days)
        
        # Get trend analysis
        trends = usage_analytics.analyze_usage_trends(
            tenant_id=tenant.id,
            metric_type=metric_type,
            start_date=start_date,
            end_date=end_date
        )
        
        return jsonify({
            'success': True,
            'trends': trends,
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat(),
                'days': period_days
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting usage trends: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@usage_analytics_api.route('/summary', methods=['GET'])
@create_endpoint_limiter('relaxed')
@enforce_quota(UsageMetricType.API_CALLS)
def get_usage_summary():
    """Get usage summary for tenant dashboard"""
    try:
        tenant = require_tenant()
        
        # Get current period usage
        current_usage = {}
        quota_status = {}
        alerts = []
        
        if tenant.subscription:
            for metric_type in UsageMetricType:
                quota = tenant.subscription.get_quota(metric_type)
                current = usage_analytics.get_current_usage(tenant.id, metric_type)
                
                if quota is not None:
                    current_usage[metric_type.value] = current
                    percentage = (current / quota * 100) if quota > 0 else 0
                    
                    quota_status[metric_type.value] = {
                        'current': current,
                        'quota': quota,
                        'percentage': round(percentage, 1),
                        'status': get_usage_status(percentage)
                    }
                    
                    # Check for alerts
                    if percentage >= 90:
                        alerts.append({
                            'metric': metric_type.value,
                            'message': f"{metric_type.value.replace('_', ' ').title()} usage at {percentage:.1f}%",
                            'severity': 'critical' if percentage >= 100 else 'warning'
                        })
        
        # Get recent usage trend (last 7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_usage = UsageRecord.query.filter(
            UsageRecord.tenant_id == tenant.id,
            UsageRecord.recorded_at >= week_ago
        ).all()
        
        # Calculate daily usage for the week
        daily_usage = {}
        for record in recent_usage:
            day = record.recorded_at.date().isoformat()
            if day not in daily_usage:
                daily_usage[day] = {}
            
            metric = record.metric_type.value
            if metric not in daily_usage[day]:
                daily_usage[day][metric] = 0
            daily_usage[day][metric] += record.quantity
        
        return jsonify({
            'success': True,
            'summary': {
                'current_usage': current_usage,
                'quota_status': quota_status,
                'alerts': alerts,
                'daily_usage': daily_usage,
                'subscription_plan': {
                    'name': tenant.subscription.plan.name if tenant.subscription else None,
                    'tier': tenant.subscription.plan.tier.value if tenant.subscription else None
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting usage summary: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Usage Recording Endpoints
# ============================================================================

@usage_analytics_api.route('/record-usage', methods=['POST'])
@create_endpoint_limiter('strict')
@enforce_quota(UsageMetricType.API_CALLS)
def record_usage_endpoint():
    """Record usage for current tenant"""
    try:
        tenant = require_tenant()
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400
        
        # Validate required fields
        metric_type_str = data.get('metric_type')
        quantity = data.get('quantity', 1)
        metadata = data.get('metadata', {})
        
        if not metric_type_str:
            return jsonify({'success': False, 'error': 'metric_type required'}), 400
        
        try:
            metric_type = UsageMetricType(metric_type_str)
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid metric_type'}), 400
        
        if not isinstance(quantity, (int, float)) or quantity <= 0:
            return jsonify({'success': False, 'error': 'quantity must be positive number'}), 400
        
        # Record usage
        success = usage_analytics.record_usage(
            tenant_id=tenant.id,
            metric_type=metric_type,
            quantity=float(quantity),
            metadata=metadata
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Usage recorded successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to record usage (quota exceeded?)'
            }), 429
        
    except Exception as e:
        logger.error(f"Error recording usage: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Utility Functions
# ============================================================================

def get_metric_description(metric_type: UsageMetricType) -> str:
    """Get human-readable description for metric type"""
    descriptions = {
        UsageMetricType.DEVICES_MONITORED: "Number of network devices being monitored",
        UsageMetricType.API_CALLS: "Number of API requests made",
        UsageMetricType.DATA_RETENTION_DAYS: "Number of days monitoring data is retained",
        UsageMetricType.ALERTS_PER_MONTH: "Number of alerts generated per month",
        UsageMetricType.USERS_PER_TENANT: "Number of users in the tenant",
        UsageMetricType.STORAGE_GB: "Amount of storage used in gigabytes",
        UsageMetricType.BANDWIDTH_GB: "Amount of bandwidth used in gigabytes",
        UsageMetricType.CUSTOM_INTEGRATIONS: "Number of custom integrations configured"
    }
    
    return descriptions.get(metric_type, "Usage metric")

def get_usage_status(percentage: float) -> str:
    """Get usage status based on percentage"""
    if percentage >= 100:
        return "over_quota"
    elif percentage >= 90:
        return "critical"
    elif percentage >= 75:
        return "warning"
    elif percentage >= 50:
        return "moderate"
    else:
        return "low"