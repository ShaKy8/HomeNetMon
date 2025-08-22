# HomeNetMon SaaS Administration API
from flask import Blueprint, request, jsonify, abort, current_app
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_, desc
from typing import Dict, Any, List, Optional
import logging
from functools import wraps

from tenant_models import *
from tenant_manager import tenant_manager, get_current_tenant
from billing_system import billing_manager
from cloud_config import get_config

logger = logging.getLogger(__name__)

# Create blueprint
saas_admin_api = Blueprint('saas_admin_api', __name__, url_prefix='/api/admin')

# ============================================================================
# Authentication and Authorization
# ============================================================================

def require_admin_auth(f):
    """Require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for admin API key
        api_key = request.headers.get('X-Admin-API-Key')
        admin_api_key = get_config('ADMIN_API_KEY')
        
        if api_key and api_key == admin_api_key:
            return f(*args, **kwargs)
        
        # Check for admin user session
        if current_user.is_authenticated and getattr(current_user, 'is_admin', False):
            return f(*args, **kwargs)
        
        abort(403, description="Admin access required")
    
    return decorated_function

def require_tenant_admin(f):
    """Require tenant admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        tenant = get_current_tenant()
        if not tenant:
            abort(400, description="Tenant context required")
        
        # Check if user is tenant admin
        if hasattr(current_user, 'is_tenant_admin') and current_user.is_tenant_admin:
            return f(*args, **kwargs)
        
        # Check for tenant admin API key
        api_key = request.headers.get('X-Tenant-API-Key')
        if api_key:
            # Validate tenant-specific API key
            # Implementation depends on your API key system
            pass
        
        abort(403, description="Tenant admin access required")
    
    return decorated_function

# ============================================================================
# System-wide Administration
# ============================================================================

@saas_admin_api.route('/system/stats', methods=['GET'])
@require_admin_auth
def get_system_stats():
    """Get system-wide statistics"""
    try:
        # Tenant statistics
        total_tenants = Tenant.query.count()
        active_tenants = Tenant.query.filter_by(status=TenantStatus.ACTIVE).count()
        trial_tenants = Tenant.query.filter_by(status=TenantStatus.TRIAL).count()
        suspended_tenants = Tenant.query.filter_by(status=TenantStatus.SUSPENDED).count()
        
        # Subscription statistics
        total_subscriptions = TenantSubscription.query.count()
        active_subscriptions = TenantSubscription.query.join(Tenant).filter(
            Tenant.status.in_([TenantStatus.ACTIVE, TenantStatus.TRIAL])
        ).count()
        
        # Revenue statistics (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_revenue = db.session.query(func.sum(Invoice.amount_cents)).filter(
            Invoice.status == InvoiceStatus.PAID.value,
            Invoice.paid_at >= thirty_days_ago
        ).scalar() or 0
        
        # Usage statistics
        total_devices = db.session.query(func.sum(
            func.cast(func.json_extract(TenantSubscription.current_usage, f'$.{UsageMetricType.DEVICES_MONITORED.value}'), Integer)
        )).scalar() or 0
        
        total_api_calls = db.session.query(func.sum(
            func.cast(func.json_extract(TenantSubscription.current_usage, f'$.{UsageMetricType.API_CALLS.value}'), Integer)
        )).scalar() or 0
        
        # Plan distribution
        plan_distribution = db.session.query(
            SubscriptionPlan.tier,
            func.count(TenantSubscription.id).label('count')
        ).join(TenantSubscription).group_by(SubscriptionPlan.tier).all()
        
        return jsonify({
            'success': True,
            'stats': {
                'tenants': {
                    'total': total_tenants,
                    'active': active_tenants,
                    'trial': trial_tenants,
                    'suspended': suspended_tenants
                },
                'subscriptions': {
                    'total': total_subscriptions,
                    'active': active_subscriptions
                },
                'revenue': {
                    'last_30_days_cents': recent_revenue,
                    'last_30_days_dollars': recent_revenue / 100
                },
                'usage': {
                    'total_devices_monitored': total_devices,
                    'total_api_calls': total_api_calls
                },
                'plan_distribution': [
                    {'tier': tier.value, 'count': count} 
                    for tier, count in plan_distribution
                ]
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@saas_admin_api.route('/tenants', methods=['GET'])
@require_admin_auth
def list_tenants():
    """List all tenants with filtering and pagination"""
    try:
        # Parse query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)
        status_filter = request.args.get('status')
        search = request.args.get('search')
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        # Build query
        query = Tenant.query
        
        if status_filter:
            query = query.filter(Tenant.status == TenantStatus(status_filter))
        
        if search:
            search_term = f"%{search}%"
            query = query.filter(or_(
                Tenant.name.ilike(search_term),
                Tenant.subdomain.ilike(search_term),
                Tenant.admin_email.ilike(search_term),
                Tenant.company_name.ilike(search_term)
            ))
        
        # Apply sorting
        if hasattr(Tenant, sort_by):
            sort_column = getattr(Tenant, sort_by)
            if sort_order == 'desc':
                sort_column = desc(sort_column)
            query = query.order_by(sort_column)
        
        # Paginate
        result = query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        # Format tenants
        tenants = []
        for tenant in result.items:
            tenant_data = {
                'id': tenant.id,
                'name': tenant.name,
                'subdomain': tenant.subdomain,
                'custom_domain': tenant.custom_domain,
                'admin_email': tenant.admin_email,
                'company_name': tenant.company_name,
                'status': tenant.status.value,
                'created_at': tenant.created_at.isoformat(),
                'trial_ends_at': tenant.trial_ends_at.isoformat() if tenant.trial_ends_at else None,
                'suspended_at': tenant.suspended_at.isoformat() if tenant.suspended_at else None,
                'suspension_reason': tenant.suspension_reason
            }
            
            # Add subscription info
            if tenant.subscription:
                tenant_data['subscription'] = {
                    'plan_name': tenant.subscription.plan.name,
                    'plan_tier': tenant.subscription.plan.tier.value,
                    'current_period_end': tenant.subscription.current_period_end.isoformat(),
                    'is_active': tenant.subscription.is_active,
                    'cancel_at_period_end': tenant.subscription.cancel_at_period_end
                }
            
            tenants.append(tenant_data)
        
        return jsonify({
            'success': True,
            'tenants': tenants,
            'pagination': {
                'page': result.page,
                'per_page': result.per_page,
                'total': result.total,
                'pages': result.pages,
                'has_prev': result.has_prev,
                'has_next': result.has_next
            }
        })
        
    except Exception as e:
        logger.error(f"Error listing tenants: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@saas_admin_api.route('/tenants/<tenant_id>', methods=['GET'])
@require_admin_auth
def get_tenant_details(tenant_id):
    """Get detailed tenant information"""
    try:
        tenant = Tenant.query.get_or_404(tenant_id)
        
        # Get tenant statistics
        with tenant_manager.tenant_context(tenant):
            device_count = TenantDevice.query.count()
            alert_count = TenantAlert.query.filter_by(acknowledged=False).count()
            user_count = TenantUser.query.count()
            
            # Get recent usage
            recent_usage = UsageRecord.query.filter(
                UsageRecord.recorded_at >= datetime.utcnow() - timedelta(days=30)
            ).all()
        
        # Get subscription details
        subscription_data = None
        if tenant.subscription:
            subscription = tenant.subscription
            subscription_data = {
                'id': subscription.id,
                'plan': {
                    'id': subscription.plan.id,
                    'name': subscription.plan.name,
                    'tier': subscription.plan.tier.value,
                    'price_cents': subscription.plan.price_cents,
                    'billing_interval': subscription.plan.billing_interval.value
                },
                'started_at': subscription.started_at.isoformat(),
                'current_period_start': subscription.current_period_start.isoformat(),
                'current_period_end': subscription.current_period_end.isoformat(),
                'is_active': subscription.is_active,
                'cancel_at_period_end': subscription.cancel_at_period_end,
                'current_usage': subscription.current_usage,
                'overage_charges': subscription.overage_charges
            }
        
        # Get recent invoices
        recent_invoices = []
        if tenant.subscription:
            invoices = Invoice.query.filter_by(
                subscription_id=tenant.subscription.id
            ).order_by(desc(Invoice.period_start)).limit(10).all()
            
            recent_invoices = [
                {
                    'id': invoice.id,
                    'invoice_number': invoice.invoice_number,
                    'amount_cents': invoice.amount_cents,
                    'status': invoice.status,
                    'period_start': invoice.period_start.isoformat(),
                    'period_end': invoice.period_end.isoformat(),
                    'due_date': invoice.due_date.isoformat(),
                    'paid_at': invoice.paid_at.isoformat() if invoice.paid_at else None
                }
                for invoice in invoices
            ]
        
        return jsonify({
            'success': True,
            'tenant': {
                'id': tenant.id,
                'name': tenant.name,
                'subdomain': tenant.subdomain,
                'custom_domain': tenant.custom_domain,
                'admin_email': tenant.admin_email,
                'company_name': tenant.company_name,
                'billing_email': tenant.billing_email,
                'phone': tenant.phone,
                'address': {
                    'line1': tenant.address_line1,
                    'line2': tenant.address_line2,
                    'city': tenant.city,
                    'state_province': tenant.state_province,
                    'postal_code': tenant.postal_code,
                    'country': tenant.country
                },
                'status': tenant.status.value,
                'created_at': tenant.created_at.isoformat(),
                'trial_ends_at': tenant.trial_ends_at.isoformat() if tenant.trial_ends_at else None,
                'suspended_at': tenant.suspended_at.isoformat() if tenant.suspended_at else None,
                'suspension_reason': tenant.suspension_reason,
                'settings': tenant.settings,
                'feature_flags': tenant.feature_flags,
                'statistics': {
                    'device_count': device_count,
                    'alert_count': alert_count,
                    'user_count': user_count
                },
                'subscription': subscription_data,
                'recent_invoices': recent_invoices,
                'recent_usage': [
                    {
                        'metric_type': usage.metric_type.value,
                        'quantity': usage.quantity,
                        'recorded_at': usage.recorded_at.isoformat()
                    }
                    for usage in recent_usage
                ]
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting tenant details: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@saas_admin_api.route('/tenants/<tenant_id>/suspend', methods=['POST'])
@require_admin_auth
def suspend_tenant(tenant_id):
    """Suspend a tenant"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'Administrative action')
        
        tenant = Tenant.query.get_or_404(tenant_id)
        tenant_manager.suspend_tenant(tenant, reason)
        
        return jsonify({
            'success': True,
            'message': f'Tenant {tenant.name} suspended',
            'reason': reason
        })
        
    except Exception as e:
        logger.error(f"Error suspending tenant: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@saas_admin_api.route('/tenants/<tenant_id>/reactivate', methods=['POST'])
@require_admin_auth
def reactivate_tenant(tenant_id):
    """Reactivate a suspended tenant"""
    try:
        tenant = Tenant.query.get_or_404(tenant_id)
        tenant_manager.reactivate_tenant(tenant)
        
        return jsonify({
            'success': True,
            'message': f'Tenant {tenant.name} reactivated'
        })
        
    except Exception as e:
        logger.error(f"Error reactivating tenant: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@saas_admin_api.route('/tenants/<tenant_id>', methods=['DELETE'])
@require_admin_auth
def delete_tenant(tenant_id):
    """Delete a tenant"""
    try:
        data = request.get_json() or {}
        hard_delete = data.get('hard_delete', False)
        
        tenant = Tenant.query.get_or_404(tenant_id)
        tenant_manager.delete_tenant(tenant, hard_delete=hard_delete)
        
        return jsonify({
            'success': True,
            'message': f'Tenant {tenant.name} {"hard" if hard_delete else "soft"} deleted'
        })
        
    except Exception as e:
        logger.error(f"Error deleting tenant: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Subscription Management
# ============================================================================

@saas_admin_api.route('/plans', methods=['GET'])
@require_admin_auth
def list_subscription_plans():
    """List all subscription plans"""
    try:
        plans = SubscriptionPlan.query.filter_by(is_active=True).all()
        
        plan_list = []
        for plan in plans:
            plan_data = {
                'id': plan.id,
                'name': plan.name,
                'tier': plan.tier.value,
                'billing_interval': plan.billing_interval.value,
                'price_cents': plan.price_cents,
                'price_dollars': plan.price_dollars,
                'currency': plan.currency,
                'quotas': plan.quotas,
                'features': plan.features,
                'description': plan.description,
                'is_active': plan.is_active,
                'created_at': plan.created_at.isoformat(),
                'subscriber_count': len(plan.subscriptions)
            }
            plan_list.append(plan_data)
        
        return jsonify({
            'success': True,
            'plans': plan_list
        })
        
    except Exception as e:
        logger.error(f"Error listing plans: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@saas_admin_api.route('/plans', methods=['POST'])
@require_admin_auth
def create_subscription_plan():
    """Create a new subscription plan"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'tier', 'billing_interval', 'price_cents', 'quotas', 'features']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400
        
        plan = billing_manager.create_subscription_plan(
            name=data['name'],
            tier=SubscriptionTier(data['tier']),
            billing_interval=BillingInterval(data['billing_interval']),
            price_cents=data['price_cents'],
            quotas=data['quotas'],
            features=data['features'],
            description=data.get('description')
        )
        
        return jsonify({
            'success': True,
            'plan': {
                'id': plan.id,
                'name': plan.name,
                'tier': plan.tier.value,
                'price_cents': plan.price_cents
            }
        })
        
    except Exception as e:
        logger.error(f"Error creating plan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@saas_admin_api.route('/tenants/<tenant_id>/subscription', methods=['PUT'])
@require_admin_auth
def update_tenant_subscription():
    """Update tenant subscription"""
    try:
        data = request.get_json()
        tenant_id = data.get('tenant_id')
        new_plan_id = data.get('plan_id')
        
        tenant = Tenant.query.get_or_404(tenant_id)
        new_plan = SubscriptionPlan.query.get_or_404(new_plan_id)
        
        if tenant.subscription:
            billing_manager.upgrade_subscription(tenant.subscription, new_plan)
        else:
            billing_manager.create_subscription(tenant, new_plan)
        
        return jsonify({
            'success': True,
            'message': f'Updated subscription to {new_plan.name}'
        })
        
    except Exception as e:
        logger.error(f"Error updating subscription: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Usage Analytics and Monitoring
# ============================================================================

@saas_admin_api.route('/analytics/usage', methods=['GET'])
@require_admin_auth
def get_usage_analytics():
    """Get system-wide usage analytics"""
    try:
        # Parse query parameters
        days = request.args.get('days', 30, type=int)
        metric_type = request.args.get('metric_type')
        
        since = datetime.utcnow() - timedelta(days=days)
        
        # Build query
        query = UsageRecord.query.filter(UsageRecord.recorded_at >= since)
        
        if metric_type:
            query = query.filter(UsageRecord.metric_type == UsageMetricType(metric_type))
        
        usage_records = query.all()
        
        # Aggregate usage by metric type and date
        usage_by_date = {}
        usage_by_metric = {}
        
        for record in usage_records:
            date_key = record.recorded_at.date().isoformat()
            metric_key = record.metric_type.value
            
            if date_key not in usage_by_date:
                usage_by_date[date_key] = {}
            
            if metric_key not in usage_by_date[date_key]:
                usage_by_date[date_key][metric_key] = 0
            
            usage_by_date[date_key][metric_key] += record.quantity
            
            if metric_key not in usage_by_metric:
                usage_by_metric[metric_key] = 0
            
            usage_by_metric[metric_key] += record.quantity
        
        return jsonify({
            'success': True,
            'analytics': {
                'period_days': days,
                'usage_by_date': usage_by_date,
                'usage_by_metric': usage_by_metric,
                'total_records': len(usage_records)
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting usage analytics: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@saas_admin_api.route('/analytics/revenue', methods=['GET'])
@require_admin_auth
def get_revenue_analytics():
    """Get revenue analytics"""
    try:
        # Parse query parameters
        days = request.args.get('days', 90, type=int)
        
        since = datetime.utcnow() - timedelta(days=days)
        
        # Get paid invoices
        invoices = Invoice.query.filter(
            Invoice.status == InvoiceStatus.PAID.value,
            Invoice.paid_at >= since
        ).all()
        
        # Aggregate revenue by date and plan
        revenue_by_date = {}
        revenue_by_plan = {}
        total_revenue = 0
        
        for invoice in invoices:
            date_key = invoice.paid_at.date().isoformat()
            plan_name = invoice.subscription.plan.name
            amount = invoice.amount_cents
            
            if date_key not in revenue_by_date:
                revenue_by_date[date_key] = 0
            
            revenue_by_date[date_key] += amount
            
            if plan_name not in revenue_by_plan:
                revenue_by_plan[plan_name] = 0
            
            revenue_by_plan[plan_name] += amount
            total_revenue += amount
        
        # Calculate growth rate
        mid_point = since + timedelta(days=days//2)
        first_half_revenue = sum(
            invoice.amount_cents for invoice in invoices
            if invoice.paid_at < mid_point
        )
        second_half_revenue = sum(
            invoice.amount_cents for invoice in invoices
            if invoice.paid_at >= mid_point
        )
        
        growth_rate = 0
        if first_half_revenue > 0:
            growth_rate = ((second_half_revenue - first_half_revenue) / first_half_revenue) * 100
        
        return jsonify({
            'success': True,
            'analytics': {
                'period_days': days,
                'total_revenue_cents': total_revenue,
                'total_revenue_dollars': total_revenue / 100,
                'revenue_by_date': {k: v/100 for k, v in revenue_by_date.items()},
                'revenue_by_plan': {k: v/100 for k, v in revenue_by_plan.items()},
                'growth_rate_percent': round(growth_rate, 2),
                'invoice_count': len(invoices)
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting revenue analytics: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Tenant-specific Administration
# ============================================================================

@saas_admin_api.route('/tenant/profile', methods=['GET'])
@require_tenant_admin
def get_tenant_profile():
    """Get current tenant profile information"""
    try:
        tenant = get_current_tenant()
        
        return jsonify({
            'success': True,
            'tenant': {
                'id': tenant.id,
                'name': tenant.name,
                'subdomain': tenant.subdomain,
                'custom_domain': tenant.custom_domain,
                'admin_email': tenant.admin_email,
                'company_name': tenant.company_name,
                'billing_email': tenant.billing_email,
                'phone': tenant.phone,
                'status': tenant.status.value,
                'created_at': tenant.created_at.isoformat(),
                'settings': tenant.settings,
                'branding': tenant.branding
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting tenant profile: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@saas_admin_api.route('/tenant/profile', methods=['PUT'])
@require_tenant_admin
def update_tenant_profile():
    """Update current tenant profile"""
    try:
        tenant = get_current_tenant()
        data = request.get_json()
        
        # Update allowed fields
        allowed_fields = [
            'name', 'company_name', 'billing_email', 'phone',
            'address_line1', 'address_line2', 'city', 'state_province',
            'postal_code', 'country'
        ]
        
        updates = {}
        for field in allowed_fields:
            if field in data:
                updates[field] = data[field]
        
        if updates:
            tenant_manager.update_tenant(tenant, **updates)
        
        return jsonify({
            'success': True,
            'message': 'Tenant profile updated successfully'
        })
        
    except Exception as e:
        logger.error(f"Error updating tenant profile: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@saas_admin_api.route('/tenant/subscription', methods=['GET'])
@require_tenant_admin
def get_tenant_subscription():
    """Get current tenant subscription details"""
    try:
        tenant = get_current_tenant()
        
        if not tenant.subscription:
            return jsonify({
                'success': True,
                'subscription': None
            })
        
        subscription = tenant.subscription
        
        return jsonify({
            'success': True,
            'subscription': {
                'id': subscription.id,
                'plan': {
                    'id': subscription.plan.id,
                    'name': subscription.plan.name,
                    'tier': subscription.plan.tier.value,
                    'price_cents': subscription.plan.price_cents,
                    'price_dollars': subscription.plan.price_dollars,
                    'billing_interval': subscription.plan.billing_interval.value,
                    'quotas': subscription.plan.quotas,
                    'features': subscription.plan.features
                },
                'current_period_start': subscription.current_period_start.isoformat(),
                'current_period_end': subscription.current_period_end.isoformat(),
                'days_until_renewal': subscription.days_until_renewal,
                'cancel_at_period_end': subscription.cancel_at_period_end,
                'current_usage': subscription.current_usage,
                'overage_charges': subscription.overage_charges
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting tenant subscription: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@saas_admin_api.route('/tenant/usage', methods=['GET'])
@require_tenant_admin
def get_tenant_usage():
    """Get current tenant usage statistics"""
    try:
        tenant = get_current_tenant()
        days = request.args.get('days', 30, type=int)
        
        # Get usage records
        since = datetime.utcnow() - timedelta(days=days)
        usage_records = UsageRecord.query.filter(
            UsageRecord.tenant_id == tenant.id,
            UsageRecord.recorded_at >= since
        ).all()
        
        # Aggregate usage
        usage_by_metric = {}
        usage_over_time = {}
        
        for record in usage_records:
            metric = record.metric_type.value
            date_key = record.recorded_at.date().isoformat()
            
            if metric not in usage_by_metric:
                usage_by_metric[metric] = 0
            usage_by_metric[metric] += record.quantity
            
            if date_key not in usage_over_time:
                usage_over_time[date_key] = {}
            if metric not in usage_over_time[date_key]:
                usage_over_time[date_key][metric] = 0
            usage_over_time[date_key][metric] += record.quantity
        
        # Get quota information
        quotas = {}
        quota_usage = {}
        if tenant.subscription:
            for metric_type in UsageMetricType:
                quota = tenant.subscription.get_quota(metric_type)
                current_usage = tenant.subscription.get_current_usage(metric_type)
                
                quotas[metric_type.value] = quota
                quota_usage[metric_type.value] = {
                    'quota': quota,
                    'used': current_usage,
                    'percentage': round((current_usage / quota * 100) if quota else 0, 1),
                    'over_quota': current_usage > quota if quota else False
                }
        
        return jsonify({
            'success': True,
            'usage': {
                'period_days': days,
                'usage_by_metric': usage_by_metric,
                'usage_over_time': usage_over_time,
                'quota_usage': quota_usage,
                'quotas': quotas
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting tenant usage: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@saas_admin_api.route('/tenant/invoices', methods=['GET'])
@require_tenant_admin
def get_tenant_invoices():
    """Get tenant invoices"""
    try:
        tenant = get_current_tenant()
        
        if not tenant.subscription:
            return jsonify({
                'success': True,
                'invoices': []
            })
        
        # Get invoices
        invoices = Invoice.query.filter_by(
            subscription_id=tenant.subscription.id
        ).order_by(desc(Invoice.period_start)).all()
        
        invoice_list = []
        for invoice in invoices:
            invoice_data = {
                'id': invoice.id,
                'invoice_number': invoice.invoice_number,
                'amount_cents': invoice.amount_cents,
                'amount_dollars': invoice.amount_dollars,
                'currency': invoice.currency,
                'status': invoice.status,
                'period_start': invoice.period_start.isoformat(),
                'period_end': invoice.period_end.isoformat(),
                'due_date': invoice.due_date.isoformat(),
                'paid_at': invoice.paid_at.isoformat() if invoice.paid_at else None,
                'is_overdue': invoice.is_overdue,
                'line_items': invoice.line_items
            }
            invoice_list.append(invoice_data)
        
        return jsonify({
            'success': True,
            'invoices': invoice_list
        })
        
    except Exception as e:
        logger.error(f"Error getting tenant invoices: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Webhooks
# ============================================================================

@saas_admin_api.route('/webhooks/stripe', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhooks"""
    try:
        payload = request.get_data()
        sig_header = request.headers.get('Stripe-Signature')
        
        # Verify webhook signature
        webhook_secret = get_config('STRIPE_WEBHOOK_SECRET')
        if webhook_secret:
            try:
                event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
            except ValueError:
                return jsonify({'error': 'Invalid payload'}), 400
            except stripe.error.SignatureVerificationError:
                return jsonify({'error': 'Invalid signature'}), 400
        else:
            # For development/testing without signature verification
            event = json.loads(payload)
        
        # Handle the event
        result = billing_manager.handle_stripe_webhook(event)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Stripe webhook error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500