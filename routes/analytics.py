# HomeNetMon Analytics Routes
from flask import Blueprint, render_template, request, redirect, url_for, flash
from datetime import datetime, timedelta
from tenant_manager import get_current_tenant, require_tenant
from usage_analytics import usage_analytics
import logging

logger = logging.getLogger(__name__)

# Create blueprint for analytics routes
analytics_routes = Blueprint('analytics_routes', __name__, url_prefix='/analytics')

@analytics_routes.route('/', methods=['GET'])
def analytics_dashboard():
    """Main analytics dashboard"""
    try:
        tenant = get_current_tenant()
        if not tenant:
            flash('Please select a tenant to view analytics', 'warning')
            return redirect(url_for('main.index'))
        
        # Check if tenant has analytics access
        has_analytics = True
        if tenant.subscription:
            has_analytics = tenant.subscription.plan.has_feature('advanced_analytics')
        
        return render_template('analytics/usage_dashboard.html', 
                             tenant=tenant,
                             has_analytics=has_analytics)
        
    except Exception as e:
        logger.error(f"Error rendering analytics dashboard: {e}")
        flash('Error loading analytics dashboard', 'error')
        return redirect(url_for('main.index'))

@analytics_routes.route('/usage', methods=['GET'])
def usage_analytics_page():
    """Usage analytics page"""
    try:
        tenant = require_tenant()
        
        # Check analytics access
        if tenant.subscription and not tenant.subscription.plan.has_feature('advanced_analytics'):
            flash('Advanced analytics not available in your plan', 'warning')
            return redirect(url_for('analytics_routes.analytics_dashboard'))
        
        return render_template('analytics/usage_dashboard.html', 
                             tenant=tenant,
                             page_title='Usage Analytics')
        
    except Exception as e:
        logger.error(f"Error rendering usage analytics page: {e}")
        flash('Error loading usage analytics', 'error')
        return redirect(url_for('main.index'))

@analytics_routes.route('/quotas', methods=['GET'])
def quota_management():
    """Quota management page"""
    try:
        tenant = require_tenant()
        
        # Get current quota status
        quota_status = usage_analytics.get_tenant_quotas(tenant.id)
        
        return render_template('analytics/quota_management.html', 
                             tenant=tenant,
                             quota_status=quota_status,
                             page_title='Quota Management')
        
    except Exception as e:
        logger.error(f"Error rendering quota management page: {e}")
        flash('Error loading quota management', 'error')
        return redirect(url_for('analytics_routes.analytics_dashboard'))

@analytics_routes.route('/reports', methods=['GET'])
def usage_reports():
    """Usage reports page"""
    try:
        tenant = require_tenant()
        
        # Get recent usage summary
        recent_usage = {}
        if tenant.subscription:
            week_ago = datetime.utcnow() - timedelta(days=7)
            
            # This would be implemented with actual report generation
            recent_usage = {
                'period': 'Last 7 days',
                'metrics': []
            }
        
        return render_template('analytics/usage_reports.html', 
                             tenant=tenant,
                             recent_usage=recent_usage,
                             page_title='Usage Reports')
        
    except Exception as e:
        logger.error(f"Error rendering usage reports page: {e}")
        flash('Error loading usage reports', 'error')
        return redirect(url_for('analytics_routes.analytics_dashboard'))