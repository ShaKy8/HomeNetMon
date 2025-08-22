# HomeNetMon Performance Dashboard
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from datetime import datetime, timedelta
import logging

from performance.metrics_collector import metrics_collector
from performance.cache_manager import cache_manager
from performance.circuit_breaker import circuit_breaker_manager
from performance.load_balancing import load_balancer_manager

logger = logging.getLogger(__name__)

# Create blueprint for performance dashboard
performance_bp = Blueprint('performance', __name__, url_prefix='/performance')

@performance_bp.route('/', methods=['GET'])
@login_required
def performance_dashboard():
    """Main performance dashboard"""
    try:
        # Get recent performance summary
        health_status = metrics_collector.get_health_status()
        
        return render_template('performance/dashboard.html',
                             health_status=health_status,
                             page_title='Performance Dashboard')
        
    except Exception as e:
        logger.error(f"Error rendering performance dashboard: {e}")
        return render_template('error.html', 
                             error="Failed to load performance dashboard"), 500

@performance_bp.route('/metrics', methods=['GET'])
@login_required
def metrics_overview():
    """Detailed metrics overview"""
    try:
        minutes = request.args.get('minutes', 60, type=int)
        
        # Get all metrics
        system_metrics = metrics_collector.get_system_metrics(minutes)
        app_metrics = metrics_collector.get_application_metrics(minutes)
        endpoint_metrics = metrics_collector.get_endpoint_metrics()
        
        return render_template('performance/metrics.html',
                             system_metrics=system_metrics,
                             app_metrics=app_metrics,
                             endpoint_metrics=endpoint_metrics,
                             minutes=minutes,
                             page_title='Performance Metrics')
        
    except Exception as e:
        logger.error(f"Error rendering metrics overview: {e}")
        return render_template('error.html', 
                             error="Failed to load metrics"), 500

@performance_bp.route('/cache', methods=['GET'])
@login_required
def cache_dashboard():
    """Cache performance dashboard"""
    try:
        cache_metrics = cache_manager.cache.get_metrics()
        
        return render_template('performance/cache.html',
                             cache_metrics=cache_metrics,
                             page_title='Cache Performance')
        
    except Exception as e:
        logger.error(f"Error rendering cache dashboard: {e}")
        return render_template('error.html', 
                             error="Failed to load cache dashboard"), 500

@performance_bp.route('/circuit-breakers', methods=['GET'])
@login_required
def circuit_breakers_dashboard():
    """Circuit breakers dashboard"""
    try:
        cb_metrics = circuit_breaker_manager.get_all_metrics()
        
        return render_template('performance/circuit_breakers.html',
                             circuit_breakers=cb_metrics,
                             page_title='Circuit Breakers')
        
    except Exception as e:
        logger.error(f"Error rendering circuit breakers dashboard: {e}")
        return render_template('error.html', 
                             error="Failed to load circuit breakers dashboard"), 500

@performance_bp.route('/load-balancers', methods=['GET'])
@login_required
def load_balancers_dashboard():
    """Load balancers dashboard"""
    try:
        lb_stats = load_balancer_manager.get_all_stats()
        
        return render_template('performance/load_balancers.html',
                             load_balancers=lb_stats,
                             page_title='Load Balancers')
        
    except Exception as e:
        logger.error(f"Error rendering load balancers dashboard: {e}")
        return render_template('error.html', 
                             error="Failed to load load balancers dashboard"), 500

# API endpoints for real-time data

@performance_bp.route('/api/health', methods=['GET'])
@login_required
def api_health():
    """Get current health status"""
    return jsonify(metrics_collector.get_health_status())

@performance_bp.route('/api/metrics/system', methods=['GET'])
@login_required
def api_system_metrics():
    """Get system metrics"""
    minutes = request.args.get('minutes', 60, type=int)
    return jsonify({
        'metrics': metrics_collector.get_system_metrics(minutes),
        'timestamp': datetime.utcnow().isoformat()
    })

@performance_bp.route('/api/metrics/application', methods=['GET'])
@login_required
def api_application_metrics():
    """Get application metrics"""
    minutes = request.args.get('minutes', 60, type=int)
    return jsonify({
        'metrics': metrics_collector.get_application_metrics(minutes),
        'timestamp': datetime.utcnow().isoformat()
    })

@performance_bp.route('/api/metrics/endpoints', methods=['GET'])
@login_required
def api_endpoint_metrics():
    """Get endpoint metrics"""
    return jsonify({
        'metrics': metrics_collector.get_endpoint_metrics(),
        'timestamp': datetime.utcnow().isoformat()
    })

@performance_bp.route('/api/cache/metrics', methods=['GET'])
@login_required
def api_cache_metrics():
    """Get cache metrics"""
    return jsonify({
        'metrics': cache_manager.cache.get_metrics(),
        'timestamp': datetime.utcnow().isoformat()
    })

@performance_bp.route('/api/cache/clear', methods=['POST'])
@login_required
def api_cache_clear():
    """Clear cache"""
    try:
        tenant_id = request.json.get('tenant_id') if request.is_json else None
        cache_manager.cache.clear(tenant_id)
        return jsonify({'success': True, 'message': 'Cache cleared successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@performance_bp.route('/api/circuit-breakers/metrics', methods=['GET'])
@login_required
def api_circuit_breaker_metrics():
    """Get circuit breaker metrics"""
    return jsonify({
        'circuit_breakers': circuit_breaker_manager.get_all_metrics(),
        'timestamp': datetime.utcnow().isoformat()
    })

@performance_bp.route('/api/circuit-breakers/reset', methods=['POST'])
@login_required
def api_circuit_breaker_reset():
    """Reset circuit breakers"""
    try:
        if request.is_json and 'name' in request.json:
            # Reset specific circuit breaker
            name = request.json['name']
            cb = circuit_breaker_manager.get_circuit_breaker(name)
            cb.reset()
            return jsonify({'success': True, 'message': f'Circuit breaker {name} reset'})
        else:
            # Reset all circuit breakers
            circuit_breaker_manager.reset_all()
            return jsonify({'success': True, 'message': 'All circuit breakers reset'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@performance_bp.route('/api/load-balancers/stats', methods=['GET'])
@login_required
def api_load_balancer_stats():
    """Get load balancer statistics"""
    return jsonify({
        'load_balancers': load_balancer_manager.get_all_stats(),
        'timestamp': datetime.utcnow().isoformat()
    })

# Real-time updates endpoint
@performance_bp.route('/api/realtime/summary', methods=['GET'])
@login_required
def api_realtime_summary():
    """Get real-time performance summary"""
    try:
        health_status = metrics_collector.get_health_status()
        
        # Get latest metrics
        latest_system = None
        latest_app = None
        
        if metrics_collector.system_metrics:
            latest_system = metrics_collector.system_metrics[-1]
        
        if metrics_collector.application_metrics:
            latest_app = metrics_collector.application_metrics[-1]
        
        # Get cache hit rate
        cache_hit_rate = 0.0
        try:
            cache_metrics = cache_manager.cache.get_metrics()
            if 'l1_memory' in cache_metrics:
                cache_hit_rate = cache_metrics['l1_memory'].hit_rate
        except Exception:
            pass
        
        # Count circuit breaker states
        cb_metrics = circuit_breaker_manager.get_all_metrics()
        cb_summary = {
            'total': len(cb_metrics),
            'closed': len([cb for cb in cb_metrics.values() if cb['state'] == 'closed']),
            'open': len([cb for cb in cb_metrics.values() if cb['state'] == 'open']),
            'half_open': len([cb for cb in cb_metrics.values() if cb['state'] == 'half_open'])
        }
        
        return jsonify({
            'health': health_status,
            'system': {
                'cpu_percent': latest_system.cpu_percent if latest_system else 0,
                'memory_percent': latest_system.memory_percent if latest_system else 0,
                'load_average': latest_system.load_average if latest_system else [0, 0, 0]
            },
            'application': {
                'request_rate': latest_app.request_rate if latest_app else 0,
                'response_time_avg': latest_app.response_time_avg if latest_app else 0,
                'error_rate': latest_app.error_rate if latest_app else 0,
                'active_connections': latest_app.active_connections if latest_app else 0
            },
            'cache': {
                'hit_rate': cache_hit_rate
            },
            'circuit_breakers': cb_summary,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Real-time summary error: {e}")
        return jsonify({'error': str(e)}), 500