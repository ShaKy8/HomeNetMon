"""
Performance Optimization API for HomeNetMon
Provides endpoints for monitoring and managing performance optimizations.
"""
from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

performance_optimization_bp = Blueprint('performance_optimization', __name__, url_prefix='/api/performance')

@performance_optimization_bp.route('/cache/stats', methods=['GET'])
def get_cache_stats():
    """Get performance cache statistics"""
    try:
        from services.performance_cache import get_cache_performance_metrics
        metrics = get_cache_performance_metrics()
        return jsonify(metrics)
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        return jsonify({'error': str(e)}), 500

@performance_optimization_bp.route('/memory/stats', methods=['GET'])
def get_memory_stats():
    """Get memory usage statistics"""
    try:
        from services.memory_monitor import get_memory_stats, memory_monitor
        
        current_stats = get_memory_stats()
        trend_data = memory_monitor.get_memory_trend(30)  # Last 30 minutes
        cleanup_stats = memory_monitor.get_cleanup_statistics()
        
        return jsonify({
            'current': {
                'total_mb': current_stats.total_mb,
                'used_mb': current_stats.used_mb,
                'available_mb': current_stats.available_mb,
                'percent_used': current_stats.percent_used * 100,
                'cache_usage_mb': current_stats.cache_usage_mb,
                'gc_collections': current_stats.gc_collections,
                'objects_tracked': current_stats.objects_tracked
            },
            'trend': trend_data,
            'cleanup': cleanup_stats,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
    except Exception as e:
        logger.error(f"Error getting memory stats: {e}")
        return jsonify({'error': str(e)}), 500

@performance_optimization_bp.route('/threads/stats', methods=['GET'])
def get_thread_stats():
    """Get thread pool statistics"""
    try:
        from services.thread_pool_manager import thread_pool_manager
        
        all_stats = thread_pool_manager.get_all_stats()
        system_resources = thread_pool_manager.get_system_resource_summary()
        
        return jsonify({
            'thread_pools': all_stats,
            'system_resources': system_resources,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
    except Exception as e:
        logger.error(f"Error getting thread stats: {e}")
        return jsonify({'error': str(e)}), 500

@performance_optimization_bp.route('/websocket/stats', methods=['GET'])
def get_websocket_stats():
    """Get WebSocket optimizer statistics"""
    try:
        from services.websocket_optimizer import websocket_optimizer
        
        if websocket_optimizer:
            stats = websocket_optimizer.get_batch_update_summary()
            return jsonify({
                'optimizer_stats': stats,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
        else:
            return jsonify({
                'error': 'WebSocket optimizer not available',
                'optimizer_stats': {},
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
    except Exception as e:
        logger.error(f"Error getting WebSocket stats: {e}")
        return jsonify({'error': str(e)}), 500

@performance_optimization_bp.route('/resources/stats', methods=['GET'])
def get_resource_stats():
    """Get frontend resource optimization statistics"""
    try:
        from services.resource_optimizer import get_resource_bundle_info
        
        bundle_info = get_resource_bundle_info()
        return jsonify({
            'bundles': bundle_info,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
    except Exception as e:
        logger.error(f"Error getting resource stats: {e}")
        return jsonify({'error': str(e)}), 500

@performance_optimization_bp.route('/overview', methods=['GET'])
def get_performance_overview():
    """Get comprehensive performance overview"""
    try:
        # Gather all performance metrics
        from services.performance_cache import get_cache_performance_metrics
        from services.memory_monitor import get_memory_stats, memory_monitor
        from services.thread_pool_manager import thread_pool_manager
        from services.websocket_optimizer import websocket_optimizer
        from services.resource_optimizer import get_resource_bundle_info
        
        # Cache metrics
        try:
            cache_metrics = get_cache_performance_metrics()
        except:
            cache_metrics = {'error': 'Cache metrics unavailable'}
        
        # Memory metrics
        try:
            memory_stats = get_memory_stats()
            memory_data = {
                'used_mb': memory_stats.used_mb,
                'percent_used': memory_stats.percent_used * 100,
                'cache_usage_mb': memory_stats.cache_usage_mb,
                'gc_collections': memory_stats.gc_collections
            }
        except:
            memory_data = {'error': 'Memory metrics unavailable'}
        
        # Thread pool metrics
        try:
            thread_stats = thread_pool_manager.get_all_stats()
            system_resources = thread_pool_manager.get_system_resource_summary()
        except:
            thread_stats = {}
            system_resources = {'error': 'Thread metrics unavailable'}
        
        # WebSocket metrics
        try:
            ws_stats = websocket_optimizer.get_batch_update_summary() if websocket_optimizer else {}
        except:
            ws_stats = {'error': 'WebSocket metrics unavailable'}
        
        # Resource bundle metrics
        try:
            resource_stats = get_resource_bundle_info()
        except:
            resource_stats = {'error': 'Resource metrics unavailable'}
        
        # Calculate overall performance score
        performance_score = calculate_performance_score({
            'cache': cache_metrics,
            'memory': memory_data,
            'system': system_resources,
            'threads': thread_stats
        })
        
        return jsonify({
            'performance_score': performance_score,
            'cache': cache_metrics,
            'memory': memory_data,
            'threads': thread_stats,
            'system': system_resources,
            'websocket': ws_stats,
            'resources': resource_stats,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'optimizations_active': {
                'property_caching': 'cache' in cache_metrics and not cache_metrics.get('error'),
                'n1_query_optimization': 'optimizer_stats' in ws_stats,
                'thread_pool_management': len(thread_stats) > 0,
                'memory_monitoring': not memory_data.get('error'),
                'resource_bundling': not resource_stats.get('error')
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting performance overview: {e}")
        return jsonify({'error': str(e)}), 500

@performance_optimization_bp.route('/cache/clear', methods=['POST'])
def clear_cache():
    """Clear performance cache"""
    try:
        from services.performance_cache import performance_cache
        
        cache_type = request.json.get('type', 'all') if request.json else 'all'
        
        if cache_type == 'all':
            performance_cache.clear()
            message = "Cleared entire performance cache"
        else:
            # Clear specific patterns
            performance_cache.invalidate(pattern=cache_type)
            message = f"Cleared cache entries matching pattern: {cache_type}"
        
        return jsonify({
            'success': True,
            'message': message,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        return jsonify({'error': str(e)}), 500

@performance_optimization_bp.route('/memory/cleanup', methods=['POST'])
def trigger_memory_cleanup():
    """Trigger manual memory cleanup"""
    try:
        from services.memory_monitor import memory_monitor
        
        severity = request.json.get('severity', 'normal') if request.json else 'normal'
        
        # Trigger cleanup
        memory_monitor.force_cleanup(severity)
        
        return jsonify({
            'success': True,
            'message': f'Triggered {severity} memory cleanup',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        logger.error(f"Error triggering memory cleanup: {e}")
        return jsonify({'error': str(e)}), 500

@performance_optimization_bp.route('/threads/optimize', methods=['POST'])
def optimize_thread_pools():
    """Optimize thread pool configurations"""
    try:
        from services.thread_pool_manager import thread_pool_manager
        
        # Trigger thread pool optimization
        thread_pool_manager.optimize_pools_for_workload()
        
        return jsonify({
            'success': True,
            'message': 'Optimized thread pool configurations',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        logger.error(f"Error optimizing thread pools: {e}")
        return jsonify({'error': str(e)}), 500

@performance_optimization_bp.route('/resources/rebuild', methods=['POST'])
def rebuild_resource_bundles():
    """Rebuild frontend resource bundles"""
    try:
        from services.resource_optimizer import resource_bundler
        
        if resource_bundler:
            # Preload bundles to rebuild them
            resource_bundler.preload_bundles()
            
            return jsonify({
                'success': True,
                'message': 'Rebuilt resource bundles',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Resource bundler not available'
            }), 500
        
    except Exception as e:
        logger.error(f"Error rebuilding resource bundles: {e}")
        return jsonify({'error': str(e)}), 500

def calculate_performance_score(metrics: dict) -> dict:
    """Calculate overall performance score based on metrics"""
    try:
        score = 100
        factors = []
        
        # Cache performance (weight: 20%)
        cache_metrics = metrics.get('cache', {})
        if not cache_metrics.get('error') and 'cache' in cache_metrics:
            cache_hit_rate = cache_metrics['cache'].get('hit_rate', 0)
            if cache_hit_rate < 0.7:
                score -= 15
                factors.append(f"Low cache hit rate: {cache_hit_rate:.1%}")
            elif cache_hit_rate >= 0.9:
                factors.append(f"Excellent cache hit rate: {cache_hit_rate:.1%}")
        
        # Memory usage (weight: 25%)
        memory_data = metrics.get('memory', {})
        if not memory_data.get('error'):
            memory_usage = memory_data.get('percent_used', 0)
            if memory_usage > 85:
                score -= 20
                factors.append(f"High memory usage: {memory_usage:.1f}%")
            elif memory_usage > 75:
                score -= 10
                factors.append(f"Moderate memory usage: {memory_usage:.1f}%")
        
        # System resources (weight: 25%)
        system_data = metrics.get('system', {})
        if not system_data.get('error'):
            cpu_usage = system_data.get('cpu_usage_percent', 0)
            if cpu_usage > 80:
                score -= 15
                factors.append(f"High CPU usage: {cpu_usage:.1f}%")
            elif cpu_usage > 60:
                score -= 8
                factors.append(f"Moderate CPU usage: {cpu_usage:.1f}%")
        
        # Thread pool efficiency (weight: 20%)
        thread_data = metrics.get('threads', {})
        if thread_data and not isinstance(thread_data, dict) or not thread_data.get('error'):
            total_active = sum(stats.active_threads for stats in thread_data.values() if hasattr(stats, 'active_threads'))
            total_pools = len(thread_data)
            if total_pools > 0:
                avg_active_per_pool = total_active / total_pools
                if avg_active_per_pool > 8:
                    score -= 10
                    factors.append(f"High thread pool utilization: {avg_active_per_pool:.1f} avg active threads")
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        # Determine grade
        if score >= 95:
            grade = 'A+'
        elif score >= 90:
            grade = 'A'
        elif score >= 85:
            grade = 'B+'
        elif score >= 80:
            grade = 'B'
        elif score >= 75:
            grade = 'C+'
        elif score >= 70:
            grade = 'C'
        elif score >= 60:
            grade = 'D'
        else:
            grade = 'F'
        
        return {
            'score': score,
            'grade': grade,
            'factors': factors,
            'status': 'excellent' if score >= 90 else 'good' if score >= 75 else 'fair' if score >= 60 else 'poor'
        }
        
    except Exception as e:
        logger.error(f"Error calculating performance score: {e}")
        return {
            'score': 0,
            'grade': 'N/A',
            'factors': [f"Error calculating score: {e}"],
            'status': 'unknown'
        }