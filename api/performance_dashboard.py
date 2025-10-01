"""
Performance monitoring dashboard API endpoints.
"""

import logging
from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
from core.query_profiler import global_profiler
from core.cache_layer import get_cache_health, global_cache
from core.db_config import ConnectionPoolMonitor, DatabaseOptimizer
from models import db
import psutil
import os
from api.rate_limited_endpoints import create_endpoint_limiter

logger = logging.getLogger(__name__)

performance_dashboard_bp = Blueprint('performance_dashboard', __name__)

@performance_dashboard_bp.route('/overview', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_performance_overview():
    """Get overall performance overview."""
    try:
        # Database performance
        db_stats = global_profiler.get_performance_summary()
        
        # Cache performance
        cache_health = get_cache_health()
        
        # System resources
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Application metrics
        pool_monitor = ConnectionPoolMonitor(db)
        pool_health = pool_monitor.check_health()
        
        overview = {
            'timestamp': datetime.now().isoformat(),
            'database': {
                'total_queries': db_stats['total_queries'],
                'queries_per_second': db_stats['queries_per_second'],
                'avg_query_time': db_stats['avg_query_time'],
                'slow_queries': db_stats['slow_queries'],
                'slow_query_percentage': db_stats['slow_query_percentage']
            },
            'cache': {
                'status': cache_health['status'],
                'hit_rate': cache_health['statistics']['hit_rate_percent'],
                'utilization': cache_health['utilization_percent'],
                'size': cache_health['statistics']['size']
            },
            'system': {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used_gb': round(memory.used / 1024**3, 2),
                'memory_total_gb': round(memory.total / 1024**3, 2),
                'disk_percent': disk.percent,
                'disk_used_gb': round(disk.used / 1024**3, 2),
                'disk_total_gb': round(disk.total / 1024**3, 2)
            },
            'connection_pool': {
                'status': 'healthy' if pool_health[0] else 'unhealthy',
                'message': pool_health[1]
            }
        }
        
        return jsonify(overview)
        
    except Exception as e:
        logger.error(f"Error getting performance overview: {e}")
        return jsonify({'error': 'Failed to get performance overview'}), 500

@performance_dashboard_bp.route('/database/queries/slow', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_slow_queries():
    """Get slow database queries."""
    try:
        limit = request.args.get('limit', 50, type=int)
        threshold = request.args.get('threshold', 1.0, type=float)
        
        slow_queries = global_profiler.get_slow_queries(limit=limit, threshold=threshold)
        
        result = []
        for query in slow_queries:
            result.append({
                'sql': query.sql[:500],  # Truncate for display
                'normalized_sql': query.normalized_sql[:200],
                'execution_time': round(query.execution_time, 3),
                'timestamp': query.timestamp.isoformat(),
                'operation_type': query.operation_type,
                'table_names': query.table_names
            })
            
        return jsonify({
            'queries': result,
            'count': len(result),
            'threshold': threshold
        })
        
    except Exception as e:
        logger.error(f"Error getting slow queries: {e}")
        return jsonify({'error': 'Failed to get slow queries'}), 500

@performance_dashboard_bp.route('/database/queries/top-by-time', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_top_queries_by_time():
    """Get queries with highest total execution time."""
    try:
        limit = request.args.get('limit', 20, type=int)
        
        top_queries = global_profiler.get_top_queries_by_time(limit=limit)
        
        result = []
        for sql, stats in top_queries:
            # Get detailed stats
            detailed_stats = global_profiler.get_query_stats(sql)
            
            result.append({
                'normalized_sql': sql[:200],
                'count': stats['count'],
                'total_time': round(stats['total_time'], 3),
                'avg_time': round(stats['avg_time'], 3),
                'min_time': round(stats['min_time'], 3),
                'max_time': round(stats['max_time'], 3),
                'median_time': round(detailed_stats.get('median_time', 0), 3),
                'p95_time': round(detailed_stats.get('p95_time', 0), 3)
            })
            
        return jsonify({
            'queries': result,
            'count': len(result)
        })
        
    except Exception as e:
        logger.error(f"Error getting top queries by time: {e}")
        return jsonify({'error': 'Failed to get top queries by time'}), 500

@performance_dashboard_bp.route('/database/queries/top-by-count', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_top_queries_by_count():
    """Get most frequently executed queries."""
    try:
        limit = request.args.get('limit', 20, type=int)
        
        top_queries = global_profiler.get_top_queries_by_count(limit=limit)
        
        result = []
        for sql, stats in top_queries:
            result.append({
                'normalized_sql': sql[:200],
                'count': stats['count'],
                'total_time': round(stats['total_time'], 3),
                'avg_time': round(stats['avg_time'], 3),
                'min_time': round(stats['min_time'], 3),
                'max_time': round(stats['max_time'], 3)
            })
            
        return jsonify({
            'queries': result,
            'count': len(result)
        })
        
    except Exception as e:
        logger.error(f"Error getting top queries by count: {e}")
        return jsonify({'error': 'Failed to get top queries by count'}), 500

@performance_dashboard_bp.route('/database/operations', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_operation_stats():
    """Get database operation statistics."""
    try:
        operation_stats = global_profiler.get_operation_stats()
        
        return jsonify({
            'operations': operation_stats,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting operation stats: {e}")
        return jsonify({'error': 'Failed to get operation stats'}), 500

@performance_dashboard_bp.route('/cache/stats', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_cache_stats():
    """Get cache performance statistics."""
    try:
        cache_health = get_cache_health()
        cache_stats = global_cache.get_stats()
        
        return jsonify({
            'health': cache_health,
            'statistics': cache_stats,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        return jsonify({'error': 'Failed to get cache stats'}), 500

@performance_dashboard_bp.route('/system/resources', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_system_resources():
    """Get system resource utilization."""
    try:
        # CPU information
        cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
        cpu_count = psutil.cpu_count()
        
        # Memory information
        memory = psutil.virtual_memory()
        
        # Disk information
        disk = psutil.disk_usage('/')
        disk_io = psutil.disk_io_counters()
        
        # Network information
        net_io = psutil.net_io_counters()
        
        # Process information
        process = psutil.Process(os.getpid())
        process_memory = process.memory_info()
        
        return jsonify({
            'cpu': {
                'count': cpu_count,
                'percent_total': round(sum(cpu_percent) / len(cpu_percent), 2),
                'percent_per_core': [round(p, 2) for p in cpu_percent]
            },
            'memory': {
                'total_gb': round(memory.total / 1024**3, 2),
                'used_gb': round(memory.used / 1024**3, 2),
                'available_gb': round(memory.available / 1024**3, 2),
                'percent': memory.percent
            },
            'disk': {
                'total_gb': round(disk.total / 1024**3, 2),
                'used_gb': round(disk.used / 1024**3, 2),
                'free_gb': round(disk.free / 1024**3, 2),
                'percent': disk.percent,
                'io_read_mb': round(disk_io.read_bytes / 1024**2, 2) if disk_io else 0,
                'io_write_mb': round(disk_io.write_bytes / 1024**2, 2) if disk_io else 0
            },
            'network': {
                'bytes_sent_mb': round(net_io.bytes_sent / 1024**2, 2),
                'bytes_recv_mb': round(net_io.bytes_recv / 1024**2, 2),
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            },
            'process': {
                'memory_rss_mb': round(process_memory.rss / 1024**2, 2),
                'memory_vms_mb': round(process_memory.vms / 1024**2, 2),
                'cpu_percent': process.cpu_percent(),
                'threads': process.num_threads(),
                'connections': len(process.connections()) if hasattr(process, 'connections') else 0
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting system resources: {e}")
        return jsonify({'error': 'Failed to get system resources'}), 500

@performance_dashboard_bp.route('/database/connection-pool', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_connection_pool_status():
    """Get database connection pool status."""
    try:
        pool_monitor = ConnectionPoolMonitor(db)
        pool_status = pool_monitor.get_pool_status()
        pool_metrics = pool_monitor.get_metrics()
        health_check = pool_monitor.check_health()
        
        return jsonify({
            'status': pool_status,
            'metrics': pool_metrics,
            'health': {
                'status': 'healthy' if health_check[0] else 'unhealthy',
                'message': health_check[1]
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting connection pool status: {e}")
        return jsonify({'error': 'Failed to get connection pool status'}), 500

@performance_dashboard_bp.route('/database/optimize', methods=['POST'])
@create_endpoint_limiter('critical')
def optimize_database():
    """Run database optimization tasks."""
    try:
        optimizer = DatabaseOptimizer(db)
        
        tasks = request.json.get('tasks', ['analyze']) if request.json else ['analyze']
        results = {}
        
        if 'vacuum' in tasks:
            results['vacuum'] = optimizer.vacuum_database()
            
        if 'analyze' in tasks:
            results['analyze'] = optimizer.analyze_database()
            
        if 'optimize' in tasks:
            results['optimize'] = optimizer.optimize_tables()
            
        return jsonify({
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error optimizing database: {e}")
        return jsonify({'error': 'Failed to optimize database'}), 500

@performance_dashboard_bp.route('/cache/clear', methods=['POST'])
@create_endpoint_limiter('critical')
def clear_cache():
    """Clear application cache."""
    try:
        # Get stats before clearing
        before_stats = global_cache.get_stats()
        
        # Clear cache
        global_cache.clear()
        
        # Get stats after clearing
        after_stats = global_cache.get_stats()
        
        return jsonify({
            'message': 'Cache cleared successfully',
            'before': before_stats,
            'after': after_stats,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        return jsonify({'error': 'Failed to clear cache'}), 500

@performance_dashboard_bp.route('/profiler/reset', methods=['POST'])
@create_endpoint_limiter('critical')
def reset_profiler():
    """Reset query profiler statistics."""
    try:
        # Get stats before reset
        before_stats = global_profiler.get_performance_summary()
        
        # Reset profiler
        global_profiler.reset_stats()
        
        # Get stats after reset
        after_stats = global_profiler.get_performance_summary()
        
        return jsonify({
            'message': 'Profiler statistics reset successfully',
            'before': before_stats,
            'after': after_stats,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error resetting profiler: {e}")
        return jsonify({'error': 'Failed to reset profiler'}), 500

@performance_dashboard_bp.route('/export/slow-queries', methods=['GET'])
@create_endpoint_limiter('relaxed')
def export_slow_queries():
    """Export slow queries for analysis."""
    try:
        format_type = request.args.get('format', 'json')
        threshold = request.args.get('threshold', 1.0, type=float)
        
        export_data = global_profiler.export_slow_queries(
            threshold=threshold,
            format=format_type
        )
        
        if format_type == 'sql':
            return export_data, 200, {'Content-Type': 'text/plain'}
        else:
            return export_data, 200, {'Content-Type': 'application/json'}
            
    except Exception as e:
        logger.error(f"Error exporting slow queries: {e}")
        return jsonify({'error': 'Failed to export slow queries'}), 500