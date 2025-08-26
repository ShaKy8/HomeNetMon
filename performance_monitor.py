"""
Performance Monitoring and Benchmarking Tool for HomeNetMon
Provides real-time performance tracking and automated optimization recommendations
"""
import time
import statistics
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any
from contextlib import contextmanager
from dataclasses import dataclass
import json
import threading

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetric:
    """Individual performance measurement"""
    name: str
    value: float
    unit: str
    timestamp: datetime
    context: Dict[str, Any] = None

class PerformanceMonitor:
    """Real-time performance monitoring and benchmarking"""
    
    def __init__(self, app=None):
        self.app = app
        self.metrics: Dict[str, List[PerformanceMetric]] = {}
        self.thresholds = {
            'api_response_time': 0.1,  # 100ms
            'database_query_time': 0.05,  # 50ms
            'page_render_time': 0.5,  # 500ms
            'websocket_emit_time': 0.01  # 10ms
        }
        self._lock = threading.Lock()
        
    def record_metric(self, name: str, value: float, unit: str = 'seconds', context: Dict = None):
        """Record a performance metric"""
        with self._lock:
            metric = PerformanceMetric(
                name=name,
                value=value,
                unit=unit,
                timestamp=datetime.utcnow(),
                context=context or {}
            )
            
            if name not in self.metrics:
                self.metrics[name] = []
            
            self.metrics[name].append(metric)
            
            # Keep only last 100 measurements per metric
            if len(self.metrics[name]) > 100:
                self.metrics[name] = self.metrics[name][-100:]
            
            # Check thresholds
            if name in self.thresholds and value > self.thresholds[name]:
                logger.warning(f"Performance threshold exceeded: {name} = {value:.3f}{unit} (threshold: {self.thresholds[name]}{unit})")
    
    @contextmanager
    def measure(self, name: str, context: Dict = None):
        """Context manager for measuring execution time"""
        start_time = time.time()
        try:
            yield
        finally:
            duration = time.time() - start_time
            self.record_metric(name, duration, 'seconds', context)
    
    def get_metric_summary(self, name: str, minutes: int = 60) -> Dict[str, Any]:
        """Get statistical summary of a metric"""
        with self._lock:
            if name not in self.metrics:
                return {'error': f'Metric {name} not found'}
            
            cutoff = datetime.utcnow() - timedelta(minutes=minutes)
            recent_metrics = [
                m for m in self.metrics[name] 
                if m.timestamp >= cutoff
            ]
            
            if not recent_metrics:
                return {'error': f'No recent data for {name}'}
            
            values = [m.value for m in recent_metrics]
            
            return {
                'name': name,
                'count': len(values),
                'min': min(values),
                'max': max(values),
                'mean': statistics.mean(values),
                'median': statistics.median(values),
                'p95': self._percentile(values, 95),
                'p99': self._percentile(values, 99),
                'unit': recent_metrics[0].unit,
                'threshold': self.thresholds.get(name),
                'threshold_exceeded': sum(1 for v in values if v > self.thresholds.get(name, float('inf'))),
                'time_range_minutes': minutes
            }
    
    def get_all_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all metrics"""
        summary = {}
        
        for metric_name in self.metrics.keys():
            summary[metric_name] = self.get_metric_summary(metric_name)
        
        return {
            'metrics': summary,
            'overall_health': self._calculate_overall_health(),
            'recommendations': self._generate_recommendations(),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def benchmark_api_endpoints(self, base_url: str = 'http://localhost:5000') -> Dict[str, Any]:
        """Benchmark critical API endpoints"""
        import requests
        
        endpoints = [
            '/api/devices',
            '/api/devices?monitored=true',
            '/api/monitoring/quick-stats',
            '/api/monitoring/alerts',
            '/health'
        ]
        
        results = {}
        
        for endpoint in endpoints:
            url = f"{base_url}{endpoint}"
            times = []
            
            # Run 5 tests per endpoint
            for _ in range(5):
                try:
                    start = time.time()
                    response = requests.get(url, timeout=30)
                    duration = time.time() - start
                    
                    if response.status_code == 200:
                        times.append(duration)
                    
                    # Record metric
                    self.record_metric(f'api_benchmark_{endpoint.replace("/", "_")}', duration, context={
                        'status_code': response.status_code,
                        'response_size': len(response.content)
                    })
                    
                except Exception as e:
                    logger.error(f"Benchmark failed for {endpoint}: {e}")
            
            if times:
                results[endpoint] = {
                    'avg_time': statistics.mean(times),
                    'min_time': min(times),
                    'max_time': max(times),
                    'tests_run': len(times),
                    'status': 'PASS' if statistics.mean(times) < 1.0 else 'SLOW' if statistics.mean(times) < 5.0 else 'FAIL'
                }
        
        return results
    
    def generate_performance_report(self) -> str:
        """Generate a comprehensive performance report"""
        summary = self.get_all_metrics_summary()
        
        report = []
        report.append("# HomeNetMon Performance Report")
        report.append(f"Generated: {datetime.utcnow().isoformat()}")
        report.append("")
        
        # Overall health
        health = summary['overall_health']
        report.append(f"## Overall Health: {health['status']}")
        report.append(f"Score: {health['score']}/100")
        report.append("")
        
        # Metrics
        report.append("## Performance Metrics")
        for metric_name, data in summary['metrics'].items():
            if 'error' in data:
                continue
            
            report.append(f"### {metric_name}")
            report.append(f"- Mean: {data['mean']:.3f}{data['unit']}")
            report.append(f"- P95: {data['p95']:.3f}{data['unit']}")
            report.append(f"- Threshold: {data['threshold']:.3f}{data['unit']}" if data['threshold'] else "- Threshold: None")
            report.append(f"- Violations: {data['threshold_exceeded']}")
            report.append("")
        
        # Recommendations
        recommendations = summary['recommendations']
        if recommendations:
            report.append("## Recommendations")
            for i, rec in enumerate(recommendations, 1):
                report.append(f"{i}. **{rec['priority']}**: {rec['description']}")
                if 'action' in rec:
                    report.append(f"   Action: {rec['action']}")
                report.append("")
        
        return "\n".join(report)
    
    def _percentile(self, values: List[float], percentile: float) -> float:
        """Calculate percentile"""
        if not values:
            return 0.0
        
        k = (len(values) - 1) * percentile / 100
        f = int(k)
        c = k - f
        
        if f == len(values) - 1:
            return values[f]
        
        return values[f] * (1 - c) + values[f + 1] * c
    
    def _calculate_overall_health(self) -> Dict[str, Any]:
        """Calculate overall system health score"""
        score = 100
        issues = []
        
        for metric_name in self.metrics.keys():
            summary = self.get_metric_summary(metric_name, minutes=30)
            
            if 'error' in summary:
                continue
            
            threshold = self.thresholds.get(metric_name)
            if threshold and summary['mean'] > threshold:
                penalty = min(30, (summary['mean'] / threshold - 1) * 20)
                score -= penalty
                issues.append(f"{metric_name} is {summary['mean']:.3f}s (threshold: {threshold}s)")
        
        status = 'HEALTHY' if score >= 90 else 'WARNING' if score >= 70 else 'CRITICAL'
        
        return {
            'score': max(0, score),
            'status': status,
            'issues': issues
        }
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate performance improvement recommendations"""
        recommendations = []
        
        # Check API performance
        api_metrics = [name for name in self.metrics.keys() if 'api' in name.lower()]
        for metric_name in api_metrics:
            summary = self.get_metric_summary(metric_name, minutes=30)
            
            if 'error' in summary:
                continue
            
            if summary['mean'] > 1.0:  # Slower than 1 second
                recommendations.append({
                    'priority': 'CRITICAL',
                    'description': f'API endpoint {metric_name} is very slow ({summary["mean"]:.2f}s average)',
                    'action': 'Implement database indexing and query optimization'
                })
            elif summary['mean'] > 0.5:  # Slower than 500ms
                recommendations.append({
                    'priority': 'HIGH',
                    'description': f'API endpoint {metric_name} exceeds recommended response time',
                    'action': 'Consider adding caching or query optimization'
                })
        
        # Check database performance
        db_metrics = [name for name in self.metrics.keys() if 'database' in name.lower() or 'query' in name.lower()]
        slow_queries = 0
        
        for metric_name in db_metrics:
            summary = self.get_metric_summary(metric_name, minutes=30)
            
            if 'error' not in summary and summary['mean'] > 0.1:  # Slower than 100ms
                slow_queries += 1
        
        if slow_queries > 0:
            recommendations.append({
                'priority': 'HIGH',
                'description': f'{slow_queries} database queries are slower than recommended',
                'action': 'Add database indexes and optimize SQL queries'
            })
        
        return recommendations

# Flask integration
def setup_performance_monitoring(app):
    """Set up performance monitoring for Flask app"""
    monitor = PerformanceMonitor(app)
    
    @app.before_request
    def start_request_timer():
        from flask import g
        g.start_time = time.time()
    
    @app.after_request
    def record_request_time(response):
        from flask import g, request
        
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            
            # Categorize the request
            if request.path.startswith('/api/'):
                monitor.record_metric('api_response_time', duration, context={
                    'endpoint': request.path,
                    'method': request.method,
                    'status_code': response.status_code
                })
            elif request.path.startswith('/static/'):
                monitor.record_metric('static_file_time', duration, context={
                    'file_path': request.path,
                    'status_code': response.status_code
                })
            else:
                monitor.record_metric('page_render_time', duration, context={
                    'page': request.path,
                    'status_code': response.status_code
                })
        
        return response
    
    # Add performance monitoring endpoint
    @app.route('/api/performance/metrics')
    def performance_metrics():
        return monitor.get_all_metrics_summary()
    
    @app.route('/api/performance/report')
    def performance_report():
        return monitor.generate_performance_report(), 200, {'Content-Type': 'text/plain'}
    
    @app.route('/api/performance/benchmark')
    def run_benchmark():
        results = monitor.benchmark_api_endpoints()
        return {'benchmark_results': results, 'timestamp': datetime.utcnow().isoformat()}
    
    # Store monitor instance in app for external access
    app.performance_monitor = monitor
    
    logger.info("Performance monitoring enabled")
    return monitor