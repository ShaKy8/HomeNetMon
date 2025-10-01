#!/usr/bin/env python3
"""
Backend Performance and Load Testing Tool for HomeNetMon
Comprehensive testing of API performance, database performance, memory usage, and load handling
"""

import os
import sys
import json
import time
import psutil
import sqlite3
import requests
import threading
import statistics
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager

class BackendPerformanceTester:
    def __init__(self, base_url="http://geekom1:5000", project_path=None):
        self.base_url = base_url
        self.project_path = Path(project_path or Path.cwd())
        self.results = defaultdict(list)
        self.load_test_results = {}
        self.database_metrics = {}
        self.system_metrics = deque(maxlen=1000)

        # Color codes for output
        self.colors = {
            'red': '\033[91m',
            'yellow': '\033[93m',
            'green': '\033[92m',
            'blue': '\033[94m',
            'purple': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'reset': '\033[0m'
        }

        # Performance thresholds
        self.thresholds = {
            'api_response_ms': {
                'excellent': 100,
                'good': 300,
                'warning': 1000,
                'poor': 3000
            },
            'db_query_ms': {
                'excellent': 10,
                'good': 50,
                'warning': 200,
                'poor': 1000
            },
            'memory_usage_mb': {
                'excellent': 100,
                'good': 250,
                'warning': 500,
                'poor': 1000
            },
            'cpu_usage_percent': {
                'excellent': 20,
                'good': 50,
                'warning': 80,
                'poor': 95
            }
        }

    def log_result(self, level, category, test_name, metric, value, target="", recommendation=""):
        """Log a performance test result"""
        result = {
            'level': level,
            'category': category,
            'test': test_name,
            'metric': metric,
            'value': value,
            'target': target,
            'recommendation': recommendation,
            'timestamp': datetime.now().isoformat()
        }
        self.results[level].append(result)

        # Color mapping
        colors = {
            'excellent': self.colors['green'],
            'good': self.colors['blue'],
            'warning': self.colors['yellow'],
            'poor': self.colors['red'],
            'info': self.colors['cyan']
        }

        icons = {
            'excellent': '🚀',
            'good': '✅',
            'warning': '⚠️',
            'poor': '❌',
            'info': 'ℹ️'
        }

        color = colors.get(level, self.colors['white'])
        icon = icons.get(level, 'ℹ️')

        print(f"{color}{icon} {test_name} - {metric}: {value}{self.colors['reset']}")
        if target:
            print(f"    Target: {target}")
        if recommendation:
            print(f"    └─ {recommendation}")

    def test_api_performance(self):
        """Test API endpoint performance"""
        print(f"\n{self.colors['cyan']}🔌 Testing API Performance{self.colors['reset']}")

        # Define API endpoints to test
        endpoints = [
            {'path': '/', 'method': 'GET', 'name': 'Home Page'},
            {'path': '/api/csrf-token', 'method': 'GET', 'name': 'CSRF Token API'},
            {'path': '/analytics', 'method': 'GET', 'name': 'Analytics Page'},
            {'path': '/settings', 'method': 'GET', 'name': 'Settings Page'},
            {'path': '/security', 'method': 'GET', 'name': 'Security Page'},
            {'path': '/topology', 'method': 'GET', 'name': 'Topology Page'},
            {'path': '/static/bundles/core.js', 'method': 'GET', 'name': 'Static Asset'},
        ]

        for endpoint in endpoints:
            self._test_single_endpoint(endpoint)

    def _test_single_endpoint(self, endpoint):
        """Test performance of a single API endpoint"""
        url = f"{self.base_url}{endpoint['path']}"
        name = endpoint['name']

        response_times = []
        status_codes = []
        content_sizes = []

        # Perform multiple requests to get average performance
        for i in range(5):
            try:
                start_time = time.time()
                response = requests.request(endpoint['method'], url, timeout=10)
                end_time = time.time()

                response_time_ms = (end_time - start_time) * 1000
                response_times.append(response_time_ms)
                status_codes.append(response.status_code)
                content_sizes.append(len(response.content))

            except requests.exceptions.RequestException as e:
                response_times.append(10000)  # 10 second timeout
                status_codes.append(0)
                content_sizes.append(0)

        # Calculate statistics
        if response_times:
            avg_response_time = statistics.mean(response_times)
            p95_response_time = sorted(response_times)[int(len(response_times) * 0.95)]
            avg_content_size = statistics.mean(content_sizes) / 1024  # KB

            # Classify performance
            thresholds = self.thresholds['api_response_ms']
            if avg_response_time <= thresholds['excellent']:
                level = 'excellent'
            elif avg_response_time <= thresholds['good']:
                level = 'good'
            elif avg_response_time <= thresholds['warning']:
                level = 'warning'
            else:
                level = 'poor'

            self.log_result(level, 'API Performance', name, 'Response Time', f"{avg_response_time:.0f}ms",
                          "< 300ms for good UX", "Optimize slow queries or add caching" if level in ['warning', 'poor'] else "")

            # Check for successful responses
            success_rate = sum(1 for code in status_codes if 200 <= code < 400) / len(status_codes) * 100
            if success_rate >= 95:
                self.log_result('good', 'API Performance', name, 'Success Rate', f"{success_rate:.0f}%")
            else:
                self.log_result('warning', 'API Performance', name, 'Success Rate', f"{success_rate:.0f}%",
                              "≥ 95%", "Check for authentication or server errors")

            # Store detailed results
            self.results['api_details'].append({
                'endpoint': name,
                'path': endpoint['path'],
                'avg_response_time': avg_response_time,
                'p95_response_time': p95_response_time,
                'success_rate': success_rate,
                'avg_content_size_kb': avg_content_size
            })

    def test_database_performance(self):
        """Test database performance"""
        print(f"\n{self.colors['cyan']}🗄️ Testing Database Performance{self.colors['reset']}")

        db_path = self.project_path / "homeNetMon.db"
        if not db_path.exists():
            self.log_result('warning', 'Database', 'Database File', 'Status', 'Not found',
                          recommendation="Database file missing - tests skipped")
            return

        try:
            # Test database connection
            start_time = time.time()
            conn = sqlite3.connect(db_path)
            connection_time = (time.time() - start_time) * 1000

            if connection_time <= 10:
                self.log_result('excellent', 'Database', 'Connection', 'Time', f"{connection_time:.1f}ms")
            elif connection_time <= 50:
                self.log_result('good', 'Database', 'Connection', 'Time', f"{connection_time:.1f}ms")
            else:
                self.log_result('warning', 'Database', 'Connection', 'Time', f"{connection_time:.1f}ms")

            # Test common queries
            self._test_database_queries(conn)

            # Test database size and structure
            self._analyze_database_structure(conn, db_path)

            conn.close()

        except Exception as e:
            self.log_result('poor', 'Database', 'Connection', 'Error', str(e),
                          recommendation="Fix database connectivity issues")

    def _test_database_queries(self, conn):
        """Test performance of common database queries"""
        queries = [
            ("SELECT COUNT(*) FROM Device", "Device Count"),
            ("SELECT COUNT(*) FROM MonitoringData", "Monitoring Data Count"),
            ("SELECT COUNT(*) FROM Alert", "Alert Count"),
            ("SELECT * FROM Device LIMIT 10", "Recent Devices"),
            ("SELECT * FROM MonitoringData ORDER BY timestamp DESC LIMIT 100", "Recent Monitoring Data"),
            ("SELECT device_id, AVG(response_time) FROM MonitoringData GROUP BY device_id LIMIT 10", "Device Averages")
        ]

        for query, name in queries:
            try:
                start_time = time.time()
                cursor = conn.execute(query)
                results = cursor.fetchall()
                query_time = (time.time() - start_time) * 1000

                # Classify query performance
                thresholds = self.thresholds['db_query_ms']
                if query_time <= thresholds['excellent']:
                    level = 'excellent'
                elif query_time <= thresholds['good']:
                    level = 'good'
                elif query_time <= thresholds['warning']:
                    level = 'warning'
                else:
                    level = 'poor'

                self.log_result(level, 'Database Query', name, 'Query Time', f"{query_time:.1f}ms",
                              "< 50ms for responsive UI",
                              "Add database indexes or optimize query" if level in ['warning', 'poor'] else "")

                # Store result count for analysis
                if name.endswith("Count") and results:
                    count = results[0][0] if results[0] else 0
                    self.log_result('info', 'Database', name, 'Records', f"{count:,}")

            except Exception as e:
                self.log_result('warning', 'Database Query', name, 'Error', str(e))

    def _analyze_database_structure(self, conn, db_path):
        """Analyze database structure and size"""
        try:
            # Get database size
            db_size_mb = db_path.stat().st_size / (1024 * 1024)
            self.log_result('info', 'Database', 'Size', 'Total', f"{db_size_mb:.1f}MB")

            # Get table information
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            self.log_result('info', 'Database', 'Structure', 'Tables', len(tables))

            # Check for indexes
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
            indexes = cursor.fetchall()
            index_count = len([idx for idx in indexes if not idx[0].startswith('sqlite_')])

            if index_count >= len(tables):
                self.log_result('good', 'Database', 'Optimization', 'Indexes', index_count)
            else:
                self.log_result('warning', 'Database', 'Optimization', 'Indexes', index_count,
                              f"≥ {len(tables)} recommended", "Consider adding indexes for better performance")

        except Exception as e:
            self.log_result('warning', 'Database', 'Analysis', 'Error', str(e))

    def test_system_performance(self):
        """Test system resource usage"""
        print(f"\n{self.colors['cyan']}💻 Testing System Performance{self.colors['reset']}")

        # Monitor system metrics for 30 seconds
        monitoring_duration = 30
        sample_interval = 1
        samples = []

        print(f"    Monitoring system for {monitoring_duration} seconds...")

        for i in range(monitoring_duration):
            sample = {
                'timestamp': datetime.now(),
                'cpu_percent': psutil.cpu_percent(interval=None),
                'memory_percent': psutil.virtual_memory().percent,
                'memory_used_mb': psutil.virtual_memory().used / (1024 * 1024),
                'disk_io': psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {},
                'network_io': psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {}
            }
            samples.append(sample)
            time.sleep(sample_interval)

        # Analyze system performance
        self._analyze_system_metrics(samples)

    def _analyze_system_metrics(self, samples):
        """Analyze collected system metrics"""
        if not samples:
            return

        # CPU Usage Analysis
        cpu_values = [s['cpu_percent'] for s in samples]
        avg_cpu = statistics.mean(cpu_values)
        max_cpu = max(cpu_values)

        cpu_thresholds = self.thresholds['cpu_usage_percent']
        if avg_cpu <= cpu_thresholds['excellent']:
            cpu_level = 'excellent'
        elif avg_cpu <= cpu_thresholds['good']:
            cpu_level = 'good'
        elif avg_cpu <= cpu_thresholds['warning']:
            cpu_level = 'warning'
        else:
            cpu_level = 'poor'

        self.log_result(cpu_level, 'System Performance', 'CPU Usage', 'Average', f"{avg_cpu:.1f}%",
                      "< 50% for good performance",
                      "Optimize CPU-intensive operations" if cpu_level in ['warning', 'poor'] else "")

        # Memory Usage Analysis
        memory_values = [s['memory_used_mb'] for s in samples]
        avg_memory = statistics.mean(memory_values)
        max_memory = max(memory_values)

        memory_thresholds = self.thresholds['memory_usage_mb']
        if avg_memory <= memory_thresholds['excellent']:
            memory_level = 'excellent'
        elif avg_memory <= memory_thresholds['good']:
            memory_level = 'good'
        elif avg_memory <= memory_thresholds['warning']:
            memory_level = 'warning'
        else:
            memory_level = 'poor'

        self.log_result(memory_level, 'System Performance', 'Memory Usage', 'Average', f"{avg_memory:.0f}MB",
                      "< 250MB for good performance",
                      "Check for memory leaks or optimize data structures" if memory_level in ['warning', 'poor'] else "")

        # Store metrics for load testing
        self.system_metrics.extend(samples)

    def test_concurrent_load(self):
        """Test performance under concurrent load"""
        print(f"\n{self.colors['cyan']}⚡ Testing Concurrent Load Performance{self.colors['reset']}")

        # Test different concurrency levels
        concurrency_levels = [1, 5, 10, 20]
        test_endpoint = f"{self.base_url}/"

        for concurrency in concurrency_levels:
            print(f"    Testing with {concurrency} concurrent users...")
            load_results = self._run_load_test(test_endpoint, concurrency, duration=10)
            self._analyze_load_test_results(concurrency, load_results)

    def _run_load_test(self, url, concurrency, duration):
        """Run load test with specified concurrency"""
        results = []
        start_time = time.time()

        def make_request():
            try:
                request_start = time.time()
                response = requests.get(url, timeout=10)
                request_time = (time.time() - request_start) * 1000
                return {
                    'response_time': request_time,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'timestamp': time.time()
                }
            except Exception as e:
                return {
                    'response_time': 10000,
                    'status_code': 0,
                    'content_length': 0,
                    'error': str(e),
                    'timestamp': time.time()
                }

        # Run concurrent requests for specified duration
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = []

            while time.time() - start_time < duration:
                if len(futures) < concurrency:
                    future = executor.submit(make_request)
                    futures.append(future)

                # Collect completed requests
                completed = []
                for future in futures:
                    if future.done():
                        try:
                            result = future.result()
                            results.append(result)
                        except Exception as e:
                            results.append({
                                'response_time': 10000,
                                'status_code': 0,
                                'content_length': 0,
                                'error': str(e),
                                'timestamp': time.time()
                            })
                        completed.append(future)

                # Remove completed futures
                for future in completed:
                    futures.remove(future)

                time.sleep(0.1)  # Small delay to prevent overwhelming

            # Wait for remaining requests
            for future in futures:
                try:
                    result = future.result(timeout=5)
                    results.append(result)
                except Exception as e:
                    results.append({
                        'response_time': 10000,
                        'status_code': 0,
                        'content_length': 0,
                        'error': str(e),
                        'timestamp': time.time()
                    })

        return results

    def _analyze_load_test_results(self, concurrency, results):
        """Analyze load test results"""
        if not results:
            self.log_result('warning', 'Load Test', f'{concurrency} Users', 'Results', 'No data')
            return

        # Calculate metrics
        response_times = [r['response_time'] for r in results if 'error' not in r]
        successful_requests = [r for r in results if r['status_code'] == 200]

        if response_times:
            avg_response_time = statistics.mean(response_times)
            p95_response_time = sorted(response_times)[int(len(response_times) * 0.95)] if len(response_times) > 1 else response_times[0]
            success_rate = len(successful_requests) / len(results) * 100
            throughput = len(successful_requests) / 10  # requests per second over 10-second test

            # Classify performance based on response time degradation
            baseline_response_time = 150  # Expected baseline from single user
            degradation_factor = avg_response_time / baseline_response_time

            if degradation_factor <= 1.5:
                level = 'excellent'
            elif degradation_factor <= 2.0:
                level = 'good'
            elif degradation_factor <= 3.0:
                level = 'warning'
            else:
                level = 'poor'

            self.log_result(level, 'Load Test', f'{concurrency} Users', 'Avg Response Time', f"{avg_response_time:.0f}ms",
                          f"< {baseline_response_time * 2}ms acceptable",
                          "Optimize for concurrent access" if level in ['warning', 'poor'] else "")

            self.log_result('info', 'Load Test', f'{concurrency} Users', 'P95 Response Time', f"{p95_response_time:.0f}ms")
            self.log_result('info', 'Load Test', f'{concurrency} Users', 'Success Rate', f"{success_rate:.1f}%")
            self.log_result('info', 'Load Test', f'{concurrency} Users', 'Throughput', f"{throughput:.1f} req/s")

            # Store results for summary
            self.load_test_results[concurrency] = {
                'avg_response_time': avg_response_time,
                'p95_response_time': p95_response_time,
                'success_rate': success_rate,
                'throughput': throughput,
                'total_requests': len(results)
            }

    def generate_performance_report(self):
        """Generate comprehensive performance report"""
        print(f"\n{self.colors['purple']}📊 Backend Performance Report{self.colors['reset']}")
        print("=" * 80)

        # Summary statistics
        total_tests = sum(len(results) for results in self.results.values() if isinstance(results, list))
        excellent_count = len(self.results['excellent'])
        good_count = len(self.results['good'])
        warning_count = len(self.results['warning'])
        poor_count = len(self.results['poor'])

        print(f"\n📈 Performance Summary:")
        print(f"  Total Tests: {total_tests}")
        print(f"  Excellent: {excellent_count}")
        print(f"  Good: {good_count}")
        print(f"  Warnings: {warning_count}")
        print(f"  Poor: {poor_count}")

        # Calculate overall performance score
        performance_score = self._calculate_performance_score()
        print(f"\n🎯 Backend Performance Score: {performance_score}/100")

        if performance_score >= 90:
            status = f"{self.colors['green']}🚀 EXCELLENT{self.colors['reset']}"
        elif performance_score >= 75:
            status = f"{self.colors['blue']}✅ GOOD{self.colors['reset']}"
        elif performance_score >= 60:
            status = f"{self.colors['yellow']}⚠️ NEEDS IMPROVEMENT{self.colors['reset']}"
        else:
            status = f"{self.colors['red']}❌ POOR{self.colors['reset']}"

        print(f"  Status: {status}")

        # Load test summary
        if self.load_test_results:
            print(f"\n⚡ Load Test Summary:")
            for concurrency, results in self.load_test_results.items():
                print(f"  {concurrency} Users: {results['avg_response_time']:.0f}ms avg, "
                      f"{results['success_rate']:.1f}% success, {results['throughput']:.1f} req/s")

        # Performance recommendations
        recommendations = self._generate_performance_recommendations()
        if recommendations:
            print(f"\n💡 Performance Recommendations:")
            for i, rec in enumerate(recommendations[:8], 1):
                print(f"  {i}. {rec}")

        # Database insights
        if hasattr(self, 'database_metrics') and self.database_metrics:
            print(f"\n🗄️ Database Insights:")
            # Add database-specific insights here

        print(f"\n⏰ Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return performance_score

    def _calculate_performance_score(self):
        """Calculate overall backend performance score"""
        score = 100

        # Deduct points for issues
        score -= len(self.results['poor']) * 20
        score -= len(self.results['warning']) * 10

        # Add bonus points for excellent performance
        score += len(self.results['excellent']) * 2

        # Adjust based on load test performance
        if self.load_test_results:
            # Check if performance degrades significantly under load
            single_user = self.load_test_results.get(1, {})
            multi_user = self.load_test_results.get(10, {})

            if single_user and multi_user:
                degradation = multi_user['avg_response_time'] / single_user['avg_response_time']
                if degradation > 3:
                    score -= 20  # Significant performance degradation
                elif degradation > 2:
                    score -= 10

        return max(0, min(100, score))

    def _generate_performance_recommendations(self):
        """Generate performance improvement recommendations"""
        recommendations = []

        # API performance recommendations
        slow_apis = [r for r in self.results.get('api_details', []) if r['avg_response_time'] > 300]
        if slow_apis:
            recommendations.append("Optimize slow API endpoints with caching or query optimization")

        # Database recommendations
        if len([r for r in self.results['warning'] + self.results['poor'] if r['category'] == 'Database Query']) > 0:
            recommendations.append("Add database indexes and optimize slow queries")

        # System resource recommendations
        high_cpu = any(r['category'] == 'System Performance' and 'CPU' in r['test'] and r['level'] in ['warning', 'poor']
                      for r in self.results['warning'] + self.results['poor'])
        if high_cpu:
            recommendations.append("Optimize CPU-intensive operations and consider async processing")

        high_memory = any(r['category'] == 'System Performance' and 'Memory' in r['test'] and r['level'] in ['warning', 'poor']
                         for r in self.results['warning'] + self.results['poor'])
        if high_memory:
            recommendations.append("Review memory usage and implement garbage collection optimization")

        # Load testing recommendations
        if self.load_test_results:
            max_concurrency = max(self.load_test_results.keys())
            if max_concurrency <= 10:
                recommendations.append("Test with higher concurrency levels for production readiness")

        # General recommendations
        recommendations.extend([
            "Implement connection pooling for database connections",
            "Add response caching for frequently accessed data",
            "Consider implementing rate limiting to prevent abuse",
            "Monitor application performance in production",
            "Set up automated performance alerts"
        ])

        return recommendations

    def save_performance_report(self):
        """Save detailed performance report to file"""
        report_file = self.project_path / "backend_performance_report.json"

        report_data = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_tests': sum(len(results) for results in self.results.values() if isinstance(results, list)),
                'excellent_count': len(self.results['excellent']),
                'good_count': len(self.results['good']),
                'warning_count': len(self.results['warning']),
                'poor_count': len(self.results['poor']),
                'performance_score': self._calculate_performance_score()
            },
            'results': dict(self.results),
            'load_test_results': self.load_test_results,
            'recommendations': self._generate_performance_recommendations()
        }

        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"\n💾 Detailed report saved to: {report_file}")
        return report_file

def main():
    """Main function to run backend performance tests"""
    project_path = Path.cwd()

    print(f"⚡ Starting Backend Performance Testing")
    print(f"📊 Project: {project_path}")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    tester = BackendPerformanceTester(project_path=project_path)

    # Run all performance tests
    tester.test_api_performance()
    tester.test_database_performance()
    tester.test_system_performance()
    tester.test_concurrent_load()

    # Generate and save report
    performance_score = tester.generate_performance_report()
    tester.save_performance_report()

    # Exit with appropriate code
    if performance_score >= 75:
        sys.exit(0)  # Good performance
    elif performance_score >= 60:
        sys.exit(1)  # Needs improvement
    else:
        sys.exit(2)  # Poor performance

if __name__ == "__main__":
    main()