#!/usr/bin/env python3
"""
Comprehensive Load and Stress Testing Suite for HomeNetMon
Phase 5.2: Validate performance under production conditions

Tests application behavior under various load scenarios:
- Concurrent user simulation
- API endpoint stress testing
- Database performance under load
- Memory and resource usage monitoring
- WebSocket connection stress testing
- Real-time feature performance validation
"""

import os
import sys
import json
import time
import sqlite3
import requests
import logging
import threading
import psutil
import statistics
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import urljoin
import concurrent.futures
from bs4 import BeautifulSoup
import socketio

class LoadStressTestSuite:
    def __init__(self, base_url="http://geekom1:5000", db_path="homeNetMon.db"):
        self.base_url = base_url
        self.db_path = Path(db_path)
        self.test_results = []
        self.performance_metrics = []

        # Test configuration
        self.test_scenarios = {
            'light_load': {'users': 5, 'duration': 60, 'requests_per_second': 1},
            'moderate_load': {'users': 15, 'duration': 120, 'requests_per_second': 2},
            'heavy_load': {'users': 30, 'duration': 180, 'requests_per_second': 5},
            'stress_test': {'users': 50, 'duration': 300, 'requests_per_second': 10},
            'spike_test': {'users': 100, 'duration': 60, 'requests_per_second': 20}
        }

        # Performance thresholds
        self.thresholds = {
            'response_time_95th': 2000,  # 95th percentile under 2s
            'response_time_avg': 500,    # Average under 500ms
            'error_rate': 0.05,          # Error rate under 5%
            'memory_limit': 2048,        # Memory under 2GB
            'cpu_limit': 80,             # CPU under 80%
            'database_size_limit': 1024  # Database under 1GB
        }

        # Color codes
        self.colors = {
            'green': '\033[92m',
            'red': '\033[91m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'purple': '\033[95m',
            'cyan': '\033[96m',
            'reset': '\033[0m'
        }

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('load_stress_test_results.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def log_test(self, scenario, test_name, passed, details="", metrics=None):
        """Log test result with performance metrics"""
        result = {
            'scenario': scenario,
            'test_name': test_name,
            'passed': passed,
            'details': details,
            'metrics': metrics or {},
            'timestamp': datetime.now().isoformat()
        }

        self.test_results.append(result)

        # Console output
        status_color = self.colors['green'] if passed else self.colors['red']
        status_icon = '✅' if passed else '❌'

        print(f"{status_color}{status_icon} {scenario.upper()}: {test_name}{self.colors['reset']}")
        if details:
            print(f"   📝 {details}")
        if metrics:
            for key, value in metrics.items():
                print(f"   📊 {key}: {value}")

    def get_system_metrics(self):
        """Get current system resource usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            return {
                'cpu_percent': cpu_percent,
                'memory_used_mb': memory.used / (1024 * 1024),
                'memory_percent': memory.percent,
                'disk_used_gb': disk.used / (1024 * 1024 * 1024),
                'disk_percent': disk.percent
            }
        except Exception as e:
            self.logger.error(f"Error getting system metrics: {e}")
            return {}

    def get_database_metrics(self):
        """Get database performance metrics"""
        try:
            db_size = self.db_path.stat().st_size / (1024 * 1024)  # Size in MB

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Test query performance
                start_time = time.time()
                cursor.execute("SELECT COUNT(*) FROM devices")
                query_time_ms = (time.time() - start_time) * 1000

                # Get table sizes
                cursor.execute("SELECT COUNT(*) FROM monitoring_data")
                monitoring_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM performance_metrics")
                performance_count = cursor.fetchone()[0]

                return {
                    'size_mb': db_size,
                    'query_time_ms': query_time_ms,
                    'monitoring_records': monitoring_count,
                    'performance_records': performance_count
                }
        except Exception as e:
            self.logger.error(f"Error getting database metrics: {e}")
            return {}

    def simulate_user_session(self, user_id, scenario_config, results_queue):
        """Simulate a single user session"""
        session = requests.Session()
        user_results = {
            'user_id': user_id,
            'requests': [],
            'errors': [],
            'start_time': time.time()
        }

        # Test pages to visit
        test_pages = [
            '/',
            '/dashboard',
            '/analytics',
            '/devices',
            '/alerts',
            '/topology'
        ]

        # API endpoints to test
        api_endpoints = [
            '/api/devices',
            '/api/monitoring/summary',
            '/api/monitoring/alerts',
            '/api/system/info'
        ]

        duration = scenario_config['duration']
        requests_per_second = scenario_config['requests_per_second']
        request_interval = 1.0 / requests_per_second

        end_time = time.time() + duration

        while time.time() < end_time:
            try:
                # Randomly choose between page and API request
                if len(user_results['requests']) % 3 == 0:
                    # API request
                    endpoint = api_endpoints[len(user_results['requests']) % len(api_endpoints)]
                    url = urljoin(self.base_url, endpoint)
                else:
                    # Page request
                    page = test_pages[len(user_results['requests']) % len(test_pages)]
                    url = urljoin(self.base_url, page)

                # Make request with timing
                start_time = time.time()
                response = session.get(url, timeout=10)
                response_time = (time.time() - start_time) * 1000

                request_result = {
                    'url': url,
                    'status_code': response.status_code,
                    'response_time_ms': response_time,
                    'timestamp': time.time()
                }

                user_results['requests'].append(request_result)

                if response.status_code >= 400:
                    user_results['errors'].append({
                        'url': url,
                        'status_code': response.status_code,
                        'timestamp': time.time()
                    })

                # Wait for next request
                time.sleep(max(0, request_interval - (time.time() - start_time)))

            except Exception as e:
                user_results['errors'].append({
                    'url': url if 'url' in locals() else 'unknown',
                    'error': str(e),
                    'timestamp': time.time()
                })
                time.sleep(request_interval)

        user_results['end_time'] = time.time()
        results_queue.append(user_results)

    def run_load_scenario(self, scenario_name, config):
        """Run a specific load testing scenario"""
        print(f"\n{self.colors['cyan']}🔥 Running {scenario_name.upper()} Load Test{self.colors['reset']}")
        print(f"Users: {config['users']}, Duration: {config['duration']}s, RPS: {config['requests_per_second']}")

        # Record initial system state
        initial_metrics = self.get_system_metrics()
        initial_db_metrics = self.get_database_metrics()

        # Start user simulation threads
        results_queue = []
        threads = []

        start_time = time.time()

        for user_id in range(config['users']):
            thread = threading.Thread(
                target=self.simulate_user_session,
                args=(user_id, config, results_queue)
            )
            threads.append(thread)
            thread.start()

            # Stagger user starts to simulate realistic load
            time.sleep(0.1)

        # Monitor system during test
        monitoring_thread = threading.Thread(
            target=self.monitor_system_during_test,
            args=(config['duration'], scenario_name)
        )
        monitoring_thread.start()

        # Wait for all users to complete
        for thread in threads:
            thread.join()

        monitoring_thread.join()

        end_time = time.time()

        # Analyze results
        self.analyze_scenario_results(scenario_name, results_queue, initial_metrics, initial_db_metrics, start_time, end_time)

    def monitor_system_during_test(self, duration, scenario_name):
        """Monitor system resources during load test"""
        monitoring_data = []
        start_time = time.time()

        while time.time() - start_time < duration:
            metrics = self.get_system_metrics()
            metrics['timestamp'] = time.time()
            monitoring_data.append(metrics)
            time.sleep(5)  # Sample every 5 seconds

        # Store monitoring data for later analysis
        self.performance_metrics.append({
            'scenario': scenario_name,
            'monitoring_data': monitoring_data
        })

    def analyze_scenario_results(self, scenario_name, user_results, initial_metrics, initial_db_metrics, start_time, end_time):
        """Analyze results from a load test scenario"""

        # Aggregate all requests
        all_requests = []
        all_errors = []

        for user_result in user_results:
            all_requests.extend(user_result['requests'])
            all_errors.extend(user_result['errors'])

        # Calculate performance metrics
        response_times = [req['response_time_ms'] for req in all_requests]
        successful_requests = [req for req in all_requests if req['status_code'] < 400]

        if response_times:
            avg_response_time = statistics.mean(response_times)
            p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
            p99_response_time = statistics.quantiles(response_times, n=100)[98]  # 99th percentile
        else:
            avg_response_time = p95_response_time = p99_response_time = 0

        total_requests = len(all_requests)
        error_count = len(all_errors)
        error_rate = error_count / total_requests if total_requests > 0 else 0

        requests_per_second = total_requests / (end_time - start_time)

        # Get final system state
        final_metrics = self.get_system_metrics()
        final_db_metrics = self.get_database_metrics()

        # Performance analysis
        metrics = {
            'total_requests': total_requests,
            'successful_requests': len(successful_requests),
            'error_count': error_count,
            'error_rate_percent': error_rate * 100,
            'avg_response_time_ms': avg_response_time,
            'p95_response_time_ms': p95_response_time,
            'p99_response_time_ms': p99_response_time,
            'requests_per_second': requests_per_second,
            'duration_seconds': end_time - start_time,
            'memory_usage_change_mb': final_metrics.get('memory_used_mb', 0) - initial_metrics.get('memory_used_mb', 0),
            'cpu_max_percent': final_metrics.get('cpu_percent', 0),
            'database_size_mb': final_db_metrics.get('size_mb', 0)
        }

        # Determine if scenario passed
        passed = (
            avg_response_time <= self.thresholds['response_time_avg'] and
            p95_response_time <= self.thresholds['response_time_95th'] and
            error_rate <= self.thresholds['error_rate'] and
            final_metrics.get('memory_used_mb', 0) <= self.thresholds['memory_limit'] and
            final_metrics.get('cpu_percent', 0) <= self.thresholds['cpu_limit']
        )

        details = f"RPS: {requests_per_second:.1f}, Errors: {error_rate*100:.1f}%, Avg: {avg_response_time:.0f}ms, P95: {p95_response_time:.0f}ms"

        self.log_test(scenario_name, 'Load test performance', passed, details, metrics)

    def test_websocket_under_load(self):
        """Test WebSocket performance under load"""
        print(f"\n{self.colors['cyan']}🔄 Testing WebSocket Performance Under Load{self.colors['reset']}")

        websocket_clients = []
        connection_results = []

        # Try to create multiple WebSocket connections
        for i in range(10):
            try:
                sio = socketio.SimpleClient()
                start_time = time.time()
                sio.connect(self.base_url, timeout=5)
                connection_time = (time.time() - start_time) * 1000

                websocket_clients.append(sio)
                connection_results.append({
                    'client_id': i,
                    'connected': True,
                    'connection_time_ms': connection_time
                })

                # Small delay between connections
                time.sleep(0.1)

            except Exception as e:
                connection_results.append({
                    'client_id': i,
                    'connected': False,
                    'error': str(e)
                })

        # Cleanup connections
        for client in websocket_clients:
            try:
                client.disconnect()
            except:
                pass

        # Analyze WebSocket performance
        successful_connections = [r for r in connection_results if r.get('connected', False)]
        connection_rate = len(successful_connections) / len(connection_results)

        if successful_connections:
            avg_connection_time = statistics.mean([r['connection_time_ms'] for r in successful_connections])
        else:
            avg_connection_time = 0

        passed = connection_rate >= 0.8 and avg_connection_time <= 1000
        details = f"Success rate: {connection_rate*100:.1f}%, Avg connection: {avg_connection_time:.0f}ms"

        self.log_test('websocket', 'WebSocket load performance', passed, details, {
            'connection_success_rate': connection_rate,
            'avg_connection_time_ms': avg_connection_time,
            'successful_connections': len(successful_connections)
        })

    def test_database_under_load(self):
        """Test database performance under concurrent load"""
        print(f"\n{self.colors['cyan']}💾 Testing Database Performance Under Load{self.colors['reset']}")

        def database_worker(worker_id, results_queue):
            """Worker function for database stress testing"""
            worker_results = []

            for i in range(50):  # 50 queries per worker
                try:
                    start_time = time.time()
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()

                        # Mix of different query types
                        if i % 3 == 0:
                            cursor.execute("SELECT COUNT(*) FROM devices")
                        elif i % 3 == 1:
                            cursor.execute("SELECT * FROM devices LIMIT 10")
                        else:
                            cursor.execute("SELECT * FROM monitoring_data ORDER BY timestamp DESC LIMIT 5")

                        cursor.fetchall()

                    query_time = (time.time() - start_time) * 1000
                    worker_results.append({
                        'worker_id': worker_id,
                        'query_id': i,
                        'query_time_ms': query_time,
                        'success': True
                    })

                except Exception as e:
                    worker_results.append({
                        'worker_id': worker_id,
                        'query_id': i,
                        'error': str(e),
                        'success': False
                    })

            results_queue.extend(worker_results)

        # Run multiple concurrent database workers
        results_queue = []
        threads = []

        start_time = time.time()

        for worker_id in range(10):  # 10 concurrent database workers
            thread = threading.Thread(target=database_worker, args=(worker_id, results_queue))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        end_time = time.time()

        # Analyze database performance
        successful_queries = [r for r in results_queue if r.get('success', False)]
        query_times = [r['query_time_ms'] for r in successful_queries]

        if query_times:
            avg_query_time = statistics.mean(query_times)
            p95_query_time = statistics.quantiles(query_times, n=20)[18]
        else:
            avg_query_time = p95_query_time = 0

        success_rate = len(successful_queries) / len(results_queue) if results_queue else 0
        queries_per_second = len(results_queue) / (end_time - start_time)

        passed = (
            success_rate >= 0.95 and
            avg_query_time <= 100 and
            p95_query_time <= 500
        )

        details = f"Success: {success_rate*100:.1f}%, QPS: {queries_per_second:.1f}, Avg: {avg_query_time:.1f}ms"

        self.log_test('database', 'Database concurrent load', passed, details, {
            'success_rate': success_rate,
            'avg_query_time_ms': avg_query_time,
            'p95_query_time_ms': p95_query_time,
            'queries_per_second': queries_per_second
        })

    def run_all_load_tests(self):
        """Run complete load and stress testing suite"""
        print(f"{self.colors['purple']}🚀 HomeNetMon Load and Stress Testing Suite{self.colors['reset']}")
        print(f"Phase 5.2: Production load validation")
        print(f"Target: {self.base_url}")
        print("=" * 80)

        start_time = time.time()

        # Test server availability first
        try:
            response = requests.get(self.base_url, timeout=5)
            if response.status_code != 200:
                print(f"❌ Server not responding properly (Status: {response.status_code})")
                return False
        except Exception as e:
            print(f"❌ Cannot connect to server: {e}")
            return False

        print(f"✅ Server responding, beginning load tests...")

        # Run load scenarios in order of increasing intensity
        for scenario_name, config in self.test_scenarios.items():
            try:
                self.run_load_scenario(scenario_name, config)
                time.sleep(10)  # Recovery time between scenarios
            except Exception as e:
                self.logger.error(f"Scenario {scenario_name} failed: {e}")
                self.log_test(scenario_name, 'Load scenario execution', False, str(e))

        # Run specialized tests
        try:
            self.test_websocket_under_load()
        except Exception as e:
            self.logger.error(f"WebSocket load test failed: {e}")

        try:
            self.test_database_under_load()
        except Exception as e:
            self.logger.error(f"Database load test failed: {e}")

        # Generate comprehensive report
        self.generate_load_test_report(start_time)

    def generate_load_test_report(self, start_time):
        """Generate comprehensive load test report"""
        duration = time.time() - start_time

        print(f"\n{self.colors['purple']}📊 Load and Stress Testing Report{self.colors['reset']}")
        print("=" * 80)

        # Overall summary
        total_tests = len(self.test_results)
        passed_tests = sum(1 for test in self.test_results if test['passed'])
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0

        print(f"\n⏱️ Duration: {duration:.1f} seconds")
        print(f"📊 Tests Run: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {total_tests - passed_tests}")
        print(f"📈 Success Rate: {success_rate:.1f}%")

        # Performance summary
        print(f"\n🎯 Performance Analysis:")

        for scenario_name in self.test_scenarios.keys():
            scenario_results = [r for r in self.test_results if r['scenario'] == scenario_name]
            if scenario_results:
                result = scenario_results[0]
                metrics = result.get('metrics', {})

                status_color = self.colors['green'] if result['passed'] else self.colors['red']
                status = "PASS" if result['passed'] else "FAIL"

                print(f"  {status_color}{scenario_name.upper()}: {status}{self.colors['reset']}")
                if 'avg_response_time_ms' in metrics:
                    print(f"    📊 Avg Response: {metrics['avg_response_time_ms']:.0f}ms")
                    print(f"    📊 P95 Response: {metrics['p95_response_time_ms']:.0f}ms")
                    print(f"    📊 Error Rate: {metrics['error_rate_percent']:.1f}%")
                    print(f"    📊 Requests/sec: {metrics['requests_per_second']:.1f}")

        # System resource analysis
        print(f"\n💻 System Resource Usage:")
        if self.performance_metrics:
            max_cpu = 0
            max_memory = 0

            for scenario_data in self.performance_metrics:
                for sample in scenario_data['monitoring_data']:
                    max_cpu = max(max_cpu, sample.get('cpu_percent', 0))
                    max_memory = max(max_memory, sample.get('memory_used_mb', 0))

            cpu_status = "GOOD" if max_cpu <= 80 else "HIGH"
            memory_status = "GOOD" if max_memory <= 2048 else "HIGH"

            print(f"  🖥️  Max CPU Usage: {max_cpu:.1f}% ({cpu_status})")
            print(f"  💾 Max Memory Usage: {max_memory:.0f}MB ({memory_status})")

        # Final assessment
        print(f"\n💡 Phase 5.2 Assessment:")

        if success_rate >= 90:
            print(f"{self.colors['green']}🎉 EXCELLENT: Application handles production load very well!{self.colors['reset']}")
            print("✅ Ready for production deployment")
        elif success_rate >= 75:
            print(f"{self.colors['yellow']}⚠️ GOOD: Application performs well under most load conditions{self.colors['reset']}")
            print("⚠️ Consider optimizations for peak load scenarios")
        else:
            print(f"{self.colors['red']}❌ NEEDS IMPROVEMENT: Performance issues under load{self.colors['reset']}")
            print("🚨 Requires optimization before production deployment")

        # Phase completion status
        if success_rate >= 80:
            print(f"\n{self.colors['green']}✅ Phase 5.2: Load and stress testing - COMPLETED{self.colors['reset']}")
        else:
            print(f"\n{self.colors['red']}❌ Phase 5.2: Load and stress testing - REQUIRES OPTIMIZATION{self.colors['reset']}")

        # Save detailed report
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'success_rate': success_rate,
            'test_results': self.test_results,
            'performance_metrics': self.performance_metrics,
            'thresholds': self.thresholds
        }

        with open('load_stress_test_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)

        print(f"\n📄 Detailed report saved to: load_stress_test_report.json")
        print(f"📋 Test log saved to: load_stress_test_results.log")

def main():
    """Main load testing execution"""
    print(f"🔥 COMPREHENSIVE LOAD AND STRESS TESTING SUITE")
    print(f"📊 Phase 5.2: Production load validation")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

    # Verify server is running
    try:
        response = requests.get("http://geekom1:5000", timeout=5)
        print(f"✅ Server is running (Status: {response.status_code})")
    except Exception as e:
        print(f"❌ Server connection failed: {e}")
        print("Please ensure the HomeNetMon server is running before testing")
        sys.exit(1)

    # Check system requirements
    try:
        import psutil
        print(f"✅ System monitoring available")
    except ImportError:
        print(f"⚠️ psutil not available - system monitoring disabled")

    # Run comprehensive load tests
    test_suite = LoadStressTestSuite()
    test_suite.run_all_load_tests()

if __name__ == "__main__":
    main()