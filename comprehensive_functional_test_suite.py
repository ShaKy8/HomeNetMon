#!/usr/bin/env python3
"""
Comprehensive Functional Test Suite for HomeNetMon
Phase 5.1: End-to-end testing of all critical functionality

Tests all fixes applied in previous phases:
- Authentication system functionality
- CSRF protection validation
- JavaScript functionality verification
- API endpoint testing
- Database operation validation
- Real-time features testing
- Form submission testing
- Security feature verification
"""

import os
import sys
import json
import time
import sqlite3
import requests
import logging
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin
import concurrent.futures
from bs4 import BeautifulSoup
import socketio

class ComprehensiveFunctionalTestSuite:
    def __init__(self, base_url="http://geekom1:5000", db_path="homeNetMon.db"):
        self.base_url = base_url
        self.db_path = Path(db_path)
        self.session = requests.Session()
        self.test_results = []
        self.total_tests = 0
        self.passed_tests = 0

        # Test categories
        self.test_categories = {
            'authentication': [],
            'csrf_protection': [],
            'javascript_functionality': [],
            'api_endpoints': [],
            'database_operations': [],
            'websocket_features': [],
            'form_submissions': [],
            'security_features': [],
            'performance_verification': []
        }

        # Color codes for output
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
                logging.FileHandler('functional_test_results.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def log_test(self, category, test_name, passed, details="", critical=False):
        """Log test result"""
        self.total_tests += 1
        if passed:
            self.passed_tests += 1

        result = {
            'category': category,
            'test_name': test_name,
            'passed': passed,
            'details': details,
            'critical': critical,
            'timestamp': datetime.now().isoformat()
        }

        self.test_results.append(result)
        self.test_categories[category].append(result)

        # Console output
        status_color = self.colors['green'] if passed else self.colors['red']
        status_icon = '✅' if passed else '❌'
        critical_mark = ' 🚨 CRITICAL' if critical else ''

        print(f"{status_color}{status_icon} {category.upper()}: {test_name}{critical_mark}{self.colors['reset']}")
        if details:
            print(f"   📝 {details}")

    def get_csrf_token(self, url_path="/"):
        """Get CSRF token from a page"""
        try:
            response = self.session.get(urljoin(self.base_url, url_path))
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                csrf_input = soup.find('input', {'name': 'csrf_token'})
                if csrf_input:
                    return csrf_input.get('value')

                # Try to get from meta tag
                csrf_meta = soup.find('meta', {'name': 'csrf-token'})
                if csrf_meta:
                    return csrf_meta.get('content')

                # Try to get from cookie
                csrf_cookie = response.cookies.get('csrf_token')
                if csrf_cookie:
                    return csrf_cookie

            return None
        except Exception as e:
            self.logger.error(f"Error getting CSRF token: {e}")
            return None

    def test_authentication_system(self):
        """Test authentication system functionality"""
        print(f"\n{self.colors['cyan']}🔐 Testing Authentication System{self.colors['reset']}")

        # Test 1: Access to public pages (should work)
        try:
            response = self.session.get(self.base_url)
            passed = response.status_code == 200
            self.log_test('authentication', 'Public page access', passed,
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test('authentication', 'Public page access', False, str(e), critical=True)

        # Test 2: Access to protected pages (should redirect to login or require auth)
        protected_endpoints = ['/settings', '/analytics', '/security', '/escalation-rules', '/dashboard/full']

        for endpoint in protected_endpoints:
            try:
                response = self.session.get(urljoin(self.base_url, endpoint))
                # Should be redirected or return 401/403
                passed = response.status_code in [302, 401, 403] or 'login' in response.url.lower()
                self.log_test('authentication', f'Protected endpoint: {endpoint}', passed,
                             f"Status: {response.status_code}, URL: {response.url}")
            except Exception as e:
                self.log_test('authentication', f'Protected endpoint: {endpoint}', False, str(e))

        # Test 3: CSRF token endpoint accessibility
        try:
            response = self.session.get(urljoin(self.base_url, '/api/csrf-token'))
            passed = response.status_code in [200, 401, 403]  # Should be available but may require auth
            self.log_test('authentication', 'CSRF token endpoint', passed,
                         f"Status: {response.status_code}")
        except Exception as e:
            self.log_test('authentication', 'CSRF token endpoint', False, str(e))

    def test_csrf_protection(self):
        """Test CSRF protection on forms and API endpoints"""
        print(f"\n{self.colors['cyan']}🛡️ Testing CSRF Protection{self.colors['reset']}")

        # Test 1: GET CSRF token
        csrf_token = self.get_csrf_token()
        passed = csrf_token is not None
        self.log_test('csrf_protection', 'CSRF token retrieval', passed,
                     f"Token: {'Found' if csrf_token else 'Not found'}")

        # Test 2: Form submission without CSRF token (should fail)
        try:
            response = self.session.post(urljoin(self.base_url, '/api/devices/scan-now'))
            passed = response.status_code in [400, 403, 422]  # Should be rejected
            self.log_test('csrf_protection', 'Request without CSRF token', passed,
                         f"Status: {response.status_code} (should be rejected)")
        except Exception as e:
            self.log_test('csrf_protection', 'Request without CSRF token', False, str(e))

        # Test 3: Form submission with CSRF token (should succeed if authenticated)
        if csrf_token:
            try:
                headers = {'X-CSRF-Token': csrf_token}
                response = self.session.post(urljoin(self.base_url, '/api/devices/scan-now'),
                                           headers=headers)
                # May require authentication, but CSRF validation should pass
                passed = response.status_code not in [400, 403, 422] or 'csrf' not in response.text.lower()
                self.log_test('csrf_protection', 'Request with CSRF token', passed,
                             f"Status: {response.status_code}")
            except Exception as e:
                self.log_test('csrf_protection', 'Request with CSRF token', False, str(e))

        # Test 4: CSRF meta tag in pages
        test_pages = ['/dashboard', '/alerts', '/analytics', '/settings']
        for page in test_pages:
            try:
                response = self.session.get(urljoin(self.base_url, page))
                soup = BeautifulSoup(response.text, 'html.parser')
                has_csrf_meta = soup.find('meta', {'name': 'csrf-token'}) is not None
                has_csrf_input = soup.find('input', {'name': 'csrf_token'}) is not None
                passed = has_csrf_meta or has_csrf_input
                self.log_test('csrf_protection', f'CSRF token in {page}', passed,
                             f"Meta: {has_csrf_meta}, Input: {has_csrf_input}")
            except Exception as e:
                self.log_test('csrf_protection', f'CSRF token in {page}', False, str(e))

    def test_javascript_functionality(self):
        """Test JavaScript functionality on pages"""
        print(f"\n{self.colors['cyan']}🔧 Testing JavaScript Functionality{self.colors['reset']}")

        # Test 1: Check for JavaScript errors in page source
        test_pages = ['/', '/dashboard', '/alerts', '/analytics', '/devices', '/topology']

        for page in test_pages:
            try:
                response = self.session.get(urljoin(self.base_url, page))
                soup = BeautifulSoup(response.text, 'html.parser')

                # Check for script tags
                scripts = soup.find_all('script')
                has_scripts = len(scripts) > 0

                # Check for potential JavaScript errors in HTML
                has_js_errors = any([
                    '</script>' in script.get_text() if script.get_text() else False
                    for script in scripts
                ])

                # Check for proper script structure
                has_proper_structure = True
                for script in scripts:
                    if script.get('src'):
                        continue  # External scripts are OK
                    text = script.get_text()
                    if text and ('</script>' in text or '<script>' in text):
                        has_proper_structure = False
                        break

                passed = has_scripts and not has_js_errors and has_proper_structure
                self.log_test('javascript_functionality', f'Script structure in {page}', passed,
                             f"Scripts: {len(scripts)}, Errors: {has_js_errors}, Structure: {has_proper_structure}")

            except Exception as e:
                self.log_test('javascript_functionality', f'Script structure in {page}', False, str(e))

        # Test 2: Check for specific JavaScript functionality indicators
        try:
            response = self.session.get(urljoin(self.base_url, '/analytics'))
            soup = BeautifulSoup(response.text, 'html.parser')

            # Look for Chart.js or other JavaScript libraries
            has_chart_js = 'chart.js' in response.text.lower() or 'chart' in response.text.lower()
            has_socket_io = 'socket.io' in response.text.lower()
            has_event_listeners = 'addEventListener' in response.text or 'onclick' in response.text.lower()

            passed = has_chart_js or has_socket_io or has_event_listeners
            self.log_test('javascript_functionality', 'Analytics page JS features', passed,
                         f"Charts: {has_chart_js}, SocketIO: {has_socket_io}, Events: {has_event_listeners}")

        except Exception as e:
            self.log_test('javascript_functionality', 'Analytics page JS features', False, str(e))

    def test_api_endpoints(self):
        """Test critical API endpoints"""
        print(f"\n{self.colors['cyan']}🔌 Testing API Endpoints{self.colors['reset']}")

        # Critical API endpoints to test
        api_endpoints = [
            ('/api/devices', 'GET'),
            ('/api/monitoring/alerts', 'GET'),
            ('/api/monitoring/summary', 'GET'),
            ('/api/performance/metrics', 'GET'),
            ('/api/health', 'GET'),
            ('/api/system/info', 'GET'),
            ('/api/csrf-token', 'GET')
        ]

        for endpoint, method in api_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                if method == 'GET':
                    response = self.session.get(url)
                else:
                    response = self.session.request(method, url)

                # API should return valid response (200, 401, 403 are acceptable)
                passed = response.status_code in [200, 401, 403]

                # Try to parse JSON if 200
                is_json = False
                if response.status_code == 200:
                    try:
                        data = response.json()
                        is_json = True
                    except:
                        pass

                self.log_test('api_endpoints', f'{method} {endpoint}', passed,
                             f"Status: {response.status_code}, JSON: {is_json}")

            except Exception as e:
                self.log_test('api_endpoints', f'{method} {endpoint}', False, str(e))

        # Test POST endpoints that require CSRF
        csrf_token = self.get_csrf_token()
        if csrf_token:
            post_endpoints = [
                '/api/devices/scan-now',
                '/api/monitoring/alerts/resolve-all'
            ]

            for endpoint in post_endpoints:
                try:
                    headers = {'X-CSRF-Token': csrf_token, 'Content-Type': 'application/json'}
                    response = self.session.post(urljoin(self.base_url, endpoint), headers=headers)

                    # Should not fail due to CSRF (may fail due to auth or other reasons)
                    passed = response.status_code not in [400, 403, 422] or 'csrf' not in response.text.lower()
                    self.log_test('api_endpoints', f'POST {endpoint} with CSRF', passed,
                                 f"Status: {response.status_code}")

                except Exception as e:
                    self.log_test('api_endpoints', f'POST {endpoint} with CSRF', False, str(e))

    def test_database_operations(self):
        """Test database operations and optimizations"""
        print(f"\n{self.colors['cyan']}💾 Testing Database Operations{self.colors['reset']}")

        # Test 1: Database file exists and accessible
        try:
            passed = self.db_path.exists()
            size_mb = self.db_path.stat().st_size / (1024 * 1024) if passed else 0
            self.log_test('database_operations', 'Database file exists', passed,
                         f"Size: {size_mb:.1f}MB" if passed else "File not found")
        except Exception as e:
            self.log_test('database_operations', 'Database file exists', False, str(e), critical=True)

        # Test 2: Database connectivity and basic operations
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Test basic query
                cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
                table_count = cursor.fetchone()[0]
                passed = table_count > 0
                self.log_test('database_operations', 'Database connectivity', passed,
                             f"Tables: {table_count}")

                # Test critical tables exist
                critical_tables = ['devices', 'monitoring_data', 'alerts', 'performance_metrics']
                for table in critical_tables:
                    cursor.execute(f"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='{table}'")
                    exists = cursor.fetchone()[0] > 0
                    self.log_test('database_operations', f'Table {table} exists', exists)

        except Exception as e:
            self.log_test('database_operations', 'Database connectivity', False, str(e), critical=True)

        # Test 3: Database performance optimizations
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Check WAL mode
                cursor.execute("PRAGMA journal_mode")
                journal_mode = cursor.fetchone()[0]
                wal_enabled = journal_mode.upper() == 'WAL'
                self.log_test('database_operations', 'WAL mode enabled', wal_enabled,
                             f"Mode: {journal_mode}")

                # Check indexes
                cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index'")
                index_count = cursor.fetchone()[0]
                has_indexes = index_count > 5  # Should have performance indexes
                self.log_test('database_operations', 'Performance indexes', has_indexes,
                             f"Indexes: {index_count}")

                # Test query performance
                start_time = time.time()
                cursor.execute("SELECT COUNT(*) FROM devices")
                query_time_ms = (time.time() - start_time) * 1000
                fast_queries = query_time_ms < 100  # Should be under 100ms
                self.log_test('database_operations', 'Query performance', fast_queries,
                             f"Time: {query_time_ms:.2f}ms")

        except Exception as e:
            self.log_test('database_operations', 'Database optimizations', False, str(e))

    def test_websocket_features(self):
        """Test WebSocket real-time features"""
        print(f"\n{self.colors['cyan']}🔄 Testing WebSocket Features{self.colors['reset']}")

        # Test 1: WebSocket endpoint accessibility
        try:
            # Try to connect to Socket.IO
            sio = socketio.SimpleClient()
            connected = False

            try:
                sio.connect(self.base_url, timeout=5)
                connected = True
                sio.disconnect()
            except Exception:
                pass

            self.log_test('websocket_features', 'WebSocket connectivity', connected,
                         "Connected successfully" if connected else "Connection failed")

        except Exception as e:
            self.log_test('websocket_features', 'WebSocket connectivity', False, str(e))

        # Test 2: Check for Socket.IO client in pages
        try:
            response = self.session.get(self.base_url)
            has_socketio = 'socket.io' in response.text.lower()
            self.log_test('websocket_features', 'Socket.IO client loaded', has_socketio,
                         "Found in page" if has_socketio else "Not found in page")
        except Exception as e:
            self.log_test('websocket_features', 'Socket.IO client loaded', False, str(e))

    def test_form_submissions(self):
        """Test form submissions and validation"""
        print(f"\n{self.colors['cyan']}📝 Testing Form Submissions{self.colors['reset']}")

        # Test 1: Forms have proper CSRF protection
        form_pages = ['/settings', '/alerts', '/escalation-rules']

        for page in form_pages:
            try:
                response = self.session.get(urljoin(self.base_url, page))
                soup = BeautifulSoup(response.text, 'html.parser')

                forms = soup.find_all('form')
                forms_with_csrf = 0

                for form in forms:
                    has_csrf = form.find('input', {'name': 'csrf_token'}) is not None
                    if has_csrf:
                        forms_with_csrf += 1

                passed = len(forms) == 0 or forms_with_csrf > 0
                self.log_test('form_submissions', f'Forms in {page} have CSRF', passed,
                             f"Forms: {len(forms)}, With CSRF: {forms_with_csrf}")

            except Exception as e:
                self.log_test('form_submissions', f'Forms in {page} have CSRF', False, str(e))

    def test_security_features(self):
        """Test security features and headers"""
        print(f"\n{self.colors['cyan']}🔒 Testing Security Features{self.colors['reset']}")

        # Test 1: Security headers
        try:
            response = self.session.get(self.base_url)
            headers = response.headers

            security_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection'
            ]

            headers_present = 0
            for header in security_headers:
                if header in headers:
                    headers_present += 1

            passed = headers_present > 0
            self.log_test('security_features', 'Security headers present', passed,
                         f"{headers_present}/{len(security_headers)} headers found")

        except Exception as e:
            self.log_test('security_features', 'Security headers present', False, str(e))

        # Test 2: Input validation
        try:
            # Test with malicious input
            malicious_params = {'test': '<script>alert("xss")</script>'}
            response = self.session.get(urljoin(self.base_url, '/api/devices'), params=malicious_params)

            # Should not execute script or return unescaped content
            has_xss = '<script>' in response.text
            passed = not has_xss
            self.log_test('security_features', 'XSS protection', passed,
                         "Script tags filtered" if passed else "Potential XSS vulnerability")

        except Exception as e:
            self.log_test('security_features', 'XSS protection', False, str(e))

    def test_performance_verification(self):
        """Verify performance optimizations are working"""
        print(f"\n{self.colors['cyan']}⚡ Testing Performance Verification{self.colors['reset']}")

        # Test 1: Page load times
        test_pages = ['/', '/dashboard', '/analytics', '/devices']

        for page in test_pages:
            try:
                start_time = time.time()
                response = self.session.get(urljoin(self.base_url, page))
                load_time_ms = (time.time() - start_time) * 1000

                passed = load_time_ms < 2000  # Should load under 2 seconds
                self.log_test('performance_verification', f'Page load time {page}', passed,
                             f"Time: {load_time_ms:.0f}ms")

            except Exception as e:
                self.log_test('performance_verification', f'Page load time {page}', False, str(e))

        # Test 2: API response times
        api_tests = ['/api/devices', '/api/monitoring/summary', '/api/health']

        for api in api_tests:
            try:
                start_time = time.time()
                response = self.session.get(urljoin(self.base_url, api))
                response_time_ms = (time.time() - start_time) * 1000

                passed = response_time_ms < 500  # Should respond under 500ms
                self.log_test('performance_verification', f'API response time {api}', passed,
                             f"Time: {response_time_ms:.0f}ms")

            except Exception as e:
                self.log_test('performance_verification', f'API response time {api}', False, str(e))

        # Test 3: Compression
        try:
            headers = {'Accept-Encoding': 'gzip, deflate'}
            response = self.session.get(self.base_url, headers=headers)

            is_compressed = 'gzip' in response.headers.get('Content-Encoding', '') or \
                           'deflate' in response.headers.get('Content-Encoding', '')

            self.log_test('performance_verification', 'Response compression', is_compressed,
                         f"Encoding: {response.headers.get('Content-Encoding', 'none')}")

        except Exception as e:
            self.log_test('performance_verification', 'Response compression', False, str(e))

    def run_all_tests(self):
        """Run complete functional test suite"""
        print(f"{self.colors['purple']}🚀 HomeNetMon Comprehensive Functional Test Suite{self.colors['reset']}")
        print(f"Phase 5.1: Testing all applied fixes and optimizations")
        print(f"Target: {self.base_url}")
        print(f"Database: {self.db_path}")
        print("=" * 80)

        start_time = time.time()

        # Run all test categories
        test_methods = [
            self.test_authentication_system,
            self.test_csrf_protection,
            self.test_javascript_functionality,
            self.test_api_endpoints,
            self.test_database_operations,
            self.test_websocket_features,
            self.test_form_submissions,
            self.test_security_features,
            self.test_performance_verification
        ]

        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                self.logger.error(f"Test method {test_method.__name__} failed: {e}")

        # Generate comprehensive report
        self.generate_final_report(start_time)

    def generate_final_report(self, start_time):
        """Generate comprehensive test report"""
        duration = time.time() - start_time

        print(f"\n{self.colors['purple']}📊 Comprehensive Functional Test Report{self.colors['reset']}")
        print("=" * 80)

        # Overall summary
        success_rate = (self.passed_tests / self.total_tests * 100) if self.total_tests > 0 else 0
        print(f"\n⏱️ Duration: {duration:.1f} seconds")
        print(f"📊 Tests Run: {self.total_tests}")
        print(f"✅ Passed: {self.passed_tests}")
        print(f"❌ Failed: {self.total_tests - self.passed_tests}")
        print(f"📈 Success Rate: {success_rate:.1f}%")

        # Category breakdown
        print(f"\n📋 Category Breakdown:")
        for category, tests in self.test_categories.items():
            if tests:
                category_passed = sum(1 for test in tests if test['passed'])
                category_total = len(tests)
                category_rate = (category_passed / category_total * 100) if category_total > 0 else 0

                status_color = self.colors['green'] if category_rate >= 80 else \
                              self.colors['yellow'] if category_rate >= 60 else self.colors['red']

                print(f"  {status_color}{category.replace('_', ' ').title()}: {category_passed}/{category_total} ({category_rate:.1f}%){self.colors['reset']}")

        # Critical failures
        critical_failures = [test for test in self.test_results if not test['passed'] and test.get('critical', False)]
        if critical_failures:
            print(f"\n{self.colors['red']}🚨 Critical Failures:{self.colors['reset']}")
            for failure in critical_failures:
                print(f"  ❌ {failure['category']}: {failure['test_name']}")
                if failure['details']:
                    print(f"     📝 {failure['details']}")

        # Recommendations
        print(f"\n💡 Phase 5.1 Assessment:")

        if success_rate >= 90:
            print(f"{self.colors['green']}🎉 EXCELLENT: All critical functionality working properly!{self.colors['reset']}")
            print("✅ Ready to proceed to Phase 5.2: Load and stress testing")
        elif success_rate >= 75:
            print(f"{self.colors['yellow']}⚠️ GOOD: Most functionality working, minor issues to address{self.colors['reset']}")
            print("⚠️ Address failures before proceeding to load testing")
        else:
            print(f"{self.colors['red']}❌ CRITICAL: Major functionality issues detected{self.colors['reset']}")
            print("🚨 Must fix critical issues before proceeding")

        # Phase completion status
        if success_rate >= 80:
            print(f"\n{self.colors['green']}✅ Phase 5.1: Comprehensive functional testing - COMPLETED{self.colors['reset']}")
        else:
            print(f"\n{self.colors['red']}❌ Phase 5.1: Comprehensive functional testing - REQUIRES ATTENTION{self.colors['reset']}")

        # Save detailed report
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'total_tests': self.total_tests,
            'passed_tests': self.passed_tests,
            'success_rate': success_rate,
            'categories': self.test_categories,
            'all_results': self.test_results
        }

        with open('comprehensive_functional_test_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)

        print(f"\n📄 Detailed report saved to: comprehensive_functional_test_report.json")
        print(f"📋 Test log saved to: functional_test_results.log")

def main():
    """Main test execution"""
    print(f"🧪 COMPREHENSIVE FUNCTIONAL TEST SUITE")
    print(f"📊 Phase 5.1: End-to-end verification of all fixes")
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

    # Run comprehensive tests
    test_suite = ComprehensiveFunctionalTestSuite()
    test_suite.run_all_tests()

if __name__ == "__main__":
    main()