#!/usr/bin/env python3
"""
Direct test of Analytics page API endpoints and functionality
"""

import requests
import json
import time
import urllib3
from urllib.parse import urljoin

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AnalyticsPageTester:
    def __init__(self, base_url="http://geekom1:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.timeout = 10
        self.results = []

    def log_result(self, test_name, status, message, details=""):
        """Log a test result"""
        result = {
            'test': test_name,
            'status': status,  # 'PASS', 'FAIL', 'WARNING', 'INFO'
            'message': message,
            'details': details
        }
        self.results.append(result)
        print(f"[{status}] {test_name}: {message}")
        if details:
            print(f"    Details: {details}")

    def test_page_accessibility(self):
        """Test if the analytics page is accessible"""
        print("\n=== Testing Analytics Page Accessibility ===")

        try:
            response = self.session.get(f"{self.base_url}/analytics")
            if response.status_code == 200:
                self.log_result("Analytics Page Access", "PASS", f"Page accessible (HTTP {response.status_code})")
                return True
            else:
                self.log_result("Analytics Page Access", "FAIL", f"Page not accessible (HTTP {response.status_code})")
                return False
        except Exception as e:
            self.log_result("Analytics Page Access", "FAIL", f"Connection error: {str(e)}")
            return False

    def test_api_endpoints(self):
        """Test analytics-related API endpoints"""
        print("\n=== Testing Analytics API Endpoints ===")

        endpoints = [
            # Core analytics endpoints
            {"path": "/api/analytics/overview", "method": "GET", "name": "Overview Data"},
            {"path": "/api/analytics/performance", "method": "GET", "name": "Performance Data"},
            {"path": "/api/analytics/devices", "method": "GET", "name": "Device Analytics"},
            {"path": "/api/analytics/bandwidth", "method": "GET", "name": "Bandwidth Data"},

            # Monitoring endpoints used by analytics
            {"path": "/api/monitoring/alerts", "method": "GET", "name": "Alerts Data"},
            {"path": "/api/devices", "method": "GET", "name": "Devices Data"},
            {"path": "/api/monitoring/summary", "method": "GET", "name": "Monitoring Summary"},

            # Speed test endpoints
            {"path": "/api/speedtest/status", "method": "GET", "name": "Speed Test Status"},
            {"path": "/api/speedtest/run", "method": "POST", "name": "Speed Test Start"},
            {"path": "/api/speedtest/cancel", "method": "POST", "name": "Speed Test Cancel"},

            # Performance endpoints
            {"path": "/api/performance/dashboard", "method": "GET", "name": "Performance Dashboard"},
            {"path": "/api/performance/trends", "method": "GET", "name": "Performance Trends"},
        ]

        for endpoint in endpoints:
            try:
                url = urljoin(self.base_url, endpoint["path"])

                if endpoint["method"] == "GET":
                    response = self.session.get(url)
                elif endpoint["method"] == "POST":
                    # For POST endpoints, send minimal data
                    response = self.session.post(url, json={})

                if response.status_code in [200, 201]:
                    self.log_result(f"API: {endpoint['name']}", "PASS", f"Endpoint working (HTTP {response.status_code})")
                elif response.status_code in [404, 405]:
                    self.log_result(f"API: {endpoint['name']}", "WARNING", f"Endpoint not found/allowed (HTTP {response.status_code})")
                elif response.status_code in [400, 401, 403]:
                    self.log_result(f"API: {endpoint['name']}", "WARNING", f"Client error (HTTP {response.status_code}) - endpoint exists but needs auth/data")
                else:
                    self.log_result(f"API: {endpoint['name']}", "FAIL", f"Server error (HTTP {response.status_code})")

            except Exception as e:
                self.log_result(f"API: {endpoint['name']}", "FAIL", f"Request failed: {str(e)}")

    def test_analytics_data_structure(self):
        """Test the structure of analytics data"""
        print("\n=== Testing Analytics Data Structure ===")

        # Test device data structure
        try:
            response = self.session.get(f"{self.base_url}/api/devices")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    device = data[0]
                    required_fields = ['id', 'name', 'ip', 'status']
                    missing_fields = [field for field in required_fields if field not in device]

                    if not missing_fields:
                        self.log_result("Device Data Structure", "PASS", f"Valid structure with {len(data)} devices")
                    else:
                        self.log_result("Device Data Structure", "WARNING", f"Missing fields: {missing_fields}")
                else:
                    self.log_result("Device Data Structure", "WARNING", "No device data or invalid format")
            else:
                self.log_result("Device Data Structure", "FAIL", f"Could not fetch device data (HTTP {response.status_code})")
        except Exception as e:
            self.log_result("Device Data Structure", "FAIL", f"Error testing device data: {str(e)}")

    def test_javascript_functions(self):
        """Test if key JavaScript functions are present in the page"""
        print("\n=== Testing JavaScript Functions ===")

        try:
            response = self.session.get(f"{self.base_url}/analytics")
            if response.status_code == 200:
                html_content = response.text

                functions_to_check = [
                    "loadAllAnalytics",
                    "runSpeedTest",
                    "cancelSpeedTest",
                    "updateDeviceTypesChart",
                    "updateHourlyPatternChart",
                    "loadBandwidthAnalytics",
                    "showToast"
                ]

                for func_name in functions_to_check:
                    if func_name in html_content:
                        self.log_result(f"JS Function: {func_name}", "PASS", "Function found in page")
                    else:
                        self.log_result(f"JS Function: {func_name}", "WARNING", "Function not found in page source")

        except Exception as e:
            self.log_result("JavaScript Functions", "FAIL", f"Error checking JavaScript: {str(e)}")

    def test_button_elements(self):
        """Test if button elements are present in the HTML"""
        print("\n=== Testing Button Elements ===")

        try:
            response = self.session.get(f"{self.base_url}/analytics")
            if response.status_code == 200:
                html_content = response.text

                button_tests = [
                    {"name": "Refresh Analytics", "selector": "refresh-analytics", "type": "id"},
                    {"name": "Speed Test Run", "selector": "speedtest-btn", "type": "id"},
                    {"name": "Speed Test Cancel", "selector": "cancel-speedtest-btn", "type": "id"},
                    {"name": "Refresh Rating", "selector": "refresh-rating-btn", "type": "id"},
                    {"name": "Tab Navigation", "selector": "data-bs-target", "type": "attribute"},
                    {"name": "Time Range Controls", "selector": "global-time-range", "type": "name"},
                    {"name": "Clear Filters", "selector": "clear-filters", "type": "id"},
                ]

                for button_test in button_tests:
                    if button_test["type"] == "id":
                        pattern = f'id="{button_test["selector"]}"'
                    elif button_test["type"] == "name":
                        pattern = f'name="{button_test["selector"]}"'
                    elif button_test["type"] == "attribute":
                        pattern = button_test["selector"]

                    if pattern in html_content:
                        self.log_result(f"Button: {button_test['name']}", "PASS", "Element found in HTML")
                    else:
                        self.log_result(f"Button: {button_test['name']}", "WARNING", "Element not found in HTML")

        except Exception as e:
            self.log_result("Button Elements", "FAIL", f"Error checking button elements: {str(e)}")

    def test_chart_dependencies(self):
        """Test if chart libraries are loaded"""
        print("\n=== Testing Chart Dependencies ===")

        try:
            response = self.session.get(f"{self.base_url}/analytics")
            if response.status_code == 200:
                html_content = response.text

                chart_tests = [
                    {"name": "Chart.js Library", "pattern": "chart.js"},
                    {"name": "Canvas Elements", "pattern": "<canvas"},
                    {"name": "Chart Containers", "pattern": "chart-container"},
                    {"name": "Bootstrap JS", "pattern": "bootstrap"},
                ]

                for chart_test in chart_tests:
                    if chart_test["pattern"].lower() in html_content.lower():
                        self.log_result(f"Chart: {chart_test['name']}", "PASS", "Component found")
                    else:
                        self.log_result(f"Chart: {chart_test['name']}", "WARNING", "Component not found")

        except Exception as e:
            self.log_result("Chart Dependencies", "FAIL", f"Error checking chart dependencies: {str(e)}")

    def test_websocket_endpoint(self):
        """Test WebSocket connectivity (basic test)"""
        print("\n=== Testing WebSocket Support ===")

        try:
            # Test the main page to see if WebSocket initialization is present
            response = self.session.get(f"{self.base_url}/analytics")
            if response.status_code == 200:
                html_content = response.text

                if "socket.io" in html_content.lower() or "websocket" in html_content.lower():
                    self.log_result("WebSocket Support", "PASS", "WebSocket code found in page")
                else:
                    self.log_result("WebSocket Support", "WARNING", "WebSocket code not found")
            else:
                self.log_result("WebSocket Support", "FAIL", "Could not test WebSocket support")

        except Exception as e:
            self.log_result("WebSocket Support", "FAIL", f"Error testing WebSocket: {str(e)}")

    def run_all_tests(self):
        """Run all analytics page tests"""
        print("=" * 60)
        print("ANALYTICS PAGE FUNCTIONALITY TEST SUITE")
        print("=" * 60)

        # Test server accessibility first
        if not self.test_page_accessibility():
            print("\n❌ Server not accessible. Cannot continue with tests.")
            return False

        # Run all test categories
        self.test_api_endpoints()
        self.test_analytics_data_structure()
        self.test_javascript_functions()
        self.test_button_elements()
        self.test_chart_dependencies()
        self.test_websocket_endpoint()

        # Summarize results
        self.print_summary()
        return True

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)

        pass_count = len([r for r in self.results if r['status'] == 'PASS'])
        fail_count = len([r for r in self.results if r['status'] == 'FAIL'])
        warning_count = len([r for r in self.results if r['status'] == 'WARNING'])
        total_count = len(self.results)

        print(f"Total Tests: {total_count}")
        print(f"✅ Passed: {pass_count}")
        print(f"⚠️  Warnings: {warning_count}")
        print(f"❌ Failed: {fail_count}")

        if fail_count > 0:
            print(f"\n❌ FAILED TESTS:")
            for result in self.results:
                if result['status'] == 'FAIL':
                    print(f"  - {result['test']}: {result['message']}")

        if warning_count > 0:
            print(f"\n⚠️  WARNING TESTS:")
            for result in self.results:
                if result['status'] == 'WARNING':
                    print(f"  - {result['test']}: {result['message']}")

        print("\n" + "=" * 60)

if __name__ == '__main__':
    tester = AnalyticsPageTester()
    tester.run_all_tests()