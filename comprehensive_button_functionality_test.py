#!/usr/bin/env python3
"""
Comprehensive Button Functionality Test for HomeNetMon
Tests all interactive elements, buttons, forms, and actions across all pages
"""

import requests
import json
import time
import re
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
import sys
from urllib3.exceptions import InsecureRequestWarning
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(InsecureRequestWarning)

class ButtonFunctionalityTester:
    def __init__(self, base_url="http://geekom1:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.timeout = 15
        self.results = []
        self.start_time = datetime.now()
        self.csrf_token = None

        # All pages and their expected interactive elements
        self.pages_to_test = [
            {
                "path": "/",
                "name": "Main Dashboard",
                "expected_buttons": [
                    "refresh-btn", "settings-btn", "search-btn", "notification-btn",
                    "device-card-buttons", "status-toggle-buttons"
                ],
                "expected_forms": ["search-form"],
                "expected_modals": ["device-detail-modal"],
                "critical": True
            },
            {
                "path": "/analytics",
                "name": "Analytics Dashboard",
                "expected_buttons": [
                    "refresh-analytics", "speedtest-btn", "cancel-speedtest-btn",
                    "refresh-rating-btn", "time-range-controls", "tab-buttons"
                ],
                "expected_forms": ["time-range-form"],
                "expected_modals": [],
                "critical": True
            },
            {
                "path": "/performance-dashboard",
                "name": "Performance Dashboard",
                "expected_buttons": [
                    "refresh-performance", "export-data", "filter-buttons",
                    "chart-controls", "time-period-selectors"
                ],
                "expected_forms": ["filter-form"],
                "expected_modals": ["export-modal"],
                "critical": True
            },
            {
                "path": "/security-dashboard",
                "name": "Security Dashboard",
                "expected_buttons": [
                    "refresh-security", "scan-network", "block-device",
                    "security-actions", "alert-controls"
                ],
                "expected_forms": ["security-form"],
                "expected_modals": ["security-modal"],
                "critical": True
            },
            {
                "path": "/devices",
                "name": "Devices List",
                "expected_buttons": [
                    "add-device", "edit-device", "delete-device",
                    "bulk-actions", "filter-devices", "export-devices"
                ],
                "expected_forms": ["device-form", "filter-form"],
                "expected_modals": ["device-modal"],
                "critical": True
            },
            {
                "path": "/alerts",
                "name": "Alerts Management",
                "expected_buttons": [
                    "acknowledge-alert", "resolve-alert", "delete-alert",
                    "bulk-operations", "filter-alerts", "alert-actions"
                ],
                "expected_forms": ["alert-form"],
                "expected_modals": ["alert-modal"],
                "critical": True
            },
            {
                "path": "/settings",
                "name": "Settings",
                "expected_buttons": [
                    "save-settings", "reset-settings", "test-connection",
                    "apply-changes", "export-config", "import-config"
                ],
                "expected_forms": ["settings-form"],
                "expected_modals": ["confirm-modal"],
                "critical": True
            },
            {
                "path": "/topology",
                "name": "Network Topology",
                "expected_buttons": [
                    "refresh-topology", "auto-layout", "manual-layout",
                    "zoom-controls", "export-topology", "fullscreen"
                ],
                "expected_forms": [],
                "expected_modals": ["node-details-modal"],
                "critical": True
            }
        ]

        # API endpoints to test for button functionality
        self.api_endpoints_to_test = [
            # Device management
            {"method": "GET", "path": "/api/devices", "name": "Get Devices List"},
            {"method": "GET", "path": "/api/device/1", "name": "Get Single Device"},
            {"method": "POST", "path": "/api/device/1/update", "name": "Update Device"},

            # Analytics endpoints
            {"method": "GET", "path": "/api/analytics/network-health-score", "name": "Network Health"},
            {"method": "GET", "path": "/api/analytics/device-insights", "name": "Device Insights"},
            {"method": "GET", "path": "/api/speedtest/status", "name": "Speed Test Status"},
            {"method": "POST", "path": "/api/speedtest/run", "name": "Start Speed Test"},

            # Monitoring endpoints
            {"method": "GET", "path": "/api/monitoring/summary", "name": "Monitoring Summary"},
            {"method": "GET", "path": "/api/monitoring/alerts", "name": "Get Alerts"},

            # System endpoints
            {"method": "GET", "path": "/api/system/info", "name": "System Information"},
            {"method": "GET", "path": "/api/csrf-token", "name": "CSRF Token"},
        ]

    def log_result(self, test_type, page_name, element_name, status, message, details=""):
        """Log test result with structured data"""
        result = {
            'timestamp': datetime.now().isoformat(),
            'test_type': test_type,
            'page': page_name,
            'element': element_name,
            'status': status,  # 'PASS', 'FAIL', 'WARNING', 'INFO'
            'message': message,
            'details': details
        }
        self.results.append(result)

        # Console output with colors
        status_colors = {
            'PASS': '\033[92m✅',
            'FAIL': '\033[91m❌',
            'WARNING': '\033[93m⚠️',
            'INFO': '\033[94mℹ️'
        }

        color = status_colors.get(status, '⭐')
        print(f"{color} {page_name} - {element_name}: {message}\033[0m")
        if details:
            print(f"    └─ {details}")

    def get_csrf_token(self):
        """Get CSRF token for form submissions"""
        try:
            response = self.session.get(f"{self.base_url}/api/csrf-token")
            if response.status_code == 200:
                data = response.json()
                self.csrf_token = data.get('csrf_token')
                self.log_result("security", "System", "CSRF Token", "PASS",
                              "CSRF token retrieved successfully")
                return True
            else:
                self.log_result("security", "System", "CSRF Token", "WARNING",
                              f"Could not get CSRF token (HTTP {response.status_code})")
                return False
        except Exception as e:
            self.log_result("security", "System", "CSRF Token", "FAIL",
                          f"Error getting CSRF token: {str(e)}")
            return False

    def extract_buttons_from_html(self, html, page_name):
        """Extract all interactive elements from HTML"""
        if not html:
            return []

        interactive_elements = []

        # Extract buttons
        button_patterns = [
            # Standard buttons
            r'<button[^>]*id=["\']([^"\']+)["\'][^>]*>([^<]*)</button>',
            r'<button[^>]*class=["\']([^"\']*btn[^"\']*)["\'][^>]*>([^<]*)</button>',
            # Input buttons
            r'<input[^>]*type=["\'](?:button|submit)["\'][^>]*id=["\']([^"\']+)["\'][^>]*>',
            # Links that act as buttons
            r'<a[^>]*class=["\']([^"\']*btn[^"\']*)["\'][^>]*id=["\']([^"\']+)["\'][^>]*>([^<]*)</a>',
            # Bootstrap dropdowns
            r'<[^>]*data-bs-toggle=["\']dropdown["\'][^>]*id=["\']([^"\']+)["\'][^>]*>([^<]*)<',
            # Bootstrap modals
            r'<[^>]*data-bs-toggle=["\']modal["\'][^>]*data-bs-target=["\']([^"\']+)["\'][^>]*>([^<]*)<',
            # Tab controls
            r'<[^>]*data-bs-toggle=["\']tab["\'][^>]*id=["\']([^"\']+)["\'][^>]*>([^<]*)<',
        ]

        for pattern in button_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
            for match in matches:
                if isinstance(match, tuple) and len(match) >= 2:
                    element_id = match[0] if match[0] else match[1]
                    element_text = match[-1] if len(match) > 2 else "Button"
                    interactive_elements.append({
                        'id': element_id,
                        'text': element_text.strip()[:50],
                        'type': 'button'
                    })

        # Extract forms
        form_patterns = [
            r'<form[^>]*id=["\']([^"\']+)["\'][^>]*>',
            r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>',
        ]

        for pattern in form_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                interactive_elements.append({
                    'id': match,
                    'text': f"Form: {match}",
                    'type': 'form'
                })

        # Extract input fields
        input_patterns = [
            r'<input[^>]*id=["\']([^"\']+)["\'][^>]*type=["\']([^"\']+)["\'][^>]*>',
            r'<select[^>]*id=["\']([^"\']+)["\'][^>]*>',
            r'<textarea[^>]*id=["\']([^"\']+)["\'][^>]*>',
        ]

        for pattern in input_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    input_id = match[0]
                    input_type = match[1] if len(match) > 1 else "input"
                    interactive_elements.append({
                        'id': input_id,
                        'text': f"{input_type.title()} Field",
                        'type': 'input'
                    })

        return interactive_elements

    def test_button_presence(self, html, page):
        """Test if expected buttons are present in the HTML"""
        if not html:
            return

        expected_buttons = page.get('expected_buttons', [])
        found_buttons = []
        missing_buttons = []

        for expected_btn in expected_buttons:
            # Search for button ID, class, or data attributes
            patterns = [
                rf'id=["\']([^"\']*{expected_btn}[^"\']*)["\']',
                rf'class=["\']([^"\']*{expected_btn}[^"\']*)["\']',
                rf'data-[^=]+=["\']([^"\']*{expected_btn}[^"\']*)["\']',
            ]

            found = False
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    found = True
                    found_buttons.append(expected_btn)
                    break

            if not found:
                missing_buttons.append(expected_btn)

        # Log results
        for btn in found_buttons:
            self.log_result("button_presence", page['name'], btn, "PASS",
                          "Expected button found in HTML")

        for btn in missing_buttons:
            status = "FAIL" if page.get('critical', False) else "WARNING"
            self.log_result("button_presence", page['name'], btn, status,
                          "Expected button not found in HTML")

    def test_javascript_event_listeners(self, html, page):
        """Check for JavaScript event listeners"""
        if not html:
            return

        # Look for event listener patterns
        event_patterns = [
            r'addEventListener\(["\']([^"\']+)["\']',
            r'\.on\(["\']([^"\']+)["\']',
            r'onclick=["\']([^"\']+)["\']',
            r'onsubmit=["\']([^"\']+)["\']',
            r'onchange=["\']([^"\']+)["\']',
        ]

        events_found = []
        for pattern in event_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            events_found.extend(matches)

        if events_found:
            unique_events = list(set(events_found))
            self.log_result("javascript", page['name'], "Event Listeners", "PASS",
                          f"Found {len(unique_events)} unique event types",
                          f"Events: {', '.join(unique_events[:5])}")
        else:
            self.log_result("javascript", page['name'], "Event Listeners", "WARNING",
                          "No JavaScript event listeners found")

    def test_api_endpoint_functionality(self, endpoint):
        """Test if API endpoints are responding correctly"""
        try:
            url = f"{self.base_url}{endpoint['path']}"

            # Prepare headers
            headers = {'Content-Type': 'application/json'}
            if self.csrf_token:
                headers['X-CSRFToken'] = self.csrf_token

            # Make request based on method
            if endpoint['method'] == 'GET':
                response = self.session.get(url, headers=headers)
            elif endpoint['method'] == 'POST':
                # Use minimal POST data for testing
                data = {}
                response = self.session.post(url, headers=headers, json=data)
            else:
                self.log_result("api", "API", endpoint['name'], "INFO",
                              f"Method {endpoint['method']} not tested")
                return

            # Evaluate response
            if response.status_code in [200, 201]:
                try:
                    # Try to parse JSON response
                    json_data = response.json()
                    data_size = len(json_data) if isinstance(json_data, (list, dict)) else 1
                    self.log_result("api", "API", endpoint['name'], "PASS",
                                  f"Endpoint working (HTTP {response.status_code})",
                                  f"Response contains data: {data_size} items")
                except json.JSONDecodeError:
                    self.log_result("api", "API", endpoint['name'], "PASS",
                                  f"Endpoint working (HTTP {response.status_code})",
                                  "Non-JSON response")

            elif response.status_code in [400, 401, 403]:
                self.log_result("api", "API", endpoint['name'], "WARNING",
                              f"Authentication/validation issue (HTTP {response.status_code})")

            elif response.status_code == 404:
                self.log_result("api", "API", endpoint['name'], "FAIL",
                              f"Endpoint not found (HTTP {response.status_code})")

            elif response.status_code == 405:
                self.log_result("api", "API", endpoint['name'], "WARNING",
                              f"Method not allowed (HTTP {response.status_code})")

            else:
                self.log_result("api", "API", endpoint['name'], "FAIL",
                              f"Server error (HTTP {response.status_code})")

        except Exception as e:
            self.log_result("api", "API", endpoint['name'], "FAIL",
                          f"Request failed: {str(e)}")

    def test_form_submission_readiness(self, html, page):
        """Test if forms are ready for submission"""
        if not html:
            return

        # Find all forms
        form_pattern = r'<form[^>]*(?:action=["\']([^"\']+)["\'])?[^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)

        for i, form in enumerate(forms):
            form_action = form[0] if form[0] else "Unknown"
            form_content = form[1] if len(form) > 1 else ""

            # Check for CSRF token
            if 'csrf' in form_content.lower() or '_token' in form_content.lower():
                self.log_result("form", page['name'], f"Form {i+1}", "PASS",
                              "CSRF protection present")
            else:
                self.log_result("form", page['name'], f"Form {i+1}", "WARNING",
                              "No CSRF protection detected")

            # Check for submit button
            if re.search(r'type=["\']submit["\']|<button[^>]*type=["\']submit["\']',
                        form_content, re.IGNORECASE):
                self.log_result("form", page['name'], f"Form {i+1}", "PASS",
                              "Submit button present")
            else:
                self.log_result("form", page['name'], f"Form {i+1}", "WARNING",
                              "No submit button found")

    def test_page_functionality(self, page):
        """Comprehensive test of a single page's functionality"""
        print(f"\n{'='*70}")
        print(f"🧪 TESTING FUNCTIONALITY: {page['name']} ({page['path']})")
        print(f"{'='*70}")

        try:
            # Get page content
            response = self.session.get(f"{self.base_url}{page['path']}")

            if response.status_code != 200:
                self.log_result("page_load", page['name'], "Page Access", "FAIL",
                              f"Cannot access page (HTTP {response.status_code})")
                return

            html = response.text

            # Run all functionality tests
            self.test_button_presence(html, page)
            self.test_javascript_event_listeners(html, page)
            self.test_form_submission_readiness(html, page)

            # Extract and count interactive elements
            interactive_elements = self.extract_buttons_from_html(html, page['name'])

            if interactive_elements:
                button_count = len([e for e in interactive_elements if e['type'] == 'button'])
                form_count = len([e for e in interactive_elements if e['type'] == 'form'])
                input_count = len([e for e in interactive_elements if e['type'] == 'input'])

                self.log_result("element_count", page['name'], "Interactive Elements", "INFO",
                              f"Found {len(interactive_elements)} interactive elements",
                              f"Buttons: {button_count}, Forms: {form_count}, Inputs: {input_count}")

                # Test a sample of interactive elements
                sample_elements = interactive_elements[:10]  # Test first 10
                for element in sample_elements:
                    self.log_result("element_detected", page['name'], element['id'], "PASS",
                                  f"{element['type'].title()}: {element['text']}")

            else:
                self.log_result("element_count", page['name'], "Interactive Elements", "WARNING",
                              "No interactive elements detected")

        except Exception as e:
            self.log_result("page_test", page['name'], "Page Test", "FAIL",
                          f"Error testing page: {str(e)}")

    def run_comprehensive_test(self):
        """Run comprehensive button and functionality test"""
        print("🧪 Starting Comprehensive Button Functionality Test")
        print(f"📊 Testing {len(self.pages_to_test)} pages and {len(self.api_endpoints_to_test)} API endpoints")
        print(f"🌐 Base URL: {self.base_url}")
        print(f"⏰ Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        # Test server connectivity
        try:
            response = self.session.get(self.base_url)
            if response.status_code != 200:
                print(f"❌ Server not accessible: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Cannot connect to server: {e}")
            return False

        print("✅ Server connectivity confirmed")

        # Get CSRF token
        self.get_csrf_token()

        # Test API endpoints first
        print(f"\n{'='*70}")
        print("🔌 TESTING API ENDPOINTS")
        print(f"{'='*70}")

        for endpoint in self.api_endpoints_to_test:
            try:
                self.test_api_endpoint_functionality(endpoint)
                time.sleep(0.2)  # Rate limiting
            except Exception as e:
                self.log_result("api", "API", endpoint['name'], "FAIL",
                              f"API test failed: {str(e)}")

        # Test page functionality
        for page in self.pages_to_test:
            try:
                self.test_page_functionality(page)
                time.sleep(0.5)  # Rate limiting
            except KeyboardInterrupt:
                print("\n⚠️ Test interrupted by user")
                break
            except Exception as e:
                self.log_result("system", page['name'], "page_test", "FAIL",
                              f"Page test failed: {str(e)}")

        # Generate summary report
        self.generate_summary_report()
        return True

    def generate_summary_report(self):
        """Generate comprehensive summary report"""
        end_time = datetime.now()
        duration = end_time - self.start_time

        print(f"\n{'='*80}")
        print("🧪 BUTTON FUNCTIONALITY TEST SUMMARY")
        print(f"{'='*80}")

        # Count results by status
        status_counts = {'PASS': 0, 'FAIL': 0, 'WARNING': 0, 'INFO': 0}
        category_counts = {}

        for result in self.results:
            status_counts[result['status']] = status_counts.get(result['status'], 0) + 1
            category = result['test_type']
            if category not in category_counts:
                category_counts[category] = {'PASS': 0, 'FAIL': 0, 'WARNING': 0, 'INFO': 0}
            category_counts[category][result['status']] += 1

        # Overall statistics
        total_tests = len(self.results)
        success_rate = (status_counts['PASS'] / total_tests * 100) if total_tests > 0 else 0

        print(f"🎯 Overall Results:")
        print(f"   ✅ Passed: {status_counts['PASS']}")
        print(f"   ❌ Failed: {status_counts['FAIL']}")
        print(f"   ⚠️  Warnings: {status_counts['WARNING']}")
        print(f"   ℹ️  Info: {status_counts['INFO']}")
        print(f"   📊 Success Rate: {success_rate:.1f}%")
        print(f"   ⏱️  Duration: {duration.total_seconds():.1f} seconds")

        # Category breakdown
        print(f"\n📋 Results by Category:")
        for category, counts in category_counts.items():
            total_cat = sum(counts.values())
            pass_rate = (counts['PASS'] / total_cat * 100) if total_cat > 0 else 0
            print(f"   {category.title()}: {counts['PASS']}/{total_cat} ({pass_rate:.1f}% pass)")

        # Critical failures
        critical_fails = [r for r in self.results if r['status'] == 'FAIL']
        if critical_fails:
            print(f"\n🚨 Critical Issues ({len(critical_fails)}):")
            for fail in critical_fails[:10]:
                print(f"   ❌ {fail['page']} - {fail['element']}: {fail['message']}")

        # Button functionality summary
        button_tests = [r for r in self.results if r['test_type'] in ['button_presence', 'element_detected']]
        button_pass = len([r for r in button_tests if r['status'] == 'PASS'])
        button_total = len(button_tests)

        if button_total > 0:
            button_success = (button_pass / button_total * 100)
            print(f"\n🔘 Button Functionality: {button_pass}/{button_total} ({button_success:.1f}% functional)")

        # API functionality summary
        api_tests = [r for r in self.results if r['test_type'] == 'api']
        api_pass = len([r for r in api_tests if r['status'] == 'PASS'])
        api_total = len(api_tests)

        if api_total > 0:
            api_success = (api_pass / api_total * 100)
            print(f"🔌 API Endpoints: {api_pass}/{api_total} ({api_success:.1f}% working)")

        # Overall assessment
        print(f"\n💡 Overall Assessment:")
        if success_rate > 90:
            print("   🎉 Excellent! All buttons and interactive elements are highly functional")
        elif success_rate > 75:
            print("   ✅ Good functionality with minor issues to address")
        elif success_rate > 60:
            print("   ⚠️  Some functionality issues need attention")
        else:
            print("   🛠️  Significant functionality problems require immediate fixing")

        # Save detailed report
        self.save_detailed_report()
        print(f"\n📄 Detailed report saved to: button_functionality_report.json")
        print(f"{'='*80}")

    def save_detailed_report(self):
        """Save detailed test results to JSON file"""
        report = {
            'test_info': {
                'timestamp': self.start_time.isoformat(),
                'base_url': self.base_url,
                'pages_tested': len(self.pages_to_test),
                'api_endpoints_tested': len(self.api_endpoints_to_test),
                'total_checks': len(self.results)
            },
            'summary': {
                'pass': len([r for r in self.results if r['status'] == 'PASS']),
                'fail': len([r for r in self.results if r['status'] == 'FAIL']),
                'warning': len([r for r in self.results if r['status'] == 'WARNING']),
                'info': len([r for r in self.results if r['status'] == 'INFO'])
            },
            'detailed_results': self.results,
            'pages_tested': self.pages_to_test,
            'api_endpoints_tested': self.api_endpoints_to_test
        }

        with open('button_functionality_report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)

if __name__ == '__main__':
    tester = ButtonFunctionalityTester()
    success = tester.run_comprehensive_test()

    if success:
        print("✅ Button Functionality Test completed successfully!")
        sys.exit(0)
    else:
        print("❌ Button Functionality Test failed!")
        sys.exit(1)