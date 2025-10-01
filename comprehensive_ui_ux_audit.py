#!/usr/bin/env python3
"""
Comprehensive UI/UX Audit Tool for HomeNetMon
Tests all pages for accessibility, responsiveness, and functionality
"""

import requests
import json
import time
import re
from urllib.parse import urljoin
from datetime import datetime
import sys

class UIUXAuditor:
    def __init__(self, base_url="http://geekom1:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.timeout = 15
        self.results = []
        self.start_time = datetime.now()

        # All pages to test based on routes analysis
        self.pages = [
            {"path": "/", "name": "Main Dashboard", "type": "dashboard", "critical": True},
            {"path": "/dashboard/full", "name": "Full Dashboard", "type": "dashboard", "critical": True},
            {"path": "/analytics", "name": "Analytics Dashboard", "type": "analytics", "critical": True},
            {"path": "/performance-dashboard", "name": "Performance Dashboard", "type": "performance", "critical": True},
            {"path": "/ai-dashboard", "name": "AI Dashboard", "type": "ai", "critical": False},
            {"path": "/security-dashboard", "name": "Security Dashboard", "type": "security", "critical": True},
            {"path": "/security", "name": "Security Page", "type": "security", "critical": True},
            {"path": "/devices", "name": "Devices List", "type": "management", "critical": True},
            {"path": "/alerts", "name": "Alerts Management", "type": "management", "critical": True},
            {"path": "/notifications", "name": "Notifications", "type": "management", "critical": False},
            {"path": "/notifications/analytics", "name": "Notification Analytics", "type": "analytics", "critical": False},
            {"path": "/topology", "name": "Network Topology", "type": "visualization", "critical": True},
            {"path": "/network-map", "name": "Network Map", "type": "visualization", "critical": False},
            {"path": "/noc", "name": "NOC View", "type": "monitoring", "critical": True},
            {"path": "/settings", "name": "Settings", "type": "configuration", "critical": True},
            {"path": "/system-info", "name": "System Information", "type": "information", "critical": False},
            {"path": "/about", "name": "About Page", "type": "information", "critical": False},
        ]

        # UI/UX criteria to check
        self.ui_checks = [
            "responsive_meta_tag",
            "bootstrap_css",
            "bootstrap_js",
            "favicon",
            "page_title",
            "navigation_menu",
            "footer_present",
            "error_handling",
            "loading_states",
            "accessibility_attributes",
            "semantic_html",
            "color_contrast",
            "mobile_viewport"
        ]

    def log_result(self, test_type, page_name, check_name, status, message, details=""):
        """Log test result with structured data"""
        result = {
            'timestamp': datetime.now().isoformat(),
            'test_type': test_type,
            'page': page_name,
            'check': check_name,
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
        print(f"{color} {page_name} - {check_name}: {message}\033[0m")
        if details:
            print(f"    └─ {details}")

    def test_page_accessibility(self, page):
        """Test page accessibility and load performance"""
        try:
            start_time = time.time()
            response = self.session.get(f"{self.base_url}{page['path']}")
            load_time = time.time() - start_time

            if response.status_code == 200:
                self.log_result("accessibility", page['name'], "Page Load", "PASS",
                              f"Loaded in {load_time:.2f}s (HTTP {response.status_code})")

                html = response.text

                # Check page load performance
                if load_time < 2.0:
                    self.log_result("performance", page['name'], "Load Time", "PASS",
                                  f"Fast load ({load_time:.2f}s)")
                elif load_time < 5.0:
                    self.log_result("performance", page['name'], "Load Time", "WARNING",
                                  f"Slow load ({load_time:.2f}s)")
                else:
                    self.log_result("performance", page['name'], "Load Time", "FAIL",
                                  f"Very slow load ({load_time:.2f}s)")

                return html, True

            elif response.status_code in [401, 403]:
                self.log_result("accessibility", page['name'], "Page Load", "WARNING",
                              f"Authentication required (HTTP {response.status_code})")
                return None, False
            elif response.status_code == 404:
                self.log_result("accessibility", page['name'], "Page Load", "FAIL",
                              f"Page not found (HTTP {response.status_code})")
                return None, False
            else:
                self.log_result("accessibility", page['name'], "Page Load", "FAIL",
                              f"Server error (HTTP {response.status_code})")
                return None, False

        except Exception as e:
            self.log_result("accessibility", page['name'], "Page Load", "FAIL",
                          f"Connection error: {str(e)}")
            return None, False

    def check_responsive_design(self, html, page):
        """Check responsive design elements"""
        if not html:
            return

        checks = [
            ("viewport_meta", r'<meta[^>]*viewport[^>]*>', "Viewport meta tag present"),
            ("responsive_grid", r'(container|row|col-)', "Bootstrap grid classes found"),
            ("media_queries", r'@media|\.d-none|\.d-sm-|\.d-md-|\.d-lg-', "Responsive CSS classes"),
            ("mobile_nav", r'navbar-toggler|mobile-menu|hamburger', "Mobile navigation elements"),
        ]

        for check_name, pattern, description in checks:
            if re.search(pattern, html, re.IGNORECASE):
                self.log_result("responsive", page['name'], check_name, "PASS", description)
            else:
                self.log_result("responsive", page['name'], check_name, "WARNING",
                              f"Missing: {description}")

    def check_ui_framework(self, html, page):
        """Check UI framework implementation"""
        if not html:
            return

        checks = [
            ("bootstrap_css", r'bootstrap.*\.css', "Bootstrap CSS loaded"),
            ("bootstrap_js", r'bootstrap.*\.js', "Bootstrap JavaScript loaded"),
            ("chartjs", r'chart\.js|Chart\.js', "Chart.js library loaded"),
            ("socketio", r'socket\.io', "Socket.IO library loaded"),
            ("favicon", r'<link[^>]*icon[^>]*>', "Favicon present"),
            ("page_title", r'<title>[^<]+</title>', "Page title present"),
        ]

        for check_name, pattern, description in checks:
            if re.search(pattern, html, re.IGNORECASE):
                self.log_result("ui_framework", page['name'], check_name, "PASS", description)
            else:
                status = "FAIL" if check_name in ["bootstrap_css", "page_title"] else "WARNING"
                self.log_result("ui_framework", page['name'], check_name, status,
                              f"Missing: {description}")

    def check_navigation_consistency(self, html, page):
        """Check navigation menu consistency"""
        if not html:
            return

        nav_elements = [
            ("main_nav", r'<nav|navbar', "Main navigation present"),
            ("nav_links", r'href="/(?:dashboard|analytics|devices|alerts)', "Core nav links present"),
            ("brand_logo", r'navbar-brand|logo', "Brand/logo present"),
            ("user_menu", r'user.*menu|profile.*menu|logout', "User menu present"),
            ("search", r'search.*input|search.*form', "Search functionality"),
            ("breadcrumbs", r'breadcrumb|nav.*aria-label', "Breadcrumb navigation"),
        ]

        for check_name, pattern, description in nav_elements:
            if re.search(pattern, html, re.IGNORECASE):
                self.log_result("navigation", page['name'], check_name, "PASS", description)
            else:
                status = "WARNING" if check_name in ["search", "breadcrumbs"] else "FAIL"
                self.log_result("navigation", page['name'], check_name, status,
                              f"Missing: {description}")

    def check_interactive_elements(self, html, page):
        """Check for interactive elements and functionality"""
        if not html:
            return

        interactive_checks = [
            ("buttons", r'<button|btn-|<input[^>]*type=["\'](?:button|submit)', "Buttons present"),
            ("forms", r'<form', "Forms present"),
            ("modals", r'modal|data-bs-toggle.*modal', "Modal dialogs"),
            ("dropdowns", r'dropdown|data-bs-toggle.*dropdown', "Dropdown menus"),
            ("tabs", r'nav-tabs|tab-content|data-bs-toggle.*tab', "Tab navigation"),
            ("tooltips", r'tooltip|data-bs-toggle.*tooltip', "Tooltips/help text"),
            ("alerts", r'alert-|notification', "Alert/notification components"),
            ("loading", r'spinner|loading|progress', "Loading indicators"),
        ]

        for check_name, pattern, description in interactive_checks:
            matches = len(re.findall(pattern, html, re.IGNORECASE))
            if matches > 0:
                self.log_result("interactive", page['name'], check_name, "PASS",
                              f"{description} ({matches} found)")
            else:
                self.log_result("interactive", page['name'], check_name, "INFO",
                              f"No {description.lower()}")

    def check_accessibility_features(self, html, page):
        """Check accessibility features"""
        if not html:
            return

        a11y_checks = [
            ("alt_text", r'alt=', "Images with alt text"),
            ("aria_labels", r'aria-label|aria-labelledby|aria-describedby', "ARIA labels"),
            ("semantic_html", r'<(?:header|nav|main|section|article|aside|footer)', "Semantic HTML5"),
            ("skip_links", r'skip.*(?:content|navigation)', "Skip navigation links"),
            ("focus_indicators", r':focus|focus-visible', "Focus indicators"),
            ("color_only", r'sr-only|visually-hidden', "Screen reader text"),
        ]

        for check_name, pattern, description in a11y_checks:
            matches = len(re.findall(pattern, html, re.IGNORECASE))
            if matches > 0:
                self.log_result("accessibility", page['name'], check_name, "PASS",
                              f"{description} ({matches} found)")
            else:
                status = "WARNING" if check_name in ["skip_links", "color_only"] else "FAIL"
                self.log_result("accessibility", page['name'], check_name, status,
                              f"Missing: {description}")

    def check_performance_indicators(self, html, page):
        """Check for performance optimization indicators"""
        if not html:
            return

        perf_checks = [
            ("minified_css", r'\.min\.css', "Minified CSS"),
            ("minified_js", r'\.min\.js', "Minified JavaScript"),
            ("compressed_assets", r'\.gz|\.br', "Compressed assets"),
            ("cdn_usage", r'cdn\.', "CDN usage"),
            ("async_scripts", r'async|defer', "Async/defer scripts"),
            ("preload", r'preload|prefetch', "Resource preloading"),
        ]

        for check_name, pattern, description in perf_checks:
            matches = len(re.findall(pattern, html, re.IGNORECASE))
            if matches > 0:
                self.log_result("performance", page['name'], check_name, "PASS",
                              f"{description} ({matches} found)")
            else:
                self.log_result("performance", page['name'], check_name, "INFO",
                              f"No {description.lower()}")

    def check_security_headers(self, page):
        """Check security headers"""
        try:
            response = self.session.get(f"{self.base_url}{page['path']}")
            headers = response.headers

            security_headers = [
                ("content_type", "Content-Type"),
                ("xss_protection", "X-XSS-Protection"),
                ("content_type_options", "X-Content-Type-Options"),
                ("frame_options", "X-Frame-Options"),
                ("csp", "Content-Security-Policy"),
                ("hsts", "Strict-Transport-Security"),
            ]

            for check_name, header_name in security_headers:
                if header_name in headers:
                    self.log_result("security", page['name'], check_name, "PASS",
                                  f"{header_name}: {headers[header_name][:50]}...")
                else:
                    status = "WARNING" if header_name in ["Content-Security-Policy", "Strict-Transport-Security"] else "FAIL"
                    self.log_result("security", page['name'], check_name, status,
                                  f"Missing header: {header_name}")

        except Exception as e:
            self.log_result("security", page['name'], "headers_check", "FAIL",
                          f"Error checking headers: {str(e)}")

    def audit_single_page(self, page):
        """Perform complete audit of a single page"""
        print(f"\n{'='*60}")
        print(f"🔍 AUDITING: {page['name']} ({page['path']})")
        print(f"{'='*60}")

        # Test page accessibility and get HTML
        html, accessible = self.test_page_accessibility(page)

        if accessible and html:
            # Run all UI/UX checks
            self.check_responsive_design(html, page)
            self.check_ui_framework(html, page)
            self.check_navigation_consistency(html, page)
            self.check_interactive_elements(html, page)
            self.check_accessibility_features(html, page)
            self.check_performance_indicators(html, page)

        # Check security headers (works even if page isn't fully accessible)
        self.check_security_headers(page)

    def run_full_audit(self):
        """Run complete UI/UX audit on all pages"""
        print("🚀 Starting Comprehensive UI/UX Audit")
        print(f"📊 Testing {len(self.pages)} pages")
        print(f"🌐 Base URL: {self.base_url}")
        print(f"⏰ Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        # Test server connectivity first
        try:
            response = self.session.get(self.base_url)
            if response.status_code != 200:
                print(f"❌ Server not accessible: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Cannot connect to server: {e}")
            return False

        print("✅ Server connectivity confirmed")

        # Audit each page
        for page in self.pages:
            try:
                self.audit_single_page(page)
                time.sleep(0.5)  # Rate limiting
            except KeyboardInterrupt:
                print("\n⚠️ Audit interrupted by user")
                break
            except Exception as e:
                self.log_result("system", page['name'], "audit_error", "FAIL",
                              f"Audit failed: {str(e)}")

        # Generate summary report
        self.generate_summary_report()
        return True

    def generate_summary_report(self):
        """Generate comprehensive summary report"""
        end_time = datetime.now()
        duration = end_time - self.start_time

        print(f"\n{'='*80}")
        print("📊 UI/UX AUDIT SUMMARY REPORT")
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

        # Critical issues
        critical_fails = [r for r in self.results if r['status'] == 'FAIL']
        if critical_fails:
            print(f"\n🚨 Critical Issues ({len(critical_fails)}):")
            for fail in critical_fails[:10]:  # Show first 10
                print(f"   ❌ {fail['page']} - {fail['check']}: {fail['message']}")
            if len(critical_fails) > 10:
                print(f"   ... and {len(critical_fails) - 10} more issues")

        # Recommendations
        print(f"\n💡 Recommendations:")
        if status_counts['FAIL'] > 0:
            print("   🔧 Address critical failures before production deployment")
        if status_counts['WARNING'] > 10:
            print("   ⚠️  Review warnings for potential improvements")
        if success_rate > 90:
            print("   🎉 Excellent! Application shows strong UI/UX implementation")
        elif success_rate > 75:
            print("   ✅ Good foundation with room for improvement")
        else:
            print("   🛠️  Significant UI/UX improvements needed")

        # Save detailed report to file
        self.save_detailed_report()

        print(f"\n📄 Detailed report saved to: ui_ux_audit_report.json")
        print(f"{'='*80}")

    def save_detailed_report(self):
        """Save detailed audit results to JSON file"""
        report = {
            'audit_info': {
                'timestamp': self.start_time.isoformat(),
                'base_url': self.base_url,
                'pages_tested': len(self.pages),
                'total_checks': len(self.results)
            },
            'summary': {
                'pass': len([r for r in self.results if r['status'] == 'PASS']),
                'fail': len([r for r in self.results if r['status'] == 'FAIL']),
                'warning': len([r for r in self.results if r['status'] == 'WARNING']),
                'info': len([r for r in self.results if r['status'] == 'INFO'])
            },
            'detailed_results': self.results,
            'pages_tested': self.pages
        }

        with open('ui_ux_audit_report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)

if __name__ == '__main__':
    auditor = UIUXAuditor()
    success = auditor.run_full_audit()

    if success:
        print("✅ UI/UX Audit completed successfully!")
        sys.exit(0)
    else:
        print("❌ UI/UX Audit failed!")
        sys.exit(1)