#!/usr/bin/env python3
"""
Frontend Performance Optimization Verification for HomeNetMon
Analyzes and verifies frontend performance optimizations including bundle optimization,
loading times, asset compression, and client-side performance
"""

import os
import sys
import json
import gzip
import time
import hashlib
import subprocess
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import requests
from urllib.parse import urljoin

class FrontendPerformanceAuditor:
    def __init__(self, project_path, base_url="http://geekom1:5000"):
        self.project_path = Path(project_path)
        self.base_url = base_url
        self.findings = defaultdict(list)
        self.bundle_info = {}
        self.asset_metrics = {}

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

    def log_finding(self, level, category, file_path, metric, value, target="", recommendation=""):
        """Log a performance finding"""
        finding = {
            'level': level,
            'category': category,
            'file': str(file_path),
            'metric': metric,
            'value': value,
            'target': target,
            'recommendation': recommendation,
            'timestamp': datetime.now().isoformat()
        }
        self.findings[level].append(finding)

        # Color mapping
        colors = {
            'excellent': self.colors['green'],
            'good': self.colors['blue'],
            'warning': self.colors['yellow'],
            'poor': self.colors['red'],
            'info': self.colors['cyan']
        }

        icons = {
            'excellent': '✅',
            'good': '👍',
            'warning': '⚠️',
            'poor': '❌',
            'info': 'ℹ️'
        }

        color = colors.get(level, self.colors['white'])
        icon = icons.get(level, 'ℹ️')

        relative_path = file_path.relative_to(self.project_path) if isinstance(file_path, Path) else file_path
        print(f"{color}{icon} {relative_path} - {metric}: {value}{self.colors['reset']}")
        if target:
            print(f"    Target: {target}")
        if recommendation:
            print(f"    └─ {recommendation}")

    def audit_asset_bundling(self):
        """Audit asset bundling and optimization"""
        print(f"\n{self.colors['cyan']}📦 Auditing Asset Bundling and Optimization{self.colors['reset']}")

        # Check for build assets script
        build_script = self.project_path / "build_assets.py"
        if build_script.exists():
            self.log_finding('good', 'Asset Bundling', build_script, 'Build Script', 'Present',
                           recommendation="Asset bundling is implemented")

            # Analyze build script effectiveness
            self._analyze_build_script(build_script)
        else:
            self.log_finding('warning', 'Asset Bundling', self.project_path, 'Build Script', 'Missing',
                           recommendation="Consider implementing asset bundling for production")

        # Check for bundled assets
        static_path = self.project_path / "static"
        if static_path.exists():
            self._analyze_static_assets(static_path)

    def _analyze_build_script(self, build_script):
        """Analyze the build script for optimization features"""
        try:
            with open(build_script, 'r') as f:
                content = f.read()

            # Check for optimization features
            optimizations = {
                'Minification': ['minify', 'uglify', 'compress'],
                'Compression': ['gzip', 'brotli', 'br'],
                'Cache Busting': ['hash', 'version', 'manifest'],
                'Bundle Splitting': ['bundle', 'chunk', 'split']
            }

            for feature, keywords in optimizations.items():
                if any(keyword in content.lower() for keyword in keywords):
                    self.log_finding('good', 'Asset Optimization', build_script, feature, 'Implemented')
                else:
                    self.log_finding('warning', 'Asset Optimization', build_script, feature, 'Missing',
                                   recommendation=f"Consider implementing {feature.lower()}")

        except Exception as e:
            self.log_finding('warning', 'Build Script', build_script, 'Analysis Error', str(e))

    def _analyze_static_assets(self, static_path):
        """Analyze static assets for size and optimization"""
        bundles_path = static_path / "bundles"
        if bundles_path.exists():
            # Analyze bundle files
            for bundle_file in bundles_path.glob("*"):
                if bundle_file.is_file():
                    self._analyze_bundle_file(bundle_file)

        # Check for other static assets
        js_files = list(static_path.glob("**/*.js"))
        css_files = list(static_path.glob("**/*.css"))

        self.log_finding('info', 'Static Assets', static_path, 'JS Files', len(js_files))
        self.log_finding('info', 'Static Assets', static_path, 'CSS Files', len(css_files))

    def _analyze_bundle_file(self, bundle_file):
        """Analyze individual bundle file"""
        try:
            file_size = bundle_file.stat().st_size
            file_size_kb = file_size / 1024

            # Determine if file is compressed
            is_compressed = bundle_file.suffix in ['.gz', '.br']

            # Size thresholds (in KB)
            if bundle_file.suffix == '.js' or '.js' in bundle_file.name:
                # JavaScript bundle thresholds
                if file_size_kb < 100:
                    level = 'excellent'
                elif file_size_kb < 250:
                    level = 'good'
                elif file_size_kb < 500:
                    level = 'warning'
                else:
                    level = 'poor'
                target = "< 250KB for good performance"
            elif bundle_file.suffix == '.css' or '.css' in bundle_file.name:
                # CSS bundle thresholds
                if file_size_kb < 50:
                    level = 'excellent'
                elif file_size_kb < 100:
                    level = 'good'
                elif file_size_kb < 200:
                    level = 'warning'
                else:
                    level = 'poor'
                target = "< 100KB for good performance"
            else:
                level = 'info'
                target = ""

            size_str = f"{file_size_kb:.1f}KB"
            if is_compressed:
                size_str += " (compressed)"

            self.log_finding(level, 'Bundle Analysis', bundle_file, 'File Size', size_str, target)

            # Store for summary
            self.bundle_info[bundle_file.name] = {
                'size_kb': file_size_kb,
                'compressed': is_compressed,
                'type': 'js' if '.js' in bundle_file.name else 'css' if '.css' in bundle_file.name else 'other'
            }

        except Exception as e:
            self.log_finding('warning', 'Bundle Analysis', bundle_file, 'Analysis Error', str(e))

    def audit_loading_performance(self):
        """Audit page loading performance"""
        print(f"\n{self.colors['cyan']}⚡ Auditing Loading Performance{self.colors['reset']}")

        # Test key pages for loading performance
        test_pages = [
            '/',
            '/dashboard',
            '/analytics',
            '/settings',
            '/security'
        ]

        for page in test_pages:
            self._test_page_loading(page)

    def _test_page_loading(self, page):
        """Test loading performance of a specific page"""
        try:
            url = urljoin(self.base_url, page)

            # Measure response time
            start_time = time.time()
            response = requests.get(url, timeout=10)
            end_time = time.time()

            response_time = (end_time - start_time) * 1000  # Convert to milliseconds

            # Analyze response
            if response.status_code == 200:
                # Response time thresholds
                if response_time < 200:
                    level = 'excellent'
                elif response_time < 500:
                    level = 'good'
                elif response_time < 1000:
                    level = 'warning'
                else:
                    level = 'poor'

                target = "< 500ms for good user experience"
                self.log_finding(level, 'Page Loading', page, 'Response Time', f"{response_time:.0f}ms", target)

                # Check response size
                content_length = len(response.content)
                content_size_kb = content_length / 1024

                if content_size_kb < 100:
                    size_level = 'excellent'
                elif content_size_kb < 300:
                    size_level = 'good'
                elif content_size_kb < 500:
                    size_level = 'warning'
                else:
                    size_level = 'poor'

                self.log_finding(size_level, 'Page Loading', page, 'Content Size', f"{content_size_kb:.1f}KB",
                               "< 300KB for good performance")

                # Check for compression headers
                encoding = response.headers.get('Content-Encoding', 'none')
                if encoding in ['gzip', 'br', 'deflate']:
                    self.log_finding('good', 'Page Loading', page, 'Compression', encoding)
                else:
                    self.log_finding('warning', 'Page Loading', page, 'Compression', 'None',
                                   recommendation="Enable gzip/brotli compression")

            else:
                self.log_finding('poor', 'Page Loading', page, 'HTTP Status', response.status_code,
                               recommendation="Page should return 200 OK")

        except requests.exceptions.RequestException as e:
            self.log_finding('poor', 'Page Loading', page, 'Connection Error', str(e),
                           recommendation="Ensure server is running and accessible")

    def audit_client_side_performance(self):
        """Audit client-side performance optimizations"""
        print(f"\n{self.colors['cyan']}🖥️ Auditing Client-Side Performance{self.colors['reset']}")

        # Check for performance-related files
        templates_path = self.project_path / "templates"
        if templates_path.exists():
            self._analyze_templates_performance(templates_path)

        # Check JavaScript for performance patterns
        static_js_path = self.project_path / "static" / "js"
        if static_js_path.exists():
            self._analyze_javascript_performance(static_js_path)

    def _analyze_templates_performance(self, templates_path):
        """Analyze templates for performance optimizations"""
        template_files = list(templates_path.glob("*.html"))

        for template_file in template_files:
            try:
                with open(template_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Check for performance optimizations
                optimizations = {
                    'Lazy Loading': ['loading="lazy"', 'lazy-load'],
                    'Async Scripts': ['async', 'defer'],
                    'Preload Resources': ['rel="preload"', 'rel="prefetch"'],
                    'Resource Hints': ['rel="dns-prefetch"', 'rel="preconnect"'],
                    'Critical CSS': ['critical-css', 'inline-css']
                }

                for optimization, patterns in optimizations.items():
                    if any(pattern in content for pattern in patterns):
                        self.log_finding('good', 'Template Optimization', template_file, optimization, 'Present')
                    elif template_file.name in ['dashboard.html', 'analytics.html']:  # Check critical pages
                        self.log_finding('info', 'Template Optimization', template_file, optimization, 'Not found',
                                       recommendation=f"Consider implementing {optimization.lower()}")

                # Count external resources
                script_tags = content.count('<script')
                link_tags = content.count('<link')

                if script_tags > 10:
                    self.log_finding('warning', 'Template Optimization', template_file, 'Script Tags', script_tags,
                                   "< 10 for optimal loading", "Consider bundling scripts")
                else:
                    self.log_finding('good', 'Template Optimization', template_file, 'Script Tags', script_tags)

                if link_tags > 15:
                    self.log_finding('warning', 'Template Optimization', template_file, 'Link Tags', link_tags,
                                   "< 15 for optimal loading", "Consider bundling stylesheets")

            except Exception as e:
                self.log_finding('warning', 'Template Analysis', template_file, 'Analysis Error', str(e))

    def _analyze_javascript_performance(self, js_path):
        """Analyze JavaScript files for performance patterns"""
        js_files = list(js_path.glob("*.js"))

        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Check for performance anti-patterns
                antipatterns = {
                    'Document Ready Overuse': ['$(document).ready', '$(function()'],
                    'Frequent DOM Queries': content.count('getElementById') + content.count('querySelector'),
                    'Memory Leaks': ['setInterval', 'setTimeout'] if 'clear' not in content else [],
                    'Blocking Operations': ['alert(', 'confirm(', 'prompt(']
                }

                # Check for frequent DOM queries
                dom_queries = content.count('getElementById') + content.count('querySelector') + content.count('getElementsBy')
                if dom_queries > 20:
                    self.log_finding('warning', 'JS Performance', js_file, 'DOM Queries', dom_queries,
                                   "< 20 per file", "Consider caching DOM references")
                elif dom_queries > 0:
                    self.log_finding('good', 'JS Performance', js_file, 'DOM Queries', dom_queries)

                # Check for modern JavaScript features
                modern_features = {
                    'ES6 Features': ['const ', 'let ', '=>', 'class '],
                    'Async/Await': ['async ', 'await '],
                    'Event Delegation': ['addEventListener', 'on(']
                }

                for feature, patterns in modern_features.items():
                    if any(pattern in content for pattern in patterns):
                        self.log_finding('good', 'JS Performance', js_file, feature, 'Used')

            except Exception as e:
                self.log_finding('warning', 'JS Analysis', js_file, 'Analysis Error', str(e))

    def audit_caching_strategy(self):
        """Audit caching strategy and headers"""
        print(f"\n{self.colors['cyan']}🗄️ Auditing Caching Strategy{self.colors['reset']}")

        # Test static asset caching
        static_assets = [
            '/static/bundles/core.js',
            '/static/bundles/core.css',
            '/static/bundles/dashboard.js',
            '/static/bundles/dashboard.css'
        ]

        for asset in static_assets:
            self._test_asset_caching(asset)

    def _test_asset_caching(self, asset_path):
        """Test caching headers for specific asset"""
        try:
            url = urljoin(self.base_url, asset_path)
            response = requests.head(url, timeout=5)

            if response.status_code == 200:
                # Check cache headers
                cache_control = response.headers.get('Cache-Control', '')
                etag = response.headers.get('ETag', '')
                last_modified = response.headers.get('Last-Modified', '')
                expires = response.headers.get('Expires', '')

                # Analyze cache strategy
                if 'max-age' in cache_control:
                    max_age = cache_control.split('max-age=')[1].split(',')[0] if 'max-age=' in cache_control else '0'
                    try:
                        max_age_seconds = int(max_age)
                        max_age_hours = max_age_seconds / 3600

                        if max_age_hours >= 24:
                            self.log_finding('excellent', 'Caching', asset_path, 'Cache Duration', f"{max_age_hours:.0f}h")
                        elif max_age_hours >= 1:
                            self.log_finding('good', 'Caching', asset_path, 'Cache Duration', f"{max_age_hours:.1f}h")
                        else:
                            self.log_finding('warning', 'Caching', asset_path, 'Cache Duration', f"{max_age_seconds}s",
                                           "Consider longer cache duration for static assets")
                    except ValueError:
                        self.log_finding('warning', 'Caching', asset_path, 'Cache Duration', 'Invalid')
                else:
                    self.log_finding('warning', 'Caching', asset_path, 'Cache Control', 'Missing',
                                   recommendation="Add Cache-Control headers")

                if etag:
                    self.log_finding('good', 'Caching', asset_path, 'ETag', 'Present')
                else:
                    self.log_finding('info', 'Caching', asset_path, 'ETag', 'Missing',
                                   recommendation="Consider adding ETag headers")

            else:
                self.log_finding('warning', 'Caching', asset_path, 'Asset Availability', f"HTTP {response.status_code}")

        except requests.exceptions.RequestException as e:
            self.log_finding('warning', 'Caching', asset_path, 'Test Error', str(e))

    def generate_performance_report(self):
        """Generate comprehensive performance report"""
        print(f"\n{self.colors['purple']}📊 Frontend Performance Report{self.colors['reset']}")
        print("=" * 80)

        # Summary statistics
        total_findings = sum(len(findings) for findings in self.findings.values())
        excellent_count = len(self.findings['excellent'])
        good_count = len(self.findings['good'])
        warning_count = len(self.findings['warning'])
        poor_count = len(self.findings['poor'])

        print(f"\n📈 Performance Summary:")
        print(f"  Total Checks: {total_findings}")
        print(f"  Excellent: {excellent_count}")
        print(f"  Good: {good_count}")
        print(f"  Warnings: {warning_count}")
        print(f"  Poor: {poor_count}")

        # Calculate performance score
        performance_score = self._calculate_performance_score()
        print(f"\n🎯 Frontend Performance Score: {performance_score}/100")

        if performance_score >= 90:
            status = f"{self.colors['green']}🚀 EXCELLENT{self.colors['reset']}"
        elif performance_score >= 75:
            status = f"{self.colors['blue']}✅ GOOD{self.colors['reset']}"
        elif performance_score >= 60:
            status = f"{self.colors['yellow']}⚠️ NEEDS IMPROVEMENT{self.colors['reset']}"
        else:
            status = f"{self.colors['red']}❌ POOR{self.colors['reset']}"

        print(f"  Status: {status}")

        # Bundle analysis summary
        if self.bundle_info:
            print(f"\n📦 Bundle Analysis:")
            total_js_size = sum(info['size_kb'] for info in self.bundle_info.values() if info['type'] == 'js')
            total_css_size = sum(info['size_kb'] for info in self.bundle_info.values() if info['type'] == 'css')

            print(f"  Total JS Bundle Size: {total_js_size:.1f}KB")
            print(f"  Total CSS Bundle Size: {total_css_size:.1f}KB")

            compressed_count = sum(1 for info in self.bundle_info.values() if info['compressed'])
            total_bundles = len(self.bundle_info)
            compression_ratio = (compressed_count / total_bundles * 100) if total_bundles > 0 else 0
            print(f"  Compression Coverage: {compression_ratio:.0f}% ({compressed_count}/{total_bundles})")

        # Top recommendations
        recommendations = self._generate_performance_recommendations()
        if recommendations:
            print(f"\n💡 Performance Recommendations:")
            for i, rec in enumerate(recommendations[:8], 1):
                print(f"  {i}. {rec}")

        print(f"\n⏰ Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return performance_score

    def _calculate_performance_score(self):
        """Calculate overall performance score"""
        score = 100

        # Deduct points for issues
        score -= len(self.findings['poor']) * 15
        score -= len(self.findings['warning']) * 5

        # Add points for good practices
        score += len(self.findings['excellent']) * 2
        score += len(self.findings['good']) * 1

        # Ensure score is between 0 and 100
        return max(0, min(100, score))

    def _generate_performance_recommendations(self):
        """Generate performance improvement recommendations"""
        recommendations = []

        # Bundle size recommendations
        large_bundles = [name for name, info in self.bundle_info.items()
                        if info['size_kb'] > 250 and info['type'] == 'js']
        if large_bundles:
            recommendations.append("Optimize large JavaScript bundles through code splitting")

        # Compression recommendations
        uncompressed = [name for name, info in self.bundle_info.items() if not info['compressed']]
        if uncompressed:
            recommendations.append("Enable compression (gzip/brotli) for all static assets")

        # General recommendations based on findings
        if len(self.findings['poor']) > 0:
            recommendations.append("Address poor performance metrics identified in the audit")

        if len(self.findings['warning']) > 3:
            recommendations.append("Resolve warning-level performance issues")

        # Standard recommendations
        recommendations.extend([
            "Implement lazy loading for images and non-critical resources",
            "Use resource hints (preload, prefetch) for critical assets",
            "Minimize render-blocking resources",
            "Optimize critical rendering path",
            "Implement service worker for offline capability",
            "Use CDN for static asset delivery"
        ])

        return recommendations

    def save_performance_report(self):
        """Save detailed performance report to file"""
        report_file = self.project_path / "frontend_performance_report.json"

        report_data = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_findings': sum(len(findings) for findings in self.findings.values()),
                'excellent_count': len(self.findings['excellent']),
                'good_count': len(self.findings['good']),
                'warning_count': len(self.findings['warning']),
                'poor_count': len(self.findings['poor']),
                'performance_score': self._calculate_performance_score()
            },
            'findings': dict(self.findings),
            'bundle_info': self.bundle_info,
            'recommendations': self._generate_performance_recommendations()
        }

        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"\n💾 Detailed report saved to: {report_file}")
        return report_file

def main():
    """Main function to run frontend performance audit"""
    project_path = Path.cwd()

    print(f"⚡ Starting Frontend Performance Audit")
    print(f"📊 Project: {project_path}")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    auditor = FrontendPerformanceAuditor(project_path)

    # Run all performance audits
    auditor.audit_asset_bundling()
    auditor.audit_loading_performance()
    auditor.audit_client_side_performance()
    auditor.audit_caching_strategy()

    # Generate and save report
    performance_score = auditor.generate_performance_report()
    auditor.save_performance_report()

    # Exit with appropriate code
    if performance_score >= 75:
        sys.exit(0)  # Good performance
    elif performance_score >= 60:
        sys.exit(1)  # Needs improvement
    else:
        sys.exit(2)  # Poor performance

if __name__ == "__main__":
    main()