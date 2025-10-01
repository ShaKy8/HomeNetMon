#!/usr/bin/env python3
"""
Comprehensive Static Code Analysis for HomeNetMon
Performs security analysis, code quality review, and best practices validation
"""

import os
import re
import ast
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple
import subprocess

class StaticCodeAnalyzer:
    def __init__(self, project_root="/home/kyle/ClaudeCode/HomeNetMon"):
        self.project_root = Path(project_root)
        self.results = []
        self.start_time = datetime.now()

        # Security patterns to detect
        self.security_patterns = {
            "sql_injection": [
                r"\.execute\([^)]*%[^)]*\)",  # String formatting in SQL
                r"\.execute\([^)]*\+[^)]*\)",  # String concatenation in SQL
                r"\.execute\([^)]*\.format\([^)]*\)",  # .format() in SQL
                r"query\s*=\s*[\"'][^\"']*%[^\"']*[\"']",  # % formatting in queries
            ],
            "command_injection": [
                r"os\.system\([^)]*\+[^)]*\)",  # Command concatenation
                r"subprocess\.[^(]*\([^)]*shell\s*=\s*True[^)]*\+[^)]*\)",  # Shell=True with concatenation
                r"os\.popen\([^)]*\+[^)]*\)",  # popen with concatenation
            ],
            "path_traversal": [
                r"open\([^)]*\+[^)]*\)",  # File path concatenation
                r"os\.path\.join\([^)]*\+[^)]*\)",  # Path join with concatenation
                r"\.\.\/",  # Literal path traversal
            ],
            "hardcoded_secrets": [
                r"password\s*=\s*[\"'][^\"']+[\"']",  # Hardcoded passwords
                r"secret\s*=\s*[\"'][^\"']+[\"']",  # Hardcoded secrets
                r"api_key\s*=\s*[\"'][^\"']+[\"']",  # Hardcoded API keys
                r"token\s*=\s*[\"'][^\"']+[\"']",  # Hardcoded tokens
            ],
            "xss_vulnerabilities": [
                r"render_template_string\([^)]*\+[^)]*\)",  # Template injection
                r"Markup\([^)]*\+[^)]*\)",  # Unsafe markup
                r"safe\s*\|[^}]*\+",  # Jinja2 safe filter with concatenation
            ],
            "csrf_missing": [
                r"@app\.route\([^)]*POST[^)]*\)",  # POST routes without CSRF
                r"methods\s*=\s*\[[^]]*[\"']POST[\"'][^]]*\]",  # POST methods
            ],
            "debug_code": [
                r"print\s*\(",  # Debug print statements
                r"console\.log\s*\(",  # JavaScript console.log
                r"debugger;",  # JavaScript debugger
                r"pdb\.set_trace\(\)",  # Python debugger
            ],
            "insecure_random": [
                r"random\.random\(\)",  # Insecure random
                r"random\.randint\(",  # Insecure random int
                r"Math\.random\(\)",  # JavaScript insecure random
            ],
            "weak_crypto": [
                r"md5\(",  # Weak MD5 hashing
                r"sha1\(",  # Weak SHA1 hashing
                r"hashlib\.md5\(",  # MD5 via hashlib
                r"hashlib\.sha1\(",  # SHA1 via hashlib
            ]
        }

        # Code quality patterns
        self.quality_patterns = {
            "long_functions": r"def\s+\w+\([^:]*\):",  # Function definitions (will check length)
            "long_lines": r".{120,}",  # Lines longer than 120 characters
            "complex_conditionals": r"if\s+[^:]*and\s+[^:]*and\s+[^:]*:",  # Complex if statements
            "bare_except": r"except\s*:",  # Bare except clauses
            "unused_imports": r"import\s+\w+$",  # Simple import pattern (need AST for accuracy)
            "missing_docstrings": r"def\s+\w+\([^:]*\):\s*\n\s*[^\"']",  # Functions without docstrings
        }

        # File extensions to analyze
        self.extensions = {'.py', '.js', '.html', '.css', '.sql', '.json', '.yaml', '.yml'}

        # Files and directories to exclude
        self.exclude_patterns = {
            'venv/', '__pycache__/', '.git/', 'node_modules/', '.pytest_cache/',
            'archive/', 'backup/', 'logs/', '*.pyc', '*.pyo', '*.log'
        }

    def log_result(self, test_type: str, file_path: str, line_num: int,
                   severity: str, message: str, details: str = "", code_snippet: str = ""):
        """Log analysis result"""
        result = {
            'timestamp': datetime.now().isoformat(),
            'test_type': test_type,
            'file': str(file_path),
            'line': line_num,
            'severity': severity,  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
            'message': message,
            'details': details,
            'code_snippet': code_snippet[:200]  # Limit snippet length
        }
        self.results.append(result)

        # Console output with colors
        severity_colors = {
            'CRITICAL': '\033[91m🚨',
            'HIGH': '\033[91m❌',
            'MEDIUM': '\033[93m⚠️',
            'LOW': '\033[94mℹ️',
            'INFO': '\033[92m✅'
        }

        color = severity_colors.get(severity, '⭐')
        file_short = str(file_path).replace(str(self.project_root), '')
        print(f"{color} {file_short}:{line_num} - {message}\033[0m")
        if details:
            print(f"    └─ {details}")

    def should_exclude_file(self, file_path: Path) -> bool:
        """Check if file should be excluded from analysis"""
        file_str = str(file_path)
        for pattern in self.exclude_patterns:
            if pattern in file_str:
                return True
        return False

    def analyze_security_patterns(self, file_path: Path, content: str):
        """Analyze file for security vulnerabilities"""
        lines = content.split('\n')

        for category, patterns in self.security_patterns.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        severity = self.get_security_severity(category)
                        message = f"Potential {category.replace('_', ' ')}"
                        details = f"Pattern: {pattern}"
                        self.log_result(
                            "security", file_path, line_num, severity,
                            message, details, line.strip()
                        )

    def get_security_severity(self, category: str) -> str:
        """Get severity level for security issue category"""
        critical_issues = {'sql_injection', 'command_injection', 'path_traversal'}
        high_issues = {'hardcoded_secrets', 'xss_vulnerabilities', 'weak_crypto'}
        medium_issues = {'csrf_missing', 'insecure_random'}

        if category in critical_issues:
            return 'CRITICAL'
        elif category in high_issues:
            return 'HIGH'
        elif category in medium_issues:
            return 'MEDIUM'
        else:
            return 'LOW'

    def analyze_code_quality(self, file_path: Path, content: str):
        """Analyze code quality issues"""
        lines = content.split('\n')

        # Check for long lines
        for line_num, line in enumerate(lines, 1):
            if len(line) > 120:
                self.log_result(
                    "quality", file_path, line_num, "LOW",
                    f"Line too long ({len(line)} chars)",
                    "Consider breaking long lines for readability",
                    line.strip()
                )

        # Check for other quality patterns
        for category, pattern in self.quality_patterns.items():
            if category == "long_lines":
                continue  # Already handled above

            for line_num, line in enumerate(lines, 1):
                matches = re.finditer(pattern, line)
                for match in matches:
                    severity = "MEDIUM" if category in ["bare_except", "complex_conditionals"] else "LOW"
                    message = f"Code quality: {category.replace('_', ' ')}"
                    self.log_result(
                        "quality", file_path, line_num, severity,
                        message, "", line.strip()
                    )

    def analyze_python_ast(self, file_path: Path, content: str):
        """Advanced Python AST analysis"""
        if not file_path.suffix == '.py':
            return

        try:
            tree = ast.parse(content)

            # Analyze function complexity
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    function_lines = len([n for n in ast.walk(node) if hasattr(n, 'lineno')])
                    if function_lines > 50:
                        self.log_result(
                            "complexity", file_path, node.lineno, "MEDIUM",
                            f"Function '{node.name}' is too long ({function_lines} nodes)",
                            "Consider breaking into smaller functions"
                        )

                # Check for eval() usage
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id in ['eval', 'exec']:
                        self.log_result(
                            "security", file_path, node.lineno, "CRITICAL",
                            f"Dangerous function: {node.func.id}()",
                            "eval/exec can execute arbitrary code"
                        )

        except SyntaxError as e:
            self.log_result(
                "syntax", file_path, e.lineno or 0, "HIGH",
                f"Syntax error: {e.msg}",
                "File contains syntax errors"
            )
        except Exception as e:
            # Don't fail on AST errors, just log and continue
            pass

    def analyze_flask_security(self, file_path: Path, content: str):
        """Analyze Flask-specific security issues"""
        if not file_path.suffix == '.py':
            return

        lines = content.split('\n')

        # Check for debug mode in production
        debug_patterns = [
            r"debug\s*=\s*True",
            r"app\.debug\s*=\s*True",
            r"app\.run\([^)]*debug\s*=\s*True[^)]*\)"
        ]

        for pattern in debug_patterns:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    self.log_result(
                        "security", file_path, line_num, "HIGH",
                        "Debug mode enabled",
                        "Debug mode should be disabled in production",
                        line.strip()
                    )

        # Check for missing authentication decorators
        route_pattern = r"@app\.route\([^)]*\)"
        auth_patterns = [r"@login_required", r"@auth\.login_required", r"@require_auth"]

        in_route = False
        route_line = 0

        for line_num, line in enumerate(lines, 1):
            if re.search(route_pattern, line):
                in_route = True
                route_line = line_num
            elif in_route and line.strip().startswith('def '):
                # Check if any auth decorator was found
                auth_found = False
                for auth_pattern in auth_patterns:
                    for check_line in lines[route_line-1:line_num-1]:
                        if re.search(auth_pattern, check_line):
                            auth_found = True
                            break

                if not auth_found and 'GET' not in lines[route_line-1]:
                    self.log_result(
                        "security", file_path, route_line, "MEDIUM",
                        "Route missing authentication",
                        "Consider adding authentication decorator",
                        lines[route_line-1].strip()
                    )
                in_route = False

    def analyze_javascript_security(self, file_path: Path, content: str):
        """Analyze JavaScript security issues"""
        if file_path.suffix not in {'.js', '.html'}:
            return

        lines = content.split('\n')

        js_security_patterns = {
            "dom_xss": [
                r"innerHTML\s*=\s*[^;]*\+",  # innerHTML with concatenation
                r"document\.write\s*\([^)]*\+[^)]*\)",  # document.write with concatenation
                r"eval\s*\(",  # eval() usage
            ],
            "insecure_storage": [
                r"localStorage\.setItem\([^)]*password[^)]*\)",  # Storing passwords
                r"sessionStorage\.setItem\([^)]*token[^)]*\)",  # Storing tokens
            ],
            "weak_random": [
                r"Math\.random\(\)",  # Insecure random
            ]
        }

        for category, patterns in js_security_patterns.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        severity = "HIGH" if category == "dom_xss" else "MEDIUM"
                        self.log_result(
                            "security", file_path, line_num, severity,
                            f"JavaScript {category.replace('_', ' ')}",
                            f"Pattern: {pattern}",
                            line.strip()
                        )

    def check_dependency_security(self):
        """Check for known vulnerable dependencies"""
        requirements_file = self.project_root / "requirements.txt"

        if requirements_file.exists():
            # Known vulnerable packages (simplified check)
            vulnerable_patterns = [
                r"flask\s*[<>=]*\s*[01]\.",  # Very old Flask versions
                r"jinja2\s*[<>=]*\s*2\.[0-9]\.",  # Old Jinja2 versions
                r"requests\s*[<>=]*\s*2\.[0-9]\.",  # Old requests versions
            ]

            content = requirements_file.read_text()
            lines = content.split('\n')

            for line_num, line in enumerate(lines, 1):
                for pattern in vulnerable_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.log_result(
                            "dependency", requirements_file, line_num, "MEDIUM",
                            "Potentially vulnerable dependency",
                            "Consider updating to latest stable version",
                            line.strip()
                        )

    def check_configuration_security(self):
        """Check configuration files for security issues"""
        config_files = [
            self.project_root / "config.py",
            self.project_root / "app.py",
            self.project_root / ".env",
            self.project_root / ".env.example"
        ]

        for config_file in config_files:
            if not config_file.exists():
                continue

            content = config_file.read_text()
            lines = content.split('\n')

            # Check for insecure configurations
            insecure_configs = [
                (r"SECRET_KEY\s*=\s*[\"'].*[\"']", "Hardcoded secret key"),
                (r"DEBUG\s*=\s*True", "Debug mode enabled"),
                (r"TESTING\s*=\s*True", "Testing mode enabled"),
                (r"host\s*=\s*[\"']0\.0\.0\.0[\"']", "Binding to all interfaces"),
            ]

            for line_num, line in enumerate(lines, 1):
                for pattern, message in insecure_configs:
                    if re.search(pattern, line, re.IGNORECASE):
                        severity = "HIGH" if "SECRET_KEY" in message else "MEDIUM"
                        self.log_result(
                            "config", config_file, line_num, severity,
                            f"Configuration issue: {message}",
                            "Review configuration for production deployment",
                            line.strip()
                        )

    def analyze_file(self, file_path: Path):
        """Analyze a single file"""
        try:
            if self.should_exclude_file(file_path):
                return

            content = file_path.read_text(encoding='utf-8', errors='ignore')

            # Run all analysis types
            self.analyze_security_patterns(file_path, content)
            self.analyze_code_quality(file_path, content)
            self.analyze_python_ast(file_path, content)
            self.analyze_flask_security(file_path, content)
            self.analyze_javascript_security(file_path, content)

        except Exception as e:
            self.log_result(
                "error", file_path, 0, "LOW",
                f"Error analyzing file: {str(e)}",
                "File could not be analyzed"
            )

    def run_external_tools(self):
        """Run external security tools if available"""
        tools_results = []

        # Try running bandit for Python security
        try:
            result = subprocess.run(
                ['bandit', '-r', str(self.project_root), '-f', 'json'],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                bandit_data = json.loads(result.stdout)
                for issue in bandit_data.get('results', []):
                    self.log_result(
                        "bandit", issue['filename'], issue['line_number'],
                        issue['issue_severity'].upper(),
                        f"Bandit: {issue['test_name']}",
                        issue['issue_text'],
                        issue.get('code', '')
                    )
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            # Tool not available or failed
            pass

    def run_comprehensive_analysis(self):
        """Run complete static code analysis"""
        print("🔍 Starting Comprehensive Static Code Analysis")
        print(f"📊 Analyzing project: {self.project_root}")
        print(f"⏰ Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        # Check if project directory exists
        if not self.project_root.exists():
            print(f"❌ Project directory not found: {self.project_root}")
            return False

        # Analyze dependency security
        self.check_dependency_security()

        # Analyze configuration security
        self.check_configuration_security()

        # Run external tools
        self.run_external_tools()

        # Analyze all files
        file_count = 0
        for file_path in self.project_root.rglob('*'):
            if file_path.is_file() and file_path.suffix in self.extensions:
                if not self.should_exclude_file(file_path):
                    self.analyze_file(file_path)
                    file_count += 1

                    # Progress indicator
                    if file_count % 10 == 0:
                        print(f"📄 Analyzed {file_count} files...")

        print(f"✅ Analysis complete. Analyzed {file_count} files.")

        # Generate summary report
        self.generate_summary_report()
        return True

    def generate_summary_report(self):
        """Generate comprehensive summary report"""
        end_time = datetime.now()
        duration = end_time - self.start_time

        print(f"\n{'='*80}")
        print("🔍 STATIC CODE ANALYSIS SUMMARY")
        print(f"{'='*80}")

        # Count by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        category_counts = {}

        for result in self.results:
            severity_counts[result['severity']] = severity_counts.get(result['severity'], 0) + 1
            category = result['test_type']
            if category not in category_counts:
                category_counts[category] = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            category_counts[category][result['severity']] += 1

        # Overall statistics
        total_issues = len(self.results)
        critical_high = severity_counts['CRITICAL'] + severity_counts['HIGH']

        print(f"🎯 Overall Results:")
        print(f"   🚨 Critical: {severity_counts['CRITICAL']}")
        print(f"   ❌ High: {severity_counts['HIGH']}")
        print(f"   ⚠️  Medium: {severity_counts['MEDIUM']}")
        print(f"   ℹ️  Low: {severity_counts['LOW']}")
        print(f"   ✅ Info: {severity_counts['INFO']}")
        print(f"   📊 Total Issues: {total_issues}")
        print(f"   ⏱️  Duration: {duration.total_seconds():.1f} seconds")

        # Category breakdown
        print(f"\n📋 Issues by Category:")
        for category, counts in category_counts.items():
            total_cat = sum(counts.values())
            critical_high_cat = counts['CRITICAL'] + counts['HIGH']
            print(f"   {category.title()}: {total_cat} issues ({critical_high_cat} critical/high)")

        # Critical issues
        critical_issues = [r for r in self.results if r['severity'] in ['CRITICAL', 'HIGH']]
        if critical_issues:
            print(f"\n🚨 CRITICAL & HIGH PRIORITY ISSUES ({len(critical_issues)}):")
            for issue in critical_issues[:20]:  # Show first 20
                file_short = issue['file'].replace(str(self.project_root), '')
                print(f"   {issue['severity']}: {file_short}:{issue['line']} - {issue['message']}")
            if len(critical_issues) > 20:
                print(f"   ... and {len(critical_issues) - 20} more critical issues")

        # Security assessment
        security_issues = [r for r in self.results if r['test_type'] == 'security']
        print(f"\n🔒 Security Assessment:")
        print(f"   Total Security Issues: {len(security_issues)}")
        print(f"   Critical Security Issues: {len([r for r in security_issues if r['severity'] == 'CRITICAL'])}")
        print(f"   High Security Issues: {len([r for r in security_issues if r['severity'] == 'HIGH'])}")

        # Recommendations
        print(f"\n💡 Recommendations:")
        if critical_high > 0:
            print(f"   🚨 {critical_high} critical/high issues need immediate attention")
        if len(security_issues) > 5:
            print("   🔒 Consider implementing additional security measures")
        if total_issues > 50:
            print("   🧹 Consider code cleanup and refactoring")

        # Overall security rating
        if critical_high == 0:
            print("   🏆 Excellent: No critical security issues found")
        elif critical_high < 5:
            print("   ✅ Good: Few critical issues, mostly secure")
        elif critical_high < 15:
            print("   ⚠️  Fair: Some security issues need attention")
        else:
            print("   🚨 Poor: Multiple security issues require immediate fixing")

        # Save detailed report
        self.save_detailed_report()
        print(f"\n📄 Detailed report saved to: static_analysis_report.json")
        print(f"{'='*80}")

    def save_detailed_report(self):
        """Save detailed analysis results to JSON file"""
        report = {
            'analysis_info': {
                'timestamp': self.start_time.isoformat(),
                'project_root': str(self.project_root),
                'total_issues': len(self.results),
                'analysis_duration': (datetime.now() - self.start_time).total_seconds()
            },
            'summary': {
                'critical': len([r for r in self.results if r['severity'] == 'CRITICAL']),
                'high': len([r for r in self.results if r['severity'] == 'HIGH']),
                'medium': len([r for r in self.results if r['severity'] == 'MEDIUM']),
                'low': len([r for r in self.results if r['severity'] == 'LOW']),
                'info': len([r for r in self.results if r['severity'] == 'INFO'])
            },
            'detailed_results': self.results
        }

        with open('static_analysis_report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)

if __name__ == '__main__':
    analyzer = StaticCodeAnalyzer()
    success = analyzer.run_comprehensive_analysis()

    if success:
        print("✅ Static Code Analysis completed successfully!")
        sys.exit(0)
    else:
        print("❌ Static Code Analysis failed!")
        sys.exit(1)