#!/usr/bin/env python3
"""
Comprehensive Authentication and Authorization Audit for HomeNetMon
Audits authentication mechanisms, session management, and access controls
"""

import os
import re
import sys
import ast
import json
import hashlib
import sqlite3
from pathlib import Path
from collections import defaultdict
from datetime import datetime

class AuthAuditor:
    def __init__(self, project_path):
        self.project_path = Path(project_path)
        self.findings = defaultdict(list)
        self.auth_routes = []
        self.protected_routes = []
        self.unprotected_routes = []
        self.session_config = {}
        self.password_policies = {}

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

    def log_finding(self, level, category, file_path, line_num, issue, detail=""):
        """Log a security finding"""
        finding = {
            'level': level,
            'category': category,
            'file': str(file_path),
            'line': line_num,
            'issue': issue,
            'detail': detail,
            'timestamp': datetime.now().isoformat()
        }
        self.findings[level].append(finding)

        # Color mapping
        colors = {
            'critical': self.colors['red'],
            'high': self.colors['yellow'],
            'medium': self.colors['blue'],
            'low': self.colors['green'],
            'info': self.colors['cyan']
        }

        color = colors.get(level, self.colors['white'])
        icon = {
            'critical': '❌',
            'high': '⚠️',
            'medium': 'ℹ️',
            'low': '✓',
            'info': '📋'
        }.get(level, 'ℹ️')

        relative_path = file_path.relative_to(self.project_path)
        print(f"{color}{icon} /{relative_path}:{line_num} - {category}: {issue}{self.colors['reset']}")
        if detail:
            print(f"    └─ {detail}")

    def audit_authentication_system(self):
        """Audit the authentication system implementation"""
        print(f"\n{self.colors['cyan']}🔐 Auditing Authentication System{self.colors['reset']}")

        # Check for authentication files
        auth_files = [
            'core/auth.py', 'core/auth_db.py', 'remote_auth.py',
            'api/auth.py', 'api/security.py'
        ]

        for auth_file in auth_files:
            file_path = self.project_path / auth_file
            if file_path.exists():
                self._audit_auth_file(file_path)
            else:
                if auth_file in ['core/auth.py', 'api/auth.py']:
                    self.log_finding('high', 'Authentication', file_path, 0,
                                   f"Missing authentication file: {auth_file}")

    def _audit_auth_file(self, file_path):
        """Audit a specific authentication file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')

            # Check for weak password policies
            password_patterns = [
                (r'min.*length.*=.*[1-5]', 'Weak password minimum length'),
                (r'password.*=.*request\.form', 'Password from form without validation'),
                (r'password.*=.*request\.json', 'Password from JSON without validation'),
                (r'bcrypt\.check.*password.*hash', 'Password verification found'),
                (r'werkzeug\.security\.check_password_hash', 'Werkzeug password check found'),
                (r'plaintext.*password', 'Potential plaintext password storage'),
                (r'md5.*password', 'Weak MD5 password hashing'),
                (r'sha1.*password', 'Weak SHA1 password hashing')
            ]

            for line_num, line in enumerate(lines, 1):
                for pattern, description in password_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        level = 'critical' if 'plaintext' in description or 'md5' in description or 'sha1' in description else 'medium'
                        self.log_finding(level, 'Password Security', file_path, line_num, description)

            # Check for session security
            session_patterns = [
                (r'session\[.*\].*=', 'Session variable assignment'),
                (r'SESSION_COOKIE_SECURE.*False', 'Insecure session cookies'),
                (r'SESSION_COOKIE_HTTPONLY.*False', 'Non-HTTPOnly session cookies'),
                (r'PERMANENT_SESSION_LIFETIME', 'Session lifetime configuration'),
                (r'remember.*token', 'Remember me token functionality'),
                (r'session\.permanent.*True', 'Permanent session configuration')
            ]

            for line_num, line in enumerate(lines, 1):
                for pattern, description in session_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        level = 'high' if 'False' in description else 'info'
                        self.log_finding(level, 'Session Security', file_path, line_num, description)

        except Exception as e:
            self.log_finding('medium', 'File Error', file_path, 0, f"Could not analyze auth file: {e}")

    def audit_route_protection(self):
        """Audit Flask routes for proper authentication protection"""
        print(f"\n{self.colors['cyan']}🛡️ Auditing Route Protection{self.colors['reset']}")

        # Find all Python files with Flask routes
        python_files = list(self.project_path.rglob("*.py"))

        for file_path in python_files:
            if file_path.name.startswith('.') or 'venv' in str(file_path):
                continue

            self._audit_routes_in_file(file_path)

    def _audit_routes_in_file(self, file_path):
        """Audit routes in a specific Python file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')

            current_route = None
            route_line = 0
            decorators = []

            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()

                # Track decorators
                if stripped.startswith('@'):
                    decorators.append(stripped)

                # Found a route
                if '@app.route(' in stripped or '@bp.route(' in stripped:
                    current_route = stripped
                    route_line = line_num

                # Function definition after route
                elif stripped.startswith('def ') and current_route:
                    self._analyze_route_security(file_path, route_line, current_route, decorators, stripped)
                    current_route = None
                    decorators = []

        except Exception as e:
            self.log_finding('medium', 'File Error', file_path, 0, f"Could not analyze routes: {e}")

    def _analyze_route_security(self, file_path, line_num, route_def, decorators, func_def):
        """Analyze security of a specific route"""
        # Extract route path and methods
        route_match = re.search(r"'([^']+)'|\"([^\"]+)\"", route_def)
        route_path = route_match.group(1) or route_match.group(2) if route_match else "unknown"

        methods_match = re.search(r"methods\s*=\s*\[([^\]]+)\]", route_def)
        methods = methods_match.group(1) if methods_match else "GET"

        # Check for authentication decorators
        auth_decorators = [
            '@login_required', '@require_auth', '@authenticate', '@admin_required',
            '@token_required', '@check_auth', '@verify_token', '@requires_auth'
        ]

        has_auth = any(any(auth_dec in dec for auth_dec in auth_decorators) for dec in decorators)

        # Sensitive endpoints that should be protected
        sensitive_patterns = [
            r'/admin', r'/config', r'/settings', r'/users', r'/delete', r'/update',
            r'/api/.*', r'/dashboard', r'/security', r'/analytics', r'/escalation'
        ]

        is_sensitive = any(re.search(pattern, route_path, re.IGNORECASE) for pattern in sensitive_patterns)

        # Public endpoints that don't need protection
        public_patterns = [
            r'/static', r'/favicon', r'/health', r'/ping', r'/login', r'/logout', r'/$'
        ]

        is_public = any(re.search(pattern, route_path, re.IGNORECASE) for pattern in public_patterns)

        # Log findings
        if is_sensitive and not has_auth:
            self.log_finding('critical', 'Route Security', file_path, line_num,
                           f"Sensitive route '{route_path}' lacks authentication",
                           f"Methods: {methods}")
            self.unprotected_routes.append(route_path)
        elif has_auth:
            self.log_finding('info', 'Route Security', file_path, line_num,
                           f"Protected route '{route_path}' has authentication")
            self.protected_routes.append(route_path)
        elif is_public:
            self.log_finding('info', 'Route Security', file_path, line_num,
                           f"Public route '{route_path}' (expected)")
        else:
            self.log_finding('medium', 'Route Security', file_path, line_num,
                           f"Route '{route_path}' may need review",
                           f"Methods: {methods}")

    def audit_database_security(self):
        """Audit database security for authentication"""
        print(f"\n{self.colors['cyan']}🗄️ Auditing Database Security{self.colors['reset']}")

        # Check SQLite database
        db_path = self.project_path / "homeNetMon.db"
        if db_path.exists():
            self._audit_sqlite_security(db_path)
        else:
            self.log_finding('medium', 'Database', db_path, 0, "SQLite database not found")

        # Check for database configuration files
        config_files = ['config.py', 'core/db_config.py', '.env']
        for config_file in config_files:
            file_path = self.project_path / config_file
            if file_path.exists():
                self._audit_db_config(file_path)

    def _audit_sqlite_security(self, db_path):
        """Audit SQLite database security"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Check for user/authentication tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            auth_tables = ['users', 'user', 'authentication', 'auth', 'sessions', 'tokens']
            found_auth_tables = [table for table in tables if any(auth in table.lower() for auth in auth_tables)]

            if found_auth_tables:
                self.log_finding('info', 'Database', db_path, 0,
                               f"Found authentication tables: {', '.join(found_auth_tables)}")

                # Check user table structure
                for table in found_auth_tables:
                    try:
                        cursor.execute(f"PRAGMA table_info({table});")
                        columns = cursor.fetchall()
                        column_names = [col[1] for col in columns]

                        # Check for password column
                        password_cols = [col for col in column_names if 'password' in col.lower()]
                        if password_cols:
                            # Check if passwords are hashed
                            cursor.execute(f"SELECT {password_cols[0]} FROM {table} LIMIT 1;")
                            result = cursor.fetchone()
                            if result and result[0]:
                                password = result[0]
                                if len(password) < 32:  # Likely plaintext
                                    self.log_finding('critical', 'Database', db_path, 0,
                                                   f"Passwords in {table} appear to be plaintext")
                                elif password.startswith('$2b$') or password.startswith('pbkdf2'):
                                    self.log_finding('info', 'Database', db_path, 0,
                                                   f"Passwords in {table} appear properly hashed")
                                else:
                                    self.log_finding('medium', 'Database', db_path, 0,
                                                   f"Passwords in {table} use unknown hashing")
                    except Exception as e:
                        self.log_finding('medium', 'Database', db_path, 0, f"Could not analyze table {table}: {e}")
            else:
                self.log_finding('high', 'Database', db_path, 0, "No authentication tables found")

            conn.close()

        except Exception as e:
            self.log_finding('medium', 'Database', db_path, 0, f"Could not connect to database: {e}")

    def _audit_db_config(self, file_path):
        """Audit database configuration file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')

            security_patterns = [
                (r'SECRET_KEY.*=.*["\'][^"\']{1,16}["\']', 'Weak secret key (too short)'),
                (r'SECRET_KEY.*=.*["\']default["\']', 'Default secret key'),
                (r'SECRET_KEY.*=.*["\']secret["\']', 'Insecure secret key'),
                (r'DATABASE.*password.*=.*["\']["\']', 'Empty database password'),
                (r'SQLALCHEMY_DATABASE_URI.*sqlite:///', 'SQLite database (consider PostgreSQL for production)'),
                (r'DEBUG.*=.*True', 'Debug mode enabled'),
                (r'SESSION_COOKIE_SECURE.*=.*False', 'Insecure session cookies'),
                (r'SESSION_COOKIE_HTTPONLY.*=.*False', 'Non-HTTPOnly session cookies')
            ]

            for line_num, line in enumerate(lines, 1):
                for pattern, description in security_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        level = 'critical' if 'weak' in description.lower() or 'default' in description.lower() else 'high'
                        level = 'medium' if 'sqlite' in description.lower() else level
                        self.log_finding(level, 'Configuration', file_path, line_num, description)

        except Exception as e:
            self.log_finding('medium', 'File Error', file_path, 0, f"Could not analyze config: {e}")

    def audit_session_management(self):
        """Audit session management security"""
        print(f"\n{self.colors['cyan']}🔑 Auditing Session Management{self.colors['reset']}")

        # Look for session-related code
        python_files = list(self.project_path.rglob("*.py"))

        for file_path in python_files:
            if file_path.name.startswith('.') or 'venv' in str(file_path):
                continue

            self._audit_session_code(file_path)

    def _audit_session_code(self, file_path):
        """Audit session management code in a file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')

            session_patterns = [
                (r'session\.permanent.*=.*True', 'Permanent sessions enabled'),
                (r'session\[.*\].*=.*request\.', 'Session data from user input'),
                (r'session\.clear\(\)', 'Session clearing found'),
                (r'session\.pop\(', 'Session data removal'),
                (r'remember_me.*token', 'Remember me functionality'),
                (r'session_id.*=', 'Session ID management'),
                (r'csrf.*token', 'CSRF token handling'),
                (r'session.*timeout', 'Session timeout configuration')
            ]

            for line_num, line in enumerate(lines, 1):
                for pattern, description in session_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        level = 'medium' if 'user input' in description else 'info'
                        self.log_finding(level, 'Session Management', file_path, line_num, description)

        except Exception as e:
            pass  # Skip files that can't be read

    def generate_auth_report(self):
        """Generate comprehensive authentication security report"""
        print(f"\n{self.colors['purple']}📊 Authentication Security Report{self.colors['reset']}")
        print("=" * 80)

        # Summary statistics
        total_findings = sum(len(findings) for findings in self.findings.values())
        critical_count = len(self.findings['critical'])
        high_count = len(self.findings['high'])
        medium_count = len(self.findings['medium'])

        print(f"\n📈 Summary Statistics:")
        print(f"  Total Findings: {total_findings}")
        print(f"  Critical: {critical_count}")
        print(f"  High: {high_count}")
        print(f"  Medium: {medium_count}")
        print(f"  Protected Routes: {len(self.protected_routes)}")
        print(f"  Unprotected Sensitive Routes: {len(self.unprotected_routes)}")

        # Authentication strength assessment
        auth_score = self._calculate_auth_score()
        print(f"\n🎯 Authentication Security Score: {auth_score}/100")

        if auth_score >= 80:
            status = f"{self.colors['green']}✅ GOOD{self.colors['reset']}"
        elif auth_score >= 60:
            status = f"{self.colors['yellow']}⚠️ NEEDS IMPROVEMENT{self.colors['reset']}"
        else:
            status = f"{self.colors['red']}❌ POOR{self.colors['reset']}"

        print(f"  Status: {status}")

        # Top security issues
        if critical_count > 0:
            print(f"\n🚨 Critical Issues Requiring Immediate Attention:")
            for finding in self.findings['critical'][:5]:  # Top 5 critical
                print(f"  • {finding['file']}:{finding['line']} - {finding['issue']}")

        # Recommendations
        print(f"\n💡 Security Recommendations:")
        recommendations = self._generate_auth_recommendations()
        for i, rec in enumerate(recommendations[:10], 1):
            print(f"  {i}. {rec}")

        print(f"\n⏰ Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return total_findings, critical_count, high_count

    def _calculate_auth_score(self):
        """Calculate authentication security score (0-100)"""
        score = 100

        # Deduct points for findings
        score -= len(self.findings['critical']) * 20
        score -= len(self.findings['high']) * 10
        score -= len(self.findings['medium']) * 5

        # Bonus points for good practices
        if len(self.protected_routes) > 0:
            score += 10

        # Ensure score is between 0 and 100
        return max(0, min(100, score))

    def _generate_auth_recommendations(self):
        """Generate security recommendations based on findings"""
        recommendations = []

        if len(self.unprotected_routes) > 0:
            recommendations.append("Add authentication decorators to unprotected sensitive routes")

        if any('secret key' in finding['issue'].lower() for finding in self.findings['critical']):
            recommendations.append("Generate a strong, random SECRET_KEY for production")

        if any('debug.*true' in finding['issue'].lower() for finding in self.findings['high']):
            recommendations.append("Disable DEBUG mode in production environment")

        if any('plaintext' in finding['issue'].lower() for finding in self.findings['critical']):
            recommendations.append("Implement proper password hashing using bcrypt or Argon2")

        if any('session' in finding['category'].lower() for finding in self.findings['high']):
            recommendations.append("Configure secure session cookies (Secure, HttpOnly, SameSite)")

        recommendations.extend([
            "Implement rate limiting on authentication endpoints",
            "Add account lockout after failed login attempts",
            "Implement strong password policy requirements",
            "Add multi-factor authentication for admin accounts",
            "Regular security audits and penetration testing"
        ])

        return recommendations

    def save_auth_report(self):
        """Save detailed authentication report to file"""
        report_file = self.project_path / "auth_security_report.json"

        report_data = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_findings': sum(len(findings) for findings in self.findings.values()),
                'critical_count': len(self.findings['critical']),
                'high_count': len(self.findings['high']),
                'medium_count': len(self.findings['medium']),
                'protected_routes': len(self.protected_routes),
                'unprotected_routes': len(self.unprotected_routes),
                'auth_score': self._calculate_auth_score()
            },
            'findings': dict(self.findings),
            'routes': {
                'protected': self.protected_routes,
                'unprotected_sensitive': self.unprotected_routes
            },
            'recommendations': self._generate_auth_recommendations()
        }

        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"\n💾 Detailed report saved to: {report_file}")
        return report_file

def main():
    """Main function to run authentication audit"""
    project_path = Path.cwd()

    print(f"🔐 Starting Comprehensive Authentication Audit")
    print(f"📊 Project: {project_path}")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    auditor = AuthAuditor(project_path)

    # Run all authentication audits
    auditor.audit_authentication_system()
    auditor.audit_route_protection()
    auditor.audit_database_security()
    auditor.audit_session_management()

    # Generate and save report
    total_findings, critical_count, high_count = auditor.generate_auth_report()
    auditor.save_auth_report()

    # Exit with appropriate code
    if critical_count > 0:
        sys.exit(1)  # Critical issues found
    elif high_count > 5:
        sys.exit(2)  # Many high-priority issues
    else:
        sys.exit(0)  # Success

if __name__ == "__main__":
    main()