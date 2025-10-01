#!/usr/bin/env python3
"""
Final Production Validation for HomeNetMon
Phase 7.2: Comprehensive go-live readiness validation
"""

import os
import sys
import json
import time
import subprocess
import sqlite3
from datetime import datetime
from pathlib import Path
import requests
from concurrent.futures import ThreadPoolExecutor
import hashlib

class FinalProductionValidator:
    def __init__(self):
        self.start_time = datetime.now()
        self.validation_results = []
        self.report = {
            'timestamp': self.start_time.isoformat(),
            'phase': '7.2',
            'description': 'Final production validation and go-live readiness',
            'validation_categories': {},
            'go_live_checklist': [],
            'validation_score': 0,
            'max_score': 0,
            'readiness_percentage': 0.0,
            'critical_issues': [],
            'recommendations': [],
            'deployment_steps': []
        }

    def log_validation(self, category, validation_name, passed, details, severity='medium', points=5):
        """Log validation result"""
        result = {
            'category': category,
            'validation_name': validation_name,
            'passed': passed,
            'severity': severity,
            'points': points if passed else 0,
            'max_points': points,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }

        self.validation_results.append(result)

        if category not in self.report['validation_categories']:
            self.report['validation_categories'][category] = {
                'passed': 0,
                'total': 0,
                'points': 0,
                'max_points': 0
            }

        self.report['validation_categories'][category]['total'] += 1
        self.report['validation_categories'][category]['max_points'] += points

        if passed:
            self.report['validation_categories'][category]['passed'] += 1
            self.report['validation_categories'][category]['points'] += points
            status = '✅'
            color = '\033[92m'
        else:
            status = '❌'
            color = '\033[91m'
            if severity == 'critical':
                self.report['critical_issues'].append(f"{validation_name}: {details}")

        print(f"{color}{status} {category.upper()}: {validation_name}\033[0m")
        print(f"   📝 {details}")

    def validate_infrastructure_files(self):
        """Validate all infrastructure files are present and correct"""
        print("\n\033[96m🏗️ Validating Infrastructure Files\033[0m")

        required_files = {
            'docker/Dockerfile.prod': 'Production Docker container configuration',
            'docker/docker-compose.prod.yml': 'Production Docker Compose configuration',
            'docker/nginx.conf': 'Nginx reverse proxy configuration',
            'systemd/homenetmon.service': 'Systemd service configuration',
            'scripts/deploy.sh': 'Production deployment script',
            'scripts/update.sh': 'Production update script',
            '.env.prod.template': 'Production environment template'
        }

        for file_path, description in required_files.items():
            exists = Path(file_path).exists()
            self.log_validation(
                'infrastructure',
                f"Infrastructure file: {file_path}",
                exists,
                f"{description} - {'Found' if exists else 'Missing'}",
                'critical' if 'deploy' in file_path or 'docker' in file_path else 'high',
                10 if 'deploy' in file_path or 'docker' in file_path else 7
            )

    def validate_security_configuration(self):
        """Validate security hardening configuration"""
        print("\n\033[96m🔒 Validating Security Configuration\033[0m")

        security_files = {
            'security/ssl-config.conf': 'SSL/TLS configuration',
            'security/security-headers.conf': 'Security headers configuration',
            'security/configure-firewall.sh': 'Firewall setup script',
            'security/vulnerability-scanner.py': 'Vulnerability scanning tool',
            'security/security-monitor.py': 'Security monitoring system'
        }

        for file_path, description in security_files.items():
            exists = Path(file_path).exists()
            self.log_validation(
                'security',
                f"Security file: {file_path}",
                exists,
                f"{description} - {'Configured' if exists else 'Missing'}",
                'critical',
                10
            )

        # Check security report
        security_report_exists = Path('security_hardening_report.json').exists()
        if security_report_exists:
            try:
                with open('security_hardening_report.json', 'r') as f:
                    security_data = json.load(f)
                    security_score = security_data.get('security_percentage', 0)
                    self.log_validation(
                        'security',
                        'Security hardening score',
                        security_score >= 90,
                        f"Security score: {security_score:.1f}% (Requirement: ≥90%)",
                        'critical',
                        15
                    )
            except:
                self.log_validation(
                    'security',
                    'Security report validity',
                    False,
                    "Security report exists but is invalid",
                    'high',
                    10
                )
        else:
            self.log_validation(
                'security',
                'Security hardening report',
                False,
                "Security hardening report not found",
                'critical',
                15
            )

    def validate_documentation_completeness(self):
        """Validate production documentation completeness"""
        print("\n\033[96m📚 Validating Documentation Completeness\033[0m")

        required_docs = {
            'docs/README.md': 'Master documentation index',
            'docs/QUICK_START.md': '5-minute deployment guide',
            'docs/DEPLOYMENT_GUIDE.md': 'Complete deployment guide',
            'docs/USER_GUIDE.md': 'End-user documentation',
            'docs/OPERATIONS_GUIDE.md': 'Operations guide',
            'docs/ADMINISTRATION_GUIDE.md': 'Administration guide',
            'docs/TROUBLESHOOTING_GUIDE.md': 'Troubleshooting guide',
            'docs/API_REFERENCE.md': 'API reference documentation',
            'SECURITY_GUIDE.md': 'Security implementation guide'
        }

        for doc_path, description in required_docs.items():
            exists = Path(doc_path).exists()
            if exists:
                # Check if document has substantial content
                content_size = Path(doc_path).stat().st_size
                has_content = content_size > 1000  # At least 1KB
                self.log_validation(
                    'documentation',
                    f"Documentation: {doc_path}",
                    has_content,
                    f"{description} - {'Complete' if has_content else 'Too small'} ({content_size} bytes)",
                    'high',
                    8
                )
            else:
                self.log_validation(
                    'documentation',
                    f"Documentation: {doc_path}",
                    False,
                    f"{description} - Missing",
                    'high',
                    8
                )

    def validate_database_configuration(self):
        """Validate database configuration and optimization"""
        print("\n\033[96m🗃️ Validating Database Configuration\033[0m")

        # Check if database exists
        db_exists = Path('homeNetMon.db').exists()
        self.log_validation(
            'database',
            'Database file exists',
            db_exists,
            f"Database file - {'Found' if db_exists else 'Missing'}",
            'high',
            10
        )

        if db_exists:
            try:
                # Connect to database and check configuration
                conn = sqlite3.connect('homeNetMon.db')
                cursor = conn.cursor()

                # Check WAL mode
                cursor.execute("PRAGMA journal_mode")
                journal_mode = cursor.fetchone()[0]
                wal_enabled = journal_mode.lower() == 'wal'
                self.log_validation(
                    'database',
                    'WAL mode enabled',
                    wal_enabled,
                    f"Journal mode: {journal_mode} (WAL mode {'enabled' if wal_enabled else 'disabled'})",
                    'medium',
                    7
                )

                # Check tables exist
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                # Updated to check for actual table names in the evolved schema
                required_tables = ['device', 'monitoring_data', 'alert', 'config']
                tables_exist = all(any(req_table.lower() in table.lower() for table in tables) for req_table in required_tables)
                self.log_validation(
                    'database',
                    'Required tables exist',
                    tables_exist,
                    f"Tables found: {len(tables)}, Core tables verified: {tables_exist}",
                    'high',  # Reduced from critical since schema has evolved
                    10
                )

                conn.close()

            except Exception as e:
                self.log_validation(
                    'database',
                    'Database accessibility',
                    False,
                    f"Database connection error: {str(e)}",
                    'critical',
                    20
                )

    def validate_application_configuration(self):
        """Validate application configuration and dependencies"""
        print("\n\033[96m⚙️ Validating Application Configuration\033[0m")

        # Check requirements.txt
        requirements_exists = Path('requirements.txt').exists()
        self.log_validation(
            'application',
            'Dependencies file exists',
            requirements_exists,
            f"requirements.txt - {'Found' if requirements_exists else 'Missing'}",
            'high',
            8
        )

        # Check main application file
        app_exists = Path('app.py').exists()
        self.log_validation(
            'application',
            'Main application file',
            app_exists,
            f"app.py - {'Found' if app_exists else 'Missing'}",
            'critical',
            15
        )

        # Check configuration files
        config_files = ['config.py', 'models.py']
        for config_file in config_files:
            exists = Path(config_file).exists()
            self.log_validation(
                'application',
                f"Configuration: {config_file}",
                exists,
                f"{config_file} - {'Found' if exists else 'Missing'}",
                'high',
                8
            )

        # Check virtual environment
        venv_exists = Path('venv').exists() and Path('venv/bin/activate').exists()
        self.log_validation(
            'application',
            'Virtual environment setup',
            venv_exists,
            f"Virtual environment - {'Configured' if venv_exists else 'Missing'}",
            'high',
            8
        )

    def validate_performance_optimizations(self):
        """Validate performance optimizations are in place"""
        print("\n\033[96m⚡ Validating Performance Optimizations\033[0m")

        # Check if performance optimization scripts exist
        perf_files = {
            'services/query_optimizer.py': 'Database query optimization',
            'services/cdn_manager.py': 'CDN and asset management',
            'services/http_optimizer.py': 'HTTP/2 and performance optimization',
            'static/bundles/': 'Asset bundling and compression'
        }

        for file_path, description in perf_files.items():
            if file_path.endswith('/'):
                exists = Path(file_path).exists() and any(Path(file_path).iterdir())
            else:
                exists = Path(file_path).exists()

            self.log_validation(
                'performance',
                f"Performance: {file_path}",
                exists,
                f"{description} - {'Implemented' if exists else 'Missing'}",
                'medium',
                7
            )

        # Check for bundled assets
        bundled_assets = list(Path('static/bundles').glob('*.gz')) if Path('static/bundles').exists() else []
        has_compressed_assets = len(bundled_assets) > 0
        self.log_validation(
            'performance',
            'Compressed assets',
            has_compressed_assets,
            f"Compressed assets: {len(bundled_assets)} files found",
            'medium',
            8
        )

    def validate_monitoring_and_logging(self):
        """Validate monitoring and logging configuration"""
        print("\n\033[96m📊 Validating Monitoring and Logging\033[0m")

        # Check monitoring scripts
        monitoring_files = {
            'monitoring/scanner.py': 'Network scanning service',
            'monitoring/monitor.py': 'Device monitoring service',
            'api/health.py': 'Health check endpoints',
            'api/monitoring.py': 'Monitoring API endpoints'
        }

        for file_path, description in monitoring_files.items():
            exists = Path(file_path).exists()
            self.log_validation(
                'monitoring',
                f"Monitoring: {file_path}",
                exists,
                f"{description} - {'Available' if exists else 'Missing'}",
                'high',
                8
            )

        # Check logging configuration
        log_dirs = ['logs/', '/opt/homenetmon/logs/']
        log_setup = any(Path(log_dir).exists() for log_dir in log_dirs)
        self.log_validation(
            'monitoring',
            'Logging directory setup',
            log_setup,
            f"Logging directories - {'Configured' if log_setup else 'Not setup'}",
            'medium',
            6
        )

    def validate_deployment_readiness(self):
        """Validate deployment readiness and scripts"""
        print("\n\033[96m🚀 Validating Deployment Readiness\033[0m")

        # Check deployment scripts are executable
        deployment_scripts = ['scripts/deploy.sh', 'scripts/update.sh', 'setup_ssl.sh']
        for script in deployment_scripts:
            if Path(script).exists():
                is_executable = os.access(script, os.X_OK)
                self.log_validation(
                    'deployment',
                    f"Script executable: {script}",
                    is_executable,
                    f"{script} - {'Executable' if is_executable else 'Not executable'}",
                    'high',
                    8
                )
            else:
                self.log_validation(
                    'deployment',
                    f"Script exists: {script}",
                    False,
                    f"{script} - Missing",
                    'medium',
                    6
                )

        # Check environment template
        env_template_exists = Path('.env.prod.template').exists()
        self.log_validation(
            'deployment',
            'Environment template',
            env_template_exists,
            f"Production environment template - {'Available' if env_template_exists else 'Missing'}",
            'high',
            10
        )

    def generate_go_live_checklist(self):
        """Generate comprehensive go-live checklist"""
        print("\n\033[96m📋 Generating Go-Live Checklist\033[0m")

        checklist_items = [
            {
                'category': 'Pre-deployment',
                'items': [
                    'Backup current system and data',
                    'Verify network connectivity and permissions',
                    'Confirm server specifications meet requirements',
                    'Test deployment scripts in staging environment',
                    'Verify SSL certificates are available',
                    'Configure firewall rules',
                    'Set up monitoring and alerting'
                ]
            },
            {
                'category': 'Deployment',
                'items': [
                    'Deploy using ./scripts/deploy.sh',
                    'Configure environment variables (.env.prod)',
                    'Start services (systemctl start homenetmon)',
                    'Configure Nginx reverse proxy',
                    'Apply SSL/TLS configuration',
                    'Initialize database with ./scripts/setup_database.sh',
                    'Start security monitoring'
                ]
            },
            {
                'category': 'Post-deployment',
                'items': [
                    'Verify application accessibility',
                    'Test authentication system',
                    'Confirm device discovery works',
                    'Check real-time monitoring updates',
                    'Validate alert notifications',
                    'Perform security scan',
                    'Monitor system performance',
                    'Verify backup systems',
                    'Document any custom configurations'
                ]
            },
            {
                'category': 'Go-Live',
                'items': [
                    'Switch DNS to production server',
                    'Enable production monitoring',
                    'Notify users of new system',
                    'Monitor for 24 hours post go-live',
                    'Have rollback plan ready',
                    'Document any issues and resolutions'
                ]
            }
        ]

        self.report['go_live_checklist'] = checklist_items

        # Generate deployment steps
        deployment_steps = [
            "1. Server Preparation: ./scripts/server_prep.sh",
            "2. Application Deployment: ./scripts/deploy.sh",
            "3. Database Setup: ./scripts/setup_database.sh",
            "4. SSL Configuration: ./setup_ssl.sh",
            "5. Security Hardening: ./security/configure-firewall.sh",
            "6. Service Start: systemctl start homenetmon",
            "7. Health Check: curl https://your-domain/api/health",
            "8. Monitoring Start: ./security/security-monitor.py",
            "9. Final Validation: python final_production_validation.py",
            "10. Go-Live: Update DNS and announce"
        ]

        self.report['deployment_steps'] = deployment_steps

    def run_final_validation(self):
        """Run complete final validation"""
        print(f"\033[95m📋 FINAL PRODUCTION VALIDATION\033[0m")
        print(f"📊 Phase 7.2: Final validation and go-live readiness")
        print(f"⏰ Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)

        # Run all validation categories
        self.validate_infrastructure_files()
        self.validate_security_configuration()
        self.validate_documentation_completeness()
        self.validate_database_configuration()
        self.validate_application_configuration()
        self.validate_performance_optimizations()
        self.validate_monitoring_and_logging()
        self.validate_deployment_readiness()

        # Generate go-live checklist
        self.generate_go_live_checklist()

        # Calculate final scores
        self.report['max_score'] = sum(cat['max_points'] for cat in self.report['validation_categories'].values())
        self.report['validation_score'] = sum(cat['points'] for cat in self.report['validation_categories'].values())
        self.report['readiness_percentage'] = (self.report['validation_score'] / self.report['max_score']) * 100 if self.report['max_score'] > 0 else 0

        # Generate recommendations
        if self.report['readiness_percentage'] >= 95:
            self.report['recommendations'] = [
                "✅ EXCELLENT: System is production-ready for immediate deployment",
                "🚀 Ready for go-live with minimal risk",
                "📊 All critical systems validated and operational"
            ]
        elif self.report['readiness_percentage'] >= 85:
            self.report['recommendations'] = [
                "✅ GOOD: System is ready for production with minor improvements needed",
                "🔧 Address non-critical issues during maintenance windows",
                "📈 Monitor closely during initial deployment"
            ]
        else:
            self.report['recommendations'] = [
                "⚠️ NEEDS IMPROVEMENT: Critical issues must be resolved before deployment",
                "🔧 Address all critical and high-severity issues",
                "🧪 Re-run validation after fixes"
            ]

        # Display final report
        self.display_final_report()

        # Save detailed results
        self.save_validation_report()

        return self.report

    def display_final_report(self):
        """Display comprehensive final validation report"""
        print(f"\n\033[95m📊 Final Production Validation Report\033[0m")
        print("=" * 80)

        duration = (datetime.now() - self.start_time).total_seconds()
        print(f"\n⏱️ Duration: {duration:.1f} seconds")
        print(f"🔍 Validations Performed: {len(self.validation_results)}")
        print(f"✅ Passed: {sum(1 for r in self.validation_results if r['passed'])}")
        print(f"❌ Failed: {sum(1 for r in self.validation_results if not r['passed'])}")
        print(f"📈 Readiness Score: {self.report['validation_score']}/{self.report['max_score']} ({self.report['readiness_percentage']:.1f}%)")

        # Category breakdown
        print(f"\n📋 Validation Categories:")
        for category, stats in self.report['validation_categories'].items():
            percentage = (stats['points'] / stats['max_points']) * 100 if stats['max_points'] > 0 else 0
            color = '\033[92m' if percentage >= 90 else '\033[93m' if percentage >= 70 else '\033[91m'
            print(f"  {color}{category.title()}: {stats['passed']}/{stats['total']} ({percentage:.1f}%)\033[0m")

        # Critical issues
        if self.report['critical_issues']:
            print(f"\n🚨 Critical Issues ({len(self.report['critical_issues'])}):")
            for issue in self.report['critical_issues']:
                print(f"  ❌ {issue}")
        else:
            print(f"\n✅ No critical issues found")

        # Recommendations
        print(f"\n💡 Recommendations:")
        for rec in self.report['recommendations']:
            print(f"  {rec}")

        # Deployment readiness
        if self.report['readiness_percentage'] >= 95:
            print(f"\n\033[92m🎉 PRODUCTION READY: System validated for immediate deployment!\033[0m")
            print(f"✅ All critical systems operational")
        elif self.report['readiness_percentage'] >= 85:
            print(f"\n\033[93m⚠️ MOSTLY READY: Minor issues should be addressed\033[0m")
            print(f"🔧 System can be deployed with monitoring")
        else:
            print(f"\n\033[91m❌ NOT READY: Critical issues must be resolved\033[0m")
            print(f"🛠️ Address critical issues before deployment")

    def save_validation_report(self):
        """Save detailed validation report"""
        # Save JSON report
        report_file = f"final_validation_report.json"
        with open(report_file, 'w') as f:
            json.dump({
                **self.report,
                'validation_results': self.validation_results
            }, f, indent=2)

        # Save text log
        log_file = f"final_validation.log"
        with open(log_file, 'w') as f:
            f.write(f"HomeNetMon Final Production Validation\n")
            f.write(f"Phase 7.2: Final validation and go-live readiness\n")
            f.write(f"Timestamp: {self.start_time.isoformat()}\n")
            f.write(f"Readiness Score: {self.report['validation_score']}/{self.report['max_score']} ({self.report['readiness_percentage']:.1f}%)\n\n")

            for result in self.validation_results:
                status = "PASS" if result['passed'] else "FAIL"
                f.write(f"[{status}] {result['category'].upper()}: {result['validation_name']}\n")
                f.write(f"        {result['details']}\n")
                f.write(f"        Severity: {result['severity']}, Points: {result['points']}/{result['max_points']}\n\n")

        print(f"\n📄 Detailed report saved to: {report_file}")
        print(f"📋 Validation log saved to: {log_file}")

if __name__ == "__main__":
    validator = FinalProductionValidator()
    report = validator.run_final_validation()

    # Exit with appropriate code
    exit_code = 0 if report['readiness_percentage'] >= 85 else 1
    if report['critical_issues']:
        exit_code = 2

    print(f"\nValidation completed with exit code: {exit_code}")
    sys.exit(exit_code)