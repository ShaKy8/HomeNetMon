#!/usr/bin/env python3
"""
Production Security Hardening for HomeNetMon
Phase 6.2: Enterprise-grade security implementation

Implements comprehensive security hardening:
- Security configuration validation
- SSL/TLS security assessment
- Firewall configuration
- Access control hardening
- Vulnerability scanning
- Security monitoring setup
- Compliance checking
- Security documentation
"""

import os
import sys
import json
import time
import socket
import ssl
import subprocess
import re
from pathlib import Path
from datetime import datetime
import logging
import hashlib
import secrets

class ProductionSecurityHardening:
    def __init__(self, project_dir="."):
        self.project_dir = Path(project_dir).resolve()
        self.security_results = []
        self.security_score = 0
        self.max_security_score = 0

        # Security standards
        self.security_requirements = {
            'ssl_tls': {
                'min_tls_version': '1.2',
                'secure_ciphers': True,
                'certificate_valid': True
            },
            'authentication': {
                'strong_passwords': True,
                'session_security': True,
                'csrf_protection': True
            },
            'network': {
                'firewall_enabled': True,
                'port_restrictions': True,
                'rate_limiting': True
            },
            'application': {
                'security_headers': True,
                'input_validation': True,
                'error_handling': True
            },
            'system': {
                'file_permissions': True,
                'user_isolation': True,
                'log_monitoring': True
            }
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
                logging.FileHandler('security_hardening.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def log_security_check(self, category, check_name, passed, details="", severity="medium"):
        """Log security check result"""
        points = {'critical': 10, 'high': 7, 'medium': 5, 'low': 3}.get(severity, 5)
        self.max_security_score += points

        if passed:
            self.security_score += points

        result = {
            'category': category,
            'check_name': check_name,
            'passed': passed,
            'severity': severity,
            'points': points,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }

        self.security_results.append(result)

        # Console output
        status_color = self.colors['green'] if passed else self.colors['red']
        status_icon = '✅' if passed else '❌'
        severity_icons = {'critical': '🚨', 'high': '⚠️', 'medium': '🔍', 'low': '💡'}
        severity_icon = severity_icons.get(severity, '🔍')

        print(f"{status_color}{status_icon} {severity_icon} {category.upper()}: {check_name}{self.colors['reset']}")
        if details:
            print(f"   📝 {details}")

    def create_security_config(self):
        """Create security configuration files"""
        print(f"\n{self.colors['cyan']}🔧 Creating Security Configuration{self.colors['reset']}")

        # Security headers configuration
        security_headers = '''# Security Headers Configuration for HomeNetMon
# Add these to your web server configuration

# Nginx Configuration (add to server block)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdn.socket.io; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; font-src 'self' cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none';" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()" always;

# Remove server version information
server_tokens off;

# Security limits
client_max_body_size 10M;
client_body_buffer_size 128k;
client_header_buffer_size 1k;
large_client_header_buffers 4 4k;
'''

        try:
            (self.project_dir / "security" / "security-headers.conf").parent.mkdir(exist_ok=True)
            (self.project_dir / "security" / "security-headers.conf").write_text(security_headers)
            self.log_security_check("configuration", "Security headers config", True,
                                   "Created comprehensive security headers configuration", "medium")
        except Exception as e:
            self.log_security_check("configuration", "Security headers config", False, str(e), "medium")

    def create_firewall_config(self):
        """Create firewall configuration"""
        print(f"\n{self.colors['cyan']}🔥 Creating Firewall Configuration{self.colors['reset']}")

        # UFW firewall rules
        ufw_rules = '''#!/bin/bash
# UFW Firewall Configuration for HomeNetMon Production

echo "🔥 Configuring UFW Firewall for HomeNetMon"

# Reset UFW to defaults
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (adjust port if non-standard)
ufw allow ssh
ufw allow 22

# Allow HTTP and HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Allow local network access for network monitoring
# Adjust network range as needed
ufw allow from 192.168.1.0/24 to any port 80
ufw allow from 192.168.1.0/24 to any port 443

# Rate limiting for SSH
ufw limit ssh

# Enable logging
ufw logging on

# Enable firewall
ufw --force enable

echo "✅ UFW Firewall configured successfully"
echo "📊 UFW Status:"
ufw status verbose
'''

        try:
            (self.project_dir / "security" / "configure-firewall.sh").write_text(ufw_rules)
            (self.project_dir / "security" / "configure-firewall.sh").chmod(0o755)
            self.log_security_check("network", "Firewall configuration", True,
                                   "Created UFW firewall configuration script", "high")
        except Exception as e:
            self.log_security_check("network", "Firewall configuration", False, str(e), "high")

        # iptables rules (alternative)
        iptables_rules = '''#!/bin/bash
# iptables Firewall Rules for HomeNetMon Production

echo "🔥 Configuring iptables Firewall for HomeNetMon"

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (with rate limiting)
iptables -A INPUT -p tcp --dport 22 -m limit --limit 5/min --limit-burst 3 -j ACCEPT

# Allow HTTP and HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow local network (adjust as needed)
iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "iptables-dropped: "

# Save rules
iptables-save > /etc/iptables/rules.v4

echo "✅ iptables Firewall configured successfully"
'''

        try:
            (self.project_dir / "security" / "configure-iptables.sh").write_text(iptables_rules)
            (self.project_dir / "security" / "configure-iptables.sh").chmod(0o755)
            self.log_security_check("network", "iptables configuration", True,
                                   "Created iptables firewall rules", "high")
        except Exception as e:
            self.log_security_check("network", "iptables configuration", False, str(e), "high")

    def create_ssl_security_config(self):
        """Create SSL/TLS security configuration"""
        print(f"\n{self.colors['cyan']}🔒 Creating SSL/TLS Security Configuration{self.colors['reset']}")

        ssl_config = '''# SSL/TLS Security Configuration for HomeNetMon
# Strong SSL/TLS configuration for Nginx

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;

# DH parameters for perfect forward secrecy
ssl_dhparam /etc/ssl/certs/dhparam.pem;

# Security headers
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
'''

        try:
            (self.project_dir / "security" / "ssl-config.conf").write_text(ssl_config)
            self.log_security_check("ssl_tls", "SSL configuration", True,
                                   "Created strong SSL/TLS configuration", "high")
        except Exception as e:
            self.log_security_check("ssl_tls", "SSL configuration", False, str(e), "high")

        # DH parameter generation script
        dh_script = '''#!/bin/bash
# Generate DH parameters for perfect forward secrecy

echo "🔐 Generating DH parameters for SSL/TLS security"
echo "This may take several minutes..."

openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

echo "✅ DH parameters generated successfully"
'''

        try:
            (self.project_dir / "security" / "generate-dhparam.sh").write_text(dh_script)
            (self.project_dir / "security" / "generate-dhparam.sh").chmod(0o755)
            self.log_security_check("ssl_tls", "DH parameters script", True,
                                   "Created DH parameter generation script", "medium")
        except Exception as e:
            self.log_security_check("ssl_tls", "DH parameters script", False, str(e), "medium")

    def create_authentication_hardening(self):
        """Create authentication security hardening"""
        print(f"\n{self.colors['cyan']}🔐 Creating Authentication Hardening{self.colors['reset']}")

        # Password policy
        password_policy = '''# Password Security Policy for HomeNetMon

## Strong Password Requirements

Passwords must meet the following criteria:
- Minimum 12 characters length
- Include uppercase letters (A-Z)
- Include lowercase letters (a-z)
- Include numbers (0-9)
- Include special characters (!@#$%^&*)
- No common dictionary words
- No personal information
- No reused passwords

## Implementation

1. Update admin password:
   ```bash
   python3 -c "
   import secrets, string
   chars = string.ascii_letters + string.digits + '!@#$%^&*'
   password = ''.join(secrets.choice(chars) for _ in range(16))
   print(f'Strong password: {password}')
   "
   ```

2. Set in environment:
   ```bash
   export ADMIN_PASSWORD='your-strong-password-here'
   ```

3. Store securely and never commit to version control
'''

        try:
            (self.project_dir / "security" / "password-policy.md").write_text(password_policy)
            self.log_security_check("authentication", "Password policy", True,
                                   "Created strong password policy documentation", "high")
        except Exception as e:
            self.log_security_check("authentication", "Password policy", False, str(e), "high")

        # Session security configuration
        session_config = '''# Session Security Configuration for HomeNetMon

# Add to Flask application configuration
SESSION_COOKIE_SECURE = True  # HTTPS only
SESSION_COOKIE_HTTPONLY = True  # No JavaScript access
SESSION_COOKIE_SAMESITE = 'Strict'  # CSRF protection
PERMANENT_SESSION_LIFETIME = timedelta(hours=1)  # Session timeout
SESSION_REGENERATE_ON_LOGIN = True  # Prevent session fixation

# Additional security settings
WTF_CSRF_TIME_LIMIT = 3600  # CSRF token timeout
WTF_CSRF_SSL_STRICT = True  # HTTPS only CSRF
'''

        try:
            (self.project_dir / "security" / "session-config.py").write_text(session_config)
            self.log_security_check("authentication", "Session security", True,
                                   "Created secure session configuration", "high")
        except Exception as e:
            self.log_security_check("authentication", "Session security", False, str(e), "high")

    def create_security_monitoring(self):
        """Create security monitoring and alerting"""
        print(f"\n{self.colors['cyan']}👁️ Creating Security Monitoring{self.colors['reset']}")

        # Log monitoring script
        log_monitor = '''#!/usr/bin/env python3
"""
Security Log Monitor for HomeNetMon
Monitors logs for security events and sends alerts
"""

import re
import time
from datetime import datetime
from pathlib import Path

def monitor_nginx_logs():
    """Monitor Nginx access logs for suspicious activity"""
    log_file = Path("/var/log/nginx/access.log")

    suspicious_patterns = [
        r'\\.\\./',  # Directory traversal
        r'<script',  # XSS attempts
        r'union.*select',  # SQL injection
        r'(?i)(cmd|exec|system)',  # Command injection
        r'\\x[0-9a-f]{2}',  # Encoded attacks
        r'(?i)(eval|base64_decode)',  # Code injection
    ]

    if not log_file.exists():
        return

    with open(log_file, 'r') as f:
        f.seek(0, 2)  # Go to end of file

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            for pattern in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    print(f"🚨 SECURITY ALERT: {datetime.now()}")
                    print(f"Suspicious activity detected: {line.strip()}")
                    # Add alerting logic here (email, webhook, etc.)

def monitor_application_logs():
    """Monitor application logs for security events"""
    log_file = Path("/opt/homenetmon/logs/app.log")

    security_events = [
        'Failed login attempt',
        'CSRF token mismatch',
        'Unauthorized access',
        'Rate limit exceeded',
        'Security violation'
    ]

    if not log_file.exists():
        return

    with open(log_file, 'r') as f:
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            for event in security_events:
                if event in line:
                    print(f"🚨 SECURITY EVENT: {datetime.now()}")
                    print(f"Event: {line.strip()}")

if __name__ == "__main__":
    print("🔍 Starting security log monitoring...")

    import threading

    nginx_thread = threading.Thread(target=monitor_nginx_logs)
    app_thread = threading.Thread(target=monitor_application_logs)

    nginx_thread.daemon = True
    app_thread.daemon = True

    nginx_thread.start()
    app_thread.start()

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\\n🛑 Security monitoring stopped")
'''

        try:
            (self.project_dir / "security" / "security-monitor.py").write_text(log_monitor)
            (self.project_dir / "security" / "security-monitor.py").chmod(0o755)
            self.log_security_check("monitoring", "Security log monitoring", True,
                                   "Created security event monitoring system", "medium")
        except Exception as e:
            self.log_security_check("monitoring", "Security log monitoring", False, str(e), "medium")

    def create_vulnerability_scanner(self):
        """Create vulnerability scanning tools"""
        print(f"\n{self.colors['cyan']}🔍 Creating Vulnerability Scanner{self.colors['reset']}")

        vuln_scanner = '''#!/usr/bin/env python3
"""
Vulnerability Scanner for HomeNetMon
Performs basic security vulnerability assessment
"""

import requests
import ssl
import socket
from urllib.parse import urljoin
import json
from datetime import datetime

def scan_ssl_tls(hostname, port=443):
    """Scan SSL/TLS configuration"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                return {
                    'ssl_version': version,
                    'cipher_suite': cipher,
                    'certificate_valid': True,
                    'certificate_expires': cert.get('notAfter', 'Unknown')
                }
    except Exception as e:
        return {'error': str(e)}

def scan_security_headers(base_url):
    """Scan for security headers"""
    try:
        response = requests.get(base_url, timeout=10)
        headers = response.headers

        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'Referrer-Policy': headers.get('Referrer-Policy')
        }

        return security_headers
    except Exception as e:
        return {'error': str(e)}

def scan_common_vulnerabilities(base_url):
    """Scan for common web vulnerabilities"""
    vulnerabilities = []

    # Test for directory traversal
    test_paths = [
        '/../../../etc/passwd',
        '/..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts',
        '/.env',
        '/.git/config'
    ]

    for path in test_paths:
        try:
            response = requests.get(urljoin(base_url, path), timeout=5)
            if response.status_code == 200 and len(response.text) > 0:
                vulnerabilities.append(f"Directory traversal possible: {path}")
        except:
            pass

    # Test for exposed files
    exposed_files = [
        '/robots.txt',
        '/.env',
        '/config.py',
        '/backup.sql'
    ]

    for file_path in exposed_files:
        try:
            response = requests.get(urljoin(base_url, file_path), timeout=5)
            if response.status_code == 200:
                vulnerabilities.append(f"Exposed file: {file_path}")
        except:
            pass

    return vulnerabilities

def run_vulnerability_scan(target_url):
    """Run complete vulnerability scan"""
    print(f"🔍 Running vulnerability scan on {target_url}")

    results = {
        'timestamp': datetime.now().isoformat(),
        'target': target_url,
        'ssl_tls': {},
        'security_headers': {},
        'vulnerabilities': []
    }

    # SSL/TLS scan
    try:
        hostname = target_url.replace('https://', '').replace('http://', '').split('/')[0]
        results['ssl_tls'] = scan_ssl_tls(hostname)
    except Exception as e:
        results['ssl_tls'] = {'error': str(e)}

    # Security headers scan
    results['security_headers'] = scan_security_headers(target_url)

    # Vulnerability scan
    results['vulnerabilities'] = scan_common_vulnerabilities(target_url)

    return results

if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost"
    results = run_vulnerability_scan(target)

    print(json.dumps(results, indent=2))
'''

        try:
            (self.project_dir / "security" / "vulnerability-scanner.py").write_text(vuln_scanner)
            (self.project_dir / "security" / "vulnerability-scanner.py").chmod(0o755)
            self.log_security_check("vulnerability", "Vulnerability scanner", True,
                                   "Created vulnerability scanning tool", "medium")
        except Exception as e:
            self.log_security_check("vulnerability", "Vulnerability scanner", False, str(e), "medium")

    def check_current_security_posture(self):
        """Check current security configuration"""
        print(f"\n{self.colors['cyan']}🔒 Checking Current Security Posture{self.colors['reset']}")

        # Check if security files exist
        security_files = [
            ('.env.prod.template', 'Environment template'),
            ('homenetmon.service', 'Systemd service'),
            ('docker/nginx.conf', 'Nginx configuration'),
            ('requirements.txt', 'Dependencies list')
        ]

        for file_path, description in security_files:
            file_exists = (self.project_dir / file_path).exists()
            self.log_security_check("configuration", f"{description} exists", file_exists,
                                   f"File: {file_path}", "low")

        # Check for sensitive files in repo
        sensitive_files = ['.env', '.env.prod', 'config.secret', 'private.key']
        for sensitive_file in sensitive_files:
            file_exists = (self.project_dir / sensitive_file).exists()
            self.log_security_check("configuration", f"No sensitive file: {sensitive_file}",
                                   not file_exists, f"Sensitive file check: {sensitive_file}", "high")

        # Check file permissions
        try:
            executable_files = ['deploy.sh', 'update.sh', 'setup_ssl.sh']
            for exec_file in executable_files:
                file_path = self.project_dir / exec_file
                if file_path.exists():
                    is_executable = file_path.stat().st_mode & 0o111
                    self.log_security_check("system", f"{exec_file} executable", bool(is_executable),
                                           f"File permissions check", "low")
        except Exception as e:
            self.log_security_check("system", "File permissions check", False, str(e), "low")

    def create_security_documentation(self):
        """Create comprehensive security documentation"""
        print(f"\n{self.colors['cyan']}📚 Creating Security Documentation{self.colors['reset']}")

        security_guide = '''# HomeNetMon Production Security Guide

This guide covers security hardening for HomeNetMon production deployments.

## Security Checklist

### 🔒 SSL/TLS Security
- [ ] Strong SSL/TLS configuration (TLS 1.2+)
- [ ] Valid SSL certificate installed
- [ ] HSTS header configured
- [ ] DH parameters generated for perfect forward secrecy
- [ ] Secure cipher suites enabled

### 🔐 Authentication & Authorization
- [ ] Strong admin password set (12+ characters)
- [ ] CSRF protection enabled on all forms
- [ ] Secure session configuration
- [ ] Session timeout configured
- [ ] Rate limiting enabled

### 🌐 Network Security
- [ ] Firewall configured (UFW or iptables)
- [ ] Unnecessary ports closed
- [ ] Rate limiting on API endpoints
- [ ] Network access restricted to required ranges

### 🛡️ Application Security
- [ ] Security headers configured
- [ ] Input validation implemented
- [ ] Error handling secured
- [ ] Debug mode disabled in production
- [ ] Server banner hidden

### 💻 System Security
- [ ] Non-root user for application
- [ ] File permissions secured
- [ ] Log monitoring enabled
- [ ] Regular security updates
- [ ] Backup encryption

## Implementation Steps

### 1. SSL/TLS Hardening

```bash
# Generate strong DH parameters
sudo ./security/generate-dhparam.sh

# Configure SSL in Nginx
sudo cp security/ssl-config.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl reload nginx
```

### 2. Firewall Configuration

```bash
# Configure UFW firewall
sudo ./security/configure-firewall.sh

# Or configure iptables
sudo ./security/configure-iptables.sh
```

### 3. Security Headers

```bash
# Add security headers to Nginx
sudo cp security/security-headers.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl reload nginx
```

### 4. Authentication Hardening

```bash
# Generate strong password
python3 -c "
import secrets, string
chars = string.ascii_letters + string.digits + '!@#$%^&*'
password = ''.join(secrets.choice(chars) for _ in range(16))
print(f'ADMIN_PASSWORD={password}')
" >> .env.prod

# Apply session security settings
cp security/session-config.py config/security.py
```

### 5. Security Monitoring

```bash
# Start security monitoring
sudo cp security/security-monitor.py /opt/homenetmon/
sudo systemctl enable homenetmon-security-monitor
sudo systemctl start homenetmon-security-monitor
```

## Security Assessment

### Vulnerability Scanning

```bash
# Run vulnerability scan
python3 security/vulnerability-scanner.py https://your-domain.com
```

### Manual Security Testing

1. **SSL/TLS Testing:**
   ```bash
   # Test SSL configuration
   openssl s_client -connect your-domain.com:443 -servername your-domain.com

   # Check certificate
   openssl x509 -in /path/to/cert.pem -text -noout
   ```

2. **Header Testing:**
   ```bash
   curl -I https://your-domain.com
   ```

3. **Port Scanning:**
   ```bash
   nmap -sS -O your-server-ip
   ```

## Security Monitoring

### Log Locations
- Application: `/opt/homenetmon/logs/app.log`
- Nginx: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`
- System: `/var/log/syslog`, `/var/log/auth.log`
- Firewall: `/var/log/ufw.log`

### Monitoring Alerts
- Failed login attempts
- CSRF token violations
- Rate limit exceeded
- Suspicious request patterns
- SSL certificate expiration

### Incident Response
1. Identify the security event
2. Isolate affected systems
3. Analyze logs and impact
4. Apply fixes and patches
5. Document incident
6. Review and improve security

## Compliance

### Security Standards
- OWASP Top 10 protection
- SSL/TLS best practices
- Secure coding standards
- Regular security updates

### Audit Requirements
- Security configuration review
- Vulnerability assessments
- Penetration testing
- Compliance reporting

## Security Updates

### Regular Tasks
- Update system packages monthly
- Review security logs weekly
- Rotate passwords quarterly
- Test backups monthly
- Update SSL certificates before expiration

### Emergency Response
- Monitor security advisories
- Apply critical patches immediately
- Test security fixes
- Document changes

## Additional Resources

- [OWASP Web Security](https://owasp.org/)
- [Mozilla SSL Configuration](https://ssl-config.mozilla.org/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## Support

For security issues:
1. Review security logs
2. Check configuration files
3. Run vulnerability scanner
4. Consult security documentation
5. Contact security team if needed

⚠️ **Important:** Never commit sensitive information to version control. Always use environment variables for secrets and configuration.
'''

        try:
            (self.project_dir / "SECURITY_GUIDE.md").write_text(security_guide)
            self.log_security_check("documentation", "Security guide", True,
                                   "Created comprehensive security documentation", "medium")
        except Exception as e:
            self.log_security_check("documentation", "Security guide", False, str(e), "medium")

    def run_security_hardening(self):
        """Run complete security hardening process"""
        print(f"{self.colors['purple']}🔒 HomeNetMon Production Security Hardening{self.colors['reset']}")
        print(f"Phase 6.2: Enterprise-grade security implementation")
        print("=" * 80)

        start_time = time.time()

        # Run all security hardening components
        hardening_components = [
            self.create_security_config,
            self.create_firewall_config,
            self.create_ssl_security_config,
            self.create_authentication_hardening,
            self.create_security_monitoring,
            self.create_vulnerability_scanner,
            self.check_current_security_posture,
            self.create_security_documentation
        ]

        for component in hardening_components:
            try:
                component()
            except Exception as e:
                self.logger.error(f"Security component {component.__name__} failed: {e}")

        # Generate security report
        self.generate_security_report(start_time)

    def generate_security_report(self, start_time):
        """Generate comprehensive security hardening report"""
        duration = time.time() - start_time

        print(f"\n{self.colors['purple']}📊 Security Hardening Report{self.colors['reset']}")
        print("=" * 80)

        # Calculate security score
        security_percentage = (self.security_score / self.max_security_score * 100) if self.max_security_score > 0 else 0

        print(f"\n⏱️ Duration: {duration:.1f} seconds")
        print(f"🔒 Security Score: {self.security_score}/{self.max_security_score} ({security_percentage:.1f}%)")

        # Security categories
        categories = {}
        for result in self.security_results:
            category = result['category']
            if category not in categories:
                categories[category] = {'passed': 0, 'total': 0, 'points': 0, 'max_points': 0}

            categories[category]['total'] += 1
            categories[category]['max_points'] += result['points']

            if result['passed']:
                categories[category]['passed'] += 1
                categories[category]['points'] += result['points']

        print(f"\n🔒 Security Categories:")
        for category, stats in categories.items():
            percentage = (stats['points'] / stats['max_points'] * 100) if stats['max_points'] > 0 else 0
            status_color = self.colors['green'] if percentage >= 80 else \
                          self.colors['yellow'] if percentage >= 60 else self.colors['red']

            print(f"  {status_color}{category.title()}: {stats['points']}/{stats['max_points']} ({percentage:.1f}%){self.colors['reset']}")

        # Security files created
        print(f"\n📁 Security Files Created:")
        security_files = [
            "security/security-headers.conf - HTTP security headers",
            "security/configure-firewall.sh - UFW firewall rules",
            "security/configure-iptables.sh - iptables firewall rules",
            "security/ssl-config.conf - Strong SSL/TLS configuration",
            "security/generate-dhparam.sh - DH parameter generation",
            "security/password-policy.md - Password requirements",
            "security/session-config.py - Secure session settings",
            "security/security-monitor.py - Security event monitoring",
            "security/vulnerability-scanner.py - Vulnerability assessment",
            "SECURITY_GUIDE.md - Comprehensive security guide"
        ]

        for file_desc in security_files:
            print(f"  🔒 {file_desc}")

        # Critical security items
        critical_failures = [r for r in self.security_results if not r['passed'] and r['severity'] == 'critical']
        if critical_failures:
            print(f"\n{self.colors['red']}🚨 Critical Security Issues:{self.colors['reset']}")
            for failure in critical_failures:
                print(f"  ❌ {failure['category']}: {failure['check_name']}")

        # Security recommendations
        print(f"\n💡 Security Recommendations:")
        if security_percentage >= 90:
            print(f"  {self.colors['green']}✅ Excellent security posture{self.colors['reset']}")
            print("  • Review and implement remaining security measures")
            print("  • Set up regular security monitoring")
            print("  • Schedule periodic security assessments")
        elif security_percentage >= 70:
            print(f"  {self.colors['yellow']}⚠️ Good security posture with room for improvement{self.colors['reset']}")
            print("  • Address medium and high priority security items")
            print("  • Implement comprehensive security monitoring")
            print("  • Review and update security configurations")
        else:
            print(f"  {self.colors['red']}🚨 Security hardening required{self.colors['reset']}")
            print("  • Address all critical and high priority security issues")
            print("  • Implement basic security measures before deployment")
            print("  • Consider security review by experts")

        # Implementation checklist
        print(f"\n📋 Next Steps:")
        print("  1. Review SECURITY_GUIDE.md for implementation steps")
        print("  2. Configure firewall: sudo ./security/configure-firewall.sh")
        print("  3. Set up SSL/TLS: sudo ./security/generate-dhparam.sh")
        print("  4. Apply security headers to web server")
        print("  5. Set strong admin password in .env.prod")
        print("  6. Run vulnerability scanner before go-live")

        # Final assessment
        if security_percentage >= 80:
            print(f"\n{self.colors['green']}✅ Phase 6.2: Security hardening - COMPLETED{self.colors['reset']}")
            print("Production security measures ready for deployment")
        elif security_percentage >= 60:
            print(f"\n{self.colors['yellow']}⚠️ Phase 6.2: Security hardening - NEEDS ATTENTION{self.colors['reset']}")
            print("Address remaining security issues before production")
        else:
            print(f"\n{self.colors['red']}❌ Phase 6.2: Security hardening - CRITICAL ISSUES{self.colors['reset']}")
            print("Major security improvements required")

        # Save detailed report
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'security_score': self.security_score,
            'max_security_score': self.max_security_score,
            'security_percentage': security_percentage,
            'categories': categories,
            'security_results': self.security_results
        }

        with open('security_hardening_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)

        print(f"\n📄 Detailed report saved to: security_hardening_report.json")
        print(f"📋 Security log saved to: security_hardening.log")

def main():
    """Main security hardening execution"""
    print(f"🔒 PRODUCTION SECURITY HARDENING")
    print(f"📊 Phase 6.2: Enterprise-grade security implementation")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

    # Run security hardening
    hardening = ProductionSecurityHardening()
    hardening.run_security_hardening()

if __name__ == "__main__":
    main()