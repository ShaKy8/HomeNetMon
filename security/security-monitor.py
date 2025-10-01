#!/usr/bin/env python3
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
        r'\.\./',  # Directory traversal
        r'<script',  # XSS attempts
        r'union.*select',  # SQL injection
        r'(?i)(cmd|exec|system)',  # Command injection
        r'\x[0-9a-f]{2}',  # Encoded attacks
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
        print("\n🛑 Security monitoring stopped")
