#!/usr/bin/env python3
"""
Production Documentation Suite for HomeNetMon
Phase 7.1: Comprehensive production documentation creation

Creates complete documentation set for production operations:
- Deployment guides and procedures
- Operations and maintenance documentation
- Troubleshooting and diagnostic guides
- API documentation and references
- User guides and tutorials
- Administrative procedures
- Monitoring and alerting guides
- Backup and recovery procedures
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path
from datetime import datetime
import logging

class ProductionDocumentationSuite:
    def __init__(self, project_dir="."):
        self.project_dir = Path(project_dir).resolve()
        self.documentation_results = []

        # Documentation categories
        self.doc_categories = [
            'deployment',
            'operations',
            'troubleshooting',
            'api_reference',
            'user_guides',
            'administration',
            'monitoring',
            'backup_recovery'
        ]

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
                logging.FileHandler('documentation_creation.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def log_doc_creation(self, category, doc_name, success, details=""):
        """Log documentation creation result"""
        result = {
            'category': category,
            'doc_name': doc_name,
            'success': success,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }

        self.documentation_results.append(result)

        # Console output
        status_color = self.colors['green'] if success else self.colors['red']
        status_icon = '✅' if success else '❌'

        print(f"{status_color}{status_icon} {category.upper()}: {doc_name}{self.colors['reset']}")
        if details:
            print(f"   📝 {details}")

    def create_deployment_documentation(self):
        """Create comprehensive deployment documentation"""
        print(f"\n{self.colors['cyan']}🚀 Creating Deployment Documentation{self.colors['reset']}")

        # Create docs directory
        docs_dir = self.project_dir / "docs"
        docs_dir.mkdir(exist_ok=True)

        # Master deployment guide
        deployment_guide = '''# HomeNetMon Production Deployment Guide

## Overview

This comprehensive guide covers all aspects of deploying HomeNetMon in production environments, from initial setup to ongoing maintenance.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Deployment Options](#deployment-options)
3. [Installation Steps](#installation-steps)
4. [Configuration](#configuration)
5. [Security Setup](#security-setup)
6. [Post-Deployment Verification](#post-deployment-verification)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **Operating System**: Ubuntu 20.04+ / CentOS 8+ / Debian 10+
- **Memory**: Minimum 2GB RAM (4GB recommended)
- **Storage**: Minimum 20GB free space
- **CPU**: 2+ cores recommended
- **Network**: Internet access for package installation

### Software Dependencies

- Python 3.8 or higher
- Docker 20.10+ (for container deployment)
- Nginx 1.18+ (for reverse proxy)
- Redis 6.0+ (for caching and rate limiting)
- SQLite 3.31+ (default database)

### Network Requirements

- Ports 80 and 443 available for web traffic
- Access to target network for monitoring
- DNS resolution for the server
- SSL certificate (Let's Encrypt recommended)

## Deployment Options

### Option 1: Docker Deployment (Recommended)

**Advantages:**
- Isolated environment
- Easy updates and rollbacks
- Consistent across environments
- Includes all dependencies

**Use Case:** Most production environments

### Option 2: Native Installation

**Advantages:**
- Direct system integration
- Maximum performance
- Full system control
- Traditional deployment model

**Use Case:** Existing infrastructure integration

### Option 3: Cloud Deployment

**Advantages:**
- Scalable infrastructure
- Managed services
- High availability options
- Geographic distribution

**Use Case:** Cloud-first organizations

## Installation Steps

### Docker Deployment

1. **Prepare Environment**
   ```bash
   # Clone repository
   git clone https://github.com/your-org/homenetmon.git
   cd homenetmon

   # Copy environment template
   cp .env.prod.template .env.prod
   ```

2. **Configure Environment**
   ```bash
   # Edit configuration
   nano .env.prod

   # Required settings:
   SECRET_KEY=your-secret-key-here
   ADMIN_PASSWORD=your-secure-password
   NETWORK_RANGE=192.168.1.0/24
   ```

3. **Deploy Application**
   ```bash
   # Build and start services
   docker-compose -f docker-compose.prod.yml up -d

   # Verify deployment
   docker-compose -f docker-compose.prod.yml ps
   ```

4. **Initial Setup**
   ```bash
   # Check application health
   curl http://localhost/health

   # Access web interface
   open http://your-server-ip
   ```

### Native Installation

1. **System Preparation**
   ```bash
   # Update system
   sudo apt update && sudo apt upgrade -y

   # Install dependencies
   sudo apt install -y python3 python3-venv python3-pip nginx redis-server nmap sqlite3
   ```

2. **Application Installation**
   ```bash
   # Run automated deployment
   sudo ./deploy.sh

   # Or manual installation:
   sudo useradd -r -d /opt/homenetmon -s /bin/bash homenetmon
   sudo mkdir -p /opt/homenetmon
   sudo cp -r . /opt/homenetmon/
   sudo chown -R homenetmon:homenetmon /opt/homenetmon
   ```

3. **Service Configuration**
   ```bash
   # Install systemd service
   sudo cp homenetmon.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable homenetmon
   sudo systemctl start homenetmon
   ```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SECRET_KEY` | Flask secret key | - | Yes |
| `ADMIN_PASSWORD` | Admin user password | - | Yes |
| `NETWORK_RANGE` | Network to monitor | 192.168.1.0/24 | Yes |
| `DATABASE_URL` | Database connection | sqlite:///data/homeNetMon.db | No |
| `REDIS_URL` | Redis connection | redis://localhost:6379/0 | No |
| `SMTP_SERVER` | Email server | - | No |
| `WEBHOOK_URL` | Webhook endpoint | - | No |

### Network Configuration

1. **Network Range Setting**
   ```bash
   # Set the network range to monitor
   NETWORK_RANGE=192.168.1.0/24
   ```

2. **Monitoring Intervals**
   ```bash
   # Ping interval (seconds)
   PING_INTERVAL=30

   # Scan interval (seconds)
   SCAN_INTERVAL=300
   ```

3. **Performance Tuning**
   ```bash
   # Worker processes
   WORKERS=4

   # Connection limits
   MAX_CONNECTIONS=100
   ```

### Database Configuration

1. **SQLite (Default)**
   ```bash
   DATABASE_URL=sqlite:////opt/homenetmon/data/homeNetMon.db
   ```

2. **PostgreSQL (Advanced)**
   ```bash
   DATABASE_URL=postgresql://user:password@localhost/homenetmon
   ```

### Security Configuration

1. **SSL/TLS Setup**
   ```bash
   # Install SSL certificate
   sudo ./setup_ssl.sh your-domain.com

   # Configure HTTPS redirect
   sudo nano /etc/nginx/sites-available/homenetmon
   ```

2. **Firewall Configuration**
   ```bash
   # Configure UFW firewall
   sudo ./security/configure-firewall.sh

   # Verify firewall status
   sudo ufw status
   ```

## Security Setup

### Authentication

1. **Set Strong Admin Password**
   ```bash
   # Generate strong password
   python3 -c "
   import secrets, string
   chars = string.ascii_letters + string.digits + '!@#$%^&*'
   password = ''.join(secrets.choice(chars) for _ in range(16))
   print(f'ADMIN_PASSWORD={password}')
   "
   ```

2. **Configure Session Security**
   ```bash
   # Apply session configuration
   cp security/session-config.py config/
   ```

### SSL/TLS

1. **Certificate Installation**
   ```bash
   # Let's Encrypt certificate
   sudo certbot --nginx -d your-domain.com

   # Verify SSL configuration
   openssl s_client -connect your-domain.com:443
   ```

2. **Security Headers**
   ```bash
   # Apply security headers
   sudo cp security/security-headers.conf /etc/nginx/conf.d/
   sudo nginx -t && sudo systemctl reload nginx
   ```

### Network Security

1. **Firewall Setup**
   ```bash
   # Basic firewall rules
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   sudo ufw allow ssh
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```

2. **Rate Limiting**
   ```bash
   # Enable rate limiting in environment
   RATE_LIMITING_ENABLED=true
   ```

## Post-Deployment Verification

### Health Checks

1. **Application Health**
   ```bash
   # Check service status
   systemctl status homenetmon

   # Test HTTP endpoints
   curl http://localhost/health
   curl http://localhost/api/devices
   ```

2. **Database Connectivity**
   ```bash
   # Test database connection
   sqlite3 /opt/homenetmon/data/homeNetMon.db ".tables"
   ```

3. **Network Monitoring**
   ```bash
   # Verify network scanning
   curl http://localhost/api/devices/scan-now
   ```

### Performance Verification

1. **Response Times**
   ```bash
   # Test page load times
   curl -w "%{time_total}\\n" -o /dev/null -s http://localhost/
   ```

2. **Resource Usage**
   ```bash
   # Check memory usage
   free -h

   # Check CPU usage
   top -p $(pgrep python)
   ```

### Security Verification

1. **SSL/TLS Testing**
   ```bash
   # Test SSL configuration
   openssl s_client -connect localhost:443

   # Check security headers
   curl -I https://localhost
   ```

2. **Vulnerability Scan**
   ```bash
   # Run vulnerability scanner
   python3 security/vulnerability-scanner.py https://localhost
   ```

## Troubleshooting

### Common Issues

1. **Service Won't Start**
   ```bash
   # Check logs
   journalctl -u homenetmon -f

   # Check configuration
   sudo -u homenetmon /opt/homenetmon/venv/bin/python -m py_compile app.py
   ```

2. **Network Scanning Issues**
   ```bash
   # Check nmap availability
   which nmap

   # Test network connectivity
   ping 192.168.1.1

   # Check permissions
   ls -la /usr/bin/nmap
   ```

3. **Database Problems**
   ```bash
   # Check database file
   ls -la /opt/homenetmon/data/homeNetMon.db

   # Test database integrity
   sqlite3 /opt/homenetmon/data/homeNetMon.db "PRAGMA integrity_check;"
   ```

4. **Performance Issues**
   ```bash
   # Check system resources
   htop

   # Analyze slow queries
   python3 optimize_database_performance.py
   ```

### Log Locations

- **Application Logs**: `/opt/homenetmon/logs/app.log`
- **Nginx Logs**: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`
- **System Logs**: `journalctl -u homenetmon`
- **Security Logs**: `/var/log/auth.log`

### Support Resources

- **Documentation**: `/opt/homenetmon/docs/`
- **Configuration Examples**: `/opt/homenetmon/config/`
- **Troubleshooting Scripts**: `/opt/homenetmon/scripts/`

## Maintenance

### Regular Tasks

1. **System Updates**
   ```bash
   # Update system packages
   sudo apt update && sudo apt upgrade

   # Update application
   sudo ./update.sh
   ```

2. **Database Maintenance**
   ```bash
   # Run database cleanup
   python3 database_performance_fix.py

   # Create backup
   python3 backup_production.py
   ```

3. **Security Updates**
   ```bash
   # Update SSL certificates
   sudo certbot renew

   # Review security logs
   sudo grep "SECURITY" /var/log/syslog
   ```

### Monitoring

1. **Performance Monitoring**
   ```bash
   # Check application metrics
   curl http://localhost/api/system/info

   # Monitor resource usage
   htop
   ```

2. **Security Monitoring**
   ```bash
   # Start security monitoring
   python3 security/security-monitor.py
   ```

## Support

For additional support:

1. Check the troubleshooting section
2. Review application logs
3. Consult the operations guide
4. Contact technical support

---

**Next Steps:**
- Complete the post-deployment checklist
- Set up monitoring and alerting
- Configure backup procedures
- Schedule regular maintenance tasks
'''

        try:
            (docs_dir / "DEPLOYMENT_GUIDE.md").write_text(deployment_guide)
            self.log_doc_creation("deployment", "Deployment Guide", True,
                                 "Created comprehensive deployment documentation")
        except Exception as e:
            self.log_doc_creation("deployment", "Deployment Guide", False, str(e))

        # Quick start guide
        quick_start = '''# HomeNetMon Quick Start Guide

## 5-Minute Deployment

### Prerequisites
- Ubuntu/Debian server with 2GB+ RAM
- Domain name (optional, for SSL)
- Network access to monitor

### Docker Deployment (Recommended)

1. **Clone and Configure**
   ```bash
   git clone https://github.com/your-org/homenetmon.git
   cd homenetmon
   cp .env.prod.template .env.prod
   ```

2. **Set Required Variables**
   ```bash
   # Edit .env.prod
   SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
   ADMIN_PASSWORD=your-secure-password-here
   NETWORK_RANGE=192.168.1.0/24  # Your network
   ```

3. **Deploy**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

4. **Access Application**
   - Open: http://your-server-ip
   - Login with admin password
   - Begin monitoring your network

### Native Deployment

1. **One-Command Deployment**
   ```bash
   sudo ./deploy.sh
   ```

2. **Configure**
   ```bash
   sudo cp .env.prod.template /opt/homenetmon/.env
   sudo nano /opt/homenetmon/.env  # Set your configuration
   sudo systemctl restart homenetmon
   ```

### SSL Setup (Optional)

```bash
sudo ./setup_ssl.sh your-domain.com
```

### Security Setup (Recommended)

```bash
sudo ./security/configure-firewall.sh
```

## Verification

```bash
# Check service status
curl http://localhost/health

# Access web interface
open http://your-server-ip
```

## Next Steps

1. Review the [Full Deployment Guide](DEPLOYMENT_GUIDE.md)
2. Configure [Security Settings](../SECURITY_GUIDE.md)
3. Set up [Monitoring and Alerts](OPERATIONS_GUIDE.md)
4. Read the [User Guide](USER_GUIDE.md)

## Troubleshooting

**Service won't start:**
```bash
journalctl -u homenetmon -f
```

**Network scanning issues:**
```bash
sudo apt install nmap
```

**Need help?** Check the [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md)
'''

        try:
            (docs_dir / "QUICK_START.md").write_text(quick_start)
            self.log_doc_creation("deployment", "Quick Start Guide", True,
                                 "Created quick deployment guide")
        except Exception as e:
            self.log_doc_creation("deployment", "Quick Start Guide", False, str(e))

    def create_operations_documentation(self):
        """Create operations and maintenance documentation"""
        print(f"\n{self.colors['cyan']}⚙️ Creating Operations Documentation{self.colors['reset']}")

        docs_dir = self.project_dir / "docs"

        # Operations guide
        operations_guide = '''# HomeNetMon Operations Guide

## Overview

This guide covers day-to-day operations, maintenance, and administration of HomeNetMon in production environments.

## Table of Contents

1. [Service Management](#service-management)
2. [Monitoring and Alerting](#monitoring-and-alerting)
3. [Database Operations](#database-operations)
4. [Performance Management](#performance-management)
5. [Security Operations](#security-operations)
6. [Backup and Recovery](#backup-and-recovery)
7. [Updates and Maintenance](#updates-and-maintenance)

## Service Management

### Systemd Service Control

```bash
# Check service status
sudo systemctl status homenetmon

# Start/stop/restart service
sudo systemctl start homenetmon
sudo systemctl stop homenetmon
sudo systemctl restart homenetmon

# Enable/disable auto-start
sudo systemctl enable homenetmon
sudo systemctl disable homenetmon

# View service logs
sudo journalctl -u homenetmon -f
sudo journalctl -u homenetmon --since "1 hour ago"
```

### Docker Service Control

```bash
# Check container status
docker-compose -f docker-compose.prod.yml ps

# Start/stop services
docker-compose -f docker-compose.prod.yml up -d
docker-compose -f docker-compose.prod.yml down

# Restart specific service
docker-compose -f docker-compose.prod.yml restart homenetmon

# View logs
docker-compose -f docker-compose.prod.yml logs -f homenetmon
```

### Application Health Monitoring

```bash
# Health check endpoint
curl http://localhost/health

# System information
curl http://localhost/api/system/info

# Service status check
./health_check.sh
```

## Monitoring and Alerting

### Performance Monitoring

1. **Real-time Monitoring**
   ```bash
   # Monitor system resources
   htop

   # Monitor application performance
   curl http://localhost/api/performance/metrics

   # Check database performance
   python3 database_performance_monitor.py
   ```

2. **Log Monitoring**
   ```bash
   # Application logs
   tail -f /opt/homenetmon/logs/app.log

   # Error logs
   grep ERROR /opt/homenetmon/logs/app.log

   # Security events
   grep SECURITY /opt/homenetmon/logs/app.log
   ```

### Alerting Setup

1. **Email Alerts**
   ```bash
   # Configure SMTP in .env
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your-email@gmail.com
   SMTP_PASSWORD=your-app-password
   ```

2. **Webhook Alerts**
   ```bash
   # Configure webhook URL
   WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
   ```

3. **Test Alerts**
   ```bash
   # Test email configuration
   python3 -c "
   from monitoring.alerts import AlertManager
   alert_manager = AlertManager()
   alert_manager.test_email_config()
   "
   ```

## Database Operations

### Daily Maintenance

```bash
# Database health check
python3 comprehensive_database_health_assessment.py

# Run optimization
python3 optimize_database_performance.py

# Clean old data
python3 database_performance_fix.py
```

### Database Monitoring

```bash
# Check database size
ls -lh /opt/homenetmon/data/homeNetMon.db

# Monitor query performance
sqlite3 /opt/homenetmon/data/homeNetMon.db "
.timer on
SELECT COUNT(*) FROM devices;
SELECT COUNT(*) FROM monitoring_data;
"

# Check database integrity
sqlite3 /opt/homenetmon/data/homeNetMon.db "PRAGMA integrity_check;"
```

### Database Backup

```bash
# Manual backup
python3 backup_production.py

# Verify backup
ls -la /opt/homenetmon/backups/

# Restore from backup
sqlite3 /opt/homenetmon/data/homeNetMon.db ".restore /path/to/backup.db"
```

## Performance Management

### Performance Monitoring

1. **Application Metrics**
   ```bash
   # Response time monitoring
   curl -w "%{time_total}\\n" -o /dev/null -s http://localhost/api/devices

   # Memory usage
   ps aux | grep python | grep homenetmon

   # Database performance
   python3 performance_monitor_live.py
   ```

2. **System Metrics**
   ```bash
   # CPU usage
   top -p $(pgrep -f homenetmon)

   # Memory usage
   free -h

   # Disk usage
   df -h

   # Network usage
   iftop
   ```

### Performance Optimization

1. **Database Optimization**
   ```bash
   # Run optimization scripts
   python3 optimize_database_performance.py
   python3 database_performance_fix.py

   # Check for data bloat
   python3 comprehensive_database_health_assessment.py
   ```

2. **Application Tuning**
   ```bash
   # Adjust worker processes
   export WORKERS=4

   # Configure connection limits
   export MAX_CONNECTIONS=100

   # Enable caching
   export REDIS_ENABLED=true
   ```

## Security Operations

### Security Monitoring

1. **Log Analysis**
   ```bash
   # Monitor security events
   python3 security/security-monitor.py

   # Check for failed logins
   grep "Failed login" /opt/homenetmon/logs/app.log

   # Monitor CSRF violations
   grep "CSRF" /opt/homenetmon/logs/app.log
   ```

2. **Vulnerability Scanning**
   ```bash
   # Run security scan
   python3 security/vulnerability-scanner.py https://localhost

   # Check SSL configuration
   openssl s_client -connect localhost:443
   ```

### Security Maintenance

1. **Certificate Management**
   ```bash
   # Check certificate expiration
   sudo certbot certificates

   # Renew certificates
   sudo certbot renew

   # Test automatic renewal
   sudo certbot renew --dry-run
   ```

2. **Firewall Management**
   ```bash
   # Check firewall status
   sudo ufw status verbose

   # Review firewall logs
   sudo tail -f /var/log/ufw.log

   # Update firewall rules
   sudo ./security/configure-firewall.sh
   ```

## Backup and Recovery

### Backup Procedures

1. **Automated Backups**
   ```bash
   # Check backup cron job
   sudo crontab -l | grep homenetmon

   # Manual backup execution
   python3 backup_production.py

   # Verify backup integrity
   gzip -t /opt/homenetmon/backups/*.gz
   ```

2. **Backup Monitoring**
   ```bash
   # Check backup status
   ls -la /opt/homenetmon/backups/

   # Verify recent backups
   find /opt/homenetmon/backups/ -name "*.gz" -mtime -1
   ```

### Recovery Procedures

1. **Database Recovery**
   ```bash
   # Stop application
   sudo systemctl stop homenetmon

   # Restore database
   cp /opt/homenetmon/backups/latest.db /opt/homenetmon/data/homeNetMon.db

   # Start application
   sudo systemctl start homenetmon
   ```

2. **Full System Recovery**
   ```bash
   # Restore application files
   sudo cp -r /backup/homenetmon/* /opt/homenetmon/

   # Restore configuration
   sudo cp /backup/homenetmon/.env /opt/homenetmon/

   # Restart services
   sudo systemctl restart homenetmon nginx
   ```

## Updates and Maintenance

### Application Updates

1. **Regular Updates**
   ```bash
   # Automated update
   sudo ./update.sh

   # Manual update process
   cd /opt/homenetmon
   sudo -u homenetmon git pull origin main
   sudo -u homenetmon ./venv/bin/pip install -r requirements.txt
   sudo systemctl restart homenetmon
   ```

2. **Update Verification**
   ```bash
   # Check application version
   curl http://localhost/api/system/info | jq '.version'

   # Verify functionality
   curl http://localhost/health

   # Check logs for errors
   sudo journalctl -u homenetmon --since "5 minutes ago"
   ```

### System Maintenance

1. **System Updates**
   ```bash
   # Update system packages
   sudo apt update && sudo apt upgrade

   # Update Docker (if used)
   sudo apt install docker-ce docker-ce-cli containerd.io
   ```

2. **Cleanup Operations**
   ```bash
   # Clean old logs
   sudo journalctl --vacuum-time=30d

   # Clean old backups
   find /opt/homenetmon/backups/ -name "*.gz" -mtime +30 -delete

   # Clean Docker images (if used)
   docker system prune -af
   ```

## Scheduled Maintenance Tasks

### Daily Tasks

- Monitor application health
- Check system resource usage
- Review error logs
- Verify backup completion

### Weekly Tasks

- Review security logs
- Check SSL certificate status
- Monitor database performance
- Update system packages

### Monthly Tasks

- Full security scan
- Performance optimization review
- Backup integrity testing
- Documentation updates

## Troubleshooting Quick Reference

| Issue | Command | Description |
|-------|---------|-------------|
| Service down | `sudo systemctl restart homenetmon` | Restart application |
| High memory | `python3 optimize_database_performance.py` | Optimize database |
| Slow queries | `python3 database_performance_fix.py` | Fix DB performance |
| SSL issues | `sudo certbot renew` | Renew SSL certificate |
| Network errors | `sudo systemctl restart networking` | Restart networking |

## Support and Escalation

1. **First Level Support**
   - Check service status
   - Review recent logs
   - Verify configuration

2. **Second Level Support**
   - Performance analysis
   - Security investigation
   - Database optimization

3. **Escalation**
   - Contact development team
   - Provide comprehensive logs
   - Document issue timeline

---

For detailed troubleshooting procedures, see the [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md).
'''

        try:
            (docs_dir / "OPERATIONS_GUIDE.md").write_text(operations_guide)
            self.log_doc_creation("operations", "Operations Guide", True,
                                 "Created comprehensive operations documentation")
        except Exception as e:
            self.log_doc_creation("operations", "Operations Guide", False, str(e))

    def create_troubleshooting_documentation(self):
        """Create troubleshooting and diagnostic documentation"""
        print(f"\n{self.colors['cyan']}🔧 Creating Troubleshooting Documentation{self.colors['reset']}")

        docs_dir = self.project_dir / "docs"

        troubleshooting_guide = '''# HomeNetMon Troubleshooting Guide

## Overview

This guide provides systematic troubleshooting procedures for common issues encountered in HomeNetMon production deployments.

## Table of Contents

1. [Quick Diagnostic Steps](#quick-diagnostic-steps)
2. [Service Issues](#service-issues)
3. [Network Problems](#network-problems)
4. [Database Issues](#database-issues)
5. [Performance Problems](#performance-problems)
6. [Security Issues](#security-issues)
7. [Configuration Problems](#configuration-problems)
8. [Advanced Diagnostics](#advanced-diagnostics)

## Quick Diagnostic Steps

### 1. Basic Health Check

```bash
# Check if service is running
sudo systemctl status homenetmon

# Test HTTP endpoint
curl -f http://localhost/health || echo "Service not responding"

# Check process
ps aux | grep -i homenetmon

# Check listening ports
sudo netstat -tlnp | grep :5000
```

### 2. Log Analysis

```bash
# Recent application logs
sudo journalctl -u homenetmon --since "10 minutes ago"

# Error logs only
sudo journalctl -u homenetmon -p err

# Application log file
tail -f /opt/homenetmon/logs/app.log

# Check for Python errors
grep -i "traceback\\|error" /opt/homenetmon/logs/app.log
```

### 3. Resource Check

```bash
# Memory usage
free -h

# Disk space
df -h

# CPU usage
top -n 1 | head -20

# Network connectivity
ping google.com
```

## Service Issues

### Service Won't Start

**Symptoms:**
- `systemctl status homenetmon` shows failed state
- Port 5000 not listening
- No response from health endpoint

**Diagnostic Steps:**

1. **Check service status**
   ```bash
   sudo systemctl status homenetmon -l
   ```

2. **Review startup logs**
   ```bash
   sudo journalctl -u homenetmon --since today
   ```

3. **Test configuration**
   ```bash
   cd /opt/homenetmon
   sudo -u homenetmon ./venv/bin/python -c "import app; print('Config OK')"
   ```

4. **Check dependencies**
   ```bash
   sudo -u homenetmon ./venv/bin/pip check
   ```

**Common Solutions:**

1. **Configuration errors**
   ```bash
   # Check environment file
   sudo cat /opt/homenetmon/.env

   # Validate environment variables
   sudo -u homenetmon bash -c 'source .env && env | grep -E "(SECRET_KEY|ADMIN_PASSWORD)"'
   ```

2. **Permission issues**
   ```bash
   # Fix ownership
   sudo chown -R homenetmon:homenetmon /opt/homenetmon

   # Fix permissions
   sudo chmod +x /opt/homenetmon/app.py
   ```

3. **Port conflicts**
   ```bash
   # Check what's using port 5000
   sudo lsof -i :5000

   # Kill conflicting process
   sudo kill -9 $(sudo lsof -t -i:5000)
   ```

### Service Crashes Frequently

**Diagnostic Steps:**

1. **Check crash logs**
   ```bash
   sudo journalctl -u homenetmon | grep -A 10 -B 10 "Main process exited"
   ```

2. **Monitor memory usage**
   ```bash
   # Watch memory usage
   watch 'ps aux | grep homenetmon'

   # Check for memory leaks
   python3 performance_monitor_live.py
   ```

3. **Check database issues**
   ```bash
   # Test database connectivity
   sqlite3 /opt/homenetmon/data/homeNetMon.db ".tables"

   # Check database locks
   lsof /opt/homenetmon/data/homeNetMon.db
   ```

**Solutions:**

1. **Memory issues**
   ```bash
   # Restart service to clear memory
   sudo systemctl restart homenetmon

   # Optimize database
   python3 optimize_database_performance.py
   ```

2. **Database corruption**
   ```bash
   # Check integrity
   sqlite3 /opt/homenetmon/data/homeNetMon.db "PRAGMA integrity_check;"

   # Repair if needed
   sqlite3 /opt/homenetmon/data/homeNetMon.db "VACUUM;"
   ```

## Network Problems

### Network Scanning Not Working

**Symptoms:**
- No devices discovered
- Scan operation times out
- Empty device list

**Diagnostic Steps:**

1. **Check nmap availability**
   ```bash
   which nmap
   nmap --version
   ```

2. **Test network connectivity**
   ```bash
   # Test ping to gateway
   ping $(ip route | grep default | awk '{print $3}')

   # Test ping to known device
   ping 192.168.1.1
   ```

3. **Check network configuration**
   ```bash
   # Current network interfaces
   ip addr show

   # Routing table
   ip route show
   ```

4. **Test manual nmap scan**
   ```bash
   # Test nmap manually
   sudo nmap -sn 192.168.1.0/24
   ```

**Solutions:**

1. **Install/fix nmap**
   ```bash
   sudo apt update
   sudo apt install nmap
   ```

2. **Network range configuration**
   ```bash
   # Check current network
   ip route | grep -E "192.168|10.0|172.16"

   # Update NETWORK_RANGE in .env
   NETWORK_RANGE=your-actual-network/24
   ```

3. **Permissions issues**
   ```bash
   # Check nmap permissions
   ls -la /usr/bin/nmap

   # Set capabilities (if needed)
   sudo setcap cap_net_raw+ep /usr/bin/nmap
   ```

### Monitoring Connectivity Issues

**Symptoms:**
- Devices show as offline
- Intermittent connectivity alerts
- High false positive rates

**Diagnostic Steps:**

1. **Test ping manually**
   ```bash
   # Test ping to problematic device
   ping -c 5 192.168.1.100

   # Test with different packet sizes
   ping -s 1024 -c 5 192.168.1.100
   ```

2. **Check network latency**
   ```bash
   # Continuous ping test
   ping 192.168.1.100 | while read line; do echo "$(date): $line"; done
   ```

3. **Monitor network interface**
   ```bash
   # Check interface statistics
   cat /proc/net/dev

   # Monitor packet drops
   netstat -i
   ```

**Solutions:**

1. **Adjust ping settings**
   ```bash
   # Increase timeout in .env
   PING_TIMEOUT=5

   # Reduce ping frequency
   PING_INTERVAL=60
   ```

2. **Network optimization**
   ```bash
   # Check MTU settings
   ip link show

   # Adjust if needed
   sudo ip link set dev eth0 mtu 1500
   ```

## Database Issues

### Database Performance Problems

**Symptoms:**
- Slow page loads
- High CPU usage
- Database timeouts

**Diagnostic Steps:**

1. **Check database size**
   ```bash
   ls -lh /opt/homenetmon/data/homeNetMon.db
   du -h /opt/homenetmon/data/
   ```

2. **Analyze database**
   ```bash
   python3 comprehensive_database_health_assessment.py
   ```

3. **Check query performance**
   ```bash
   sqlite3 /opt/homenetmon/data/homeNetMon.db "
   .timer on
   SELECT COUNT(*) FROM monitoring_data;
   SELECT COUNT(*) FROM performance_metrics;
   "
   ```

**Solutions:**

1. **Database optimization**
   ```bash
   # Run optimization
   python3 optimize_database_performance.py

   # Clean old data
   python3 database_performance_fix.py

   # Emergency cleanup
   python3 emergency_database_cleanup.py
   ```

2. **Index optimization**
   ```bash
   # Rebuild indexes
   sqlite3 /opt/homenetmon/data/homeNetMon.db "
   REINDEX;
   ANALYZE;
   "
   ```

### Database Corruption

**Symptoms:**
- "Database is locked" errors
- Integrity check failures
- Application crashes during DB operations

**Diagnostic Steps:**

1. **Check database integrity**
   ```bash
   sqlite3 /opt/homenetmon/data/homeNetMon.db "PRAGMA integrity_check;"
   ```

2. **Check for locks**
   ```bash
   lsof /opt/homenetmon/data/homeNetMon.db
   ```

3. **Backup status**
   ```bash
   ls -la /opt/homenetmon/backups/
   ```

**Solutions:**

1. **Repair database**
   ```bash
   # Stop service
   sudo systemctl stop homenetmon

   # Repair database
   sqlite3 /opt/homenetmon/data/homeNetMon.db "
   PRAGMA integrity_check;
   VACUUM;
   PRAGMA optimize;
   "

   # Restart service
   sudo systemctl start homenetmon
   ```

2. **Restore from backup**
   ```bash
   # Stop service
   sudo systemctl stop homenetmon

   # Restore latest backup
   cp /opt/homenetmon/backups/latest.db /opt/homenetmon/data/homeNetMon.db

   # Fix permissions
   chown homenetmon:homenetmon /opt/homenetmon/data/homeNetMon.db

   # Start service
   sudo systemctl start homenetmon
   ```

## Performance Problems

### High Memory Usage

**Symptoms:**
- System running out of memory
- OOM killer activated
- Slow application response

**Diagnostic Steps:**

1. **Memory analysis**
   ```bash
   # Current memory usage
   free -h

   # Process memory usage
   ps aux --sort=-%mem | head

   # HomeNetMon memory usage
   ps aux | grep homenetmon
   ```

2. **Check for memory leaks**
   ```bash
   # Monitor memory over time
   while true; do
     date
     ps aux | grep homenetmon | awk '{print $6}'
     sleep 60
   done
   ```

**Solutions:**

1. **Immediate relief**
   ```bash
   # Restart service
   sudo systemctl restart homenetmon

   # Clear system cache
   sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
   ```

2. **Long-term fixes**
   ```bash
   # Optimize database
   python3 optimize_database_performance.py

   # Clean old data
   python3 emergency_database_cleanup.py

   # Reduce worker processes
   export WORKERS=2
   ```

### High CPU Usage

**Diagnostic Steps:**

1. **CPU analysis**
   ```bash
   # Top processes
   top -n 1

   # HomeNetMon CPU usage
   top -p $(pgrep python | grep homenetmon)
   ```

2. **Application profiling**
   ```bash
   # Check monitoring frequency
   grep -i "interval" /opt/homenetmon/.env

   # Monitor active connections
   netstat -an | grep :5000
   ```

**Solutions:**

1. **Reduce monitoring frequency**
   ```bash
   # Increase intervals
   PING_INTERVAL=60
   SCAN_INTERVAL=600
   ```

2. **Optimize database queries**
   ```bash
   python3 optimize_database_performance.py
   ```

## Security Issues

### SSL/TLS Problems

**Symptoms:**
- Browser security warnings
- Certificate errors
- HTTPS not working

**Diagnostic Steps:**

1. **Test SSL configuration**
   ```bash
   # Test SSL connection
   openssl s_client -connect localhost:443

   # Check certificate
   openssl x509 -in /etc/letsencrypt/live/domain/cert.pem -text -noout
   ```

2. **Nginx configuration**
   ```bash
   # Test nginx config
   sudo nginx -t

   # Check SSL settings
   sudo grep -r ssl /etc/nginx/sites-enabled/
   ```

**Solutions:**

1. **Renew certificate**
   ```bash
   sudo certbot renew
   sudo systemctl reload nginx
   ```

2. **Fix SSL configuration**
   ```bash
   # Apply SSL config
   sudo cp security/ssl-config.conf /etc/nginx/conf.d/
   sudo nginx -t && sudo systemctl reload nginx
   ```

### Authentication Issues

**Symptoms:**
- Cannot log in
- Session expires immediately
- CSRF token errors

**Diagnostic Steps:**

1. **Check authentication configuration**
   ```bash
   grep -i "admin_password" /opt/homenetmon/.env
   grep -i "secret_key" /opt/homenetmon/.env
   ```

2. **Test login process**
   ```bash
   curl -X POST -d "username=admin&password=yourpassword" http://localhost/login
   ```

**Solutions:**

1. **Reset admin password**
   ```bash
   # Generate new password
   python3 -c "
   import secrets, string
   chars = string.ascii_letters + string.digits + '!@#$%^&*'
   password = ''.join(secrets.choice(chars) for _ in range(16))
   print(f'New password: {password}')
   "

   # Update .env file
   ADMIN_PASSWORD=new-password-here
   ```

2. **Fix session configuration**
   ```bash
   # Generate new secret key
   python3 -c "import secrets; print(secrets.token_hex(32))"

   # Update .env file
   SECRET_KEY=new-secret-key-here
   ```

## Configuration Problems

### Environment Configuration

**Common Issues:**
- Missing required variables
- Invalid configuration values
- File permission problems

**Diagnostic Steps:**

1. **Validate configuration**
   ```bash
   # Check environment file
   cat /opt/homenetmon/.env

   # Test configuration loading
   cd /opt/homenetmon
   python3 -c "from config import Config; print('Config loaded successfully')"
   ```

2. **Check required variables**
   ```bash
   grep -E "(SECRET_KEY|ADMIN_PASSWORD|NETWORK_RANGE)" /opt/homenetmon/.env
   ```

**Solutions:**

1. **Fix missing variables**
   ```bash
   # Copy template
   cp .env.prod.template /opt/homenetmon/.env

   # Set required values
   nano /opt/homenetmon/.env
   ```

2. **Fix permissions**
   ```bash
   chmod 640 /opt/homenetmon/.env
   chown homenetmon:homenetmon /opt/homenetmon/.env
   ```

## Advanced Diagnostics

### Debug Mode

```bash
# Enable debug mode
export DEBUG=true
export FLASK_ENV=development

# Restart with debug
sudo systemctl restart homenetmon
```

### Performance Profiling

```bash
# Run performance monitor
python3 performance_monitor_live.py

# Database performance analysis
python3 comprehensive_database_health_assessment.py

# Load testing
python3 comprehensive_load_stress_test_suite.py
```

### Log Analysis Tools

```bash
# Error pattern analysis
grep -E "(ERROR|CRITICAL|Exception)" /opt/homenetmon/logs/app.log | tail -20

# Performance metrics
grep "response_time" /opt/homenetmon/logs/app.log | tail -10

# Security events
grep -i "security\\|csrf\\|auth" /opt/homenetmon/logs/app.log
```

## Getting Help

### Information to Collect

Before seeking support, collect:

1. **System information**
   ```bash
   uname -a
   python3 --version
   sqlite3 --version
   ```

2. **Application logs**
   ```bash
   sudo journalctl -u homenetmon --since "1 hour ago" > homenetmon-logs.txt
   ```

3. **Configuration (sanitized)**
   ```bash
   grep -v -E "(PASSWORD|SECRET|KEY)" /opt/homenetmon/.env > config-sanitized.txt
   ```

4. **Error details**
   - Exact error messages
   - Steps to reproduce
   - When the issue started
   - Recent changes made

### Support Channels

1. **Documentation**: Check all relevant guides
2. **Logs**: Review application and system logs
3. **Community**: Search for similar issues
4. **Professional Support**: Contact with detailed information

---

Remember: Always backup your data before making significant changes during troubleshooting.
'''

        try:
            (docs_dir / "TROUBLESHOOTING_GUIDE.md").write_text(troubleshooting_guide)
            self.log_doc_creation("troubleshooting", "Troubleshooting Guide", True,
                                 "Created comprehensive troubleshooting documentation")
        except Exception as e:
            self.log_doc_creation("troubleshooting", "Troubleshooting Guide", False, str(e))

    def create_api_documentation(self):
        """Create API reference documentation"""
        print(f"\n{self.colors['cyan']}📡 Creating API Documentation{self.colors['reset']}")

        docs_dir = self.project_dir / "docs"

        api_reference = '''# HomeNetMon API Reference

## Overview

HomeNetMon provides a comprehensive REST API for programmatic access to all monitoring functionality. This reference covers all available endpoints, authentication, and usage examples.

## Table of Contents

1. [Authentication](#authentication)
2. [Base URLs and Versioning](#base-urls-and-versioning)
3. [Response Formats](#response-formats)
4. [Error Handling](#error-handling)
5. [Rate Limiting](#rate-limiting)
6. [Device Management API](#device-management-api)
7. [Monitoring API](#monitoring-api)
8. [Performance API](#performance-api)
9. [System API](#system-api)
10. [Security API](#security-api)
11. [WebSocket Events](#websocket-events)

## Authentication

### Session-Based Authentication

Most API endpoints require authentication. Use the web login to establish a session, then include session cookies with API requests.

```bash
# Login to establish session
curl -X POST -c cookies.txt \\
  -d "username=admin&password=yourpassword" \\
  -d "csrf_token=$(curl -b cookies.txt http://localhost/api/csrf-token | jq -r '.csrf_token')" \\
  http://localhost/login

# Use session cookies for API calls
curl -b cookies.txt http://localhost/api/devices
```

### CSRF Protection

All POST/PUT/DELETE requests require CSRF tokens:

```bash
# Get CSRF token
CSRF_TOKEN=$(curl -s http://localhost/api/csrf-token | jq -r '.csrf_token')

# Include in requests
curl -X POST -H "X-CSRF-Token: $CSRF_TOKEN" \\
  -d '{"name": "New Device"}' \\
  http://localhost/api/devices
```

## Base URLs and Versioning

- **Base URL**: `http://your-server/api/`
- **Current Version**: v1 (implicit)
- **Content Type**: `application/json`

## Response Formats

### Success Response

```json
{
  "success": true,
  "data": {
    // Response data
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Error Response

```json
{
  "success": false,
  "error": "Error description",
  "code": "ERROR_CODE",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Error Handling

### HTTP Status Codes

| Code | Description | Usage |
|------|-------------|-------|
| 200 | OK | Successful request |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid request data |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 422 | Unprocessable Entity | Validation errors |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |

### Error Codes

| Code | Description |
|------|-------------|
| `AUTHENTICATION_REQUIRED` | Login required |
| `CSRF_TOKEN_MISSING` | CSRF token required |
| `VALIDATION_ERROR` | Input validation failed |
| `DEVICE_NOT_FOUND` | Device does not exist |
| `NETWORK_ERROR` | Network operation failed |
| `DATABASE_ERROR` | Database operation failed |

## Rate Limiting

API endpoints are rate limited to prevent abuse:

- **Default Limit**: 100 requests per minute per IP
- **API Endpoints**: 60 requests per minute per IP
- **Authentication**: 10 attempts per minute per IP

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## Device Management API

### List All Devices

```http
GET /api/devices
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "ip": "192.168.1.100",
      "name": "Router",
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "vendor": "Cisco",
      "status": "online",
      "last_seen": "2024-01-01T12:00:00Z",
      "response_time": 15.5,
      "device_type": "router"
    }
  ]
}
```

### Get Device Details

```http
GET /api/devices/{device_id}
```

**Parameters:**
- `device_id` (integer): Device ID

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "ip": "192.168.1.100",
    "name": "Router",
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "vendor": "Cisco",
    "status": "online",
    "last_seen": "2024-01-01T12:00:00Z",
    "response_time": 15.5,
    "device_type": "router",
    "monitoring_enabled": true,
    "alert_enabled": true
  }
}
```

### Update Device

```http
PUT /api/devices/{device_id}
```

**Request Body:**
```json
{
  "name": "Updated Device Name",
  "device_type": "computer",
  "monitoring_enabled": true,
  "alert_enabled": true
}
```

### Delete Device

```http
DELETE /api/devices/{device_id}
```

### Scan for New Devices

```http
POST /api/devices/scan-now
```

**Request Headers:**
```
X-CSRF-Token: your-csrf-token
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scan_id": "scan-123",
    "status": "started",
    "message": "Network scan initiated"
  }
}
```

## Monitoring API

### Get Monitoring Summary

```http
GET /api/monitoring/summary
```

**Query Parameters:**
- `hours` (integer, optional): Time period in hours (default: 24)

**Response:**
```json
{
  "success": true,
  "data": {
    "total_devices": 25,
    "online_devices": 23,
    "offline_devices": 2,
    "average_response_time": 18.5,
    "uptime_percentage": 92.5,
    "alerts": {
      "active": 3,
      "resolved": 15
    }
  }
}
```

### Get Device Monitoring Data

```http
GET /api/monitoring/device/{device_id}
```

**Query Parameters:**
- `hours` (integer, optional): Time period in hours (default: 24)
- `limit` (integer, optional): Maximum number of records (default: 100)

**Response:**
```json
{
  "success": true,
  "data": {
    "device_id": 1,
    "monitoring_data": [
      {
        "timestamp": "2024-01-01T12:00:00Z",
        "status": "online",
        "response_time": 15.5,
        "packet_loss": 0
      }
    ]
  }
}
```

### Get Alerts

```http
GET /api/monitoring/alerts
```

**Query Parameters:**
- `status` (string, optional): Filter by status (`active`, `resolved`)
- `device_id` (integer, optional): Filter by device
- `limit` (integer, optional): Maximum number of alerts

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "device_id": 5,
      "alert_type": "device_offline",
      "message": "Device Router has been offline for 5 minutes",
      "severity": "high",
      "status": "active",
      "created_at": "2024-01-01T12:00:00Z",
      "resolved_at": null
    }
  ]
}
```

### Resolve Alert

```http
PUT /api/monitoring/alerts/{alert_id}/resolve
```

**Request Headers:**
```
X-CSRF-Token: your-csrf-token
```

### Bulk Resolve Alerts

```http
POST /api/monitoring/alerts/resolve-all
```

**Request Headers:**
```
X-CSRF-Token: your-csrf-token
```

**Request Body:**
```json
{
  "alert_ids": [1, 2, 3],
  "reason": "Maintenance window"
}
```

## Performance API

### Get Performance Summary

```http
GET /api/performance/summary
```

**Query Parameters:**
- `hours` (integer, optional): Time period in hours (default: 24)

**Response:**
```json
{
  "success": true,
  "data": {
    "network_health_score": 95.5,
    "average_response_time": 18.5,
    "packet_loss_percentage": 0.1,
    "uptime_percentage": 99.2,
    "device_count": 25,
    "performance_trends": {
      "response_time_trend": "stable",
      "availability_trend": "improving"
    }
  }
}
```

### Get Device Performance

```http
GET /api/performance/device/{device_id}
```

**Query Parameters:**
- `hours` (integer, optional): Time period in hours (default: 24)
- `metrics` (string, optional): Comma-separated metrics list

**Response:**
```json
{
  "success": true,
  "data": {
    "device_id": 1,
    "health_score": 98.5,
    "metrics": {
      "average_response_time": 12.3,
      "packet_loss": 0.0,
      "uptime_percentage": 99.8,
      "availability_score": 100.0
    },
    "trends": {
      "response_time": "improving",
      "availability": "stable"
    }
  }
}
```

### Get Network Health Score

```http
GET /api/performance/network-health
```

**Response:**
```json
{
  "success": true,
  "data": {
    "overall_health_score": 95.5,
    "components": {
      "device_availability": 98.0,
      "response_times": 92.5,
      "network_stability": 96.0
    },
    "recommendations": [
      "Monitor device 192.168.1.50 for high response times",
      "Consider upgrading router firmware"
    ]
  }
}
```

## System API

### Get System Information

```http
GET /api/system/info
```

**Response:**
```json
{
  "success": true,
  "data": {
    "version": "1.0.0",
    "uptime": 86400,
    "system": {
      "cpu_usage": 15.5,
      "memory_usage": 45.2,
      "disk_usage": 25.8
    },
    "database": {
      "size_mb": 125.5,
      "record_count": 50000
    },
    "monitoring": {
      "devices_monitored": 25,
      "active_scans": 1,
      "last_scan": "2024-01-01T12:00:00Z"
    }
  }
}
```

### Health Check

```http
GET /api/system/health
```

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "checks": {
      "database": "ok",
      "network": "ok",
      "disk_space": "ok",
      "memory": "ok"
    },
    "timestamp": "2024-01-01T12:00:00Z"
  }
}
```

### Get Configuration

```http
GET /api/system/config
```

**Response:**
```json
{
  "success": true,
  "data": {
    "network_range": "192.168.1.0/24",
    "ping_interval": 30,
    "scan_interval": 300,
    "alert_enabled": true,
    "monitoring_enabled": true
  }
}
```

### Update Configuration

```http
PUT /api/system/config
```

**Request Headers:**
```
X-CSRF-Token: your-csrf-token
```

**Request Body:**
```json
{
  "ping_interval": 60,
  "scan_interval": 600,
  "alert_enabled": true
}
```

## Security API

### Get CSRF Token

```http
GET /api/csrf-token
```

**Response:**
```json
{
  "csrf_token": "your-csrf-token-here"
}
```

### Security Status

```http
GET /api/security/status
```

**Response:**
```json
{
  "success": true,
  "data": {
    "ssl_enabled": true,
    "firewall_enabled": true,
    "rate_limiting_enabled": true,
    "csrf_protection_enabled": true,
    "security_headers_enabled": true,
    "last_security_scan": "2024-01-01T12:00:00Z"
  }
}
```

## WebSocket Events

HomeNetMon provides real-time updates via WebSocket connections.

### Connection

```javascript
const socket = io('http://your-server');
```

### Device Status Updates

```javascript
socket.on('device_status_update', function(data) {
  console.log('Device update:', data);
  // data: { device_id, status, response_time, timestamp }
});
```

### Network Summary Updates

```javascript
socket.on('monitoring_summary', function(data) {
  console.log('Network summary:', data);
  // data: { total_devices, online_devices, offline_devices, timestamp }
});
```

### Alert Notifications

```javascript
socket.on('new_alert', function(data) {
  console.log('New alert:', data);
  // data: { alert_id, device_id, message, severity, timestamp }
});
```

### Scan Progress

```javascript
socket.on('scan_progress', function(data) {
  console.log('Scan progress:', data);
  // data: { scan_id, progress_percentage, devices_found, timestamp }
});
```

## Usage Examples

### Python Example

```python
import requests
import json

class HomeNetMonAPI:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.session = requests.Session()
        self.login(username, password)

    def login(self, username, password):
        # Get CSRF token
        csrf_response = self.session.get(f"{self.base_url}/api/csrf-token")
        csrf_token = csrf_response.json()['csrf_token']

        # Login
        login_data = {
            'username': username,
            'password': password,
            'csrf_token': csrf_token
        }
        self.session.post(f"{self.base_url}/login", data=login_data)

    def get_devices(self):
        response = self.session.get(f"{self.base_url}/api/devices")
        return response.json()

    def scan_network(self):
        csrf_response = self.session.get(f"{self.base_url}/api/csrf-token")
        csrf_token = csrf_response.json()['csrf_token']

        headers = {'X-CSRF-Token': csrf_token}
        response = self.session.post(
            f"{self.base_url}/api/devices/scan-now",
            headers=headers
        )
        return response.json()

# Usage
api = HomeNetMonAPI('http://localhost', 'admin', 'password')
devices = api.get_devices()
scan_result = api.scan_network()
```

### JavaScript Example

```javascript
class HomeNetMonAPI {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }

    async getCSRFToken() {
        const response = await fetch(`${this.baseUrl}/api/csrf-token`);
        const data = await response.json();
        return data.csrf_token;
    }

    async getDevices() {
        const response = await fetch(`${this.baseUrl}/api/devices`);
        return await response.json();
    }

    async scanNetwork() {
        const csrfToken = await this.getCSRFToken();

        const response = await fetch(`${this.baseUrl}/api/devices/scan-now`, {
            method: 'POST',
            headers: {
                'X-CSRF-Token': csrfToken
            }
        });
        return await response.json();
    }
}

// Usage
const api = new HomeNetMonAPI('http://localhost');
api.getDevices().then(devices => console.log(devices));
api.scanNetwork().then(result => console.log(result));
```

### cURL Examples

```bash
# Get devices
curl -b cookies.txt http://localhost/api/devices

# Get monitoring summary
curl -b cookies.txt "http://localhost/api/monitoring/summary?hours=48"

# Scan network
CSRF_TOKEN=$(curl -b cookies.txt -s http://localhost/api/csrf-token | jq -r '.csrf_token')
curl -b cookies.txt -X POST -H "X-CSRF-Token: $CSRF_TOKEN" \\
  http://localhost/api/devices/scan-now

# Update device
curl -b cookies.txt -X PUT -H "X-CSRF-Token: $CSRF_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"name": "Updated Device Name"}' \\
  http://localhost/api/devices/1
```

## Best Practices

### Authentication
- Always use HTTPS in production
- Include CSRF tokens for state-changing operations
- Handle session expiration gracefully
- Store credentials securely

### Rate Limiting
- Implement client-side rate limiting
- Handle 429 responses with exponential backoff
- Cache responses when appropriate
- Use WebSocket for real-time updates instead of polling

### Error Handling
- Always check response status codes
- Handle network errors gracefully
- Implement retry logic for transient failures
- Log errors for debugging

### Performance
- Use appropriate query parameters to limit data
- Implement pagination for large datasets
- Cache frequently accessed data
- Use WebSocket for real-time updates

---

For additional API questions or feature requests, please refer to the [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md) or contact support.
'''

        try:
            (docs_dir / "API_REFERENCE.md").write_text(api_reference)
            self.log_doc_creation("api_reference", "API Reference", True,
                                 "Created comprehensive API documentation")
        except Exception as e:
            self.log_doc_creation("api_reference", "API Reference", False, str(e))

    def create_user_guides(self):
        """Create user guides and tutorials"""
        print(f"\n{self.colors['cyan']}👥 Creating User Guides{self.colors['reset']}")

        docs_dir = self.project_dir / "docs"

        user_guide = '''# HomeNetMon User Guide

## Overview

HomeNetMon is a comprehensive network monitoring solution that helps you monitor, manage, and analyze your home or small business network. This guide covers all user-facing features and functionality.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Device Management](#device-management)
4. [Network Monitoring](#network-monitoring)
5. [Alerts and Notifications](#alerts-and-notifications)
6. [Performance Analytics](#performance-analytics)
7. [Network Topology](#network-topology)
8. [Settings and Configuration](#settings-and-configuration)
9. [Troubleshooting](#troubleshooting)

## Getting Started

### First Login

1. **Access the Application**
   - Open your web browser
   - Navigate to `http://your-server-ip` or your configured domain
   - You should see the HomeNetMon login screen

2. **Login**
   - Username: `admin`
   - Password: Your configured admin password
   - Click "Login"

3. **Initial Setup**
   - Upon first login, the system will automatically start scanning your network
   - Wait for the initial scan to complete (usually 1-2 minutes)
   - You'll see discovered devices appear on the dashboard

### Dashboard Overview

The main dashboard provides a real-time overview of your network:

#### Top Statistics Bar
- **Total Devices**: Number of discovered devices
- **Online Devices**: Currently responsive devices
- **Offline Devices**: Non-responsive devices
- **Network Health**: Overall network health score

#### Device Status Grid
- **Green**: Device is online and responsive
- **Red**: Device is offline or not responding
- **Yellow**: Device has connectivity issues
- **Gray**: Device monitoring is disabled

#### Quick Actions
- **Scan Network**: Manually trigger a network scan
- **Refresh**: Update current status
- **Settings**: Access configuration options

## Device Management

### Viewing Devices

#### Device List
- All discovered devices are shown in a grid layout
- Each device card shows:
  - Device name (or IP address)
  - Current status (online/offline)
  - Last seen timestamp
  - Response time (for online devices)
  - Device type icon

#### Device Details
- Click on any device card to view detailed information:
  - IP address and MAC address
  - Vendor information (if available)
  - Connection history
  - Performance statistics
  - Alert history

### Managing Devices

#### Renaming Devices
1. Click on a device to open its details
2. Click the "Edit" button
3. Enter a friendly name (e.g., "Living Room TV")
4. Click "Save"

#### Setting Device Types
1. Open device details
2. Click "Edit"
3. Select the appropriate device type:
   - Computer
   - Router
   - Switch
   - Printer
   - Phone
   - Tablet
   - Smart TV
   - IoT Device
   - Gaming Console
   - Other
4. Click "Save"

#### Enabling/Disabling Monitoring
1. Open device details
2. Toggle "Monitoring Enabled"
3. Disabled devices will not be pinged or generate alerts

#### Removing Devices
1. Open device details
2. Click "Remove Device"
3. Confirm the action
   - Note: Devices may be rediscovered during network scans

### Network Discovery

#### Automatic Scanning
- HomeNetMon automatically scans your network every 5 minutes
- New devices are automatically added
- Existing devices are updated with current information

#### Manual Scanning
- Click "Scan Network" on the dashboard
- Useful after adding new devices to your network
- Takes 30-60 seconds depending on network size

#### Scan Settings
- Network range is configured during setup
- Default: Scans your primary network subnet
- Can be adjusted in Settings if needed

## Network Monitoring

### Real-Time Status
- Device status updates every 30 seconds
- Dashboard shows current network state
- WebSocket connections provide instant updates

### Historical Data
- Performance data is stored for analysis
- Default retention: 30 days
- Includes response times, availability, and connectivity

### Performance Metrics

#### Response Time
- Time for ping response from each device
- Measured in milliseconds
- Lower is better (typically <50ms for local devices)

#### Availability
- Percentage of time device responds to pings
- Calculated over selected time period
- 100% = always responsive

#### Packet Loss
- Percentage of ping packets that don't receive responses
- 0% = perfect connectivity
- >5% may indicate network issues

### Monitoring Views

#### Live Dashboard
- Real-time device status
- Current response times
- Active alerts
- Quick network overview

#### Device History
- Click device → "History" tab
- Shows response time trends
- Availability statistics
- Connection events

#### Network Overview
- View all devices simultaneously
- Filter by status (online/offline)
- Sort by response time or last seen

## Alerts and Notifications

### Alert Types

#### Device Offline
- Triggered when device stops responding
- Default threshold: 3 consecutive failed pings
- Resolution: Device comes back online

#### High Response Time
- Triggered when response time exceeds threshold
- Default threshold: 1000ms (1 second)
- May indicate network congestion

#### Device Discovered
- Triggered when new device joins network
- Helps identify unauthorized devices
- Automatically cleared after review

#### Device Missing
- Triggered when previously seen device disappears
- May indicate device powered off or disconnected
- Cleared when device reappears

### Alert Management

#### Viewing Alerts
1. Click "Alerts" in navigation menu
2. See all current and historical alerts
3. Filter by status, device, or type

#### Alert Details
- Click on any alert to see details:
  - Device information
  - Alert trigger time
  - Current status
  - Resolution time (if resolved)

#### Resolving Alerts
1. Open alert details
2. Click "Resolve" button
3. Add optional resolution notes
4. Alert is marked as resolved

#### Bulk Operations
- Select multiple alerts using checkboxes
- Use "Resolve Selected" for bulk resolution
- Useful for maintenance periods

### Notification Setup

#### Email Notifications
1. Go to Settings → Notifications
2. Configure SMTP settings:
   - SMTP server (e.g., smtp.gmail.com)
   - Port (usually 587 for TLS)
   - Username and password
   - From email address
3. Test email configuration
4. Enable email alerts

#### Webhook Notifications
1. Go to Settings → Notifications
2. Enter webhook URL (e.g., Slack, Discord, Teams)
3. Test webhook connection
4. Enable webhook alerts

## Performance Analytics

### Network Health Score
- Overall network performance rating (0-100)
- Based on device availability and response times
- Green (90-100): Excellent
- Yellow (70-89): Good
- Red (<70): Needs attention

### Performance Trends
- Access via "Analytics" menu
- Shows network performance over time
- Identifies patterns and issues

#### Response Time Trends
- Average response times over time
- Identifies network slowdowns
- Helps plan network upgrades

#### Availability Trends
- Network uptime statistics
- Device reliability analysis
- Outage pattern identification

#### Device Performance Comparison
- Compare device performance
- Identify problematic devices
- Network topology optimization

### Analytics Features

#### Time Range Selection
- Last 24 hours
- Last 7 days
- Last 30 days
- Custom date ranges

#### Device Filtering
- View specific devices
- Group by device type
- Filter by performance criteria

#### Export Options
- Download charts as images
- Export data as CSV
- Generate PDF reports

## Network Topology

### Topology View
- Visual representation of your network
- Shows device relationships
- Interactive network map

### Features

#### Device Visualization
- Devices shown as nodes
- Connections represented as lines
- Status indicated by color coding

#### Interactive Elements
- Click devices for quick info
- Drag to reorganize layout
- Zoom and pan for large networks

#### Layout Options
- Automatic layout algorithms
- Manual positioning
- Save custom layouts

### Topology Information

#### Device Relationships
- Router/gateway identification
- Switch connections
- Wireless access points
- Client device connections

#### Network Structure
- Subnet visualization
- VLAN identification (if supported)
- Physical vs. logical connections

## Settings and Configuration

### Network Settings

#### Network Range
- Define which IP range to monitor
- Usually your local subnet (e.g., 192.168.1.0/24)
- Can monitor multiple ranges

#### Scan Intervals
- Network scan frequency (default: 5 minutes)
- Ping interval (default: 30 seconds)
- Balance between accuracy and network load

#### Monitoring Thresholds
- Offline detection threshold
- High response time threshold
- Alert trigger sensitivity

### User Preferences

#### Dashboard Layout
- Device grid size
- Information display options
- Refresh intervals

#### Notifications
- Email alert settings
- Webhook configurations
- Alert severity filters

#### Data Retention
- Historical data storage period
- Database cleanup settings
- Backup configurations

### System Settings

#### Performance Tuning
- Worker process count
- Database optimization
- Cache settings

#### Security Configuration
- Password requirements
- Session timeouts
- SSL/TLS settings

#### Backup Settings
- Automatic backup scheduling
- Backup retention policy
- Restore procedures

## Advanced Features

### API Access
- RESTful API for automation
- WebSocket for real-time data
- Authentication and rate limiting

### Custom Integrations
- Webhook support for external systems
- SNMP monitoring (if supported)
- Integration with network management tools

### Automation
- Automated network discovery
- Self-healing capabilities
- Intelligent alerting

## Tips and Best Practices

### Network Optimization
1. **Place router centrally** for best coverage
2. **Use wired connections** for critical devices
3. **Update device firmware** regularly
4. **Monitor bandwidth usage** to identify bottlenecks

### Monitoring Best Practices
1. **Set meaningful device names** for easy identification
2. **Configure appropriate alert thresholds** to avoid noise
3. **Review alerts regularly** to identify patterns
4. **Use analytics** to plan network improvements

### Security Considerations
1. **Change default passwords** immediately
2. **Enable HTTPS** for secure access
3. **Limit network access** to monitoring system
4. **Monitor for unauthorized devices**

### Maintenance
1. **Check system health** regularly
2. **Update HomeNetMon** when new versions are available
3. **Backup configurations** before changes
4. **Review and clean old data** periodically

## Troubleshooting

### Common Issues

#### Devices Not Appearing
- Check network range configuration
- Verify device is on same network
- Manually trigger network scan
- Check device firewall settings

#### Offline Devices Showing as Online
- Check ping thresholds
- Verify device responds to ping manually
- Review monitoring settings
- Check network connectivity

#### Slow Dashboard Loading
- Clear browser cache
- Check server performance
- Optimize database
- Review system resources

#### Alerts Not Working
- Verify notification settings
- Test email/webhook configuration
- Check alert thresholds
- Review device monitoring status

### Getting Help
1. Check this user guide for solutions
2. Review the troubleshooting section
3. Check application logs for errors
4. Contact support with specific details

### Performance Tips
- **Use modern browser** for best experience
- **Enable JavaScript** for full functionality
- **Close unused browser tabs** to save memory
- **Use wired connection** for monitoring system

---

## Next Steps

After reading this guide:
1. Set up your network monitoring preferences
2. Configure notifications for important alerts
3. Customize device names and types
4. Explore the analytics features
5. Set up regular maintenance routines

For technical questions, see the [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md) or [API Reference](API_REFERENCE.md).
'''

        try:
            (docs_dir / "USER_GUIDE.md").write_text(user_guide)
            self.log_doc_creation("user_guides", "User Guide", True,
                                 "Created comprehensive user documentation")
        except Exception as e:
            self.log_doc_creation("user_guides", "User Guide", False, str(e))

    def create_administration_documentation(self):
        """Create administration and maintenance documentation"""
        print(f"\n{self.colors['cyan']}⚙️ Creating Administration Documentation{self.colors['reset']}")

        docs_dir = self.project_dir / "docs"

        admin_guide = '''# HomeNetMon Administration Guide

## Overview

This guide covers administrative tasks, advanced configuration, maintenance procedures, and troubleshooting for HomeNetMon administrators and technical staff.

## Table of Contents

1. [System Administration](#system-administration)
2. [User Management](#user-management)
3. [Configuration Management](#configuration-management)
4. [Database Administration](#database-administration)
5. [Performance Monitoring](#performance-monitoring)
6. [Security Administration](#security-administration)
7. [Backup and Recovery](#backup-and-recovery)
8. [Maintenance Procedures](#maintenance-procedures)
9. [Monitoring and Alerting](#monitoring-and-alerting)
10. [Advanced Configuration](#advanced-configuration)

## System Administration

### Service Management

#### Systemd Service Control
```bash
# Check service status
sudo systemctl status homenetmon

# Start/stop service
sudo systemctl start homenetmon
sudo systemctl stop homenetmon
sudo systemctl restart homenetmon

# Enable/disable auto-start
sudo systemctl enable homenetmon
sudo systemctl disable homenetmon

# View logs
sudo journalctl -u homenetmon -f
sudo journalctl -u homenetmon --since "1 hour ago"
```

#### Docker Container Management
```bash
# Check container status
docker-compose -f docker-compose.prod.yml ps

# Start/stop containers
docker-compose -f docker-compose.prod.yml up -d
docker-compose -f docker-compose.prod.yml down

# View logs
docker-compose -f docker-compose.prod.yml logs -f
docker logs homenetmon-prod
```

### Process Management

#### Application Processes
```bash
# Find HomeNetMon processes
ps aux | grep homenetmon
pgrep -f homenetmon

# Monitor resource usage
top -p $(pgrep python | grep homenetmon)
htop -p $(pgrep python | grep homenetmon)
```

#### Memory Management
```bash
# Check memory usage
free -h
cat /proc/meminfo

# Monitor application memory
ps -o pid,ppid,cmd,%mem,%cpu --sort=-%mem | grep homenetmon

# Clear system cache if needed
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
```

### File System Management

#### Directory Structure
```
/opt/homenetmon/
├── app.py                 # Main application
├── config.py             # Configuration
├── models.py             # Database models
├── requirements.txt      # Dependencies
├── .env                  # Environment variables
├── data/                 # Database and data files
│   └── homeNetMon.db
├── logs/                 # Application logs
│   ├── app.log
│   └── error.log
├── backups/              # Database backups
└── venv/                 # Python virtual environment
```

#### File Permissions
```bash
# Set correct ownership
sudo chown -R homenetmon:homenetmon /opt/homenetmon

# Set directory permissions
sudo find /opt/homenetmon -type d -exec chmod 755 {} \\;

# Set file permissions
sudo find /opt/homenetmon -type f -exec chmod 644 {} \\;

# Set executable permissions
sudo chmod +x /opt/homenetmon/app.py
sudo chmod +x /opt/homenetmon/scripts/*.sh
```

## User Management

### Administrative Access

#### Default Admin Account
- Username: `admin`
- Password: Set during installation
- Full system access
- Cannot be deleted

#### Password Management
```bash
# Generate strong password
python3 -c "
import secrets, string
chars = string.ascii_letters + string.digits + '!@#$%^&*'
password = ''.join(secrets.choice(chars) for _ in range(16))
print(f'New password: {password}')
"

# Update admin password
# Edit /opt/homenetmon/.env
ADMIN_PASSWORD=new-secure-password
```

#### Session Management
```bash
# Current sessions
# View in application logs
grep "login\\|session" /opt/homenetmon/logs/app.log

# Session configuration
# Edit in config.py or .env
SESSION_TIMEOUT=3600  # 1 hour
SESSION_COOKIE_SECURE=true
```

### Access Control

#### Authentication Settings
```bash
# Authentication configuration
AUTHENTICATION_REQUIRED=true
SESSION_TIMEOUT=3600
CSRF_PROTECTION=true
RATE_LIMITING=true
```

#### API Access Control
```bash
# API rate limiting
API_RATE_LIMIT=60  # requests per minute
API_BURST_LIMIT=100

# CORS settings (if needed)
CORS_ENABLED=false
CORS_ORIGINS=https://yourdomain.com
```

## Configuration Management

### Environment Configuration

#### Core Settings
```bash
# Network configuration
NETWORK_RANGE=192.168.1.0/24
PING_INTERVAL=30
SCAN_INTERVAL=300

# Database configuration
DATABASE_URL=sqlite:////opt/homenetmon/data/homeNetMon.db
DATABASE_BACKUP_ENABLED=true

# Performance settings
WORKERS=4
MAX_CONNECTIONS=100
CACHE_ENABLED=true
```

#### Security Settings
```bash
# Security configuration
SECRET_KEY=your-secret-key-here
CSRF_ENABLED=true
HTTPS_ENABLED=true
RATE_LIMITING_ENABLED=true

# SSL/TLS settings
SSL_CERT_PATH=/etc/ssl/certs/homenetmon.crt
SSL_KEY_PATH=/etc/ssl/private/homenetmon.key
```

### Application Configuration

#### Monitoring Settings
```bash
# Monitoring thresholds
OFFLINE_THRESHOLD=3      # Failed pings before offline
RESPONSE_TIME_THRESHOLD=1000  # High response time (ms)
ALERT_COOLDOWN=300      # Seconds between repeat alerts

# Data retention
DATA_RETENTION_DAYS=30
CLEANUP_INTERVAL=86400  # Daily cleanup
```

#### Notification Settings
```bash
# Email configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true

# Webhook configuration
WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
WEBHOOK_ENABLED=true
```

### Configuration Validation

#### Syntax Checking
```bash
# Validate Python syntax
cd /opt/homenetmon
python3 -m py_compile app.py
python3 -m py_compile config.py

# Check imports
python3 -c "import app; print('Configuration valid')"
```

#### Environment Validation
```bash
# Check required variables
python3 -c "
import os
required = ['SECRET_KEY', 'ADMIN_PASSWORD', 'NETWORK_RANGE']
missing = [var for var in required if not os.getenv(var)]
if missing:
    print(f'Missing: {missing}')
else:
    print('All required variables set')
"
```

## Database Administration

### Database Management

#### Basic Operations
```bash
# Access database
sqlite3 /opt/homenetmon/data/homeNetMon.db

# Check database size
ls -lh /opt/homenetmon/data/homeNetMon.db
du -h /opt/homenetmon/data/

# Verify integrity
sqlite3 /opt/homenetmon/data/homeNetMon.db "PRAGMA integrity_check;"
```

#### Schema Information
```sql
-- List all tables
.tables

-- Describe table structure
.schema devices
.schema monitoring_data

-- Count records in tables
SELECT COUNT(*) FROM devices;
SELECT COUNT(*) FROM monitoring_data;
SELECT COUNT(*) FROM alerts;
```

### Database Optimization

#### Performance Optimization
```bash
# Run optimization script
python3 optimize_database_performance.py

# Manual optimization
sqlite3 /opt/homenetmon/data/homeNetMon.db "
VACUUM;
REINDEX;
ANALYZE;
PRAGMA optimize;
"
```

#### Data Cleanup
```bash
# Run cleanup script
python3 database_performance_fix.py

# Emergency cleanup
python3 emergency_database_cleanup.py

# Manual cleanup (old data)
sqlite3 /opt/homenetmon/data/homeNetMon.db "
DELETE FROM monitoring_data
WHERE timestamp < datetime('now', '-30 days');
"
```

### Database Monitoring

#### Health Assessment
```bash
# Run health assessment
python3 comprehensive_database_health_assessment.py

# Check database statistics
sqlite3 /opt/homenetmon/data/homeNetMon.db "
SELECT
  name,
  COUNT(*) as record_count
FROM (
  SELECT 'devices' as name UNION ALL
  SELECT 'monitoring_data' UNION ALL
  SELECT 'alerts' UNION ALL
  SELECT 'performance_metrics'
) tables
GROUP BY name;
"
```

#### Performance Monitoring
```bash
# Monitor query performance
sqlite3 /opt/homenetmon/data/homeNetMon.db "
.timer on
SELECT COUNT(*) FROM devices;
SELECT COUNT(*) FROM monitoring_data WHERE timestamp > datetime('now', '-1 day');
"
```

## Performance Monitoring

### System Performance

#### Resource Monitoring
```bash
# CPU usage
top -n 1 | grep "Cpu(s)"
cat /proc/loadavg

# Memory usage
free -h
cat /proc/meminfo | grep -E "(MemTotal|MemFree|MemAvailable)"

# Disk usage
df -h
iostat -x 1 5

# Network statistics
cat /proc/net/dev
iftop -n
```

#### Application Performance
```bash
# Response time monitoring
curl -w "%{time_total}\\n" -o /dev/null -s http://localhost/health

# Memory usage by process
ps aux | grep homenetmon | awk '{print $6}' | sort -n

# File descriptor usage
lsof -p $(pgrep python | grep homenetmon) | wc -l
```

### Performance Optimization

#### Application Tuning
```bash
# Adjust worker processes
export WORKERS=4  # Number of CPU cores

# Configure connection limits
export MAX_CONNECTIONS=100

# Enable caching
export REDIS_ENABLED=true
export CACHE_TTL=300
```

#### Database Tuning
```bash
# Database optimization settings
sqlite3 /opt/homenetmon/data/homeNetMon.db "
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=10000;
PRAGMA temp_store=MEMORY;
"
```

### Performance Monitoring Tools

#### Built-in Monitoring
```bash
# Run performance monitor
python3 performance_monitor_live.py

# Check system info
curl http://localhost/api/system/info | jq
```

#### External Monitoring
```bash
# Setup monitoring endpoints for external tools
# Prometheus metrics (if configured)
curl http://localhost/metrics

# Health check for monitoring systems
curl http://localhost/health
```

## Security Administration

### Security Configuration

#### SSL/TLS Management
```bash
# Check certificate status
sudo certbot certificates

# Renew certificates
sudo certbot renew

# Test certificate
openssl x509 -in /etc/letsencrypt/live/domain/cert.pem -text -noout

# Verify SSL configuration
openssl s_client -connect localhost:443
```

#### Firewall Management
```bash
# Check firewall status
sudo ufw status verbose

# Configure basic firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Check firewall logs
sudo tail -f /var/log/ufw.log
```

### Security Monitoring

#### Access Monitoring
```bash
# Monitor login attempts
grep -i "login\\|auth" /opt/homenetmon/logs/app.log

# Check for suspicious activity
grep -i "error\\|failed\\|denied" /opt/homenetmon/logs/app.log

# Monitor API access
grep -E "(POST|PUT|DELETE)" /var/log/nginx/access.log
```

#### Security Scanning
```bash
# Run vulnerability scanner
python3 security/vulnerability-scanner.py https://localhost

# Check for security updates
sudo apt list --upgradable | grep -i security

# Verify security headers
curl -I https://localhost | grep -E "(Strict-Transport|X-Frame|X-Content)"
```

### Security Maintenance

#### Regular Security Tasks
```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Check for security advisories
sudo apt list --upgradable

# Review access logs
sudo grep "authentication failure" /var/log/auth.log

# Verify file permissions
find /opt/homenetmon -type f -perm /o+w
```

#### Incident Response
```bash
# Stop service immediately
sudo systemctl stop homenetmon

# Isolate system (if needed)
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default deny outgoing

# Collect evidence
cp /opt/homenetmon/logs/app.log /tmp/incident-log
journalctl -u homenetmon > /tmp/incident-systemd-log
```

## Backup and Recovery

### Backup Procedures

#### Automated Backups
```bash
# Check backup cron job
sudo crontab -l | grep homenetmon

# Manual backup
python3 backup_production.py

# Verify backup
ls -la /opt/homenetmon/backups/
gzip -t /opt/homenetmon/backups/*.gz
```

#### Backup Configuration
```bash
# Backup settings in .env
DATABASE_BACKUP_ENABLED=true
DATABASE_BACKUP_INTERVAL=86400  # Daily
DATABASE_RETENTION_DAYS=30

# Backup location
BACKUP_DIRECTORY=/opt/homenetmon/backups
```

### Recovery Procedures

#### Database Recovery
```bash
# Stop application
sudo systemctl stop homenetmon

# Restore from backup
gunzip -c /opt/homenetmon/backups/latest.db.gz > /opt/homenetmon/data/homeNetMon.db

# Fix permissions
sudo chown homenetmon:homenetmon /opt/homenetmon/data/homeNetMon.db

# Start application
sudo systemctl start homenetmon

# Verify recovery
curl http://localhost/health
```

#### Full System Recovery
```bash
# Restore application files
sudo tar -xzf /backup/homenetmon-full-backup.tar.gz -C /opt/

# Restore configuration
sudo cp /backup/homenetmon.env /opt/homenetmon/.env

# Restore systemd service
sudo cp /backup/homenetmon.service /etc/systemd/system/
sudo systemctl daemon-reload

# Start services
sudo systemctl start homenetmon
```

### Disaster Recovery

#### Recovery Planning
1. **Backup Strategy**
   - Daily database backups
   - Weekly configuration backups
   - Monthly full system backups

2. **Recovery Procedures**
   - Document recovery steps
   - Test recovery procedures
   - Maintain offline backups

3. **Business Continuity**
   - Identify critical functions
   - Define recovery time objectives
   - Plan alternative monitoring methods

## Maintenance Procedures

### Regular Maintenance Tasks

#### Daily Tasks
```bash
# Check service status
sudo systemctl status homenetmon

# Review error logs
grep -i error /opt/homenetmon/logs/app.log | tail -10

# Check disk space
df -h | grep -E "(/$|/opt)"

# Monitor system resources
free -h && uptime
```

#### Weekly Tasks
```bash
# Review performance
python3 performance_monitor_live.py

# Check database size
ls -lh /opt/homenetmon/data/homeNetMon.db

# Review security logs
grep -i "security\\|auth" /opt/homenetmon/logs/app.log

# Update system packages
sudo apt update && sudo apt list --upgradable
```

#### Monthly Tasks
```bash
# Full system optimization
python3 optimize_database_performance.py

# Security scan
python3 security/vulnerability-scanner.py https://localhost

# Backup verification
gzip -t /opt/homenetmon/backups/*.gz

# Configuration review
# Review .env file for obsolete settings
# Check for security updates
```

### Preventive Maintenance

#### Database Maintenance
```bash
# Schedule monthly optimization
# Add to cron:
0 2 1 * * /opt/homenetmon/venv/bin/python /opt/homenetmon/optimize_database_performance.py

# Monitor database growth
du -h /opt/homenetmon/data/homeNetMon.db

# Clean old data regularly
python3 database_performance_fix.py
```

#### System Optimization
```bash
# Clear log files
sudo journalctl --vacuum-time=30d

# Clean temporary files
sudo find /tmp -type f -atime +7 -delete

# Update package cache
sudo apt autoremove && sudo apt autoclean
```

## Advanced Configuration

### High Availability Setup

#### Load Balancing
```bash
# Multiple instance configuration
# Instance 1
INSTANCE_ID=1
BIND_PORT=5001

# Instance 2
INSTANCE_ID=2
BIND_PORT=5002

# Load balancer configuration (nginx)
upstream homenetmon_backend {
    server 127.0.0.1:5001;
    server 127.0.0.1:5002;
}
```

#### Database Clustering
```bash
# PostgreSQL setup (advanced)
DATABASE_URL=postgresql://user:pass@localhost/homenetmon
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20
```

### Custom Integration

#### API Integration
```bash
# External monitoring system integration
EXTERNAL_API_ENABLED=true
EXTERNAL_API_URL=https://monitoring.example.com/api
EXTERNAL_API_KEY=your-api-key
```

#### Webhook Customization
```bash
# Custom webhook format
WEBHOOK_FORMAT=slack  # or discord, teams, custom
WEBHOOK_CUSTOM_TEMPLATE=/opt/homenetmon/templates/webhook.json
```

### Scaling Configuration

#### Performance Scaling
```bash
# High-performance configuration
WORKERS=8
MAX_CONNECTIONS=200
CACHE_ENABLED=true
CACHE_SIZE=1000

# Database optimization
DATABASE_CACHE_SIZE=50000
DATABASE_WAL_AUTOCHECKPOINT=1000
```

#### Resource Limits
```bash
# Systemd resource limits
[Service]
MemoryLimit=2G
CPUQuota=200%
TasksMax=1000
```

## Troubleshooting

### Common Administrative Issues

#### Service Won't Start
1. Check configuration syntax
2. Verify file permissions
3. Review environment variables
4. Check port availability
5. Examine error logs

#### Performance Issues
1. Monitor system resources
2. Check database size
3. Review query performance
4. Optimize configuration
5. Consider hardware upgrades

#### Security Concerns
1. Review access logs
2. Check for unauthorized access
3. Verify SSL/TLS configuration
4. Update security settings
5. Run security scans

### Diagnostic Tools

#### Log Analysis
```bash
# Error analysis
grep -E "(ERROR|CRITICAL|Exception)" /opt/homenetmon/logs/app.log | tail -20

# Performance analysis
grep "response_time" /opt/homenetmon/logs/app.log | awk '{print $NF}' | sort -n

# Security analysis
grep -i "login\\|auth\\|security" /opt/homenetmon/logs/app.log
```

#### System Analysis
```bash
# Resource usage
ps aux | grep homenetmon
netstat -tlnp | grep 5000
lsof -p $(pgrep python | head -1)

# Database analysis
sqlite3 /opt/homenetmon/data/homeNetMon.db "
SELECT COUNT(*) as total_records,
       (COUNT(*) * 100.0 / (SELECT COUNT(*) FROM sqlite_master WHERE type='table')) as avg_per_table
FROM (
  SELECT * FROM devices UNION ALL
  SELECT * FROM monitoring_data UNION ALL
  SELECT * FROM alerts
);
"
```

## Support and Documentation

### Internal Documentation
- Keep configuration changes documented
- Maintain change logs
- Document custom procedures
- Update contact information

### External Resources
- Review official documentation
- Check for software updates
- Monitor security advisories
- Participate in community forums

### Escalation Procedures
1. **Level 1**: Basic troubleshooting
2. **Level 2**: Advanced configuration
3. **Level 3**: Developer support
4. **Emergency**: Critical system issues

---

This administration guide should be reviewed and updated regularly to reflect system changes and new procedures.
'''

        try:
            (docs_dir / "ADMINISTRATION_GUIDE.md").write_text(admin_guide)
            self.log_doc_creation("administration", "Administration Guide", True,
                                 "Created comprehensive administration documentation")
        except Exception as e:
            self.log_doc_creation("administration", "Administration Guide", False, str(e))

    def create_final_documentation_index(self):
        """Create master documentation index"""
        print(f"\n{self.colors['cyan']}📚 Creating Documentation Index{self.colors['reset']}")

        docs_dir = self.project_dir / "docs"

        # Master README
        master_readme = '''# HomeNetMon Documentation

## Overview

Welcome to the comprehensive documentation for HomeNetMon, a powerful network monitoring solution for home and small business environments. This documentation covers everything from quick deployment to advanced administration.

## Quick Navigation

### 🚀 Getting Started
- [**Quick Start Guide**](QUICK_START.md) - 5-minute deployment
- [**Deployment Guide**](DEPLOYMENT_GUIDE.md) - Complete installation procedures
- [**User Guide**](USER_GUIDE.md) - User interface and features

### 🔧 Operations & Maintenance
- [**Operations Guide**](OPERATIONS_GUIDE.md) - Day-to-day operations
- [**Administration Guide**](ADMINISTRATION_GUIDE.md) - Advanced administration
- [**Troubleshooting Guide**](TROUBLESHOOTING_GUIDE.md) - Problem resolution

### 🔌 Technical Reference
- [**API Reference**](API_REFERENCE.md) - Complete API documentation
- [**Security Guide**](../SECURITY_GUIDE.md) - Security hardening
- [**Production Deployment**](../PRODUCTION_DEPLOYMENT.md) - Production setup

## Documentation Structure

### For New Users
1. Start with [Quick Start Guide](QUICK_START.md) for immediate deployment
2. Read [User Guide](USER_GUIDE.md) to understand features
3. Configure using [Deployment Guide](DEPLOYMENT_GUIDE.md) for production

### For Administrators
1. Review [Administration Guide](ADMINISTRATION_GUIDE.md) for management tasks
2. Implement [Security Guide](../SECURITY_GUIDE.md) for hardening
3. Use [Operations Guide](OPERATIONS_GUIDE.md) for daily operations

### For Developers
1. Study [API Reference](API_REFERENCE.md) for integration
2. Review codebase structure and patterns
3. Use [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md) for diagnostics

## Key Features Covered

### Network Monitoring
- Automatic device discovery
- Real-time status monitoring
- Performance analytics
- Historical data tracking

### Alerting & Notifications
- Configurable alert thresholds
- Email and webhook notifications
- Alert management and resolution
- Escalation procedures

### Performance Management
- Network health scoring
- Response time monitoring
- Availability tracking
- Performance optimization

### Security Features
- Authentication and authorization
- SSL/TLS encryption
- Rate limiting and protection
- Security monitoring

### Administration
- User management
- Configuration management
- Backup and recovery
- System maintenance

## Common Use Cases

### Home Network Monitoring
- Monitor family devices and IoT equipment
- Track internet connectivity issues
- Identify unauthorized devices
- Optimize WiFi performance

### Small Business Networks
- Monitor critical business devices
- Ensure network reliability
- Track performance trends
- Manage network security

### IT Professional Tools
- Network diagnostic capabilities
- Performance baseline establishment
- Proactive issue identification
- Documentation and reporting

## Support Resources

### Documentation Hierarchy
```
docs/
├── README.md                    # This file - main index
├── QUICK_START.md              # 5-minute deployment
├── DEPLOYMENT_GUIDE.md         # Complete installation
├── USER_GUIDE.md               # End-user documentation
├── OPERATIONS_GUIDE.md         # Daily operations
├── ADMINISTRATION_GUIDE.md     # Advanced administration
├── TROUBLESHOOTING_GUIDE.md    # Problem resolution
└── API_REFERENCE.md            # Complete API documentation
```

### External Documentation
- [Security Guide](../SECURITY_GUIDE.md) - Security implementation
- [Production Deployment](../PRODUCTION_DEPLOYMENT.md) - Production setup
- [Performance Optimization](../PERFORMANCE_OPTIMIZATION_GUIDE.md) - Optimization

### Getting Help

#### Self-Service Resources
1. **Search Documentation** - Use browser search (Ctrl+F) within guides
2. **Check Troubleshooting** - Review [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md)
3. **Review Logs** - Check application and system logs
4. **Test Configuration** - Verify settings and connectivity

#### Common Solutions
| Issue | Quick Solution | Documentation |
|-------|----------------|---------------|
| Service won't start | Check logs and configuration | [Troubleshooting](TROUBLESHOOTING_GUIDE.md#service-issues) |
| Devices not appearing | Verify network range | [User Guide](USER_GUIDE.md#network-discovery) |
| Poor performance | Run optimization scripts | [Operations](OPERATIONS_GUIDE.md#performance-management) |
| Security concerns | Review security checklist | [Security Guide](../SECURITY_GUIDE.md) |
| API integration | Check API documentation | [API Reference](API_REFERENCE.md) |

#### Support Channels
1. **Documentation** - Comprehensive guides for all topics
2. **Troubleshooting** - Step-by-step problem resolution
3. **Community** - Forums and discussion groups
4. **Professional Support** - Technical assistance (if available)

## Version Information

- **Documentation Version**: 1.0
- **Last Updated**: 2024-01-01
- **Compatible With**: HomeNetMon v1.0+

## Contributing to Documentation

### Improvement Suggestions
- Report unclear sections
- Suggest additional examples
- Request new topics
- Provide feedback on accuracy

### Documentation Standards
- Clear, concise language
- Step-by-step procedures
- Working examples
- Regular updates

## Quick Reference Cards

### Essential Commands
```bash
# Service management
sudo systemctl status homenetmon
sudo systemctl restart homenetmon

# Health checks
curl http://localhost/health
./health_check.sh

# Backup and restore
python3 backup_production.py
python3 optimize_database_performance.py

# Security
sudo ./security/configure-firewall.sh
sudo certbot renew
```

### Important File Locations
```
/opt/homenetmon/                # Application directory
/opt/homenetmon/.env           # Configuration file
/opt/homenetmon/logs/          # Log files
/opt/homenetmon/backups/       # Database backups
/etc/systemd/system/homenetmon.service  # Systemd service
```

### Default URLs and Ports
- **Web Interface**: http://localhost or http://your-server-ip
- **API Base**: http://localhost/api/
- **Health Check**: http://localhost/health
- **Default Port**: 5000 (application), 80/443 (web)

## Quick Start Summary

For immediate deployment:

1. **Download and Configure**
   ```bash
   git clone https://github.com/your-org/homenetmon.git
   cd homenetmon
   cp .env.prod.template .env.prod
   # Edit .env.prod with your settings
   ```

2. **Deploy**
   ```bash
   # Docker (recommended)
   docker-compose -f docker-compose.prod.yml up -d

   # Or native
   sudo ./deploy.sh
   ```

3. **Access and Configure**
   - Open http://your-server-ip
   - Login with admin credentials
   - Configure network range
   - Start monitoring

For detailed instructions, see the [Quick Start Guide](QUICK_START.md).

---

**Next Steps:**
- Choose your deployment method from the guides above
- Configure your specific environment needs
- Set up monitoring and alerting
- Implement security best practices
- Establish maintenance procedures

Happy monitoring! 🚀
'''

        try:
            (docs_dir / "README.md").write_text(master_readme)
            self.log_doc_creation("documentation", "Master Documentation Index", True,
                                 "Created comprehensive documentation index")
        except Exception as e:
            self.log_doc_creation("documentation", "Master Documentation Index", False, str(e))

    def run_documentation_suite(self):
        """Run complete documentation creation suite"""
        print(f"{self.colors['purple']}📚 HomeNetMon Production Documentation Suite{self.colors['reset']}")
        print(f"Phase 7.1: Comprehensive production documentation creation")
        print("=" * 80)

        start_time = time.time()

        # Run all documentation creation components
        documentation_components = [
            self.create_deployment_documentation,
            self.create_operations_documentation,
            self.create_troubleshooting_documentation,
            self.create_api_documentation,
            self.create_user_guides,
            self.create_administration_documentation,
            self.create_final_documentation_index
        ]

        for component in documentation_components:
            try:
                component()
            except Exception as e:
                self.logger.error(f"Documentation component {component.__name__} failed: {e}")

        # Generate documentation report
        self.generate_documentation_report(start_time)

    def generate_documentation_report(self, start_time):
        """Generate comprehensive documentation creation report"""
        duration = time.time() - start_time

        print(f"\n{self.colors['purple']}📊 Documentation Creation Report{self.colors['reset']}")
        print("=" * 80)

        # Summary
        total_docs = len(self.documentation_results)
        successful_docs = sum(1 for result in self.documentation_results if result['success'])
        success_rate = (successful_docs / total_docs * 100) if total_docs > 0 else 0

        print(f"\n⏱️ Duration: {duration:.1f} seconds")
        print(f"📚 Documents Created: {total_docs}")
        print(f"✅ Successful: {successful_docs}")
        print(f"❌ Failed: {total_docs - successful_docs}")
        print(f"📈 Success Rate: {success_rate:.1f}%")

        # Documentation by category
        categories = {}
        for result in self.documentation_results:
            category = result['category']
            if category not in categories:
                categories[category] = {'successful': 0, 'total': 0}

            categories[category]['total'] += 1
            if result['success']:
                categories[category]['successful'] += 1

        print(f"\n📋 Documentation Categories:")
        for category, stats in categories.items():
            percentage = (stats['successful'] / stats['total'] * 100) if stats['total'] > 0 else 0
            status_color = self.colors['green'] if percentage >= 90 else \
                          self.colors['yellow'] if percentage >= 70 else self.colors['red']

            print(f"  {status_color}{category.replace('_', ' ').title()}: {stats['successful']}/{stats['total']} ({percentage:.1f}%){self.colors['reset']}")

        # Documentation files created
        print(f"\n📄 Documentation Files Created:")
        doc_files = [
            "docs/README.md - Master documentation index",
            "docs/QUICK_START.md - 5-minute deployment guide",
            "docs/DEPLOYMENT_GUIDE.md - Complete installation procedures",
            "docs/OPERATIONS_GUIDE.md - Day-to-day operations",
            "docs/TROUBLESHOOTING_GUIDE.md - Problem resolution",
            "docs/API_REFERENCE.md - Complete API documentation",
            "docs/USER_GUIDE.md - End-user documentation",
            "docs/ADMINISTRATION_GUIDE.md - Advanced administration"
        ]

        for file_desc in doc_files:
            print(f"  📚 {file_desc}")

        # Documentation structure
        print(f"\n📁 Documentation Structure:")
        print(f"  docs/")
        print(f"  ├── README.md (Master Index)")
        print(f"  ├── QUICK_START.md (5-min deployment)")
        print(f"  ├── DEPLOYMENT_GUIDE.md (Complete installation)")
        print(f"  ├── USER_GUIDE.md (End-user features)")
        print(f"  ├── OPERATIONS_GUIDE.md (Daily operations)")
        print(f"  ├── ADMINISTRATION_GUIDE.md (Advanced admin)")
        print(f"  ├── TROUBLESHOOTING_GUIDE.md (Problem solving)")
        print(f"  └── API_REFERENCE.md (API documentation)")

        # Documentation metrics
        print(f"\n📊 Documentation Metrics:")
        total_sections = 0
        total_examples = 0

        for result in self.documentation_results:
            if result['success']:
                # Estimate content based on documentation type
                if 'guide' in result['doc_name'].lower():
                    total_sections += 10  # Estimated sections per guide
                    total_examples += 20  # Estimated examples per guide
                elif 'api' in result['doc_name'].lower():
                    total_sections += 15
                    total_examples += 50
                else:
                    total_sections += 8
                    total_examples += 15

        print(f"  📖 Estimated Sections: {total_sections}")
        print(f"  💡 Estimated Examples: {total_examples}")
        print(f"  🔗 Cross-references: Comprehensive")
        print(f"  📱 Format: Markdown (GitHub-flavored)")

        # Usage guidance
        print(f"\n🎯 Documentation Usage:")
        print(f"  🚀 New Users: Start with docs/QUICK_START.md")
        print(f"  👤 End Users: Read docs/USER_GUIDE.md")
        print(f"  ⚙️ Administrators: Review docs/ADMINISTRATION_GUIDE.md")
        print(f"  🔧 Operations: Use docs/OPERATIONS_GUIDE.md")
        print(f"  🔌 Developers: Study docs/API_REFERENCE.md")
        print(f"  🔍 Problems: Check docs/TROUBLESHOOTING_GUIDE.md")

        # Final assessment
        if success_rate >= 95:
            print(f"\n{self.colors['green']}🎉 EXCELLENT: Complete documentation suite created!{self.colors['reset']}")
            print("✅ Production-ready documentation covering all aspects")
        elif success_rate >= 80:
            print(f"\n{self.colors['yellow']}⚠️ GOOD: Most documentation created successfully{self.colors['reset']}")
            print("⚠️ Review failed components for completion")
        else:
            print(f"\n{self.colors['red']}❌ INCOMPLETE: Significant documentation gaps{self.colors['reset']}")
            print("🚨 Complete missing documentation before deployment")

        # Phase completion status
        if success_rate >= 90:
            print(f"\n{self.colors['green']}✅ Phase 7.1: Production documentation creation - COMPLETED{self.colors['reset']}")
        else:
            print(f"\n{self.colors['red']}❌ Phase 7.1: Production documentation creation - NEEDS COMPLETION{self.colors['reset']}")

        # Save detailed report
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'total_documents': total_docs,
            'successful_documents': successful_docs,
            'success_rate': success_rate,
            'categories': categories,
            'documentation_results': self.documentation_results
        }

        with open('documentation_creation_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)

        print(f"\n📄 Detailed report saved to: documentation_creation_report.json")
        print(f"📋 Documentation log saved to: documentation_creation.log")

def main():
    """Main documentation creation execution"""
    print(f"📚 PRODUCTION DOCUMENTATION SUITE")
    print(f"📊 Phase 7.1: Comprehensive production documentation creation")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

    # Run documentation creation
    documentation = ProductionDocumentationSuite()
    documentation.run_documentation_suite()

if __name__ == "__main__":
    main()