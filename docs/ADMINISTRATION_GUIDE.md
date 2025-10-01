# HomeNetMon Administration Guide

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
sudo find /opt/homenetmon -type d -exec chmod 755 {} \;

# Set file permissions
sudo find /opt/homenetmon -type f -exec chmod 644 {} \;

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
grep "login\|session" /opt/homenetmon/logs/app.log

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
curl -w "%{time_total}\n" -o /dev/null -s http://localhost/health

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
grep -i "login\|auth" /opt/homenetmon/logs/app.log

# Check for suspicious activity
grep -i "error\|failed\|denied" /opt/homenetmon/logs/app.log

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
grep -i "security\|auth" /opt/homenetmon/logs/app.log

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
grep -i "login\|auth\|security" /opt/homenetmon/logs/app.log
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
