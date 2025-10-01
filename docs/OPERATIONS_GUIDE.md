# HomeNetMon Operations Guide

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
   curl -w "%{time_total}\n" -o /dev/null -s http://localhost/api/devices

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
