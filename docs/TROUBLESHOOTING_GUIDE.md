# HomeNetMon Troubleshooting Guide

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
grep -i "traceback\|error" /opt/homenetmon/logs/app.log
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
grep -i "security\|csrf\|auth" /opt/homenetmon/logs/app.log
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
