# HomeNetMon Production Deployment Guide

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
   curl -w "%{time_total}\n" -o /dev/null -s http://localhost/
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
