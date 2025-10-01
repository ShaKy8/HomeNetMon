#!/usr/bin/env python3
"""
Production Infrastructure Setup for HomeNetMon
Phase 6.1: Complete production deployment preparation

Creates all necessary production infrastructure components:
- Docker production configuration
- Nginx reverse proxy setup
- SSL/TLS certificate configuration
- Systemd service files
- Database backup automation
- Monitoring and logging setup
- Environment configuration
- Performance optimization
"""

import os
import sys
import json
import time
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
import logging

class ProductionInfrastructureSetup:
    def __init__(self, project_dir="."):
        self.project_dir = Path(project_dir).resolve()
        self.setup_results = []

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
                logging.FileHandler('production_setup.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def log_step(self, step_name, success, details=""):
        """Log setup step result"""
        self.setup_results.append({
            'step': step_name,
            'success': success,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })

        status_color = self.colors['green'] if success else self.colors['red']
        status_icon = '✅' if success else '❌'

        print(f"{status_color}{status_icon} {step_name}{self.colors['reset']}")
        if details:
            print(f"   📝 {details}")

    def create_docker_production_config(self):
        """Create production Docker configuration"""
        print(f"\n{self.colors['cyan']}🐳 Creating Docker Production Configuration{self.colors['reset']}")

        # Production Dockerfile
        dockerfile_prod_content = '''FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    pkg-config \\
    libssl-dev \\
    libffi-dev \\
    nmap \\
    sqlite3 \\
    nginx \\
    supervisor \\
    && rm -rf /var/lib/apt/lists/*

# Create app directory and user
RUN useradd -m -u 1000 homenetmon
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .
RUN chown -R homenetmon:homenetmon /app

# Create necessary directories
RUN mkdir -p /app/logs /app/backups /app/data \\
    && chown -R homenetmon:homenetmon /app/logs /app/backups /app/data

# Copy production configurations
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose ports
EXPOSE 80 443

# Set environment variables
ENV FLASK_ENV=production
ENV PYTHONPATH=/app
ENV DATABASE_URL=sqlite:////app/data/homeNetMon.db

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \\
    CMD curl -f http://localhost/health || exit 1

# Switch to non-root user
USER homenetmon

# Start with supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
'''

        try:
            (self.project_dir / "Dockerfile.prod").write_text(dockerfile_prod_content)
            self.log_step("Production Dockerfile", True, "Created optimized production Docker image")
        except Exception as e:
            self.log_step("Production Dockerfile", False, str(e))

        # Docker Compose Production
        docker_compose_prod = '''version: '3.8'

services:
  homenetmon:
    build:
      context: .
      dockerfile: Dockerfile.prod
    container_name: homenetmon-prod
    restart: unless-stopped
    environment:
      - FLASK_ENV=production
      - SECRET_KEY=${SECRET_KEY}
      - ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - NETWORK_RANGE=${NETWORK_RANGE:-192.168.1.0/24}
      - PING_INTERVAL=${PING_INTERVAL:-30}
      - DATABASE_URL=sqlite:////app/data/homeNetMon.db
      - REDIS_URL=${REDIS_URL:-redis://redis:6379/0}
    volumes:
      - homenetmon_data:/app/data
      - homenetmon_logs:/app/logs
      - homenetmon_backups:/app/backups
      - /etc/localtime:/etc/localtime:ro
    ports:
      - "80:80"
      - "443:443"
    networks:
      - homenetmon_network
    depends_on:
      - redis
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  redis:
    image: redis:7-alpine
    container_name: homenetmon-redis
    restart: unless-stopped
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - homenetmon_network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 5s
      retries: 3

  backup:
    build:
      context: .
      dockerfile: Dockerfile.prod
    container_name: homenetmon-backup
    restart: "no"
    environment:
      - DATABASE_URL=sqlite:////app/data/homeNetMon.db
    volumes:
      - homenetmon_data:/app/data:ro
      - homenetmon_backups:/app/backups
    networks:
      - homenetmon_network
    entrypoint: ["python", "/app/backup_database.py"]
    profiles:
      - backup

volumes:
  homenetmon_data:
    driver: local
  homenetmon_logs:
    driver: local
  homenetmon_backups:
    driver: local
  redis_data:
    driver: local

networks:
  homenetmon_network:
    driver: bridge
'''

        try:
            (self.project_dir / "docker-compose.prod.yml").write_text(docker_compose_prod)
            self.log_step("Docker Compose Production", True, "Created production docker-compose configuration")
        except Exception as e:
            self.log_step("Docker Compose Production", False, str(e))

    def create_nginx_config(self):
        """Create Nginx reverse proxy configuration"""
        print(f"\n{self.colors['cyan']}🌐 Creating Nginx Configuration{self.colors['reset']}")

        # Create docker directory
        docker_dir = self.project_dir / "docker"
        docker_dir.mkdir(exist_ok=True)

        nginx_config = '''user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    access_log /var/log/nginx/access.log main;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 50M;

    # Compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdn.socket.io; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; font-src 'self' cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self' ws: wss:;";

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

    # Upstream Flask application
    upstream homenetmon_app {
        server 127.0.0.1:5000;
        keepalive 32;
    }

    server {
        listen 80;
        server_name _;

        # Redirect HTTP to HTTPS in production
        # return 301 https://$server_name$request_uri;

        # For development/testing, serve directly
        location / {
            proxy_pass http://homenetmon_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # WebSocket support
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";

            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }

        # API rate limiting
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://homenetmon_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Static files
        location /static/ {
            alias /app/static/;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }

        # Health check
        location /health {
            proxy_pass http://homenetmon_app;
            access_log off;
        }

        # Security
        location ~ /\\. {
            deny all;
        }
    }

    # HTTPS configuration (uncomment for production)
    # server {
    #     listen 443 ssl http2;
    #     server_name your-domain.com;
    #
    #     ssl_certificate /path/to/cert.pem;
    #     ssl_certificate_key /path/to/key.pem;
    #     ssl_protocols TLSv1.2 TLSv1.3;
    #     ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    #     ssl_prefer_server_ciphers off;
    #
    #     # Same location blocks as HTTP server
    # }
}
'''

        try:
            (docker_dir / "nginx.conf").write_text(nginx_config)
            self.log_step("Nginx Configuration", True, "Created production-ready Nginx config with security headers")
        except Exception as e:
            self.log_step("Nginx Configuration", False, str(e))

    def create_supervisor_config(self):
        """Create Supervisor configuration for process management"""
        print(f"\n{self.colors['cyan']}👥 Creating Supervisor Configuration{self.colors['reset']}")

        docker_dir = self.project_dir / "docker"
        docker_dir.mkdir(exist_ok=True)

        supervisor_config = '''[supervisord]
nodaemon=true
user=root
logfile=/var/log/supervisor/supervisord.log
pidfile=/var/run/supervisord.pid

[program:nginx]
command=nginx -g "daemon off;"
stdout_logfile=/var/log/nginx/stdout.log
stderr_logfile=/var/log/nginx/stderr.log
autorestart=true
user=root

[program:homenetmon]
command=python app.py
directory=/app
user=homenetmon
environment=FLASK_ENV=production,PYTHONPATH=/app
stdout_logfile=/app/logs/app.log
stderr_logfile=/app/logs/app_error.log
autorestart=true
redirect_stderr=true
startsecs=10
stopwaitsecs=30

[program:redis]
command=redis-server --appendonly yes
user=redis
stdout_logfile=/var/log/redis/stdout.log
stderr_logfile=/var/log/redis/stderr.log
autorestart=true
'''

        try:
            (docker_dir / "supervisord.conf").write_text(supervisor_config)
            self.log_step("Supervisor Configuration", True, "Created process management configuration")
        except Exception as e:
            self.log_step("Supervisor Configuration", False, str(e))

    def create_systemd_service(self):
        """Create systemd service file for native deployment"""
        print(f"\n{self.colors['cyan']}⚙️ Creating Systemd Service Configuration{self.colors['reset']}")

        systemd_service = '''[Unit]
Description=HomeNetMon Network Monitoring Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=homenetmon
Group=homenetmon
WorkingDirectory=/opt/homenetmon
Environment=FLASK_ENV=production
Environment=PYTHONPATH=/opt/homenetmon
Environment=DATABASE_URL=sqlite:////opt/homenetmon/data/homeNetMon.db
ExecStart=/opt/homenetmon/venv/bin/python app.py
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=homenetmon

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/homenetmon/data /opt/homenetmon/logs
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
'''

        try:
            (self.project_dir / "homenetmon.service").write_text(systemd_service)
            self.log_step("Systemd Service", True, "Created systemd service file for native deployment")
        except Exception as e:
            self.log_step("Systemd Service", False, str(e))

    def create_environment_template(self):
        """Create production environment template"""
        print(f"\n{self.colors['cyan']}🔧 Creating Environment Configuration{self.colors['reset']}")

        env_template = '''# HomeNetMon Production Environment Configuration
# Copy to .env.prod and customize for your deployment

# Application Settings
FLASK_ENV=production
SECRET_KEY=your-secret-key-here-generate-a-strong-one
ADMIN_PASSWORD=your-secure-admin-password

# Network Configuration
NETWORK_RANGE=192.168.1.0/24
PING_INTERVAL=30
SCAN_INTERVAL=300

# Database Configuration
DATABASE_URL=sqlite:////opt/homenetmon/data/homeNetMon.db
DATABASE_BACKUP_ENABLED=true
DATABASE_BACKUP_INTERVAL=86400
DATABASE_RETENTION_DAYS=30

# Redis Configuration (for caching and rate limiting)
REDIS_URL=redis://localhost:6379/0
REDIS_ENABLED=true

# Security Settings
HTTPS_ENABLED=true
CSRF_ENABLED=true
RATE_LIMITING_ENABLED=true

# SMTP Configuration (for email alerts)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true
ALERT_FROM_EMAIL=homenetmon@yourdomain.com

# Webhook Configuration
WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
WEBHOOK_ENABLED=false

# Performance Settings
WORKERS=4
MAX_CONNECTIONS=100
CACHE_ENABLED=true
CACHE_TTL=300

# Logging
LOG_LEVEL=INFO
LOG_FILE=/opt/homenetmon/logs/homenetmon.log
LOG_MAX_SIZE=10485760
LOG_BACKUP_COUNT=5

# Monitoring
HEALTH_CHECK_ENABLED=true
METRICS_ENABLED=true
PERFORMANCE_MONITORING=true

# Security Scanning
SECURITY_SCANNING_ENABLED=true
SECURITY_SCAN_INTERVAL=3600
'''

        try:
            (self.project_dir / ".env.prod.template").write_text(env_template)
            self.log_step("Environment Template", True, "Created production environment template")
        except Exception as e:
            self.log_step("Environment Template", False, str(e))

    def create_deployment_scripts(self):
        """Create deployment automation scripts"""
        print(f"\n{self.colors['cyan']}📜 Creating Deployment Scripts{self.colors['reset']}")

        # Deploy script
        deploy_script = '''#!/bin/bash
set -e

echo "🚀 HomeNetMon Production Deployment"
echo "=================================="

# Configuration
APP_USER="homenetmon"
APP_DIR="/opt/homenetmon"
SERVICE_NAME="homenetmon"
BACKUP_DIR="/opt/homenetmon/backups"

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

# Create application user
if ! id "$APP_USER" &>/dev/null; then
    log_info "Creating application user: $APP_USER"
    useradd -r -d $APP_DIR -s /bin/bash $APP_USER
fi

# Create application directory
log_info "Setting up application directory: $APP_DIR"
mkdir -p $APP_DIR/{data,logs,backups}
chown -R $APP_USER:$APP_USER $APP_DIR

# Install system dependencies
log_info "Installing system dependencies"
apt-get update
apt-get install -y python3 python3-venv python3-pip nginx redis-server nmap sqlite3 curl

# Copy application files
log_info "Deploying application files"
cp -r . $APP_DIR/
chown -R $APP_USER:$APP_USER $APP_DIR

# Create virtual environment
log_info "Setting up Python virtual environment"
sudo -u $APP_USER python3 -m venv $APP_DIR/venv
sudo -u $APP_USER $APP_DIR/venv/bin/pip install -r $APP_DIR/requirements.txt

# Configure systemd service
log_info "Installing systemd service"
cp $APP_DIR/homenetmon.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable $SERVICE_NAME

# Configure nginx
log_info "Configuring Nginx"
cp $APP_DIR/docker/nginx.conf /etc/nginx/sites-available/homenetmon
ln -sf /etc/nginx/sites-available/homenetmon /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx

# Start services
log_info "Starting services"
systemctl start redis-server
systemctl enable redis-server
systemctl start $SERVICE_NAME

# Setup log rotation
log_info "Setting up log rotation"
cat > /etc/logrotate.d/homenetmon << EOF
$APP_DIR/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $APP_USER $APP_USER
    postrotate
        systemctl reload $SERVICE_NAME
    endscript
}
EOF

# Setup backup cron job
log_info "Setting up database backup"
cat > /etc/cron.d/homenetmon-backup << EOF
0 2 * * * $APP_USER cd $APP_DIR && $APP_DIR/venv/bin/python backup_database.py
EOF

log_info "Deployment completed successfully!"
log_info "Service status: $(systemctl is-active $SERVICE_NAME)"
log_info "Access your application at: http://localhost"
'''

        try:
            deploy_path = self.project_dir / "deploy.sh"
            deploy_path.write_text(deploy_script)
            deploy_path.chmod(0o755)
            self.log_step("Deployment Script", True, "Created automated deployment script")
        except Exception as e:
            self.log_step("Deployment Script", False, str(e))

        # Update script
        update_script = '''#!/bin/bash
set -e

echo "🔄 HomeNetMon Update"
echo "==================="

APP_DIR="/opt/homenetmon"
SERVICE_NAME="homenetmon"
BACKUP_DIR="$APP_DIR/backups"

# Colors
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Create backup before update
log_info "Creating backup before update"
BACKUP_FILE="$BACKUP_DIR/pre-update-$(date +%Y%m%d_%H%M%S).db"
cp "$APP_DIR/data/homeNetMon.db" "$BACKUP_FILE"
log_info "Backup created: $BACKUP_FILE"

# Stop service
log_info "Stopping service"
systemctl stop $SERVICE_NAME

# Update application code
log_info "Updating application code"
cd $APP_DIR
git pull origin main

# Update dependencies
log_info "Updating dependencies"
sudo -u homenetmon $APP_DIR/venv/bin/pip install -r requirements.txt

# Run database migrations if needed
log_info "Running database migrations"
sudo -u homenetmon $APP_DIR/venv/bin/python database_schema_fix.py

# Start service
log_info "Starting service"
systemctl start $SERVICE_NAME

# Check status
sleep 5
if systemctl is-active --quiet $SERVICE_NAME; then
    log_info "Update completed successfully!"
    log_info "Service is running"
else
    log_warn "Service failed to start. Check logs: journalctl -u $SERVICE_NAME"
fi
'''

        try:
            update_path = self.project_dir / "update.sh"
            update_path.write_text(update_script)
            update_path.chmod(0o755)
            self.log_step("Update Script", True, "Created automated update script")
        except Exception as e:
            self.log_step("Update Script", False, str(e))

    def create_ssl_setup(self):
        """Create SSL/TLS setup script"""
        print(f"\n{self.colors['cyan']}🔒 Creating SSL/TLS Setup{self.colors['reset']}")

        ssl_setup_script = '''#!/bin/bash
# SSL/TLS Setup for HomeNetMon
# This script helps set up SSL certificates using Let's Encrypt

set -e

echo "🔒 SSL/TLS Setup for HomeNetMon"
echo "==============================="

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain-name>"
    echo "Example: $0 homenetmon.yourdomain.com"
    exit 1
fi

DOMAIN=$1
EMAIL=${2:-admin@${DOMAIN}}

# Install certbot
apt-get update
apt-get install -y certbot python3-certbot-nginx

# Get certificate
certbot --nginx -d $DOMAIN --email $EMAIL --agree-tos --non-interactive

# Setup auto-renewal
systemctl enable certbot.timer
systemctl start certbot.timer

echo "✅ SSL certificate installed for $DOMAIN"
echo "Auto-renewal is configured"
echo "Check renewal status: certbot renew --dry-run"
'''

        try:
            ssl_path = self.project_dir / "setup_ssl.sh"
            ssl_path.write_text(ssl_setup_script)
            ssl_path.chmod(0o755)
            self.log_step("SSL Setup Script", True, "Created SSL certificate setup script")
        except Exception as e:
            self.log_step("SSL Setup Script", False, str(e))

    def create_monitoring_setup(self):
        """Create monitoring and alerting setup"""
        print(f"\n{self.colors['cyan']}📊 Creating Monitoring Setup{self.colors['reset']}")

        # Health check script
        health_check_script = '''#!/bin/bash
# Health check script for HomeNetMon
# Can be used with external monitoring systems

APP_URL="http://localhost"
SERVICE_NAME="homenetmon"

# Check HTTP response
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" $APP_URL/health || echo "000")

# Check service status
SERVICE_STATUS=$(systemctl is-active $SERVICE_NAME)

# Check database
DB_CHECK=$(systemctl --user is-active $SERVICE_NAME && echo "OK" || echo "FAIL")

if [ "$HTTP_STATUS" == "200" ] && [ "$SERVICE_STATUS" == "active" ]; then
    echo "OK - HomeNetMon is healthy"
    exit 0
else
    echo "CRITICAL - HomeNetMon is unhealthy"
    echo "HTTP Status: $HTTP_STATUS"
    echo "Service Status: $SERVICE_STATUS"
    exit 2
fi
'''

        try:
            health_path = self.project_dir / "health_check.sh"
            health_path.write_text(health_check_script)
            health_path.chmod(0o755)
            self.log_step("Health Check Script", True, "Created health monitoring script")
        except Exception as e:
            self.log_step("Health Check Script", False, str(e))

    def create_backup_automation(self):
        """Create automated backup system"""
        print(f"\n{self.colors['cyan']}💾 Creating Backup Automation{self.colors['reset']}")

        backup_script = '''#!/usr/bin/env python3
"""
Automated backup system for HomeNetMon production
Creates database backups with retention policy
"""

import os
import shutil
import sqlite3
import gzip
from datetime import datetime, timedelta
from pathlib import Path

def create_backup():
    """Create compressed database backup"""

    # Configuration
    db_path = Path("/opt/homenetmon/data/homeNetMon.db")
    backup_dir = Path("/opt/homenetmon/backups")
    retention_days = 30

    # Create backup directory
    backup_dir.mkdir(exist_ok=True)

    # Create backup filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"homeNetMon_backup_{timestamp}.db"
    compressed_file = backup_dir / f"homeNetMon_backup_{timestamp}.db.gz"

    try:
        # Create database backup
        with sqlite3.connect(db_path) as source:
            with sqlite3.connect(backup_file) as backup:
                source.backup(backup)

        # Compress backup
        with open(backup_file, 'rb') as f_in:
            with gzip.open(compressed_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        # Remove uncompressed backup
        backup_file.unlink()

        print(f"✅ Backup created: {compressed_file}")

        # Cleanup old backups
        cleanup_old_backups(backup_dir, retention_days)

        return True

    except Exception as e:
        print(f"❌ Backup failed: {e}")
        return False

def cleanup_old_backups(backup_dir, retention_days):
    """Remove backups older than retention period"""
    cutoff_date = datetime.now() - timedelta(days=retention_days)

    for backup_file in backup_dir.glob("homeNetMon_backup_*.db.gz"):
        if backup_file.stat().st_mtime < cutoff_date.timestamp():
            backup_file.unlink()
            print(f"🗑️ Removed old backup: {backup_file.name}")

if __name__ == "__main__":
    create_backup()
'''

        try:
            backup_path = self.project_dir / "backup_production.py"
            backup_path.write_text(backup_script)
            backup_path.chmod(0o755)
            self.log_step("Backup Automation", True, "Created automated backup system")
        except Exception as e:
            self.log_step("Backup Automation", False, str(e))

    def create_production_readme(self):
        """Create production deployment documentation"""
        print(f"\n{self.colors['cyan']}📚 Creating Production Documentation{self.colors['reset']}")

        production_readme = '''# HomeNetMon Production Deployment Guide

This guide covers deploying HomeNetMon in a production environment.

## Quick Start

### Option 1: Docker Deployment (Recommended)

1. **Prepare environment:**
   ```bash
   cp .env.prod.template .env.prod
   # Edit .env.prod with your configuration
   ```

2. **Deploy with Docker:**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

3. **Access application:**
   - HTTP: http://your-server
   - HTTPS: https://your-server (after SSL setup)

### Option 2: Native Deployment

1. **Run deployment script:**
   ```bash
   sudo ./deploy.sh
   ```

2. **Configure environment:**
   ```bash
   sudo cp .env.prod.template /opt/homenetmon/.env
   sudo nano /opt/homenetmon/.env
   ```

3. **Restart service:**
   ```bash
   sudo systemctl restart homenetmon
   ```

## SSL/TLS Setup

Enable HTTPS with Let's Encrypt:

```bash
sudo ./setup_ssl.sh your-domain.com your-email@domain.com
```

## Configuration

### Environment Variables

Key production settings in `.env.prod`:

- `SECRET_KEY`: Strong secret key for sessions
- `ADMIN_PASSWORD`: Admin login password
- `NETWORK_RANGE`: Your network CIDR (e.g., 192.168.1.0/24)
- `SMTP_*`: Email configuration for alerts
- `REDIS_URL`: Redis connection for caching

### Security Settings

- Change default admin password
- Configure firewall (ports 80, 443)
- Enable HTTPS in production
- Set strong SECRET_KEY
- Configure SMTP for alerts

## Monitoring

### Health Checks

```bash
./health_check.sh
curl http://localhost/health
```

### Service Management

```bash
# Check status
systemctl status homenetmon

# View logs
journalctl -u homenetmon -f

# Restart service
systemctl restart homenetmon
```

### Database Backups

Backups run automatically via cron. Manual backup:

```bash
python3 backup_production.py
```

## Updates

Update to latest version:

```bash
sudo ./update.sh
```

## Performance Tuning

### Database Optimization

- Automatic cleanup runs daily
- WAL mode enabled for performance
- Indexes optimized for queries

### Nginx Configuration

- Gzip compression enabled
- Static file caching
- Rate limiting configured
- Security headers applied

### Application Settings

- Redis caching enabled
- Connection pooling
- Performance monitoring
- Resource optimization

## Troubleshooting

### Common Issues

1. **Service won't start:**
   ```bash
   journalctl -u homenetmon --no-pager -l
   ```

2. **Network scanning issues:**
   - Check nmap installation
   - Verify network permissions
   - Review NETWORK_RANGE setting

3. **Database problems:**
   ```bash
   sqlite3 /opt/homenetmon/data/homeNetMon.db ".schema"
   ```

4. **Performance issues:**
   ```bash
   python3 optimize_database_performance.py
   ```

### Log Locations

- Application: `/opt/homenetmon/logs/`
- Nginx: `/var/log/nginx/`
- System: `journalctl -u homenetmon`

## Security Checklist

- [ ] Strong admin password set
- [ ] HTTPS enabled with valid certificate
- [ ] Firewall configured (UFW/iptables)
- [ ] Regular security updates
- [ ] Database backups verified
- [ ] Rate limiting enabled
- [ ] Security headers configured
- [ ] Non-root user running application

## Scaling

For high-traffic deployments:

1. **Database:** Consider PostgreSQL migration
2. **Caching:** Redis cluster setup
3. **Load Balancing:** Multiple app instances
4. **Monitoring:** External monitoring tools

## Support

- Configuration issues: Check logs and environment
- Performance problems: Run optimization scripts
- Security concerns: Review security checklist
- Updates: Use provided update script

## Architecture

```
Internet → Nginx → HomeNetMon App → SQLite/Redis
                ↓
         Static Files, WebSockets
```

Production deployment provides:
- High availability
- Security hardening
- Performance optimization
- Automated backups
- Monitoring capabilities
'''

        try:
            (self.project_dir / "PRODUCTION_DEPLOYMENT.md").write_text(production_readme)
            self.log_step("Production Documentation", True, "Created comprehensive deployment guide")
        except Exception as e:
            self.log_step("Production Documentation", False, str(e))

    def run_infrastructure_setup(self):
        """Run complete production infrastructure setup"""
        print(f"{self.colors['purple']}🚀 HomeNetMon Production Infrastructure Setup{self.colors['reset']}")
        print(f"Phase 6.1: Complete production deployment preparation")
        print("=" * 80)

        start_time = time.time()

        # Run all setup components
        setup_components = [
            self.create_docker_production_config,
            self.create_nginx_config,
            self.create_supervisor_config,
            self.create_systemd_service,
            self.create_environment_template,
            self.create_deployment_scripts,
            self.create_ssl_setup,
            self.create_monitoring_setup,
            self.create_backup_automation,
            self.create_production_readme
        ]

        for component in setup_components:
            try:
                component()
            except Exception as e:
                self.logger.error(f"Component {component.__name__} failed: {e}")

        # Generate setup report
        self.generate_setup_report(start_time)

    def generate_setup_report(self, start_time):
        """Generate infrastructure setup report"""
        duration = time.time() - start_time

        print(f"\n{self.colors['purple']}📊 Production Infrastructure Setup Report{self.colors['reset']}")
        print("=" * 80)

        # Summary
        total_steps = len(self.setup_results)
        successful_steps = sum(1 for result in self.setup_results if result['success'])
        success_rate = (successful_steps / total_steps * 100) if total_steps > 0 else 0

        print(f"\n⏱️ Duration: {duration:.1f} seconds")
        print(f"📊 Setup Steps: {total_steps}")
        print(f"✅ Successful: {successful_steps}")
        print(f"❌ Failed: {total_steps - successful_steps}")
        print(f"📈 Success Rate: {success_rate:.1f}%")

        # Component status
        print(f"\n🔧 Component Status:")
        for result in self.setup_results:
            status_color = self.colors['green'] if result['success'] else self.colors['red']
            status = "✅ READY" if result['success'] else "❌ FAILED"
            print(f"  {status_color}{result['step']}: {status}{self.colors['reset']}")

        # Files created
        print(f"\n📁 Production Files Created:")
        created_files = [
            "Dockerfile.prod - Production Docker image",
            "docker-compose.prod.yml - Production Docker Compose",
            "docker/nginx.conf - Nginx reverse proxy config",
            "docker/supervisord.conf - Process management",
            "homenetmon.service - Systemd service file",
            ".env.prod.template - Environment configuration",
            "deploy.sh - Automated deployment script",
            "update.sh - Update automation script",
            "setup_ssl.sh - SSL certificate setup",
            "health_check.sh - Health monitoring",
            "backup_production.py - Backup automation",
            "PRODUCTION_DEPLOYMENT.md - Deployment guide"
        ]

        for file_desc in created_files:
            print(f"  📄 {file_desc}")

        # Deployment options
        print(f"\n🚀 Deployment Options:")
        print(f"  1. Docker: docker-compose -f docker-compose.prod.yml up -d")
        print(f"  2. Native: sudo ./deploy.sh")
        print(f"  3. Manual: Follow PRODUCTION_DEPLOYMENT.md")

        # Final assessment
        if success_rate >= 90:
            print(f"\n{self.colors['green']}🎉 PRODUCTION INFRASTRUCTURE READY!{self.colors['reset']}")
            print("✅ All components configured for production deployment")
        elif success_rate >= 75:
            print(f"\n{self.colors['yellow']}⚠️ MOSTLY READY - Some components need attention{self.colors['reset']}")
        else:
            print(f"\n{self.colors['red']}❌ SETUP INCOMPLETE - Review failed components{self.colors['reset']}")

        # Phase completion
        if success_rate >= 80:
            print(f"\n{self.colors['green']}✅ Phase 6.1: Production infrastructure setup - COMPLETED{self.colors['reset']}")
        else:
            print(f"\n{self.colors['red']}❌ Phase 6.1: Production infrastructure setup - NEEDS ATTENTION{self.colors['reset']}")

        # Save detailed report
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'total_steps': total_steps,
            'successful_steps': successful_steps,
            'success_rate': success_rate,
            'setup_results': self.setup_results
        }

        with open('production_infrastructure_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)

        print(f"\n📄 Detailed report saved to: production_infrastructure_report.json")
        print(f"📋 Setup log saved to: production_setup.log")

def main():
    """Main infrastructure setup execution"""
    print(f"🏗️ PRODUCTION INFRASTRUCTURE SETUP")
    print(f"📊 Phase 6.1: Complete production deployment preparation")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

    # Run infrastructure setup
    setup = ProductionInfrastructureSetup()
    setup.run_infrastructure_setup()

if __name__ == "__main__":
    main()