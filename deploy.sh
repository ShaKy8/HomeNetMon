#!/bin/bash
set -e

echo "🚀 HomeNetMon Production Deployment"
echo "=================================="

# Configuration
APP_USER="homenetmon"
APP_DIR="/opt/homenetmon"
SERVICE_NAME="homenetmon"
BACKUP_DIR="/opt/homenetmon/backups"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
