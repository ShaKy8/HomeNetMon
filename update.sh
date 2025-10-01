#!/bin/bash
set -e

echo "🔄 HomeNetMon Update"
echo "==================="

APP_DIR="/opt/homenetmon"
SERVICE_NAME="homenetmon"
BACKUP_DIR="$APP_DIR/backups"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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
