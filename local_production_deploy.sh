#!/bin/bash
# Local Production Deployment for HomeNetMon
# Runs in user space without sudo requirements

set -e

echo "🚀 HomeNetMon Local Production Deployment"
echo "=========================================="
echo "Running production setup in user space..."

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Configuration
APP_DIR="$HOME/ClaudeCode/HomeNetMon"
DATA_DIR="$APP_DIR/production_data"
LOG_DIR="$APP_DIR/logs"
VENV_DIR="$APP_DIR/venv"

# Create production directories
log_info "Creating production directories..."
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"

# Copy production environment
log_info "Setting up production environment..."
if [ -f "$APP_DIR/.env.prod" ]; then
    cp "$APP_DIR/.env.prod" "$APP_DIR/.env"
    log_info "Production environment configured"
else
    log_warn "Production environment file not found"
fi

# Update database path in environment
log_info "Configuring database path..."
sed -i "s|/opt/homenetmon/data|$DATA_DIR|g" "$APP_DIR/.env" 2>/dev/null || true

# Update log path in environment
sed -i "s|/opt/homenetmon/logs|$LOG_DIR|g" "$APP_DIR/.env" 2>/dev/null || true

# Copy database if exists
if [ -f "$APP_DIR/homeNetMon.db" ]; then
    log_info "Copying database to production location..."
    cp "$APP_DIR/homeNetMon.db" "$DATA_DIR/"
fi

# Create systemd user service
log_info "Creating systemd user service..."
mkdir -p "$HOME/.config/systemd/user"

cat > "$HOME/.config/systemd/user/homenetmon.service" << EOF
[Unit]
Description=HomeNetMon Network Monitoring Service
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=FLASK_ENV=production
Environment=PYTHONPATH=$APP_DIR
Environment=DATABASE_URL=sqlite:///$DATA_DIR/homeNetMon.db
Environment=HOST=0.0.0.0
Environment=PORT=5000
ExecStart=$VENV_DIR/bin/python app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF

# Reload systemd user daemon
log_info "Reloading systemd user configuration..."
systemctl --user daemon-reload

# Install Python dependencies if needed
if [ ! -d "$VENV_DIR" ]; then
    log_warn "Virtual environment not found, creating..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip
    "$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt"
fi

# Create production runner script
cat > "$APP_DIR/run_production.sh" << 'EOF'
#!/bin/bash
# Production runner for HomeNetMon

# Load environment
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Set production defaults
export FLASK_ENV=production
export HOST=0.0.0.0
export PORT=5000

# Run the application
exec venv/bin/python app.py
EOF

chmod +x "$APP_DIR/run_production.sh"

log_info "Local production deployment complete!"
echo ""
echo "📋 Next Steps:"
echo "1. Start service: systemctl --user start homenetmon"
echo "2. Enable auto-start: systemctl --user enable homenetmon"
echo "3. Check status: systemctl --user status homenetmon"
echo "4. View logs: journalctl --user -u homenetmon -f"
echo ""
echo "Or run directly: ./run_production.sh"
echo ""
echo "🌐 Access the application at: http://localhost:5000"
echo "🔐 Admin Password: Check .env.prod file"