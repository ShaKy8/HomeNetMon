#!/bin/bash

# HomeNetMon Installation Script
# This script installs HomeNetMon on Ubuntu/Debian systems

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/homeNetMon"
SERVICE_USER="homeNetMon"
VENV_DIR="$INSTALL_DIR/venv"
PYTHON_VERSION="3.8"

# Functions
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root!"
        print_status "Please run as a regular user with sudo privileges."
        exit 1
    fi
    
    if ! sudo -l > /dev/null 2>&1; then
        print_error "This user does not have sudo privileges!"
        exit 1
    fi
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        print_error "Cannot determine OS version"
        exit 1
    fi
    
    case $OS in
        ubuntu|debian)
            print_status "Detected OS: $OS $VER"
            ;;
        *)
            print_error "Unsupported OS: $OS"
            print_status "This script supports Ubuntu and Debian only."
            exit 1
            ;;
    esac
}

install_system_dependencies() {
    print_status "Installing system dependencies..."
    
    sudo apt-get update
    sudo apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        nmap \
        iputils-ping \
        net-tools \
        curl \
        git \
        supervisor \
        nginx \
        sqlite3 \
        libpcap-dev
    
    print_success "System dependencies installed"
}

create_user() {
    if id "$SERVICE_USER" &>/dev/null; then
        print_status "User $SERVICE_USER already exists"
    else
        print_status "Creating user $SERVICE_USER..."
        sudo useradd --system --create-home --home-dir /home/$SERVICE_USER --shell /bin/bash $SERVICE_USER
        print_success "User $SERVICE_USER created"
    fi
}

create_directories() {
    print_status "Creating directories..."
    
    sudo mkdir -p $INSTALL_DIR
    sudo mkdir -p /var/log/homeNetMon
    sudo mkdir -p /etc/homeNetMon
    
    sudo chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR
    sudo chown -R $SERVICE_USER:$SERVICE_USER /var/log/homeNetMon
    sudo chown -R $SERVICE_USER:$SERVICE_USER /etc/homeNetMon
    
    print_success "Directories created"
}

install_application() {
    print_status "Installing HomeNetMon application..."
    
    # Copy application files
    sudo cp -r . $INSTALL_DIR/
    sudo chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR
    
    # Create virtual environment
    sudo -u $SERVICE_USER python3 -m venv $VENV_DIR
    
    # Install Python dependencies
    sudo -u $SERVICE_USER $VENV_DIR/bin/pip install --upgrade pip
    sudo -u $SERVICE_USER $VENV_DIR/bin/pip install -r $INSTALL_DIR/requirements.txt
    
    print_success "Application installed"
}

create_systemd_service() {
    print_status "Creating systemd service..."
    
    sudo tee /etc/systemd/system/homeNetMon.service > /dev/null << EOF
[Unit]
Description=HomeNetMon - Home Network Monitoring Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$VENV_DIR/bin
ExecStart=$VENV_DIR/bin/python app.py
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=30
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$INSTALL_DIR /var/log/homeNetMon /etc/homeNetMon
PrivateTmp=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

# Network capabilities
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=homeNetMon

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    sudo systemctl enable homeNetMon.service
    
    print_success "Systemd service created"
}

create_nginx_config() {
    print_status "Creating nginx configuration..."
    
    sudo tee /etc/nginx/sites-available/homeNetMon > /dev/null << 'EOF'
server {
    listen 80;
    server_name homeNetMon homeNetMon.local localhost;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy strict-origin-when-cross-origin;
    
    # Proxy to Flask application
    location / {
        proxy_pass http://127.0.0.1:5000;
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
    
    # Static files (optional optimization)
    location /static {
        proxy_pass http://127.0.0.1:5000;
        expires 1d;
        add_header Cache-Control "public, immutable";
    }
    
    # Health check
    location /health {
        proxy_pass http://127.0.0.1:5000;
        access_log off;
    }
    
    # Logging
    access_log /var/log/nginx/homeNetMon.access.log;
    error_log /var/log/nginx/homeNetMon.error.log;
}
EOF
    
    # Enable the site
    sudo ln -sf /etc/nginx/sites-available/homeNetMon /etc/nginx/sites-enabled/homeNetMon
    
    # Test nginx configuration
    if sudo nginx -t; then
        print_success "Nginx configuration created"
    else
        print_error "Nginx configuration test failed"
    fi
}

create_configuration() {
    print_status "Creating default configuration..."
    
    sudo -u $SERVICE_USER tee /etc/homeNetMon/config.yaml > /dev/null << EOF
# HomeNetMon Configuration File
# You can modify these settings via the web interface

network:
  range: "192.168.86.0/24"
  ping_interval: 30
  scan_interval: 300
  ping_timeout: 3.0
  max_workers: 50

database:
  retention_days: 30

web:
  host: "127.0.0.1"
  port: 5000
  debug: false

alerts:
  email:
    enabled: false
    smtp_server: ""
    smtp_port: 587
    username: ""
    password: ""
    use_tls: true
    from_email: ""
    to_emails: []
  
  webhook:
    enabled: false
    url: ""
    timeout: 10

logging:
  level: "INFO"
  file: "/var/log/homeNetMon/homeNetMon.log"
EOF
    
    print_success "Default configuration created"
}

start_services() {
    print_status "Starting services..."
    
    # Start HomeNetMon service
    sudo systemctl start homeNetMon.service
    
    # Restart nginx
    sudo systemctl restart nginx
    
    # Wait a moment for service to start
    sleep 3
    
    # Check service status
    if sudo systemctl is-active --quiet homeNetMon.service; then
        print_success "HomeNetMon service started successfully"
    else
        print_error "Failed to start HomeNetMon service"
        print_status "Check logs with: sudo journalctl -u homeNetMon.service -f"
        return 1
    fi
}

show_completion_message() {
    print_success "HomeNetMon installation completed!"
    echo
    echo "=== Installation Summary ==="
    echo "Installation Directory: $INSTALL_DIR"
    echo "Configuration File: /etc/homeNetMon/config.yaml"
    echo "Log Files: /var/log/homeNetMon/"
    echo "Service User: $SERVICE_USER"
    echo
    echo "=== Access Information ==="
    echo "Web Interface: http://$(hostname -I | awk '{print $1}')/"
    echo "Health Check: http://$(hostname -I | awk '{print $1}')/health"
    echo
    echo "=== Useful Commands ==="
    echo "View service status: sudo systemctl status homeNetMon"
    echo "View logs: sudo journalctl -u homeNetMon -f"
    echo "Restart service: sudo systemctl restart homeNetMon"
    echo "Stop service: sudo systemctl stop homeNetMon"
    echo "Update config: sudo nano /etc/homeNetMon/config.yaml"
    echo
    print_status "You can now access HomeNetMon via your web browser!"
}

# Main installation process
main() {
    echo "=== HomeNetMon Installation Script ==="
    echo
    
    check_root
    check_os
    
    print_status "Starting installation..."
    
    install_system_dependencies
    create_user
    create_directories
    install_application
    create_systemd_service
    create_nginx_config
    create_configuration
    
    if start_services; then
        show_completion_message
    else
        print_error "Installation completed with errors. Please check the service status."
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "HomeNetMon Installation Script"
        echo "Usage: $0 [options]"
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --uninstall    Uninstall HomeNetMon"
        echo "  --update       Update existing installation"
        exit 0
        ;;
    --uninstall)
        print_status "Uninstalling HomeNetMon..."
        sudo systemctl stop homeNetMon || true
        sudo systemctl disable homeNetMon || true
        sudo rm -f /etc/systemd/system/homeNetMon.service
        sudo rm -f /etc/nginx/sites-enabled/homeNetMon
        sudo rm -f /etc/nginx/sites-available/homeNetMon
        sudo rm -rf $INSTALL_DIR
        sudo rm -rf /var/log/homeNetMon
        sudo rm -rf /etc/homeNetMon
        sudo userdel $SERVICE_USER || true
        sudo systemctl daemon-reload
        sudo systemctl reload nginx || true
        print_success "HomeNetMon uninstalled"
        exit 0
        ;;
    --update)
        print_status "Updating HomeNetMon..."
        sudo systemctl stop homeNetMon
        sudo cp -r . $INSTALL_DIR/
        sudo chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR
        sudo -u $SERVICE_USER $VENV_DIR/bin/pip install -r $INSTALL_DIR/requirements.txt
        sudo systemctl start homeNetMon
        print_success "HomeNetMon updated"
        exit 0
        ;;
    "")
        main
        ;;
    *)
        print_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac