#!/bin/bash
# Setup script for HomeNetMon systemd service

set -e

echo "Setting up HomeNetMon systemd service..."

# Stop any running Python app.py processes first
echo "Stopping any existing HomeNetMon processes..."
pkill -f "python.*app.py" || true
sleep 2

# Copy service file to systemd directory
echo "Copying service file..."
sudo cp homenetmon.service /etc/systemd/system/

# Reload systemd daemon
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Enable the service to start on boot
echo "Enabling HomeNetMon service..."
sudo systemctl enable homenetmon

# Start the service
echo "Starting HomeNetMon service..."
sudo systemctl start homenetmon

# Wait for service to start
sleep 3

# Check service status
echo "Checking service status..."
sudo systemctl status homenetmon --no-pager

echo ""
echo "HomeNetMon service setup complete!"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status homenetmon    - Check service status"
echo "  sudo systemctl start homenetmon     - Start service"
echo "  sudo systemctl stop homenetmon      - Stop service"
echo "  sudo systemctl restart homenetmon   - Restart service"
echo "  sudo journalctl -u homenetmon -f    - Follow logs in real-time"