#!/bin/bash
# Setup script for HomeNetMon systemd service

echo "Setting up HomeNetMon systemd service..."

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

# Check service status
echo "Checking service status..."
sudo systemctl status homenetmon

echo ""
echo "HomeNetMon service setup complete!"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status homenetmon    - Check service status"
echo "  sudo systemctl start homenetmon     - Start service"
echo "  sudo systemctl stop homenetmon      - Stop service"
echo "  sudo systemctl restart homenetmon   - Restart service"
echo "  sudo systemctl logs homenetmon      - View logs"
echo "  journalctl -u homenetmon -f         - Follow logs in real-time"