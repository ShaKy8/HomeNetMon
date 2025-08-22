#!/bin/bash

echo "Updating HomeNetMon systemd service..."

# Stop the current service
echo "Stopping current service..."
sudo systemctl stop homenetmon

# Copy the updated service file
echo "Updating service file..."
sudo cp homenetmon-updated.service /etc/systemd/system/homenetmon.service

# Reload systemd daemon
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Enable the service for auto-start
echo "Enabling service for auto-start..."
sudo systemctl enable homenetmon

# Start the service
echo "Starting HomeNetMon service..."
sudo systemctl start homenetmon

# Check status
echo "Checking service status..."
sudo systemctl status homenetmon

echo ""
echo "HomeNetMon service update complete!"
echo ""
echo "The web interface should be available at: http://0.0.0.0:5000"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status homenetmon    - Check service status"
echo "  sudo systemctl restart homenetmon   - Restart service"
echo "  sudo journalctl -u homenetmon -f    - Follow logs in real-time"