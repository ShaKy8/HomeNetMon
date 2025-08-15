#!/bin/bash
# Restart HomeNetMon service script

echo "Attempting to restart HomeNetMon service..."

# Try user service first
if systemctl --user restart homenetmon 2>/dev/null; then
    echo "✅ User service restarted successfully"
    exit 0
fi

# Try system service with sudo
if sudo systemctl restart homenetmon 2>/dev/null; then
    echo "✅ System service restarted successfully" 
    exit 0
fi

# Fallback: kill process and let systemd restart it
echo "Trying to restart by killing process..."
if sudo pkill -f "python3.*app.py"; then
    echo "Process killed, waiting for systemd to restart..."
    sleep 5
    if systemctl is-active homenetmon >/dev/null 2>&1; then
        echo "✅ Service restarted successfully"
    else
        echo "❌ Service restart failed"
        exit 1
    fi
else
    echo "❌ Could not restart service - may need manual intervention"
    exit 1
fi