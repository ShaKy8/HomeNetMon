#!/bin/bash

echo "🔧 Fixing HomeNetMon Ping Permissions"
echo "===================================="

# Stop current processes
echo "1. Stopping current HomeNetMon..."
pkill -f "app_context_fix.py" 2>/dev/null && echo "✅ Stopped existing process" || echo "ℹ️  No process to stop"
sleep 2

# Set network capabilities on Python
echo ""
echo "2. Setting network capabilities on Python..."
PYTHON_PATH=$(which python3)
echo "Python binary: $PYTHON_PATH"

# Try to set capabilities (requires sudo)
echo "Setting CAP_NET_RAW capability..."
sudo setcap cap_net_raw+ep "$PYTHON_PATH"

if [ $? -eq 0 ]; then
    echo "✅ Network capabilities set successfully"
    getcap "$PYTHON_PATH"
    USE_SUDO=false
else
    echo "❌ Failed to set capabilities - will use sudo method"
    USE_SUDO=true
fi

# Test ping capability
echo ""
echo "3. Testing ping capability..."
cd /home/kyle/ClaudeCode/HomeNetMon

if [ "$USE_SUDO" = false ]; then
    python3 -c "
from ping3 import ping
try:
    result = ping('127.0.0.1', timeout=2)
    if result:
        print('✅ Ping test successful - capabilities working')
    else:
        print('❌ Ping returned None')
except Exception as e:
    print(f'❌ Ping failed: {e}')
    exit(1)
"
    if [ $? -ne 0 ]; then
        USE_SUDO=true
        echo "Capabilities didn't work, falling back to sudo"
    fi
fi

# Restart HomeNetMon
echo ""
echo "4. Restarting HomeNetMon..."
export NETWORK_RANGE="192.168.86.0/24"
export DEBUG=true
export HOST=0.0.0.0
export PORT=5000

if [ "$USE_SUDO" = true ]; then
    echo "🔐 Starting with sudo (required for ping operations)..."
    sudo -E python3 app_context_fix.py > homeNetMon_fixed.log 2>&1 &
    PID=$!
    echo "Started with sudo, PID: $PID"
else
    echo "🚀 Starting with user privileges and capabilities..."
    python3 app_context_fix.py > homeNetMon_fixed.log 2>&1 &
    PID=$!
    echo "Started with capabilities, PID: $PID"
fi

# Test startup
sleep 5

if ps -p $PID > /dev/null; then
    echo ""
    echo "✅ HomeNetMon restarted successfully!"
    echo ""
    echo "🌐 Access at: http://192.168.86.64:5000"
    echo ""
    echo "📝 Monitor logs:"
    echo "  tail -f homeNetMon_fixed.log"
    echo ""
    echo "🧪 Test ping functionality:"
    echo "  - Go to the web interface"
    echo "  - Click ping on any device"
    echo "  - Should work without permission errors"
else
    echo ""
    echo "❌ Failed to start HomeNetMon"
    echo "Last 10 lines of log:"
    tail -10 homeNetMon_fixed.log
fi