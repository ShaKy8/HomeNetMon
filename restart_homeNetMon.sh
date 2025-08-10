#!/bin/bash

echo "🔄 Restarting HomeNetMon with proper environment"
echo "================================================"

# Stop any existing processes
echo "Stopping existing HomeNetMon processes..."
pkill -f "python3 app.py" 2>/dev/null || echo "No existing processes found"
sleep 2

# Verify Flask is available
echo ""
echo "Checking Python environment..."
python3 -c "
import sys
print(f'Python: {sys.executable}')
try:
    import flask
    print('✅ Flask: Available')
except ImportError:
    print('❌ Flask: Not available')
    exit(1)

try:
    import ping3
    print('✅ ping3: Available')
except ImportError:
    print('❌ ping3: Not available')
    exit(1)

try:
    import nmap
    print('✅ python-nmap: Available') 
except ImportError:
    print('❌ python-nmap: Not available')
    exit(1)
"

if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Required packages not available. Reinstalling..."
    pip install --break-system-packages --user flask flask-sqlalchemy flask-socketio ping3 python-nmap manuf eventlet structlog python-dateutil python-dotenv
fi

echo ""
echo "🚀 Starting HomeNetMon..."
cd /home/kyle/ClaudeCode/HomeNetMon

# Set environment variables
export NETWORK_RANGE="192.168.86.0/24"
export DEBUG=true
export HOST=0.0.0.0
export PORT=5000

# Start HomeNetMon in background
python3 app.py > homeNetMon.log 2>&1 &
PID=$!

echo "HomeNetMon started with PID: $PID"
echo ""

# Wait a moment and check if it's running
sleep 3

if ps -p $PID > /dev/null; then
    echo "✅ HomeNetMon is running successfully!"
    
    # Test if it's responding
    sleep 2
    if curl -s http://localhost:5000/health > /dev/null; then
        echo "✅ Web interface is responding"
    else
        echo "⚠️  Web interface not responding yet (may take a moment)"
    fi
    
    echo ""
    echo "🌐 Access HomeNetMon at:"
    echo "   http://localhost:5000"
    echo "   http://$(hostname -I | awk '{print $1}'):5000"
    echo ""
    echo "📝 Monitor logs with:"
    echo "   tail -f homeNetMon.log"
    
else
    echo "❌ HomeNetMon failed to start"
    echo ""
    echo "📄 Last 10 lines of log:"
    tail -10 homeNetMon.log
    echo ""
    echo "🔧 Try running with sudo if needed:"
    echo "   sudo -E python3 app.py"
fi