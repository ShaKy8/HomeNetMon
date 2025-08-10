#!/bin/bash

# HomeNetMon Permission Fix Script
echo "🔧 HomeNetMon Permission Fix"
echo "==============================="

# Stop current process
echo "Stopping current HomeNetMon process..."
pkill -f "python3 app.py" 2>/dev/null || echo "No existing process found"
sleep 2

# Method 1: Set capabilities (preferred)
echo ""
echo "Method 1: Setting network capabilities..."
if command -v setcap >/dev/null 2>&1; then
    PYTHON_PATH=$(which python3)
    echo "Python path: $PYTHON_PATH"
    
    echo "Setting CAP_NET_RAW capability on Python..."
    sudo setcap cap_net_raw+ep "$PYTHON_PATH"
    
    if [ $? -eq 0 ]; then
        echo "✅ Capabilities set successfully!"
        
        # Verify capabilities
        echo "Verifying capabilities..."
        getcap "$PYTHON_PATH"
        
        # Start HomeNetMon with capabilities
        echo ""
        echo "Starting HomeNetMon with network capabilities..."
        cd /home/kyle/ClaudeCode/HomeNetMon
        export NETWORK_RANGE="192.168.86.0/24"
        export DEBUG=true
        export HOST=0.0.0.0 
        export PORT=5000
        
        python3 app.py > homeNetMon.log 2>&1 &
        PID=$!
        echo "HomeNetMon started with PID: $PID"
        
        # Wait a moment and test
        sleep 3
        if ps -p $PID > /dev/null; then
            echo "✅ HomeNetMon is running successfully!"
            echo ""
            echo "Testing ping functionality..."
            sleep 2
            
            # Test ping manually
            python3 -c "
from ping3 import ping
result = ping('192.168.86.1', timeout=3)
if result:
    print(f'✅ Ping test successful: {result*1000:.1f}ms')
else:
    print('❌ Ping test failed')
"
        else
            echo "❌ HomeNetMon failed to start"
            cat homeNetMon.log | tail -10
        fi
        
    else
        echo "❌ Failed to set capabilities. Trying sudo method..."
        
        # Method 2: Run with sudo
        echo ""
        echo "Method 2: Running with sudo..."
        cd /home/kyle/ClaudeCode/HomeNetMon
        export NETWORK_RANGE="192.168.86.0/24"
        export DEBUG=true
        export HOST=0.0.0.0
        export PORT=5000
        
        echo "Starting HomeNetMon with sudo..."
        sudo -E python3 app.py > homeNetMon.log 2>&1 &
        PID=$!
        echo "HomeNetMon started with sudo, PID: $PID"
        
        sleep 3
        if ps -p $PID > /dev/null; then
            echo "✅ HomeNetMon is running with sudo!"
        else
            echo "❌ Failed to start with sudo"
            cat homeNetMon.log | tail -10
        fi
    fi
else
    echo "setcap not available, using sudo method..."
    
    # Method 2: Run with sudo
    cd /home/kyle/ClaudeCode/HomeNetMon
    export NETWORK_RANGE="192.168.86.0/24"
    export DEBUG=true
    export HOST=0.0.0.0
    export PORT=5000
    
    echo "Starting HomeNetMon with sudo..."
    sudo -E python3 app.py > homeNetMon.log 2>&1 &
    PID=$!
    echo "HomeNetMon started with sudo, PID: $PID"
fi

echo ""
echo "🌐 Access HomeNetMon:"
echo "   http://localhost:5000"
echo "   http://$(hostname -I | awk '{print $1}'):5000"
echo ""
echo "📊 Check status:"
echo "   curl http://localhost:5000/health"
echo ""
echo "📝 View logs:"
echo "   tail -f homeNetMon.log"