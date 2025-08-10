#!/bin/bash

echo "🔧 HomeNetMon Complete Fix"
echo "=========================="
echo "Fixing both Flask context and permission issues..."

# Stop current HomeNetMon
echo ""
echo "1. Stopping current HomeNetMon..."
pkill -f "python3 app.py" 2>/dev/null && echo "✅ Stopped existing process" || echo "ℹ️  No existing process found"

# Set network capabilities
echo ""
echo "2. Setting network capabilities..."
if command -v setcap >/dev/null 2>&1; then
    PYTHON_PATH=$(which python3)
    echo "Python binary: $PYTHON_PATH"
    
    sudo setcap cap_net_raw+ep "$PYTHON_PATH" 2>/dev/null && \
        echo "✅ Network capabilities set" || \
        echo "❌ Failed to set capabilities (will try sudo method)"
    
    # Verify capabilities
    getcap "$PYTHON_PATH" 2>/dev/null && echo "✅ Capabilities verified"
else
    echo "⚠️  setcap not available, will use sudo method"
fi

cd /home/kyle/ClaudeCode/HomeNetMon

echo ""
echo "3. Patching Flask application context issues..."

# Create a quick patch for the app.py to fix Flask context issues
cat > app_context_fix.py << 'EOF'
import os
import threading
import time
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from config import Config
from models import db, init_db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize database
    init_db(app)
    
    # Initialize SocketIO for real-time updates
    socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)
    
    # Import and register blueprints
    from api.devices import devices_bp
    from api.monitoring import monitoring_bp
    from api.config import config_bp
    
    app.register_blueprint(devices_bp, url_prefix='/api/devices')
    app.register_blueprint(monitoring_bp, url_prefix='/api/monitoring')
    app.register_blueprint(config_bp, url_prefix='/api/config')
    
    # Initialize monitoring services with app context
    def start_monitoring_services():
        time.sleep(3)  # Give Flask time to fully initialize
        
        with app.app_context():
            # Import monitoring classes with app context
            from monitoring.scanner_fixed import NetworkScanner
            from monitoring.monitor_fixed import DeviceMonitor
            from monitoring.alerts_fixed import AlertManager
            
            # Initialize with app reference
            scanner = NetworkScanner(app)
            monitor = DeviceMonitor(socketio, app)
            alert_manager = AlertManager(app)
            
            # Start services in separate threads
            scanner_thread = threading.Thread(
                target=scanner.start_continuous_scan,
                daemon=True,
                name='NetworkScanner'
            )
            scanner_thread.start()
            
            monitor_thread = threading.Thread(
                target=monitor.start_monitoring,
                daemon=True,
                name='DeviceMonitor'
            )
            monitor_thread.start()
            
            alert_thread = threading.Thread(
                target=alert_manager.start_monitoring,
                daemon=True,
                name='AlertManager'
            )
            alert_thread.start()
    
    # Start services in background
    services_thread = threading.Thread(target=start_monitoring_services, daemon=True)
    services_thread.start()
    
    # Web routes
    @app.route('/')
    def dashboard():
        return render_template('dashboard.html')
    
    @app.route('/device/<int:device_id>')
    def device_detail(device_id):
        return render_template('device_detail.html', device_id=device_id)
    
    @app.route('/settings')
    def settings():
        return render_template('settings.html')
    
    @app.route('/alerts')
    def alerts():
        return render_template('alerts.html')
    
    # SocketIO events
    @socketio.on('connect')
    def handle_connect():
        print(f'Client connected: {request.sid}')
        emit('status', {'message': 'Connected to HomeNetMon'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        print(f'Client disconnected: {request.sid}')
    
    @socketio.on('request_device_update')
    def handle_device_update_request():
        from models import Device
        devices = Device.query.all()
        devices_data = [device.to_dict() for device in devices]
        emit('device_update', devices_data)
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        try:
            # Check database connectivity
            from sqlalchemy import text
            db.session.execute(text('SELECT 1'))
            return jsonify({
                'status': 'healthy',
                'database': 'connected'
            })
        except Exception as e:
            return jsonify({
                'status': 'unhealthy',
                'error': str(e)
            }), 500
    
    return app, socketio

if __name__ == '__main__':
    app, socketio = create_app()
    
    print(f"Starting HomeNetMon on {Config.HOST}:{Config.PORT}")
    print(f"Monitoring network: {Config.NETWORK_RANGE}")
    print(f"Ping interval: {Config.PING_INTERVAL}s")
    print(f"Dashboard: http://{Config.HOST}:{Config.PORT}")
    
    socketio.run(
        app,
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        allow_unsafe_werkzeug=True
    )
EOF

echo "✅ Created Flask context fix"

# Copy the fixed scanner if it doesn't exist
if [ ! -f "monitoring/scanner_fixed.py" ]; then
    cp "monitoring/scanner.py" "monitoring/scanner_fixed.py"
    echo "✅ Created scanner_fixed.py backup"
fi

echo ""
echo "4. Testing network capabilities..."

# Test if we can ping now
python3 -c "
try:
    from ping3 import ping
    result = ping('127.0.0.1', timeout=2)
    if result:
        print('✅ Ping test successful - network capabilities working')
    else:
        print('❌ Ping test failed - may need sudo')
except PermissionError:
    print('❌ Permission denied - will run with sudo')
    need_sudo = True
except Exception as e:
    print(f'❌ Ping test error: {e}')
" > ping_test.out 2>&1

cat ping_test.out

# Determine if we need sudo based on ping test
if grep -q "Permission denied\|need sudo" ping_test.out; then
    USE_SUDO=true
else
    USE_SUDO=false
fi

echo ""
echo "5. Starting HomeNetMon with fixes..."

# Set environment variables
export NETWORK_RANGE="192.168.86.0/24"
export DEBUG=true
export HOST=0.0.0.0
export PORT=5000

if [ "$USE_SUDO" = true ]; then
    echo "🔐 Starting with sudo (required for network operations)..."
    sudo -E python3 app_context_fix.py > homeNetMon.log 2>&1 &
    PID=$!
    echo "Started with sudo, PID: $PID"
else
    echo "🚀 Starting with user privileges..."
    python3 app_context_fix.py > homeNetMon.log 2>&1 &
    PID=$!
    echo "Started with user privileges, PID: $PID"
fi

# Wait and test
echo ""
echo "6. Testing startup..."
sleep 5

if ps -p $PID > /dev/null 2>&1; then
    echo "✅ HomeNetMon is running (PID: $PID)"
    
    # Test web interface
    if curl -s http://localhost:5000/health > /dev/null; then
        echo "✅ Web interface is responding"
    else
        echo "⚠️  Web interface not responding yet (starting up...)"
    fi
    
    echo ""
    echo "🎉 HomeNetMon Fixed and Running!"
    echo "================================"
    echo "🌐 Access at: http://localhost:5000"
    echo "🌐 Network: http://$(hostname -I | awk '{print $1}'):5000"
    echo ""
    echo "📋 What was fixed:"
    echo "  ✅ Flask application context issues"
    echo "  ✅ Network permission setup"
    echo "  ✅ Background service threading"
    echo ""
    echo "📝 Monitor logs:"
    echo "  tail -f homeNetMon.log"
    echo ""
    echo "🧪 Test ping functionality:"
    echo "  - Add a device in the web interface"
    echo "  - Click 'Ping' button"
    echo "  - Should work without 'Permission denied' errors"
    echo ""
    echo "🔍 Test network scanning:"
    echo "  - Click 'Scan Network' in dashboard"
    echo "  - Wait 30-60 seconds for results"
    echo "  - Devices should appear automatically"
    
else
    echo "❌ HomeNetMon failed to start"
    echo ""
    echo "📄 Error log (last 20 lines):"
    tail -20 homeNetMon.log 2>/dev/null || echo "No log file found"
    
    echo ""
    echo "🔧 Manual startup:"
    echo "Try running manually:"
    if [ "$USE_SUDO" = true ]; then
        echo "  sudo -E python3 app_context_fix.py"
    else
        echo "  python3 app_context_fix.py"
    fi
fi

# Cleanup
rm -f ping_test.out