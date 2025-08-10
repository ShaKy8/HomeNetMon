import os
import threading
import time
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from config import Config
from models import db, init_db

def create_app():
    print("DEBUG: create_app() called")
    app = Flask(__name__)
    app.config.from_object(Config)
    print("DEBUG: Flask app created")
    
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
        try:
            print("DEBUG: start_monitoring_services() called")
            time.sleep(3)  # Give Flask time to fully initialize
            print("DEBUG: About to enter app context")
            
            with app.app_context():
                print("DEBUG: Inside app context")
                # Import monitoring classes with app context
                from monitoring.scanner import NetworkScanner
                from monitoring.monitor import DeviceMonitor
                from monitoring.alerts import AlertManager
                
                # Initialize with app reference
                scanner = NetworkScanner(app)
                monitor = DeviceMonitor(socketio, app)
                alert_manager = AlertManager(app)
                
                print("DEBUG: Starting scanner...")
                # Run scanner directly in this thread instead of separate threads
                def scanner_wrapper():
                    try:
                        with app.app_context():
                            scanner.start_continuous_scan()
                    except Exception as e:
                        print(f"SCANNER ERROR: {e}")
                        import traceback
                        traceback.print_exc()
                
                scanner_thread = threading.Thread(target=scanner_wrapper, daemon=True, name='NetworkScanner')
                scanner_thread.start()
                print(f"DEBUG: Scanner thread started, alive: {scanner_thread.is_alive()}")
                
                # Skip monitor and alerts for now to focus on scanner
                print("DEBUG: Services started successfully")
                
        except Exception as e:
            print(f"ERROR in start_monitoring_services: {e}")
            import traceback
            traceback.print_exc()
    
    # Start services in background
    print("DEBUG: Creating services thread")
    services_thread = threading.Thread(target=start_monitoring_services, daemon=True)
    print("DEBUG: Starting services thread")
    services_thread.start()
    print(f"DEBUG: Services thread started, alive: {services_thread.is_alive()}")
    
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
