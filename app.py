import os
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit
from config import Config
from models import db, init_db
from monitoring.scanner import NetworkScanner
from monitoring.monitor import DeviceMonitor
from monitoring.alerts import AlertManager
from monitoring.bandwidth_monitor import BandwidthMonitor

# Global variable to track server startup time
SERVER_START_TIME = datetime.now()

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
    from api.analytics import analytics_bp
    from api.speedtest import speedtest_bp
    from api.device_control import device_control_bp
    from api.anomaly import anomaly_bp
    from api.security import security_bp
    
    app.register_blueprint(devices_bp, url_prefix='/api/devices')
    app.register_blueprint(monitoring_bp, url_prefix='/api/monitoring')
    app.register_blueprint(config_bp, url_prefix='/api/config')
    app.register_blueprint(analytics_bp, url_prefix='/api/analytics')
    app.register_blueprint(speedtest_bp, url_prefix='/api/speedtest')
    app.register_blueprint(device_control_bp, url_prefix='/api/device-control')
    app.register_blueprint(anomaly_bp, url_prefix='/api/anomaly')
    app.register_blueprint(security_bp, url_prefix='/api/security')
    
    # Initialize monitoring services
    scanner = NetworkScanner(app)
    monitor = DeviceMonitor(socketio, app)
    alert_manager = AlertManager(app)
    bandwidth_monitor = BandwidthMonitor(app)
    
    # Initialize speed test service
    from services.speedtest import speed_test_service
    speed_test_service.app = app
    
    # Initialize anomaly detection service
    from services.anomaly_detection import anomaly_detection_service
    anomaly_detection_service.app = app
    
    # Initialize security scanner service
    from services.security_scanner import security_scanner
    security_scanner.app = app
    
    # Make services accessible to other parts of the app
    app._scanner = scanner
    app.alert_manager = alert_manager
    app.bandwidth_monitor = bandwidth_monitor
    app.speed_test_service = speed_test_service
    app.anomaly_detection_service = anomaly_detection_service
    app.security_scanner = security_scanner
    
    # Start background services in separate threads
    def start_monitoring_services():
        time.sleep(2)  # Give Flask time to fully initialize
        
        # Start network scanner
        scanner_thread = threading.Thread(
            target=scanner.start_continuous_scan,
            daemon=True,
            name='NetworkScanner'
        )
        scanner_thread.start()
        
        # Start device monitor
        monitor_thread = threading.Thread(
            target=monitor.start_monitoring,
            daemon=True,
            name='DeviceMonitor'
        )
        monitor_thread.start()
        
        # Start alert manager
        alert_thread = threading.Thread(
            target=alert_manager.start_monitoring,
            daemon=True,
            name='AlertManager'
        )
        alert_thread.start()
        
        # Start anomaly detection service
        anomaly_thread = threading.Thread(
            target=anomaly_detection_service.start_monitoring,
            daemon=True,
            name='AnomalyDetection'
        )
        anomaly_thread.start()
        
        # Start security scanner service
        security_thread = threading.Thread(
            target=security_scanner.start_monitoring,
            daemon=True,
            name='SecurityScanner'
        )
        security_thread.start()
        
        # Start bandwidth monitor
        bandwidth_thread = threading.Thread(
            target=bandwidth_monitor.start_monitoring,
            daemon=True,
            name='BandwidthMonitor'
        )
        bandwidth_thread.start()
    
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
    
    @app.route('/analytics')
    def analytics():
        return render_template('analytics.html')
    
    @app.route('/ai-dashboard')
    def ai_dashboard():
        return render_template('ai_dashboard.html')
    
    @app.route('/security-dashboard')
    def security_dashboard():
        return render_template('security_dashboard.html')
    
    # Redirect routes for common URL variations (underscored URLs redirect to hyphenated ones)
    @app.route('/ai_dashboard')
    def ai_dashboard_underscore_redirect():
        return redirect(url_for('ai_dashboard'))
    
    @app.route('/security_dashboard')  
    def security_dashboard_underscore_redirect():
        return redirect(url_for('security_dashboard'))
    
    @app.route('/topology')
    def topology():
        try:
            return render_template('topology.html')
        except Exception as e:
            return f'<html><body><h1>Template Error</h1><p>{str(e)}</p></body></html>', 500
    
    @app.route('/test')
    def test():
        return jsonify({'message': 'Flask is working'})
    
    @app.route('/debug/routes')
    def list_routes():
        routes = []
        for rule in app.url_map.iter_rules():
            routes.append({
                'endpoint': rule.endpoint,
                'methods': list(rule.methods),
                'rule': rule.rule
            })
        return jsonify({'count': len(routes), 'routes': routes})
    
    @app.route('/simple-test')
    def simple_test():
        return redirect('/ai-dashboard')
    
    @app.route('/traceroute-test')
    def traceroute_test():
        from services.device_control import DeviceControlService
        service = DeviceControlService()
        result = service.traceroute_to_device('8.8.8.8')
        return jsonify({
            'hop_count': result.get('hop_count', 0),
            'hops_length': len(result.get('hops', [])),
            'success': result.get('success', False),
            'first_hop': result.get('hops', [{}])[0] if result.get('hops') else None
        })
    
    @app.route('/static/service-worker.js')
    def service_worker():
        return app.send_static_file('service-worker.js'), 200, {'Content-Type': 'application/javascript'}
    
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
                'database': 'connected',
                'started_at': SERVER_START_TIME.isoformat(),
                'uptime_seconds': int((datetime.now() - SERVER_START_TIME).total_seconds()),
                'services': {
                    'scanner': scanner.is_running if hasattr(scanner, 'is_running') else 'unknown',
                    'monitor': monitor.is_running if hasattr(monitor, 'is_running') else 'unknown',
                    'alerts': alert_manager.is_running if hasattr(alert_manager, 'is_running') else 'unknown'
                }
            })
        except Exception as e:
            return jsonify({
                'status': 'unhealthy',
                'error': str(e)
            }), 500
    
    # Network topology endpoint
    @app.route('/api/monitoring/topology-test')
    def get_topology_test():
        """Network topology data for graph visualization"""
        from models import Device, MonitoringData, Alert
        try:
            devices = Device.query.filter_by(is_monitored=True).limit(10).all()
            
            nodes = []
            for i, device in enumerate(devices):
                color_map = {'up': '#28a745', 'down': '#dc3545', 'warning': '#ffc107', 'unknown': '#6c757d'}
                icon_map = {'router': '🌐', 'computer': '💻', 'phone': '📱', 'camera': '📷', 'smart_home': '🏠', 'unknown': '❓'}
                
                # Get latest response time directly to avoid property caching issues
                latest_data = MonitoringData.query.filter_by(device_id=device.id)\
                                                 .order_by(MonitoringData.timestamp.desc())\
                                                 .first()
                latest_response_time = latest_data.response_time if latest_data else None
                
                # Get active alerts count  
                active_alerts = Alert.query.filter_by(device_id=device.id, resolved=False).count()
                
                nodes.append({
                    'id': str(device.id),
                    'label': device.display_name[:15],
                    'ip': device.ip_address,
                    'status': device.status,
                    'color': color_map.get(device.status, '#6c757d'),
                    'icon': icon_map.get(device.device_type, '❓'),
                    'device_type': device.device_type,
                    'response_time': latest_response_time,
                    'uptime_percentage': device.uptime_percentage or 0,
                    'active_alerts': active_alerts,
                    'size': 20 + (device.uptime_percentage or 0) / 5
                })
            
            # Create simple hub topology
            edges = []
            if nodes:
                hub_id = nodes[0]['id']  # Use first device as hub
                for node in nodes[1:]:
                    edges.append({
                        'source': hub_id,
                        'target': node['id'],
                        'strength': 1.0,
                        'color': '#28a745' if node['status'] == 'up' else '#dc3545'
                    })
            
            return jsonify({
                'nodes': nodes,
                'edges': edges,
                'stats': {'total_devices': len(nodes), 'subnets': 1, 'connections': len(edges)},
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
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