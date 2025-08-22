import os
import threading
import time
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from config import Config
from models import db, init_db
from version import get_version_string, get_complete_info
from monitoring.scanner import NetworkScanner
from monitoring.monitor import DeviceMonitor
from monitoring.alerts import AlertManager
from monitoring.bandwidth_monitor import BandwidthMonitor

# Global variable to track server startup time
SERVER_START_TIME = datetime.now()

def create_app():
    # Setup centralized logging
    Config.setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("Starting HomeNetMon application")
    
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
    from api.notifications import notifications_bp
    from api.automation import automation_bp
    from api.config_management import config_management_bp
    from api.system import system_bp
    from api.health import health_bp
    from api.escalation import escalation_bp
    from api.performance import performance_bp
    
    app.register_blueprint(devices_bp, url_prefix='/api/devices')
    app.register_blueprint(monitoring_bp, url_prefix='/api/monitoring')
    app.register_blueprint(config_bp, url_prefix='/api/config')
    app.register_blueprint(config_management_bp, url_prefix='/api/config-management')
    app.register_blueprint(analytics_bp, url_prefix='/api/analytics')
    app.register_blueprint(speedtest_bp, url_prefix='/api/speedtest')
    app.register_blueprint(device_control_bp, url_prefix='/api/device-control')
    app.register_blueprint(anomaly_bp, url_prefix='/api/anomaly')
    app.register_blueprint(security_bp, url_prefix='/api/security')
    app.register_blueprint(notifications_bp, url_prefix='/api/notifications')
    app.register_blueprint(automation_bp, url_prefix='/api/automation')
    app.register_blueprint(system_bp, url_prefix='/api/system')
    app.register_blueprint(health_bp, url_prefix='/api/health')
    app.register_blueprint(escalation_bp, url_prefix='/api/escalation')
    app.register_blueprint(performance_bp, url_prefix='/api/performance')
    
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
    
    # Initialize rule engine service
    from services.rule_engine import rule_engine_service
    rule_engine_service.app = app
    
    # Initialize configuration service
    from services.configuration_service import configuration_service
    configuration_service.app = app
    
    # Initialize escalation service
    from services.escalation_service import escalation_service
    escalation_service.init_app(app)
    
    # Initialize performance monitor service
    from services.performance_monitor import performance_monitor
    performance_monitor.app = app
    performance_monitor.set_socketio(socketio)
    
    # Make services accessible to other parts of the app
    app._scanner = scanner
    app._monitor = monitor
    app.alert_manager = alert_manager
    app.bandwidth_monitor = bandwidth_monitor
    app.speed_test_service = speed_test_service
    app.anomaly_detection_service = anomaly_detection_service
    app.security_scanner = security_scanner
    app.rule_engine_service = rule_engine_service
    app.configuration_service = configuration_service
    app.escalation_service = escalation_service
    app.performance_monitor = performance_monitor
    app.socketio = socketio
    
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
        
        # Start rule engine service
        rule_engine_thread = threading.Thread(
            target=rule_engine_service.start_monitoring,
            daemon=True,
            name='RuleEngine'
        )
        rule_engine_thread.start()
        
        # Start configuration service
        configuration_thread = threading.Thread(
            target=configuration_service.start_monitoring,
            daemon=True,
            name='ConfigurationService'
        )
        configuration_thread.start()
        
        # Start escalation service
        escalation_thread = threading.Thread(
            target=escalation_service.start_monitoring,
            daemon=True,
            name='EscalationService'
        )
        escalation_thread.start()
        
        # Start performance monitor service
        performance_thread = threading.Thread(
            target=performance_monitor.start_monitoring,
            daemon=True,
            name='PerformanceMonitor'
        )
        performance_thread.start()
        
        # Register service callbacks for configuration changes
        def register_config_callbacks():
            time.sleep(1)  # Wait for services to initialize
            
            # Register scanner callback
            def scanner_config_callback(key, old_value, new_value):
                if key in ['network_range', 'scan_interval']:
                    scanner.reload_config()
            configuration_service.register_service_callback('NetworkScanner', scanner_config_callback)
            
            # Register monitor callback
            def monitor_config_callback(key, old_value, new_value):
                if key in ['ping_interval', 'ping_timeout', 'max_workers']:
                    monitor.reload_config()
            configuration_service.register_service_callback('DeviceMonitor', monitor_config_callback)
            
            # Register alert manager callback
            def alert_config_callback(key, old_value, new_value):
                if key.startswith('alert_'):
                    alert_manager.reload_config()
            configuration_service.register_service_callback('AlertManager', alert_config_callback)
            
            # Register bandwidth monitor callback
            def bandwidth_config_callback(key, old_value, new_value):
                if key in ['bandwidth_interval']:
                    bandwidth_monitor.reload_config()
            configuration_service.register_service_callback('BandwidthMonitor', bandwidth_config_callback)
            
            # Register performance monitor callback
            def performance_config_callback(key, old_value, new_value):
                if key in ['performance_collection_interval', 'performance_collection_period', 'performance_retention_days']:
                    performance_monitor.reload_config()
            configuration_service.register_service_callback('PerformanceMonitor', performance_config_callback)
        
        # Register callbacks in background
        callback_thread = threading.Thread(target=register_config_callbacks, daemon=True)
        callback_thread.start()
    
    # Template context processor to inject version info
    @app.context_processor
    def inject_version():
        """Make version information available in all templates"""
        from version import get_version_string, get_version_info
        return {
            'app_version': get_version_string(),
            'version_info': get_version_info()
        }
    
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
    
    @app.route('/notifications')
    def notifications():
        return render_template('notifications.html')
    
    @app.route('/notifications/analytics')
    def notification_analytics():
        """Advanced notification analytics dashboard"""
        return render_template('notification_analytics.html')
    
    @app.route('/analytics')
    def analytics():
        return render_template('analytics.html')
    
    @app.route('/performance-dashboard')
    def performance_dashboard():
        """Real-time performance monitoring dashboard"""
        return render_template('performance_dashboard.html')
    
    @app.route('/ai-dashboard')
    def ai_dashboard():
        return render_template('ai_dashboard.html')
    
    @app.route('/security-dashboard')
    def security_dashboard():
        return render_template('security_dashboard.html')
    
    @app.route('/health-overview')
    def health_overview():
        return render_template('health_overview.html')
    
    @app.route('/system-info')
    def system_info():
        return render_template('system_info.html')
    
    @app.route('/monitored-hosts')
    def monitored_hosts():
        return render_template('monitored_hosts.html')
    
    @app.route('/noc')
    def noc_view():
        """Network Operations Center - Full-screen monitoring dashboard"""
        return render_template('noc_view.html')
    
    # Redirect routes for common URL variations (underscored URLs redirect to hyphenated ones)
    @app.route('/ai_dashboard')
    def ai_dashboard_underscore_redirect():
        return redirect(url_for('ai_dashboard'))
    
    @app.route('/security_dashboard')  
    def security_dashboard_underscore_redirect():
        return redirect(url_for('security_dashboard'))
    
    @app.route('/health_overview')  
    def health_overview_underscore_redirect():
        return redirect(url_for('health_overview'))
    
    @app.route('/topology')
    def topology():
        try:
            return render_template('topology.html')
        except Exception as e:
            return f'<html><body><h1>Template Error</h1><p>{str(e)}</p></body></html>', 500
    
    @app.route('/escalation-rules')
    def escalation_rules():
        """Escalation rules management page"""
        return render_template('escalation_rules.html')
    
    @app.route('/escalation-rules/new')
    def new_escalation_rule():
        """Create new escalation rule page"""
        return render_template('escalation_rule_form.html', rule_id=None)
    
    @app.route('/escalation-rules/<int:rule_id>/edit')
    def edit_escalation_rule(rule_id):
        """Edit existing escalation rule page"""
        return render_template('escalation_rule_form.html', rule_id=rule_id)
    
    @app.route('/escalation-executions')
    def escalation_executions():
        """Escalation executions monitoring page"""
        return render_template('escalation_executions.html')
    
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
    
    # SocketIO events with room management for selective updates
    @socketio.on('connect')
    def handle_connect():
        print(f'Client connected: {request.sid}')
        # Join default room for basic updates
        join_room('general')
        emit('status', {'message': 'Connected to HomeNetMon'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        print(f'Client disconnected: {request.sid}')
    
    @socketio.on('subscribe_to_updates')
    def handle_subscription(data):
        """Allow clients to subscribe to specific types of updates"""
        try:
            update_types = data.get('types', [])
            client_sid = request.sid
            
            # Available subscription types
            available_types = [
                'device_status',      # Device status updates
                'monitoring_summary', # Overall monitoring summaries
                'alerts',            # Alert notifications
                'chart_data',        # Chart and graph data
                'performance',       # Performance metrics
                'configuration'      # Configuration changes
            ]
            
            # Join rooms for requested update types
            joined_rooms = []
            for update_type in update_types:
                if update_type in available_types:
                    join_room(f'updates_{update_type}')
                    joined_rooms.append(update_type)
            
            emit('subscription_confirmed', {
                'subscribed_to': joined_rooms,
                'available_types': available_types
            })
            
            logger.info(f"Client {client_sid} subscribed to: {joined_rooms}")
            
        except Exception as e:
            logger.error(f"Error handling subscription: {e}")
            emit('subscription_error', {'error': str(e)})
    
    @socketio.on('unsubscribe_from_updates')
    def handle_unsubscription(data):
        """Allow clients to unsubscribe from specific types of updates"""
        try:
            update_types = data.get('types', [])
            client_sid = request.sid
            
            # Leave rooms for requested update types
            left_rooms = []
            for update_type in update_types:
                leave_room(f'updates_{update_type}')
                left_rooms.append(update_type)
            
            emit('unsubscription_confirmed', {
                'unsubscribed_from': left_rooms
            })
            
            logger.info(f"Client {client_sid} unsubscribed from: {left_rooms}")
            
        except Exception as e:
            logger.error(f"Error handling unsubscription: {e}")
            emit('unsubscription_error', {'error': str(e)})
    
    @socketio.on('request_device_update')
    def handle_device_update_request():
        from models import Device
        devices = Device.query.all()
        devices_data = [device.to_dict() for device in devices]
        emit('device_update', devices_data)
    
    @socketio.on('request_config_update')
    def handle_config_update_request():
        """Handle request for current configuration"""
        try:
            from models import Configuration
            configs = Configuration.query.all()
            config_data = {config.key: {
                'value': config.value,
                'description': config.description,
                'version': config.version,
                'updated_at': config.updated_at.isoformat()
            } for config in configs}
            emit('configuration_full_update', config_data)
        except Exception as e:
            emit('configuration_error', {'error': str(e)})
    
    @socketio.on('update_configuration')
    def handle_configuration_update(data):
        """Handle configuration update via WebSocket"""
        try:
            key = data.get('key')
            value = data.get('value')
            description = data.get('description')
            user = data.get('user', 'websocket_user')
            
            if not key or value is None:
                emit('configuration_error', {'error': 'Key and value are required'})
                return
            
            # Use configuration service to update
            success, message = configuration_service.set_configuration(
                key=key,
                value=value,
                description=description,
                user=user,
                validate=True
            )
            
            if success:
                emit('configuration_update_success', {
                    'key': key,
                    'value': value,
                    'message': message
                })
                # Broadcast to all clients
                socketio.emit('configuration_updated', {
                    'key': key,
                    'value': value,
                    'user': user,
                    'timestamp': datetime.utcnow().isoformat()
                })
            else:
                emit('configuration_error', {'error': message})
                
        except Exception as e:
            emit('configuration_error', {'error': str(e)})
    
    @socketio.on('request_health_update')
    def handle_health_update_request():
        """Handle request for health overview update"""
        try:
            from api.health import calculate_health_score, get_recent_network_activity
            from models import Device, MonitoringData, Alert
            from datetime import timedelta
            
            # Get current health data
            now = datetime.utcnow()
            online_threshold = now - timedelta(minutes=10)
            
            total_devices = Device.query.filter_by(is_monitored=True).count()
            devices_online = Device.query.filter(
                Device.is_monitored == True,
                Device.last_seen >= online_threshold
            ).count()
            
            # Quick health score calculation
            health_score = calculate_health_score(
                devices_online, total_devices, 50.0, 0, 95.0  # Simplified for real-time
            )
            
            emit('health_update', {
                'health_score': health_score,
                'network_status': {
                    'devices_online': devices_online,
                    'devices_offline': total_devices - devices_online,
                    'total_devices': total_devices
                },
                'timestamp': now.isoformat() + 'Z'
            })
            
        except Exception as e:
            emit('health_error', {'error': str(e)})
    
    @socketio.on('request_topology_update')
    def handle_topology_update_request():
        """Handle request for network topology update"""
        try:
            from models import Device
            
            devices = Device.query.filter_by(is_monitored=True).all()
            online_threshold = datetime.utcnow() - timedelta(minutes=10)
            
            topology_data = []
            for device in devices:
                status = 'online' if device.last_seen and device.last_seen >= online_threshold else 'offline'
                topology_data.append({
                    'id': device.id,
                    'ip_address': device.ip_address,
                    'name': device.display_name,
                    'type': device.device_type or 'unknown',
                    'status': status
                })
            
            emit('topology_update', {
                'devices': topology_data,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
            
        except Exception as e:
            emit('topology_error', {'error': str(e)})
    
    @socketio.on('request_alert_updates')
    def handle_alert_updates_request():
        """Handle request for real-time alert updates"""
        try:
            from models import Alert
            
            # Get active alerts summary
            active_alerts = Alert.query.filter_by(resolved=False).all()
            
            alert_data = []
            for alert in active_alerts:
                alert_data.append({
                    'id': alert.id,
                    'device_id': alert.device_id,
                    'device_name': alert.device.display_name,
                    'device_ip': alert.device.ip_address,
                    'alert_type': alert.alert_type,
                    'severity': alert.severity,
                    'message': alert.message,
                    'created_at': alert.created_at.isoformat() + 'Z',
                    'acknowledged': alert.acknowledged,
                    'resolved': alert.resolved
                })
            
            emit('alert_updates', {
                'alerts': alert_data,
                'count': len(alert_data),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
            
        except Exception as e:
            emit('alert_error', {'error': str(e)})
    
    @socketio.on('request_chart_data')
    def handle_chart_data_request(data):
        """Handle request for specific chart data"""
        try:
            chart_type = data.get('type')
            device_id = data.get('device_id')
            time_range = data.get('time_range', '24h')
            
            if chart_type == 'device_response_time' and device_id:
                # Get recent response time data for a specific device
                from models import MonitoringData
                from datetime import timedelta
                
                hours_map = {'1h': 1, '6h': 6, '24h': 24, '7d': 168}
                hours = hours_map.get(time_range, 24)
                cutoff = datetime.utcnow() - timedelta(hours=hours)
                
                data_points = MonitoringData.query.filter(
                    MonitoringData.device_id == device_id,
                    MonitoringData.timestamp >= cutoff
                ).order_by(MonitoringData.timestamp.desc()).limit(200).all()
                
                chart_data = [{
                    'timestamp': point.timestamp.isoformat(),
                    'response_time': point.response_time,
                    'device_id': point.device_id
                } for point in reversed(data_points)]
                
                emit('chart_data_response', {
                    'type': chart_type,
                    'device_id': device_id,
                    'data': chart_data,
                    'timestamp': datetime.utcnow().isoformat()
                })
            
            elif chart_type == 'device_types':
                # Get device types breakdown
                from models import Device
                from collections import defaultdict
                
                devices = Device.query.filter_by(is_monitored=True).all()
                device_types = defaultdict(lambda: {'up': 0, 'down': 0})
                
                online_threshold = datetime.utcnow() - timedelta(minutes=10)
                
                for device in devices:
                    device_type = device.device_type or 'unknown'
                    if device.last_seen and device.last_seen >= online_threshold:
                        device_types[device_type]['up'] += 1
                    else:
                        device_types[device_type]['down'] += 1
                
                chart_data = []
                for device_type, counts in device_types.items():
                    total = counts['up'] + counts['down']
                    if total > 0:
                        chart_data.append({
                            'type': device_type,
                            'total': total,
                            'up': counts['up'],
                            'down': counts['down'],
                            'uptime_percentage': (counts['up'] / total) * 100
                        })
                
                emit('chart_data_response', {
                    'type': chart_type,
                    'data': chart_data,
                    'timestamp': datetime.utcnow().isoformat()
                })
            
        except Exception as e:
            emit('chart_data_error', {'error': str(e), 'type': chart_type})
    
    @socketio.on('request_performance_summary')
    def handle_performance_summary_request():
        """Handle request for performance summary"""
        try:
            summary = performance_monitor.get_network_performance_summary(24)
            if summary:
                emit('performance_summary_response', summary)
            else:
                emit('performance_error', {'error': 'Unable to generate performance summary'})
        except Exception as e:
            emit('performance_error', {'error': str(e)})
    
    @socketio.on('request_device_performance')
    def handle_device_performance_request(data):
        """Handle request for device performance data"""
        try:
            device_id = data.get('device_id')
            hours = data.get('hours', 24)
            
            if not device_id:
                emit('performance_error', {'error': 'Device ID required'})
                return
            
            from models import Device
            device = Device.query.get(device_id)
            if not device:
                emit('performance_error', {'error': 'Device not found'})
                return
            
            performance_summary = device.get_performance_summary(hours)
            emit('device_performance_response', {
                'device_id': device_id,
                'performance_summary': performance_summary,
                'timestamp': datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            emit('performance_error', {'error': str(e)})
    
    @socketio.on('trigger_performance_collection')
    def handle_performance_collection_trigger(data):
        """Handle manual performance collection trigger"""
        try:
            device_id = data.get('device_id') if data else None
            
            if device_id:
                # Collect for specific device
                result = performance_monitor.collect_device_performance_metrics(device_id)
                if result:
                    emit('performance_collection_success', {
                        'message': f'Performance metrics collected for device {device_id}',
                        'device_id': device_id,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                else:
                    emit('performance_collection_error', {
                        'error': 'Failed to collect device performance metrics'
                    })
            else:
                # Collect for all devices
                performance_monitor.collect_all_devices_performance()
                emit('performance_collection_success', {
                    'message': 'Performance metrics collection triggered for all devices',
                    'timestamp': datetime.utcnow().isoformat()
                })
                
        except Exception as e:
            emit('performance_collection_error', {'error': str(e)})
    
    def emit_alert_update(alert, action='created'):
        """Emit real-time alert update to all connected clients"""
        try:
            alert_data = {
                'id': alert.id,
                'device_id': alert.device_id,
                'device_name': alert.device.display_name,
                'device_ip': alert.device.ip_address,
                'alert_type': alert.alert_type,
                'severity': alert.severity,
                'message': alert.message,
                'created_at': alert.created_at.isoformat() + 'Z',
                'acknowledged': alert.acknowledged,
                'resolved': alert.resolved,
                'action': action  # 'created', 'updated', 'resolved', 'acknowledged', 'deleted'
            }
            
            socketio.emit('alert_update', {
                'type': 'alert_update',
                'alert': alert_data,
                'action': action,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
            
        except Exception as e:
            logger.error(f"Error emitting alert update: {e}")
    
    # Store the emit function in app context for use by alert manager
    app.emit_alert_update = emit_alert_update
    
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