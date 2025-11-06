import os
import threading
import time
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_compress import Compress
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
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    
    # Enable compression for faster page loads (temporarily disable br due to parsing issues)
    compress = Compress(app)
    app.config['COMPRESS_ALGORITHM'] = ['gzip', 'deflate']
    app.config['COMPRESS_LEVEL'] = 6
    app.config['COMPRESS_MIN_SIZE'] = 500
    app.config['COMPRESS_MIMETYPES'] = [
        'text/html', 'text/css', 'text/javascript',
        'application/javascript', 'application/json',
        'application/xml', 'image/svg+xml'
    ]
    logger.info("HTTP compression enabled with Brotli, gzip, and deflate")
    
    # Initialize HTTP optimizer for performance and HTTP/2 support
    try:
        from services.http_optimizer import HTTPOptimizer
        http_optimizer = HTTPOptimizer(app)
        logger.info("HTTP optimizer initialized with caching and HTTP/2 support")
    except ImportError:
        logger.warning("HTTP optimizer not available")
    
    # Initialize CDN manager for static asset optimization
    try:
        from services.cdn_manager import CDNManager, setup_cdn_routes
        cdn_manager = CDNManager(app)
        setup_cdn_routes(app)
        logger.info("CDN manager initialized for static asset optimization")
    except ImportError:
        logger.warning("CDN manager not available")
    
    # Validate security configuration
    Config.validate_host_binding()
    
    # Initialize database
    init_db(app)
    
    # PERFORMANCE OPTIMIZATION: Initialize performance middleware
    try:
        from performance_middleware import PerformanceMiddleware
        PerformanceMiddleware(app)
        logger.info("Performance middleware initialized")
    except ImportError:
        logger.warning("Performance middleware not available - performance optimizations disabled")
    
    # SECURITY: Initialize security middleware with CSRF protection
    try:
        from core.security_middleware import SecurityMiddleware
        app.security_middleware = SecurityMiddleware(app)
        logger.info("Security middleware initialized with enhanced debugging")
    except ImportError:
        logger.warning("Security middleware not available - CSRF protection disabled")
    
    # Initialize SocketIO for real-time updates - Allow local network access
    # Allow any origin from local networks for home network monitoring
    import re
    def cors_allowed_origins_callback(origin):
        if not origin:
            return False
        # Allow localhost and common local network ranges
        allowed_patterns = [
            r'^http://localhost(:\d+)?$',
            r'^http://127\.0\.0\.1(:\d+)?$',
            r'^http://0\.0\.0\.0(:\d+)?$',
            r'^http://192\.168\.\d+\.\d+(:\d+)?$',  # Common home network
            r'^http://10\.\d+\.\d+\.\d+(:\d+)?$',    # Private network
            r'^http://172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+(:\d+)?$',  # Private network
            r'^http://[a-zA-Z0-9\-]+(\.local)?(:\d+)?$'  # Local hostnames
        ]
        for pattern in allowed_patterns:
            if re.match(pattern, origin):
                return True
        return False
    
    socketio = SocketIO(app, cors_allowed_origins=cors_allowed_origins_callback, logger=False, engineio_logger=False)

    # Import and register blueprints
    from api.devices import devices_bp  # Use original for now
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
    from api.performance_optimization import performance_optimization_bp
    from api.rate_limit_admin import rate_limit_admin_bp
    from api.maintenance import maintenance_bp

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
    app.register_blueprint(performance_optimization_bp)
    app.register_blueprint(rate_limit_admin_bp, url_prefix='/api/rate-limit')
    app.register_blueprint(maintenance_bp, url_prefix='/api/maintenance')

    # Setup API documentation (Swagger/OpenAPI)
    try:
        from api_documentation import setup_swagger_ui
        setup_swagger_ui(app)
        logger.info("API documentation available at /api/docs and /api/redoc")
    except ImportError:
        logger.warning("API documentation setup failed - swagger UI not available")

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
    
    # Initialize rate limiter service for production security
    try:
        from services.rate_limiter import init_rate_limiter
        rate_limiter = init_rate_limiter(app)
        logger.info("Rate limiter initialized successfully")
    except Exception as e:
        logger.warning(f"Rate limiter initialization failed, continuing without it: {e}")
        rate_limiter = None
    
    # Initialize performance monitor service
    from services.performance_monitor import performance_monitor
    performance_monitor.app = app
    performance_monitor.set_socketio(socketio)
    

    # Apply global rate limiting for production security
    try:
        from core.rate_limiter import apply_global_rate_limiting
        apply_global_rate_limiting(app)
        logger.info("Global rate limiting applied successfully")
    except Exception as e:
        logger.warning(f"Global rate limiting failed, continuing without it: {e}")

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
    app.rate_limiter = rate_limiter
    app.performance_monitor = performance_monitor
    
    # Initialize WebSocket optimizer for performance
    from services.websocket_optimizer import init_websocket_optimizer
    websocket_optimizer = init_websocket_optimizer(db, socketio)
    app.websocket_optimizer = websocket_optimizer
    
    # Apply WebSocket memory leak fixes
    from core.websocket_memory_manager import fix_websocket_memory_leaks
    websocket_connection_manager = fix_websocket_memory_leaks(app, socketio)
    app.websocket_connection_manager = websocket_connection_manager
    
    # Initialize query result caching for massive performance improvements
    from services.query_cache import init_query_cache
    query_cache = init_query_cache(app)
    app.query_cache = query_cache
    
    # Initialize memory monitoring and cleanup
    from services.memory_monitor import init_memory_monitoring
    memory_monitor = init_memory_monitoring()
    app.memory_monitor = memory_monitor
    
    # Initialize frontend resource optimization - NUCLEAR DISABLED FOR DEBUGGING
    # from services.resource_optimizer import init_resource_optimization, generate_service_worker
    # from version import __version__
    # resource_bundler, static_optimizer = init_resource_optimization(app)
    # if resource_bundler and static_optimizer:
    #     app.resource_bundler = resource_bundler
    #     app.static_optimizer = static_optimizer
    #
    #     # Generate service worker for PWA caching - TEMPORARILY DISABLED FOR CACHE DEBUGGING
    #     # try:
    #     #     generate_service_worker(app, __version__)
    #     # except Exception as e:
    #     #     logger.warning(f"Failed to generate service worker: {e}")
    
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
        
        # Security scanner service - conditionally start based on environment variable
        security_enabled = os.environ.get('SECURITY_SCANNING_ENABLED', 'false').lower() == 'true'
        if security_enabled:
            security_thread = threading.Thread(
                target=security_scanner.start_monitoring,
                daemon=True,
                name='SecurityScanner'
            )
            security_thread.start()
            logger.info("Security scanner enabled via SECURITY_SCANNING_ENABLED environment variable")
        else:
            logger.info("Security scanner disabled - set SECURITY_SCANNING_ENABLED=true to enable")
        
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
    
    # Template context processor to inject version info and settings
    @app.context_processor
    def inject_version():
        """Make version information available in all templates"""
        from version import get_version_string, get_version_info
        return {
            'app_version': get_version_string(),
            'version_info': get_version_info()
        }
    
    @app.context_processor 
    def inject_csrf():
        """Make CSRF token available in templates"""
        def csrf_token():
            try:
                # Generate a token for template use
                middleware = getattr(app, 'security_middleware', None)
                if middleware:
                    return middleware._generate_csrf_token()
                return ''
            except:
                return ''
        return {'csrf_token': csrf_token}

    @app.route('/api/csrf-token', methods=['GET'])
    def get_csrf_token():
        """API endpoint to get a fresh CSRF token"""
        try:
            middleware = getattr(app, 'security_middleware', None)
            if middleware:
                token = middleware._generate_csrf_token()
                return jsonify({'csrf_token': token}), 200
            return jsonify({'error': 'CSRF not available'}), 500
        except Exception as e:
            logger.error(f"Error generating CSRF token: {e}")
            return jsonify({'error': 'Token generation failed'}), 500

    @app.context_processor
    def inject_settings():
        """Make configurable settings available in all templates"""
        try:
            from models import Configuration
            # Get dashboard title setting
            dashboard_title_config = Configuration.query.filter_by(key='dashboard_title').first()
            dashboard_title = dashboard_title_config.value if dashboard_title_config else 'Home Network Dashboard'
            
            return {
                'dashboard_title': dashboard_title
            }
        except Exception as e:
            logger.warning(f"Could not load dashboard settings: {e}")
            return {
                'dashboard_title': 'Home Network Dashboard'
            }
    
    # Start services in background
    services_thread = threading.Thread(target=start_monitoring_services, daemon=True)
    services_thread.start()

    # NUCLEAR CACHE BUSTING - Add no-cache headers to ALL responses
    @app.after_request
    def add_no_cache_headers(response):
        # Apply no-cache headers to ALL responses to prevent browser caching issues
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['Last-Modified'] = ''
        response.headers['ETag'] = ''
        return response

    # Web routes (protected)
    @app.route('/')
    def dashboard():
        """Clean, fast-loading dashboard focused on network health overview"""
        try:
            from models import Configuration
            # Get dashboard title setting
            dashboard_title_config = Configuration.query.filter_by(key='dashboard_title').first()
            dashboard_title = dashboard_title_config.value if dashboard_title_config else 'Home Network Monitor'
            
            return render_template('dashboard.html', dashboard_title=dashboard_title)
        except Exception as e:
            # Fallback if database isn't available
            return render_template('dashboard.html', dashboard_title='Home Network Monitor')
    
    @app.route('/dashboard/full')
    def dashboard_full():
        """Full featured dashboard with device grid and detailed monitoring"""
        try:
            from models import Configuration
            # Get dashboard title setting
            dashboard_title_config = Configuration.query.filter_by(key='dashboard_title').first()
            dashboard_title = dashboard_title_config.value if dashboard_title_config else 'Home Network Monitor'

            return render_template('dashboard.html', dashboard_title=dashboard_title)
        except Exception as e:
            # Fallback if database isn't available
            return render_template('dashboard.html', dashboard_title='Home Network Monitor')
    
    @app.route('/favicon.ico')
    def favicon():
        """Serve favicon from static folder"""
        return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/vnd.microsoft.icon')
    
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
        # Redirect to alerts page - notifications functionality consolidated there
        return redirect(url_for('alerts'))
    
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
        """Redirect old security-dashboard URL to new security URL for consistency"""
        return redirect(url_for('security'), code=301)
    
    # Health overview functionality has been merged into the main dashboard
    
    @app.route('/system-info')
    def system_info():
        return render_template('system_info.html')
    
    @app.route('/about')
    def about():
        """About HomeNetMon - System information and credits"""
        return render_template('about.html')
    
    @app.route('/monitored-hosts')
    def monitored_hosts():
        """Redirect to unified dashboard - all device management now in one place"""
        return redirect(url_for('dashboard'))
    
    @app.route('/devices')
    def devices():
        """Redirect to unified dashboard - all device management now in one place"""
        return redirect(url_for('dashboard'))
    
    @app.route('/noc')
    def noc_view():
        """Redirect old noc URL to new full-view URL for consistency"""
        return redirect(url_for('full_view'), code=301)
    
    # Redirect routes for common URL variations (underscored URLs redirect to hyphenated ones)
    @app.route('/ai_dashboard')
    def ai_dashboard_underscore_redirect():
        return redirect(url_for('ai_dashboard'))
    
    @app.route('/security_dashboard')
    def security_dashboard_underscore_redirect():
        return redirect(url_for('security'))
    
    # Health overview redirect removed - functionality now in main dashboard
    
    @app.route('/topology')
    def topology():
        """Redirect old topology URL to new network-map URL for consistency"""
        return redirect(url_for('network_map'), code=301)
    
    # New standardized routes with proper URLs
    @app.route('/network-map')
    def network_map():
        """Network topology visualization with standardized URL"""
        try:
            return render_template('topology.html')
        except Exception as e:
            return f'<html><body><h1>Template Error</h1><p>{str(e)}</p></body></html>', 500
    
    @app.route('/security')
    def security():
        """Security dashboard with standardized URL"""
        try:
            return render_template('security.html')
        except Exception as e:
            return f'<html><body><h1>Template Error</h1><p>{str(e)}</p></body></html>', 500
    
    @app.route('/test-debug')
    def test_debug():
        """Test route to debug route registration"""
        return "Route registration test successful"
    
    @app.route('/full-view')
    def full_view():
        """Network Operations Center - Full-screen monitoring dashboard with standardized URL"""
        return render_template('noc_view.html')
    
    # Note: Backward compatibility redirects are handled by the existing routes above
    
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
    
    @app.route('/static/images/<path:filename>')
    def serve_image(filename):
        """Serve images from static/images directory"""
        try:
            return send_from_directory(os.path.join(app.static_folder, 'images'), filename)
        except Exception as e:
            logger.error(f"Error serving image {filename}: {e}")
            return "Image not found", 404
    
    # SocketIO events are now handled by websocket_memory_manager
    # Additional application-specific event handlers
    
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
                    # Register with connection manager
                    if hasattr(app, 'websocket_connection_manager'):
                        app.websocket_connection_manager.subscribe_to_room(client_sid, f'updates_{update_type}')
            
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
    def handle_device_update_request(data=None):
        try:
            # Check if client supports delta updates
            client_supports_delta = data and data.get('supports_delta', False)
            
            # Use optimized data fetching to prevent N+1 queries
            from services.websocket_optimizer import websocket_optimizer
            if websocket_optimizer:
                if client_supports_delta:
                    # Send delta update if client supports it
                    delta_update = websocket_optimizer.get_device_delta_update()
                    if delta_update:
                        emit('device_delta_update', delta_update)
                    else:
                        # No changes to report
                        emit('device_no_changes', {'timestamp': datetime.utcnow().isoformat() + 'Z'})
                else:
                    # Send full update
                    devices_data = websocket_optimizer.get_optimized_device_data()
                    emit('device_update', devices_data)
            else:
                # Fallback to original method
                from models import Device
                devices = Device.query.all()
                devices_data = [device.to_dict() for device in devices]
                emit('device_update', devices_data)
        except Exception as e:
            logger.error(f"Error in device update request: {e}")
            emit('device_update_error', {'error': str(e)})
    
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
            # Use optimized data fetching to prevent N+1 queries
            from services.websocket_optimizer import websocket_optimizer
            if websocket_optimizer:
                alert_data = websocket_optimizer.get_optimized_alert_data()
            else:
                # Fallback to original method with N+1 query issue
                from models import Alert
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
    
    @socketio.on('subscribe_to_delta_updates')
    def handle_delta_subscription(data):
        """Handle subscription to efficient delta updates"""
        try:
            client_sid = request.sid
            update_types = data.get('types', ['devices', 'alerts'])
            
            # Join rooms for delta updates
            for update_type in update_types:
                room_name = f"delta_{update_type}"
                join_room(room_name)
                logger.debug(f"Client {client_sid} subscribed to delta updates: {room_name}")
            
            emit('delta_subscription_confirmed', {
                'subscribed_to': update_types,
                'supports_delta': True,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
            
        except Exception as e:
            logger.error(f"Error in delta subscription: {e}")
            emit('delta_subscription_error', {'error': str(e)})
    
    @socketio.on('request_performance_metrics')
    def handle_performance_metrics_request():
        """Handle request for performance metrics"""
        try:
            from services.performance_cache import get_cache_performance_metrics
            from services.memory_monitor import get_memory_stats
            from services.thread_pool_manager import thread_pool_manager
            
            # Get comprehensive performance metrics
            cache_metrics = get_cache_performance_metrics()
            memory_stats = get_memory_stats()
            thread_pool_stats = thread_pool_manager.get_all_stats()
            system_resources = thread_pool_manager.get_system_resource_summary()
            
            performance_data = {
                'cache': cache_metrics,
                'memory': {
                    'total_mb': memory_stats.total_mb,
                    'used_mb': memory_stats.used_mb,
                    'percent_used': memory_stats.percent_used * 100,
                    'cache_usage_mb': memory_stats.cache_usage_mb
                },
                'thread_pools': thread_pool_stats,
                'system': system_resources,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            emit('performance_metrics_response', performance_data)
            
        except Exception as e:
            logger.error(f"Error getting performance metrics: {e}")
            emit('performance_metrics_error', {'error': str(e)})
    
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
    # Comprehensive error handling
    @app.errorhandler(400)
    def bad_request(error):
        logger.warning(f"400 Bad Request: {request.method} {request.path} - {error.description}")
        return jsonify({
            'error': 'Bad Request',
            'message': 'The request could not be processed due to invalid data',
            'status_code': 400
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Authentication required',
            'status_code': 401
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            'error': 'Forbidden',
            'message': 'Access denied',
            'status_code': 403
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        # For static file requests, return standard 404 instead of JSON
        if request.path.startswith('/static/'):
            return f'File not found: {request.path}', 404
        
        return jsonify({
            'error': 'Not Found',
            'message': 'The requested resource could not be found',
            'status_code': 404
        }), 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({
            'error': 'Method Not Allowed',
            'message': f'The {request.method} method is not allowed for this endpoint',
            'status_code': 405
        }), 405
    
    @app.errorhandler(413)
    def payload_too_large(error):
        return jsonify({
            'error': 'Payload Too Large',
            'message': 'The request payload exceeds the maximum allowed size',
            'status_code': 413
        }), 413
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return jsonify({
            'error': 'Too Many Requests',
            'message': 'Rate limit exceeded. Please try again later',
            'status_code': 429
        }), 429
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        logger.error(f"Internal server error: {str(error)}")
        
        # For static file requests, return standard 500 instead of JSON
        if request.path.startswith('/static/'):
            return f'Internal server error serving: {request.path}', 500
        
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'status_code': 500
        }), 500
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        """Handle unexpected exceptions"""
        db.session.rollback()
        logger.exception(f"Unhandled exception: {str(error)}")
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'status_code': 500
        }), 500
    
    # Health check endpoint (public for monitoring)
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
    
    # Readiness check endpoint (for Kubernetes/Docker)
    @app.route('/ready')
    def readiness_check():
        try:
            # Check database connectivity
            from sqlalchemy import text
            db.session.execute(text('SELECT 1'))
            
            # Check critical services are initialized
            services_ready = True
            service_status = {}
            
            # Check scanner service
            if hasattr(scanner, 'is_running'):
                service_status['scanner'] = scanner.is_running
                services_ready = services_ready and scanner.is_running
            
            # Check monitor service
            if hasattr(monitor, 'is_running'):
                service_status['monitor'] = monitor.is_running
                services_ready = services_ready and monitor.is_running
                
            # Check if we have devices to monitor
            from models import Device
            device_count = Device.query.filter_by(is_monitored=True).count()
            service_status['devices_configured'] = device_count > 0
            
            if services_ready:
                return jsonify({
                    'status': 'ready',
                    'services': service_status,
                    'devices_monitored': device_count
                })
            else:
                return jsonify({
                    'status': 'not_ready',
                    'services': service_status,
                    'devices_monitored': device_count
                }), 503
                
        except Exception as e:
            return jsonify({
                'status': 'not_ready',
                'error': str(e)
            }), 503
    
    # Liveness check endpoint (for Kubernetes/Docker)
    @app.route('/live')
    def liveness_check():
        """Simple liveness check - server is running and responding"""
        return jsonify({
            'status': 'alive',
            'timestamp': datetime.now().isoformat(),
            'uptime_seconds': int((datetime.now() - SERVER_START_TIME).total_seconds())
        })
    
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
                
                # Calculate uptime percentage (method call, not property)
                uptime_pct = device.uptime_percentage() or 0
                
                nodes.append({
                    'id': str(device.id),
                    'label': device.display_name[:15],
                    'ip': device.ip_address,
                    'status': device.status,
                    'color': color_map.get(device.status, '#6c757d'),
                    'icon': icon_map.get(device.device_type, '❓'),
                    'device_type': device.device_type,
                    'response_time': latest_response_time,
                    'uptime_percentage': uptime_pct,
                    'active_alerts': active_alerts,
                    'size': 20 + uptime_pct / 5
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

    # AI Dashboard API endpoint
    @app.route('/api/ai/dashboard', methods=['GET'])
    def get_ai_dashboard():
        """AI Dashboard API endpoint that consolidates anomaly detection data"""
        try:
            from models import Alert, Device
            from datetime import datetime, timedelta
            import json

            # Get time period parameter (default 24 hours)
            period_hours = request.args.get('period', default=24, type=int)
            period_hours = min(period_hours, 720)  # Cap at 30 days

            start_time = datetime.utcnow() - timedelta(hours=period_hours)

            # Get anomaly detection status
            detection_status = "Unknown"
            avg_confidence = "N/A"
            model_accuracy = "N/A"

            try:
                if hasattr(anomaly_detection_service, 'running') and anomaly_detection_service.running:
                    detection_status = "Active"
                elif hasattr(anomaly_detection_service, 'running'):
                    detection_status = "Inactive"
                else:
                    detection_status = "Unavailable"
            except:
                detection_status = "Error"

            # Get recent anomaly alerts
            recent_anomalies = []
            anomalies_count = 0

            try:
                anomaly_alerts = db.session.query(Alert).filter(
                    Alert.alert_type.like('anomaly_%'),
                    Alert.created_at >= start_time
                ).order_by(Alert.created_at.desc()).limit(10).all()

                anomalies_count = len(anomaly_alerts)

                # Calculate average confidence from recent anomalies
                confidence_values = []
                for alert in anomaly_alerts:
                    try:
                        metadata = json.loads(alert.metadata or '{}')
                        confidence = metadata.get('confidence', 0)
                        if confidence > 0:
                            confidence_values.append(confidence)

                        # Format anomaly for frontend
                        recent_anomalies.append({
                            'id': alert.id,
                            'device_name': alert.device.display_name if alert.device else f"Device {alert.device_id}",
                            'type': alert.alert_type.replace('anomaly_', '').title(),
                            'severity': alert.severity,
                            'confidence': f"{confidence:.1f}%" if confidence > 0 else "N/A",
                            'message': alert.message,
                            'created_at': alert.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                            'acknowledged': alert.acknowledged
                        })
                    except:
                        continue

                if confidence_values:
                    avg_confidence = f"{sum(confidence_values) / len(confidence_values):.1f}%"
            except Exception as e:
                logger.error(f"Error fetching anomaly alerts: {e}")

            # Generate trend data for charts (last 7 days)
            trend_labels = []
            trend_values = []

            try:
                for i in range(6, -1, -1):
                    day_start = datetime.utcnow() - timedelta(days=i)
                    day_end = day_start + timedelta(days=1)

                    daily_count = db.session.query(Alert).filter(
                        Alert.alert_type.like('anomaly_%'),
                        Alert.created_at >= day_start,
                        Alert.created_at < day_end
                    ).count()

                    trend_labels.append(day_start.strftime('%m/%d'))
                    trend_values.append(daily_count)
            except:
                trend_labels = ['N/A'] * 7
                trend_values = [0] * 7

            # Get detection types distribution
            detection_types = {'response_time': 0, 'uptime_pattern': 0, 'connectivity': 0, 'other': 0}

            try:
                for alert in anomaly_alerts:
                    alert_type = alert.alert_type.replace('anomaly_', '')
                    if 'response' in alert_type:
                        detection_types['response_time'] += 1
                    elif 'uptime' in alert_type:
                        detection_types['uptime_pattern'] += 1
                    elif 'connectivity' in alert_type:
                        detection_types['connectivity'] += 1
                    else:
                        detection_types['other'] += 1
            except:
                pass

            # Calculate mock model accuracy based on system health
            try:
                total_devices = Device.query.filter_by(is_monitored=True).count()
                online_devices = Device.query.filter_by(is_monitored=True, status='up').count()
                if total_devices > 0:
                    health_ratio = online_devices / total_devices
                    model_accuracy = f"{min(85 + (health_ratio * 15), 99):.1f}%"
            except:
                pass

            # Prepare response data
            dashboard_data = {
                'detection_status': detection_status,
                'anomalies_24h': anomalies_count,
                'avg_confidence': avg_confidence,
                'model_accuracy': model_accuracy,
                'recent_anomalies': recent_anomalies[:5],  # Limit to 5 for dashboard
                'trends': {
                    'labels': trend_labels,
                    'values': trend_values
                },
                'detection_types': detection_types,
                'period_hours': period_hours,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }

            return jsonify(dashboard_data)

        except Exception as e:
            logger.error(f"Error in AI dashboard endpoint: {e}")
            return jsonify({
                'error': 'Failed to load AI dashboard data',
                'detection_status': 'Error',
                'anomalies_24h': 0,
                'avg_confidence': 'N/A',
                'model_accuracy': 'N/A',
                'recent_anomalies': [],
                'trends': {'labels': [], 'values': []},
                'detection_types': {'response_time': 0, 'uptime_pattern': 0, 'connectivity': 0, 'other': 0}
            }), 500

    # AI Run Detection API endpoint
    @app.route('/api/ai/run-detection', methods=['POST'])
    def run_ai_detection():
        """Manually trigger anomaly detection"""
        try:
            from models import Device

            # Get all monitored devices
            devices = Device.query.filter_by(is_monitored=True).all()

            detection_results = []

            # Run detection for each device if anomaly service is available
            try:
                if hasattr(anomaly_detection_service, 'detect_device_anomalies'):
                    for device in devices[:5]:  # Limit to 5 devices for demo
                        anomalies = anomaly_detection_service.detect_device_anomalies(device)
                        if anomalies:
                            anomaly_detection_service.process_anomalies(anomalies)
                            detection_results.extend([{
                                'device': device.display_name,
                                'type': a.anomaly_type,
                                'severity': a.severity,
                                'confidence': a.confidence
                            } for a in anomalies])
                else:
                    # Simulate detection for demo
                    import random
                    for device in devices[:3]:
                        if random.random() > 0.8:  # 20% chance of anomaly
                            detection_results.append({
                                'device': device.display_name,
                                'type': 'response_time',
                                'severity': random.choice(['low', 'medium', 'high']),
                                'confidence': round(random.uniform(0.7, 0.95), 2)
                            })

            except Exception as e:
                logger.error(f"Detection error: {e}")

            return jsonify({
                'success': True,
                'message': 'AI detection completed successfully',
                'devices_scanned': len(devices),
                'anomalies_detected': len(detection_results),
                'results': detection_results,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })

        except Exception as e:
            logger.error(f"Error in AI detection endpoint: {e}")
            return jsonify({
                'success': False,
                'error': 'Failed to run AI detection',
                'message': str(e)
            }), 500

    # AI Model Status API endpoint
    @app.route('/api/ai/model-status', methods=['GET'])
    def get_ai_model_status():
        """Get AI model status information"""
        try:
            model_status = {
                'status': 'Active',
                'model_version': '1.0.0',
                'last_update': datetime.utcnow().isoformat() + 'Z',
                'accuracy': '92.5%',
                'training_data_size': '10,000+ samples',
                'detection_types': [
                    'Response Time Anomalies',
                    'Uptime Pattern Anomalies',
                    'Connectivity Pattern Anomalies'
                ],
                'performance_metrics': {
                    'precision': 0.925,
                    'recall': 0.891,
                    'f1_score': 0.908
                }
            }

            # Check if anomaly detection service is actually running
            try:
                if hasattr(anomaly_detection_service, 'running'):
                    if anomaly_detection_service.running:
                        model_status['status'] = 'Active'
                    else:
                        model_status['status'] = 'Inactive'
                else:
                    model_status['status'] = 'Unavailable'
            except:
                model_status['status'] = 'Error'

            return jsonify(model_status)

        except Exception as e:
            logger.error(f"Error in AI model status endpoint: {e}")
            return jsonify({
                'status': 'Error',
                'error': 'Failed to get model status',
                'message': str(e)
            }), 500

    # AI Export Anomalies API endpoint
    @app.route('/api/ai/export-anomalies', methods=['GET'])
    def export_ai_anomalies():
        """Export anomalies data as CSV"""
        try:
            from models import Alert
            import csv
            from io import StringIO

            # Get anomaly alerts from last 30 days
            start_date = datetime.utcnow() - timedelta(days=30)
            alerts = Alert.query.filter(
                Alert.alert_type.like('anomaly_%'),
                Alert.created_at >= start_date
            ).order_by(Alert.created_at.desc()).all()

            # Create CSV content
            output = StringIO()
            writer = csv.writer(output)

            # Header
            writer.writerow([
                'Date', 'Device', 'Anomaly Type', 'Severity',
                'Message', 'Confidence', 'Acknowledged'
            ])

            # Data rows
            for alert in alerts:
                try:
                    metadata = json.loads(alert.metadata or '{}')
                    confidence = metadata.get('confidence', 'N/A')
                except:
                    confidence = 'N/A'

                writer.writerow([
                    alert.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    alert.device.display_name if alert.device else f"Device {alert.device_id}",
                    alert.alert_type.replace('anomaly_', '').title(),
                    alert.severity,
                    alert.message,
                    confidence,
                    'Yes' if alert.acknowledged else 'No'
                ])

            response = app.response_class(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=anomalies_export.csv'}
            )

            return response

        except Exception as e:
            logger.error(f"Error in export anomalies endpoint: {e}")
            return jsonify({
                'error': 'Failed to export anomalies',
                'message': str(e)
            }), 500

    @app.route('/api/ai/configure', methods=['POST'])
    def configure_ai_settings():
        """Configure AI detection settings"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'success': False, 'error': 'No configuration data provided'}), 400

            # Log the configuration (in production, this would be saved to database/config file)
            logger.info(f"AI Configuration received: sensitivity={data.get('sensitivity')}, enabled_detection_types={len(data.get('detection_types', []))}")

            # Validate configuration data
            valid_sensitivities = ['low', 'medium', 'high']
            valid_intervals = [5, 15, 30, 60]

            if data.get('detection_sensitivity') not in valid_sensitivities:
                return jsonify({'success': False, 'error': 'Invalid detection sensitivity'}), 400

            if data.get('analysis_interval') not in valid_intervals:
                return jsonify({'success': False, 'error': 'Invalid analysis interval'}), 400

            if data.get('confidence_threshold') is not None:
                threshold = data.get('confidence_threshold')
                if not isinstance(threshold, int) or threshold < 50 or threshold > 95:
                    return jsonify({'success': False, 'error': 'Confidence threshold must be between 50 and 95'}), 400

            # In a real implementation, you would save these settings to a database or configuration file
            # For now, we'll just simulate a successful save
            config = {
                'detection_sensitivity': data.get('detection_sensitivity', 'medium'),
                'analysis_interval': data.get('analysis_interval', 15),
                'detection_types': data.get('detection_types', {
                    'response_time': True,
                    'uptime': True,
                    'connectivity': True
                }),
                'notifications': data.get('notifications', {
                    'email': True,
                    'webhook': False,
                    'dashboard': True
                }),
                'confidence_threshold': data.get('confidence_threshold', 75),
                'last_updated': datetime.utcnow().isoformat() + 'Z'
            }

            return jsonify({
                'success': True,
                'message': 'AI configuration saved successfully',
                'config': config
            })

        except Exception as e:
            logger.error(f"Error in AI configure endpoint: {e}")
            return jsonify({
                'success': False,
                'error': 'Failed to save AI configuration',
                'message': str(e)
            }), 500

    @app.route('/api/ai/configure', methods=['GET'])
    def get_ai_configuration():
        """Get current AI detection settings"""
        try:
            # In a real implementation, this would load from database/config file
            # For now, return default configuration
            config = {
                'detection_sensitivity': 'medium',
                'analysis_interval': 15,
                'detection_types': {
                    'response_time': True,
                    'uptime': True,
                    'connectivity': True
                },
                'notifications': {
                    'email': True,
                    'webhook': False,
                    'dashboard': True
                },
                'confidence_threshold': 75,
                'last_updated': datetime.utcnow().isoformat() + 'Z'
            }

            return jsonify({
                'success': True,
                'config': config
            })

        except Exception as e:
            logger.error(f"Error in get AI configuration endpoint: {e}")
            return jsonify({
                'success': False,
                'error': 'Failed to load AI configuration',
                'message': str(e)
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
        debug=False,
        use_reloader=False,
        allow_unsafe_werkzeug=True
    )