import json
import logging
import os
import threading
import time
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
from constants import DEVICE_DOWN_AFTER_SECONDS

# Global variable to track server startup time
SERVER_START_TIME = datetime.utcnow()

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

    # (services/http_optimizer.py was removed: it duplicated flask-compress and the
    # security/performance middlewares, and -- running last in the after_request
    # chain -- overrode X-Frame-Options to SAMEORIGIN and made API GET responses
    # publicly cacheable for 30 s.)

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

    # Initialize centralized error handler for standardized API error responses
    try:
        from core.error_handler import global_error_handler
        global_error_handler.init_app(app)
        logger.info("Centralized error handler initialized")
    except ImportError:
        logger.warning("Error handler not available - using default Flask error handling")

    # Initialize SocketIO for real-time updates.
    # CORS: the pages are served from this host, so a legitimate Origin is whatever
    # address the browser used to reach it: a private/link-local IP, a *.local or bare
    # hostname, a Tailscale address (100.64.0.0/10 or this node's MagicDNS name) or a
    # name listed in ALLOWED_ORIGIN_HOSTS. Public addresses are refused so a page on
    # another site cannot open a socket to the dashboard from a visiting browser.
    import ipaddress
    import re
    from urllib.parse import urlparse

    from constants import CGNAT_NETWORK
    from services import tailscale

    try:
        _allowed_network = ipaddress.ip_network(Config.NETWORK_RANGE, strict=False)
    except ValueError:
        logger.warning(
            "Invalid NETWORK_RANGE=%r for CORS check; falling back to all-RFC1918",
            Config.NETWORK_RANGE,
        )
        _allowed_network = None

    _local_hostname_pattern = re.compile(r'^[a-zA-Z0-9\-]+(\.local)?$')

    def cors_allowed_origins_callback(origin):
        if not origin:
            return False
        try:
            parsed = urlparse(origin)
        except Exception:
            return False
        if parsed.scheme not in ('http', 'https'):
            return False
        host = parsed.hostname
        if not host:
            return False

        # Localhost / loopback
        if host in ('localhost', '127.0.0.1', '0.0.0.0', '::1'):
            return True

        # Local hostnames (foo.local or bare unqualified)
        if _local_hostname_pattern.match(host) and '.' not in host.replace('.local', ''):
            return True

        lowered = host.lower()
        if lowered in Config.ALLOWED_ORIGIN_HOSTS:
            return True

        # Other hostnames: only this node's own Tailscale MagicDNS name (cached lookup,
        # one subprocess per 30 s at most). Not *.ts.net wholesale: those names resolve
        # publicly, so any tailnet could otherwise host a page that reaches this socket.
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return lowered in tailscale.own_hostnames()

        # IP literal: any private / link-local / loopback / CGNAT address -- that may be
        # another local subnet (a second interface, a VLAN, a VPN or the tailnet) than
        # the one being monitored.
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip in CGNAT_NETWORK:
            return True
        if _allowed_network is not None and ip in _allowed_network:
            return True
        return False

    # async_mode is explicit: every background service is a native thread doing
    # blocking subprocess/SQLite work, so the server must be threading-based too.
    # (Left unset, python-engineio auto-selected eventlet because the package was
    # installed, with no monkey-patching -- a greenlet hub beside ten OS threads.)
    socketio = SocketIO(app, cors_allowed_origins=cors_allowed_origins_callback, async_mode='threading',
                        logger=False, engineio_logger=False)

    # Import and register blueprints
    from api.devices import devices_bp  # Use original for now
    from api.monitoring import monitoring_bp
    from api.config import config_bp
    from api.analytics import analytics_bp
    from api.device_control import device_control_bp
    from api.security import security_bp
    from api.notifications import notifications_bp
    from api.config_management import config_management_bp
    from api.system import system_bp
    from api.performance import performance_bp

    app.register_blueprint(devices_bp, url_prefix='/api/devices')
    app.register_blueprint(monitoring_bp, url_prefix='/api/monitoring')
    app.register_blueprint(config_bp, url_prefix='/api/config')
    app.register_blueprint(config_management_bp, url_prefix='/api/config-management')
    app.register_blueprint(analytics_bp, url_prefix='/api/analytics')
    app.register_blueprint(device_control_bp, url_prefix='/api/device-control')
    app.register_blueprint(security_bp, url_prefix='/api/security')
    app.register_blueprint(notifications_bp, url_prefix='/api/notifications')
    app.register_blueprint(system_bp, url_prefix='/api/system')
    app.register_blueprint(performance_bp, url_prefix='/api/performance')

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


    # Initialize security scanner service
    from services.security_scanner import security_scanner
    security_scanner.app = app

    # Internet / gateway reachability monitor
    from monitoring.wan_monitor import WanMonitor
    wan_monitor = WanMonitor(app)
    app.wan_monitor = wan_monitor

    # Initialize rule engine service

    # Initialize configuration service
    from services.configuration_service import configuration_service
    configuration_service.app = app


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


    # (core/rate_limiter.py -- a second, in-memory limiter with a cross-IP global
    # cap, unconditional X-Forwarded-For trust and dead auth limits -- was removed.
    # Flask-Limiter in services/rate_limiter.py is the one rate limiter.)

    # Make services accessible to other parts of the app
    app._scanner = scanner
    app._monitor = monitor
    app.alert_manager = alert_manager
    app.bandwidth_monitor = bandwidth_monitor
    app.security_scanner = security_scanner
    app.configuration_service = configuration_service
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

    # Initialize resource monitor (scheduled DB retention + system resource cleanup)
    from services.resource_monitor import ResourceMonitor
    resource_monitor = ResourceMonitor(app)
    app.resource_monitor = resource_monitor

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

        # Start performance monitor service
        performance_thread = threading.Thread(
            target=performance_monitor.start_monitoring,
            daemon=True,
            name='PerformanceMonitor'
        )
        performance_thread.start()

        # Start resource monitor (DB retention + system resource cleanup)
        wan_thread = threading.Thread(
            target=wan_monitor.start_monitoring,
            daemon=True,
            name='WanMonitor'
        )
        wan_thread.start()

        resource_monitor_thread = threading.Thread(
            target=resource_monitor.start_monitoring,
            daemon=True,
            name='ResourceMonitor'
        )
        resource_monitor_thread.start()

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
    # Under pytest (conftest sets Config.TESTING before create_app) the monitoring
    # threads must not start: they would ping test devices and write rows into the
    # test database mid-test, which made several tests order-dependent.
    if getattr(Config, 'TESTING', False) or app.config.get('TESTING'):
        logger.info("TESTING set: background monitoring services not started")
    else:
        services_thread = threading.Thread(target=start_monitoring_services, daemon=True)
        services_thread.start()


    # Web routes (protected)
    @app.context_processor
    def inject_defaults():
        return {'default_network_range': Config.NETWORK_RANGE}

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

    @app.route('/favicon.ico')
    def favicon():
        """Serve favicon from static folder"""
        return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/vnd.microsoft.icon')

    # Retired pages. The NOC view, performance dashboard and AI dashboard were
    # consolidated into / and /analytics (anomaly detection was removed in 2.5.0).
    # Old bookmarks are redirected.
    @app.route('/dashboard/full')
    @app.route('/full-view')
    @app.route('/noc')
    def retired_to_dashboard():
        return redirect(url_for('dashboard'), code=301)

    @app.route('/performance-dashboard')
    def retired_performance_dashboard():
        return redirect(url_for('analytics') + '#performance', code=301)

    @app.route('/ai-dashboard')
    @app.route('/ai_dashboard')
    def retired_ai_dashboard():
        return redirect(url_for('analytics'), code=301)

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

    @app.route('/analytics')
    def analytics():
        return render_template('analytics.html')

    @app.route('/security-dashboard')
    def security_dashboard():
        """Redirect old security-dashboard URL to new security URL for consistency"""
        return redirect(url_for('security'), code=301)

    # Health overview functionality has been merged into the main dashboard

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

    # Request/response Socket.IO handlers were removed: no page ever emitted them,
    # and `update_configuration` allowed unauthenticated config writes that bypassed
    # CSRF and validation. Pages use the REST API plus the room-based pushes below.

    def emit_alert_update(alert, action='created'):
        """Emit real-time alert update to all connected clients"""
        try:
            alert_data = {
                'id': alert.id,
                'device_id': alert.device_id,
                'device_name': alert.device.display_name,
                'device_ip': alert.device.ip_address,
                'alert_type': alert.alert_type,
                'alert_subtype': getattr(alert, 'alert_subtype', None),
                'title': getattr(alert, 'title', alert.alert_type),
                'severity': alert.severity,
                'message': alert.message,
                'created_at': alert.created_at.isoformat() + 'Z',
                'acknowledged': alert.acknowledged,
                'acknowledged_by': getattr(alert, 'acknowledged_by', None),
                'resolved': alert.resolved,
                'priority_level': getattr(alert, 'priority_level', None),
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

    def emit_alerts_changed(action, count):
        """Bulk alert change (acknowledge-all, bulk resolve, deletes): pages reload once."""
        try:
            socketio.emit('alert_update', {
                'type': 'alert_update',
                'alert': None,
                'action': 'bulk',
                'bulk_action': action,
                'count': count,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
        except Exception as e:
            logger.error(f"Error emitting alerts_changed: {e}")

    app.emit_alerts_changed = emit_alerts_changed

    # Error handlers
    # Comprehensive error handling
    # Error handling lives in core.error_handler (JSON for /api/*, HTML otherwise).

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
                'uptime_seconds': int((datetime.utcnow() - SERVER_START_TIME).total_seconds()),
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
