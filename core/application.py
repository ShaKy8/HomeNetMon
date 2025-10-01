"""
Refactored application factory using modular architecture.
This replaces the monolithic create_app() function with a clean, maintainable structure.
"""

import os
import logging
from datetime import datetime
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO

from config import Config
from models import db, init_db
from version import get_version_string, get_complete_info

# Import core modules
from core.blueprint_registry import BlueprintRegistry
from core.service_manager import ServiceManager
from core.websocket_manager import WebSocketManager
from core.thread_manager import ThreadManager
from core.security_middleware import SecurityMiddleware
from core.db_config import DatabaseConfig, ConnectionPoolMonitor
from core.db_optimizer import QueryOptimizer, OptimizedQueries, DatabaseIndexManager
from core.websocket_optimizer import WebSocketBroadcastOptimizer
from core.cache_layer import setup_cache_cleanup, global_cache
from core.query_profiler import global_profiler
from core.quality_manager import QualityManager

# Import performance middleware
from performance_middleware import PerformanceMiddleware

logger = logging.getLogger(__name__)

# Global variable to track server startup time
SERVER_START_TIME = datetime.now()


class Application:
    """Main application class that orchestrates all components."""
    
    def __init__(self):
        self.app = None
        self.socketio = None
        self.blueprint_registry = None
        self.service_manager = None
        self.websocket_manager = None
        self.thread_manager = None
        self.auth_manager = None
        self.security_middleware = None
        self.db_optimizer = None
        self.websocket_optimizer = None
        self.connection_monitor = None
        self.quality_manager = None
        
    def create_app(self) -> Flask:
        """Create and configure the Flask application."""
        # Setup logging
        Config.setup_logging()
        logger.info("Starting HomeNetMon application with refactored architecture")
        
        # Create Flask app
        self.app = Flask(__name__)
        self.app.config.from_object(Config)
        
        # Configure optimized database settings
        DatabaseConfig.configure_app(self.app)
        
        # Initialize database
        init_db(self.app)
        
        # Register database event listeners
        DatabaseConfig.register_event_listeners(db)
        
        # Initialize database optimizations
        self._initialize_database_optimizations()
        
        # Initialize components
        self._initialize_quality_management()
        self._initialize_socketio()
        self._initialize_blueprints()
        self._initialize_services()
        self._initialize_websockets()
        self._register_routes()
        self._register_error_handlers()
        
        logger.info("Application initialization complete")
        return self.app
        
    def _initialize_database_optimizations(self):
        """Initialize database performance optimizations."""
        logger.info("Initializing database optimizations")
        
        # Create database optimizer
        self.db_optimizer = QueryOptimizer(db)
        
        # Create connection pool monitor
        self.connection_monitor = ConnectionPoolMonitor(db)
        
        # Register query profiler and indexes within app context
        with self.app.app_context():
            from core.query_profiler import register_sqlalchemy_profiler
            register_sqlalchemy_profiler(db.engine, global_profiler)
            
            # Create performance indexes
            index_manager = DatabaseIndexManager(db)
            index_manager.create_performance_indexes()
            
        # Setup cache cleanup
        setup_cache_cleanup()
        
    def _initialize_quality_management(self):
        """Initialize quality management system."""
        logger.info("Initializing quality management system")
        
        # Initialize quality manager (includes error handling, validation, etc.)
        config_file = os.environ.get('CONFIG_FILE', '.env')
        self.quality_manager = QualityManager()
        self.quality_manager.init_app(self.app, config_file)
        
        # Initialize security after quality management
        self._initialize_security()
        
    def _initialize_security(self):
        """Initialize security components."""
        logger.info("Initializing security components")
        
        # Initialize authentication manager
        self.auth_manager = AuthManager(self.app)
        self.app.extensions['auth_manager'] = self.auth_manager
        
        # Initialize security middleware
        self.security_middleware = SecurityMiddleware(self.app)
        
        # Initialize performance middleware
        PerformanceMiddleware(self.app)
        
    def _initialize_socketio(self):
        """Initialize SocketIO for real-time updates."""
        logger.info("Initializing SocketIO")
        
        self.socketio = SocketIO(
            self.app,
            cors_allowed_origins="*",
            logger=True,
            engineio_logger=False,
            async_mode='threading',
            ping_interval=10,
            ping_timeout=60
        )
        
    def _initialize_blueprints(self):
        """Initialize and register all API blueprints."""
        logger.info("Initializing API blueprints")
        
        self.blueprint_registry = BlueprintRegistry.create_default()
        self.blueprint_registry.init_app(self.app)
        
        # Register authentication endpoints
        self._register_auth_endpoints()
        
    def _initialize_services(self):
        """Initialize background services."""
        logger.info("Initializing background services")
        
        # Create thread manager for legacy services
        self.thread_manager = ThreadManager(max_threads=20)
        
        # Create service manager
        self.service_manager = ServiceManager.create_default(self.app)
        
        # Update monitor with socketio instance
        if hasattr(self.service_manager, 'monitor'):
            self.service_manager.monitor.socketio = self.socketio
            
        # Initialize additional services
        self._initialize_additional_services()
        
    def _initialize_additional_services(self):
        """Initialize additional services that aren't core monitoring."""
        # Speed test service
        from services.speedtest import speed_test_service
        speed_test_service.app = self.app
        
        # Anomaly detection service
        from services.anomaly_detection import anomaly_detection_service
        anomaly_detection_service.app = self.app
        
        # Security scanner service
        from services.security_scanner import security_scanner
        security_scanner.app = self.app
        
        # Rule engine service
        from services.rule_engine import rule_engine_service
        rule_engine_service.app = self.app
        
        # Configuration service
        from services.configuration_service import configuration_service
        configuration_service.app = self.app
        
        # Alert correlation service
        from services.alert_correlation import alert_correlation_service
        alert_correlation_service.app = self.app
        
        # Performance monitor service
        from services.performance_monitor import performance_monitor
        performance_monitor.app = self.app
        
        # Rate limiter service
        from services.rate_limiter import rate_limiter
        rate_limiter.app = self.app
        
        logger.info("Additional services initialized")
        
    def _initialize_websockets(self):
        """Initialize WebSocket event handlers."""
        logger.info("Initializing WebSocket handlers")
        
        self.websocket_manager = WebSocketManager(self.socketio)
        self.websocket_manager.register_handlers()
        
        # Initialize WebSocket broadcast optimizer
        self.websocket_optimizer = WebSocketBroadcastOptimizer(self.socketio)
        
        # Register monitoring-specific events
        if hasattr(self.service_manager, 'monitor') and hasattr(self.service_manager, 'alert_manager'):
            self.websocket_manager.register_monitoring_events(
                self.service_manager.monitor,
                self.service_manager.alert_manager
            )
            
    def _register_auth_endpoints(self):
        """Register authentication endpoints."""
        from flask import Blueprint, request, jsonify
        
        auth_bp = Blueprint('auth', __name__)
        
        @auth_bp.route('/api/auth/login', methods=['POST'])
        def login():
            """Login endpoint."""
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                return jsonify({'error': 'Username and password required'}), 400
                
            user = self.auth_manager.authenticate(username, password)
            if not user:
                return jsonify({'error': 'Invalid credentials'}), 401
                
            tokens = self.auth_manager.generate_tokens(user)
            return jsonify(tokens), 200
            
        @auth_bp.route('/api/auth/refresh', methods=['POST'])
        def refresh():
            """Refresh token endpoint."""
            data = request.get_json()
            refresh_token = data.get('refresh_token')
            
            if not refresh_token:
                return jsonify({'error': 'Refresh token required'}), 400
                
            tokens = self.auth_manager.refresh_access_token(refresh_token)
            if not tokens:
                return jsonify({'error': 'Invalid refresh token'}), 401
                
            return jsonify(tokens), 200
            
        @auth_bp.route('/api/auth/logout', methods=['POST'])
        def logout():
            """Logout endpoint."""
            auth_header = request.headers.get('Authorization')
            if auth_header:
                parts = auth_header.split()
                if len(parts) == 2:
                    token = parts[1]
                    self.auth_manager.revoke_token(token)
                    
            return jsonify({'message': 'Logged out successfully'}), 200
            
        self.app.register_blueprint(auth_bp)
        logger.info("Authentication endpoints registered")
        
    def _register_routes(self):
        """Register main application routes."""
        
        @self.app.route('/')
        def index():
            """Main dashboard page."""
            return render_template('index.html')
            
        @self.app.route('/dashboard')
        def dashboard():
            """Dashboard page."""
            return render_template('dashboard.html')
            
        @self.app.route('/devices')
        def devices():
            """Devices management page."""
            return render_template('devices.html')
            
        @self.app.route('/device/<int:device_id>')
        def device_detail(device_id):
            """Individual device detail page."""
            return render_template('device_detail.html', device_id=device_id)
            
        @self.app.route('/alerts')
        def alerts():
            """Alerts management page."""
            return render_template('alerts.html')
            
        @self.app.route('/settings')
        def settings():
            """Settings page."""
            return render_template('settings.html')
            
        @self.app.route('/topology')
        def topology():
            """Network topology visualization page."""
            return render_template('topology.html')
            
        @self.app.route('/version')
        def version():
            """Version information endpoint."""
            return jsonify(get_complete_info())
            
        logger.info("Main routes registered")
        
    def _register_error_handlers(self):
        """Register error handlers."""
        
        @self.app.errorhandler(404)
        def not_found(error):
            """Handle 404 errors."""
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Endpoint not found'}), 404
            return render_template('404.html'), 404
            
        @self.app.errorhandler(500)
        def internal_error(error):
            """Handle 500 errors."""
            logger.error(f"Internal server error: {error}")
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Internal server error'}), 500
            return render_template('500.html'), 500
            
        logger.info("Error handlers registered")
        
    def start_services(self):
        """Start all background services."""
        logger.info("Starting background services")
        
        # Start service manager services
        self.service_manager.start_all()
        
        # Start any thread manager threads if needed
        # (Currently using ServiceManager instead)
        
        logger.info("All services started")
        
    def stop_services(self):
        """Stop all background services."""
        logger.info("Stopping background services")
        
        if self.service_manager:
            self.service_manager.shutdown()
            
        if self.thread_manager:
            self.thread_manager.shutdown()
            
        logger.info("All services stopped")
        
    def get_status(self) -> dict:
        """Get application status."""
        status = {
            'server_start_time': SERVER_START_TIME.isoformat(),
            'uptime_seconds': (datetime.now() - SERVER_START_TIME).total_seconds(),
            'version': get_version_string()
        }
        
        if self.service_manager:
            status['services'] = self.service_manager.health_check()
            
        if self.websocket_manager:
            status['websockets'] = self.websocket_manager.get_metrics()
            
        if self.thread_manager:
            status['threads'] = self.thread_manager.get_metrics()
            
        return status


def create_app() -> Flask:
    """Factory function to create the Flask application."""
    application = Application()
    app = application.create_app()
    
    # Store application instance for access
    app.application_instance = application
    
    # Start services
    application.start_services()
    
    return app


def get_socketio() -> SocketIO:
    """Get the SocketIO instance."""
    from flask import current_app
    if hasattr(current_app, 'application_instance'):
        return current_app.application_instance.socketio
    return None