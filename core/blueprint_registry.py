import logging
from flask import Flask, Blueprint
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

class BlueprintRegistry:
    """Manages registration of Flask blueprints in a centralized way."""
    
    def __init__(self):
        self.blueprints: List[Tuple[Blueprint, Dict]] = []
        
    def register(self, blueprint: Blueprint, url_prefix: str = None, **options):
        """Register a blueprint with its configuration."""
        config = {'url_prefix': url_prefix}
        config.update(options)
        self.blueprints.append((blueprint, config))
        logger.debug(f"Registered blueprint: {blueprint.name} with prefix: {url_prefix}")
        
    def init_app(self, app: Flask):
        """Initialize all registered blueprints with the Flask app."""
        logger.info(f"Initializing {len(self.blueprints)} blueprints")
        
        for blueprint, config in self.blueprints:
            try:
                app.register_blueprint(blueprint, **config)
                logger.debug(f"Successfully registered {blueprint.name}")
            except Exception as e:
                logger.error(f"Failed to register blueprint {blueprint.name}: {e}")
                raise
                
    @classmethod
    def create_default(cls) -> 'BlueprintRegistry':
        """Create a BlueprintRegistry with all default blueprints."""
        registry = cls()
        
        # Import all blueprints
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
        from api.performance_optimization import performance_optimization_bp
        from api.rate_limit_admin import rate_limit_admin_bp
        from api.performance_dashboard import performance_dashboard_bp
        from api.health_check import health_check_bp
        
        # Register all blueprints with their prefixes
        registry.register(devices_bp, url_prefix='/api/devices')
        registry.register(monitoring_bp, url_prefix='/api/monitoring')
        registry.register(config_bp, url_prefix='/api/config')
        registry.register(config_management_bp, url_prefix='/api/config-management')
        registry.register(analytics_bp, url_prefix='/api/analytics')
        registry.register(speedtest_bp, url_prefix='/api/speedtest')
        registry.register(device_control_bp, url_prefix='/api/device-control')
        registry.register(anomaly_bp, url_prefix='/api/anomaly')
        registry.register(security_bp, url_prefix='/api/security')
        registry.register(notifications_bp, url_prefix='/api/notifications')
        registry.register(automation_bp, url_prefix='/api/automation')
        registry.register(system_bp, url_prefix='/api/system')
        registry.register(health_bp, url_prefix='/api/health')
        registry.register(escalation_bp, url_prefix='/api/escalation')
        registry.register(performance_bp, url_prefix='/api/performance')
        registry.register(performance_optimization_bp)
        registry.register(rate_limit_admin_bp, url_prefix='/api/rate-limit')
        registry.register(performance_dashboard_bp, url_prefix='/api/performance-dashboard')
        registry.register(health_check_bp, url_prefix='/api')
        
        logger.info("Created default blueprint registry with all API endpoints")
        return registry