"""
External System Integration Manager

This module provides comprehensive integration capabilities with external systems:

1. ITSM (IT Service Management) integration (ServiceNow, Jira Service Desk, etc.)
2. SIEM (Security Information and Event Management) integration
3. Cloud platform connectors (AWS CloudWatch, Azure Monitor, GCP Operations)
4. Monitoring tool integration (Prometheus, Grafana, Nagios, Zabbix)
5. Communication platform integration (Slack, Microsoft Teams, Discord)
6. Network device management integration (SNMP, SSH, REST APIs)
7. Authentication system integration (LDAP, Active Directory, SSO)
8. Backup and data export integration
"""

import asyncio
import threading
import time
import logging
import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import hashlib
import base64
from urllib.parse import urljoin, urlparse
import aiohttp
import ssl

from models import db, Device, Alert, MonitoringData
from services.notification import notification_service

logger = logging.getLogger(__name__)


class IntegrationType(Enum):
    """Types of external system integrations"""
    ITSM = "itsm"                    # IT Service Management
    SIEM = "siem"                    # Security Information and Event Management
    MONITORING = "monitoring"         # Monitoring and Observability
    CLOUD = "cloud"                  # Cloud Platform Services
    COMMUNICATION = "communication"   # Chat and Communication
    AUTHENTICATION = "authentication" # Identity and Access Management
    NETWORK_DEVICE = "network_device" # Network Equipment
    BACKUP = "backup"                # Backup and Storage
    CUSTOM = "custom"                # Custom integrations


class IntegrationStatus(Enum):
    """Integration connection status"""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    AUTHENTICATION_FAILED = "auth_failed"
    RATE_LIMITED = "rate_limited"
    MAINTENANCE = "maintenance"


class AuthMethod(Enum):
    """Authentication methods for integrations"""
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    BASIC_AUTH = "basic_auth"
    BEARER_TOKEN = "bearer_token"
    JWT = "jwt"
    CERTIFICATE = "certificate"
    CUSTOM = "custom"


@dataclass
class IntegrationConfig:
    """Configuration for an external system integration"""
    integration_id: str
    name: str
    integration_type: IntegrationType
    enabled: bool = True
    
    # Connection details
    base_url: str = None
    api_version: str = None
    timeout_seconds: int = 30
    
    # Authentication
    auth_method: AuthMethod = AuthMethod.API_KEY
    auth_config: Dict[str, Any] = None
    
    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    
    # Data mapping and filtering
    field_mappings: Dict[str, str] = None
    data_filters: Dict[str, Any] = None
    
    # Sync configuration
    sync_enabled: bool = True
    sync_interval_seconds: int = 300
    batch_size: int = 100
    
    # Retry configuration
    max_retries: int = 3
    retry_delay_seconds: int = 5
    
    # Custom configuration
    custom_config: Dict[str, Any] = None


@dataclass
class IntegrationEvent:
    """Event data for integration processing"""
    event_id: str
    integration_id: str
    event_type: str
    timestamp: datetime
    
    # Source data
    source_system: str
    source_id: str
    
    # Event data
    data: Dict[str, Any]
    metadata: Dict[str, Any] = None
    
    # Processing status
    processed: bool = False
    error_message: str = None
    retry_count: int = 0


@dataclass
class IntegrationStats:
    """Statistics for an integration"""
    integration_id: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    last_request_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    last_error_time: Optional[datetime] = None
    last_error_message: str = None
    average_response_time_ms: float = 0.0
    rate_limit_hits: int = 0


class ExternalSystemIntegrationManager:
    """
    Manages all external system integrations with standardized APIs,
    authentication, error handling, and data synchronization.
    """
    
    def __init__(self, app=None):
        self.app = app
        self.running = False
        self.sync_thread = None
        
        # Integration registry
        self.integrations: Dict[str, IntegrationConfig] = {}
        self.integration_handlers: Dict[str, Callable] = {}
        self.integration_stats: Dict[str, IntegrationStats] = {}
        
        # Event processing
        self.event_queue = deque(maxlen=10000)
        self.processing_lock = threading.Lock()
        
        # Rate limiting
        self.rate_limiters: Dict[str, Dict[str, Any]] = {}
        
        # Authentication cache
        self.auth_cache: Dict[str, Dict[str, Any]] = {}
        
        # Configuration
        self.config = {
            'max_concurrent_requests': 10,
            'default_timeout': 30,
            'event_batch_size': 50,
            'auth_cache_ttl': 3600,  # 1 hour
            'health_check_interval': 300,  # 5 minutes
            'stats_retention_hours': 168  # 1 week
        }
        
        # Initialize built-in integrations
        self._register_builtin_handlers()
    
    def start_integration_manager(self):
        """Start the integration manager"""
        if self.running:
            logger.warning("Integration manager is already running")
            return
        
        self.running = True
        
        # Start synchronization thread
        self.sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self.sync_thread.start()
        
        logger.info("External system integration manager started")
    
    def stop_integration_manager(self):
        """Stop the integration manager"""
        self.running = False
        
        if self.sync_thread and self.sync_thread.is_alive():
            self.sync_thread.join(timeout=30)
        
        logger.info("External system integration manager stopped")
    
    def register_integration(self, config: IntegrationConfig) -> bool:
        """Register a new external system integration"""
        try:
            # Validate configuration
            if not self._validate_integration_config(config):
                logger.error(f"Invalid integration configuration for {config.integration_id}")
                return False
            
            # Test connection
            if config.enabled:
                connection_test = asyncio.run(self._test_integration_connection(config))
                if not connection_test:
                    logger.warning(f"Connection test failed for {config.integration_id}, registering anyway")
            
            # Register integration
            self.integrations[config.integration_id] = config
            self.integration_stats[config.integration_id] = IntegrationStats(
                integration_id=config.integration_id
            )
            
            # Initialize rate limiter
            self.rate_limiters[config.integration_id] = {
                'requests': [],
                'limit': config.rate_limit_requests,
                'window': config.rate_limit_window_seconds
            }
            
            logger.info(f"Registered integration {config.integration_id} ({config.name})")
            return True
            
        except Exception as e:
            logger.error(f"Error registering integration {config.integration_id}: {e}")
            return False
    
    def unregister_integration(self, integration_id: str) -> bool:
        """Unregister an external system integration"""
        try:
            if integration_id not in self.integrations:
                logger.warning(f"Integration {integration_id} not found")
                return False
            
            # Remove integration data
            del self.integrations[integration_id]
            if integration_id in self.integration_stats:
                del self.integration_stats[integration_id]
            if integration_id in self.rate_limiters:
                del self.rate_limiters[integration_id]
            if integration_id in self.auth_cache:
                del self.auth_cache[integration_id]
            
            logger.info(f"Unregistered integration {integration_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error unregistering integration {integration_id}: {e}")
            return False
    
    def send_event(self, integration_id: str, event_type: str, data: Dict[str, Any],
                   source_system: str = "homenetmon", source_id: str = None) -> bool:
        """Send an event to an external system"""
        try:
            if integration_id not in self.integrations:
                logger.error(f"Integration {integration_id} not found")
                return False
            
            # Create event
            event = IntegrationEvent(
                event_id=f"{integration_id}_{event_type}_{int(time.time())}_{len(self.event_queue)}",
                integration_id=integration_id,
                event_type=event_type,
                timestamp=datetime.utcnow(),
                source_system=source_system,
                source_id=source_id or str(time.time()),
                data=data
            )
            
            # Add to processing queue
            self.event_queue.append(event)
            
            logger.debug(f"Queued event {event.event_id} for integration {integration_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending event to integration {integration_id}: {e}")
            return False
    
    def _sync_loop(self):
        """Main synchronization loop"""
        logger.info("Starting integration synchronization loop")
        
        while self.running:
            try:
                # Process events in queue
                self._process_event_queue()
                
                # Perform health checks
                asyncio.run(self._perform_health_checks())
                
                # Clean up old auth cache entries
                self._cleanup_auth_cache()
                
                time.sleep(10)  # Process every 10 seconds
                
            except Exception as e:
                logger.error(f"Error in integration sync loop: {e}")
                time.sleep(30)
    
    def _process_event_queue(self):
        """Process events in the queue"""
        with self.processing_lock:
            events_to_process = []
            
            # Get batch of events to process
            for _ in range(min(self.config['event_batch_size'], len(self.event_queue))):
                if self.event_queue:
                    events_to_process.append(self.event_queue.popleft())
            
            if events_to_process:
                # Process events asynchronously
                asyncio.run(self._process_events_batch(events_to_process))
    
    async def _process_events_batch(self, events: List[IntegrationEvent]):
        """Process a batch of events concurrently"""
        semaphore = asyncio.Semaphore(self.config['max_concurrent_requests'])
        
        tasks = []
        for event in events:
            task = asyncio.create_task(self._process_single_event(semaphore, event))
            tasks.append(task)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _process_single_event(self, semaphore: asyncio.Semaphore, event: IntegrationEvent):
        """Process a single integration event"""
        async with semaphore:
            try:
                integration = self.integrations.get(event.integration_id)
                if not integration or not integration.enabled:
                    return
                
                # Check rate limiting
                if not self._check_rate_limit(event.integration_id):
                    logger.warning(f"Rate limit exceeded for integration {event.integration_id}")
                    self.integration_stats[event.integration_id].rate_limit_hits += 1
                    # Re-queue the event for later processing
                    self.event_queue.append(event)
                    return
                
                # Get handler for integration type
                handler = self.integration_handlers.get(integration.integration_type.value)
                if not handler:
                    logger.error(f"No handler found for integration type {integration.integration_type.value}")
                    return
                
                # Process the event
                start_time = time.time()
                success = await handler(integration, event)
                end_time = time.time()
                
                # Update statistics
                stats = self.integration_stats[event.integration_id]
                stats.total_requests += 1
                response_time = (end_time - start_time) * 1000  # Convert to milliseconds
                
                if success:
                    stats.successful_requests += 1
                    stats.last_success_time = datetime.utcnow()
                    event.processed = True
                    
                    # Update average response time
                    if stats.average_response_time_ms == 0:
                        stats.average_response_time_ms = response_time
                    else:
                        stats.average_response_time_ms = (stats.average_response_time_ms + response_time) / 2
                else:
                    stats.failed_requests += 1
                    stats.last_error_time = datetime.utcnow()
                    
                    # Retry logic
                    if event.retry_count < integration.max_retries:
                        event.retry_count += 1
                        await asyncio.sleep(integration.retry_delay_seconds)
                        self.event_queue.append(event)  # Re-queue for retry
                
                stats.last_request_time = datetime.utcnow()
                
            except Exception as e:
                logger.error(f"Error processing event {event.event_id}: {e}")
                event.error_message = str(e)
                
                # Update error statistics
                stats = self.integration_stats[event.integration_id]
                stats.failed_requests += 1
                stats.last_error_time = datetime.utcnow()
                stats.last_error_message = str(e)
    
    def _register_builtin_handlers(self):
        """Register built-in integration handlers"""
        self.integration_handlers[IntegrationType.ITSM.value] = self._handle_itsm_event
        self.integration_handlers[IntegrationType.SIEM.value] = self._handle_siem_event
        self.integration_handlers[IntegrationType.MONITORING.value] = self._handle_monitoring_event
        self.integration_handlers[IntegrationType.CLOUD.value] = self._handle_cloud_event
        self.integration_handlers[IntegrationType.COMMUNICATION.value] = self._handle_communication_event
        self.integration_handlers[IntegrationType.NETWORK_DEVICE.value] = self._handle_network_device_event
        self.integration_handlers[IntegrationType.CUSTOM.value] = self._handle_custom_event
    
    async def _handle_itsm_event(self, integration: IntegrationConfig, event: IntegrationEvent) -> bool:
        """Handle ITSM integration events (ServiceNow, Jira, etc.)"""
        try:
            if event.event_type == "create_incident":
                return await self._create_itsm_incident(integration, event)
            elif event.event_type == "update_incident":
                return await self._update_itsm_incident(integration, event)
            elif event.event_type == "create_change_request":
                return await self._create_itsm_change_request(integration, event)
            else:
                logger.warning(f"Unknown ITSM event type: {event.event_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error handling ITSM event: {e}")
            return False
    
    async def _handle_siem_event(self, integration: IntegrationConfig, event: IntegrationEvent) -> bool:
        """Handle SIEM integration events"""
        try:
            if event.event_type in ["security_alert", "security_incident", "vulnerability_detected"]:
                return await self._send_siem_event(integration, event)
            else:
                logger.warning(f"Unknown SIEM event type: {event.event_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error handling SIEM event: {e}")
            return False
    
    async def _handle_monitoring_event(self, integration: IntegrationConfig, event: IntegrationEvent) -> bool:
        """Handle monitoring tool integration events (Prometheus, Grafana, etc.)"""
        try:
            if event.event_type == "send_metrics":
                return await self._send_metrics_to_monitoring_system(integration, event)
            elif event.event_type == "create_alert":
                return await self._create_monitoring_alert(integration, event)
            else:
                logger.warning(f"Unknown monitoring event type: {event.event_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error handling monitoring event: {e}")
            return False
    
    async def _handle_cloud_event(self, integration: IntegrationConfig, event: IntegrationEvent) -> bool:
        """Handle cloud platform integration events (AWS, Azure, GCP)"""
        try:
            if event.event_type == "send_cloudwatch_metrics":
                return await self._send_cloudwatch_metrics(integration, event)
            elif event.event_type == "create_cloud_alert":
                return await self._create_cloud_alert(integration, event)
            else:
                logger.warning(f"Unknown cloud event type: {event.event_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error handling cloud event: {e}")
            return False
    
    async def _handle_communication_event(self, integration: IntegrationConfig, event: IntegrationEvent) -> bool:
        """Handle communication platform events (Slack, Teams, etc.)"""
        try:
            if event.event_type == "send_message":
                return await self._send_communication_message(integration, event)
            elif event.event_type == "create_channel":
                return await self._create_communication_channel(integration, event)
            else:
                logger.warning(f"Unknown communication event type: {event.event_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error handling communication event: {e}")
            return False
    
    async def _handle_network_device_event(self, integration: IntegrationConfig, event: IntegrationEvent) -> bool:
        """Handle network device integration events"""
        try:
            if event.event_type == "configure_device":
                return await self._configure_network_device(integration, event)
            elif event.event_type == "query_device":
                return await self._query_network_device(integration, event)
            else:
                logger.warning(f"Unknown network device event type: {event.event_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error handling network device event: {e}")
            return False
    
    async def _handle_custom_event(self, integration: IntegrationConfig, event: IntegrationEvent) -> bool:
        """Handle custom integration events"""
        try:
            # Generic HTTP POST for custom integrations
            return await self._send_custom_http_request(integration, event)
            
        except Exception as e:
            logger.error(f"Error handling custom event: {e}")
            return False
    
    async def _create_itsm_incident(self, integration: IntegrationConfig, event: IntegrationEvent) -> bool:
        """Create an incident in ITSM system"""
        try:
            # Prepare incident data
            incident_data = {
                "summary": event.data.get("title", "HomeNetMon Alert"),
                "description": event.data.get("description", ""),
                "priority": self._map_severity_to_priority(event.data.get("severity", "medium")),
                "category": "Network",
                "subcategory": "Monitoring",
                "caller_id": integration.custom_config.get("default_caller", "homenetmon"),
                "assignment_group": integration.custom_config.get("assignment_group", "Network Operations"),
                "source": "HomeNetMon"
            }
            
            # Apply field mappings
            if integration.field_mappings:
                incident_data = self._apply_field_mappings(incident_data, integration.field_mappings)
            
            # Send to ITSM system
            headers = await self._get_auth_headers(integration)
            headers["Content-Type"] = "application/json"
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=integration.timeout_seconds)) as session:
                url = urljoin(integration.base_url, "/api/now/table/incident")
                
                async with session.post(url, json=incident_data, headers=headers) as response:
                    if response.status in [200, 201]:
                        result = await response.json()
                        incident_number = result.get("result", {}).get("number")
                        logger.info(f"Created ITSM incident {incident_number}")
                        return True
                    else:
                        logger.error(f"Failed to create ITSM incident: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Error creating ITSM incident: {e}")
            return False
    
    async def _send_siem_event(self, integration: IntegrationConfig, event: IntegrationEvent) -> bool:
        """Send security event to SIEM system"""
        try:
            # Prepare SIEM event data
            siem_event = {
                "timestamp": event.timestamp.isoformat(),
                "source": "HomeNetMon",
                "event_type": event.event_type,
                "severity": event.data.get("severity", "medium"),
                "category": "Network Security",
                "device_ip": event.data.get("device_ip"),
                "device_name": event.data.get("device_name"),
                "description": event.data.get("description"),
                "raw_data": event.data
            }
            
            # Send to SIEM system (example format for generic SIEM)
            headers = await self._get_auth_headers(integration)
            headers["Content-Type"] = "application/json"
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=integration.timeout_seconds)) as session:
                url = urljoin(integration.base_url, "/api/events")
                
                async with session.post(url, json=siem_event, headers=headers) as response:
                    if response.status in [200, 201, 202]:
                        logger.info(f"Sent SIEM event {event.event_id}")
                        return True
                    else:
                        logger.error(f"Failed to send SIEM event: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Error sending SIEM event: {e}")
            return False
    
    async def _send_communication_message(self, integration: IntegrationConfig, event: IntegrationEvent) -> bool:
        """Send message to communication platform (Slack, Teams, etc.)"""
        try:
            # Prepare message data
            message_data = {
                "text": event.data.get("message", "HomeNetMon Alert"),
                "channel": event.data.get("channel") or integration.custom_config.get("default_channel"),
                "username": "HomeNetMon",
                "icon_emoji": ":warning:"
            }
            
            # Format message based on platform
            platform = integration.custom_config.get("platform", "slack").lower()
            
            if platform == "slack":
                # Slack-specific formatting
                if event.data.get("severity") == "critical":
                    message_data["icon_emoji"] = ":red_circle:"
                elif event.data.get("severity") == "high":
                    message_data["icon_emoji"] = ":large_orange_diamond:"
                
                # Add attachments for rich formatting
                if event.data.get("details"):
                    message_data["attachments"] = [{
                        "color": self._get_severity_color(event.data.get("severity", "medium")),
                        "fields": [
                            {"title": "Device", "value": event.data.get("device_name", "Unknown"), "short": True},
                            {"title": "Time", "value": event.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "short": True}
                        ]
                    }]
            
            elif platform == "teams":
                # Microsoft Teams formatting
                message_data = {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "themeColor": self._get_severity_color(event.data.get("severity", "medium")),
                    "summary": event.data.get("message", "HomeNetMon Alert"),
                    "sections": [{
                        "activityTitle": "HomeNetMon Alert",
                        "activitySubtitle": event.data.get("message", ""),
                        "facts": [
                            {"name": "Device", "value": event.data.get("device_name", "Unknown")},
                            {"name": "Severity", "value": event.data.get("severity", "medium")},
                            {"name": "Time", "value": event.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
                        ]
                    }]
                }
            
            # Send message
            headers = await self._get_auth_headers(integration)
            headers["Content-Type"] = "application/json"
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=integration.timeout_seconds)) as session:
                async with session.post(integration.base_url, json=message_data, headers=headers) as response:
                    if response.status in [200, 201, 202]:
                        logger.info(f"Sent communication message for event {event.event_id}")
                        return True
                    else:
                        logger.error(f"Failed to send communication message: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Error sending communication message: {e}")
            return False
    
    async def _send_custom_http_request(self, integration: IntegrationConfig, event: IntegrationEvent) -> bool:
        """Send custom HTTP request for generic integrations"""
        try:
            # Prepare request data
            request_data = {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "source": event.source_system,
                "event_type": event.event_type,
                "data": event.data
            }
            
            # Apply field mappings if configured
            if integration.field_mappings:
                request_data = self._apply_field_mappings(request_data, integration.field_mappings)
            
            # Get HTTP method from config (default to POST)
            method = integration.custom_config.get("method", "POST").upper()
            
            # Prepare headers
            headers = await self._get_auth_headers(integration)
            headers["Content-Type"] = "application/json"
            
            # Add custom headers if configured
            if integration.custom_config.get("headers"):
                headers.update(integration.custom_config["headers"])
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=integration.timeout_seconds)) as session:
                endpoint = integration.custom_config.get("endpoint", "/api/events")
                url = urljoin(integration.base_url, endpoint)
                
                if method == "POST":
                    async with session.post(url, json=request_data, headers=headers) as response:
                        success = response.status in [200, 201, 202]
                elif method == "PUT":
                    async with session.put(url, json=request_data, headers=headers) as response:
                        success = response.status in [200, 201, 204]
                else:
                    logger.error(f"Unsupported HTTP method: {method}")
                    return False
                
                if success:
                    logger.info(f"Sent custom HTTP request for event {event.event_id}")
                    return True
                else:
                    logger.error(f"Failed to send custom HTTP request: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error sending custom HTTP request: {e}")
            return False
    
    async def _get_auth_headers(self, integration: IntegrationConfig) -> Dict[str, str]:
        """Get authentication headers for integration"""
        headers = {}
        
        try:
            if integration.auth_method == AuthMethod.API_KEY:
                api_key = integration.auth_config.get("api_key")
                header_name = integration.auth_config.get("header_name", "X-API-Key")
                if api_key:
                    headers[header_name] = api_key
            
            elif integration.auth_method == AuthMethod.BEARER_TOKEN:
                token = integration.auth_config.get("token")
                if token:
                    headers["Authorization"] = f"Bearer {token}"
            
            elif integration.auth_method == AuthMethod.BASIC_AUTH:
                username = integration.auth_config.get("username")
                password = integration.auth_config.get("password")
                if username and password:
                    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                    headers["Authorization"] = f"Basic {credentials}"
            
            elif integration.auth_method == AuthMethod.JWT:
                jwt_token = await self._get_jwt_token(integration)
                if jwt_token:
                    headers["Authorization"] = f"Bearer {jwt_token}"
            
            elif integration.auth_method == AuthMethod.OAUTH2:
                access_token = await self._get_oauth2_token(integration)
                if access_token:
                    headers["Authorization"] = f"Bearer {access_token}"
            
        except Exception as e:
            logger.error(f"Error getting auth headers for {integration.integration_id}: {e}")
        
        return headers
    
    async def _get_jwt_token(self, integration: IntegrationConfig) -> Optional[str]:
        """Get JWT token for authentication"""
        # Implementation would depend on specific JWT requirements
        # This is a placeholder for JWT token generation/retrieval
        return integration.auth_config.get("jwt_token")
    
    async def _get_oauth2_token(self, integration: IntegrationConfig) -> Optional[str]:
        """Get OAuth2 access token"""
        # Check cache first
        cache_key = f"{integration.integration_id}_oauth2_token"
        if cache_key in self.auth_cache:
            cached_token = self.auth_cache[cache_key]
            if cached_token["expires_at"] > datetime.utcnow():
                return cached_token["access_token"]
        
        # Get new token
        try:
            token_url = integration.auth_config.get("token_url")
            client_id = integration.auth_config.get("client_id")
            client_secret = integration.auth_config.get("client_secret")
            
            if not all([token_url, client_id, client_secret]):
                return None
            
            data = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(token_url, data=data) as response:
                    if response.status == 200:
                        token_data = await response.json()
                        access_token = token_data.get("access_token")
                        expires_in = token_data.get("expires_in", 3600)
                        
                        # Cache the token
                        self.auth_cache[cache_key] = {
                            "access_token": access_token,
                            "expires_at": datetime.utcnow() + timedelta(seconds=expires_in - 60)  # 1 minute buffer
                        }
                        
                        return access_token
            
        except Exception as e:
            logger.error(f"Error getting OAuth2 token: {e}")
        
        return None
    
    def _check_rate_limit(self, integration_id: str) -> bool:
        """Check if request is within rate limits"""
        try:
            rate_limiter = self.rate_limiters.get(integration_id)
            if not rate_limiter:
                return True
            
            current_time = time.time()
            window_start = current_time - rate_limiter["window"]
            
            # Remove old requests
            rate_limiter["requests"] = [
                req_time for req_time in rate_limiter["requests"]
                if req_time > window_start
            ]
            
            # Check if under limit
            if len(rate_limiter["requests"]) < rate_limiter["limit"]:
                rate_limiter["requests"].append(current_time)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {e}")
            return True  # Allow request if check fails
    
    def _apply_field_mappings(self, data: Dict[str, Any], mappings: Dict[str, str]) -> Dict[str, Any]:
        """Apply field mappings to transform data"""
        try:
            mapped_data = {}
            
            for source_field, target_field in mappings.items():
                if source_field in data:
                    mapped_data[target_field] = data[source_field]
                else:
                    # Keep original field if mapping source doesn't exist
                    if source_field in data:
                        mapped_data[source_field] = data[source_field]
            
            # Add any fields not in mappings
            for key, value in data.items():
                if key not in mappings and key not in mapped_data:
                    mapped_data[key] = value
            
            return mapped_data
            
        except Exception as e:
            logger.error(f"Error applying field mappings: {e}")
            return data
    
    def _map_severity_to_priority(self, severity: str) -> str:
        """Map HomeNetMon severity to ITSM priority"""
        severity_mapping = {
            "critical": "1 - Critical",
            "high": "2 - High",
            "medium": "3 - Medium",
            "low": "4 - Low"
        }
        return severity_mapping.get(severity.lower(), "3 - Medium")
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity level"""
        color_mapping = {
            "critical": "#FF0000",  # Red
            "high": "#FF8C00",      # Orange
            "medium": "#FFD700",    # Yellow
            "low": "#32CD32"        # Green
        }
        return color_mapping.get(severity.lower(), "#808080")  # Gray for unknown
    
    async def _test_integration_connection(self, integration: IntegrationConfig) -> bool:
        """Test connection to external system"""
        try:
            headers = await self._get_auth_headers(integration)
            
            # Try to make a simple request
            test_endpoint = integration.custom_config.get("health_endpoint", "/api/health")
            url = urljoin(integration.base_url, test_endpoint)
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=integration.timeout_seconds)) as session:
                async with session.get(url, headers=headers) as response:
                    return response.status in [200, 201, 202, 401, 403]  # Accept auth errors as connection success
                    
        except Exception as e:
            logger.debug(f"Connection test failed for {integration.integration_id}: {e}")
            return False
    
    async def _perform_health_checks(self):
        """Perform health checks on all integrations"""
        for integration_id, integration in self.integrations.items():
            if integration.enabled:
                try:
                    is_healthy = await self._test_integration_connection(integration)
                    # Update integration status based on health check
                    # This could be stored in a status field if added to IntegrationConfig
                    
                except Exception as e:
                    logger.error(f"Health check failed for {integration_id}: {e}")
    
    def _cleanup_auth_cache(self):
        """Clean up expired authentication cache entries"""
        try:
            current_time = datetime.utcnow()
            expired_keys = []
            
            for key, cached_data in self.auth_cache.items():
                if cached_data.get("expires_at", current_time) <= current_time:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.auth_cache[key]
                
        except Exception as e:
            logger.error(f"Error cleaning up auth cache: {e}")
    
    def _validate_integration_config(self, config: IntegrationConfig) -> bool:
        """Validate integration configuration"""
        try:
            # Check required fields
            if not config.integration_id or not config.name:
                return False
            
            # Validate URL if provided
            if config.base_url:
                parsed = urlparse(config.base_url)
                if not parsed.scheme or not parsed.netloc:
                    return False
            
            # Validate auth configuration
            if config.auth_method and config.auth_config:
                required_fields = {
                    AuthMethod.API_KEY: ["api_key"],
                    AuthMethod.BASIC_AUTH: ["username", "password"],
                    AuthMethod.BEARER_TOKEN: ["token"],
                    AuthMethod.OAUTH2: ["client_id", "client_secret", "token_url"]
                }
                
                if config.auth_method in required_fields:
                    for field in required_fields[config.auth_method]:
                        if field not in config.auth_config:
                            logger.error(f"Missing required auth field: {field}")
                            return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating integration config: {e}")
            return False
    
    # Public API methods
    
    def get_integrations_summary(self) -> Dict[str, Any]:
        """Get summary of all integrations"""
        try:
            integrations_data = []
            
            for integration_id, integration in self.integrations.items():
                stats = self.integration_stats.get(integration_id, IntegrationStats(integration_id=integration_id))
                
                integrations_data.append({
                    "integration_id": integration_id,
                    "name": integration.name,
                    "type": integration.integration_type.value,
                    "enabled": integration.enabled,
                    "total_requests": stats.total_requests,
                    "success_rate": (stats.successful_requests / stats.total_requests * 100) if stats.total_requests > 0 else 0,
                    "last_success": stats.last_success_time.isoformat() + 'Z' if stats.last_success_time else None,
                    "last_error": stats.last_error_time.isoformat() + 'Z' if stats.last_error_time else None,
                    "avg_response_time": stats.average_response_time_ms
                })
            
            return {
                "integrations": integrations_data,
                "total_integrations": len(self.integrations),
                "enabled_integrations": sum(1 for i in self.integrations.values() if i.enabled),
                "events_in_queue": len(self.event_queue)
            }
            
        except Exception as e:
            logger.error(f"Error getting integrations summary: {e}")
            return {"integrations": [], "total_integrations": 0, "enabled_integrations": 0, "events_in_queue": 0}
    
    def get_integration_stats(self, integration_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed statistics for a specific integration"""
        try:
            if integration_id not in self.integrations:
                return None
            
            integration = self.integrations[integration_id]
            stats = self.integration_stats.get(integration_id, IntegrationStats(integration_id=integration_id))
            
            return {
                "integration": asdict(integration),
                "statistics": asdict(stats),
                "rate_limit_info": {
                    "requests_in_window": len(self.rate_limiters.get(integration_id, {}).get("requests", [])),
                    "limit": integration.rate_limit_requests,
                    "window_seconds": integration.rate_limit_window_seconds
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting integration stats: {e}")
            return None
    
    def get_manager_status(self) -> Dict[str, Any]:
        """Get integration manager status"""
        return {
            "running": self.running,
            "total_integrations": len(self.integrations),
            "events_in_queue": len(self.event_queue),
            "auth_cache_entries": len(self.auth_cache),
            "configuration": self.config
        }


# Global integration manager instance
integration_manager = ExternalSystemIntegrationManager()