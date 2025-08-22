"""
Multi-Site & Distributed Monitoring Manager

This module provides comprehensive multi-site monitoring capabilities for HomeNetMon:

1. Multi-site network topology management
2. Remote site connectivity and health monitoring
3. Cross-site performance comparison and analytics
4. Distributed alerting and notification system
5. Site-to-site network quality monitoring
6. Centralized configuration management across sites
7. Multi-site data aggregation and reporting
8. Inter-site communication and synchronization
"""

import asyncio
import threading
import time
import logging
import requests
import websockets
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import json
import socket
import aiohttp
import ssl
from urllib.parse import urlparse

from models import db, Device, MonitoringData
from services.notification import notification_service

logger = logging.getLogger(__name__)


class SiteStatus(Enum):
    """Site operational status"""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    UNKNOWN = "unknown"


class SiteType(Enum):
    """Types of monitored sites"""
    PRIMARY = "primary"          # Main headquarters/datacenter
    BRANCH = "branch"           # Branch offices
    REMOTE = "remote"           # Remote locations
    CLOUD = "cloud"             # Cloud deployments
    EDGE = "edge"               # Edge computing locations
    MOBILE = "mobile"           # Mobile/temporary sites


class ConnectionType(Enum):
    """Types of inter-site connections"""
    VPN = "vpn"
    MPLS = "mpls"
    INTERNET = "internet"
    DIRECT = "direct"
    SATELLITE = "satellite"
    CELLULAR = "cellular"


class SyncMethod(Enum):
    """Methods for data synchronization"""
    REST_API = "rest_api"
    WEBSOCKET = "websocket"
    WEBHOOK = "webhook"
    MESSAGE_QUEUE = "message_queue"
    DATABASE_REPLICATION = "database_replication"


@dataclass
class Site:
    """Represents a monitored site/location"""
    site_id: str
    name: str
    description: str
    site_type: SiteType
    
    # Location information
    address: str
    city: str
    state: str
    country: str
    timezone: str
    coordinates: Optional[Tuple[float, float]] = None
    
    # Network configuration
    primary_network: str  # CIDR notation
    secondary_networks: List[str] = None
    gateway_ip: str = None
    dns_servers: List[str] = None
    
    # HomeNetMon instance configuration
    homenetmon_url: str = None
    api_key: str = None
    version: str = None
    
    # Connection configuration
    connection_types: List[ConnectionType] = None
    vpn_endpoints: List[str] = None
    
    # Operational status
    status: SiteStatus = SiteStatus.UNKNOWN
    last_seen: Optional[datetime] = None
    uptime_percentage: float = 0.0
    
    # Performance metrics
    avg_latency_ms: float = 0.0
    bandwidth_mbps: float = 0.0
    device_count: int = 0
    alert_count: int = 0


@dataclass
class InterSiteConnection:
    """Represents a connection between two sites"""
    connection_id: str
    source_site_id: str
    destination_site_id: str
    connection_type: ConnectionType
    
    # Connection details
    source_endpoint: str
    destination_endpoint: str
    bandwidth_mbps: float = 0.0
    
    # Quality metrics
    latency_ms: float = 0.0
    jitter_ms: float = 0.0
    packet_loss_percent: float = 0.0
    uptime_percentage: float = 0.0
    
    # Status and monitoring
    status: str = "unknown"  # up, down, degraded
    last_tested: Optional[datetime] = None
    test_interval_seconds: int = 300  # 5 minutes
    
    # Configuration
    monitoring_enabled: bool = True
    alert_thresholds: Dict[str, float] = None


@dataclass
class SiteMetrics:
    """Aggregated metrics for a site"""
    site_id: str
    timestamp: datetime
    
    # Device metrics
    total_devices: int
    online_devices: int
    offline_devices: int
    
    # Performance metrics
    avg_response_time_ms: float
    max_response_time_ms: float
    packet_loss_percentage: float
    uptime_percentage: float
    
    # Alert metrics
    active_alerts: int
    critical_alerts: int
    high_alerts: int
    
    # Bandwidth metrics
    total_bandwidth_mbps: float
    bandwidth_utilization_percent: float
    
    # Site health score (0-100)
    health_score: float


@dataclass
class CrossSiteAlert:
    """Alert that affects multiple sites or inter-site connectivity"""
    alert_id: str
    title: str
    description: str
    severity: str
    
    # Affected sites
    affected_sites: List[str]
    impact_scope: str  # local, regional, global
    
    # Alert details
    alert_type: str  # connectivity, performance, security, etc.
    detected_at: datetime
    resolved_at: Optional[datetime] = None
    
    # Response information
    escalated: bool = False
    assigned_to: str = None
    status: str = "active"  # active, acknowledged, resolved


class MultiSiteManager:
    """
    Manages monitoring across multiple network sites with centralized coordination,
    performance comparison, and distributed alerting capabilities.
    """
    
    def __init__(self, app=None):
        self.app = app
        self.running = False
        self.monitoring_thread = None
        self.sync_thread = None
        
        # Site management
        self.sites: Dict[str, Site] = {}
        self.inter_site_connections: Dict[str, InterSiteConnection] = {}
        self.site_metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Configuration
        self.config = {
            'monitoring_interval': 60,  # seconds
            'sync_interval': 300,       # 5 minutes
            'health_check_timeout': 30,  # seconds
            'max_concurrent_checks': 10,
            'alert_consolidation_window': 300,  # 5 minutes
            'cross_site_thresholds': {
                'latency_ms': 200,
                'packet_loss_percent': 2.0,
                'uptime_percent': 95.0
            }
        }
        
        # Alerting and communication
        self.cross_site_alerts: Dict[str, CrossSiteAlert] = {}
        self.alert_consolidation_queue = deque(maxlen=1000)
        
        # Performance tracking
        self.performance_baselines: Dict[str, Dict[str, float]] = {}
        self.site_comparison_data = {}
        
        # Statistics
        self.statistics = {
            'total_sites': 0,
            'online_sites': 0,
            'total_connections': 0,
            'active_connections': 0,
            'total_devices_all_sites': 0,
            'last_sync': None,
            'sync_errors': 0,
            'cross_site_alerts': 0
        }
    
    def start_monitoring(self):
        """Start multi-site monitoring"""
        if self.running:
            logger.warning("Multi-site manager is already running")
            return
        
        self.running = True
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        # Start synchronization thread
        self.sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self.sync_thread.start()
        
        logger.info("Multi-site monitoring started")
    
    def stop_monitoring(self):
        """Stop multi-site monitoring"""
        self.running = False
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=30)
        
        if self.sync_thread and self.sync_thread.is_alive():
            self.sync_thread.join(timeout=30)
        
        logger.info("Multi-site monitoring stopped")
    
    def add_site(self, site: Site) -> bool:
        """Add a new site to monitoring"""
        try:
            # Validate site configuration
            if not self._validate_site_config(site):
                logger.error(f"Invalid site configuration for {site.site_id}")
                return False
            
            # Test connectivity to site
            if site.homenetmon_url and not self._test_site_connectivity(site):
                logger.warning(f"Cannot connect to site {site.site_id}, adding anyway")
            
            # Add site to registry
            self.sites[site.site_id] = site
            self.site_metrics_history[site.site_id] = deque(maxlen=1000)
            
            # Initialize performance baselines
            self.performance_baselines[site.site_id] = {}
            
            logger.info(f"Added site {site.site_id} ({site.name}) to monitoring")
            self._update_statistics()
            
            return True
            
        except Exception as e:
            logger.error(f"Error adding site {site.site_id}: {e}")
            return False
    
    def remove_site(self, site_id: str) -> bool:
        """Remove a site from monitoring"""
        try:
            if site_id not in self.sites:
                logger.warning(f"Site {site_id} not found")
                return False
            
            # Remove associated connections
            connections_to_remove = [
                conn_id for conn_id, conn in self.inter_site_connections.items()
                if conn.source_site_id == site_id or conn.destination_site_id == site_id
            ]
            
            for conn_id in connections_to_remove:
                del self.inter_site_connections[conn_id]
            
            # Remove site data
            del self.sites[site_id]
            if site_id in self.site_metrics_history:
                del self.site_metrics_history[site_id]
            if site_id in self.performance_baselines:
                del self.performance_baselines[site_id]
            
            logger.info(f"Removed site {site_id} from monitoring")
            self._update_statistics()
            
            return True
            
        except Exception as e:
            logger.error(f"Error removing site {site_id}: {e}")
            return False
    
    def add_inter_site_connection(self, connection: InterSiteConnection) -> bool:
        """Add an inter-site connection for monitoring"""
        try:
            # Validate connection
            if (connection.source_site_id not in self.sites or 
                connection.destination_site_id not in self.sites):
                logger.error(f"Invalid site IDs in connection {connection.connection_id}")
                return False
            
            # Set default alert thresholds if not provided
            if not connection.alert_thresholds:
                connection.alert_thresholds = self.config['cross_site_thresholds'].copy()
            
            self.inter_site_connections[connection.connection_id] = connection
            
            logger.info(f"Added inter-site connection {connection.connection_id}")
            self._update_statistics()
            
            return True
            
        except Exception as e:
            logger.error(f"Error adding inter-site connection: {e}")
            return False
    
    def _monitoring_loop(self):
        """Main monitoring loop for all sites"""
        logger.info("Starting multi-site monitoring loop")
        
        while self.running:
            try:
                start_time = time.time()
                
                # Monitor all sites concurrently
                asyncio.run(self._monitor_all_sites())
                
                # Monitor inter-site connections
                asyncio.run(self._monitor_inter_site_connections())
                
                # Process alerts and consolidation
                self._process_cross_site_alerts()
                
                # Update statistics
                self._update_statistics()
                
                # Calculate sleep time
                monitoring_duration = time.time() - start_time
                sleep_time = max(0, self.config['monitoring_interval'] - monitoring_duration)
                time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Error in multi-site monitoring loop: {e}")
                time.sleep(30)
    
    def _sync_loop(self):
        """Synchronization loop for data exchange between sites"""
        logger.info("Starting multi-site synchronization loop")
        
        while self.running:
            try:
                # Synchronize with all sites
                asyncio.run(self._sync_all_sites())
                
                # Update sync timestamp
                self.statistics['last_sync'] = datetime.utcnow()
                
                time.sleep(self.config['sync_interval'])
                
            except Exception as e:
                logger.error(f"Error in synchronization loop: {e}")
                self.statistics['sync_errors'] += 1
                time.sleep(60)
    
    async def _monitor_all_sites(self):
        """Monitor all registered sites concurrently"""
        tasks = []
        semaphore = asyncio.Semaphore(self.config['max_concurrent_checks'])
        
        for site_id, site in self.sites.items():
            task = asyncio.create_task(self._monitor_site(semaphore, site))
            tasks.append(task)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _monitor_site(self, semaphore: asyncio.Semaphore, site: Site):
        """Monitor a specific site"""
        async with semaphore:
            try:
                # Test basic connectivity
                site_online = await self._test_site_connectivity_async(site)
                
                if site_online:
                    site.status = SiteStatus.ONLINE
                    site.last_seen = datetime.utcnow()
                    
                    # Collect detailed metrics if HomeNetMon instance is available
                    if site.homenetmon_url:
                        metrics = await self._collect_site_metrics(site)
                        if metrics:
                            self.site_metrics_history[site.site_id].append(metrics)
                            
                            # Update site summary information
                            site.device_count = metrics.total_devices
                            site.alert_count = metrics.active_alerts
                            site.avg_latency_ms = metrics.avg_response_time_ms
                else:
                    site.status = SiteStatus.OFFLINE
                
                # Calculate uptime percentage
                self._update_site_uptime(site)
                
            except Exception as e:
                logger.error(f"Error monitoring site {site.site_id}: {e}")
                site.status = SiteStatus.UNKNOWN
    
    async def _monitor_inter_site_connections(self):
        """Monitor all inter-site connections"""
        tasks = []
        semaphore = asyncio.Semaphore(self.config['max_concurrent_checks'])
        
        for conn_id, connection in self.inter_site_connections.items():
            if connection.monitoring_enabled:
                task = asyncio.create_task(self._test_inter_site_connection(semaphore, connection))
                tasks.append(task)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _test_inter_site_connection(self, semaphore: asyncio.Semaphore, 
                                        connection: InterSiteConnection):
        """Test connectivity between two sites"""
        async with semaphore:
            try:
                # Ping test between endpoints
                latency = await self._ping_endpoint(connection.destination_endpoint)
                
                if latency is not None:
                    connection.latency_ms = latency
                    connection.status = "up"
                    connection.last_tested = datetime.utcnow()
                    
                    # Check against thresholds
                    if (connection.alert_thresholds and 
                        latency > connection.alert_thresholds.get('latency_ms', 200)):
                        self._create_connection_alert(connection, 'high_latency', latency)
                else:
                    connection.status = "down"
                    self._create_connection_alert(connection, 'connection_down', None)
                
                # Update connection uptime
                self._update_connection_uptime(connection)
                
            except Exception as e:
                logger.error(f"Error testing connection {connection.connection_id}: {e}")
                connection.status = "unknown"
    
    async def _sync_all_sites(self):
        """Synchronize data with all sites"""
        for site_id, site in self.sites.items():
            if site.homenetmon_url and site.status == SiteStatus.ONLINE:
                try:
                    await self._sync_with_site(site)
                except Exception as e:
                    logger.error(f"Error syncing with site {site_id}: {e}")
                    self.statistics['sync_errors'] += 1
    
    async def _sync_with_site(self, site: Site):
        """Synchronize data with a specific site"""
        try:
            headers = {}
            if site.api_key:
                headers['Authorization'] = f'Bearer {site.api_key}'
            
            timeout = aiohttp.ClientTimeout(total=self.config['health_check_timeout'])
            
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                # Get site status and basic info
                async with session.get(f"{site.homenetmon_url}/api/status") as response:
                    if response.status == 200:
                        status_data = await response.json()
                        site.version = status_data.get('version', 'unknown')
                        
                # Sync configuration if needed
                # This could include alerting rules, device configurations, etc.
                
                # Exchange important alerts
                await self._exchange_alerts_with_site(session, site)
                
        except Exception as e:
            logger.error(f"Error during sync with site {site.site_id}: {e}")
            raise
    
    async def _exchange_alerts_with_site(self, session: aiohttp.ClientSession, site: Site):
        """Exchange alert information with a remote site"""
        try:
            # Get critical alerts from remote site
            async with session.get(f"{site.homenetmon_url}/api/alerts?severity=critical&limit=10") as response:
                if response.status == 200:
                    alerts_data = await response.json()
                    
                    # Process remote alerts for cross-site correlation
                    for alert in alerts_data.get('alerts', []):
                        self._process_remote_alert(site, alert)
                        
        except Exception as e:
            logger.debug(f"Error exchanging alerts with site {site.site_id}: {e}")
    
    async def _collect_site_metrics(self, site: Site) -> Optional[SiteMetrics]:
        """Collect comprehensive metrics from a site"""
        try:
            headers = {}
            if site.api_key:
                headers['Authorization'] = f'Bearer {site.api_key}'
            
            timeout = aiohttp.ClientTimeout(total=self.config['health_check_timeout'])
            
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                # Collect device summary
                async with session.get(f"{site.homenetmon_url}/api/devices/summary") as response:
                    if response.status != 200:
                        return None
                    
                    device_summary = await response.json()
                
                # Collect performance summary
                async with session.get(f"{site.homenetmon_url}/api/performance/summary") as response:
                    perf_summary = {}
                    if response.status == 200:
                        perf_summary = await response.json()
                
                # Collect alert summary
                async with session.get(f"{site.homenetmon_url}/api/alerts/summary") as response:
                    alert_summary = {}
                    if response.status == 200:
                        alert_summary = await response.json()
                
                # Create metrics object
                metrics = SiteMetrics(
                    site_id=site.site_id,
                    timestamp=datetime.utcnow(),
                    total_devices=device_summary.get('total_devices', 0),
                    online_devices=device_summary.get('online_devices', 0),
                    offline_devices=device_summary.get('offline_devices', 0),
                    avg_response_time_ms=perf_summary.get('avg_response_time', 0.0),
                    max_response_time_ms=perf_summary.get('max_response_time', 0.0),
                    packet_loss_percentage=perf_summary.get('packet_loss_percent', 0.0),
                    uptime_percentage=perf_summary.get('uptime_percent', 0.0),
                    active_alerts=alert_summary.get('active_count', 0),
                    critical_alerts=alert_summary.get('critical_count', 0),
                    high_alerts=alert_summary.get('high_count', 0),
                    total_bandwidth_mbps=perf_summary.get('bandwidth_mbps', 0.0),
                    bandwidth_utilization_percent=perf_summary.get('bandwidth_utilization', 0.0),
                    health_score=self._calculate_site_health_score(device_summary, perf_summary, alert_summary)
                )
                
                return metrics
                
        except Exception as e:
            logger.error(f"Error collecting metrics from site {site.site_id}: {e}")
            return None
    
    def _calculate_site_health_score(self, device_summary: Dict, 
                                   perf_summary: Dict, alert_summary: Dict) -> float:
        """Calculate overall health score for a site (0-100)"""
        try:
            score = 100.0
            
            # Device availability (30% weight)
            total_devices = device_summary.get('total_devices', 1)
            online_devices = device_summary.get('online_devices', 0)
            device_availability = (online_devices / total_devices) * 100 if total_devices > 0 else 100
            score -= (100 - device_availability) * 0.3
            
            # Performance metrics (40% weight)
            avg_latency = perf_summary.get('avg_response_time', 0)
            packet_loss = perf_summary.get('packet_loss_percent', 0)
            
            # Latency penalty
            if avg_latency > 100:
                score -= min(20, (avg_latency - 100) / 10) * 0.2
            
            # Packet loss penalty  
            if packet_loss > 0:
                score -= min(30, packet_loss * 10) * 0.2
            
            # Alert impact (30% weight)
            critical_alerts = alert_summary.get('critical_count', 0)
            high_alerts = alert_summary.get('high_count', 0)
            
            score -= critical_alerts * 10 * 0.3
            score -= high_alerts * 5 * 0.3
            
            return max(0.0, min(100.0, score))
            
        except Exception as e:
            logger.error(f"Error calculating site health score: {e}")
            return 50.0  # Default to neutral score
    
    async def _test_site_connectivity_async(self, site: Site) -> bool:
        """Test basic connectivity to a site asynchronously"""
        try:
            if not site.homenetmon_url:
                # If no URL provided, try to ping the gateway
                if site.gateway_ip:
                    latency = await self._ping_endpoint(site.gateway_ip)
                    return latency is not None
                return False
            
            # Test HTTP connectivity to HomeNetMon instance
            timeout = aiohttp.ClientTimeout(total=self.config['health_check_timeout'])
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"{site.homenetmon_url}/api/health") as response:
                    return response.status == 200
                    
        except Exception:
            return False
    
    def _test_site_connectivity(self, site: Site) -> bool:
        """Test basic connectivity to a site (synchronous)"""
        try:
            if not site.homenetmon_url:
                return False
            
            response = requests.get(
                f"{site.homenetmon_url}/api/health",
                timeout=self.config['health_check_timeout']
            )
            return response.status_code == 200
            
        except Exception:
            return False
    
    async def _ping_endpoint(self, endpoint: str) -> Optional[float]:
        """Ping an endpoint and return latency in milliseconds"""
        try:
            # Extract hostname/IP from endpoint if it's a URL
            if endpoint.startswith(('http://', 'https://')):
                parsed = urlparse(endpoint)
                hostname = parsed.hostname
            else:
                hostname = endpoint
            
            # Use system ping command (simplified)
            import subprocess
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '3000', hostname],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse ping output for latency
                output = result.stdout
                if 'time=' in output:
                    latency_str = output.split('time=')[1].split()[0]
                    return float(latency_str)
            
            return None
            
        except Exception as e:
            logger.debug(f"Error pinging {endpoint}: {e}")
            return None
    
    def _validate_site_config(self, site: Site) -> bool:
        """Validate site configuration"""
        try:
            # Check required fields
            if not site.site_id or not site.name:
                return False
            
            # Validate network configuration
            if site.primary_network:
                import ipaddress
                ipaddress.ip_network(site.primary_network)
            
            # Validate URL if provided
            if site.homenetmon_url:
                parsed = urlparse(site.homenetmon_url)
                if not parsed.scheme or not parsed.netloc:
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _update_site_uptime(self, site: Site):
        """Update site uptime percentage"""
        try:
            # Simple uptime calculation based on recent status
            # In a real implementation, this would use historical data
            if site.status == SiteStatus.ONLINE:
                site.uptime_percentage = min(100.0, site.uptime_percentage + 0.1)
            else:
                site.uptime_percentage = max(0.0, site.uptime_percentage - 1.0)
                
        except Exception as e:
            logger.error(f"Error updating site uptime: {e}")
    
    def _update_connection_uptime(self, connection: InterSiteConnection):
        """Update inter-site connection uptime"""
        try:
            if connection.status == "up":
                connection.uptime_percentage = min(100.0, connection.uptime_percentage + 0.1)
            else:
                connection.uptime_percentage = max(0.0, connection.uptime_percentage - 1.0)
                
        except Exception as e:
            logger.error(f"Error updating connection uptime: {e}")
    
    def _create_connection_alert(self, connection: InterSiteConnection, 
                               alert_type: str, value: Optional[float]):
        """Create an alert for inter-site connection issues"""
        try:
            alert_id = f"conn_{connection.connection_id}_{alert_type}_{int(time.time())}"
            
            source_site = self.sites.get(connection.source_site_id)
            dest_site = self.sites.get(connection.destination_site_id)
            
            if alert_type == 'high_latency':
                title = f"High Latency: {source_site.name} to {dest_site.name}"
                description = f"Latency between {source_site.name} and {dest_site.name} is {value:.1f}ms (threshold: {connection.alert_thresholds.get('latency_ms', 200)}ms)"
                severity = "medium" if value < 500 else "high"
            elif alert_type == 'connection_down':
                title = f"Connection Down: {source_site.name} to {dest_site.name}"
                description = f"Connection between {source_site.name} and {dest_site.name} is not responding"
                severity = "critical"
            else:
                title = f"Connection Issue: {source_site.name} to {dest_site.name}"
                description = f"Unknown connection issue between {source_site.name} and {dest_site.name}"
                severity = "medium"
            
            alert = CrossSiteAlert(
                alert_id=alert_id,
                title=title,
                description=description,
                severity=severity,
                affected_sites=[connection.source_site_id, connection.destination_site_id],
                impact_scope="regional",
                alert_type="connectivity",
                detected_at=datetime.utcnow()
            )
            
            self.cross_site_alerts[alert_id] = alert
            self.statistics['cross_site_alerts'] = len(self.cross_site_alerts)
            
            # Send notification
            self._send_cross_site_alert_notification(alert)
            
        except Exception as e:
            logger.error(f"Error creating connection alert: {e}")
    
    def _process_cross_site_alerts(self):
        """Process and consolidate cross-site alerts"""
        try:
            # Clean up resolved alerts
            current_time = datetime.utcnow()
            alerts_to_remove = []
            
            for alert_id, alert in self.cross_site_alerts.items():
                # Auto-resolve alerts older than 1 hour if connection is back up
                if (current_time - alert.detected_at).total_seconds() > 3600:
                    if alert.alert_type == "connectivity":
                        # Check if connection is back up
                        connection_up = self._check_connection_status_for_alert(alert)
                        if connection_up:
                            alert.resolved_at = current_time
                            alert.status = "resolved"
                            alerts_to_remove.append(alert_id)
            
            # Remove resolved alerts
            for alert_id in alerts_to_remove:
                del self.cross_site_alerts[alert_id]
            
            self.statistics['cross_site_alerts'] = len(self.cross_site_alerts)
            
        except Exception as e:
            logger.error(f"Error processing cross-site alerts: {e}")
    
    def _check_connection_status_for_alert(self, alert: CrossSiteAlert) -> bool:
        """Check if the connection mentioned in an alert is now working"""
        try:
            if len(alert.affected_sites) != 2:
                return False
            
            # Find connection between the two sites
            for connection in self.inter_site_connections.values():
                if (connection.source_site_id in alert.affected_sites and
                    connection.destination_site_id in alert.affected_sites):
                    return connection.status == "up"
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking connection status for alert: {e}")
            return False
    
    def _process_remote_alert(self, site: Site, alert_data: Dict):
        """Process an alert received from a remote site"""
        try:
            # Check if this is a critical alert that needs cross-site coordination
            if alert_data.get('severity') in ['critical', 'high']:
                # Create cross-site alert if it affects multiple sites
                alert_id = f"remote_{site.site_id}_{alert_data.get('id', int(time.time()))}"
                
                cross_site_alert = CrossSiteAlert(
                    alert_id=alert_id,
                    title=f"Remote Alert: {alert_data.get('title', 'Unknown')}",
                    description=f"Alert from {site.name}: {alert_data.get('message', '')}",
                    severity=alert_data.get('severity', 'medium'),
                    affected_sites=[site.site_id],
                    impact_scope="local",
                    alert_type="remote_alert",
                    detected_at=datetime.utcnow()
                )
                
                self.cross_site_alerts[alert_id] = cross_site_alert
                
        except Exception as e:
            logger.error(f"Error processing remote alert: {e}")
    
    def _send_cross_site_alert_notification(self, alert: CrossSiteAlert):
        """Send notification for cross-site alert"""
        try:
            site_names = [self.sites[site_id].name for site_id in alert.affected_sites 
                         if site_id in self.sites]
            
            notification_service.send_notification(
                subject=f"Multi-Site Alert: {alert.title}",
                message=f"""
Multi-Site Alert Details:
- Title: {alert.title}
- Severity: {alert.severity}
- Affected Sites: {', '.join(site_names)}
- Impact Scope: {alert.impact_scope}
- Description: {alert.description}
- Detected: {alert.detected_at.strftime('%Y-%m-%d %H:%M:%S')}

Please investigate the connectivity between the affected sites.
                """.strip(),
                level="error" if alert.severity in ["critical", "high"] else "warning"
            )
            
        except Exception as e:
            logger.error(f"Error sending cross-site alert notification: {e}")
    
    def _update_statistics(self):
        """Update system statistics"""
        try:
            self.statistics['total_sites'] = len(self.sites)
            self.statistics['online_sites'] = sum(
                1 for site in self.sites.values() 
                if site.status == SiteStatus.ONLINE
            )
            self.statistics['total_connections'] = len(self.inter_site_connections)
            self.statistics['active_connections'] = sum(
                1 for conn in self.inter_site_connections.values()
                if conn.status == "up"
            )
            self.statistics['total_devices_all_sites'] = sum(
                site.device_count for site in self.sites.values()
            )
            self.statistics['cross_site_alerts'] = len(self.cross_site_alerts)
            
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
    
    # Public API methods
    
    def get_sites_summary(self) -> Dict[str, Any]:
        """Get summary of all monitored sites"""
        try:
            sites_data = []
            
            for site in self.sites.values():
                recent_metrics = None
                if self.site_metrics_history[site.site_id]:
                    recent_metrics = self.site_metrics_history[site.site_id][-1]
                
                sites_data.append({
                    'site_id': site.site_id,
                    'name': site.name,
                    'site_type': site.site_type.value,
                    'status': site.status.value,
                    'location': f"{site.city}, {site.state}, {site.country}",
                    'device_count': site.device_count,
                    'alert_count': site.alert_count,
                    'uptime_percentage': site.uptime_percentage,
                    'avg_latency_ms': site.avg_latency_ms,
                    'last_seen': site.last_seen.isoformat() + 'Z' if site.last_seen else None,
                    'health_score': recent_metrics.health_score if recent_metrics else 0.0
                })
            
            return {
                'sites': sites_data,
                'summary': self.statistics
            }
            
        except Exception as e:
            logger.error(f"Error getting sites summary: {e}")
            return {'sites': [], 'summary': self.statistics}
    
    def get_site_details(self, site_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific site"""
        try:
            if site_id not in self.sites:
                return None
            
            site = self.sites[site_id]
            
            # Get recent metrics
            recent_metrics = []
            if self.site_metrics_history[site_id]:
                recent_metrics = [
                    asdict(metric) for metric in list(self.site_metrics_history[site_id])[-24:]
                ]
            
            # Get connections involving this site
            connections = []
            for conn in self.inter_site_connections.values():
                if site_id in [conn.source_site_id, conn.destination_site_id]:
                    connections.append(asdict(conn))
            
            return {
                'site': asdict(site),
                'recent_metrics': recent_metrics,
                'connections': connections
            }
            
        except Exception as e:
            logger.error(f"Error getting site details for {site_id}: {e}")
            return None
    
    def get_cross_site_alerts(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get cross-site alerts from the specified time period"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            alerts = [
                asdict(alert) for alert in self.cross_site_alerts.values()
                if alert.detected_at >= cutoff_time
            ]
            
            # Sort by detection time (newest first)
            alerts.sort(key=lambda a: a['detected_at'], reverse=True)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error getting cross-site alerts: {e}")
            return []
    
    def get_site_comparison(self, metric: str = 'health_score') -> Dict[str, Any]:
        """Get comparison data across all sites for a specific metric"""
        try:
            comparison_data = []
            
            for site_id, site in self.sites.items():
                if self.site_metrics_history[site_id]:
                    recent_metrics = self.site_metrics_history[site_id][-1]
                    
                    value = getattr(recent_metrics, metric, 0.0)
                    comparison_data.append({
                        'site_id': site_id,
                        'site_name': site.name,
                        'value': value,
                        'status': site.status.value
                    })
            
            # Sort by value
            comparison_data.sort(key=lambda x: x['value'], reverse=True)
            
            return {
                'metric': metric,
                'sites': comparison_data,
                'generated_at': datetime.utcnow().isoformat() + 'Z'
            }
            
        except Exception as e:
            logger.error(f"Error getting site comparison: {e}")
            return {'metric': metric, 'sites': [], 'generated_at': datetime.utcnow().isoformat() + 'Z'}
    
    def get_manager_status(self) -> Dict[str, Any]:
        """Get multi-site manager status and statistics"""
        return {
            'running': self.running,
            'statistics': self.statistics,
            'configuration': self.config
        }


# Global multi-site manager instance
multi_site_manager = MultiSiteManager()