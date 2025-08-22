"""
Network Topology Discovery & Mapping Service

This service implements advanced network topology discovery and relationship mapping:
1. Automatic discovery of network device relationships
2. Network path analysis and route mapping
3. Gateway and infrastructure device identification
4. Device dependency tree construction
5. Network segment and VLAN discovery
6. Real-time topology monitoring and updates
"""

import logging
import subprocess
import threading
import time
import socket
import ipaddress
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set

from models import db, Device, MonitoringData, Configuration
from services.device_analytics import DeviceBehaviorAnalytics

logger = logging.getLogger(__name__)


class NetworkTopologyEngine:
    """Advanced network topology discovery and mapping engine"""
    
    def __init__(self, app=None):
        self.app = app
        self.device_analytics = DeviceBehaviorAnalytics()
        
        # Topology data structures
        self.device_relationships = {}
        self.network_paths = {}
        self.gateway_devices = set()
        self.infrastructure_devices = set()
        self.network_segments = {}
        self.device_dependencies = {}
        
        # Discovery configuration
        self.discovery_methods = {
            'arp_analysis': True,
            'route_tracing': True,
            'latency_analysis': True,
            'subnet_scanning': True,
            'port_scanning': False  # Disabled by default for security
        }
        
        # Topology cache and performance
        self.topology_cache = {}
        self.last_full_discovery = None
        self.discovery_lock = threading.Lock()
        
        # Network analysis thresholds
        self.gateway_detection_thresholds = {
            'ip_ending_1': True,
            'lowest_latency': True,
            'highest_traffic': True,
            'route_analysis': True
        }
        
    def discover_network_topology(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Perform comprehensive network topology discovery"""
        try:
            with self.discovery_lock:
                # Check if we need to refresh
                if not force_refresh and self.last_full_discovery:
                    time_since_discovery = (datetime.utcnow() - self.last_full_discovery).total_seconds()
                    if time_since_discovery < 3600:  # 1 hour cache
                        logger.info("Using cached topology data")
                        return self.topology_cache
                
                logger.info("Starting comprehensive network topology discovery")
                start_time = datetime.utcnow()
                
                with self.app.app_context():
                    # Get all monitored devices
                    devices = Device.query.filter_by(is_monitored=True).all()
                    
                    if not devices:
                        return {'error': 'No monitored devices found'}
                    
                    # Step 1: Analyze network segments
                    network_segments = self._discover_network_segments(devices)
                    
                    # Step 2: Identify infrastructure devices
                    infrastructure_devices = self._identify_infrastructure_devices(devices)
                    
                    # Step 3: Discover device relationships
                    device_relationships = self._discover_device_relationships(devices)
                    
                    # Step 4: Perform route analysis
                    route_analysis = self._analyze_network_routes(devices)
                    
                    # Step 5: Build dependency tree
                    dependency_tree = self._build_dependency_tree(devices, device_relationships)
                    
                    # Step 6: Analyze network paths
                    network_paths = self._analyze_network_paths(devices, infrastructure_devices)
                    
                    # Step 7: Calculate topology metrics
                    topology_metrics = self._calculate_topology_metrics(devices, device_relationships)
                    
                    # Compile comprehensive topology
                    topology = {
                        'discovery_metadata': {
                            'discovered_at': start_time.isoformat(),
                            'discovery_duration_seconds': (datetime.utcnow() - start_time).total_seconds(),
                            'total_devices': len(devices),
                            'discovery_methods_used': [method for method, enabled in self.discovery_methods.items() if enabled]
                        },
                        'network_segments': network_segments,
                        'infrastructure_devices': infrastructure_devices,
                        'device_relationships': device_relationships,
                        'route_analysis': route_analysis,
                        'dependency_tree': dependency_tree,
                        'network_paths': network_paths,
                        'topology_metrics': topology_metrics,
                        'visualization_data': self._generate_visualization_data(
                            devices, device_relationships, infrastructure_devices
                        )
                    }
                    
                    # Cache the results
                    self.topology_cache = topology
                    self.last_full_discovery = start_time
                    
                    logger.info(f"Network topology discovery completed in {topology['discovery_metadata']['discovery_duration_seconds']:.2f}s")
                    
                    return topology
                    
        except Exception as e:
            logger.error(f"Error discovering network topology: {e}")
            return {'error': str(e)}
    
    def _discover_network_segments(self, devices: List[Device]) -> Dict[str, Any]:
        """Discover and analyze network segments"""
        segments = defaultdict(lambda: {
            'devices': [],
            'device_count': 0,
            'device_types': defaultdict(int),
            'subnet_mask': '/24',  # Default assumption
            'estimated_gateway': None,
            'segment_health': 0.0
        })
        
        for device in devices:
            if not device.ip_address:
                continue
            
            try:
                # Extract subnet (assuming /24)
                ip_parts = device.ip_address.split('.')
                subnet = '.'.join(ip_parts[:3]) + '.0/24'
                
                # Add device to segment
                segments[subnet]['devices'].append({
                    'device_id': device.id,
                    'device_name': device.display_name,
                    'ip_address': device.ip_address,
                    'device_type': device.device_type,
                    'vendor': device.vendor,
                    'last_seen': device.last_seen.isoformat() if device.last_seen else None
                })
                
                segments[subnet]['device_count'] += 1
                segments[subnet]['device_types'][device.device_type or 'unknown'] += 1
                
                # Check for potential gateway
                if device.ip_address.endswith('.1'):
                    segments[subnet]['estimated_gateway'] = {
                        'device_id': device.id,
                        'device_name': device.display_name,
                        'ip_address': device.ip_address
                    }
                
            except Exception as e:
                logger.warning(f"Error processing device {device.id} for segment discovery: {e}")
                continue
        
        # Calculate segment health scores
        for subnet, segment_data in segments.items():
            try:
                # Calculate health based on device uptime and response
                total_health = 0
                healthy_devices = 0
                
                for device_info in segment_data['devices']:
                    device = Device.query.get(device_info['device_id'])
                    if device and device.last_seen:
                        hours_since_seen = (datetime.utcnow() - device.last_seen).total_seconds() / 3600
                        if hours_since_seen < 24:  # Device seen in last 24 hours
                            device_health = max(0, 1 - (hours_since_seen / 24))
                            total_health += device_health
                            healthy_devices += 1
                
                if segment_data['device_count'] > 0:
                    segment_data['segment_health'] = round(total_health / segment_data['device_count'], 3)
                
            except Exception as e:
                logger.warning(f"Error calculating health for segment {subnet}: {e}")
                segment_data['segment_health'] = 0.0
        
        return dict(segments)
    
    def _identify_infrastructure_devices(self, devices: List[Device]) -> Dict[str, Any]:
        """Identify critical infrastructure devices"""
        infrastructure = {
            'gateways': [],
            'routers': [],
            'switches': [],
            'access_points': [],
            'servers': [],
            'critical_services': []
        }
        
        for device in devices:
            device_info = {
                'device_id': device.id,
                'device_name': device.display_name,
                'ip_address': device.ip_address,
                'device_type': device.device_type,
                'vendor': device.vendor,
                'infrastructure_score': 0.0,
                'criticality_level': 'normal'
            }
            
            # Calculate infrastructure score
            score = 0.0
            
            # IP-based scoring
            if device.ip_address:
                if device.ip_address.endswith('.1'):
                    score += 0.8  # Likely gateway
                    infrastructure['gateways'].append(device_info.copy())
                elif device.ip_address.endswith(('.2', '.3', '.4', '.5')):
                    score += 0.4  # Likely infrastructure range
            
            # Device type scoring
            device_type = (device.device_type or '').lower()
            if 'router' in device_type:
                score += 0.9
                infrastructure['routers'].append(device_info.copy())
            elif 'switch' in device_type:
                score += 0.7
                infrastructure['switches'].append(device_info.copy())
            elif 'access' in device_type or 'ap' in device_type:
                score += 0.6
                infrastructure['access_points'].append(device_info.copy())
            elif 'server' in device_type:
                score += 0.8
                infrastructure['servers'].append(device_info.copy())
            
            # Vendor-based scoring
            vendor = (device.vendor or '').lower()
            infrastructure_vendors = ['cisco', 'ubiquiti', 'netgear', 'linksys', 'tp-link', 'juniper']
            if any(v in vendor for v in infrastructure_vendors):
                score += 0.3
            
            # Hostname analysis
            hostname = (device.hostname or '').lower()
            infrastructure_keywords = ['gateway', 'router', 'switch', 'firewall', 'dns', 'dhcp']
            if any(keyword in hostname for keyword in infrastructure_keywords):
                score += 0.5
            
            device_info['infrastructure_score'] = round(score, 3)
            
            # Determine criticality level
            if score >= 0.8:
                device_info['criticality_level'] = 'critical'
                infrastructure['critical_services'].append(device_info.copy())
            elif score >= 0.5:
                device_info['criticality_level'] = 'important'
        
        # Calculate infrastructure statistics
        infrastructure['statistics'] = {
            'total_infrastructure_devices': sum(len(devices) for devices in infrastructure.values()) - len(infrastructure['statistics']) if 'statistics' in infrastructure else sum(len(devices) for devices in infrastructure.values()),
            'critical_device_count': len(infrastructure['critical_services']),
            'gateway_count': len(infrastructure['gateways']),
            'router_count': len(infrastructure['routers']),
            'switch_count': len(infrastructure['switches'])
        }
        
        return infrastructure
    
    def _discover_device_relationships(self, devices: List[Device]) -> Dict[str, Any]:
        """Discover relationships between network devices"""
        relationships = {
            'connections': [],
            'parent_child': {},
            'peer_relationships': [],
            'dependency_chains': []
        }
        
        # Analyze latency-based relationships
        latency_relationships = self._analyze_latency_relationships(devices)
        relationships['connections'].extend(latency_relationships)
        
        # Analyze subnet-based relationships
        subnet_relationships = self._analyze_subnet_relationships(devices)
        relationships['peer_relationships'].extend(subnet_relationships)
        
        # Build parent-child relationships (gateway -> devices)
        parent_child = self._build_parent_child_relationships(devices)
        relationships['parent_child'] = parent_child
        
        # Identify dependency chains
        dependency_chains = self._identify_dependency_chains(devices, parent_child)
        relationships['dependency_chains'] = dependency_chains
        
        return relationships
    
    def _analyze_latency_relationships(self, devices: List[Device]) -> List[Dict]:
        """Analyze device relationships based on response time patterns"""
        relationships = []
        
        try:
            # Get recent monitoring data for latency analysis
            cutoff = datetime.utcnow() - timedelta(hours=24)
            
            device_latencies = {}
            for device in devices:
                if not device.ip_address:
                    continue
                
                # Get average response time
                avg_response = db.session.query(
                    db.func.avg(MonitoringData.response_time)
                ).filter(
                    MonitoringData.device_id == device.id,
                    MonitoringData.timestamp >= cutoff,
                    MonitoringData.response_time.isnot(None)
                ).scalar()
                
                if avg_response:
                    device_latencies[device.id] = {
                        'device': device,
                        'avg_latency': float(avg_response),
                        'ip_address': device.ip_address
                    }
            
            # Find devices with similar latency patterns (likely same network path)
            for device_id1, data1 in device_latencies.items():
                for device_id2, data2 in device_latencies.items():
                    if device_id1 >= device_id2:  # Avoid duplicates
                        continue
                    
                    latency_diff = abs(data1['avg_latency'] - data2['avg_latency'])
                    if latency_diff < 10:  # Similar response times (within 10ms)
                        # Check if they're in same subnet
                        ip1_parts = data1['ip_address'].split('.')
                        ip2_parts = data2['ip_address'].split('.')
                        
                        if ip1_parts[:3] == ip2_parts[:3]:  # Same subnet
                            relationships.append({
                                'type': 'latency_peer',
                                'device1': {
                                    'device_id': device_id1,
                                    'device_name': data1['device'].display_name,
                                    'ip_address': data1['ip_address'],
                                    'avg_latency': round(data1['avg_latency'], 2)
                                },
                                'device2': {
                                    'device_id': device_id2,
                                    'device_name': data2['device'].display_name,
                                    'ip_address': data2['ip_address'],
                                    'avg_latency': round(data2['avg_latency'], 2)
                                },
                                'latency_difference': round(latency_diff, 2),
                                'relationship_strength': 'high' if latency_diff < 5 else 'medium'
                            })
            
        except Exception as e:
            logger.error(f"Error analyzing latency relationships: {e}")
        
        return relationships
    
    def _analyze_subnet_relationships(self, devices: List[Device]) -> List[Dict]:
        """Analyze device relationships within subnets"""
        relationships = []
        subnet_devices = defaultdict(list)
        
        # Group devices by subnet
        for device in devices:
            if device.ip_address:
                try:
                    ip_parts = device.ip_address.split('.')
                    subnet = '.'.join(ip_parts[:3]) + '.0/24'
                    subnet_devices[subnet].append(device)
                except:
                    continue
        
        # Analyze relationships within each subnet
        for subnet, subnet_device_list in subnet_devices.items():
            if len(subnet_device_list) < 2:
                continue
            
            # Find potential gateway device
            gateway_device = None
            for device in subnet_device_list:
                if device.ip_address.endswith('.1'):
                    gateway_device = device
                    break
            
            # Create relationships
            for device in subnet_device_list:
                if device == gateway_device:
                    continue
                
                if gateway_device:
                    # Device -> Gateway relationship
                    relationships.append({
                        'type': 'subnet_gateway',
                        'child_device': {
                            'device_id': device.id,
                            'device_name': device.display_name,
                            'ip_address': device.ip_address
                        },
                        'gateway_device': {
                            'device_id': gateway_device.id,
                            'device_name': gateway_device.display_name,
                            'ip_address': gateway_device.ip_address
                        },
                        'subnet': subnet,
                        'relationship_type': 'gateway_dependency'
                    })
        
        return relationships
    
    def _build_parent_child_relationships(self, devices: List[Device]) -> Dict[str, Any]:
        """Build hierarchical parent-child device relationships"""
        parent_child = {
            'hierarchy': {},
            'orphaned_devices': [],
            'root_devices': []
        }
        
        # Identify potential parent devices (gateways, routers)
        potential_parents = []
        for device in devices:
            is_parent = False
            
            # Gateway detection
            if device.ip_address and device.ip_address.endswith('.1'):
                is_parent = True
            
            # Device type detection
            device_type = (device.device_type or '').lower()
            if any(keyword in device_type for keyword in ['router', 'gateway', 'switch']):
                is_parent = True
            
            if is_parent:
                potential_parents.append(device)
                parent_child['root_devices'].append({
                    'device_id': device.id,
                    'device_name': device.display_name,
                    'ip_address': device.ip_address,
                    'device_type': device.device_type
                })
        
        # Build hierarchy
        for parent in potential_parents:
            if not parent.ip_address:
                continue
            
            # Find devices in same subnet
            parent_subnet = '.'.join(parent.ip_address.split('.')[:3])
            children = []
            
            for device in devices:
                if device == parent or not device.ip_address:
                    continue
                
                device_subnet = '.'.join(device.ip_address.split('.')[:3])
                if device_subnet == parent_subnet:
                    children.append({
                        'device_id': device.id,
                        'device_name': device.display_name,
                        'ip_address': device.ip_address,
                        'device_type': device.device_type,
                        'vendor': device.vendor
                    })
            
            if children:
                parent_child['hierarchy'][parent.id] = {
                    'parent': {
                        'device_id': parent.id,
                        'device_name': parent.display_name,
                        'ip_address': parent.ip_address,
                        'device_type': parent.device_type
                    },
                    'children': children,
                    'child_count': len(children)
                }
        
        # Find orphaned devices (devices without clear parent)
        devices_with_parents = set()
        for hierarchy_data in parent_child['hierarchy'].values():
            for child in hierarchy_data['children']:
                devices_with_parents.add(child['device_id'])
        
        for device in devices:
            if device.id not in devices_with_parents and device.id not in [p['device_id'] for p in parent_child['root_devices']]:
                parent_child['orphaned_devices'].append({
                    'device_id': device.id,
                    'device_name': device.display_name,
                    'ip_address': device.ip_address,
                    'reason': 'no_clear_parent_found'
                })
        
        return parent_child
    
    def _identify_dependency_chains(self, devices: List[Device], parent_child: Dict) -> List[Dict]:
        """Identify device dependency chains"""
        chains = []
        
        # Build dependency chains from parent-child relationships
        for parent_id, hierarchy_data in parent_child.get('hierarchy', {}).items():
            parent_info = hierarchy_data['parent']
            children = hierarchy_data['children']
            
            if len(children) > 1:
                chain = {
                    'chain_id': f"chain_{parent_id}",
                    'root_device': parent_info,
                    'dependent_devices': children,
                    'chain_length': len(children) + 1,
                    'chain_type': 'subnet_dependency',
                    'criticality': 'high' if len(children) > 5 else 'medium'
                }
                chains.append(chain)
        
        return chains
    
    def _analyze_network_routes(self, devices: List[Device]) -> Dict[str, Any]:
        """Analyze network routing and paths"""
        route_analysis = {
            'default_gateways': [],
            'routing_metrics': {},
            'path_redundancy': {},
            'single_points_of_failure': []
        }
        
        # Identify default gateways
        for device in devices:
            if device.ip_address and device.ip_address.endswith('.1'):
                subnet = '.'.join(device.ip_address.split('.')[:3]) + '.0/24'
                route_analysis['default_gateways'].append({
                    'device_id': device.id,
                    'device_name': device.display_name,
                    'ip_address': device.ip_address,
                    'subnet': subnet,
                    'device_type': device.device_type
                })
        
        # Analyze single points of failure
        subnet_gateways = defaultdict(list)
        for gateway in route_analysis['default_gateways']:
            subnet_gateways[gateway['subnet']].append(gateway)
        
        for subnet, gateways in subnet_gateways.items():
            if len(gateways) == 1:
                gateway = gateways[0]
                # Count devices dependent on this gateway
                dependent_count = sum(1 for device in devices 
                                    if device.ip_address and 
                                    device.ip_address.startswith(subnet.split('/')[0][:subnet.rfind('.')]))
                
                if dependent_count > 1:
                    route_analysis['single_points_of_failure'].append({
                        'gateway': gateway,
                        'subnet': subnet,
                        'dependent_device_count': dependent_count,
                        'risk_level': 'high' if dependent_count > 10 else 'medium'
                    })
        
        return route_analysis
    
    def _analyze_network_paths(self, devices: List[Device], infrastructure: Dict) -> Dict[str, Any]:
        """Analyze network paths and connectivity with advanced path discovery"""
        network_paths = {
            'critical_paths': [],
            'backup_paths': [],
            'path_metrics': {},
            'route_mappings': {},
            'connectivity_matrix': {},
            'path_redundancy_analysis': {},
            'bottleneck_analysis': {}
        }
        
        try:
            # Step 1: Build connectivity matrix
            connectivity_matrix = self._build_connectivity_matrix(devices)
            network_paths['connectivity_matrix'] = connectivity_matrix
            
            # Step 2: Discover route mappings
            route_mappings = self._discover_route_mappings(devices, infrastructure)
            network_paths['route_mappings'] = route_mappings
            
            # Step 3: Identify critical paths (to infrastructure devices)
            critical_paths = self._identify_critical_paths(devices, infrastructure, connectivity_matrix)
            network_paths['critical_paths'] = critical_paths
            
            # Step 4: Analyze backup and redundant paths
            backup_paths = self._analyze_backup_paths(devices, infrastructure, connectivity_matrix)
            network_paths['backup_paths'] = backup_paths
            
            # Step 5: Calculate path metrics and performance
            path_metrics = self._calculate_path_metrics(devices, critical_paths, backup_paths)
            network_paths['path_metrics'] = path_metrics
            
            # Step 6: Analyze path redundancy
            redundancy_analysis = self._analyze_path_redundancy(devices, infrastructure, connectivity_matrix)
            network_paths['path_redundancy_analysis'] = redundancy_analysis
            
            # Step 7: Identify network bottlenecks
            bottleneck_analysis = self._identify_network_bottlenecks(devices, infrastructure, connectivity_matrix)
            network_paths['bottleneck_analysis'] = bottleneck_analysis
            
        except Exception as e:
            logger.error(f"Error in network path analysis: {e}")
            network_paths['analysis_error'] = str(e)
        
        return network_paths
    
    def _build_connectivity_matrix(self, devices: List[Device]) -> Dict[str, Any]:
        """Build a connectivity matrix showing device-to-device connections"""
        matrix = {
            'direct_connections': {},
            'subnet_connections': {},
            'latency_matrix': {},
            'reachability_matrix': {}
        }
        
        try:
            # Build direct connection matrix based on subnets
            subnet_groups = defaultdict(list)
            for device in devices:
                if device.ip_address:
                    subnet = '.'.join(device.ip_address.split('.')[:3]) + '.0/24'
                    subnet_groups[subnet].append(device)
            
            # Create subnet connections
            for subnet, subnet_devices in subnet_groups.items():
                device_list = []
                for device in subnet_devices:
                    device_list.append({
                        'device_id': device.id,
                        'device_name': device.display_name,
                        'ip_address': device.ip_address,
                        'device_type': device.device_type
                    })
                
                matrix['subnet_connections'][subnet] = {
                    'devices': device_list,
                    'device_count': len(device_list),
                    'subnet_gateway': next((d for d in device_list if d['ip_address'].endswith('.1')), None)
                }
            
            # Build latency matrix
            cutoff = datetime.utcnow() - timedelta(hours=24)
            for device in devices:
                if not device.ip_address:
                    continue
                    
                avg_response = db.session.query(
                    db.func.avg(MonitoringData.response_time)
                ).filter(
                    MonitoringData.device_id == device.id,
                    MonitoringData.timestamp >= cutoff,
                    MonitoringData.response_time.isnot(None)
                ).scalar()
                
                if avg_response:
                    matrix['latency_matrix'][device.id] = {
                        'device_name': device.display_name,
                        'ip_address': device.ip_address,
                        'avg_response_time': round(float(avg_response), 2),
                        'latency_category': 'low' if avg_response < 10 else 'medium' if avg_response < 50 else 'high'
                    }
            
            # Build reachability matrix (simplified - based on same subnet)
            for device1 in devices:
                if not device1.ip_address:
                    continue
                    
                reachable_devices = []
                device1_subnet = '.'.join(device1.ip_address.split('.')[:3])
                
                for device2 in devices:
                    if device1.id == device2.id or not device2.ip_address:
                        continue
                    
                    device2_subnet = '.'.join(device2.ip_address.split('.')[:3])
                    
                    # Direct reachability (same subnet)
                    if device1_subnet == device2_subnet:
                        reachable_devices.append({
                            'device_id': device2.id,
                            'device_name': device2.display_name,
                            'ip_address': device2.ip_address,
                            'connection_type': 'direct_subnet',
                            'hops': 1
                        })
                    else:
                        # Cross-subnet reachability (through gateway)
                        reachable_devices.append({
                            'device_id': device2.id,
                            'device_name': device2.display_name,
                            'ip_address': device2.ip_address,
                            'connection_type': 'routed',
                            'hops': 3  # Estimated hops through gateway
                        })
                
                matrix['reachability_matrix'][device1.id] = {
                    'device_name': device1.display_name,
                    'reachable_devices': reachable_devices,
                    'total_reachable': len(reachable_devices)
                }
        
        except Exception as e:
            logger.error(f"Error building connectivity matrix: {e}")
            matrix['error'] = str(e)
        
        return matrix
    
    def _discover_route_mappings(self, devices: List[Device], infrastructure: Dict) -> Dict[str, Any]:
        """Discover and map network routes between devices and segments"""
        route_mappings = {
            'inter_subnet_routes': [],
            'gateway_routes': {},
            'route_table_analysis': {},
            'hop_count_analysis': {}
        }
        
        try:
            # Identify gateways and their managed subnets
            gateways = infrastructure.get('gateways', [])
            
            for gateway in gateways:
                gateway_ip = gateway['ip_address']
                if not gateway_ip:
                    continue
                
                gateway_subnet = '.'.join(gateway_ip.split('.')[:3]) + '.0/24'
                
                # Find devices in this gateway's subnet
                managed_devices = []
                for device in devices:
                    if (device.ip_address and 
                        device.ip_address.startswith('.'.join(gateway_ip.split('.')[:3])) and 
                        device.id != gateway['device_id']):
                        managed_devices.append({
                            'device_id': device.id,
                            'device_name': device.display_name,
                            'ip_address': device.ip_address
                        })
                
                route_mappings['gateway_routes'][gateway['device_id']] = {
                    'gateway_info': gateway,
                    'managed_subnet': gateway_subnet,
                    'managed_devices': managed_devices,
                    'device_count': len(managed_devices),
                    'route_priority': 'primary'
                }
            
            # Analyze inter-subnet routes
            subnets = set()
            for device in devices:
                if device.ip_address:
                    subnet = '.'.join(device.ip_address.split('.')[:3]) + '.0/24'
                    subnets.add(subnet)
            
            for subnet1 in subnets:
                for subnet2 in subnets:
                    if subnet1 != subnet2:
                        # Find route between subnets (typically through gateways)
                        subnet1_gateway = None
                        subnet2_gateway = None
                        
                        for gateway_id, gateway_data in route_mappings['gateway_routes'].items():
                            if gateway_data['managed_subnet'] == subnet1:
                                subnet1_gateway = gateway_data['gateway_info']
                            elif gateway_data['managed_subnet'] == subnet2:
                                subnet2_gateway = gateway_data['gateway_info']
                        
                        if subnet1_gateway and subnet2_gateway:
                            route_mappings['inter_subnet_routes'].append({
                                'source_subnet': subnet1,
                                'destination_subnet': subnet2,
                                'source_gateway': subnet1_gateway,
                                'destination_gateway': subnet2_gateway,
                                'estimated_hops': 3 if subnet1_gateway['device_id'] != subnet2_gateway['device_id'] else 2,
                                'route_type': 'gateway_routed'
                            })
            
            # Hop count analysis
            hop_analysis = {}
            for device in devices:
                if not device.ip_address:
                    continue
                
                device_subnet = '.'.join(device.ip_address.split('.')[:3]) + '.0/24'
                
                # Count hops to other subnets
                hops_to_subnets = {}
                for subnet in subnets:
                    if subnet == device_subnet:
                        hops_to_subnets[subnet] = 0  # Same subnet
                    else:
                        hops_to_subnets[subnet] = 2  # Through gateway
                
                hop_analysis[device.id] = {
                    'device_name': device.display_name,
                    'device_subnet': device_subnet,
                    'hops_to_subnets': hops_to_subnets,
                    'avg_hop_count': round(sum(hops_to_subnets.values()) / len(hops_to_subnets), 1)
                }
            
            route_mappings['hop_count_analysis'] = hop_analysis
        
        except Exception as e:
            logger.error(f"Error discovering route mappings: {e}")
            route_mappings['error'] = str(e)
        
        return route_mappings
    
    def _identify_critical_paths(self, devices: List[Device], infrastructure: Dict, 
                               connectivity_matrix: Dict) -> List[Dict]:
        """Identify critical network paths that affect multiple devices"""
        critical_paths = []
        
        try:
            # Identify paths to/from infrastructure devices
            critical_devices = infrastructure.get('critical_services', [])
            gateways = infrastructure.get('gateways', [])
            
            # Gateway critical paths
            for gateway in gateways:
                gateway_id = gateway['device_id']
                gateway_ip = gateway['ip_address']
                
                if not gateway_ip:
                    continue
                
                gateway_subnet = '.'.join(gateway_ip.split('.')[:3])
                
                # Find all devices that depend on this gateway
                dependent_devices = []
                for device in devices:
                    if (device.id != gateway_id and 
                        device.ip_address and 
                        device.ip_address.startswith(gateway_subnet)):
                        dependent_devices.append({
                            'device_id': device.id,
                            'device_name': device.display_name,
                            'ip_address': device.ip_address,
                            'dependency_type': 'internet_gateway'
                        })
                
                if dependent_devices:
                    # Calculate path criticality
                    criticality_score = len(dependent_devices) * 0.1
                    if len(dependent_devices) > 10:
                        criticality_level = 'critical'
                    elif len(dependent_devices) > 5:
                        criticality_level = 'high'
                    else:
                        criticality_level = 'medium'
                    
                    critical_paths.append({
                        'path_id': f"gateway_path_{gateway_id}",
                        'path_type': 'gateway_dependency',
                        'critical_device': gateway,
                        'dependent_devices': dependent_devices,
                        'path_importance': 'critical',
                        'affected_device_count': len(dependent_devices),
                        'criticality_level': criticality_level,
                        'criticality_score': round(min(1.0, criticality_score), 3),
                        'failure_impact': f"Network isolation for {len(dependent_devices)} devices",
                        'redundancy_available': len([g for g in gateways if g['device_id'] != gateway_id]) > 0
                    })
            
            # Infrastructure service paths
            for critical_device in critical_devices:
                if critical_device['device_id'] in [g['device_id'] for g in gateways]:
                    continue  # Already processed as gateway
                
                critical_id = critical_device['device_id']
                critical_ip = critical_device['ip_address']
                
                if not critical_ip:
                    continue
                
                # Estimate devices that might use this service
                affected_devices = []
                service_type = critical_device.get('device_type', '').lower()
                
                # For DNS/DHCP servers, all devices in network are affected
                if any(service in service_type for service in ['dns', 'dhcp', 'server']):
                    for device in devices:
                        if device.id != critical_id:
                            affected_devices.append({
                                'device_id': device.id,
                                'device_name': device.display_name,
                                'ip_address': device.ip_address,
                                'dependency_type': f'{service_type}_service'
                            })
                
                if affected_devices:
                    critical_paths.append({
                        'path_id': f"service_path_{critical_id}",
                        'path_type': 'service_dependency',
                        'critical_device': critical_device,
                        'dependent_devices': affected_devices[:20],  # Limit for display
                        'path_importance': 'high',
                        'affected_device_count': len(affected_devices),
                        'criticality_level': 'high',
                        'failure_impact': f"Service loss for {len(affected_devices)} devices"
                    })
        
        except Exception as e:
            logger.error(f"Error identifying critical paths: {e}")
        
        return critical_paths
    
    def _analyze_backup_paths(self, devices: List[Device], infrastructure: Dict, 
                            connectivity_matrix: Dict) -> List[Dict]:
        """Analyze backup and redundant network paths"""
        backup_paths = []
        
        try:
            gateways = infrastructure.get('gateways', [])
            
            # Group gateways by subnet to find backup gateways
            subnet_gateways = defaultdict(list)
            for gateway in gateways:
                if gateway['ip_address']:
                    subnet = '.'.join(gateway['ip_address'].split('.')[:3]) + '.0/24'
                    subnet_gateways[subnet].append(gateway)
            
            # Analyze backup gateway availability
            for subnet, gateway_list in subnet_gateways.items():
                if len(gateway_list) > 1:
                    primary_gateway = gateway_list[0]  # Assume first is primary
                    backup_gateways = gateway_list[1:]
                    
                    # Find devices that could use backup paths
                    subnet_devices = []
                    subnet_prefix = subnet.split('/')[0][:-1]  # Remove .0
                    
                    for device in devices:
                        if (device.ip_address and 
                            device.ip_address.startswith(subnet_prefix) and
                            device.id not in [g['device_id'] for g in gateway_list]):
                            subnet_devices.append({
                                'device_id': device.id,
                                'device_name': device.display_name,
                                'ip_address': device.ip_address
                            })
                    
                    backup_paths.append({
                        'backup_path_id': f"backup_gateway_{subnet.replace('/', '_')}",
                        'path_type': 'gateway_redundancy',
                        'primary_gateway': primary_gateway,
                        'backup_gateways': backup_gateways,
                        'protected_subnet': subnet,
                        'protected_devices': subnet_devices,
                        'redundancy_level': len(backup_gateways),
                        'failover_capability': 'automatic' if len(backup_gateways) > 0 else 'manual',
                        'protection_coverage': len(subnet_devices)
                    })
            
            # Analyze cross-subnet backup paths
            all_subnets = set()
            for device in devices:
                if device.ip_address:
                    subnet = '.'.join(device.ip_address.split('.')[:3]) + '.0/24'
                    all_subnets.add(subnet)
            
            if len(all_subnets) > 1:
                # Multiple subnets provide backup connectivity
                backup_paths.append({
                    'backup_path_id': 'cross_subnet_redundancy',
                    'path_type': 'subnet_redundancy',
                    'available_subnets': list(all_subnets),
                    'subnet_count': len(all_subnets),
                    'redundancy_type': 'network_segmentation',
                    'isolation_protection': True,
                    'description': f"Network segmented across {len(all_subnets)} subnets for isolation and redundancy"
                })
        
        except Exception as e:
            logger.error(f"Error analyzing backup paths: {e}")
        
        return backup_paths
    
    def _calculate_path_metrics(self, devices: List[Device], critical_paths: List, 
                              backup_paths: List) -> Dict[str, Any]:
        """Calculate comprehensive path performance metrics"""
        metrics = {
            'path_performance': {},
            'redundancy_metrics': {},
            'reliability_scores': {},
            'network_resilience': {}
        }
        
        try:
            # Calculate path performance metrics
            total_devices = len(devices)
            total_critical_paths = len(critical_paths)
            total_backup_paths = len(backup_paths)
            
            # Network resilience scoring
            redundancy_score = 0.0
            if total_critical_paths > 0:
                paths_with_backup = sum(1 for path in critical_paths 
                                      if path.get('redundancy_available', False))
                redundancy_score = paths_with_backup / total_critical_paths
            
            # Calculate overall network reliability
            gateway_devices = [d for d in devices if d.ip_address and d.ip_address.endswith('.1')]
            infrastructure_devices = [d for d in devices if any(
                infra in (d.device_type or '').lower() 
                for infra in ['router', 'switch', 'gateway']
            )]
            
            reliability_factors = {
                'gateway_redundancy': len(gateway_devices) > 1,
                'infrastructure_diversity': len(infrastructure_devices) > 2,
                'subnet_segmentation': len(set(
                    '.'.join(d.ip_address.split('.')[:3]) + '.0/24' 
                    for d in devices if d.ip_address
                )) > 1,
                'backup_path_availability': total_backup_paths > 0
            }
            
            reliability_score = sum(reliability_factors.values()) / len(reliability_factors)
            
            metrics['path_performance'] = {
                'total_network_devices': total_devices,
                'critical_path_count': total_critical_paths,
                'backup_path_count': total_backup_paths,
                'redundancy_coverage': round(redundancy_score * 100, 1),
                'avg_devices_per_critical_path': round(
                    sum(path['affected_device_count'] for path in critical_paths) / max(1, total_critical_paths), 1
                )
            }
            
            metrics['redundancy_metrics'] = {
                'gateway_redundancy_available': len(gateway_devices) > 1,
                'infrastructure_redundancy': len(infrastructure_devices) > 2,
                'cross_subnet_redundancy': len(set(
                    '.'.join(d.ip_address.split('.')[:3]) + '.0/24' 
                    for d in devices if d.ip_address
                )) > 1,
                'backup_path_ratio': round(total_backup_paths / max(1, total_critical_paths), 2)
            }
            
            metrics['reliability_scores'] = {
                'network_reliability_score': round(reliability_score * 100, 1),
                'redundancy_score': round(redundancy_score * 100, 1),
                'resilience_factors': reliability_factors,
                'single_point_of_failure_count': sum(
                    1 for path in critical_paths 
                    if not path.get('redundancy_available', False)
                )
            }
            
            # Network resilience assessment
            if reliability_score >= 0.8:
                resilience_level = 'excellent'
            elif reliability_score >= 0.6:
                resilience_level = 'good'
            elif reliability_score >= 0.4:
                resilience_level = 'fair'
            else:
                resilience_level = 'poor'
            
            metrics['network_resilience'] = {
                'resilience_level': resilience_level,
                'resilience_score': round(reliability_score, 3),
                'recommended_improvements': self._get_resilience_recommendations(reliability_factors, critical_paths)
            }
        
        except Exception as e:
            logger.error(f"Error calculating path metrics: {e}")
            metrics['error'] = str(e)
        
        return metrics
    
    def _analyze_path_redundancy(self, devices: List[Device], infrastructure: Dict, 
                               connectivity_matrix: Dict) -> Dict[str, Any]:
        """Analyze path redundancy and failover capabilities"""
        redundancy_analysis = {
            'redundancy_summary': {},
            'failover_paths': [],
            'single_points_of_failure': [],
            'redundancy_recommendations': []
        }
        
        try:
            gateways = infrastructure.get('gateways', [])
            
            # Analyze gateway redundancy
            gateway_subnets = defaultdict(list)
            for gateway in gateways:
                if gateway['ip_address']:
                    subnet = '.'.join(gateway['ip_address'].split('.')[:3]) + '.0/24'
                    gateway_subnets[subnet].append(gateway)
            
            # Identify single points of failure
            for subnet, subnet_gateways in gateway_subnets.items():
                if len(subnet_gateways) == 1:
                    # Count dependent devices
                    dependent_count = sum(1 for device in devices 
                                        if device.ip_address and 
                                        device.ip_address.startswith(subnet.split('/')[0][:-1]))
                    
                    if dependent_count > 1:
                        redundancy_analysis['single_points_of_failure'].append({
                            'failure_point_type': 'gateway',
                            'critical_device': subnet_gateways[0],
                            'affected_subnet': subnet,
                            'dependent_device_count': dependent_count,
                            'risk_level': 'high' if dependent_count > 10 else 'medium',
                            'recommended_action': 'Add backup gateway to subnet'
                        })
            
            # Analyze infrastructure redundancy
            infrastructure_types = ['router', 'switch', 'dns', 'dhcp']
            for infra_type in infrastructure_types:
                infra_devices = [
                    device for device in devices 
                    if device.device_type and infra_type in device.device_type.lower()
                ]
                
                if len(infra_devices) == 1:
                    redundancy_analysis['single_points_of_failure'].append({
                        'failure_point_type': f'{infra_type}_service',
                        'critical_device': {
                            'device_id': infra_devices[0].id,
                            'device_name': infra_devices[0].display_name,
                            'ip_address': infra_devices[0].ip_address,
                            'device_type': infra_devices[0].device_type
                        },
                        'service_type': infra_type,
                        'risk_level': 'high',
                        'recommended_action': f'Deploy redundant {infra_type} service'
                    })
            
            # Generate redundancy recommendations
            recommendations = []
            
            if len(redundancy_analysis['single_points_of_failure']) > 0:
                recommendations.append({
                    'priority': 'high',
                    'recommendation': 'Address single points of failure',
                    'details': f"Found {len(redundancy_analysis['single_points_of_failure'])} critical single points of failure"
                })
            
            if len(gateways) == 1:
                recommendations.append({
                    'priority': 'medium',
                    'recommendation': 'Add backup internet gateway',
                    'details': 'Only one gateway detected - consider dual WAN setup'
                })
            
            redundancy_analysis['redundancy_recommendations'] = recommendations
            
            # Summary statistics
            redundancy_analysis['redundancy_summary'] = {
                'total_gateways': len(gateways),
                'subnets_with_backup_gateways': sum(1 for gateways in gateway_subnets.values() if len(gateways) > 1),
                'total_single_points_of_failure': len(redundancy_analysis['single_points_of_failure']),
                'redundancy_coverage_percentage': round(
                    (1 - len(redundancy_analysis['single_points_of_failure']) / max(1, len(devices))) * 100, 1
                )
            }
        
        except Exception as e:
            logger.error(f"Error analyzing path redundancy: {e}")
            redundancy_analysis['error'] = str(e)
        
        return redundancy_analysis
    
    def _identify_network_bottlenecks(self, devices: List[Device], infrastructure: Dict, 
                                    connectivity_matrix: Dict) -> Dict[str, Any]:
        """Identify potential network bottlenecks and performance issues"""
        bottleneck_analysis = {
            'bottleneck_devices': [],
            'performance_concerns': [],
            'capacity_analysis': {},
            'optimization_recommendations': []
        }
        
        try:
            # Analyze device loading based on dependency counts
            for device in devices:
                if not device.ip_address:
                    continue
                
                # Count devices that might depend on this one
                dependent_count = 0
                
                # Gateway bottleneck analysis
                if device.ip_address.endswith('.1'):
                    device_subnet = '.'.join(device.ip_address.split('.')[:3])
                    dependent_count = sum(1 for d in devices 
                                        if d.ip_address and 
                                        d.ip_address.startswith(device_subnet) and 
                                        d.id != device.id)
                    
                    if dependent_count > 20:
                        bottleneck_level = 'high'
                    elif dependent_count > 10:
                        bottleneck_level = 'medium'
                    else:
                        bottleneck_level = 'low'
                    
                    bottleneck_analysis['bottleneck_devices'].append({
                        'device_id': device.id,
                        'device_name': device.display_name,
                        'ip_address': device.ip_address,
                        'bottleneck_type': 'gateway_overload',
                        'dependent_device_count': dependent_count,
                        'bottleneck_level': bottleneck_level,
                        'recommended_action': 'Consider load balancing or subnet segmentation' if bottleneck_level != 'low' else None
                    })
            
            # Analyze response time bottlenecks
            cutoff = datetime.utcnow() - timedelta(hours=24)
            high_latency_devices = []
            
            for device in devices:
                avg_response = db.session.query(
                    db.func.avg(MonitoringData.response_time)
                ).filter(
                    MonitoringData.device_id == device.id,
                    MonitoringData.timestamp >= cutoff,
                    MonitoringData.response_time.isnot(None)
                ).scalar()
                
                if avg_response and avg_response > 100:  # High latency threshold
                    high_latency_devices.append({
                        'device_id': device.id,
                        'device_name': device.display_name,
                        'ip_address': device.ip_address,
                        'avg_response_time': round(float(avg_response), 2),
                        'performance_impact': 'high' if avg_response > 200 else 'medium'
                    })
            
            if high_latency_devices:
                bottleneck_analysis['performance_concerns'].append({
                    'concern_type': 'high_latency_devices',
                    'affected_devices': high_latency_devices,
                    'impact_assessment': 'Network performance degradation',
                    'recommended_investigation': 'Check network congestion, device health, and connectivity'
                })
            
            # Subnet capacity analysis
            subnet_analysis = {}
            subnet_devices = defaultdict(list)
            
            for device in devices:
                if device.ip_address:
                    subnet = '.'.join(device.ip_address.split('.')[:3]) + '.0/24'
                    subnet_devices[subnet].append(device)
            
            for subnet, subnet_device_list in subnet_devices.items():
                device_count = len(subnet_device_list)
                # Assume /24 subnet (254 usable addresses)
                capacity_utilization = (device_count / 254) * 100
                
                subnet_analysis[subnet] = {
                    'device_count': device_count,
                    'capacity_utilization_percentage': round(capacity_utilization, 1),
                    'capacity_status': 'high' if capacity_utilization > 80 else 'medium' if capacity_utilization > 50 else 'low',
                    'available_addresses': 254 - device_count
                }
                
                if capacity_utilization > 80:
                    bottleneck_analysis['performance_concerns'].append({
                        'concern_type': 'subnet_capacity',
                        'affected_subnet': subnet,
                        'capacity_utilization': round(capacity_utilization, 1),
                        'impact_assessment': 'Subnet nearing capacity limits',
                        'recommended_action': 'Consider subnet expansion or segmentation'
                    })
            
            bottleneck_analysis['capacity_analysis'] = subnet_analysis
            
            # Generate optimization recommendations
            recommendations = []
            
            if len(bottleneck_analysis['bottleneck_devices']) > 0:
                recommendations.append({
                    'priority': 'high',
                    'optimization': 'Address device bottlenecks',
                    'details': f"Found {len(bottleneck_analysis['bottleneck_devices'])} potential bottleneck devices",
                    'actions': ['Load balancing', 'Network segmentation', 'Hardware upgrades']
                })
            
            if high_latency_devices:
                recommendations.append({
                    'priority': 'medium',
                    'optimization': 'Improve network performance',
                    'details': f"Found {len(high_latency_devices)} devices with high latency",
                    'actions': ['Network diagnostics', 'Bandwidth analysis', 'QoS implementation']
                })
            
            bottleneck_analysis['optimization_recommendations'] = recommendations
        
        except Exception as e:
            logger.error(f"Error identifying network bottlenecks: {e}")
            bottleneck_analysis['error'] = str(e)
        
        return bottleneck_analysis
    
    def _get_resilience_recommendations(self, reliability_factors: Dict, critical_paths: List) -> List[str]:
        """Generate recommendations for improving network resilience"""
        recommendations = []
        
        if not reliability_factors.get('gateway_redundancy'):
            recommendations.append("Deploy backup gateway/router for internet redundancy")
        
        if not reliability_factors.get('infrastructure_diversity'):
            recommendations.append("Add redundant network infrastructure (switches, access points)")
        
        if not reliability_factors.get('subnet_segmentation'):
            recommendations.append("Implement network segmentation for isolation and performance")
        
        if not reliability_factors.get('backup_path_availability'):
            recommendations.append("Establish backup network paths and failover mechanisms")
        
        # Check for high-risk critical paths
        high_risk_paths = [path for path in critical_paths 
                          if path.get('affected_device_count', 0) > 10 and 
                          not path.get('redundancy_available', False)]
        
        if high_risk_paths:
            recommendations.append(f"Address {len(high_risk_paths)} high-risk single points of failure")
        
        if not recommendations:
            recommendations.append("Network resilience is excellent - maintain current infrastructure")
        
        return recommendations
    
    def _calculate_topology_metrics(self, devices: List[Device], relationships: Dict) -> Dict[str, Any]:
        """Calculate network topology metrics"""
        metrics = {
            'network_density': 0.0,
            'connectivity_score': 0.0,
            'redundancy_score': 0.0,
            'centralization_score': 0.0,
            'device_distribution': {},
            'subnet_coverage': {}
        }
        
        total_devices = len(devices)
        if total_devices == 0:
            return metrics
        
        # Calculate network density
        total_possible_connections = (total_devices * (total_devices - 1)) / 2
        actual_connections = len(relationships.get('connections', []))
        metrics['network_density'] = round(actual_connections / total_possible_connections, 3) if total_possible_connections > 0 else 0
        
        # Calculate connectivity score based on device relationships
        connected_devices = set()
        for connection in relationships.get('connections', []):
            connected_devices.add(connection.get('device1', {}).get('device_id'))
            connected_devices.add(connection.get('device2', {}).get('device_id'))
        
        metrics['connectivity_score'] = round(len(connected_devices) / total_devices, 3)
        
        # Calculate redundancy score (multiple paths)
        hierarchy = relationships.get('parent_child', {}).get('hierarchy', {})
        single_parent_devices = sum(1 for h in hierarchy.values() if len(h.get('children', [])) > 0)
        metrics['redundancy_score'] = round(1 - (single_parent_devices / total_devices), 3) if total_devices > 0 else 0
        
        # Device type distribution
        device_types = defaultdict(int)
        for device in devices:
            device_types[device.device_type or 'unknown'] += 1
        metrics['device_distribution'] = dict(device_types)
        
        # Subnet coverage analysis
        subnets = set()
        for device in devices:
            if device.ip_address:
                try:
                    subnet = '.'.join(device.ip_address.split('.')[:3]) + '.0/24'
                    subnets.add(subnet)
                except:
                    continue
        
        metrics['subnet_coverage'] = {
            'total_subnets': len(subnets),
            'subnets': list(subnets)
        }
        
        return metrics
    
    def _generate_visualization_data(self, devices: List[Device], relationships: Dict, 
                                   infrastructure: Dict) -> Dict[str, Any]:
        """Generate data for network topology visualization"""
        visualization = {
            'nodes': [],
            'edges': [],
            'clusters': [],
            'layout_hints': {}
        }
        
        # Generate nodes
        for device in devices:
            # Determine node properties
            node_type = 'infrastructure' if any(
                device.id == infra_device['device_id'] 
                for infra_devices in infrastructure.values() 
                if isinstance(infra_devices, list)
                for infra_device in infra_devices
            ) else 'endpoint'
            
            node_size = 'large' if node_type == 'infrastructure' else 'medium'
            if device.ip_address and device.ip_address.endswith('.1'):
                node_size = 'xlarge'
            
            visualization['nodes'].append({
                'id': device.id,
                'label': device.display_name,
                'ip_address': device.ip_address,
                'device_type': device.device_type,
                'vendor': device.vendor,
                'node_type': node_type,
                'size': node_size,
                'status': 'online' if device.last_seen and 
                         (datetime.utcnow() - device.last_seen).total_seconds() < 3600 else 'offline',
                'subnet': '.'.join(device.ip_address.split('.')[:3]) + '.0/24' if device.ip_address else None
            })
        
        # Generate edges from relationships
        edge_id = 0
        for connection in relationships.get('connections', []):
            visualization['edges'].append({
                'id': edge_id,
                'source': connection.get('device1', {}).get('device_id'),
                'target': connection.get('device2', {}).get('device_id'),
                'type': connection.get('type', 'connection'),
                'strength': connection.get('relationship_strength', 'medium'),
                'label': f"{connection.get('type', 'connection')}"
            })
            edge_id += 1
        
        # Add parent-child edges
        hierarchy = relationships.get('parent_child', {}).get('hierarchy', {})
        for parent_id, hierarchy_data in hierarchy.items():
            for child in hierarchy_data.get('children', []):
                visualization['edges'].append({
                    'id': edge_id,
                    'source': parent_id,
                    'target': child['device_id'],
                    'type': 'parent_child',
                    'strength': 'strong',
                    'label': 'gateway'
                })
                edge_id += 1
        
        # Generate clusters by subnet
        subnet_clusters = defaultdict(list)
        for node in visualization['nodes']:
            if node['subnet']:
                subnet_clusters[node['subnet']].append(node['id'])
        
        cluster_id = 0
        for subnet, node_ids in subnet_clusters.items():
            if len(node_ids) > 1:
                visualization['clusters'].append({
                    'id': cluster_id,
                    'label': subnet,
                    'nodes': node_ids,
                    'type': 'subnet'
                })
                cluster_id += 1
        
        return visualization
    
    def analyze_device_relationships(self, device_id: int) -> Dict[str, Any]:
        """Analyze relationships for a specific device"""
        try:
            with self.app.app_context():
                device = Device.query.get(device_id)
                if not device:
                    return {'error': 'Device not found'}
                
                relationships = {
                    'device_info': {
                        'device_id': device.id,
                        'device_name': device.display_name,
                        'ip_address': device.ip_address,
                        'device_type': device.device_type,
                        'vendor': device.vendor
                    },
                    'direct_relationships': [],
                    'network_dependencies': [],
                    'subnet_peers': [],
                    'communication_patterns': {},
                    'network_role': 'unknown',
                    'criticality_assessment': {}
                }
                
                # Analyze direct relationships
                direct_relationships = self._analyze_direct_relationships(device)
                relationships['direct_relationships'] = direct_relationships
                
                # Analyze network dependencies
                dependencies = self._analyze_device_dependencies(device)
                relationships['network_dependencies'] = dependencies
                
                # Find subnet peers
                subnet_peers = self._find_subnet_peers(device)
                relationships['subnet_peers'] = subnet_peers
                
                # Analyze communication patterns
                communication = self._analyze_communication_patterns(device)
                relationships['communication_patterns'] = communication
                
                # Determine network role
                network_role = self._determine_network_role(device, direct_relationships, dependencies)
                relationships['network_role'] = network_role
                
                # Assess criticality
                criticality = self._assess_device_criticality(device, dependencies, subnet_peers)
                relationships['criticality_assessment'] = criticality
                
                return relationships
                
        except Exception as e:
            logger.error(f"Error analyzing relationships for device {device_id}: {e}")
            return {'error': str(e)}
    
    def _analyze_direct_relationships(self, device: Device) -> List[Dict]:
        """Analyze direct device-to-device relationships"""
        relationships = []
        
        if not device.ip_address:
            return relationships
        
        try:
            # Get all devices in same subnet
            device_subnet = '.'.join(device.ip_address.split('.')[:3])
            subnet_devices = Device.query.filter(
                Device.ip_address.like(f"{device_subnet}.%"),
                Device.id != device.id,
                Device.is_monitored == True
            ).all()
            
            # Analyze response time correlations
            cutoff = datetime.utcnow() - timedelta(hours=24)
            
            device_avg_response = db.session.query(
                db.func.avg(MonitoringData.response_time)
            ).filter(
                MonitoringData.device_id == device.id,
                MonitoringData.timestamp >= cutoff,
                MonitoringData.response_time.isnot(None)
            ).scalar()
            
            if device_avg_response:
                for other_device in subnet_devices:
                    other_avg_response = db.session.query(
                        db.func.avg(MonitoringData.response_time)
                    ).filter(
                        MonitoringData.device_id == other_device.id,
                        MonitoringData.timestamp >= cutoff,
                        MonitoringData.response_time.isnot(None)
                    ).scalar()
                    
                    if other_avg_response:
                        latency_similarity = 1 - min(1, abs(device_avg_response - other_avg_response) / max(device_avg_response, other_avg_response))
                        
                        if latency_similarity > 0.8:  # High similarity
                            relationship_type = self._determine_relationship_type(device, other_device)
                            
                            relationships.append({
                                'related_device': {
                                    'device_id': other_device.id,
                                    'device_name': other_device.display_name,
                                    'ip_address': other_device.ip_address,
                                    'device_type': other_device.device_type
                                },
                                'relationship_type': relationship_type,
                                'similarity_score': round(latency_similarity, 3),
                                'avg_latency_difference': round(abs(device_avg_response - other_avg_response), 2),
                                'connection_strength': 'strong' if latency_similarity > 0.9 else 'medium'
                            })
            
        except Exception as e:
            logger.error(f"Error analyzing direct relationships: {e}")
        
        return relationships
    
    def _determine_relationship_type(self, device1: Device, device2: Device) -> str:
        """Determine the type of relationship between two devices"""
        # Gateway relationship
        if device1.ip_address and device1.ip_address.endswith('.1'):
            return 'gateway_to_client'
        elif device2.ip_address and device2.ip_address.endswith('.1'):
            return 'client_to_gateway'
        
        # Infrastructure relationships
        device1_type = (device1.device_type or '').lower()
        device2_type = (device2.device_type or '').lower()
        
        infrastructure_types = ['router', 'switch', 'gateway', 'access_point']
        device1_is_infra = any(infra in device1_type for infra in infrastructure_types)
        device2_is_infra = any(infra in device2_type for infra in infrastructure_types)
        
        if device1_is_infra and device2_is_infra:
            return 'infrastructure_peer'
        elif device1_is_infra or device2_is_infra:
            return 'infrastructure_client'
        
        # Same device type
        if device1_type == device2_type and device1_type != 'unknown':
            return 'device_type_peer'
        
        # Same vendor
        if device1.vendor and device2.vendor and device1.vendor == device2.vendor:
            return 'vendor_peer'
        
        return 'subnet_peer'
    
    def _analyze_device_dependencies(self, device: Device) -> Dict[str, Any]:
        """Analyze what this device depends on and what depends on it"""
        dependencies = {
            'depends_on': [],
            'dependents': [],
            'dependency_score': 0.0,
            'critical_dependencies': []
        }
        
        if not device.ip_address:
            return dependencies
        
        try:
            # Find potential gateway dependencies
            device_subnet = '.'.join(device.ip_address.split('.')[:3])
            potential_gateway = Device.query.filter(
                Device.ip_address == f"{device_subnet}.1",
                Device.id != device.id
            ).first()
            
            if potential_gateway:
                dependencies['depends_on'].append({
                    'dependency_type': 'gateway',
                    'device': {
                        'device_id': potential_gateway.id,
                        'device_name': potential_gateway.display_name,
                        'ip_address': potential_gateway.ip_address,
                        'device_type': potential_gateway.device_type
                    },
                    'dependency_strength': 'critical',
                    'failure_impact': 'network_isolation'
                })
                dependencies['critical_dependencies'].append(potential_gateway.id)
            
            # Find DNS/DHCP dependencies (common infrastructure IPs)
            infrastructure_ips = [f"{device_subnet}.2", f"{device_subnet}.3", f"{device_subnet}.4"]
            for infra_ip in infrastructure_ips:
                infra_device = Device.query.filter_by(ip_address=infra_ip).first()
                if infra_device:
                    service_type = 'dns' if infra_ip.endswith('.2') else 'dhcp' if infra_ip.endswith('.3') else 'infrastructure'
                    dependencies['depends_on'].append({
                        'dependency_type': service_type,
                        'device': {
                            'device_id': infra_device.id,
                            'device_name': infra_device.display_name,
                            'ip_address': infra_device.ip_address,
                            'device_type': infra_device.device_type
                        },
                        'dependency_strength': 'high',
                        'failure_impact': f'{service_type}_service_loss'
                    })
            
            # Check if this device is infrastructure that others depend on
            if (device.ip_address.endswith('.1') or 
                (device.device_type and any(infra in device.device_type.lower() 
                                          for infra in ['router', 'switch', 'gateway']))):
                
                # Find dependent devices in same subnet
                dependent_devices = Device.query.filter(
                    Device.ip_address.like(f"{device_subnet}.%"),
                    Device.id != device.id,
                    Device.is_monitored == True
                ).all()
                
                for dependent in dependent_devices:
                    dependencies['dependents'].append({
                        'device_id': dependent.id,
                        'device_name': dependent.display_name,
                        'ip_address': dependent.ip_address,
                        'device_type': dependent.device_type,
                        'dependency_type': 'network_access'
                    })
            
            # Calculate dependency score
            dependency_score = len(dependencies['depends_on']) * 0.3 + len(dependencies['dependents']) * 0.7
            dependencies['dependency_score'] = round(min(1.0, dependency_score / 10), 3)
            
        except Exception as e:
            logger.error(f"Error analyzing device dependencies: {e}")
        
        return dependencies
    
    def _find_subnet_peers(self, device: Device) -> List[Dict]:
        """Find peer devices in the same subnet"""
        peers = []
        
        if not device.ip_address:
            return peers
        
        try:
            device_subnet = '.'.join(device.ip_address.split('.')[:3])
            subnet_devices = Device.query.filter(
                Device.ip_address.like(f"{device_subnet}.%"),
                Device.id != device.id,
                Device.is_monitored == True
            ).all()
            
            for peer_device in subnet_devices:
                # Calculate peer relationship strength
                relationship_strength = self._calculate_peer_strength(device, peer_device)
                
                peers.append({
                    'device_id': peer_device.id,
                    'device_name': peer_device.display_name,
                    'ip_address': peer_device.ip_address,
                    'device_type': peer_device.device_type,
                    'vendor': peer_device.vendor,
                    'relationship_strength': relationship_strength,
                    'shared_characteristics': self._find_shared_characteristics(device, peer_device)
                })
            
        except Exception as e:
            logger.error(f"Error finding subnet peers: {e}")
        
        return peers
    
    def _calculate_peer_strength(self, device1: Device, device2: Device) -> str:
        """Calculate the strength of peer relationship"""
        strength_score = 0
        
        # Same device type
        if device1.device_type == device2.device_type:
            strength_score += 3
        
        # Same vendor
        if device1.vendor and device2.vendor and device1.vendor == device2.vendor:
            strength_score += 2
        
        # Similar IP range (sequential IPs)
        if device1.ip_address and device2.ip_address:
            try:
                ip1_last = int(device1.ip_address.split('.')[-1])
                ip2_last = int(device2.ip_address.split('.')[-1])
                if abs(ip1_last - ip2_last) <= 5:  # Within 5 IP addresses
                    strength_score += 1
            except:
                pass
        
        # Similar hostnames
        if device1.hostname and device2.hostname:
            hostname1 = device1.hostname.lower()
            hostname2 = device2.hostname.lower()
            if any(part in hostname2 for part in hostname1.split('-')[:2]):
                strength_score += 1
        
        if strength_score >= 5:
            return 'very_strong'
        elif strength_score >= 3:
            return 'strong'
        elif strength_score >= 1:
            return 'medium'
        else:
            return 'weak'
    
    def _find_shared_characteristics(self, device1: Device, device2: Device) -> List[str]:
        """Find shared characteristics between devices"""
        shared = []
        
        if device1.device_type == device2.device_type and device1.device_type:
            shared.append(f"same_device_type_{device1.device_type}")
        
        if device1.vendor == device2.vendor and device1.vendor:
            shared.append(f"same_vendor_{device1.vendor}")
        
        # Check IP proximity
        if device1.ip_address and device2.ip_address:
            try:
                ip1_parts = device1.ip_address.split('.')
                ip2_parts = device2.ip_address.split('.')
                if ip1_parts[:3] == ip2_parts[:3]:
                    shared.append("same_subnet")
                    
                ip1_last = int(ip1_parts[-1])
                ip2_last = int(ip2_parts[-1])
                if abs(ip1_last - ip2_last) <= 10:
                    shared.append("adjacent_ips")
            except:
                pass
        
        return shared
    
    def _analyze_communication_patterns(self, device: Device) -> Dict[str, Any]:
        """Analyze communication patterns for the device"""
        patterns = {
            'response_patterns': {},
            'uptime_correlation': {},
            'failure_correlation': {},
            'traffic_patterns': {}
        }
        
        try:
            # Analyze response time patterns
            cutoff = datetime.utcnow() - timedelta(days=7)
            monitoring_data = MonitoringData.query.filter(
                MonitoringData.device_id == device.id,
                MonitoringData.timestamp >= cutoff
            ).order_by(MonitoringData.timestamp.desc()).all()
            
            if monitoring_data:
                # Response time analysis
                response_times = [data.response_time for data in monitoring_data if data.response_time is not None]
                if response_times:
                    patterns['response_patterns'] = {
                        'avg_response_time': round(sum(response_times) / len(response_times), 2),
                        'min_response_time': round(min(response_times), 2),
                        'max_response_time': round(max(response_times), 2),
                        'response_variability': round(
                            (max(response_times) - min(response_times)) / (sum(response_times) / len(response_times)), 2
                        ) if sum(response_times) > 0 else 0,
                        'pattern_stability': 'stable' if len(set(int(rt/10)*10 for rt in response_times)) <= 3 else 'variable'
                    }
                
                # Uptime pattern analysis
                total_checks = len(monitoring_data)
                successful_checks = len(response_times)
                patterns['uptime_correlation'] = {
                    'uptime_percentage': round((successful_checks / total_checks) * 100, 1),
                    'total_checks': total_checks,
                    'successful_checks': successful_checks,
                    'reliability_rating': 'excellent' if successful_checks/total_checks > 0.98 else 
                                        'good' if successful_checks/total_checks > 0.95 else
                                        'fair' if successful_checks/total_checks > 0.90 else 'poor'
                }
            
        except Exception as e:
            logger.error(f"Error analyzing communication patterns: {e}")
        
        return patterns
    
    def _determine_network_role(self, device: Device, relationships: List, dependencies: Dict) -> str:
        """Determine the network role of the device"""
        # Gateway/Router role
        if device.ip_address and device.ip_address.endswith('.1'):
            return 'gateway_router'
        
        # Infrastructure role
        device_type = (device.device_type or '').lower()
        if any(infra in device_type for infra in ['router', 'switch', 'gateway', 'access_point']):
            return 'network_infrastructure'
        
        # Server role
        if 'server' in device_type or (device.ip_address and device.ip_address.endswith(('.2', '.3', '.4', '.5'))):
            return 'server_service'
        
        # High dependency device (many things depend on it)
        if len(dependencies.get('dependents', [])) > 5:
            return 'critical_service'
        
        # Client device roles
        if 'camera' in device_type:
            return 'security_camera'
        elif any(mobile in device_type for mobile in ['phone', 'tablet', 'mobile']):
            return 'mobile_client'
        elif any(iot in device_type for iot in ['smart', 'iot', 'sensor']):
            return 'iot_device'
        elif any(computer in device_type for computer in ['computer', 'laptop', 'desktop', 'pc']):
            return 'workstation'
        elif 'printer' in device_type:
            return 'network_printer'
        elif any(media in device_type for media in ['tv', 'media', 'roku', 'chromecast']):
            return 'media_device'
        
        return 'network_client'
    
    def _assess_device_criticality(self, device: Device, dependencies: Dict, peers: List) -> Dict[str, Any]:
        """Assess the criticality of the device to network operations"""
        criticality = {
            'criticality_level': 'normal',
            'criticality_score': 0.0,
            'impact_factors': [],
            'failure_impact_assessment': 'low'
        }
        
        score = 0.0
        
        # Infrastructure scoring
        if device.ip_address and device.ip_address.endswith('.1'):
            score += 0.8
            criticality['impact_factors'].append('gateway_device')
        
        device_type = (device.device_type or '').lower()
        if any(infra in device_type for infra in ['router', 'switch', 'gateway']):
            score += 0.7
            criticality['impact_factors'].append('network_infrastructure')
        
        # Dependency scoring
        dependent_count = len(dependencies.get('dependents', []))
        if dependent_count > 10:
            score += 0.6
            criticality['impact_factors'].append(f'high_dependency_count_{dependent_count}')
        elif dependent_count > 5:
            score += 0.4
            criticality['impact_factors'].append(f'medium_dependency_count_{dependent_count}')
        
        # Service scoring
        if device.ip_address and device.ip_address.endswith(('.2', '.3', '.4')):
            score += 0.5
            criticality['impact_factors'].append('service_ip_range')
        
        # Calculate final criticality
        criticality['criticality_score'] = round(min(1.0, score), 3)
        
        if score >= 0.8:
            criticality['criticality_level'] = 'critical'
            criticality['failure_impact_assessment'] = 'severe'
        elif score >= 0.6:
            criticality['criticality_level'] = 'high'
            criticality['failure_impact_assessment'] = 'high'
        elif score >= 0.3:
            criticality['criticality_level'] = 'medium'
            criticality['failure_impact_assessment'] = 'medium'
        else:
            criticality['criticality_level'] = 'normal'
            criticality['failure_impact_assessment'] = 'low'
        
        return criticality
    
    def monitor_topology_changes(self) -> Dict[str, Any]:
        """Monitor for topology changes and updates"""
        try:
            with self.app.app_context():
                current_topology = self.discover_network_topology(force_refresh=True)
                
                if 'error' in current_topology:
                    return current_topology
                
                # Compare with previous topology if available
                changes = {
                    'topology_changed': False,
                    'new_devices': [],
                    'removed_devices': [],
                    'relationship_changes': [],
                    'infrastructure_changes': [],
                    'change_summary': {}
                }
                
                # For now, return current topology with change monitoring structure
                # In production, this would compare against stored previous topology
                changes['change_summary'] = {
                    'total_devices': current_topology['discovery_metadata']['total_devices'],
                    'infrastructure_devices': len(current_topology['infrastructure_devices']['critical_services']),
                    'network_segments': len(current_topology['network_segments']),
                    'monitoring_timestamp': datetime.utcnow().isoformat()
                }
                
                return {
                    'current_topology': current_topology,
                    'changes': changes
                }
                
        except Exception as e:
            logger.error(f"Error monitoring topology changes: {e}")
            return {'error': str(e)}


# Global topology engine instance
network_topology_engine = NetworkTopologyEngine()