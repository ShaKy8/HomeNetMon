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

logger = logging.getLogger(__name__)


class NetworkTopologyEngine:
    """Advanced network topology discovery and mapping engine"""

    def __init__(self, app=None):
        self.app = app

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

    def _app_context(self):
        """App context from the attached app, or the current request's app.

        The singleton in api/analytics.py is created at import time with app=None,
        so every request-driven call failed with 'NoneType has no app_context'."""
        app = self.app
        if app is None:
            from flask import current_app
            app = current_app._get_current_object()
        return app.app_context()

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

                with self._app_context():
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

                    # Step 4: Build dependency tree
                    dependency_tree = self._build_dependency_tree(devices, device_relationships)

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
                        'dependency_tree': dependency_tree,
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

    def _build_dependency_tree(self, devices: List[Device], relationships: Dict) -> Dict[str, Any]:
        """Nest the parent/child hierarchy into a tree rooted at the gateway(s).

        (Referenced by discover_network_topology since the engine was written but
        never defined -- the endpoint had never completed a request.)
        """
        parent_child = relationships.get('parent_child', {}) or {}
        hierarchy = parent_child.get('hierarchy', {}) or {}
        by_id = {d.id: d for d in devices}

        def describe(device_id):
            d = by_id.get(device_id)
            return {
                'device_id': device_id,
                'device_name': d.display_name if d else f'Device {device_id}',
                'ip_address': d.ip_address if d else None,
                'device_type': d.device_type if d else None,
            }

        max_depth = [0]
        seen = set()

        def build(device_id, depth):
            node = describe(device_id)
            node['depth'] = depth
            node['children'] = []
            max_depth[0] = max(max_depth[0], depth)
            if device_id in seen:          # cycle guard
                return node
            seen.add(device_id)
            for child in (hierarchy.get(device_id) or {}).get('children', []):
                child_id = child.get('device_id') if isinstance(child, dict) else child
                if child_id is not None:
                    node['children'].append(build(child_id, depth + 1))
            return node

        roots = []
        for root in parent_child.get('root_devices', []) or []:
            root_id = root.get('device_id') if isinstance(root, dict) else root
            if root_id is not None:
                roots.append(build(root_id, 0))
        # Parents that are not listed as roots and have no parent themselves also head a tree
        child_ids = {c.get('device_id') if isinstance(c, dict) else c
                     for h in hierarchy.values() for c in (h or {}).get('children', [])}
        for parent_id in hierarchy:
            if parent_id not in seen and parent_id not in child_ids:
                roots.append(build(parent_id, 0))

        orphaned = [describe(o.get('device_id') if isinstance(o, dict) else o)
                    for o in parent_child.get('orphaned_devices', []) or []]
        return {
            'roots': roots,
            'orphaned_devices': orphaned,
            'max_depth': max_depth[0],
            'devices_in_tree': len(seen),
            'device_count': len(devices),
        }

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
