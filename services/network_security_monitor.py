"""
Network Security Monitoring Service

This service implements comprehensive network security monitoring capabilities:
1. Real-time traffic analysis and anomaly detection
2. Intrusion detection system (IDS) functionality
3. Network behavior pattern analysis
4. Security event correlation and analysis
5. Automated threat response and alerting
"""

import logging
import threading
import time
import socket
import subprocess
import re
import statistics
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum

from models import db, Device, Alert, SecurityEvent, SecurityIncident
from services.anomaly_detection import AnomalyDetectionEngine
from services.security_scanner import security_scanner

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(Enum):
    """Types of detected attacks"""
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DOS_ATTACK = "dos_attack"
    SUSPICIOUS_TRAFFIC = "suspicious_traffic"
    MALWARE_COMMUNICATION = "malware_communication"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    NETWORK_RECONNAISSANCE = "network_reconnaissance"


@dataclass
class NetworkThreat:
    """Represents a detected network security threat"""
    threat_id: str
    source_ip: str
    target_ip: str
    attack_type: AttackType
    threat_level: ThreatLevel
    description: str
    evidence: Dict[str, Any]
    confidence_score: float
    detected_at: datetime
    duration_seconds: int = 0
    packet_count: int = 0
    byte_count: int = 0
    response_actions: List[str] = field(default_factory=list)


@dataclass
class TrafficPattern:
    """Network traffic pattern for analysis"""
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    packet_count: int
    byte_count: int
    duration_seconds: int
    first_seen: datetime
    last_seen: datetime
    flags: Set[str] = field(default_factory=set)


class NetworkSecurityMonitor:
    """Advanced network security monitoring and intrusion detection system"""
    
    def __init__(self, app=None):
        self.app = app
        self.running = False
        self.anomaly_detection = AnomalyDetectionEngine()
        
        # Traffic analysis configuration
        self.monitoring_config = {
            'packet_capture_enabled': False,  # Requires root privileges
            'log_analysis_enabled': True,
            'behavior_analysis_enabled': True,
            'real_time_alerts': True,
            'analysis_window_seconds': 300,  # 5-minute analysis window
            'threat_threshold': 0.7,  # Minimum confidence for threat detection
        }
        
        # Traffic pattern tracking
        self.traffic_patterns = defaultdict(lambda: defaultdict(TrafficPattern))
        self.connection_history = deque(maxlen=10000)
        self.threat_history = deque(maxlen=1000)
        
        # Attack detection thresholds
        self.attack_thresholds = {
            'port_scan_threshold': 10,      # ports scanned within window
            'brute_force_threshold': 20,    # failed attempts within window
            'dos_packet_threshold': 1000,   # packets per second
            'connection_rate_threshold': 100, # new connections per minute
            'suspicious_port_threshold': 5   # connections to suspicious ports
        }
        
        # Monitoring statistics
        self.monitoring_stats = {
            'packets_analyzed': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'active_threats': 0,
            'last_analysis': datetime.utcnow()
        }
        
        # Known malicious indicators
        self.malicious_indicators = {
            'suspicious_ports': [135, 139, 445, 1433, 3389, 5900, 6379, 23, 21],
            'suspicious_user_agents': ['nikto', 'sqlmap', 'nmap', 'masscan', 'zmap'],
            'malware_domains': set(),  # Could be populated from threat intelligence
            'malicious_ips': set()     # Could be populated from blocklists
        }
        
    def start_monitoring(self):
        """Start the network security monitoring system"""
        if self.running:
            logger.warning("Network security monitor already running")
            return
        
        self.running = True
        logger.info("Starting network security monitoring")
        
        # Start multiple monitoring threads
        monitoring_threads = [
            threading.Thread(target=self._log_analysis_loop, daemon=True, name='LogAnalysis'),
            threading.Thread(target=self._behavior_analysis_loop, daemon=True, name='BehaviorAnalysis'),
            threading.Thread(target=self._threat_correlation_loop, daemon=True, name='ThreatCorrelation'),
            threading.Thread(target=self._real_time_analysis_loop, daemon=True, name='RealTimeAnalysis')
        ]
        
        for thread in monitoring_threads:
            thread.start()
        
        logger.info("Network security monitoring started with 4 analysis threads")
    
    def stop_monitoring(self):
        """Stop the network security monitoring"""
        self.running = False
        logger.info("Network security monitoring stopped")
    
    def _log_analysis_loop(self):
        """Analyze system logs for security indicators"""
        while self.running:
            try:
                # Analyze various system logs for security events
                self._analyze_auth_logs()
                self._analyze_network_logs()
                self._analyze_firewall_logs()
                self._analyze_application_logs()
                
                time.sleep(60)  # Analyze logs every minute
                
            except Exception as e:
                logger.error(f"Error in log analysis loop: {e}")
                time.sleep(60)
    
    def _behavior_analysis_loop(self):
        """Analyze network behavior patterns for anomalies"""
        while self.running:
            try:
                # Perform behavioral analysis
                self._analyze_connection_patterns()
                self._analyze_traffic_anomalies()
                self._analyze_device_behavior()
                
                # Update monitoring statistics
                self.monitoring_stats['last_analysis'] = datetime.utcnow()
                
                time.sleep(self.monitoring_config['analysis_window_seconds'])
                
            except Exception as e:
                logger.error(f"Error in behavior analysis loop: {e}")
                time.sleep(60)
    
    def _threat_correlation_loop(self):
        """Correlate security events and identify complex attack patterns"""
        while self.running:
            try:
                # Correlate recent security events
                self._correlate_security_events()
                self._identify_attack_campaigns()
                self._update_threat_intelligence()
                
                time.sleep(300)  # Correlation analysis every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in threat correlation loop: {e}")
                time.sleep(300)
    
    def _real_time_analysis_loop(self):
        """Real-time network traffic analysis"""
        while self.running:
            try:
                # Real-time analysis of current network state
                self._analyze_current_connections()
                self._detect_active_attacks()
                self._monitor_resource_usage()
                
                time.sleep(30)  # Real-time checks every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in real-time analysis loop: {e}")
                time.sleep(30)
    
    def _analyze_auth_logs(self):
        """Analyze authentication logs for brute force and unauthorized access attempts"""
        try:
            # Parse auth logs for failed login attempts
            auth_log_files = ['/var/log/auth.log', '/var/log/secure']
            
            for log_file in auth_log_files:
                try:
                    with open(log_file, 'r') as f:
                        # Read last 1000 lines efficiently
                        lines = deque(f, maxlen=1000)
                        
                        failed_attempts = defaultdict(list)
                        success_attempts = []
                        
                        for line in lines:
                            if 'Failed password' in line or 'authentication failure' in line:
                                # Extract IP address and timestamp
                                ip_match = re.search(r'from (\\d+\\.\\d+\\.\\d+\\.\\d+)', line)
                                if ip_match:
                                    ip_address = ip_match.group(1)
                                    timestamp = self._parse_log_timestamp(line)
                                    failed_attempts[ip_address].append(timestamp)
                            
                            elif 'Accepted password' in line or 'session opened' in line:
                                ip_match = re.search(r'from (\\d+\\.\\d+\\.\\d+\\.\\d+)', line)
                                if ip_match:
                                    ip_address = ip_match.group(1)
                                    timestamp = self._parse_log_timestamp(line)
                                    success_attempts.append((ip_address, timestamp))
                        
                        # Analyze failed attempts for brute force attacks
                        self._detect_brute_force_attacks(failed_attempts)
                        
                        # Check for successful logins after multiple failures
                        self._detect_successful_brute_force(failed_attempts, success_attempts)
                        
                except FileNotFoundError:
                    continue  # Log file doesn't exist
                except PermissionError:
                    logger.warning(f"Permission denied reading {log_file}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error analyzing auth logs: {e}")
    
    def _analyze_network_logs(self):
        """Analyze network connection logs"""
        try:
            # Use netstat to get current connections
            result = subprocess.run(['netstat', '-tuln'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                connections = self._parse_netstat_output(result.stdout)
                self._analyze_connection_patterns_from_netstat(connections)
            
        except subprocess.TimeoutExpired:
            logger.warning("Netstat command timed out")
        except Exception as e:
            logger.error(f"Error analyzing network logs: {e}")
    
    def _analyze_firewall_logs(self):
        """Analyze firewall logs for blocked connections and attacks"""
        try:
            # Check UFW logs (Ubuntu firewall)
            ufw_log = '/var/log/ufw.log'
            
            try:
                with open(ufw_log, 'r') as f:
                    lines = deque(f, maxlen=500)
                    
                    blocked_ips = defaultdict(int)
                    blocked_ports = defaultdict(int)
                    
                    for line in lines:
                        if '[UFW BLOCK]' in line:
                            # Extract source IP and destination port
                            src_match = re.search(r'SRC=(\\d+\\.\\d+\\.\\d+\\.\\d+)', line)
                            dpt_match = re.search(r'DPT=(\\d+)', line)
                            
                            if src_match and dpt_match:
                                src_ip = src_match.group(1)
                                dst_port = int(dpt_match.group(1))
                                
                                blocked_ips[src_ip] += 1
                                blocked_ports[dst_port] += 1
                    
                    # Detect scanning activities based on blocked connections
                    self._detect_port_scanning_from_firewall(blocked_ips, blocked_ports)
                    
            except FileNotFoundError:
                pass  # UFW log doesn't exist
                
        except Exception as e:
            logger.error(f"Error analyzing firewall logs: {e}")
    
    def _analyze_application_logs(self):
        """Analyze application logs for security indicators"""
        try:
            # Check for HomeNetMon application logs
            app_log = '/var/log/homenetmon.log'
            
            try:
                with open(app_log, 'r') as f:
                    lines = deque(f, maxlen=200)
                    
                    for line in lines:
                        # Look for security-relevant events
                        if any(keyword in line.lower() for keyword in 
                              ['error', 'warning', 'failed', 'unauthorized', 'suspicious']):
                            self._analyze_application_security_event(line)
                            
            except FileNotFoundError:
                pass  # Application log doesn't exist
                
        except Exception as e:
            logger.error(f"Error analyzing application logs: {e}")
    
    def _detect_brute_force_attacks(self, failed_attempts: Dict[str, List[datetime]]):
        """Detect brute force attacks from failed login attempts"""
        current_time = datetime.utcnow()
        window_start = current_time - timedelta(minutes=15)  # 15-minute window
        
        for ip_address, timestamps in failed_attempts.items():
            # Count recent failed attempts
            recent_attempts = [ts for ts in timestamps if ts >= window_start]
            
            if len(recent_attempts) >= self.attack_thresholds['brute_force_threshold']:
                # Detected brute force attack
                threat = NetworkThreat(
                    threat_id=f"brute_force_{ip_address}_{int(current_time.timestamp())}",
                    source_ip=ip_address,
                    target_ip="localhost",  # Authentication attempts against local system
                    attack_type=AttackType.BRUTE_FORCE,
                    threat_level=ThreatLevel.HIGH,
                    description=f"Brute force attack detected from {ip_address}: {len(recent_attempts)} failed login attempts in 15 minutes",
                    evidence={
                        'failed_attempts': len(recent_attempts),
                        'time_window_minutes': 15,
                        'attack_duration': (max(timestamps) - min(timestamps)).total_seconds(),
                        'attempt_timestamps': [ts.isoformat() for ts in recent_attempts[-10:]]  # Last 10 attempts
                    },
                    confidence_score=0.9,
                    detected_at=current_time
                )
                
                self._process_threat(threat)
    
    def _detect_port_scanning_from_firewall(self, blocked_ips: Dict[str, int], blocked_ports: Dict[str, int]):
        """Detect port scanning activities from firewall logs"""
        current_time = datetime.utcnow()
        
        for ip_address, block_count in blocked_ips.items():
            if block_count >= self.attack_thresholds['port_scan_threshold']:
                # Check which ports were targeted
                targeted_ports = []
                for port, count in blocked_ports.items():
                    if count >= 3:  # Port targeted multiple times
                        targeted_ports.append(port)
                
                threat = NetworkThreat(
                    threat_id=f"port_scan_{ip_address}_{int(current_time.timestamp())}",
                    source_ip=ip_address,
                    target_ip="network",
                    attack_type=AttackType.PORT_SCAN,
                    threat_level=ThreatLevel.MEDIUM,
                    description=f"Port scanning detected from {ip_address}: {block_count} blocked connection attempts",
                    evidence={
                        'blocked_attempts': block_count,
                        'targeted_ports': targeted_ports,
                        'scanning_pattern': 'firewall_blocked'
                    },
                    confidence_score=0.8,
                    detected_at=current_time
                )
                
                self._process_threat(threat)
    
    def _analyze_connection_patterns(self):
        """Analyze network connection patterns for anomalies"""
        try:
            if not self.app:
                return
            
            with self.app.app_context():
                devices = Device.query.filter_by(is_monitored=True).all()
                current_time = datetime.utcnow()
                
                for device in devices:
                    # Analyze device connection behavior
                    anomalies = self.anomaly_detection.detect_device_anomalies(device.id, hours=1)
                    
                    for anomaly in anomalies:
                        if anomaly.get('security_relevant', False):
                            threat_level = self._map_anomaly_to_threat_level(anomaly.get('severity', 'medium'))
                            
                            threat = NetworkThreat(
                                threat_id=f"anomaly_{device.id}_{anomaly['type']}_{int(current_time.timestamp())}",
                                source_ip=device.ip_address,
                                target_ip="network",
                                attack_type=AttackType.SUSPICIOUS_TRAFFIC,
                                threat_level=threat_level,
                                description=f"Suspicious network behavior detected from {device.display_name}: {anomaly.get('description', 'Anomalous activity')}",
                                evidence={
                                    'anomaly_type': anomaly['type'],
                                    'anomaly_details': anomaly.get('details', {}),
                                    'confidence': anomaly.get('confidence', 0.5),
                                    'device_info': {
                                        'name': device.display_name,
                                        'type': device.device_type,
                                        'vendor': device.vendor
                                    }
                                },
                                confidence_score=anomaly.get('confidence', 0.5),
                                detected_at=current_time
                            )
                            
                            if threat.confidence_score >= self.monitoring_config['threat_threshold']:
                                self._process_threat(threat)
                                
        except Exception as e:
            logger.error(f"Error analyzing connection patterns: {e}")
    
    def _analyze_current_connections(self):
        """Analyze current network connections for suspicious activity"""
        try:
            # Get current network connections
            result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                connections = self._parse_ss_output(result.stdout)
                
                # Analyze for suspicious patterns
                self._check_suspicious_connections(connections)
                self._check_connection_anomalies(connections)
            
        except subprocess.TimeoutExpired:
            logger.warning("ss command timed out")
        except Exception as e:
            logger.error(f"Error analyzing current connections: {e}")
    
    def _process_threat(self, threat: NetworkThreat):
        """Process a detected network threat"""
        try:
            logger.warning(f"NETWORK THREAT DETECTED: {threat.attack_type.value} from {threat.source_ip}")
            
            # Add to threat history
            self.threat_history.append(threat)
            
            # Update statistics
            self.monitoring_stats['threats_detected'] += 1
            self.monitoring_stats['active_threats'] += 1
            
            # Create security event
            self._create_security_event(threat)
            
            # Create alert
            self._create_threat_alert(threat)
            
            # Determine and execute response actions
            response_actions = self._determine_response_actions(threat)
            threat.response_actions = response_actions
            
            for action in response_actions:
                self._execute_response_action(threat, action)
            
            # Check if this should create a security incident
            if threat.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                self._create_security_incident(threat)
            
        except Exception as e:
            logger.error(f"Error processing threat: {e}")
    
    def _create_security_event(self, threat: NetworkThreat):
        """Create a security event record for the threat"""
        try:
            if not self.app:
                return
            
            with self.app.app_context():
                # Find the device associated with the source IP
                device = Device.query.filter_by(ip_address=threat.source_ip).first()
                
                event = SecurityEvent(
                    device_id=device.id if device else None,
                    event_type=f"threat_{threat.attack_type.value}",
                    severity=threat.threat_level.value,
                    message=threat.description,
                    event_metadata=json.dumps({
                        'threat_id': threat.threat_id,
                        'source_ip': threat.source_ip,
                        'target_ip': threat.target_ip,
                        'attack_type': threat.attack_type.value,
                        'evidence': threat.evidence,
                        'confidence_score': threat.confidence_score,
                        'duration_seconds': threat.duration_seconds,
                        'packet_count': threat.packet_count
                    }),
                    created_at=threat.detected_at
                )
                
                db.session.add(event)
                db.session.commit()
                
                logger.info(f"Created security event for threat {threat.threat_id}")
                
        except Exception as e:
            logger.error(f"Error creating security event: {e}")
            if self.app:
                db.session.rollback()
    
    def _create_threat_alert(self, threat: NetworkThreat):
        """Create an alert for the detected threat"""
        try:
            if not self.app:
                return
            
            with self.app.app_context():
                # Find the device associated with the source IP
                device = Device.query.filter_by(ip_address=threat.source_ip).first()
                
                alert_metadata = {
                    'threat_id': threat.threat_id,
                    'attack_type': threat.attack_type.value,
                    'source_ip': threat.source_ip,
                    'target_ip': threat.target_ip,
                    'confidence_score': threat.confidence_score,
                    'evidence': threat.evidence
                }
                
                alert = Alert(
                    device_id=device.id if device else None,
                    alert_type=f'security_threat_{threat.attack_type.value}',
                    severity=threat.threat_level.value,
                    message=f"[SECURITY THREAT] {threat.description}",
                    metadata=json.dumps(alert_metadata),
                    created_at=threat.detected_at
                )
                
                db.session.add(alert)
                db.session.commit()
                
                logger.info(f"Created threat alert for {threat.threat_id}")
                
        except Exception as e:
            logger.error(f"Error creating threat alert: {e}")
            if self.app:
                db.session.rollback()
    
    def _determine_response_actions(self, threat: NetworkThreat) -> List[str]:
        """Determine appropriate response actions for a threat"""
        actions = []
        
        # Default action: log and monitor
        actions.append("log_and_monitor")
        
        # Medium and higher threats: send notification
        if threat.threat_level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            actions.append("send_notification")
        
        # High and critical threats: additional actions
        if threat.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            actions.append("enhance_monitoring")
            
            # Specific actions based on attack type
            if threat.attack_type == AttackType.BRUTE_FORCE:
                actions.extend(["rate_limit_ip", "temporary_block"])
            elif threat.attack_type == AttackType.PORT_SCAN:
                actions.extend(["firewall_alert", "block_scanning_ip"])
            elif threat.attack_type == AttackType.DOS_ATTACK:
                actions.extend(["traffic_shaping", "emergency_block"])
        
        # Critical threats: emergency response
        if threat.threat_level == ThreatLevel.CRITICAL:
            actions.extend(["incident_response", "isolate_affected_systems"])
        
        return actions
    
    def _execute_response_action(self, threat: NetworkThreat, action: str):
        """Execute a specific response action"""
        try:
            logger.info(f"Executing response action '{action}' for threat {threat.threat_id}")
            
            if action == "send_notification":
                self._send_threat_notification(threat)
            elif action == "temporary_block":
                self._implement_temporary_block(threat.source_ip)
            elif action == "enhance_monitoring":
                self._enhance_monitoring(threat.source_ip)
            elif action == "incident_response":
                self._trigger_incident_response(threat)
            # Add more response actions as needed
            
        except Exception as e:
            logger.error(f"Error executing response action {action}: {e}")
    
    def _send_threat_notification(self, threat: NetworkThreat):
        """Send notification for detected threat"""
        try:
            from services.push_notifications import push_service
            from models import Configuration
            from config import Config
            
            # Update push service configuration
            push_service.enabled = Configuration.get_value('push_notifications_enabled', 'false').lower() == 'true'
            push_service.topic = Configuration.get_value('ntfy_topic', '')
            push_service.server = Configuration.get_value('ntfy_server', 'https://ntfy.sh')
            
            if push_service.is_configured():
                dashboard_url = f"http://{Config.HOST}:{Config.PORT}/security"
                
                success = push_service.send_security_threat(
                    threat_type=threat.attack_type.value,
                    source_ip=threat.source_ip,
                    severity=threat.threat_level.value,
                    description=threat.description,
                    dashboard_url=dashboard_url
                )
                
                if success:
                    logger.info(f"Sent threat notification for {threat.threat_id}")
                else:
                    logger.warning(f"Failed to send threat notification for {threat.threat_id}")
            
        except Exception as e:
            logger.error(f"Error sending threat notification: {e}")
    
    def _correlate_security_events(self):
        """Correlate recent security events to identify attack campaigns"""
        try:
            # Get recent threats for correlation
            recent_threats = [t for t in self.threat_history 
                            if (datetime.utcnow() - t.detected_at).total_seconds() <= 3600]  # Last hour
            
            if len(recent_threats) < 2:
                return
            
            # Group threats by source IP
            threats_by_source = defaultdict(list)
            for threat in recent_threats:
                threats_by_source[threat.source_ip].append(threat)
            
            # Look for coordinated attacks from same source
            for source_ip, threats in threats_by_source.items():
                if len(threats) >= 3:  # Multiple different attack types from same source
                    attack_types = set(t.attack_type for t in threats)
                    
                    if len(attack_types) >= 2:  # Different types of attacks
                        self._create_coordinated_attack_incident(source_ip, threats)
            
            # Look for distributed attacks (same attack type from multiple sources)
            threats_by_type = defaultdict(list)
            for threat in recent_threats:
                threats_by_type[threat.attack_type].append(threat)
            
            for attack_type, threats in threats_by_type.items():
                if len(threats) >= 5:  # Same attack from multiple sources
                    source_ips = set(t.source_ip for t in threats)
                    if len(source_ips) >= 3:  # From multiple sources
                        self._create_distributed_attack_incident(attack_type, threats)
                        
        except Exception as e:
            logger.error(f"Error correlating security events: {e}")
    
    def _identify_attack_campaigns(self):
        """Identify complex attack campaigns across time"""
        try:
            # Look for attack patterns over longer time periods
            extended_threats = [t for t in self.threat_history 
                              if (datetime.utcnow() - t.detected_at).total_seconds() <= 86400]  # Last 24 hours
            
            if len(extended_threats) < 5:
                return
            
            # Analyze attack progression patterns
            self._analyze_attack_progression(extended_threats)
            
            # Look for reconnaissance -> exploitation patterns
            self._detect_attack_kill_chain(extended_threats)
            
        except Exception as e:
            logger.error(f"Error identifying attack campaigns: {e}")
    
    def _analyze_attack_progression(self, threats: List[NetworkThreat]):
        """Analyze attack progression patterns"""
        try:
            # Sort threats by time
            sorted_threats = sorted(threats, key=lambda t: t.detected_at)
            
            # Look for typical attack progression: reconnaissance -> scanning -> exploitation
            progression_patterns = {
                'reconnaissance': [AttackType.NETWORK_RECONNAISSANCE, AttackType.PORT_SCAN],
                'exploitation': [AttackType.BRUTE_FORCE, AttackType.UNAUTHORIZED_ACCESS],
                'impact': [AttackType.DOS_ATTACK, AttackType.DATA_EXFILTRATION]
            }
            
            # Group threats into time windows
            time_windows = defaultdict(list)
            for threat in sorted_threats:
                window = int(threat.detected_at.timestamp() // 3600)  # Hour-based windows
                time_windows[window].append(threat)
            
            # Look for progression across windows
            windows = sorted(time_windows.keys())
            if len(windows) >= 3:
                self._check_attack_progression_pattern(windows, time_windows)
                
        except Exception as e:
            logger.error(f"Error analyzing attack progression: {e}")
    
    def _detect_attack_kill_chain(self, threats: List[NetworkThreat]):
        """Detect cyber attack kill chain patterns"""
        try:
            # Map attack types to kill chain phases
            kill_chain_phases = {
                'reconnaissance': [AttackType.NETWORK_RECONNAISSANCE, AttackType.PORT_SCAN],
                'weaponization': [AttackType.MALWARE_COMMUNICATION],
                'delivery': [AttackType.SUSPICIOUS_TRAFFIC],
                'exploitation': [AttackType.BRUTE_FORCE, AttackType.UNAUTHORIZED_ACCESS],
                'installation': [AttackType.MALWARE_COMMUNICATION],
                'command_control': [AttackType.SUSPICIOUS_TRAFFIC, AttackType.MALWARE_COMMUNICATION],
                'actions': [AttackType.DATA_EXFILTRATION, AttackType.DOS_ATTACK]
            }
            
            # Group threats by source IP
            threats_by_source = defaultdict(list)
            for threat in threats:
                threats_by_source[threat.source_ip].append(threat)
            
            # Check each source for kill chain progression
            for source_ip, source_threats in threats_by_source.items():
                if len(source_threats) >= 3:
                    phases_detected = set()
                    
                    for threat in source_threats:
                        for phase, attack_types in kill_chain_phases.items():
                            if threat.attack_type in attack_types:
                                phases_detected.add(phase)
                    
                    # If multiple phases detected, create incident
                    if len(phases_detected) >= 3:
                        self._create_kill_chain_incident(source_ip, source_threats, phases_detected)
                        
        except Exception as e:
            logger.error(f"Error detecting attack kill chain: {e}")
    
    def _update_threat_intelligence(self):
        """Update threat intelligence based on detected patterns"""
        try:
            # Update malicious IP tracking
            current_time = datetime.utcnow()
            recent_threats = [t for t in self.threat_history 
                            if (current_time - t.detected_at).total_seconds() <= 86400]
            
            # Track IPs with multiple high-severity threats
            threat_counts = defaultdict(int)
            for threat in recent_threats:
                if threat.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    threat_counts[threat.source_ip] += 1
            
            # Add frequently threatening IPs to malicious indicators
            for ip, count in threat_counts.items():
                if count >= 5:  # 5 or more high-severity threats
                    self.malicious_indicators['malicious_ips'].add(ip)
                    logger.info(f"Added {ip} to malicious IP indicators (threat count: {count})")
            
            # Clean up old indicators (remove IPs that haven't been threatening recently)
            self._cleanup_old_threat_indicators()
            
        except Exception as e:
            logger.error(f"Error updating threat intelligence: {e}")
    
    def _cleanup_old_threat_indicators(self):
        """Remove old threat indicators that are no longer active"""
        try:
            current_time = datetime.utcnow()
            cutoff_time = current_time - timedelta(days=7)  # 7 days threshold
            
            # Get recent threat sources
            recent_threat_sources = set()
            for threat in self.threat_history:
                if threat.detected_at >= cutoff_time:
                    recent_threat_sources.add(threat.source_ip)
            
            # Remove IPs that haven't been seen in recent threats
            old_malicious_ips = self.malicious_indicators['malicious_ips'] - recent_threat_sources
            
            for ip in old_malicious_ips:
                self.malicious_indicators['malicious_ips'].discard(ip)
                logger.info(f"Removed {ip} from malicious IP indicators (no recent activity)")
                
        except Exception as e:
            logger.error(f"Error cleaning up threat indicators: {e}")
    
    def _detect_active_attacks(self):
        """Detect currently active attacks"""
        try:
            current_time = datetime.utcnow()
            
            # Check for ongoing attacks (threats within last 5 minutes)
            active_threats = [t for t in self.threat_history 
                            if (current_time - t.detected_at).total_seconds() <= 300]
            
            if len(active_threats) >= 3:  # Multiple threats in short time
                # Check if we need to escalate response
                critical_active = [t for t in active_threats if t.threat_level == ThreatLevel.CRITICAL]
                high_active = [t for t in active_threats if t.threat_level == ThreatLevel.HIGH]
                
                if len(critical_active) >= 1 or len(high_active) >= 2:
                    self._escalate_active_attack_response(active_threats)
            
            # Update active threat count
            self.monitoring_stats['active_threats'] = len(active_threats)
            
        except Exception as e:
            logger.error(f"Error detecting active attacks: {e}")
    
    def _monitor_resource_usage(self):
        """Monitor system resource usage for security indicators"""
        try:
            # Check CPU and memory usage for anomalies
            # High resource usage could indicate DDoS or crypto mining
            
            # Use basic system commands to check resource usage
            try:
                # Check load average
                with open('/proc/loadavg', 'r') as f:
                    load_avg = float(f.read().split()[0])
                
                # Check memory usage
                result = subprocess.run(['free', '-m'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    if len(lines) >= 2:
                        mem_line = lines[1].split()
                        if len(mem_line) >= 3:
                            total_mem = int(mem_line[1])
                            used_mem = int(mem_line[2])
                            mem_usage_pct = (used_mem / total_mem) * 100
                            
                            # Check for resource exhaustion indicators
                            if load_avg > 10.0 or mem_usage_pct > 95:
                                self._create_resource_exhaustion_threat(load_avg, mem_usage_pct)
                                
            except (FileNotFoundError, PermissionError):
                pass  # System monitoring not available
                
        except Exception as e:
            logger.error(f"Error monitoring resource usage: {e}")
    
    def _create_resource_exhaustion_threat(self, load_avg: float, mem_usage_pct: float):
        """Create threat for resource exhaustion"""
        try:
            current_time = datetime.utcnow()
            
            threat = NetworkThreat(
                threat_id=f"resource_exhaustion_{int(current_time.timestamp())}",
                source_ip="localhost",
                target_ip="system",
                attack_type=AttackType.DOS_ATTACK,
                threat_level=ThreatLevel.HIGH,
                description=f"System resource exhaustion detected: Load {load_avg:.1f}, Memory {mem_usage_pct:.1f}%",
                evidence={
                    'load_average': load_avg,
                    'memory_usage_percent': mem_usage_pct,
                    'analysis_type': 'resource_monitoring'
                },
                confidence_score=0.8,
                detected_at=current_time
            )
            
            self._process_threat(threat)
            
        except Exception as e:
            logger.error(f"Error creating resource exhaustion threat: {e}")
    
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Get network security monitoring statistics"""
        try:
            current_time = datetime.utcnow()
            
            # Calculate recent threat statistics
            recent_threats = [t for t in self.threat_history 
                            if (current_time - t.detected_at).total_seconds() <= 3600]  # Last hour
            
            threat_by_type = defaultdict(int)
            threat_by_level = defaultdict(int)
            
            for threat in recent_threats:
                threat_by_type[threat.attack_type.value] += 1
                threat_by_level[threat.threat_level.value] += 1
            
            return {
                'monitoring_status': 'active' if self.running else 'inactive',
                'last_analysis': self.monitoring_stats['last_analysis'].isoformat() + 'Z',
                'total_threats_detected': self.monitoring_stats['threats_detected'],
                'active_threats': len(recent_threats),
                'recent_threats_by_type': dict(threat_by_type),
                'recent_threats_by_level': dict(threat_by_level),
                'monitoring_uptime_hours': (current_time - datetime.utcnow()).total_seconds() / 3600,
                'analysis_configuration': self.monitoring_config,
                'attack_thresholds': self.attack_thresholds
            }
            
        except Exception as e:
            logger.error(f"Error getting monitoring statistics: {e}")
            return {'error': str(e)}
    
    def get_recent_threats(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent network security threats"""
        try:
            current_time = datetime.utcnow()
            cutoff_time = current_time - timedelta(hours=hours)
            
            recent_threats = [t for t in self.threat_history if t.detected_at >= cutoff_time]
            
            return [
                {
                    'threat_id': threat.threat_id,
                    'source_ip': threat.source_ip,
                    'target_ip': threat.target_ip,
                    'attack_type': threat.attack_type.value,
                    'threat_level': threat.threat_level.value,
                    'description': threat.description,
                    'confidence_score': threat.confidence_score,
                    'detected_at': threat.detected_at.isoformat() + 'Z',
                    'response_actions': threat.response_actions,
                    'evidence': threat.evidence
                }
                for threat in sorted(recent_threats, key=lambda t: t.detected_at, reverse=True)
            ]
            
        except Exception as e:
            logger.error(f"Error getting recent threats: {e}")
            return []
    
    # Helper methods for parsing and analysis
    def _parse_log_timestamp(self, log_line: str) -> datetime:
        """Parse timestamp from log line"""
        # This is a simplified parser - would need to be more robust for production
        current_year = datetime.utcnow().year
        try:
            # Try to extract timestamp pattern from log line
            # This would need to be adapted for different log formats
            return datetime.utcnow()  # Placeholder
        except:
            return datetime.utcnow()
    
    def _map_anomaly_to_threat_level(self, anomaly_severity: str) -> ThreatLevel:
        """Map anomaly severity to threat level"""
        mapping = {
            'low': ThreatLevel.LOW,
            'medium': ThreatLevel.MEDIUM,
            'high': ThreatLevel.HIGH,
            'critical': ThreatLevel.CRITICAL
        }
        return mapping.get(anomaly_severity, ThreatLevel.MEDIUM)
    
    def _parse_netstat_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse netstat output for connection analysis"""
        connections = []
        lines = output.strip().split('\\n')
        
        for line in lines[2:]:  # Skip header lines
            parts = line.split()
            if len(parts) >= 4:
                connections.append({
                    'protocol': parts[0],
                    'local_address': parts[3],
                    'state': parts[5] if len(parts) > 5 else 'LISTEN'
                })
        
        return connections
    
    def _parse_ss_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse ss (socket statistics) output"""
        connections = []
        lines = output.strip().split('\\n')
        
        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 5:
                connections.append({
                    'state': parts[0],
                    'protocol': parts[1] if len(parts) > 1 else 'unknown',
                    'local_address': parts[4] if len(parts) > 4 else '',
                    'remote_address': parts[5] if len(parts) > 5 else ''
                })
        
        return connections
    
    def _analyze_connection_patterns_from_netstat(self, connections: List[Dict[str, Any]]):
        """Analyze connection patterns from netstat output"""
        try:
            # Count connections by type and destination
            connection_stats = defaultdict(int)
            suspicious_connections = []
            
            for conn in connections:
                protocol = conn.get('protocol', 'unknown')
                local_addr = conn.get('local_address', '')
                state = conn.get('state', '')
                
                connection_stats[f"{protocol}_{state}"] += 1
                
                # Check for connections to suspicious ports
                if ':' in local_addr:
                    try:
                        port = int(local_addr.split(':')[-1])
                        if port in self.malicious_indicators['suspicious_ports']:
                            suspicious_connections.append({
                                'protocol': protocol,
                                'port': port,
                                'state': state
                            })
                    except ValueError:
                        pass
            
            # Generate threat if too many suspicious connections
            if len(suspicious_connections) >= self.attack_thresholds['suspicious_port_threshold']:
                current_time = datetime.utcnow()
                
                threat = NetworkThreat(
                    threat_id=f"suspicious_connections_{int(current_time.timestamp())}",
                    source_ip="localhost",
                    target_ip="network",
                    attack_type=AttackType.SUSPICIOUS_TRAFFIC,
                    threat_level=ThreatLevel.MEDIUM,
                    description=f"Multiple connections to suspicious ports detected: {len(suspicious_connections)} connections",
                    evidence={
                        'suspicious_connections': suspicious_connections,
                        'connection_stats': dict(connection_stats),
                        'analysis_type': 'netstat_analysis'
                    },
                    confidence_score=0.7,
                    detected_at=current_time
                )
                
                self._process_threat(threat)
                
        except Exception as e:
            logger.error(f"Error analyzing connection patterns from netstat: {e}")
    
    def _check_suspicious_connections(self, connections: List[Dict[str, Any]]):
        """Check current connections for suspicious activity"""
        try:
            current_time = datetime.utcnow()
            suspicious_patterns = []
            
            # Analyze connection patterns
            remote_ips = defaultdict(int)
            remote_ports = defaultdict(int)
            
            for conn in connections:
                remote_addr = conn.get('remote_address', '')
                if remote_addr and ':' in remote_addr:
                    try:
                        ip, port = remote_addr.rsplit(':', 1)
                        remote_ips[ip] += 1
                        remote_ports[int(port)] += 1
                    except ValueError:
                        continue
            
            # Check for connections to many different IPs (potential data exfiltration)
            if len(remote_ips) > 50:  # More than 50 different remote IPs
                suspicious_patterns.append({
                    'pattern': 'excessive_remote_connections',
                    'count': len(remote_ips),
                    'severity': 'medium'
                })
            
            # Check for connections from single IP with high frequency
            for ip, count in remote_ips.items():
                if count > 20:  # More than 20 connections from single IP
                    suspicious_patterns.append({
                        'pattern': 'high_frequency_connection',
                        'source_ip': ip,
                        'count': count,
                        'severity': 'high' if count > 50 else 'medium'
                    })
            
            # Generate threats for suspicious patterns
            for pattern in suspicious_patterns:
                threat = NetworkThreat(
                    threat_id=f"connection_pattern_{pattern['pattern']}_{int(current_time.timestamp())}",
                    source_ip=pattern.get('source_ip', 'network'),
                    target_ip="localhost",
                    attack_type=AttackType.SUSPICIOUS_TRAFFIC,
                    threat_level=ThreatLevel.HIGH if pattern['severity'] == 'high' else ThreatLevel.MEDIUM,
                    description=f"Suspicious connection pattern detected: {pattern['pattern']}",
                    evidence=pattern,
                    confidence_score=0.8 if pattern['severity'] == 'high' else 0.6,
                    detected_at=current_time
                )
                
                self._process_threat(threat)
                
        except Exception as e:
            logger.error(f"Error checking suspicious connections: {e}")
    
    def _check_connection_anomalies(self, connections: List[Dict[str, Any]]):
        """Check for connection anomalies using statistical analysis"""
        try:
            # Track connection statistics over time
            current_stats = {
                'total_connections': len(connections),
                'tcp_connections': len([c for c in connections if c.get('protocol') == 'tcp']),
                'udp_connections': len([c for c in connections if c.get('protocol') == 'udp']),
                'listening_ports': len([c for c in connections if c.get('state') == 'LISTEN'])
            }
            
            # Store current stats (in production, this would be persistent)
            if not hasattr(self, '_connection_history'):
                self._connection_history = deque(maxlen=100)
            
            self._connection_history.append(current_stats)
            
            # Analyze for anomalies if we have enough historical data
            if len(self._connection_history) >= 10:
                historical_data = list(self._connection_history)
                
                for metric, current_value in current_stats.items():
                    historical_values = [h[metric] for h in historical_data[:-1]]
                    
                    if len(historical_values) > 0:
                        mean_value = statistics.mean(historical_values)
                        std_value = statistics.stdev(historical_values) if len(historical_values) > 1 else 0
                        
                        # Check for significant deviation (more than 3 standard deviations)
                        if std_value > 0 and abs(current_value - mean_value) > (3 * std_value):
                            current_time = datetime.utcnow()
                            
                            threat = NetworkThreat(
                                threat_id=f"connection_anomaly_{metric}_{int(current_time.timestamp())}",
                                source_ip="localhost",
                                target_ip="network",
                                attack_type=AttackType.SUSPICIOUS_TRAFFIC,
                                threat_level=ThreatLevel.MEDIUM,
                                description=f"Connection anomaly detected in {metric}: current={current_value}, mean={mean_value:.1f}, std={std_value:.1f}",
                                evidence={
                                    'metric': metric,
                                    'current_value': current_value,
                                    'historical_mean': mean_value,
                                    'historical_std': std_value,
                                    'deviation_factor': abs(current_value - mean_value) / std_value if std_value > 0 else 0,
                                    'analysis_type': 'statistical_anomaly'
                                },
                                confidence_score=0.6,
                                detected_at=current_time
                            )
                            
                            self._process_threat(threat)
                            
        except Exception as e:
            logger.error(f"Error checking connection anomalies: {e}")
    
    def _analyze_traffic_anomalies(self):
        """Analyze network traffic for anomalous patterns"""
        try:
            # This would analyze network traffic patterns
            # In a full implementation, this could use packet capture or flow data
            
            # For now, we'll analyze existing connection patterns
            self._analyze_bandwidth_anomalies()
            self._analyze_protocol_distribution_anomalies()
            
        except Exception as e:
            logger.error(f"Error analyzing traffic anomalies: {e}")
    
    def _analyze_bandwidth_anomalies(self):
        """Analyze bandwidth usage for anomalies"""
        try:
            if not self.app:
                return
            
            with self.app.app_context():
                # Get recent bandwidth data from devices
                from models import PerformanceMetrics
                
                recent_metrics = PerformanceMetrics.query.filter(
                    PerformanceMetrics.timestamp >= datetime.utcnow() - timedelta(hours=1)
                ).all()
                
                # Analyze bandwidth patterns
                device_bandwidth = defaultdict(list)
                
                for metric in recent_metrics:
                    if metric.bandwidth_in_mbps and metric.bandwidth_out_mbps:
                        total_bandwidth = metric.bandwidth_in_mbps + metric.bandwidth_out_mbps
                        device_bandwidth[metric.device_id].append(total_bandwidth)
                
                # Check for bandwidth anomalies
                for device_id, bandwidth_values in device_bandwidth.items():
                    if len(bandwidth_values) >= 5:  # Need enough data points
                        mean_bw = statistics.mean(bandwidth_values)
                        max_bw = max(bandwidth_values)
                        
                        # Check for bandwidth spikes
                        if max_bw > (mean_bw * 5) and max_bw > 10:  # 5x increase and >10 Mbps
                            device = Device.query.get(device_id)
                            if device:
                                current_time = datetime.utcnow()
                                
                                threat = NetworkThreat(
                                    threat_id=f"bandwidth_anomaly_{device_id}_{int(current_time.timestamp())}",
                                    source_ip=device.ip_address,
                                    target_ip="network",
                                    attack_type=AttackType.DATA_EXFILTRATION,
                                    threat_level=ThreatLevel.MEDIUM,
                                    description=f"Bandwidth anomaly detected on {device.display_name}: {max_bw:.1f} Mbps (avg: {mean_bw:.1f} Mbps)",
                                    evidence={
                                        'max_bandwidth_mbps': max_bw,
                                        'average_bandwidth_mbps': mean_bw,
                                        'spike_factor': max_bw / mean_bw,
                                        'device_info': {
                                            'name': device.display_name,
                                            'type': device.device_type
                                        }
                                    },
                                    confidence_score=0.7,
                                    detected_at=current_time
                                )
                                
                                self._process_threat(threat)
                                
        except Exception as e:
            logger.error(f"Error analyzing bandwidth anomalies: {e}")
    
    def _analyze_protocol_distribution_anomalies(self):
        """Analyze protocol distribution for anomalies"""
        try:
            # Get current protocol distribution
            result = subprocess.run(['ss', '-s'], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse socket statistics summary
                lines = result.stdout.split('\n')
                protocol_stats = {}
                
                for line in lines:
                    if 'TCP:' in line:
                        # Extract TCP connection count
                        tcp_match = re.search(r'TCP:\s+(\d+)', line)
                        if tcp_match:
                            protocol_stats['tcp'] = int(tcp_match.group(1))
                    elif 'UDP:' in line:
                        # Extract UDP connection count
                        udp_match = re.search(r'UDP:\s+(\d+)', line)
                        if udp_match:
                            protocol_stats['udp'] = int(udp_match.group(1))
                
                # Store and analyze protocol statistics over time
                if not hasattr(self, '_protocol_history'):
                    self._protocol_history = deque(maxlen=50)
                
                self._protocol_history.append(protocol_stats)
                
                # Look for unusual protocol distribution
                if len(self._protocol_history) >= 10:
                    self._detect_protocol_anomalies(protocol_stats)
                    
        except Exception as e:
            logger.error(f"Error analyzing protocol distribution: {e}")
    
    def _detect_protocol_anomalies(self, current_stats: Dict[str, int]):
        """Detect anomalies in protocol distribution"""
        try:
            historical_data = list(self._protocol_history)[:-1]  # Exclude current
            
            for protocol, current_count in current_stats.items():
                historical_counts = [h.get(protocol, 0) for h in historical_data]
                
                if len(historical_counts) > 0:
                    mean_count = statistics.mean(historical_counts)
                    
                    # Check for significant increase in protocol usage
                    if mean_count > 0 and current_count > (mean_count * 3):
                        current_time = datetime.utcnow()
                        
                        threat = NetworkThreat(
                            threat_id=f"protocol_anomaly_{protocol}_{int(current_time.timestamp())}",
                            source_ip="localhost",
                            target_ip="network",
                            attack_type=AttackType.SUSPICIOUS_TRAFFIC,
                            threat_level=ThreatLevel.MEDIUM,
                            description=f"Unusual {protocol.upper()} protocol activity: {current_count} connections (avg: {mean_count:.1f})",
                            evidence={
                                'protocol': protocol,
                                'current_connections': current_count,
                                'historical_average': mean_count,
                                'increase_factor': current_count / mean_count,
                                'analysis_type': 'protocol_distribution'
                            },
                            confidence_score=0.6,
                            detected_at=current_time
                        )
                        
                        self._process_threat(threat)
                        
        except Exception as e:
            logger.error(f"Error detecting protocol anomalies: {e}")
    
    def _analyze_device_behavior(self):
        """Analyze individual device behavior for security threats"""
        try:
            if not self.app:
                return
            
            with self.app.app_context():
                devices = Device.query.filter_by(is_monitored=True).all()
                
                for device in devices:
                    # Check device response patterns
                    self._check_device_response_anomalies(device)
                    
                    # Check device uptime patterns
                    self._check_device_uptime_anomalies(device)
                    
        except Exception as e:
            logger.error(f"Error analyzing device behavior: {e}")
    
    def _check_device_response_anomalies(self, device: Device):
        """Check for anomalies in device response patterns"""
        try:
            from models import MonitoringData
            
            # Get recent monitoring data
            recent_data = MonitoringData.query.filter(
                MonitoringData.device_id == device.id,
                MonitoringData.timestamp >= datetime.utcnow() - timedelta(hours=2)
            ).order_by(MonitoringData.timestamp.desc()).limit(100).all()
            
            if len(recent_data) < 10:
                return
            
            # Analyze response times for patterns
            response_times = [d.response_time for d in recent_data if d.response_time is not None]
            
            if len(response_times) >= 10:
                # Check for unusual response time patterns
                mean_response = statistics.mean(response_times)
                recent_responses = response_times[:10]  # Most recent 10
                recent_mean = statistics.mean(recent_responses)
                
                # Check for significant degradation (possible DoS or resource exhaustion)
                if mean_response > 0 and recent_mean > (mean_response * 5):
                    current_time = datetime.utcnow()
                    
                    threat = NetworkThreat(
                        threat_id=f"response_degradation_{device.id}_{int(current_time.timestamp())}",
                        source_ip=device.ip_address,
                        target_ip="localhost",
                        attack_type=AttackType.DOS_ATTACK,
                        threat_level=ThreatLevel.MEDIUM,
                        description=f"Severe response time degradation detected on {device.display_name}: {recent_mean:.1f}ms (avg: {mean_response:.1f}ms)",
                        evidence={
                            'device_name': device.display_name,
                            'recent_avg_response_ms': recent_mean,
                            'historical_avg_response_ms': mean_response,
                            'degradation_factor': recent_mean / mean_response,
                            'sample_size': len(response_times)
                        },
                        confidence_score=0.7,
                        detected_at=current_time
                    )
                    
                    self._process_threat(threat)
                    
        except Exception as e:
            logger.error(f"Error checking device response anomalies for {device.id}: {e}")
    
    def _check_device_uptime_anomalies(self, device: Device):
        """Check for unusual uptime patterns that might indicate compromise"""
        try:
            # Check for devices that are online at unusual times
            # or have changed their typical uptime patterns
            
            current_time = datetime.utcnow()
            hour_of_day = current_time.hour
            
            # Simple heuristic: if device is typically offline at night but suddenly online
            if device.is_online() and (hour_of_day < 6 or hour_of_day > 22):  # Late night/early morning
                # Check if this is unusual for this device
                from models import MonitoringData
                
                # Get historical data for same time period
                same_hour_data = MonitoringData.query.filter(
                    MonitoringData.device_id == device.id,
                    db.extract('hour', MonitoringData.timestamp) == hour_of_day,
                    MonitoringData.timestamp >= datetime.utcnow() - timedelta(days=30),
                    MonitoringData.response_time.isnot(None)
                ).count()
                
                total_same_hour_checks = MonitoringData.query.filter(
                    MonitoringData.device_id == device.id,
                    db.extract('hour', MonitoringData.timestamp) == hour_of_day,
                    MonitoringData.timestamp >= datetime.utcnow() - timedelta(days=30)
                ).count()
                
                if total_same_hour_checks > 10:  # Need enough data
                    online_percentage = (same_hour_data / total_same_hour_checks) * 100
                    
                    # If device is usually offline at this hour but is online now
                    if online_percentage < 20:  # Less than 20% uptime at this hour historically
                        threat = NetworkThreat(
                            threat_id=f"unusual_activity_{device.id}_{int(current_time.timestamp())}",
                            source_ip=device.ip_address,
                            target_ip="network",
                            attack_type=AttackType.UNAUTHORIZED_ACCESS,
                            threat_level=ThreatLevel.LOW,
                            description=f"Unusual activity time detected on {device.display_name}: online at {hour_of_day}:00 (historically {online_percentage:.1f}% uptime)",
                            evidence={
                                'device_name': device.display_name,
                                'hour_of_day': hour_of_day,
                                'historical_uptime_percentage': online_percentage,
                                'analysis_period_days': 30,
                                'device_type': device.device_type
                            },
                            confidence_score=0.4,  # Lower confidence as this could be legitimate
                            detected_at=current_time
                        )
                        
                        self._process_threat(threat)
                        
        except Exception as e:
            logger.error(f"Error checking device uptime anomalies for {device.id}: {e}")
    
    def _successful_brute_force(self, failed_attempts: Dict[str, List[datetime]], success_attempts: List[Tuple[str, datetime]]):
        """Detect successful brute force attacks (success after many failures)"""
        try:
            current_time = datetime.utcnow()
            window_start = current_time - timedelta(minutes=30)  # 30-minute window
            
            for success_ip, success_time in success_attempts:
                if success_time >= window_start:
                    # Check if this IP had many recent failed attempts
                    recent_failures = [ts for ts in failed_attempts.get(success_ip, []) if ts >= window_start and ts < success_time]
                    
                    if len(recent_failures) >= 10:  # Many failures before success
                        threat = NetworkThreat(
                            threat_id=f"successful_brute_force_{success_ip}_{int(current_time.timestamp())}",
                            source_ip=success_ip,
                            target_ip="localhost",
                            attack_type=AttackType.BRUTE_FORCE,
                            threat_level=ThreatLevel.CRITICAL,
                            description=f"Successful brute force attack from {success_ip}: {len(recent_failures)} failures followed by successful login",
                            evidence={
                                'failed_attempts_before_success': len(recent_failures),
                                'success_timestamp': success_time.isoformat(),
                                'attack_duration_minutes': (success_time - min(recent_failures)).total_seconds() / 60,
                                'attack_pattern': 'brute_force_then_success'
                            },
                            confidence_score=0.95,
                            detected_at=current_time
                        )
                        
                        self._process_threat(threat)
                        
        except Exception as e:
            logger.error(f"Error detecting successful brute force: {e}")
    
    def _analyze_application_security_event(self, log_line: str):
        """Analyze application log line for security indicators"""
        try:
            # Extract timestamp and message
            current_time = datetime.utcnow()
            
            # Look for specific security patterns
            security_keywords = {
                'sql injection': AttackType.UNAUTHORIZED_ACCESS,
                'cross-site scripting': AttackType.UNAUTHORIZED_ACCESS,
                'directory traversal': AttackType.UNAUTHORIZED_ACCESS,
                'buffer overflow': AttackType.UNAUTHORIZED_ACCESS,
                'privilege escalation': AttackType.UNAUTHORIZED_ACCESS,
                'unauthorized access': AttackType.UNAUTHORIZED_ACCESS,
                'authentication bypass': AttackType.UNAUTHORIZED_ACCESS,
                'session hijack': AttackType.UNAUTHORIZED_ACCESS
            }
            
            log_line_lower = log_line.lower()
            
            for keyword, attack_type in security_keywords.items():
                if keyword in log_line_lower:
                    # Extract source IP if possible
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log_line)
                    source_ip = ip_match.group(1) if ip_match else "unknown"
                    
                    threat = NetworkThreat(
                        threat_id=f"app_security_{keyword.replace(' ', '_')}_{int(current_time.timestamp())}",
                        source_ip=source_ip,
                        target_ip="application",
                        attack_type=attack_type,
                        threat_level=ThreatLevel.HIGH,
                        description=f"Security event detected in application logs: {keyword}",
                        evidence={
                            'log_line': log_line.strip(),
                            'security_keyword': keyword,
                            'source': 'application_logs'
                        },
                        confidence_score=0.8,
                        detected_at=current_time
                    )
                    
                    self._process_threat(threat)
                    break  # Only process first match per log line
                    
        except Exception as e:
            logger.error(f"Error analyzing application security event: {e}")


    def _implement_temporary_block(self, ip_address: str):
        """Implement temporary IP blocking (placeholder)"""
        logger.info(f"Implementing temporary block for IP {ip_address}")
        # In production, this would interface with firewall systems
    
    def _enhance_monitoring(self, ip_address: str):
        """Enhance monitoring for specific IP address"""
        logger.info(f"Enhancing monitoring for IP {ip_address}")
        # Could increase monitoring frequency, add additional checks
    
    def _trigger_incident_response(self, threat: NetworkThreat):
        """Trigger incident response procedures"""
        logger.critical(f"TRIGGERING INCIDENT RESPONSE for threat {threat.threat_id}")
        # Would integrate with incident response systems
    
    def _create_coordinated_attack_incident(self, source_ip: str, threats: List[NetworkThreat]):
        """Create incident for coordinated attack from single source"""
        try:
            from models import SecurityIncident
            
            if not self.app:
                return
            
            with self.app.app_context():
                incident_id = f"COORD_{source_ip.replace('.', '_')}_{int(datetime.utcnow().timestamp())}"
                
                attack_types = list(set(t.attack_type.value for t in threats))
                max_severity = max(t.threat_level for t in threats)
                
                incident = SecurityIncident(
                    incident_id=incident_id,
                    title=f"Coordinated Attack from {source_ip}",
                    description=f"Multiple attack types detected from {source_ip}: {', '.join(attack_types)}",
                    severity=max_severity.value,
                    category="coordinated_attack",
                    affected_devices=json.dumps([t.target_ip for t in threats]),
                    affected_services=json.dumps(attack_types),
                    response_actions=json.dumps(["block_ip", "enhance_monitoring", "forensic_analysis"]),
                    risk_score=8.0,
                    business_impact="high"
                )
                
                db.session.add(incident)
                db.session.commit()
                
                logger.warning(f"Created coordinated attack incident: {incident_id}")
                
        except Exception as e:
            logger.error(f"Error creating coordinated attack incident: {e}")
    
    def _create_distributed_attack_incident(self, attack_type: AttackType, threats: List[NetworkThreat]):
        """Create incident for distributed attack"""
        try:
            from models import SecurityIncident
            
            if not self.app:
                return
            
            with self.app.app_context():
                incident_id = f"DIST_{attack_type.value}_{int(datetime.utcnow().timestamp())}"
                
                source_ips = list(set(t.source_ip for t in threats))
                
                incident = SecurityIncident(
                    incident_id=incident_id,
                    title=f"Distributed {attack_type.value} Attack",
                    description=f"Distributed {attack_type.value} attack from {len(source_ips)} source IPs",
                    severity="high",
                    category="distributed_attack",
                    affected_devices=json.dumps(list(set(t.target_ip for t in threats))),
                    affected_services=json.dumps([attack_type.value]),
                    response_actions=json.dumps(["block_source_ips", "rate_limiting", "ddos_mitigation"]),
                    risk_score=7.5,
                    business_impact="high"
                )
                
                db.session.add(incident)
                db.session.commit()
                
                logger.warning(f"Created distributed attack incident: {incident_id}")
                
        except Exception as e:
            logger.error(f"Error creating distributed attack incident: {e}")
    
    def _create_security_incident(self, threat: NetworkThreat):
        """Create a security incident for high-severity threats"""
        try:
            from models import SecurityIncident
            
            if not self.app:
                return
            
            with self.app.app_context():
                incident_id = f"THREAT_{threat.threat_id}"
                
                incident = SecurityIncident(
                    incident_id=incident_id,
                    title=f"{threat.attack_type.value} - {threat.threat_level.value}",
                    description=threat.description,
                    severity=threat.threat_level.value,
                    category=threat.attack_type.value,
                    affected_devices=json.dumps([threat.target_ip]),
                    response_actions=json.dumps(threat.response_actions),
                    risk_score=threat.confidence_score * 10,
                    business_impact="medium" if threat.threat_level == ThreatLevel.HIGH else "high"
                )
                
                db.session.add(incident)
                db.session.commit()
                
                logger.warning(f"Created security incident: {incident_id}")
                
        except Exception as e:
            logger.error(f"Error creating security incident: {e}")

# Global network security monitor instance
network_security_monitor = NetworkSecurityMonitor()