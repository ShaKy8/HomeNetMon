import nmap
import threading
import logging
import time
import json
import socket
import ssl
import subprocess
import hashlib
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from models import db, Device, Alert, Configuration
from sqlalchemy import and_
from services.anomaly_detection import AnomalyDetectionEngine

logger = logging.getLogger(__name__)

class SecuritySeverity(Enum):
    """Enhanced security severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityCategory(Enum):
    """Vulnerability categories"""
    NETWORK = "network"
    SERVICE = "service"
    CONFIGURATION = "configuration"
    CERTIFICATE = "certificate"
    AUTHENTICATION = "authentication"
    ENCRYPTION = "encryption"
    ACCESS_CONTROL = "access_control"
    COMPLIANCE = "compliance"


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    CIS = "cis"
    NIST = "nist"
    PCI_DSS = "pci_dss"
    ISO27001 = "iso27001"


@dataclass
class SecurityAlert:
    """Represents a security-related alert"""
    device_id: int
    device_name: str
    alert_type: str  # 'new_service', 'suspicious_port', 'vulnerability', 'config_change'
    severity: str    # 'low', 'medium', 'high', 'critical'
    message: str
    detected_at: datetime
    port: Optional[int] = None
    service: Optional[str] = None
    version: Optional[str] = None
    risk_score: Optional[float] = None


@dataclass
class VulnerabilityFinding:
    """Enhanced vulnerability finding"""
    finding_id: str
    device_id: int
    device_name: str
    category: VulnerabilityCategory
    severity: SecuritySeverity
    title: str
    description: str
    evidence: Dict[str, Any]
    risk_score: float
    remediation: List[str]
    discovered_at: datetime
    last_verified: datetime
    status: str = "open"  # open, acknowledged, remediated, false_positive
    cvss_score: Optional[float] = None
    cve_references: List[str] = field(default_factory=list)
    compliance_violations: List[str] = field(default_factory=list)


@dataclass
class SSLCertificateInfo:
    """SSL Certificate information"""
    device_id: int
    port: int
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    key_size: int
    is_self_signed: bool
    is_expired: bool
    days_until_expiry: int
    san_list: List[str] = field(default_factory=list)


@dataclass
class ComplianceCheck:
    """Compliance check result"""
    check_id: str
    framework: ComplianceFramework
    rule_id: str
    title: str
    description: str
    severity: SecuritySeverity
    status: str  # pass, fail, not_applicable
    evidence: Dict[str, Any]
    remediation: List[str]
    checked_at: datetime

@dataclass
class PortScanResult:
    """Represents the result of a port scan"""
    device_id: int
    ip_address: str
    port: int
    state: str       # 'open', 'closed', 'filtered'
    service: str
    version: str
    product: str
    extra_info: str
    confidence: int
    scanned_at: datetime

class NetworkSecurityScanner:
    """Enhanced enterprise-grade network security scanner for HomeNetMon with comprehensive vulnerability assessment"""
    
    def __init__(self, app=None):
        self.app = app
        self.running = False
        self.scan_interval = 86400  # 24 hours default - much less aggressive to reduce alerts
        self.nm = nmap.PortScanner()
        self.anomaly_detection = AnomalyDetectionEngine()
        
        # Scan progress tracking
        self.current_scan = {
            'active': False,
            'start_time': None,
            'end_time': None,
            'status': 'idle',  # idle, running, completed, failed
            'progress': 0,
            'total_devices': 0,
            'devices_completed': 0,
            'current_device': None,
            'current_device_progress': 0,
            'total_ports_scanned': 0,
            'open_ports_found': 0,
            'alerts_generated': 0,
            'error_message': None
        }
        
        # Security scanning configuration
        self.scan_config = {
            'top_ports': 1000,  # Scan top 1000 most common ports
            'service_detection': True,
            'version_detection': True,
            'aggressive_timing': True,  # T4 timing
            'skip_host_discovery': True,  # Assume hosts are up
            'max_concurrent_scans': 5
        }
        
        # Risk scoring weights
        self.risk_weights = {
            'ssh': 3,           # SSH access
            'telnet': 8,        # Unencrypted remote access
            'ftp': 5,           # File transfer
            'smtp': 4,          # Email server
            'http': 2,          # Web server
            'https': 1,         # Secure web server
            'rdp': 7,           # Remote desktop
            'vnc': 6,           # VNC remote access
            'snmp': 5,          # Network management
            'nfs': 4,           # Network file system
            'smb': 6,           # Windows file sharing
            'mysql': 5,         # Database
            'postgresql': 5,    # Database
            'mongodb': 5,       # Database
            'redis': 4,         # Cache/database
            'unknown': 2        # Unknown service
        }
        
        # Suspicious ports that should trigger alerts
        self.suspicious_ports = {
            23: 'telnet',       # Unencrypted remote access
            135: 'msrpc',       # Microsoft RPC
            139: 'netbios',     # NetBIOS
            445: 'smb',         # SMB/CIFS
            1433: 'mssql',      # Microsoft SQL Server
            3389: 'rdp',        # Remote Desktop
            5432: 'postgresql', # PostgreSQL
            5900: 'vnc',        # VNC
            6379: 'redis',      # Redis
            27017: 'mongodb'    # MongoDB
        }
    
    def start_monitoring(self):
        """Start the security scanner monitoring loop"""
        if self.running:
            logger.warning("Security scanner already running")
            return
            
        self.running = True
        logger.info("Starting network security scanner")
        
        def scanner_loop():
            while self.running:
                try:
                    self.run_security_scan()
                    time.sleep(self.scan_interval)
                except Exception as e:
                    logger.error(f"Error in security scanner loop: {e}")
                    time.sleep(300)  # Wait 5 minutes on error
        
        scanner_thread = threading.Thread(
            target=scanner_loop,
            daemon=True,
            name='SecurityScanner'
        )
        scanner_thread.start()
    
    def stop_monitoring(self):
        """Stop the security scanner monitoring"""
        self.running = False
        logger.info("Security scanner stopped")
    
    def get_scan_progress(self):
        """Get current scan progress"""
        return dict(self.current_scan)
    
    def _reset_scan_progress(self):
        """Reset scan progress tracking"""
        self.current_scan.update({
            'active': False,
            'start_time': None,
            'end_time': None,
            'status': 'idle',
            'progress': 0,
            'total_devices': 0,
            'devices_completed': 0,
            'current_device': None,
            'current_device_progress': 0,
            'total_ports_scanned': 0,
            'open_ports_found': 0,
            'alerts_generated': 0,
            'error_message': None
        })
    
    def _update_scan_progress(self, **kwargs):
        """Update scan progress"""
        self.current_scan.update(kwargs)
        
        # Calculate overall progress
        if self.current_scan['total_devices'] > 0:
            device_progress = self.current_scan['devices_completed'] / self.current_scan['total_devices']
            current_device_progress = self.current_scan['current_device_progress'] / 100.0
            
            # Overall progress is completed devices + partial progress of current device
            overall_progress = device_progress + (current_device_progress / self.current_scan['total_devices'])
            self.current_scan['progress'] = min(100, int(overall_progress * 100))
    
    def run_security_scan(self):
        """Run a complete security scan of the network"""
        logger.info("Starting network security scan")
        
        if not self.app:
            logger.error("No Flask app context available")
            self._update_scan_progress(status='failed', error_message='No Flask app context available')
            return
        
        # Reset and start progress tracking
        self._reset_scan_progress()
        self._update_scan_progress(
            active=True,
            status='running', 
            start_time=datetime.utcnow()
        )
        
        try:
            with self.app.app_context():
                devices = Device.query.filter_by(is_monitored=True).all()
                total_devices = len(devices)
                
                self._update_scan_progress(total_devices=total_devices)
                logger.info(f"Found {total_devices} devices to scan")
                
                scan_results = []
                security_alerts = []
                
                for i, device in enumerate(devices):
                    try:
                        # Update progress for current device
                        self._update_scan_progress(
                            current_device=device.display_name,
                            current_device_progress=0
                        )
                        
                        logger.info(f"Scanning device {i+1}/{total_devices}: {device.display_name} ({device.ip_address})")
                        
                        # Update progress to show scanning started
                        self._update_scan_progress(current_device_progress=25)
                        
                        device_results = self.scan_device_ports(device)
                        scan_results.extend(device_results)
                        
                        # Update progress after port scan
                        self._update_scan_progress(
                            current_device_progress=75,
                            total_ports_scanned=self.current_scan['total_ports_scanned'] + len(device_results),
                            open_ports_found=self.current_scan['open_ports_found'] + len([r for r in device_results if r.state == 'open'])
                        )
                        
                        # Analyze results for security issues
                        device_alerts = self.analyze_security_results(device, device_results)
                        security_alerts.extend(device_alerts)
                        
                        # Mark device as completed
                        self._update_scan_progress(
                            devices_completed=i + 1,
                            current_device_progress=100,
                            alerts_generated=len(security_alerts)
                        )
                        
                    except Exception as e:
                        logger.error(f"Error scanning device {device.id}: {e}")
                        # Still mark as completed to continue with other devices
                        self._update_scan_progress(devices_completed=i + 1)
                
                # Store scan results
                if scan_results:
                    logger.info(f"Storing {len(scan_results)} scan results")
                    self.store_scan_results(scan_results)
                
                # Process security alerts
                if security_alerts:
                    logger.info(f"Found {len(security_alerts)} security issues")
                    self.process_security_alerts(security_alerts)
                else:
                    logger.info("No security issues detected")
                
                # Mark scan as completed
                self._update_scan_progress(
                    status='completed',
                    end_time=datetime.utcnow(),
                    progress=100,
                    current_device=None,
                    current_device_progress=0
                )
                
                logger.info(f"Network security scan completed - scanned {total_devices} devices, found {len([r for r in scan_results if r.state == 'open'])} open ports, generated {len(security_alerts)} alerts")
                
        except Exception as e:
            logger.error(f"Security scan failed: {e}")
            self._update_scan_progress(
                status='failed',
                end_time=datetime.utcnow(),
                error_message=str(e)
            )
    
    def start_background_scan(self):
        """Start a background security scan"""
        if self.current_scan['active']:
            logger.warning("Security scan already in progress")
            return {'success': False, 'error': 'Scan already in progress'}
        
        try:
            # Start scan in background thread
            scan_thread = threading.Thread(
                target=self.run_security_scan,
                daemon=True,
                name='BackgroundSecurityScan'
            )
            scan_thread.start()
            
            logger.info("Background security scan started")
            return {'success': True, 'message': 'Security scan started in background'}
            
        except Exception as e:
            logger.error(f"Failed to start background scan: {e}")
            return {'success': False, 'error': str(e)}
    
    def scan_device_ports(self, device: Device) -> List[PortScanResult]:
        """Enhanced port scanning with comprehensive service detection"""
        results = []
        
        try:
            # Build enhanced nmap command arguments
            nmap_args = f"-T4 --top-ports {self.scan_config['top_ports']}"
            
            if self.scan_config['service_detection']:
                nmap_args += " -sV"
            
            if self.scan_config['version_detection']:
                nmap_args += " --version-intensity 7"
            
            if self.scan_config['skip_host_discovery']:
                nmap_args += " -Pn"
            
            # OS detection requires root privileges - disabled for CAP_NET_RAW mode
            # nmap_args += " -O --osscan-limit"
            
            # Add script scanning for vulnerability detection
            nmap_args += " --script=vuln,safe,version"
            
            logger.debug(f"Running enhanced nmap scan: nmap {nmap_args} {device.ip_address}")
            scan_result = self.nm.scan(device.ip_address, arguments=nmap_args)
            
            # Parse results
            if device.ip_address in scan_result['scan']:
                host_info = scan_result['scan'][device.ip_address]
                
                # Parse TCP ports
                if 'tcp' in host_info:
                    for port, port_info in host_info['tcp'].items():
                        result = PortScanResult(
                            device_id=device.id,
                            ip_address=device.ip_address,
                            port=port,
                            state=port_info.get('state', 'unknown'),
                            service=port_info.get('name', 'unknown'),
                            version=port_info.get('version', ''),
                            product=port_info.get('product', ''),
                            extra_info=port_info.get('extrainfo', ''),
                            confidence=port_info.get('conf', 0),
                            scanned_at=datetime.utcnow()
                        )
                        results.append(result)
                        
                        logger.debug(f"Found service: {device.ip_address}:{port} - {result.service} {result.version}")
                
                # Parse UDP ports if enabled
                if 'udp' in host_info:
                    for port, port_info in host_info['udp'].items():
                        result = PortScanResult(
                            device_id=device.id,
                            ip_address=device.ip_address,
                            port=port,
                            state=port_info.get('state', 'unknown'),
                            service=f"udp/{port_info.get('name', 'unknown')}",
                            version=port_info.get('version', ''),
                            product=port_info.get('product', ''),
                            extra_info=port_info.get('extrainfo', ''),
                            confidence=port_info.get('conf', 0),
                            scanned_at=datetime.utcnow()
                        )
                        results.append(result)
                
                # Store OS detection results if available
                if 'osmatch' in host_info and host_info['osmatch']:
                    os_info = host_info['osmatch'][0]
                    self._store_os_detection(device.id, os_info)
        
        except Exception as e:
            logger.error(f"Error scanning {device.ip_address}: {e}")
        
        return results
    
    def analyze_security_results(self, device: Device, scan_results: List[PortScanResult]) -> List[SecurityAlert]:
        """Analyze scan results for security issues"""
        alerts = []
        
        # Get previous scan results for comparison
        previous_results = self.get_previous_scan_results(device.id)
        previous_services = {(r['port'], r['service']) for r in previous_results}
        current_services = {(r.port, r.service) for r in scan_results if r.state == 'open'}
        
        # Check for new services
        new_services = current_services - previous_services
        for port, service in new_services:
            alert = SecurityAlert(
                device_id=device.id,
                device_name=device.display_name,
                alert_type='new_service',
                severity=self.calculate_service_severity(port, service),
                message=f"New service detected: {service} on port {port}",
                detected_at=datetime.utcnow(),
                port=port,
                service=service,
                risk_score=self.calculate_risk_score(port, service)
            )
            alerts.append(alert)
        
        # Check for suspicious ports
        for result in scan_results:
            if result.state == 'open' and result.port in self.suspicious_ports:
                alert = SecurityAlert(
                    device_id=device.id,
                    device_name=device.display_name,
                    alert_type='suspicious_port',
                    severity='high',
                    message=f"Suspicious service detected: {result.service} on port {result.port}",
                    detected_at=datetime.utcnow(),
                    port=result.port,
                    service=result.service,
                    version=result.version,
                    risk_score=self.calculate_risk_score(result.port, result.service)
                )
                alerts.append(alert)
        
        # Check for high-risk services
        for result in scan_results:
            if result.state == 'open':
                risk_score = self.calculate_risk_score(result.port, result.service)
                if risk_score >= 9:  # Much higher risk threshold to reduce false alarms
                    alert = SecurityAlert(
                        device_id=device.id,
                        device_name=device.display_name,
                        alert_type='vulnerability',
                        severity='critical' if risk_score >= 8 else 'high',
                        message=f"High-risk service: {result.service} v{result.version} on port {result.port}",
                        detected_at=datetime.utcnow(),
                        port=result.port,
                        service=result.service,
                        version=result.version,
                        risk_score=risk_score
                    )
                    alerts.append(alert)
        
        return alerts
    
    def calculate_risk_score(self, port: int, service: str) -> float:
        """Calculate risk score for a service"""
        base_score = self.risk_weights.get(service.lower(), self.risk_weights['unknown'])
        
        # Adjust score based on port
        if port in self.suspicious_ports:
            base_score += 2
        
        # Well-known insecure services
        if service.lower() in ['telnet', 'ftp', 'http']:
            base_score += 1
        
        # Secure services get lower scores
        if service.lower() in ['https', 'ssh']:
            base_score = max(1, base_score - 1)
        
        return min(10.0, base_score)
    
    def calculate_service_severity(self, port: int, service: str) -> str:
        """Calculate severity level for a service"""
        risk_score = self.calculate_risk_score(port, service)
        
        # Much higher thresholds to reduce alert sensitivity
        if risk_score >= 9.5:
            return 'critical'
        elif risk_score >= 8:
            return 'high'
        elif risk_score >= 6:
            return 'medium'
        else:
            return 'low'
    
    def get_previous_scan_results(self, device_id: int) -> List[Dict]:
        """Get previous scan results for comparison"""
        try:
            from models import SecurityScan
            
            # Get the most recent scan results for this device (last 24 hours)
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            
            previous_scans = db.session.query(SecurityScan).filter(
                and_(
                    SecurityScan.device_id == device_id,
                    SecurityScan.scanned_at >= cutoff_time,
                    SecurityScan.state == 'open'
                )
            ).all()
            
            return [
                {
                    'port': scan.port,
                    'service': scan.service,
                    'version': scan.version,
                    'risk_score': scan.risk_score
                }
                for scan in previous_scans
            ]
            
        except Exception as e:
            logger.error(f"Error getting previous scan results: {e}")
            return []
    
    def store_scan_results(self, scan_results: List[PortScanResult]):
        """Store scan results in database"""
        try:
            from models import SecurityScan, SecurityEvent
            
            logger.info(f"Storing {len(scan_results)} scan results")
            
            # Store individual scan results
            for result in scan_results:
                # Calculate risk score
                risk_score = self.calculate_risk_score(result.port, result.service)
                
                security_scan = SecurityScan(
                    device_id=result.device_id,
                    ip_address=result.ip_address,
                    port=result.port,
                    state=result.state,
                    service=result.service,
                    version=result.version,
                    product=result.product,
                    extra_info=result.extra_info,
                    confidence=result.confidence,
                    risk_score=risk_score,
                    scanned_at=result.scanned_at
                )
                
                db.session.add(security_scan)
            
            # Create a security event for the completed scan
            device_ids = list(set(r.device_id for r in scan_results))
            for device_id in device_ids:
                device_results = [r for r in scan_results if r.device_id == device_id]
                open_ports = [r for r in device_results if r.state == 'open']
                
                event_metadata = {
                    'ports_scanned': len(device_results),
                    'open_ports': len(open_ports),
                    'services_found': list(set(r.service for r in open_ports)),
                    'scan_duration': 'unknown'  # Could be enhanced with timing
                }
                
                security_event = SecurityEvent(
                    device_id=device_id,
                    event_type='scan_completed',
                    severity='info',
                    message=f"Security scan completed: {len(open_ports)} open ports found",
                    event_metadata=json.dumps(event_metadata),
                    created_at=datetime.utcnow()
                )
                
                db.session.add(security_event)
            
            db.session.commit()
            logger.info("Security scan results stored successfully")
            
        except Exception as e:
            logger.error(f"Error storing scan results: {e}")
            db.session.rollback()
    
    def process_security_alerts(self, security_alerts: List[SecurityAlert]):
        """Process detected security alerts"""
        for alert in security_alerts:
            try:
                logger.warning(
                    f"SECURITY ALERT - Device: {alert.device_name}, "
                    f"Type: {alert.alert_type}, Severity: {alert.severity}, "
                    f"Message: {alert.message}"
                )
                
                # Create alert record
                self.create_security_alert(alert)
                
                # Send push notification for security alert
                self.send_security_push_notification(alert)
                
            except Exception as e:
                logger.error(f"Error processing security alert: {e}")
    
    def create_security_alert(self, alert: SecurityAlert):
        """Create a security alert record"""
        try:
            from models import Alert
            
            # Create alert with security-specific data
            alert_data = {
                'alert_type': alert.alert_type,
                'port': alert.port,
                'service': alert.service,
                'version': alert.version,
                'risk_score': alert.risk_score
            }
            
            db_alert = Alert(
                device_id=alert.device_id,
                alert_type=f'security_{alert.alert_type}',
                severity=alert.severity,
                message=f"[SECURITY] {alert.message}",
                metadata=json.dumps(alert_data),
                created_at=alert.detected_at
            )
            
            db.session.add(db_alert)
            db.session.commit()
            
            logger.info(f"Created security alert for device {alert.device_name}")
            
        except Exception as e:
            logger.error(f"Error creating security alert: {e}")
            db.session.rollback()
    
    def send_security_push_notification(self, alert: SecurityAlert):
        """Send push notification for security alert"""
        try:
            from services.push_notifications import push_service
            from models import Configuration, Device
            from config import Config
            
            # Update push service configuration from database
            push_service.enabled = Configuration.get_value('push_notifications_enabled', 'false').lower() == 'true'
            push_service.topic = Configuration.get_value('ntfy_topic', '')
            push_service.server = Configuration.get_value('ntfy_server', 'https://ntfy.sh')
            
            if not push_service.is_configured():
                logger.debug("Push notifications not configured, skipping security alert notification")
                return
            
            # Get device information
            device = Device.query.filter_by(id=alert.device_id).first()
            if not device:
                logger.error(f"Device {alert.device_id} not found for security alert notification")
                return
            
            # Calculate risk score for push notification
            risk_score = alert.risk_score if alert.risk_score else self.calculate_risk_score(
                alert.port if alert.port else 0, 
                alert.service if alert.service else 'unknown'
            )
            
            # Build dashboard URL
            dashboard_url = f"http://{Config.HOST}:{Config.PORT}/security"
            
            # Send security push notification
            success = push_service.send_security_alert(
                device_name=alert.device_name,
                ip_address=device.ip_address,
                vulnerability=alert.message,
                risk_score=risk_score,
                dashboard_url=dashboard_url
            )
            
            if success:
                logger.info(f"Sent security push notification for {alert.device_name}: {alert.alert_type}")
            else:
                logger.warning(f"Failed to send security push notification for {alert.device_name}")
                
        except Exception as e:
            logger.error(f"Error sending security push notification: {e}")
    
    def perform_compliance_assessment(self, device: Device, framework: ComplianceFramework = ComplianceFramework.CIS) -> List[ComplianceCheck]:
        """Perform compliance assessment against specified framework"""
        compliance_checks = []
        
        try:
            logger.info(f"Starting {framework.value.upper()} compliance assessment for {device.display_name}")
            
            # Get current scan results for compliance evaluation
            scan_results = self.scan_device_ports(device)
            open_ports = [r for r in scan_results if r.state == 'open']
            
            if framework == ComplianceFramework.CIS:
                compliance_checks.extend(self._perform_cis_controls_assessment(device, open_ports))
            elif framework == ComplianceFramework.NIST:
                compliance_checks.extend(self._perform_nist_assessment(device, open_ports))
            elif framework == ComplianceFramework.PCI_DSS:
                compliance_checks.extend(self._perform_pci_dss_assessment(device, open_ports))
            elif framework == ComplianceFramework.ISO27001:
                compliance_checks.extend(self._perform_iso27001_assessment(device, open_ports))
            
            logger.info(f"Compliance assessment completed: {len(compliance_checks)} checks for {device.display_name}")
            return compliance_checks
            
        except Exception as e:
            logger.error(f"Error in compliance assessment: {e}")
            return []
    
    def _perform_cis_controls_assessment(self, device: Device, open_ports: List[PortScanResult]) -> List[ComplianceCheck]:
        """Perform CIS Controls assessment"""
        checks = []
        
        # CIS Control 4.1: Secure Configuration for Hardware and Software
        telnet_ports = [r for r in open_ports if r.service == 'telnet']
        if telnet_ports:
            checks.append(ComplianceCheck(
                check_id=f"CIS_4.1_{device.id}",
                framework=ComplianceFramework.CIS,
                rule_id="4.1",
                title="Secure Configuration - Insecure Services",
                description="Telnet service detected - violates CIS Control 4.1 (Secure Configuration)",
                severity=SecuritySeverity.HIGH,
                status="fail",
                evidence={
                    'insecure_services': [{'port': r.port, 'service': r.service} for r in telnet_ports],
                    'control': 'CIS Control 4.1'
                },
                remediation=['Disable telnet service', 'Use SSH instead', 'Implement secure remote access'],
                checked_at=datetime.utcnow()
            ))
        else:
            checks.append(ComplianceCheck(
                check_id=f"CIS_4.1_{device.id}",
                framework=ComplianceFramework.CIS,
                rule_id="4.1",
                title="Secure Configuration - Insecure Services",
                description="No insecure services detected",
                severity=SecuritySeverity.INFO,
                status="pass",
                evidence={'insecure_services': []},
                remediation=[],
                checked_at=datetime.utcnow()
            ))
        
        # CIS Control 12.2: Actively Scan for Vulnerabilities
        checks.append(ComplianceCheck(
            check_id=f"CIS_12.2_{device.id}",
            framework=ComplianceFramework.CIS,
            rule_id="12.2",
            title="Vulnerability Scanning",
            description="Security scan performed as part of active vulnerability management",
            severity=SecuritySeverity.INFO,
            status="pass",
            evidence={
                'scan_date': datetime.utcnow().isoformat(),
                'ports_scanned': len(open_ports),
                'control': 'CIS Control 12.2'
            },
            remediation=[],
            checked_at=datetime.utcnow()
        ))
        
        return checks
    
    def _perform_nist_assessment(self, device: Device, open_ports: List[PortScanResult]) -> List[ComplianceCheck]:
        """Perform NIST Cybersecurity Framework assessment"""
        checks = []
        
        # NIST ID.AM-1: Physical devices and systems within the organization are inventoried
        checks.append(ComplianceCheck(
            check_id=f"NIST_ID.AM-1_{device.id}",
            framework=ComplianceFramework.NIST,
            rule_id="ID.AM-1",
            title="Asset Management - Device Inventory",
            description="Device identified and inventoried in security scanning system",
            severity=SecuritySeverity.INFO,
            status="pass",
            evidence={
                'device_id': device.id,
                'device_name': device.display_name,
                'ip_address': device.ip_address,
                'last_seen': device.last_seen.isoformat() if device.last_seen else None
            },
            remediation=[],
            checked_at=datetime.utcnow()
        ))
        
        # NIST PR.IP-1: A baseline configuration of information technology/industrial control systems
        excessive_ports = len(open_ports) > 15
        checks.append(ComplianceCheck(
            check_id=f"NIST_PR.IP-1_{device.id}",
            framework=ComplianceFramework.NIST,
            rule_id="PR.IP-1",
            title="Information Protection - Baseline Configuration",
            description="Excessive open ports may indicate non-standard configuration" if excessive_ports else "Port configuration appears reasonable",
            severity=SecuritySeverity.MEDIUM if excessive_ports else SecuritySeverity.INFO,
            status="fail" if excessive_ports else "pass",
            evidence={
                'open_ports_count': len(open_ports),
                'threshold': 15,
                'open_ports': [{'port': r.port, 'service': r.service} for r in open_ports]
            },
            remediation=['Review necessity of all open ports', 'Close unused services', 'Document approved services'] if excessive_ports else [],
            checked_at=datetime.utcnow()
        ))
        
        return checks
    
    def _perform_pci_dss_assessment(self, device: Device, open_ports: List[PortScanResult]) -> List[ComplianceCheck]:
        """Perform PCI DSS assessment"""
        checks = []
        
        # PCI DSS 2.2.2: Enable only necessary services, protocols, daemons
        unnecessary_services = [r for r in open_ports if r.service in ['telnet', 'ftp', 'rsh', 'rcp']]
        checks.append(ComplianceCheck(
            check_id=f"PCI_2.2.2_{device.id}",
            framework=ComplianceFramework.PCI_DSS,
            rule_id="2.2.2",
            title="Secure System Configuration",
            description="Unnecessary insecure services detected" if unnecessary_services else "No unnecessary insecure services detected",
            severity=SecuritySeverity.HIGH if unnecessary_services else SecuritySeverity.INFO,
            status="fail" if unnecessary_services else "pass",
            evidence={
                'unnecessary_services': [{'port': r.port, 'service': r.service} for r in unnecessary_services],
                'requirement': 'PCI DSS 2.2.2'
            },
            remediation=['Disable unnecessary services', 'Use secure alternatives', 'Document business justification'] if unnecessary_services else [],
            checked_at=datetime.utcnow()
        ))
        
        return checks
    
    def _perform_iso27001_assessment(self, device: Device, open_ports: List[PortScanResult]) -> List[ComplianceCheck]:
        """Perform ISO 27001 assessment"""
        checks = []
        
        # ISO 27001 A.13.1.1: Network controls
        checks.append(ComplianceCheck(
            check_id=f"ISO_A.13.1.1_{device.id}",
            framework=ComplianceFramework.ISO27001,
            rule_id="A.13.1.1",
            title="Network Security Management",
            description="Network security assessment performed",
            severity=SecuritySeverity.INFO,
            status="pass",
            evidence={
                'network_ports_assessed': len(open_ports),
                'control': 'ISO 27001 A.13.1.1',
                'assessment_date': datetime.utcnow().isoformat()
            },
            remediation=[],
            checked_at=datetime.utcnow()
        ))
        
        return checks
    
    def _store_os_detection(self, device_id: int, os_info: Dict[str, Any]):
        """Store OS detection results"""
        try:
            from models import DeviceOSInfo
            
            os_record = DeviceOSInfo(
                device_id=device_id,
                os_name=os_info.get('name', 'Unknown'),
                os_family=os_info.get('osclass', [{}])[0].get('osfamily', 'Unknown'),
                os_version=os_info.get('osclass', [{}])[0].get('osgen', 'Unknown'),
                accuracy=os_info.get('accuracy', 0),
                detected_at=datetime.utcnow()
            )
            
            db.session.merge(os_record)
            db.session.commit()
            
            logger.debug(f"Stored OS detection for device {device_id}: {os_info.get('name')}")
            
        except Exception as e:
            logger.error(f"Error storing OS detection: {e}")
    
    def get_security_summary(self, hours: int = 24) -> Dict:
        """Get comprehensive security summary statistics"""
        try:
            from models import Alert, SecurityVulnerability
            
            start_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Count security alerts by type and severity
            security_alerts = db.session.query(Alert).filter(
                and_(
                    Alert.alert_type.like('security_%'),
                    Alert.created_at >= start_time
                )
            ).all()
            
            # Count vulnerability findings
            vulnerabilities = db.session.query(SecurityVulnerability).filter(
                SecurityVulnerability.discovered_at >= start_time
            ).all()
            
            # Count recent scans (safely handle missing table)
            try:
                from models import SecurityScan
                recent_scans = db.session.query(db.func.count(db.distinct(
                    db.func.date(SecurityScan.scanned_at)
                ))).filter(
                    SecurityScan.scanned_at >= start_time
                ).scalar() or 0
            except Exception as e:
                logger.debug(f"Could not query security scans table: {e}")
                recent_scans = 0
            
            summary = {
                'total_alerts': len(security_alerts),
                'total_vulnerabilities': len(vulnerabilities),
                'by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                'by_type': {},
                'vulnerability_categories': {},
                'recent_scans': recent_scans,
                'devices_scanned': len(set(alert.device_id for alert in security_alerts)),
                'high_risk_findings': len([v for v in vulnerabilities if v.risk_score >= 7.0]),
                'compliance_violations': len([v for v in vulnerabilities if json.loads(v.compliance_violations or '[]')])
            }
            
            # Count alerts by severity
            for alert in security_alerts:
                summary['by_severity'][alert.severity] += 1
                alert_type = alert.alert_type.replace('security_', '')
                summary['by_type'][alert_type] = summary['by_type'].get(alert_type, 0) + 1
            
            # Count vulnerabilities by severity and category
            for vuln in vulnerabilities:
                summary['by_severity'][vuln.severity] += 1
                summary['vulnerability_categories'][vuln.category] = summary['vulnerability_categories'].get(vuln.category, 0) + 1
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting security summary: {e}")
            return {'error': str(e)}
    
    def perform_vulnerability_assessment(self, device: Device) -> List[VulnerabilityFinding]:
        """Comprehensive vulnerability assessment for a device"""
        findings = []
        
        try:
            logger.info(f"Starting vulnerability assessment for {device.display_name}")
            
            # 1. Port-based vulnerability assessment
            port_findings = self._assess_port_vulnerabilities(device)
            findings.extend(port_findings)
            
            # 2. Service version vulnerability checks
            service_findings = self._assess_service_vulnerabilities(device)
            findings.extend(service_findings)
            
            # 3. SSL/TLS certificate analysis
            ssl_findings = self._assess_ssl_vulnerabilities(device)
            findings.extend(ssl_findings)
            
            # 4. Configuration security checks
            config_findings = self._assess_configuration_security(device)
            findings.extend(config_findings)
            
            # 5. Network behavior anomaly assessment
            if self.anomaly_detection:
                anomaly_findings = self._assess_anomaly_based_vulnerabilities(device)
                findings.extend(anomaly_findings)
            
            logger.info(f"Vulnerability assessment completed: {len(findings)} findings for {device.display_name}")
            return findings
            
        except Exception as e:
            logger.error(f"Error in vulnerability assessment for {device.display_name}: {e}")
            return []
    
    def _assess_port_vulnerabilities(self, device: Device) -> List[VulnerabilityFinding]:
        """Assess vulnerabilities based on open ports"""
        findings = []
        
        try:
            # Get recent port scan results
            scan_results = self.scan_device_ports(device)
            
            for result in scan_results:
                if result.state != 'open':
                    continue
                
                # Check for high-risk ports
                if result.port in self.suspicious_ports:
                    severity = SecuritySeverity.HIGH if result.port in [23, 3389, 5900] else SecuritySeverity.MEDIUM
                    
                    finding = VulnerabilityFinding(
                        finding_id=f"port_{device.id}_{result.port}_{int(datetime.utcnow().timestamp())}",
                        device_id=device.id,
                        device_name=device.display_name,
                        category=VulnerabilityCategory.NETWORK,
                        severity=severity,
                        title=f"Suspicious Service on Port {result.port}",
                        description=f"Service {result.service} running on potentially vulnerable port {result.port}",
                        evidence={
                            'port': result.port,
                            'service': result.service,
                            'version': result.version,
                            'product': result.product,
                            'state': result.state
                        },
                        risk_score=self.calculate_risk_score(result.port, result.service),
                        remediation=self._get_port_remediation(result.port, result.service),
                        discovered_at=datetime.utcnow(),
                        last_verified=datetime.utcnow()
                    )
                    findings.append(finding)
                
                # Check for default/weak service configurations
                if self._is_default_service_config(result):
                    finding = VulnerabilityFinding(
                        finding_id=f"default_config_{device.id}_{result.port}_{int(datetime.utcnow().timestamp())}",
                        device_id=device.id,
                        device_name=device.display_name,
                        category=VulnerabilityCategory.CONFIGURATION,
                        severity=SecuritySeverity.MEDIUM,
                        title=f"Default Service Configuration Detected",
                        description=f"Service {result.service} appears to be running with default configuration",
                        evidence={
                            'port': result.port,
                            'service': result.service,
                            'version': result.version,
                            'indicators': 'default_port_service_combination'
                        },
                        risk_score=self.calculate_risk_score(result.port, result.service) + 1,
                        remediation=['Review service configuration', 'Change default credentials if applicable', 'Disable unnecessary services'],
                        discovered_at=datetime.utcnow(),
                        last_verified=datetime.utcnow()
                    )
                    findings.append(finding)
            
        except Exception as e:
            logger.error(f"Error assessing port vulnerabilities: {e}")
        
        return findings
    
    def _assess_service_vulnerabilities(self, device: Device) -> List[VulnerabilityFinding]:
        """Assess vulnerabilities based on service versions"""
        findings = []
        
        try:
            scan_results = self.scan_device_ports(device)
            
            for result in scan_results:
                if result.state != 'open' or not result.version:
                    continue
                
                # Check for known vulnerable service versions
                vulnerabilities = self._check_service_version_vulnerabilities(result.service, result.version)
                
                for vuln in vulnerabilities:
                    finding = VulnerabilityFinding(
                        finding_id=f"service_vuln_{device.id}_{result.port}_{vuln['id']}_{int(datetime.utcnow().timestamp())}",
                        device_id=device.id,
                        device_name=device.display_name,
                        category=VulnerabilityCategory.SERVICE,
                        severity=SecuritySeverity(vuln['severity']),
                        title=f"Vulnerable {result.service} Version",
                        description=vuln['description'],
                        evidence={
                            'service': result.service,
                            'version': result.version,
                            'port': result.port,
                            'vulnerability_details': vuln
                        },
                        risk_score=vuln['risk_score'],
                        remediation=vuln['remediation'],
                        discovered_at=datetime.utcnow(),
                        last_verified=datetime.utcnow(),
                        cvss_score=vuln.get('cvss_score'),
                        cve_references=vuln.get('cve_references', [])
                    )
                    findings.append(finding)
            
        except Exception as e:
            logger.error(f"Error assessing service vulnerabilities: {e}")
        
        return findings
    
    def _assess_ssl_vulnerabilities(self, device: Device) -> List[VulnerabilityFinding]:
        """Assess SSL/TLS certificate and configuration vulnerabilities"""
        findings = []
        
        try:
            # Check common SSL/TLS ports
            ssl_ports = [443, 993, 995, 8443, 9443]
            scan_results = self.scan_device_ports(device)
            
            for result in scan_results:
                if result.state == 'open' and (result.port in ssl_ports or 'ssl' in result.service.lower()):
                    ssl_info = self._analyze_ssl_certificate(device.ip_address, result.port)
                    
                    if ssl_info:
                        # Check for expired certificates
                        if ssl_info.is_expired:
                            finding = VulnerabilityFinding(
                                finding_id=f"ssl_expired_{device.id}_{result.port}_{int(datetime.utcnow().timestamp())}",
                                device_id=device.id,
                                device_name=device.display_name,
                                category=VulnerabilityCategory.CERTIFICATE,
                                severity=SecuritySeverity.HIGH,
                                title="Expired SSL Certificate",
                                description=f"SSL certificate on port {result.port} has expired",
                                evidence={
                                    'port': result.port,
                                    'subject': ssl_info.subject,
                                    'issuer': ssl_info.issuer,
                                    'expiry_date': ssl_info.not_after.isoformat(),
                                    'days_expired': abs(ssl_info.days_until_expiry)
                                },
                                risk_score=8.0,
                                remediation=['Renew SSL certificate immediately', 'Update certificate configuration', 'Verify certificate chain'],
                                discovered_at=datetime.utcnow(),
                                last_verified=datetime.utcnow()
                            )
                            findings.append(finding)
                        
                        # Check for certificates expiring soon
                        elif ssl_info.days_until_expiry <= 30:
                            severity = SecuritySeverity.HIGH if ssl_info.days_until_expiry <= 7 else SecuritySeverity.MEDIUM
                            
                            finding = VulnerabilityFinding(
                                finding_id=f"ssl_expiring_{device.id}_{result.port}_{int(datetime.utcnow().timestamp())}",
                                device_id=device.id,
                                device_name=device.display_name,
                                category=VulnerabilityCategory.CERTIFICATE,
                                severity=severity,
                                title="SSL Certificate Expiring Soon",
                                description=f"SSL certificate on port {result.port} expires in {ssl_info.days_until_expiry} days",
                                evidence={
                                    'port': result.port,
                                    'subject': ssl_info.subject,
                                    'issuer': ssl_info.issuer,
                                    'expiry_date': ssl_info.not_after.isoformat(),
                                    'days_until_expiry': ssl_info.days_until_expiry
                                },
                                risk_score=6.0 if ssl_info.days_until_expiry <= 7 else 4.0,
                                remediation=['Schedule certificate renewal', 'Update certificate before expiry', 'Monitor certificate status'],
                                discovered_at=datetime.utcnow(),
                                last_verified=datetime.utcnow()
                            )
                            findings.append(finding)
                        
                        # Check for self-signed certificates
                        if ssl_info.is_self_signed:
                            finding = VulnerabilityFinding(
                                finding_id=f"ssl_selfsigned_{device.id}_{result.port}_{int(datetime.utcnow().timestamp())}",
                                device_id=device.id,
                                device_name=device.display_name,
                                category=VulnerabilityCategory.CERTIFICATE,
                                severity=SecuritySeverity.MEDIUM,
                                title="Self-Signed SSL Certificate",
                                description=f"Self-signed SSL certificate detected on port {result.port}",
                                evidence={
                                    'port': result.port,
                                    'subject': ssl_info.subject,
                                    'issuer': ssl_info.issuer,
                                    'is_self_signed': ssl_info.is_self_signed
                                },
                                risk_score=5.0,
                                remediation=['Replace with CA-signed certificate', 'Consider certificate authority validation', 'Review certificate trust chain'],
                                discovered_at=datetime.utcnow(),
                                last_verified=datetime.utcnow()
                            )
                            findings.append(finding)
            
        except Exception as e:
            logger.error(f"Error assessing SSL vulnerabilities: {e}")
        
        return findings
    
    def _assess_configuration_security(self, device: Device) -> List[VulnerabilityFinding]:
        """Assess device configuration security issues"""
        findings = []
        
        try:
            # Check for insecure service combinations
            scan_results = self.scan_device_ports(device)
            open_services = [r.service for r in scan_results if r.state == 'open']
            
            # Check for telnet + other services (indicates poor security practices)
            if 'telnet' in open_services:
                other_services = [s for s in open_services if s != 'telnet']
                if other_services:
                    finding = VulnerabilityFinding(
                        finding_id=f"insecure_combo_{device.id}_{int(datetime.utcnow().timestamp())}",
                        device_id=device.id,
                        device_name=device.display_name,
                        category=VulnerabilityCategory.CONFIGURATION,
                        severity=SecuritySeverity.HIGH,
                        title="Insecure Service Configuration",
                        description="Telnet service running alongside other services indicates poor security configuration",
                        evidence={
                            'insecure_service': 'telnet',
                            'other_services': other_services,
                            'security_risk': 'unencrypted_remote_access'
                        },
                        risk_score=8.0,
                        remediation=['Disable telnet service', 'Use SSH for remote access', 'Review all service configurations', 'Implement security hardening'],
                        discovered_at=datetime.utcnow(),
                        last_verified=datetime.utcnow()
                    )
                    findings.append(finding)
            
            # Check for excessive open ports (potential over-exposure)
            open_ports = [r.port for r in scan_results if r.state == 'open']
            if len(open_ports) > 10:
                finding = VulnerabilityFinding(
                    finding_id=f"port_exposure_{device.id}_{int(datetime.utcnow().timestamp())}",
                    device_id=device.id,
                    device_name=device.display_name,
                    category=VulnerabilityCategory.CONFIGURATION,
                    severity=SecuritySeverity.MEDIUM,
                    title="Excessive Port Exposure",
                    description=f"Device has {len(open_ports)} open ports, indicating potential over-exposure",
                    evidence={
                        'open_port_count': len(open_ports),
                        'open_ports': sorted(open_ports),
                        'services': open_services
                    },
                    risk_score=5.0 + min(3.0, (len(open_ports) - 10) * 0.2),
                    remediation=['Review necessity of all open ports', 'Close unused services', 'Implement firewall rules', 'Follow principle of least exposure'],
                    discovered_at=datetime.utcnow(),
                    last_verified=datetime.utcnow()
                )
                findings.append(finding)
            
        except Exception as e:
            logger.error(f"Error assessing configuration security: {e}")
        
        return findings
    
    def _assess_anomaly_based_vulnerabilities(self, device: Device) -> List[VulnerabilityFinding]:
        """Assess vulnerabilities based on anomaly detection"""
        findings = []
        
        try:
            # Get anomaly detection results for this device
            anomalies = self.anomaly_detection.detect_device_anomalies(device.id, hours=24)
            
            for anomaly in anomalies:
                if anomaly.get('security_relevant', False):
                    severity_map = {
                        'low': SecuritySeverity.LOW,
                        'medium': SecuritySeverity.MEDIUM,
                        'high': SecuritySeverity.HIGH,
                        'critical': SecuritySeverity.CRITICAL
                    }
                    
                    finding = VulnerabilityFinding(
                        finding_id=f"anomaly_{device.id}_{anomaly['type']}_{int(datetime.utcnow().timestamp())}",
                        device_id=device.id,
                        device_name=device.display_name,
                        category=VulnerabilityCategory.NETWORK,
                        severity=severity_map.get(anomaly.get('severity', 'medium'), SecuritySeverity.MEDIUM),
                        title=f"Security-Relevant Anomaly: {anomaly['type']}",
                        description=anomaly.get('description', 'Anomalous behavior detected that may indicate security issues'),
                        evidence={
                            'anomaly_type': anomaly['type'],
                            'detection_details': anomaly.get('details', {}),
                            'confidence_score': anomaly.get('confidence', 0),
                            'detection_time': anomaly.get('timestamp')
                        },
                        risk_score=anomaly.get('risk_score', 5.0),
                        remediation=['Investigate anomalous behavior', 'Review device activity logs', 'Consider device isolation if necessary', 'Monitor for continued anomalies'],
                        discovered_at=datetime.utcnow(),
                        last_verified=datetime.utcnow()
                    )
                    findings.append(finding)
            
        except Exception as e:
            logger.error(f"Error assessing anomaly-based vulnerabilities: {e}")
        
        return findings
    
    def manual_scan_device(self, device_id: int) -> Dict:
        """Manually trigger a comprehensive security scan for a specific device"""
        try:
            with self.app.app_context():
                device = Device.query.get(device_id)
                if not device:
                    return {'error': 'Device not found'}
                
                logger.info(f"Manual security scan requested for {device.display_name}")
                
                # Perform comprehensive vulnerability assessment
                vulnerability_findings = self.perform_vulnerability_assessment(device)
                
                # Legacy port scanning for compatibility
                scan_results = self.scan_device_ports(device)
                security_alerts = self.analyze_security_results(device, scan_results)
                
                if scan_results:
                    self.store_scan_results(scan_results)
                
                if security_alerts:
                    self.process_security_alerts(security_alerts)
                
                # Store vulnerability findings
                if vulnerability_findings:
                    self.store_vulnerability_findings(vulnerability_findings)
                
                return {
                    'success': True,
                    'device_name': device.display_name,
                    'ports_scanned': len(scan_results),
                    'open_ports': len([r for r in scan_results if r.state == 'open']),
                    'security_alerts': len(security_alerts),
                    'vulnerability_findings': len(vulnerability_findings),
                    'alerts': [
                        {
                            'type': a.alert_type,
                            'severity': a.severity,
                            'message': a.message,
                            'risk_score': a.risk_score
                        } for a in security_alerts
                    ],
                    'vulnerabilities': [
                        {
                            'finding_id': v.finding_id,
                            'category': v.category.value,
                            'severity': v.severity.value,
                            'title': v.title,
                            'risk_score': v.risk_score
                        } for v in vulnerability_findings
                    ]
                }
                
        except Exception as e:
            logger.error(f"Error in manual device scan: {e}")
            return {'error': str(e)}

    def _check_service_version_vulnerabilities(self, service: str, version: str) -> List[Dict[str, Any]]:
        """Check for known vulnerabilities in service versions"""
        vulnerabilities = []
        
        # Known vulnerability patterns (simplified database)
        vuln_patterns = {
            'ssh': {
                'OpenSSH_7.4': [
                    {
                        'id': 'CVE-2018-15473',
                        'severity': 'medium',
                        'description': 'OpenSSH 7.4 username enumeration vulnerability',
                        'risk_score': 5.5,
                        'cvss_score': 5.3,
                        'cve_references': ['CVE-2018-15473'],
                        'remediation': ['Update OpenSSH to latest version', 'Implement fail2ban', 'Use key-based authentication']
                    }
                ]
            },
            'apache': {
                'Apache/2.4.6': [
                    {
                        'id': 'CVE-2017-15715',
                        'severity': 'high',
                        'description': 'Apache 2.4.6 expression injection vulnerability',
                        'risk_score': 7.2,
                        'cvss_score': 6.0,
                        'cve_references': ['CVE-2017-15715'],
                        'remediation': ['Update Apache to 2.4.29 or later', 'Review .htaccess configurations', 'Implement WAF']
                    }
                ]
            },
            'nginx': {
                'nginx/1.10.3': [
                    {
                        'id': 'CVE-2017-7529',
                        'severity': 'high',
                        'description': 'Nginx integer overflow vulnerability',
                        'risk_score': 7.5,
                        'cvss_score': 7.5,
                        'cve_references': ['CVE-2017-7529'],
                        'remediation': ['Update nginx to 1.13.3 or later', 'Review nginx configuration', 'Monitor for unusual requests']
                    }
                ]
            }
        }
        
        # Check for exact version matches
        service_lower = service.lower()
        for vuln_service, versions in vuln_patterns.items():
            if vuln_service in service_lower:
                for vuln_version, vulns in versions.items():
                    if vuln_version in version:
                        vulnerabilities.extend(vulns)
        
        # Check for generic old version patterns
        if self._is_outdated_version(service, version):
            vulnerabilities.append({
                'id': f'OUTDATED_{service.upper()}',
                'severity': 'medium',
                'description': f'Potentially outdated {service} version detected: {version}',
                'risk_score': 4.0,
                'remediation': [f'Update {service} to latest version', 'Review security advisories', 'Test compatibility before updating']
            })
        
        return vulnerabilities
    
    def get_compliance_summary(self, framework: ComplianceFramework = None, hours: int = 24) -> Dict[str, Any]:
        """Get compliance assessment summary"""
        try:
            from models import ComplianceResult
            
            start_time = datetime.utcnow() - timedelta(hours=hours)
            query = db.session.query(ComplianceResult).filter(
                ComplianceResult.checked_at >= start_time
            )
            
            if framework:
                query = query.filter(ComplianceResult.framework == framework.value)
            
            compliance_results = query.all()
            
            summary = {
                'total_checks': len(compliance_results),
                'by_status': {'pass': 0, 'fail': 0, 'not_applicable': 0},
                'by_framework': {},
                'by_severity': {'info': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                'compliance_score': 0.0,
                'critical_violations': 0
            }
            
            for result in compliance_results:
                # Count by status
                summary['by_status'][result.status] += 1
                
                # Count by framework
                summary['by_framework'][result.framework] = summary['by_framework'].get(result.framework, 0) + 1
                
                # Count by severity
                summary['by_severity'][result.severity] += 1
                
                # Count critical violations
                if result.severity == 'critical' and result.status == 'fail':
                    summary['critical_violations'] += 1
            
            # Calculate compliance score
            if summary['total_checks'] > 0:
                passing_checks = summary['by_status']['pass']
                summary['compliance_score'] = round((passing_checks / summary['total_checks']) * 100, 2)
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting compliance summary: {e}")
            return {'error': str(e)}
    
    def store_compliance_results(self, compliance_checks: List[ComplianceCheck]):
        """Store compliance check results in database"""
        try:
            from models import ComplianceResult
            
            logger.info(f"Storing {len(compliance_checks)} compliance results")
            
            for check in compliance_checks:
                compliance_result = ComplianceResult(
                    check_id=check.check_id,
                    framework=check.framework.value,
                    rule_id=check.rule_id,
                    title=check.title,
                    description=check.description,
                    severity=check.severity.value,
                    status=check.status,
                    evidence=json.dumps(check.evidence),
                    remediation=json.dumps(check.remediation),
                    checked_at=check.checked_at
                )
                
                db.session.merge(compliance_result)
            
            db.session.commit()
            logger.info("Compliance results stored successfully")
            
        except Exception as e:
            logger.error(f"Error storing compliance results: {e}")
            db.session.rollback()
    
    def _is_outdated_version(self, service: str, version: str) -> bool:
        """Simple heuristic to detect potentially outdated versions"""
        import re
        
        # Extract year from version string
        year_match = re.search(r'(201[0-9]|202[0-4])', version)
        if year_match:
            version_year = int(year_match.group(1))
            current_year = datetime.utcnow().year
            return (current_year - version_year) > 3
        
        # Check for obviously old version patterns
        old_patterns = ['1.0.', '0.', '2010', '2011', '2012', '2013', '2014', '2015']
        return any(pattern in version for pattern in old_patterns)
    
    def _is_default_service_config(self, scan_result: PortScanResult) -> bool:
        """Check if service appears to be running with default configuration"""
        # Common default port/service combinations that indicate default configs
        default_configs = {
            80: 'http',
            8080: 'http-proxy',
            8000: 'http-alt',
            3000: 'ppp',
            5000: 'upnp',
            8888: 'sun-answerbook'
        }
        
        return scan_result.port in default_configs and default_configs[scan_result.port] in scan_result.service
    
    def _get_port_remediation(self, port: int, service: str) -> List[str]:
        """Get remediation steps for specific port/service combinations"""
        remediation_map = {
            23: ['Disable telnet service', 'Use SSH instead', 'Enable firewall blocking'],
            21: ['Secure FTP configuration', 'Use SFTP/FTPS', 'Implement strong authentication'],
            135: ['Disable RPC if not needed', 'Configure RPC security', 'Use firewall to restrict access'],
            139: ['Disable NetBIOS if not needed', 'Configure SMB security', 'Use SMB signing'],
            445: ['Enable SMB signing', 'Update SMB to latest version', 'Restrict SMB access'],
            3389: ['Enable NLA for RDP', 'Use strong RDP passwords', 'Implement RDP gateway'],
            5900: ['Secure VNC with authentication', 'Use VNC over VPN', 'Consider alternatives to VNC']
        }
        
        return remediation_map.get(port, ['Review service configuration', 'Implement access controls', 'Monitor service logs'])
    
    def _analyze_ssl_certificate(self, ip_address: str, port: int) -> Optional[SSLCertificateInfo]:
        """Analyze SSL certificate for a given IP and port"""
        try:
            import ssl
            import socket
            from datetime import datetime
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((ip_address, port), timeout=10) as sock:
                with context.wrap_socket(sock) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_info = ssock.getpeercert()
                    
                    if not cert_info:
                        return None
                    
                    # Parse certificate information
                    subject = dict(x[0] for x in cert_info.get('subject', []))
                    issuer = dict(x[0] for x in cert_info.get('issuer', []))
                    
                    # Parse dates
                    not_before = datetime.strptime(cert_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    # Calculate expiry
                    now = datetime.utcnow()
                    days_until_expiry = (not_after - now).days
                    is_expired = now > not_after
                    
                    # Check if self-signed
                    is_self_signed = subject.get('commonName') == issuer.get('commonName')
                    
                    # Get SAN list
                    san_list = []
                    for san in cert_info.get('subjectAltName', []):
                        if san[0] == 'DNS':
                            san_list.append(san[1])
                    
                    return SSLCertificateInfo(
                        device_id=0,  # Will be set by caller
                        port=port,
                        subject=subject.get('commonName', 'Unknown'),
                        issuer=issuer.get('commonName', 'Unknown'),
                        serial_number=str(cert_info.get('serialNumber', 'Unknown')),
                        not_before=not_before,
                        not_after=not_after,
                        signature_algorithm=cert_info.get('signatureAlgorithm', 'Unknown'),
                        key_size=0,  # Would need additional parsing
                        is_self_signed=is_self_signed,
                        is_expired=is_expired,
                        days_until_expiry=days_until_expiry,
                        san_list=san_list
                    )
        
        except Exception as e:
            logger.debug(f"Could not analyze SSL certificate for {ip_address}:{port}: {e}")
            return None
    
    def store_vulnerability_findings(self, findings: List[VulnerabilityFinding]):
        """Store vulnerability findings in database"""
        try:
            from models import SecurityVulnerability
            
            logger.info(f"Storing {len(findings)} vulnerability findings")
            
            for finding in findings:
                vulnerability = SecurityVulnerability(
                    finding_id=finding.finding_id,
                    device_id=finding.device_id,
                    category=finding.category.value,
                    severity=finding.severity.value,
                    title=finding.title,
                    description=finding.description,
                    evidence=json.dumps(finding.evidence),
                    risk_score=finding.risk_score,
                    remediation=json.dumps(finding.remediation),
                    discovered_at=finding.discovered_at,
                    last_verified=finding.last_verified,
                    status=finding.status,
                    cvss_score=finding.cvss_score,
                    cve_references=json.dumps(finding.cve_references),
                    compliance_violations=json.dumps(finding.compliance_violations)
                )
                
                db.session.add(vulnerability)
            
            db.session.commit()
            logger.info("Vulnerability findings stored successfully")
            
        except Exception as e:
            logger.error(f"Error storing vulnerability findings: {e}")
            db.session.rollback()
    
    def get_vulnerability_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get vulnerability summary statistics"""
        try:
            from models import SecurityVulnerability
            
            start_time = datetime.utcnow() - timedelta(hours=hours)
            
            vulnerabilities = db.session.query(SecurityVulnerability).filter(
                SecurityVulnerability.discovered_at >= start_time
            ).all()
            
            summary = {
                'total_vulnerabilities': len(vulnerabilities),
                'by_severity': {'info': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                'by_category': {},
                'by_status': {'open': 0, 'acknowledged': 0, 'remediated': 0, 'false_positive': 0},
                'high_risk_count': 0,
                'cve_count': 0
            }
            
            for vuln in vulnerabilities:
                # Count by severity
                summary['by_severity'][vuln.severity] += 1
                
                # Count by category
                summary['by_category'][vuln.category] = summary['by_category'].get(vuln.category, 0) + 1
                
                # Count by status
                summary['by_status'][vuln.status] += 1
                
                # High risk count (risk score >= 7)
                if vuln.risk_score >= 7.0:
                    summary['high_risk_count'] += 1
                
                # CVE count
                cve_refs = json.loads(vuln.cve_references or '[]')
                if cve_refs:
                    summary['cve_count'] += 1
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting vulnerability summary: {e}")
            return {'error': str(e)}
    
    def get_device_security_posture(self, device_id: int) -> Dict[str, Any]:
        """Get comprehensive security posture for a specific device"""
        try:
            with self.app.app_context():
                device = Device.query.get(device_id)
                if not device:
                    return {'error': 'Device not found'}
                
                # Get recent vulnerability findings
                start_time = datetime.utcnow() - timedelta(days=30)
                from models import SecurityVulnerability, Alert
                
                vulnerabilities = db.session.query(SecurityVulnerability).filter(
                    and_(
                        SecurityVulnerability.device_id == device_id,
                        SecurityVulnerability.discovered_at >= start_time
                    )
                ).all()
                
                # Get recent security alerts
                security_alerts = db.session.query(Alert).filter(
                    and_(
                        Alert.device_id == device_id,
                        Alert.alert_type.like('security_%'),
                        Alert.created_at >= start_time
                    )
                ).all()
                
                # Calculate risk score
                risk_scores = [v.risk_score for v in vulnerabilities if v.risk_score]
                avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
                
                # Determine security posture level
                critical_vulns = len([v for v in vulnerabilities if v.severity == 'critical'])
                high_vulns = len([v for v in vulnerabilities if v.severity == 'high'])
                
                if critical_vulns > 0:
                    posture_level = 'critical'
                elif high_vulns > 2:
                    posture_level = 'poor'
                elif high_vulns > 0:
                    posture_level = 'moderate'
                elif avg_risk_score > 5.0:
                    posture_level = 'fair'
                else:
                    posture_level = 'good'
                
                return {
                    'device_id': device_id,
                    'device_name': device.display_name,
                    'security_posture': posture_level,
                    'average_risk_score': round(avg_risk_score, 2),
                    'total_vulnerabilities': len(vulnerabilities),
                    'vulnerability_breakdown': {
                        'critical': len([v for v in vulnerabilities if v.severity == 'critical']),
                        'high': len([v for v in vulnerabilities if v.severity == 'high']),
                        'medium': len([v for v in vulnerabilities if v.severity == 'medium']),
                        'low': len([v for v in vulnerabilities if v.severity == 'low'])
                    },
                    'recent_alerts': len(security_alerts),
                    'last_assessment': max(v.discovered_at for v in vulnerabilities).isoformat() if vulnerabilities else None,
                    'recommendations': self._generate_security_recommendations(vulnerabilities, security_alerts)
                }
                
        except Exception as e:
            logger.error(f"Error getting device security posture: {e}")
            return {'error': str(e)}
    
    def _generate_security_recommendations(self, vulnerabilities: List, alerts: List) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Check for critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.severity == 'critical']
        if critical_vulns:
            recommendations.append("Address critical vulnerabilities immediately")
            recommendations.append("Consider isolating device until critical issues are resolved")
        
        # Check for certificate issues
        cert_issues = [v for v in vulnerabilities if v.category == 'certificate']
        if cert_issues:
            recommendations.append("Review and update SSL/TLS certificates")
        
        # Check for configuration issues
        config_issues = [v for v in vulnerabilities if v.category == 'configuration']
        if config_issues:
            recommendations.append("Review and harden device configuration")
            recommendations.append("Disable unnecessary services and ports")
        
        # Check for service vulnerabilities
        service_issues = [v for v in vulnerabilities if v.category == 'service']
        if service_issues:
            recommendations.append("Update services to latest secure versions")
            recommendations.append("Apply security patches promptly")
        
        # General recommendations if no specific issues
        if not recommendations:
            recommendations.extend([
                "Continue regular security monitoring",
                "Keep system and services updated",
                "Maintain security best practices"
            ])
        
        return recommendations

# Global security scanner service instance
security_scanner = NetworkSecurityScanner()