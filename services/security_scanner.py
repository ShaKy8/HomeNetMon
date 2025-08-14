import nmap
import threading
import logging
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from models import db, Device
from sqlalchemy import and_

logger = logging.getLogger(__name__)

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
    """Enterprise-grade network security scanner for HomeNetMon"""
    
    def __init__(self, app=None):
        self.app = app
        self.running = False
        self.scan_interval = 3600  # 1 hour default
        self.nm = nmap.PortScanner()
        
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
        """Scan ports on a specific device"""
        results = []
        
        try:
            # Build nmap command arguments
            nmap_args = f"-T4 --top-ports {self.scan_config['top_ports']}"
            
            if self.scan_config['service_detection']:
                nmap_args += " -sV"
            
            if self.scan_config['skip_host_discovery']:
                nmap_args += " -Pn"
            
            # Perform the scan
            logger.debug(f"Running nmap scan: nmap {nmap_args} {device.ip_address}")
            scan_result = self.nm.scan(device.ip_address, arguments=nmap_args)
            
            # Parse results
            if device.ip_address in scan_result['scan']:
                host_info = scan_result['scan'][device.ip_address]
                
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
                        
                        logger.debug(f"Found service: {device.ip_address}:{port} - {result.service}")
        
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
                if risk_score >= 7:  # High risk threshold
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
        
        if risk_score >= 8:
            return 'critical'
        elif risk_score >= 6:
            return 'high'
        elif risk_score >= 4:
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
    
    def get_security_summary(self, hours: int = 24) -> Dict:
        """Get security summary statistics"""
        try:
            from models import Alert
            
            start_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Count security alerts by type and severity
            security_alerts = db.session.query(Alert).filter(
                and_(
                    Alert.alert_type.like('security_%'),
                    Alert.created_at >= start_time
                )
            ).all()
            
            summary = {
                'total_alerts': len(security_alerts),
                'by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                'by_type': {},
                'recent_scans': 0,
                'devices_scanned': 0
            }
            
            for alert in security_alerts:
                # Count by severity
                summary['by_severity'][alert.severity] += 1
                
                # Count by type
                alert_type = alert.alert_type.replace('security_', '')
                summary['by_type'][alert_type] = summary['by_type'].get(alert_type, 0) + 1
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting security summary: {e}")
            return {'error': str(e)}
    
    def manual_scan_device(self, device_id: int) -> Dict:
        """Manually trigger a security scan for a specific device"""
        try:
            with self.app.app_context():
                device = Device.query.get(device_id)
                if not device:
                    return {'error': 'Device not found'}
                
                logger.info(f"Manual security scan requested for {device.display_name}")
                
                scan_results = self.scan_device_ports(device)
                security_alerts = self.analyze_security_results(device, scan_results)
                
                if scan_results:
                    self.store_scan_results(scan_results)
                
                if security_alerts:
                    self.process_security_alerts(security_alerts)
                
                return {
                    'success': True,
                    'device_name': device.display_name,
                    'ports_scanned': len(scan_results),
                    'open_ports': len([r for r in scan_results if r.state == 'open']),
                    'security_alerts': len(security_alerts),
                    'alerts': [
                        {
                            'type': a.alert_type,
                            'severity': a.severity,
                            'message': a.message,
                            'risk_score': a.risk_score
                        } for a in security_alerts
                    ]
                }
                
        except Exception as e:
            logger.error(f"Error in manual device scan: {e}")
            return {'error': str(e)}

# Global security scanner service instance
security_scanner = NetworkSecurityScanner()