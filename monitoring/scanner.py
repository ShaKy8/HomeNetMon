import nmap
import time
import threading
import ipaddress
import subprocess
import re
import logging
from datetime import datetime
from manuf import manuf
from models import db, Device, Configuration
from config import Config
from services.push_notifications import push_service

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, app=None):
        self.nm = nmap.PortScanner()
        self.mac_parser = manuf.MacParser()
        self.is_running = False
        self.is_scanning = False  # Track manual scan status
        self.scan_thread = None
        self._stop_event = threading.Event()
        self.app = app
        self.rule_engine_service = None
        
        # Configuration caching for hot-reload
        self._config_cache = {}
        self._config_versions = {}
        self._last_config_check = datetime.utcnow()
        
        # Track new devices for notifications
        self._devices_before_scan = set()
        self._new_devices_found = []
        
    def get_config_value(self, key, default):
        """Get configuration value from database with hot-reload support"""
        try:
            with self.app.app_context():
                # Check if we need to reload configuration (every 10 seconds)
                now = datetime.utcnow()
                if (now - self._last_config_check).total_seconds() > 10:
                    self._check_config_changes()
                    self._last_config_check = now
                
                # Return cached value if available and valid
                if key in self._config_cache:
                    return self._config_cache[key]
                
                # Load from database and cache
                value = Configuration.get_value(key, str(default))
                self._config_cache[key] = value
                self._config_versions[key] = Configuration.get_config_version(key)
                return value
        except Exception as e:
            logger.error(f"Error getting config value {key}: {e}")
            return str(default)
    
    def _check_config_changes(self):
        """Check for configuration changes and reload if needed"""
        try:
            with self.app.app_context():
                # Check each cached config for version changes
                for key in list(self._config_cache.keys()):
                    current_version = Configuration.get_config_version(key)
                    cached_version = self._config_versions.get(key, 0)
                    
                    if current_version != cached_version:
                        # Configuration changed, reload it
                        new_value = Configuration.get_value(key, self._config_cache[key])
                        old_value = self._config_cache[key]
                        self._config_cache[key] = new_value
                        self._config_versions[key] = current_version
                        
                        logger.info(f"Configuration reloaded: {key} changed from '{old_value}' to '{new_value}'")
                        
                        # Trigger specific actions for certain config changes
                        if key == 'network_range' and old_value != new_value:
                            self._handle_network_range_change(old_value, new_value)
                        
        except Exception as e:
            logger.error(f"Error checking config changes: {e}")
    
    def _handle_network_range_change(self, old_range, new_range):
        """Handle network range configuration change"""
        logger.info(f"Network range changed from {old_range} to {new_range}")
        # Trigger a network scan with the new range if not currently scanning
        if not self.is_scanning:
            logger.info("Triggering network scan with new range")
            threading.Thread(target=self.scan_network, daemon=True, name='NetworkRangeScan').start()
    
    def reload_config(self):
        """Force reload all cached configuration"""
        logger.info("Force reloading all configuration")
        self._config_cache.clear()
        self._config_versions.clear()
        self._last_config_check = datetime.utcnow()
        self._check_config_changes()
        
    def get_arp_table(self):
        """Parse ARP table to find active devices"""
        devices = []
        try:
            # Try different ARP commands based on OS
            try:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
                arp_output = result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError):
                try:
                    result = subprocess.run(['ip', 'neigh'], capture_output=True, text=True, timeout=10)
                    arp_output = result.stdout
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    logger.warning("Could not execute ARP or ip neigh command")
                    return devices
            
            # Parse ARP table output
            lines = arp_output.strip().split('\n')
            for line in lines:
                # Match patterns like: 192.168.86.1 at aa:bb:cc:dd:ee:ff on en0
                # or: 192.168.86.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                
                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(0).lower()
                    
                    # Normalize MAC address format
                    mac = mac.replace('-', ':')
                    
                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'source': 'arp'
                    })
                    
        except Exception as e:
            logger.error(f"Error parsing ARP table: {e}")
            
        return devices
    
    def nmap_scan(self, network_range):
        """Perform nmap scan to discover devices"""
        devices = []
        try:
            logger.info(f"Starting nmap scan of {network_range}")
            
            # Use nmap ping scan to find live hosts
            scan_result = self.nm.scan(hosts=network_range, arguments='-sn')
            
            for host in scan_result['scan']:
                host_info = scan_result['scan'][host]
                
                if host_info['status']['state'] == 'up':
                    device_info = {
                        'ip': host,
                        'mac': None,
                        'hostname': None,
                        'vendor': None,
                        'source': 'nmap'
                    }
                    
                    # Get MAC address if available
                    if 'addresses' in host_info and 'mac' in host_info['addresses']:
                        device_info['mac'] = host_info['addresses']['mac'].lower()
                    
                    # Get hostname if available
                    if 'hostnames' in host_info and host_info['hostnames']:
                        device_info['hostname'] = host_info['hostnames'][0]['name']
                    
                    devices.append(device_info)
                    
        except Exception as e:
            logger.error(f"Error during nmap scan: {e}")
            
        return devices
    
    def resolve_hostname(self, ip):
        """Resolve hostname for IP address"""
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def get_mac_vendor(self, mac):
        """Get vendor information from MAC address"""
        try:
            return self.mac_parser.get_manuf(mac)
        except:
            return None
    
    def classify_device_type(self, device_info):
        """Attempt to classify device type based on available information"""
        hostname = (device_info.get('hostname') or '').lower()
        vendor = (device_info.get('vendor') or '').lower()
        ip = device_info.get('ip') or ''
        
        # Camera detection (highest priority)
        camera_keywords = [
            'camera', 'cam', 'ring', 'wyze', 'nest-cam', 'arlo', 'surveillance',
            'doorbell', 'spotlight', 'security', 'webcam', 'ipcam'
        ]
        if any(keyword in hostname for keyword in camera_keywords):
            return 'camera'
        if any(keyword in vendor for keyword in ['wyzelabs', 'ring', 'arlo', 'hikvision', 'dahua']):
            return 'camera'
        # Ring devices often have ring- prefix or specific patterns
        if 'ring-' in hostname or 'ringspotlight' in hostname or 'ringdoorbell' in hostname:
            return 'camera'
            
        # Network Infrastructure
        router_keywords = ['router', 'gateway', 'gw', 'modem', 'switch', 'access-point', 'ap']
        if any(keyword in hostname for keyword in router_keywords):
            return 'router'
        if any(keyword in vendor for keyword in ['cisco', 'netgear', 'linksys', 'tp-link', 'asus', 'ubiquiti']):
            return 'router'
        # Google Nest WiFi points
        if 'nest-wifi' in hostname or 'google-wifi' in hostname:
            return 'router'
            
        # Smart Home & IoT Devices
        iot_keywords = [
            'nest', 'thermostat', 'smart', 'hub', 'sensor', 'switch', 'plug',
            'bulb', 'light', 'alexa', 'echo', 'google-home', 'google-nest',
            'chromecast', 'sonos', 'speaker', 'litter-robot', 'fridge',
            'dishwasher', 'washer', 'dryer', 'hvac', 'irrigation', 'sprinkler'
        ]
        if any(keyword in hostname for keyword in iot_keywords):
            return 'smart_home'
        if any(keyword in vendor for keyword in ['sonos', 'nestlabs', 'google', 'amazon', 'philips', 'wemo']):
            return 'smart_home'
        # Specific IoT device patterns
        if 'esp' in hostname or 'arduino' in hostname or 'raspberry' in hostname:
            return 'iot'
            
        # Apple/Mac devices  
        mac_keywords = ['macbook', 'imac', 'mac.', 'macos', 'iphone', 'ipad', 'apple']
        if any(keyword in hostname for keyword in mac_keywords):
            return 'apple'
        if 'apple' in vendor:
            return 'apple'
        # Check for Apple-like MAC addresses (common patterns)
        mac = device_info.get('mac') or ''
        if mac:
            mac = mac.lower()
            apple_ouis = ['00:1b:63', '00:1f:f3', '00:23:df', '00:25:00', '3c:07:54', '4c:8d:79']
            if any(mac.startswith(oui) for oui in apple_ouis):
                return 'apple'
            
        # Mobile/Phone detection
        phone_keywords = ['android', 'phone', 'mobile', 'samsung', 'pixel', 'oneplus']
        if any(keyword in hostname for keyword in phone_keywords):
            return 'phone'
        if any(keyword in vendor for keyword in ['samsung', 'samsunge', 'lg', 'motorola', 'huawei']):
            return 'phone'
            
        # Computer/Laptop detection
        computer_keywords = [
            'pc', 'laptop', 'desktop', 'workstation', 'server', 'nuc',
            'dell', 'hp', 'lenovo', 'asus', 'thinkpad', 'surface'
        ]
        if any(keyword in hostname for keyword in computer_keywords):
            return 'computer'
        if any(keyword in vendor for keyword in ['dell', 'hewletthp', 'hewlettp', 'lenovo', 'asus', 'microsoft']):
            return 'computer'
            
        # Gaming Consoles
        gaming_keywords = ['xbox', 'playstation', 'ps4', 'ps5', 'nintendo', 'switch', 'steam']
        if any(keyword in hostname for keyword in gaming_keywords):
            return 'gaming'
        if any(keyword in vendor for keyword in ['microsoft', 'sony', 'nintendo']):
            return 'gaming'
            
        # TV/Media devices
        media_keywords = ['tv', 'roku', 'appletv', 'firetv', 'nvidia-shield', 'media-player']
        if any(keyword in hostname for keyword in media_keywords):
            return 'media'
        if any(keyword in vendor for keyword in ['roku', 'nvidia', 'lg', 'samsung', 'sony']):
            # Only classify as media if it's clearly a TV/media device
            if any(keyword in hostname for keyword in ['tv', 'roku', 'shield', 'chromecast']):
                return 'media'
            
        # Printers
        printer_keywords = ['printer', 'print', 'canon', 'epson', 'brother', 'hp-printer']
        if any(keyword in hostname for keyword in printer_keywords):
            return 'printer'
        if any(keyword in vendor for keyword in ['canon', 'epson', 'brother']) and 'print' in hostname:
            return 'printer'
            
        # Storage/NAS
        storage_keywords = ['nas', 'storage', 'synology', 'qnap', 'drobo', 'freenas']
        if any(keyword in hostname for keyword in storage_keywords):
            return 'storage'
        if any(keyword in vendor for keyword in ['synology', 'qnap', 'drobo']):
            return 'storage'
            
        return 'unknown'
    
    def scan_network(self):
        """Perform complete network scan and update database"""
        logger.info("Starting network discovery scan")
        
        # Set scanning flag
        self.is_scanning = True
        
        # Store existing devices before scan for new device detection
        try:
            with self.app.app_context():
                existing_devices = Device.query.all()
                self._devices_before_scan = {device.ip_address for device in existing_devices}
                self._new_devices_found = []
        except Exception as e:
            logger.error(f"Error getting existing devices: {e}")
            self._devices_before_scan = set()
            self._new_devices_found = []
        
        try:
            # Use Flask application context for database operations
            with self.app.app_context():
                try:
                    # Get devices from ARP table (faster)
                    arp_devices = self.get_arp_table()
                    logger.info(f"Found {len(arp_devices)} devices in ARP table")
                    
                    # Get network range from database configuration
                    network_range = self.get_config_value('network_range', Config.NETWORK_RANGE)
                    logger.info(f"Using network range: {network_range}")
                    
                    # Merge with nmap scan results
                    nmap_devices = self.nmap_scan(network_range)
                    logger.info(f"Found {len(nmap_devices)} devices with nmap scan")
                    
                    # Combine and deduplicate devices
                    all_devices = {}
                    
                    # Add ARP devices
                    for device in arp_devices:
                        all_devices[device['ip']] = device
                    
                    # Add nmap devices (may override ARP info)
                    for device in nmap_devices:
                        if device['ip'] in all_devices:
                            # Merge information
                            all_devices[device['ip']].update({k: v for k, v in device.items() if v})
                        else:
                            all_devices[device['ip']] = device
                    
                    # Process each discovered device
                    for ip, device_info in all_devices.items():
                        self.process_discovered_device(device_info)
                        
                    logger.info(f"Network scan completed. Processed {len(all_devices)} devices")
                    
                    # Send push notifications for scan completion and new devices
                    self._send_scan_completion_notifications(len(all_devices))
                    
                    # Trigger rule engine for scan completion
                    self._trigger_rule_engine_for_scan_completion(len(all_devices), len(self._new_devices_found))
                    
                except Exception as e:
                    logger.error(f"Error during network scan: {e}")
        finally:
            # Always clear the scanning flag when done
            self.is_scanning = False
    
    def process_discovered_device(self, device_info):
        """Process a discovered device and update database"""
        try:
            ip = device_info['ip']
            
            # Check if device already exists
            device = Device.query.filter_by(ip_address=ip).first()
            
            if device:
                # Update existing device
                updated = False
                
                if device_info.get('mac') and device.mac_address != device_info['mac']:
                    device.mac_address = device_info['mac']
                    updated = True
                
                if device_info.get('hostname') and device.hostname != device_info['hostname']:
                    device.hostname = device_info['hostname']
                    updated = True
                
                # Resolve hostname if we don't have one
                if not device.hostname:
                    hostname = self.resolve_hostname(ip)
                    if hostname:
                        device.hostname = hostname
                        updated = True
                
                # Get vendor info if we have MAC but no vendor
                if device.mac_address and not device.vendor:
                    vendor = self.get_mac_vendor(device.mac_address)
                    if vendor:
                        device.vendor = vendor
                        updated = True
                
                # Classify device type if not set
                if not device.device_type:
                    device_type = self.classify_device_type({
                        'hostname': device.hostname,
                        'vendor': device.vendor
                    })
                    device.device_type = device_type
                    updated = True
                
                device.last_seen = datetime.utcnow()
                
                if updated:
                    device.updated_at = datetime.utcnow()
                    
            else:
                # Create new device
                hostname = device_info.get('hostname') or self.resolve_hostname(ip)
                vendor = None
                
                if device_info.get('mac'):
                    vendor = self.get_mac_vendor(device_info['mac'])
                
                device_type = self.classify_device_type({
                    'hostname': hostname,
                    'vendor': vendor
                })
                
                device = Device(
                    ip_address=ip,
                    mac_address=device_info.get('mac'),
                    hostname=hostname,
                    vendor=vendor,
                    device_type=device_type,
                    last_seen=datetime.utcnow()
                )
                
                db.session.add(device)
                db.session.flush()  # Ensure device has an ID for rule engine
                logger.info(f"Added new device: {ip} ({hostname or 'unknown'})")
                
                # Trigger rule engine for new device discovery
                self._trigger_rule_engine_for_new_device(device)
                
                # Track new device for notifications
                if ip not in self._devices_before_scan:
                    self._new_devices_found.append({
                        'ip': ip,
                        'hostname': hostname,
                        'device_type': device_type,
                        'vendor': vendor
                    })
            
            db.session.commit()
            
        except Exception as e:
            logger.error(f"Error processing device {device_info.get('ip')}: {e}")
            db.session.rollback()
    
    def _send_scan_completion_notifications(self, total_devices):
        """Send push notifications for scan completion and new devices"""
        try:
            with self.app.app_context():
                # Get dashboard URL
                dashboard_url = f"http://{Config.HOST}:{Config.PORT}"
                
                # Send individual notifications for new devices (limit to 5 to avoid spam)
                new_device_count = len(self._new_devices_found)
                devices_to_notify = self._new_devices_found[:5]  # Limit to first 5
                
                for device_info in devices_to_notify:
                    device_name = device_info['hostname'] or device_info['ip']
                    success = push_service.send_new_device_alert(
                        device_name=device_name,
                        ip_address=device_info['ip'],
                        device_type=device_info['device_type'],
                        dashboard_url=dashboard_url
                    )
                    if success:
                        logger.info(f"Sent new device notification for {device_name}")
                
                # Send scan completion notification
                success = push_service.send_network_scan_complete(
                    new_devices=new_device_count,
                    total_devices=total_devices,
                    dashboard_url=dashboard_url
                )
                if success:
                    logger.info(f"Sent scan completion notification: {new_device_count} new, {total_devices} total")
                    
                # If more than 5 new devices, send a summary notification
                if new_device_count > 5:
                    summary_title = f"📱 {new_device_count - 5} More New Devices"
                    summary_message = f"Found {new_device_count - 5} additional new devices. Check the dashboard for full details."
                    push_service.send_notification(
                        title=summary_title,
                        message=summary_message,
                        priority="low",
                        tags="information_source,blue_circle",
                        click_url=dashboard_url
                    )
                    
        except Exception as e:
            logger.error(f"Error sending scan completion notifications: {e}")
    
    def _get_push_service_config(self):
        """Update push service configuration from database"""
        try:
            with self.app.app_context():
                push_service.enabled = Configuration.get_value('push_notifications_enabled', 'false').lower() == 'true'
                push_service.topic = Configuration.get_value('ntfy_topic', '')
                push_service.server = Configuration.get_value('ntfy_server', 'https://ntfy.sh')
        except Exception as e:
            logger.error(f"Error updating push service config: {e}")
    
    def start_continuous_scan(self):
        """Start continuous network scanning"""
        try:
            self.is_running = True
            
            logger.info("Starting continuous network scanning")
            
            # Update push service configuration
            self._get_push_service_config()
            
            # Perform initial scan
            self.scan_network()
        except Exception as e:
            logger.error(f"SCANNER STARTUP ERROR: {e}")
            import traceback
            logger.error(f"SCANNER TRACEBACK: {traceback.format_exc()}")
            return
        
        # Continue scanning at intervals
        while not self._stop_event.is_set():
            try:
                scan_interval = int(self.get_config_value('scan_interval', Config.SCAN_INTERVAL))
                self._stop_event.wait(scan_interval)
                if not self._stop_event.is_set():
                    self.scan_network()
            except Exception as e:
                logger.error(f"Error in continuous scan loop: {e}")
                time.sleep(60)  # Wait before retrying
        
        self.is_running = False
        logger.info("Network scanning stopped")
    
    def stop(self):
        """Stop the network scanner"""
        logger.info("Stopping network scanner")
        self._stop_event.set()
        self.is_running = False
    
    def _trigger_rule_engine_for_new_device(self, device):
        """Trigger rule engine evaluation for new device discovery"""
        try:
            # Get rule engine service from app if available
            if self.app and hasattr(self.app, 'rule_engine_service'):
                rule_engine_service = self.app.rule_engine_service
                
                # Import here to avoid circular imports
                from services.rule_engine import TriggerContext
                
                # Create trigger context for the new device event
                context = TriggerContext(
                    event_type='new_device_discovered',
                    device_id=device.id,
                    device={
                        'id': device.id,
                        'display_name': device.display_name,
                        'ip_address': device.ip_address,
                        'mac_address': device.mac_address,
                        'hostname': device.hostname,
                        'vendor': device.vendor,
                        'device_type': device.device_type,
                        'is_monitored': device.is_monitored
                    },
                    metadata={
                        'discovery_method': 'network_scan',
                        'scan_timestamp': datetime.utcnow().isoformat()
                    }
                )
                
                # Evaluate rules in background thread to avoid blocking scan processing
                import threading
                rule_thread = threading.Thread(
                    target=rule_engine_service.evaluate_rules,
                    args=(context,),
                    daemon=True,
                    name='RuleEngine-NewDevice'
                )
                rule_thread.start()
                
                logger.debug(f"Triggered rule engine for new device discovery: {device.display_name}")
                
        except Exception as e:
            logger.error(f"Error triggering rule engine for new device: {e}")
            # Don't let rule engine errors affect scan processing
    
    def _trigger_rule_engine_for_scan_completion(self, total_devices, new_devices):
        """Trigger rule engine evaluation for scan completion"""
        try:
            # Get rule engine service from app if available
            if self.app and hasattr(self.app, 'rule_engine_service'):
                rule_engine_service = self.app.rule_engine_service
                
                # Import here to avoid circular imports
                from services.rule_engine import TriggerContext
                
                # Create trigger context for the scan completion event
                context = TriggerContext(
                    event_type='scan_complete',
                    metadata={
                        'total_devices': total_devices,
                        'new_devices': new_devices,
                        'scan_type': 'network',
                        'scan_timestamp': datetime.utcnow().isoformat()
                    }
                )
                
                # Evaluate rules in background thread to avoid blocking scan processing
                import threading
                rule_thread = threading.Thread(
                    target=rule_engine_service.evaluate_rules,
                    args=(context,),
                    daemon=True,
                    name='RuleEngine-ScanComplete'
                )
                rule_thread.start()
                
                logger.debug(f"Triggered rule engine for scan completion: {total_devices} total, {new_devices} new")
                
        except Exception as e:
            logger.error(f"Error triggering rule engine for scan completion: {e}")
            # Don't let rule engine errors affect scan processing