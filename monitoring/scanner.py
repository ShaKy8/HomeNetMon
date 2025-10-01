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

    def _emit_scan_progress(self, progress, stage, devices_found=0, new_devices=0):
        """Emit scan progress via WebSocket"""
        try:
            if hasattr(self.app, 'socketio'):
                self.app.socketio.emit('scan_progress', {
                    'progress': progress,
                    'stage': stage,
                    'devices_found': devices_found,
                    'new_devices': new_devices,
                    'timestamp': datetime.utcnow().isoformat()
                })
                logger.debug(f"Emitted scan progress: {progress}% - {stage}")
        except Exception as e:
            logger.error(f"Error emitting scan progress: {e}")

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
    
    def get_adaptive_scan_interval(self):
        """Get adaptive scan interval based on network activity and time of day"""
        base_interval = int(self.get_config_value('scan_interval', Config.SCAN_INTERVAL))
        
        try:
            current_hour = datetime.now().hour
            
            # Reduce scanning during typical sleep hours (11 PM - 7 AM)
            if current_hour >= 23 or current_hour <= 7:
                return base_interval * 2  # Double interval during night hours
            
            # Reduce scanning during typical work hours (9 AM - 5 PM) when network is more active
            elif 9 <= current_hour <= 17:
                return int(base_interval * 1.5)  # 1.5x interval during day
            
            # Normal interval during evening hours
            else:
                return base_interval
                
        except Exception as e:
            logger.warning(f"Error calculating adaptive scan interval: {e}")
            return base_interval

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
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10, shell=False)
                arp_output = result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError):
                try:
                    result = subprocess.run(['ip', 'neigh'], capture_output=True, text=True, timeout=10, shell=False)
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
    
    def is_sensitive_device(self, device_info):
        """Check if device should be scanned less frequently or excluded"""
        sensitive_patterns = [
            # IoT devices that may be sensitive to scanning
            'ring', 'nest', 'wyze', 'arlo', 'roku', 'chromecast',
            'echo', 'alexa', 'thermostat', 'camera', 'sensor',
            'bulb', 'switch', 'plug', 'doorbell', 'apple-tv',
            # Manufacturers known for IoT devices
            'amazon', 'google', 'nest labs', 'ring inc', 'wyze labs'
        ]
        
        device_name = device_info.get('hostname', '').lower()
        device_vendor = device_info.get('vendor', '').lower()
        
        for pattern in sensitive_patterns:
            if pattern in device_name or pattern in device_vendor:
                return True
        return False

    def _get_excluded_device_ips(self):
        """Get list of device IPs that should be excluded from nmap scanning"""
        excluded_ips = []
        try:
            with self.app.app_context():
                # Get printers and other sensitive device types
                sensitive_types = ['printer']
                
                # Query for devices with sensitive types
                sensitive_devices = Device.query.filter(
                    Device.device_type.in_(sensitive_types)
                ).all()
                
                for device in sensitive_devices:
                    if device.ip_address:
                        excluded_ips.append(device.ip_address)
                        logger.debug(f"Excluding {device.device_type} device from nmap scan: {device.ip_address}")
                
                # Also check for user-configured exclusions
                excluded_config = self.get_config_value('scan_excluded_ips', '')
                if excluded_config:
                    # Parse comma-separated IP list
                    for ip in excluded_config.split(','):
                        ip = ip.strip()
                        if ip and ip not in excluded_ips:
                            excluded_ips.append(ip)
                            logger.debug(f"Excluding user-configured IP from nmap scan: {ip}")
                            
        except Exception as e:
            logger.error(f"Error getting excluded device IPs: {e}")
            
        return excluded_ips
    
    def _get_scan_targets_excluding_ips(self, network_range, excluded_ips):
        """Generate scan targets from network range while excluding specific IPs"""
        scan_targets = []
        try:
            import ipaddress
            
            # Parse the network range
            network = ipaddress.IPv4Network(network_range, strict=False)
            
            # For small networks (< 50 hosts), scan individual IPs
            # For larger networks, use subnet exclusion where possible
            if network.num_addresses <= 50:
                # Generate individual IP list, excluding the ones we want to skip
                for ip in network.hosts():
                    ip_str = str(ip)
                    if ip_str not in excluded_ips:
                        scan_targets.append(ip_str)
            else:
                # For larger networks, use the full range and rely on nmap's built-in exclusion
                # This is less precise but more efficient for large networks
                scan_targets.append(network_range)
                logger.warning(f"Large network detected ({network.num_addresses} addresses), using range scan with post-processing exclusion")
                
        except Exception as e:
            logger.error(f"Error processing network range exclusions: {e}")
            # Fallback to original network range
            scan_targets.append(network_range)
            
        return scan_targets

    def nmap_scan(self, network_range):
        """Perform nmap scan to discover devices, excluding sensitive devices like printers"""
        devices = []
        try:
            # Get list of printer IPs to exclude from nmap scanning
            excluded_ips = self._get_excluded_device_ips()
            
            if excluded_ips:
                logger.info(f"Excluding {len(excluded_ips)} sensitive devices from nmap scan: {', '.join(excluded_ips)}")
            
            # If we have devices to exclude, we need to scan individual IPs or subnets
            if excluded_ips and '/' in network_range:
                # Parse network range and exclude specific IPs
                scan_targets = self._get_scan_targets_excluding_ips(network_range, excluded_ips)
                if not scan_targets:
                    logger.info("All devices in network range are excluded, skipping nmap scan")
                    return devices
                scan_hosts = ','.join(scan_targets)
            else:
                scan_hosts = network_range
            
            logger.info(f"Starting gentle nmap scan of network (excluding sensitive devices)")
            
            # Use gentle nmap ping scan optimized for home networks
            # -sn: Ping scan only (no port scan)
            # -T2: Polite timing (slower but less aggressive)
            # --max-rtt-timeout 2000ms: Allow slower devices more time to respond
            # --max-retries 1: Reduce retries to minimize network traffic
            scan_result = self.nm.scan(hosts=scan_hosts, arguments='-sn -T2 --max-rtt-timeout 2000ms --max-retries 1')
            
            for host in scan_result['scan']:
                host_info = scan_result['scan'][host]
                
                # Skip excluded IPs (double-check in case they somehow got scanned)
                if host in excluded_ips:
                    logger.debug(f"Filtering out excluded IP from nmap results: {host}")
                    continue
                
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
            
        # Printers - Enhanced detection to catch all printer models
        printer_keywords = ['printer', 'print', 'canon', 'epson', 'brother', 'hp-printer',
                           'laserjet', 'deskjet', 'officejet', 'envy', 'pixma', 'imageclass',
                           'ultrathink', 'xerox', 'lexmark', 'ricoh', 'sharp', 'kyocera',
                           'samsung-printer', 'dell-printer', 'konica', 'minolta', 'toshiba']
        if any(keyword in hostname for keyword in printer_keywords):
            return 'printer'
        # Check vendor names for printer manufacturers
        printer_vendors = ['canon', 'epson', 'brother', 'hewlett', 'hp', 'xerox',
                          'lexmark', 'ricoh', 'sharp', 'kyocera', 'konica', 'minolta']
        if any(keyword in vendor for keyword in printer_vendors):
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

        # Store existing devices before scan for new device detection (use MAC when available)
        try:
            with self.app.app_context():
                existing_devices = Device.query.all()
                self._devices_before_scan = set()
                for device in existing_devices:
                    # Use MAC address as primary identifier, fallback to IP for devices without MAC
                    identifier = device.mac_address if device.mac_address else device.ip_address
                    self._devices_before_scan.add(identifier)
                self._new_devices_found = []

                # Emit initial progress
                self._emit_scan_progress(5, 'Initializing scan...', 0, 0)
        except Exception as e:
            logger.error(f"Error getting existing devices: {e}")
            self._devices_before_scan = set()
            self._new_devices_found = []
        
        try:
            # Use Flask application context for database operations
            with self.app.app_context():
                try:
                    # Get devices from ARP table (faster)
                    self._emit_scan_progress(15, 'Scanning ARP table...', 0, 0)
                    arp_devices = self.get_arp_table()
                    logger.info(f"Found {len(arp_devices)} devices in ARP table")

                    # Get network range from database configuration
                    network_range = self.get_config_value('network_range', Config.NETWORK_RANGE)
                    logger.info(f"Using network range: {network_range}")

                    # Merge with nmap scan results
                    self._emit_scan_progress(30, 'Running network discovery (nmap)...', len(arp_devices), 0)
                    nmap_devices = self.nmap_scan(network_range)
                    logger.info(f"Found {len(nmap_devices)} devices with nmap scan")
                    self._emit_scan_progress(60, 'Merging scan results...', len(nmap_devices), 0)
                    
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
                    self._emit_scan_progress(75, 'Processing discovered devices...', len(all_devices), 0)
                    for i, (ip, device_info) in enumerate(all_devices.items()):
                        self.process_discovered_device(device_info)

                        # Update progress for device processing
                        if i % 5 == 0:  # Update every 5 devices to avoid too many emissions
                            progress = 75 + (i / len(all_devices)) * 15  # From 75% to 90%
                            self._emit_scan_progress(progress, f'Processing device {i+1}/{len(all_devices)}...', len(all_devices), len(self._new_devices_found))

                    self._emit_scan_progress(90, 'Updating database...', len(all_devices), len(self._new_devices_found))

                    # Commit the database changes
                    db.session.commit()

                    logger.info(f"Network scan completed. Processed {len(all_devices)} devices")

                    self._emit_scan_progress(95, 'Finalizing results...', len(all_devices), len(self._new_devices_found))

                    # Send push notifications for scan completion and new devices
                    self._send_scan_completion_notifications(len(all_devices))

                    # Trigger rule engine for scan completion
                    self._trigger_rule_engine_for_scan_completion(len(all_devices), len(self._new_devices_found))

                    # Emit final 100% completion
                    self._emit_scan_progress(100, 'Scan completed successfully!', len(all_devices), len(self._new_devices_found))
                    
                except Exception as e:
                    logger.error(f"Error during network scan: {e}")
                    # Emit error event via WebSocket
                    try:
                        if hasattr(self.app, 'socketio'):
                            self.app.socketio.emit('scan_error', {
                                'error': str(e),
                                'timestamp': datetime.utcnow().isoformat()
                            }, namespace='/', broadcast=True)
                    except Exception as emit_error:
                        logger.error(f"Error emitting scan error: {emit_error}")
                    raise
        finally:
            # Always clear the scanning flag when done
            self.is_scanning = False
    
    def process_discovered_device(self, device_info):
        """Process a discovered device and update database using MAC-based identification"""
        try:
            ip = device_info['ip']
            mac = device_info.get('mac')
            
            device = None
            ip_changed = False
            is_new_device = False
            
            # MAC-based device identification (primary method)
            if mac:
                # Look up device by MAC address first
                device = Device.query.filter_by(mac_address=mac).first()
                
                if device:
                    # Device exists - check if IP has changed
                    if device.ip_address != ip:
                        old_ip = device.ip_address
                        logger.info(f"Device MAC {mac} IP changed: {old_ip} -> {ip}")
                        
                        # Check if another device already has this IP
                        existing_device_with_ip = Device.query.filter_by(ip_address=ip).first()

                        if existing_device_with_ip and existing_device_with_ip.id != device.id:
                            logger.warning(f"IP conflict detected: {ip} is already used by device {existing_device_with_ip.id}")

                            # Resolve conflict: if the other device has no MAC or different MAC,
                            # it's likely a stale entry, so clear its IP
                            if not existing_device_with_ip.mac_address or existing_device_with_ip.mac_address != mac:
                                logger.info(f"Clearing IP from stale device {existing_device_with_ip.id}")
                                existing_device_with_ip.ip_address = None
                                existing_device_with_ip.updated_at = datetime.utcnow()
                            else:
                                # Both devices have the same MAC - this shouldn't happen, but skip update
                                logger.error(f"Two devices with same MAC {mac} and IP {ip} - skipping update")
                                return

                        # Log IP change to history table
                        try:
                            db.session.execute(db.text("""
                                INSERT INTO device_ip_history
                                (device_id, old_ip_address, new_ip_address, change_reason, changed_at, detected_by, change_detected_at, change_source)
                                VALUES (:device_id, :old_ip, :new_ip, :reason, :changed_at, :detected_by, :change_detected_at, :change_source)
                            """), {
                                'device_id': device.id,
                                'old_ip': old_ip,
                                'new_ip': ip,
                                'reason': 'DHCP IP address change detected during scan',
                                'changed_at': datetime.utcnow().isoformat(),
                                'detected_by': 'network_scanner',
                                'change_detected_at': datetime.utcnow().isoformat(),
                                'change_source': 'network_scanner'
                            })

                            # Update device IP address
                            device.ip_address = ip
                            ip_changed = True
                            logger.info(f"Updated device {device.display_name} IP: {old_ip} -> {ip}")

                        except Exception as e:
                            logger.error(f"Error logging IP change for device {device.id}: {e}")
                            # Even if history logging fails, try to update the IP
                            try:
                                device.ip_address = ip
                                ip_changed = True
                                logger.info(f"Updated device {device.display_name} IP: {old_ip} -> {ip} (history logging failed)")
                            except Exception as ip_error:
                                logger.error(f"Failed to update IP for device {device.id}: {ip_error}")
                
            # Fallback: IP-based lookup for devices without MAC
            if not device:
                device = Device.query.filter_by(ip_address=ip).first()
                
                # If we found a device by IP but now have a MAC, update it
                if device and mac and not device.mac_address:
                    device.mac_address = mac
                    logger.info(f"Added MAC address {mac} to existing device {device.display_name}")
            
            if device:
                # Update existing device
                updated = ip_changed  # IP change already counts as an update
                
                # Update MAC if we didn't have one before
                if mac and not device.mac_address:
                    device.mac_address = mac
                    updated = True
                
                # Update hostname if provided and different
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
                        'vendor': device.vendor,
                        'mac': device.mac_address,
                        'ip': device.ip_address
                    })
                    device.device_type = device_type
                    updated = True
                
                device.last_seen = datetime.utcnow()
                
                if updated:
                    device.updated_at = datetime.utcnow()
                    
            else:
                # Create new device
                is_new_device = True
                hostname = device_info.get('hostname') or self.resolve_hostname(ip)
                vendor = None

                if mac:
                    vendor = self.get_mac_vendor(mac)

                device_type = self.classify_device_type({
                    'hostname': hostname,
                    'vendor': vendor,
                    'mac': mac,
                    'ip': ip
                })

                # Check if another device already has this IP (collision handling)
                existing_ip_device = Device.query.filter_by(ip_address=ip).first()
                if existing_ip_device:
                    logger.warning(f"IP {ip} already exists for device {existing_ip_device.id}. Resolving conflict...")

                    # If existing device has no MAC or different MAC, clear its IP
                    if not existing_ip_device.mac_address or (mac and existing_ip_device.mac_address != mac):
                        logger.info(f"Clearing IP from existing device {existing_ip_device.id} to resolve conflict")
                        existing_ip_device.ip_address = None
                        existing_ip_device.updated_at = datetime.utcnow()
                    else:
                        # Both have same IP/MAC - this is a duplicate, skip creation
                        logger.error(f"Duplicate device detected: IP {ip}, MAC {mac} - skipping creation")
                        return

                device = Device(
                    ip_address=ip,
                    mac_address=mac,
                    hostname=hostname,
                    vendor=vendor,
                    device_type=device_type,
                    last_seen=datetime.utcnow()
                )

                db.session.add(device)
                db.session.flush()  # Ensure device has an ID for rule engine
                
                if mac:
                    logger.info(f"Added new device: {ip} (MAC: {mac}) ({hostname or 'unknown'})")
                else:
                    logger.warning(f"Added new device without MAC: {ip} ({hostname or 'unknown'}) - may create duplicates")
                
                # Trigger rule engine for new device discovery
                self._trigger_rule_engine_for_new_device(device)
                
                # Track new device for notifications (use MAC if available, otherwise IP)
                device_key = mac if mac else ip
                if device_key not in self._devices_before_scan:
                    self._new_devices_found.append({
                        'ip': ip,
                        'mac': mac,
                        'hostname': hostname,
                        'device_type': device_type,
                        'vendor': vendor
                    })
            
            # Don't commit here - let the scan_network method handle batch commits

            # Log significant events
            if ip_changed:
                logger.info(f"Device {device.display_name} (MAC: {mac}) changed IP address")
            if is_new_device and not mac:
                logger.warning(f"New device {device.display_name} has no MAC address - consider re-scanning")
            
        except Exception as e:
            logger.error(f"Error processing device {device_info.get('ip')} (MAC: {device_info.get('mac')}): {e}")
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
        
        # Continue scanning at adaptive intervals
        while not self._stop_event.is_set():
            try:
                scan_interval = self.get_adaptive_scan_interval()
                logger.info(f"Next network scan in {scan_interval} seconds")
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