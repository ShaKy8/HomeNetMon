import subprocess
import socket
import struct
import logging
import requests
from datetime import datetime
from flask import current_app

logger = logging.getLogger(__name__)

class DeviceControlService:
    """Service for controlling network devices"""
    
    def __init__(self, app=None):
        self.app = app
        
    def send_wake_on_lan(self, mac_address):
        """Send Wake-on-LAN magic packet to device"""
        try:
            # Remove any separators from MAC address
            mac_address = mac_address.replace(':', '').replace('-', '').replace(' ', '').upper()
            
            if len(mac_address) != 12:
                return {
                    'success': False,
                    'error': 'Invalid MAC address format',
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                }
            
            # Convert MAC address to bytes
            mac_bytes = bytes.fromhex(mac_address)
            
            # Create magic packet (6 bytes of FF followed by 16 repetitions of MAC)
            magic_packet = b'\\xff' * 6 + mac_bytes * 16
            
            # Send packet via UDP broadcast
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Send to multiple broadcast addresses for better coverage
            broadcast_addresses = [
                '255.255.255.255',  # General broadcast
                '192.168.1.255',    # Common subnet
                '192.168.0.255',    # Common subnet
                '192.168.86.255',   # Kyle's subnet
            ]
            
            sent_count = 0
            for broadcast_addr in broadcast_addresses:
                try:
                    sock.sendto(magic_packet, (broadcast_addr, 9))  # Port 9 is standard for WOL
                    sent_count += 1
                except Exception as e:
                    logger.debug(f"Failed to send WOL packet to {broadcast_addr}: {e}")
            
            sock.close()
            
            logger.info(f"Wake-on-LAN packet sent to MAC {mac_address} via {sent_count} broadcast addresses")
            
            return {
                'success': True,
                'message': f'Wake-on-LAN packet sent to {mac_address}',
                'broadcast_count': sent_count,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
        except Exception as e:
            logger.error(f"Error sending Wake-on-LAN packet: {e}")
            return {
                'success': False,
                'error': f'Wake-on-LAN error: {str(e)}',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
    
    def ping_device(self, ip_address, count=4):
        """Ping a device to test connectivity"""
        try:
            # Use system ping command
            if subprocess.run(['which', 'ping'], capture_output=True).returncode == 0:
                cmd = ['ping', '-c', str(count), '-W', '3', ip_address]
            else:
                return {
                    'success': False,
                    'error': 'Ping command not available',
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                }
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Parse ping output
            output_lines = result.stdout.split('\\n')
            success_count = 0
            total_count = count
            avg_time = 0
            
            for line in output_lines:
                if 'bytes from' in line and 'time=' in line:
                    success_count += 1
                    # Extract time
                    time_part = line.split('time=')[1].split()[0]
                    avg_time += float(time_part)
            
            if success_count > 0:
                avg_time = avg_time / success_count
            
            success_rate = (success_count / total_count) * 100
            
            return {
                'success': True,
                'ip_address': ip_address,
                'packets_sent': total_count,
                'packets_received': success_count,
                'packet_loss_percent': 100 - success_rate,
                'avg_response_time': round(avg_time, 2),
                'raw_output': result.stdout,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Ping operation timed out',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        except Exception as e:
            logger.error(f"Error pinging device {ip_address}: {e}")
            return {
                'success': False,
                'error': f'Ping error: {str(e)}',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
    
    def scan_device_ports(self, ip_address, ports=None):
        """Scan common ports on a device"""
        if ports is None:
            # Common ports to scan
            ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 1723, 3389, 5900, 8080]
        
        try:
            open_ports = []
            closed_ports = []
            
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)  # 2 second timeout
                
                try:
                    result = sock.connect_ex((ip_address, port))
                    if result == 0:
                        open_ports.append(port)
                    else:
                        closed_ports.append(port)
                except Exception:
                    closed_ports.append(port)
                finally:
                    sock.close()
            
            # Map ports to services
            port_services = {
                22: 'SSH', 23: 'Telnet', 53: 'DNS', 80: 'HTTP', 135: 'RPC',
                139: 'NetBIOS', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
                995: 'POP3S', 1723: 'PPTP', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
            }
            
            open_services = [
                {'port': port, 'service': port_services.get(port, 'Unknown')}
                for port in open_ports
            ]
            
            return {
                'success': True,
                'ip_address': ip_address,
                'open_ports': open_ports,
                'open_services': open_services,
                'closed_ports': closed_ports,
                'total_scanned': len(ports),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
        except Exception as e:
            logger.error(f"Error scanning ports on {ip_address}: {e}")
            return {
                'success': False,
                'error': f'Port scan error: {str(e)}',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
    
    def discover_device_info(self, ip_address):
        """Discover additional information about a device"""
        try:
            info = {
                'ip_address': ip_address,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            # Try to get hostname
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                info['hostname'] = hostname
            except:
                info['hostname'] = None
            
            # Try HTTP title grab
            try:
                response = requests.get(f'http://{ip_address}', timeout=5)
                if '<title>' in response.text.lower():
                    title_start = response.text.lower().find('<title>') + 7
                    title_end = response.text.lower().find('</title>', title_start)
                    if title_end > title_start:
                        info['http_title'] = response.text[title_start:title_end].strip()
            except:
                pass
            
            # Try HTTPS title grab
            try:
                response = requests.get(f'https://{ip_address}', timeout=5, verify=False)
                if '<title>' in response.text.lower():
                    title_start = response.text.lower().find('<title>') + 7
                    title_end = response.text.lower().find('</title>', title_start)
                    if title_end > title_start:
                        info['https_title'] = response.text[title_start:title_end].strip()
            except:
                pass
            
            return {
                'success': True,
                'device_info': info
            }
            
        except Exception as e:
            logger.error(f"Error discovering device info for {ip_address}: {e}")
            return {
                'success': False,
                'error': f'Device discovery error: {str(e)}',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
    
    def traceroute_to_device(self, ip_address):
        """Perform traceroute to device"""
        try:
            # Try different traceroute commands
            commands = [
                ['traceroute', '-n', '-m', '15', ip_address],
                ['tracert', '-h', '15', ip_address],  # Windows
                ['mtr', '-r', '-c', '1', ip_address]  # If mtr is available
            ]
            
            for cmd in commands:
                try:
                    if subprocess.run(['which', cmd[0]], capture_output=True).returncode == 0:
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                        
                        if result.returncode == 0:
                            # Parse traceroute output
                            hops = []
                            lines = result.stdout.split('\n')
                            # Parse traceroute output
                            for line in lines:
                                line = line.strip()
                                if line and not line.startswith(('traceroute', 'Start:', 'HOST:')):
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        # Handle mtr output format: "1.|-- hostname"
                                        hop_part = parts[0]
                                        if '.|--' in hop_part:
                                            hop_num = hop_part.split('.')[0]
                                        else:
                                            hop_num = parts[0].rstrip('.')
                                        
                                        if hop_num.isdigit():
                                            hop_info = {
                                                'hop': int(hop_num),
                                                'raw_line': line
                                            }
                                            
                                            # Extract hostname from mtr format
                                            if '.|--' in parts[0] and len(parts) > 1:
                                                hostname = parts[1]
                                                hop_info['hostname'] = hostname
                                                
                                                # Check if hostname is already an IP
                                                if '.' in hostname and hostname.count('.') == 3:
                                                    try:
                                                        socket.inet_aton(hostname)
                                                        hop_info['ip'] = hostname
                                                    except:
                                                        pass
                                            
                                            # Extract timing info (Last column in mtr)
                                            if len(parts) >= 6:
                                                try:
                                                    last_time = float(parts[5])
                                                    hop_info['rtt'] = f"{last_time:.1f}ms"
                                                except (ValueError, IndexError):
                                                    pass
                                            
                                            hops.append(hop_info)
                            
                            return {
                                'success': True,
                                'ip_address': ip_address,
                                'hops': hops,
                                'hop_count': len(hops),
                                'raw_output': result.stdout,
                                'command_used': cmd[0],
                                'timestamp': datetime.utcnow().isoformat() + 'Z'
                            }
                except FileNotFoundError:
                    continue
            
            return {
                'success': False,
                'error': 'No traceroute command available (traceroute, tracert, or mtr)',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Traceroute operation timed out',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        except Exception as e:
            logger.error(f"Error running traceroute to {ip_address}: {e}")
            return {
                'success': False,
                'error': f'Traceroute error: {str(e)}',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
    
    def get_device_capabilities(self, device):
        """Determine what control capabilities a device has"""
        capabilities = []
        
        # All devices can be pinged
        capabilities.append('ping')
        
        # If MAC address is known, Wake-on-LAN is possible
        if device.mac_address:
            capabilities.append('wake_on_lan')
        
        # All devices can be port scanned
        capabilities.append('port_scan')
        
        # All devices can have info discovered
        capabilities.append('discover_info')
        
        # All devices can be traced
        capabilities.append('traceroute')
        
        # Add device-type specific capabilities
        if device.device_type:
            device_type = device.device_type.lower()
            
            if 'router' in device_type or 'gateway' in device_type:
                capabilities.extend(['web_interface', 'snmp'])
            elif 'computer' in device_type or 'server' in device_type:
                capabilities.extend(['ssh', 'rdp', 'web_interface'])
            elif 'printer' in device_type:
                capabilities.extend(['web_interface', 'snmp'])
            elif 'camera' in device_type:
                capabilities.extend(['web_interface', 'rtsp'])
        
        return capabilities

# Global device control service instance
device_control_service = DeviceControlService()