# HomeNetMon SSL/TLS Tunnel Support
import os
import ssl
import socket
import threading
import time
import json
import subprocess
import tempfile
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import logging

logger = logging.getLogger(__name__)

class SSLTunnelManager:
    """Manages SSL/TLS tunnels for secure remote access"""
    
    def __init__(self, config_dir='/etc/homenetmon/ssl'):
        self.config_dir = config_dir
        self.ssl_configs = {}
        self.active_tunnels = {}
        
        # Ensure config directory exists
        os.makedirs(config_dir, exist_ok=True)
        
        # Load existing configurations
        self._load_ssl_configs()
    
    def create_ssl_tunnel(self, tunnel_name, local_port, target_host, target_port, ssl_mode='server'):
        """Create a new SSL tunnel configuration"""
        logger.info(f"Creating SSL tunnel: {tunnel_name}")
        
        # Generate SSL certificates
        cert_data = self._generate_ssl_certificate(tunnel_name)
        
        # Create tunnel configuration
        tunnel_config = {
            'name': tunnel_name,
            'type': 'ssl',
            'local_port': local_port,
            'target_host': target_host,
            'target_port': target_port,
            'ssl_mode': ssl_mode,  # 'server' or 'client'
            'cert_file': cert_data['cert_file'],
            'key_file': cert_data['key_file'],
            'ca_file': cert_data['ca_file'],
            'created': datetime.utcnow().isoformat(),
            'active': False
        }
        
        # Save configuration
        tunnel_id = f"ssl_{tunnel_name}_{local_port}"
        self.ssl_configs[tunnel_id] = tunnel_config
        self._save_ssl_configs()
        
        return {
            'tunnel_id': tunnel_id,
            'config': tunnel_config
        }
    
    def _generate_ssl_certificate(self, tunnel_name):
        """Generate SSL certificate for tunnel"""
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "HomeNet"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HomeNetMon"),
            x509.NameAttribute(NameOID.COMMON_NAME, tunnel_name),
        ])
        
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName(tunnel_name),
                x509.IPAddress(socket.inet_aton("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Save certificate and key files
        cert_file = os.path.join(self.config_dir, f"{tunnel_name}_cert.pem")
        key_file = os.path.join(self.config_dir, f"{tunnel_name}_key.pem")
        ca_file = os.path.join(self.config_dir, f"{tunnel_name}_ca.pem")
        
        with open(cert_file, 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
        with open(key_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Use the same certificate as CA for self-signed
        with open(ca_file, 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
        # Set secure permissions
        os.chmod(key_file, 0o600)
        os.chmod(cert_file, 0o644)
        os.chmod(ca_file, 0o644)
        
        return {
            'cert_file': cert_file,
            'key_file': key_file,
            'ca_file': ca_file
        }
    
    def start_ssl_tunnel(self, tunnel_id):
        """Start an SSL tunnel"""
        if tunnel_id not in self.ssl_configs:
            raise ValueError("SSL tunnel not found")
        
        config = self.ssl_configs[tunnel_id]
        
        if config['active']:
            logger.warning(f"SSL tunnel {tunnel_id} is already active")
            return False
        
        try:
            if config['ssl_mode'] == 'server':
                tunnel_thread = threading.Thread(
                    target=self._run_ssl_server,
                    args=(tunnel_id, config),
                    daemon=True
                )
            else:
                tunnel_thread = threading.Thread(
                    target=self._run_ssl_client,
                    args=(tunnel_id, config),
                    daemon=True
                )
            
            tunnel_thread.start()
            
            # Give the tunnel a moment to start
            time.sleep(1)
            
            config['active'] = True
            self.active_tunnels[tunnel_id] = {
                'thread': tunnel_thread,
                'start_time': datetime.utcnow().isoformat(),
                'connections': 0
            }
            
            self._save_ssl_configs()
            
            logger.info(f"SSL tunnel started: {tunnel_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start SSL tunnel {tunnel_id}: {e}")
            return False
    
    def _run_ssl_server(self, tunnel_id, config):
        """Run SSL server tunnel"""
        try:
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(config['cert_file'], config['key_file'])
            
            # Create server socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', config['local_port']))
            server_socket.listen(5)
            
            logger.info(f"SSL server listening on port {config['local_port']}")
            
            while config['active']:
                try:
                    client_socket, addr = server_socket.accept()
                    logger.info(f"SSL connection from {addr}")
                    
                    # Wrap socket with SSL
                    ssl_socket = context.wrap_socket(client_socket, server_side=True)
                    
                    # Handle connection in separate thread
                    conn_thread = threading.Thread(
                        target=self._handle_ssl_connection,
                        args=(tunnel_id, ssl_socket, config),
                        daemon=True
                    )
                    conn_thread.start()
                    
                    # Update connection count
                    if tunnel_id in self.active_tunnels:
                        self.active_tunnels[tunnel_id]['connections'] += 1
                        
                except ssl.SSLError as e:
                    logger.warning(f"SSL error: {e}")
                except Exception as e:
                    logger.error(f"Error accepting SSL connection: {e}")
                    
        except Exception as e:
            logger.error(f"SSL server error: {e}")
        finally:
            if 'server_socket' in locals():
                server_socket.close()
            config['active'] = False
    
    def _handle_ssl_connection(self, tunnel_id, ssl_socket, config):
        """Handle individual SSL connection"""
        target_socket = None
        try:
            # Connect to target
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect((config['target_host'], config['target_port']))
            
            # Start bidirectional relay
            relay_threads = [
                threading.Thread(
                    target=self._relay_data,
                    args=(ssl_socket, target_socket),
                    daemon=True
                ),
                threading.Thread(
                    target=self._relay_data,
                    args=(target_socket, ssl_socket),
                    daemon=True
                )
            ]
            
            for thread in relay_threads:
                thread.start()
            
            for thread in relay_threads:
                thread.join()
                
        except Exception as e:
            logger.error(f"Error handling SSL connection: {e}")
        finally:
            ssl_socket.close()
            if target_socket:
                target_socket.close()
    
    def _relay_data(self, source_socket, dest_socket):
        """Relay data between sockets"""
        try:
            while True:
                data = source_socket.recv(4096)
                if not data:
                    break
                dest_socket.sendall(data)
        except Exception as e:
            logger.debug(f"Relay connection closed: {e}")
    
    def stop_ssl_tunnel(self, tunnel_id):
        """Stop an SSL tunnel"""
        if tunnel_id not in self.ssl_configs:
            raise ValueError("SSL tunnel not found")
        
        config = self.ssl_configs[tunnel_id]
        config['active'] = False
        
        if tunnel_id in self.active_tunnels:
            del self.active_tunnels[tunnel_id]
        
        self._save_ssl_configs()
        
        logger.info(f"SSL tunnel stopped: {tunnel_id}")
        return True
    
    def get_ssl_tunnel_status(self, tunnel_id):
        """Get SSL tunnel status"""
        if tunnel_id not in self.ssl_configs:
            return None
        
        config = self.ssl_configs[tunnel_id]
        tunnel_info = self.active_tunnels.get(tunnel_id, {})
        
        return {
            'tunnel_id': tunnel_id,
            'name': config['name'],
            'active': config['active'],
            'local_port': config['local_port'],
            'target': f"{config['target_host']}:{config['target_port']}",
            'ssl_mode': config['ssl_mode'],
            'start_time': tunnel_info.get('start_time'),
            'connections': tunnel_info.get('connections', 0)
        }
    
    def list_ssl_tunnels(self):
        """List all SSL tunnel configurations"""
        return {
            tunnel_id: {
                'name': config['name'],
                'type': config['type'],
                'local_port': config['local_port'],
                'target': f"{config['target_host']}:{config['target_port']}",
                'ssl_mode': config['ssl_mode'],
                'active': config['active'],
                'created': config['created']
            }
            for tunnel_id, config in self.ssl_configs.items()
        }
    
    def delete_ssl_tunnel(self, tunnel_id):
        """Delete an SSL tunnel configuration"""
        if tunnel_id not in self.ssl_configs:
            return False
        
        config = self.ssl_configs[tunnel_id]
        
        # Stop tunnel if active
        if config['active']:
            self.stop_ssl_tunnel(tunnel_id)
        
        # Remove certificate files
        for file_path in [config['cert_file'], config['key_file'], config['ca_file']]:
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Remove configuration
        del self.ssl_configs[tunnel_id]
        self._save_ssl_configs()
        
        logger.info(f"SSL tunnel deleted: {tunnel_id}")
        return True
    
    def _load_ssl_configs(self):
        """Load SSL configurations from disk"""
        config_file = os.path.join(self.config_dir, 'ssl_tunnels.json')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    self.ssl_configs = json.load(f)
                logger.info(f"Loaded {len(self.ssl_configs)} SSL tunnel configurations")
            except Exception as e:
                logger.error(f"Failed to load SSL configs: {e}")
                self.ssl_configs = {}
    
    def _save_ssl_configs(self):
        """Save SSL configurations to disk"""
        config_file = os.path.join(self.config_dir, 'ssl_tunnels.json')
        try:
            with open(config_file, 'w') as f:
                json.dump(self.ssl_configs, f, indent=2)
            os.chmod(config_file, 0o600)
        except Exception as e:
            logger.error(f"Failed to save SSL configs: {e}")


class OpenVPNManager:
    """Enhanced OpenVPN management with SSL/TLS support"""
    
    def __init__(self, config_dir='/etc/homenetmon/openvpn'):
        self.config_dir = config_dir
        self.openvpn_configs = {}
        self.active_servers = {}
        
        # Ensure config directory exists
        os.makedirs(config_dir, exist_ok=True)
        
        # Load existing configurations
        self._load_openvpn_configs()
    
    def create_openvpn_server(self, server_name, port, network, ca_cert, server_cert, server_key):
        """Create OpenVPN server configuration"""
        logger.info(f"Creating OpenVPN server: {server_name}")
        
        # Create server configuration
        config_file = os.path.join(self.config_dir, f"{server_name}.conf")
        
        server_config = f"""# OpenVPN Server Configuration for {server_name}
port {port}
proto udp
dev tun

# SSL/TLS configuration
ca {ca_cert}
cert {server_cert}
key {server_key}
dh {self._generate_dh_params(server_name)}

# Network configuration  
server {network} 255.255.255.0
ifconfig-pool-persist ipp.txt

# Push routes to clients
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Client connection settings
keepalive 10 120
tls-auth {self._generate_ta_key(server_name)} 0
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun

# Logging
status openvpn-status.log
log-append openvpn.log
verb 3
explicit-exit-notify 1

# Security
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
"""
        
        with open(config_file, 'w') as f:
            f.write(server_config)
        
        os.chmod(config_file, 0o600)
        
        # Save configuration metadata
        server_id = f"ovpn_{server_name}_{port}"
        self.openvpn_configs[server_id] = {
            'name': server_name,
            'type': 'openvpn',
            'port': port,
            'network': network,
            'config_file': config_file,
            'ca_cert': ca_cert,
            'server_cert': server_cert,
            'server_key': server_key,
            'created': datetime.utcnow().isoformat(),
            'active': False
        }
        
        self._save_openvpn_configs()
        
        return {
            'server_id': server_id,
            'config_file': config_file
        }
    
    def _generate_dh_params(self, server_name):
        """Generate Diffie-Hellman parameters"""
        dh_file = os.path.join(self.config_dir, f"{server_name}_dh2048.pem")
        
        if not os.path.exists(dh_file):
            try:
                # Generate DH params (this can take a while)
                subprocess.run([
                    'openssl', 'dhparam', '-out', dh_file, '2048'
                ], check=True, capture_output=True, shell=False)
                
                os.chmod(dh_file, 0o600)
                logger.info(f"Generated DH parameters: {dh_file}")
                
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to generate DH params: {e}")
                # Create a minimal DH params file for testing
                with open(dh_file, 'w') as f:
                    f.write("# Placeholder DH params - replace with real params in production\n")
        
        return dh_file
    
    def _generate_ta_key(self, server_name):
        """Generate TLS authentication key"""
        ta_file = os.path.join(self.config_dir, f"{server_name}_ta.key")
        
        if not os.path.exists(ta_file):
            try:
                subprocess.run([
                    'openvpn', '--genkey', '--secret', ta_file
                ], check=True, capture_output=True, shell=False)
                
                os.chmod(ta_file, 0o600)
                logger.info(f"Generated TLS auth key: {ta_file}")
                
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to generate TLS auth key: {e}")
                # Create a placeholder
                with open(ta_file, 'w') as f:
                    f.write("# Placeholder TLS auth key - replace with real key in production\n")
        
        return ta_file
    
    def start_openvpn_server(self, server_id):
        """Start OpenVPN server"""
        if server_id not in self.openvpn_configs:
            raise ValueError("OpenVPN server not found")
        
        config = self.openvpn_configs[server_id]
        
        if config['active']:
            logger.warning(f"OpenVPN server {server_id} is already active")
            return False
        
        try:
            # Start OpenVPN process
            process = subprocess.Popen([
                'openvpn',
                '--config', config['config_file'],
                '--daemon'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Give the process time to start
            time.sleep(2)
            
            # Check if process is still running
            if process.poll() is None:
                config['active'] = True
                self.active_servers[server_id] = {
                    'process': process,
                    'start_time': datetime.utcnow().isoformat(),
                    'pid': process.pid
                }
                
                self._save_openvpn_configs()
                
                logger.info(f"OpenVPN server started: {server_id}")
                return True
            else:
                stdout, stderr = process.communicate()
                logger.error(f"OpenVPN server failed to start: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start OpenVPN server {server_id}: {e}")
            return False
    
    def stop_openvpn_server(self, server_id):
        """Stop OpenVPN server"""
        if server_id not in self.openvpn_configs:
            raise ValueError("OpenVPN server not found")
        
        config = self.openvpn_configs[server_id]
        config['active'] = False
        
        if server_id in self.active_servers:
            server_info = self.active_servers[server_id]
            process = server_info['process']
            
            try:
                process.terminate()
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
            except Exception as e:
                logger.error(f"Error stopping OpenVPN server: {e}")
            
            del self.active_servers[server_id]
        
        self._save_openvpn_configs()
        
        logger.info(f"OpenVPN server stopped: {server_id}")
        return True
    
    def generate_client_config(self, server_id, client_name, client_cert, client_key):
        """Generate OpenVPN client configuration"""
        if server_id not in self.openvpn_configs:
            raise ValueError("OpenVPN server not found")
        
        config = self.openvpn_configs[server_id]
        
        # Read CA certificate
        with open(config['ca_cert'], 'r') as f:
            ca_content = f.read()
        
        # Read client certificate and key
        with open(client_cert, 'r') as f:
            cert_content = f.read()
        
        with open(client_key, 'r') as f:
            key_content = f.read()
        
        # Read TLS auth key
        ta_file = self._generate_ta_key(config['name'])
        with open(ta_file, 'r') as f:
            ta_content = f.read()
        
        client_config = f"""# OpenVPN Client Configuration for {client_name}
client
dev tun
proto udp
remote YOUR_SERVER_IP {config['port']}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-CBC
verb 3

<ca>
{ca_content}
</ca>

<cert>
{cert_content}
</cert>

<key>
{key_content}
</key>

<tls-auth>
{ta_content}
</tls-auth>
key-direction 1
"""
        
        return client_config
    
    def _load_openvpn_configs(self):
        """Load OpenVPN configurations from disk"""
        config_file = os.path.join(self.config_dir, 'openvpn_servers.json')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    self.openvpn_configs = json.load(f)
                logger.info(f"Loaded {len(self.openvpn_configs)} OpenVPN server configurations")
            except Exception as e:
                logger.error(f"Failed to load OpenVPN configs: {e}")
                self.openvpn_configs = {}
    
    def _save_openvpn_configs(self):
        """Save OpenVPN configurations to disk"""
        config_file = os.path.join(self.config_dir, 'openvpn_servers.json')
        try:
            with open(config_file, 'w') as f:
                json.dump(self.openvpn_configs, f, indent=2)
            os.chmod(config_file, 0o600)
        except Exception as e:
            logger.error(f"Failed to save OpenVPN configs: {e}")


# Initialize global managers
ssl_tunnel_manager = None
openvpn_manager = None

def init_ssl_managers(ssl_config_dir=None, openvpn_config_dir=None):
    """Initialize global SSL and OpenVPN managers"""
    global ssl_tunnel_manager, openvpn_manager
    
    if ssl_config_dir is None:
        ssl_config_dir = os.getenv('HOMENETMON_SSL_CONFIG', '/etc/homenetmon/ssl')
    
    if openvpn_config_dir is None:
        openvpn_config_dir = os.getenv('HOMENETMON_OPENVPN_CONFIG', '/etc/homenetmon/openvpn')
    
    ssl_tunnel_manager = SSLTunnelManager(ssl_config_dir)
    openvpn_manager = OpenVPNManager(openvpn_config_dir)
    
    return ssl_tunnel_manager, openvpn_manager

def get_ssl_tunnel_manager():
    """Get the global SSL tunnel manager instance"""
    global ssl_tunnel_manager
    if ssl_tunnel_manager is None:
        init_ssl_managers()
    return ssl_tunnel_manager

def get_openvpn_manager():
    """Get the global OpenVPN manager instance"""
    global openvpn_manager
    if openvpn_manager is None:
        init_ssl_managers()
    return openvpn_manager