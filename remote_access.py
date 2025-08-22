# HomeNetMon Secure Remote Access Module
import os
import json
import subprocess
import tempfile
import secrets
import hashlib
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import NameOID
from cryptography import x509
import base64
import socket
import threading
import time
import logging
from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecureTunnelManager:
    """Manages secure tunnels for remote access to HomeNetMon"""
    
    def __init__(self, config_dir='/etc/homenetmon/remote'):
        self.config_dir = config_dir
        self.tunnels = {}
        self.active_connections = {}
        self.certificates = {}
        
        # Ensure config directory exists
        os.makedirs(config_dir, exist_ok=True)
        
        # Initialize certificate authority
        self.ca_key, self.ca_cert = self._load_or_create_ca()
        
        # Load existing tunnel configurations
        self._load_tunnel_configs()
        
    def _load_or_create_ca(self):
        """Load existing CA or create new certificate authority"""
        ca_key_path = os.path.join(self.config_dir, 'ca-key.pem')
        ca_cert_path = os.path.join(self.config_dir, 'ca-cert.pem')
        
        if os.path.exists(ca_key_path) and os.path.exists(ca_cert_path):
            # Load existing CA
            with open(ca_key_path, 'rb') as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            logger.info("Loaded existing certificate authority")
            return ca_key, ca_cert
        else:
            # Create new CA
            return self._create_certificate_authority()
    
    def _create_certificate_authority(self):
        """Create a new certificate authority for HomeNetMon"""
        logger.info("Creating new certificate authority for HomeNetMon")
        
        # Generate CA private key
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        
        # Create CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "HomeNet"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HomeNetMon"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Remote Access"),
            x509.NameAttribute(NameOID.COMMON_NAME, "HomeNetMon Certificate Authority"),
        ])
        
        ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(ca_key, hashes.SHA256())
        
        # Save CA key and certificate
        ca_key_path = os.path.join(self.config_dir, 'ca-key.pem')
        ca_cert_path = os.path.join(self.config_dir, 'ca-cert.pem')
        
        with open(ca_key_path, 'wb') as f:
            f.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(ca_cert_path, 'wb') as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        
        # Set proper permissions
        os.chmod(ca_key_path, 0o600)
        os.chmod(ca_cert_path, 0o644)
        
        logger.info("Certificate authority created successfully")
        return ca_key, ca_cert
    
    def create_client_certificate(self, client_name, email=None, valid_days=365):
        """Create a client certificate for remote access"""
        logger.info(f"Creating client certificate for: {client_name}")
        
        # Generate client private key
        client_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create client certificate
        subject_components = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "HomeNet"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HomeNetMon"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Remote Client"),
            x509.NameAttribute(NameOID.COMMON_NAME, client_name),
        ]
        
        if email:
            subject_components.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
        
        subject = x509.Name(subject_components)
        
        client_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            client_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=valid_days)
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        ).sign(self.ca_key, hashes.SHA256())
        
        # Store certificate info
        cert_id = hashlib.sha256(client_name.encode()).hexdigest()[:16]
        self.certificates[cert_id] = {
            'name': client_name,
            'email': email,
            'created': datetime.utcnow().isoformat(),
            'expires': (datetime.utcnow() + timedelta(days=valid_days)).isoformat(),
            'serial': str(client_cert.serial_number),
            'revoked': False
        }
        
        self._save_certificates()
        
        # Return certificate data
        return {
            'cert_id': cert_id,
            'private_key': client_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8'),
            'certificate': client_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            'ca_certificate': self.ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        }
    
    def revoke_certificate(self, cert_id):
        """Revoke a client certificate"""
        if cert_id in self.certificates:
            self.certificates[cert_id]['revoked'] = True
            self.certificates[cert_id]['revoked_at'] = datetime.utcnow().isoformat()
            self._save_certificates()
            logger.info(f"Certificate {cert_id} revoked")
            return True
        return False
    
    def create_secure_tunnel(self, tunnel_name, tunnel_type='wireguard', port_range=(51820, 51830)):
        """Create a new secure tunnel configuration"""
        logger.info(f"Creating secure tunnel: {tunnel_name} ({tunnel_type})")
        
        if tunnel_type == 'wireguard':
            return self._create_wireguard_tunnel(tunnel_name, port_range)
        elif tunnel_type == 'openvpn':
            return self._create_openvpn_tunnel(tunnel_name, port_range)
        else:
            raise ValueError(f"Unsupported tunnel type: {tunnel_type}")
    
    def _create_wireguard_tunnel(self, tunnel_name, port_range):
        """Create WireGuard tunnel configuration"""
        
        # Find available port
        port = self._find_available_port(port_range)
        if not port:
            raise RuntimeError("No available ports in range")
        
        # Generate WireGuard keys
        try:
            # Generate private key
            private_key = subprocess.check_output(
                ['wg', 'genkey'], 
                stderr=subprocess.DEVNULL
            ).decode().strip()
            
            # Generate public key from private key
            public_key = subprocess.check_output(
                ['wg', 'pubkey'],
                input=private_key.encode(),
                stderr=subprocess.DEVNULL
            ).decode().strip()
            
        except subprocess.CalledProcessError:
            # Fallback: generate keys using Python crypto
            private_key = base64.b64encode(os.urandom(32)).decode()
            # For demo purposes - in production, implement proper WireGuard key derivation
            public_key = base64.b64encode(hashlib.sha256(private_key.encode()).digest()).decode()
        
        # Create tunnel configuration
        tunnel_config = {
            'name': tunnel_name,
            'type': 'wireguard',
            'port': port,
            'private_key': private_key,
            'public_key': public_key,
            'network': f'10.{200 + len(self.tunnels)}.0.0/24',
            'endpoint': self._get_external_ip(),
            'created': datetime.utcnow().isoformat(),
            'active': False,
            'clients': {}
        }
        
        # Save configuration
        tunnel_id = hashlib.sha256(tunnel_name.encode()).hexdigest()[:16]
        self.tunnels[tunnel_id] = tunnel_config
        self._save_tunnel_configs()
        
        return {
            'tunnel_id': tunnel_id,
            'config': tunnel_config
        }
    
    def _create_openvpn_tunnel(self, tunnel_name, port_range):
        """Create OpenVPN tunnel configuration"""
        
        # Find available port
        port = self._find_available_port(port_range)
        if not port:
            raise RuntimeError("No available ports in range")
        
        # Generate OpenVPN server configuration
        tunnel_config = {
            'name': tunnel_name,
            'type': 'openvpn',
            'port': port,
            'network': f'10.{200 + len(self.tunnels)}.0.0',
            'netmask': '255.255.255.0',
            'endpoint': self._get_external_ip(),
            'created': datetime.utcnow().isoformat(),
            'active': False,
            'clients': {}
        }
        
        # Save configuration
        tunnel_id = hashlib.sha256(tunnel_name.encode()).hexdigest()[:16]
        self.tunnels[tunnel_id] = tunnel_config
        self._save_tunnel_configs()
        
        return {
            'tunnel_id': tunnel_id,
            'config': tunnel_config
        }
    
    def add_tunnel_client(self, tunnel_id, client_name, client_ip=None):
        """Add a client to a tunnel"""
        if tunnel_id not in self.tunnels:
            raise ValueError("Tunnel not found")
        
        tunnel = self.tunnels[tunnel_id]
        
        if client_ip is None:
            # Auto-assign IP from tunnel network
            network_base = tunnel['network'].split('/')[0].rsplit('.', 1)[0]
            client_num = len(tunnel['clients']) + 2  # Start from .2
            client_ip = f"{network_base}.{client_num}"
        
        # Generate client-specific keys for WireGuard
        if tunnel['type'] == 'wireguard':
            try:
                client_private = subprocess.check_output(
                    ['wg', 'genkey'],
                    stderr=subprocess.DEVNULL
                ).decode().strip()
                
                client_public = subprocess.check_output(
                    ['wg', 'pubkey'],
                    input=client_private.encode(),
                    stderr=subprocess.DEVNULL
                ).decode().strip()
            except subprocess.CalledProcessError:
                # Fallback key generation
                client_private = base64.b64encode(os.urandom(32)).decode()
                client_public = base64.b64encode(hashlib.sha256(client_private.encode()).digest()).decode()
        else:
            client_private = None
            client_public = None
        
        # Add client to tunnel
        client_id = hashlib.sha256(f"{tunnel_id}-{client_name}".encode()).hexdigest()[:16]
        tunnel['clients'][client_id] = {
            'name': client_name,
            'ip': client_ip,
            'private_key': client_private,
            'public_key': client_public,
            'added': datetime.utcnow().isoformat(),
            'last_seen': None,
            'bytes_sent': 0,
            'bytes_received': 0
        }
        
        self._save_tunnel_configs()
        
        return {
            'client_id': client_id,
            'config': self._generate_client_config(tunnel_id, client_id)
        }
    
    def _generate_client_config(self, tunnel_id, client_id):
        """Generate client configuration file"""
        tunnel = self.tunnels[tunnel_id]
        client = tunnel['clients'][client_id]
        
        if tunnel['type'] == 'wireguard':
            config = f"""[Interface]
PrivateKey = {client['private_key']}
Address = {client['ip']}/24
DNS = {tunnel['network'].split('/')[0].rsplit('.', 1)[0]}.1

[Peer]
PublicKey = {tunnel['public_key']}
Endpoint = {tunnel['endpoint']}:{tunnel['port']}
AllowedIPs = {tunnel['network']}
PersistentKeepalive = 25
"""
        elif tunnel['type'] == 'openvpn':
            config = f"""client
dev tun
proto udp
remote {tunnel['endpoint']} {tunnel['port']}
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
cipher AES-256-CBC
verb 3
"""
        
        return config
    
    def start_tunnel(self, tunnel_id):
        """Start a tunnel server"""
        if tunnel_id not in self.tunnels:
            raise ValueError("Tunnel not found")
        
        tunnel = self.tunnels[tunnel_id]
        
        if tunnel['type'] == 'wireguard':
            return self._start_wireguard_tunnel(tunnel_id)
        elif tunnel['type'] == 'openvpn':
            return self._start_openvpn_tunnel(tunnel_id)
        
        return False
    
    def _start_wireguard_tunnel(self, tunnel_id):
        """Start WireGuard tunnel"""
        tunnel = self.tunnels[tunnel_id]
        interface_name = f"wg-{tunnel_id[:8]}"
        
        try:
            # Create WireGuard interface configuration
            config_path = os.path.join(self.config_dir, f"{interface_name}.conf")
            
            with open(config_path, 'w') as f:
                f.write(f"""[Interface]
PrivateKey = {tunnel['private_key']}
Address = {tunnel['network'].split('/')[0].rsplit('.', 1)[0]}.1/24
ListenPort = {tunnel['port']}
SaveConfig = true

""")
                # Add peers (clients)
                for client in tunnel['clients'].values():
                    f.write(f"""[Peer]
PublicKey = {client['public_key']}
AllowedIPs = {client['ip']}/32

""")
            
            # Set proper permissions
            os.chmod(config_path, 0o600)
            
            # Start WireGuard interface
            subprocess.run(['wg-quick', 'up', config_path], check=True)
            
            tunnel['active'] = True
            tunnel['interface'] = interface_name
            self._save_tunnel_configs()
            
            logger.info(f"WireGuard tunnel {tunnel_id} started on interface {interface_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start WireGuard tunnel: {e}")
            return False
        except Exception as e:
            logger.error(f"Error starting WireGuard tunnel: {e}")
            return False
    
    def stop_tunnel(self, tunnel_id):
        """Stop a tunnel server"""
        if tunnel_id not in self.tunnels:
            raise ValueError("Tunnel not found")
        
        tunnel = self.tunnels[tunnel_id]
        
        if tunnel['type'] == 'wireguard':
            return self._stop_wireguard_tunnel(tunnel_id)
        elif tunnel['type'] == 'openvpn':
            return self._stop_openvpn_tunnel(tunnel_id)
        
        return False
    
    def _stop_wireguard_tunnel(self, tunnel_id):
        """Stop WireGuard tunnel"""
        tunnel = self.tunnels[tunnel_id]
        interface_name = tunnel.get('interface', f"wg-{tunnel_id[:8]}")
        
        try:
            config_path = os.path.join(self.config_dir, f"{interface_name}.conf")
            subprocess.run(['wg-quick', 'down', config_path], check=False)
            
            tunnel['active'] = False
            self._save_tunnel_configs()
            
            logger.info(f"WireGuard tunnel {tunnel_id} stopped")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping WireGuard tunnel: {e}")
            return False
    
    def get_tunnel_status(self, tunnel_id):
        """Get tunnel status and statistics"""
        if tunnel_id not in self.tunnels:
            return None
        
        tunnel = self.tunnels[tunnel_id]
        
        if tunnel['type'] == 'wireguard' and tunnel.get('active'):
            return self._get_wireguard_status(tunnel_id)
        
        return {
            'tunnel_id': tunnel_id,
            'active': tunnel.get('active', False),
            'clients': len(tunnel['clients']),
            'type': tunnel['type']
        }
    
    def _get_wireguard_status(self, tunnel_id):
        """Get WireGuard tunnel status"""
        tunnel = self.tunnels[tunnel_id]
        interface_name = tunnel.get('interface', f"wg-{tunnel_id[:8]}")
        
        try:
            # Get WireGuard status
            output = subprocess.check_output(
                ['wg', 'show', interface_name],
                stderr=subprocess.DEVNULL
            ).decode()
            
            # Parse peer information
            peers = {}
            current_peer = None
            
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('peer:'):
                    current_peer = line.split(': ')[1]
                    peers[current_peer] = {}
                elif current_peer and ':' in line:
                    key, value = line.split(': ', 1)
                    peers[current_peer][key.strip()] = value.strip()
            
            return {
                'tunnel_id': tunnel_id,
                'active': True,
                'interface': interface_name,
                'clients': len(tunnel['clients']),
                'peers': peers,
                'type': 'wireguard'
            }
            
        except subprocess.CalledProcessError:
            return {
                'tunnel_id': tunnel_id,
                'active': False,
                'error': 'Interface not found',
                'type': 'wireguard'
            }
    
    def _find_available_port(self, port_range):
        """Find an available port in the given range"""
        start_port, end_port = port_range
        
        for port in range(start_port, end_port + 1):
            if self._is_port_available(port):
                return port
        return None
    
    def _is_port_available(self, port):
        """Check if a port is available"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(('', port))
                return True
        except OSError:
            return False
    
    def _get_external_ip(self):
        """Get external IP address"""
        try:
            # Try to get external IP
            import urllib.request
            response = urllib.request.urlopen('https://ifconfig.me', timeout=5)
            return response.read().decode().strip()
        except:
            # Fallback to local IP
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.connect(('8.8.8.8', 80))
                    return sock.getsockname()[0]
            except:
                return '127.0.0.1'
    
    def _load_tunnel_configs(self):
        """Load tunnel configurations from disk"""
        config_file = os.path.join(self.config_dir, 'tunnels.json')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    self.tunnels = json.load(f)
                logger.info(f"Loaded {len(self.tunnels)} tunnel configurations")
            except Exception as e:
                logger.error(f"Failed to load tunnel configs: {e}")
                self.tunnels = {}
    
    def _save_tunnel_configs(self):
        """Save tunnel configurations to disk"""
        config_file = os.path.join(self.config_dir, 'tunnels.json')
        try:
            with open(config_file, 'w') as f:
                json.dump(self.tunnels, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save tunnel configs: {e}")
    
    def _save_certificates(self):
        """Save certificate registry to disk"""
        cert_file = os.path.join(self.config_dir, 'certificates.json')
        try:
            with open(cert_file, 'w') as f:
                json.dump(self.certificates, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save certificates: {e}")
    
    def list_tunnels(self):
        """List all configured tunnels"""
        return {
            tunnel_id: {
                'name': config['name'],
                'type': config['type'],
                'port': config.get('port'),
                'active': config.get('active', False),
                'clients': len(config['clients']),
                'created': config['created']
            }
            for tunnel_id, config in self.tunnels.items()
        }
    
    def list_certificates(self):
        """List all certificates"""
        return self.certificates
    
    def delete_tunnel(self, tunnel_id):
        """Delete a tunnel configuration"""
        if tunnel_id in self.tunnels:
            # Stop tunnel if active
            if self.tunnels[tunnel_id].get('active'):
                self.stop_tunnel(tunnel_id)
            
            # Remove configuration files
            tunnel = self.tunnels[tunnel_id]
            if tunnel['type'] == 'wireguard':
                interface_name = tunnel.get('interface', f"wg-{tunnel_id[:8]}")
                config_path = os.path.join(self.config_dir, f"{interface_name}.conf")
                if os.path.exists(config_path):
                    os.remove(config_path)
            
            # Remove from memory and save
            del self.tunnels[tunnel_id]
            self._save_tunnel_configs()
            
            logger.info(f"Tunnel {tunnel_id} deleted")
            return True
        
        return False


# Initialize global tunnel manager
tunnel_manager = None

def init_tunnel_manager(config_dir=None):
    """Initialize the global tunnel manager"""
    global tunnel_manager
    if config_dir is None:
        config_dir = os.getenv('HOMENETMON_REMOTE_CONFIG', '/etc/homenetmon/remote')
    
    tunnel_manager = SecureTunnelManager(config_dir)
    return tunnel_manager

def get_tunnel_manager():
    """Get the global tunnel manager instance"""
    global tunnel_manager
    if tunnel_manager is None:
        tunnel_manager = init_tunnel_manager()
    return tunnel_manager