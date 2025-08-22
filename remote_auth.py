# HomeNetMon Remote Authentication System
import os
import json
import secrets
import hashlib
import time
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import qrcode
import io
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyotp
import jwt
from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RemoteAuthManager:
    """Manages remote authentication for HomeNetMon access"""
    
    def __init__(self, config_dir='/etc/homenetmon/auth'):
        self.config_dir = config_dir
        self.users = {}
        self.sessions = {}
        self.api_keys = {}
        self.mfa_secrets = {}
        self.login_attempts = {}
        
        # Security settings
        self.max_login_attempts = 5
        self.lockout_duration = 300  # 5 minutes
        self.session_timeout = 3600  # 1 hour
        self.api_key_lifetime = 86400 * 30  # 30 days
        
        # Ensure config directory exists
        os.makedirs(config_dir, exist_ok=True)
        
        # Load existing configurations
        self._load_auth_configs()
        
        # Generate JWT secret if not exists
        self.jwt_secret = self._load_or_generate_jwt_secret()
    
    def _load_auth_configs(self):
        """Load authentication configurations from disk"""
        users_file = os.path.join(self.config_dir, 'users.json')
        sessions_file = os.path.join(self.config_dir, 'sessions.json')
        api_keys_file = os.path.join(self.config_dir, 'api_keys.json')
        mfa_file = os.path.join(self.config_dir, 'mfa_secrets.json')
        
        for file_path, target_dict in [
            (users_file, self.users),
            (sessions_file, self.sessions), 
            (api_keys_file, self.api_keys),
            (mfa_file, self.mfa_secrets)
        ]:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        target_dict.update(data)
                except Exception as e:
                    logger.error(f"Failed to load {file_path}: {e}")
    
    def _save_auth_configs(self):
        """Save authentication configurations to disk"""
        configs = [
            ('users.json', self.users),
            ('sessions.json', self.sessions),
            ('api_keys.json', self.api_keys),
            ('mfa_secrets.json', self.mfa_secrets)
        ]
        
        for filename, data in configs:
            file_path = os.path.join(self.config_dir, filename)
            try:
                with open(file_path, 'w') as f:
                    json.dump(data, f, indent=2)
                os.chmod(file_path, 0o600)  # Secure permissions
            except Exception as e:
                logger.error(f"Failed to save {file_path}: {e}")
    
    def _load_or_generate_jwt_secret(self):
        """Load existing JWT secret or generate new one"""
        secret_file = os.path.join(self.config_dir, 'jwt_secret.key')
        
        if os.path.exists(secret_file):
            with open(secret_file, 'r') as f:
                return f.read().strip()
        else:
            secret = secrets.token_urlsafe(64)
            with open(secret_file, 'w') as f:
                f.write(secret)
            os.chmod(secret_file, 0o600)
            return secret
    
    def create_user(self, username, password, email, role='user', require_mfa=True):
        """Create a new user account"""
        if username in self.users:
            raise ValueError("Username already exists")
        
        # Validate password strength
        if not self._validate_password_strength(password):
            raise ValueError("Password does not meet strength requirements")
        
        # Generate user ID
        user_id = hashlib.sha256(username.encode()).hexdigest()[:16]
        
        # Create user record
        user_data = {
            'user_id': user_id,
            'username': username,
            'password_hash': generate_password_hash(password),
            'email': email,
            'role': role,
            'created': datetime.utcnow().isoformat(),
            'last_login': None,
            'failed_attempts': 0,
            'locked_until': None,
            'mfa_enabled': require_mfa,
            'mfa_verified': False,
            'email_verified': False,
            'active': True
        }
        
        self.users[user_id] = user_data
        
        # Setup MFA if required
        mfa_secret = None
        if require_mfa:
            mfa_secret = self._setup_mfa(user_id, username)
        
        self._save_auth_configs()
        
        logger.info(f"User created: {username} ({user_id})")
        
        return {
            'user_id': user_id,
            'mfa_secret': mfa_secret,
            'backup_codes': self._generate_backup_codes(user_id) if require_mfa else None
        }
    
    def _validate_password_strength(self, password):
        """Validate password meets security requirements"""
        if len(password) < 12:
            return False
        
        checks = [
            any(c.islower() for c in password),  # lowercase
            any(c.isupper() for c in password),  # uppercase  
            any(c.isdigit() for c in password),  # digit
            any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)  # special char
        ]
        
        return sum(checks) >= 3
    
    def _setup_mfa(self, user_id, username):
        """Setup multi-factor authentication for user"""
        secret = pyotp.random_base32()
        
        self.mfa_secrets[user_id] = {
            'secret': secret,
            'created': datetime.utcnow().isoformat(),
            'backup_codes': self._generate_backup_codes(user_id)
        }
        
        return secret
    
    def _generate_backup_codes(self, user_id):
        """Generate backup codes for MFA"""
        codes = [secrets.token_hex(4).upper() for _ in range(10)]
        
        if user_id not in self.mfa_secrets:
            self.mfa_secrets[user_id] = {}
        
        self.mfa_secrets[user_id]['backup_codes'] = [
            generate_password_hash(code) for code in codes
        ]
        
        return codes
    
    def authenticate_user(self, username, password, mfa_token=None, remember_me=False):
        """Authenticate user with password and optional MFA"""
        
        # Find user by username
        user = None
        user_id = None
        for uid, user_data in self.users.items():
            if user_data['username'] == username:
                user = user_data
                user_id = uid
                break
        
        if not user:
            logger.warning(f"Authentication failed: user not found - {username}")
            return None
        
        # Check if account is locked
        if self._is_account_locked(user_id):
            logger.warning(f"Authentication failed: account locked - {username}")
            return None
        
        # Check password
        if not check_password_hash(user['password_hash'], password):
            self._record_failed_attempt(user_id)
            logger.warning(f"Authentication failed: invalid password - {username}")
            return None
        
        # Check MFA if enabled
        if user['mfa_enabled']:
            if not mfa_token:
                return {'requires_mfa': True, 'user_id': user_id}
            
            if not self._verify_mfa_token(user_id, mfa_token):
                self._record_failed_attempt(user_id)
                logger.warning(f"Authentication failed: invalid MFA token - {username}")
                return None
        
        # Successful authentication
        self._clear_failed_attempts(user_id)
        
        # Update last login
        user['last_login'] = datetime.utcnow().isoformat()
        
        # Create session
        session_data = self._create_session(user_id, remember_me)
        
        self._save_auth_configs()
        
        logger.info(f"User authenticated successfully: {username}")
        
        return {
            'user_id': user_id,
            'username': username,
            'role': user['role'],
            'session_token': session_data['token'],
            'expires_at': session_data['expires_at']
        }
    
    def _verify_mfa_token(self, user_id, token):
        """Verify MFA token (TOTP or backup code)"""
        if user_id not in self.mfa_secrets:
            return False
        
        mfa_data = self.mfa_secrets[user_id]
        
        # Try TOTP verification
        totp = pyotp.TOTP(mfa_data['secret'])
        if totp.verify(token, valid_window=1):
            return True
        
        # Try backup codes
        backup_codes = mfa_data.get('backup_codes', [])
        for i, hashed_code in enumerate(backup_codes):
            if check_password_hash(hashed_code, token.upper()):
                # Remove used backup code
                backup_codes.pop(i)
                self._save_auth_configs()
                return True
        
        return False
    
    def _is_account_locked(self, user_id):
        """Check if account is locked due to failed attempts"""
        if user_id not in self.login_attempts:
            return False
        
        attempts = self.login_attempts[user_id]
        
        if attempts['count'] >= self.max_login_attempts:
            if attempts['locked_until'] > time.time():
                return True
            else:
                # Lock period expired, clear attempts
                del self.login_attempts[user_id]
        
        return False
    
    def _record_failed_attempt(self, user_id):
        """Record a failed login attempt"""
        now = time.time()
        
        if user_id not in self.login_attempts:
            self.login_attempts[user_id] = {'count': 0, 'locked_until': 0}
        
        self.login_attempts[user_id]['count'] += 1
        
        if self.login_attempts[user_id]['count'] >= self.max_login_attempts:
            self.login_attempts[user_id]['locked_until'] = now + self.lockout_duration
            logger.warning(f"Account locked due to failed attempts: {user_id}")
    
    def _clear_failed_attempts(self, user_id):
        """Clear failed login attempts"""
        if user_id in self.login_attempts:
            del self.login_attempts[user_id]
    
    def _create_session(self, user_id, remember_me=False):
        """Create a new user session"""
        session_id = secrets.token_urlsafe(32)
        
        # Set expiration
        if remember_me:
            expires_at = datetime.utcnow() + timedelta(days=30)
        else:
            expires_at = datetime.utcnow() + timedelta(seconds=self.session_timeout)
        
        session_data = {
            'user_id': user_id,
            'created': datetime.utcnow().isoformat(),
            'expires_at': expires_at.isoformat(),
            'last_activity': datetime.utcnow().isoformat(),
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.headers.get('User-Agent') if request else None
        }
        
        self.sessions[session_id] = session_data
        
        # Clean up expired sessions
        self._cleanup_expired_sessions()
        
        return {
            'token': session_id,
            'expires_at': expires_at.isoformat()
        }
    
    def validate_session(self, session_token):
        """Validate and refresh session"""
        if not session_token or session_token not in self.sessions:
            return None
        
        session_data = self.sessions[session_token]
        expires_at = datetime.fromisoformat(session_data['expires_at'])
        
        if datetime.utcnow() > expires_at:
            # Session expired
            del self.sessions[session_token]
            return None
        
        # Update last activity
        session_data['last_activity'] = datetime.utcnow().isoformat()
        
        # Get user data
        user_id = session_data['user_id']
        if user_id not in self.users:
            del self.sessions[session_token]
            return None
        
        user = self.users[user_id]
        
        return {
            'user_id': user_id,
            'username': user['username'],
            'role': user['role'],
            'session_token': session_token
        }
    
    def logout_user(self, session_token):
        """Logout user by invalidating session"""
        if session_token in self.sessions:
            user_id = self.sessions[session_token]['user_id']
            del self.sessions[session_token]
            self._save_auth_configs()
            logger.info(f"User logged out: {user_id}")
            return True
        return False
    
    def create_api_key(self, user_id, name, permissions=None, expires_days=30):
        """Create API key for programmatic access"""
        if user_id not in self.users:
            raise ValueError("User not found")
        
        api_key = f"hnm_{secrets.token_urlsafe(32)}"
        key_id = hashlib.sha256(api_key.encode()).hexdigest()[:16]
        
        key_data = {
            'key_id': key_id,
            'user_id': user_id,
            'name': name,
            'key_hash': hashlib.sha256(api_key.encode()).hexdigest(),
            'permissions': permissions or ['read'],
            'created': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(days=expires_days)).isoformat(),
            'last_used': None,
            'active': True
        }
        
        self.api_keys[key_id] = key_data
        self._save_auth_configs()
        
        logger.info(f"API key created: {name} for user {user_id}")
        
        return api_key
    
    def validate_api_key(self, api_key):
        """Validate API key"""
        if not api_key or not api_key.startswith('hnm_'):
            return None
        
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        for key_id, key_data in self.api_keys.items():
            if key_data['key_hash'] == key_hash:
                # Check if expired
                expires_at = datetime.fromisoformat(key_data['expires_at'])
                if datetime.utcnow() > expires_at:
                    return None
                
                # Update last used
                key_data['last_used'] = datetime.utcnow().isoformat()
                
                # Get user data
                user_id = key_data['user_id']
                if user_id not in self.users:
                    return None
                
                user = self.users[user_id]
                
                return {
                    'user_id': user_id,
                    'username': user['username'],
                    'role': user['role'],
                    'key_id': key_id,
                    'permissions': key_data['permissions']
                }
        
        return None
    
    def revoke_api_key(self, key_id):
        """Revoke an API key"""
        if key_id in self.api_keys:
            self.api_keys[key_id]['active'] = False
            self._save_auth_configs()
            logger.info(f"API key revoked: {key_id}")
            return True
        return False
    
    def generate_mfa_qr_code(self, user_id):
        """Generate QR code for MFA setup"""
        if user_id not in self.users or user_id not in self.mfa_secrets:
            return None
        
        user = self.users[user_id]
        secret = self.mfa_secrets[user_id]['secret']
        
        # Create TOTP URI
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user['email'],
            issuer_name="HomeNetMon"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for web display
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_str = base64.b64encode(img_buffer.getvalue()).decode()
        
        return {
            'qr_code': f"data:image/png;base64,{img_str}",
            'secret': secret,
            'uri': totp_uri
        }
    
    def _cleanup_expired_sessions(self):
        """Remove expired sessions"""
        now = datetime.utcnow()
        expired_sessions = []
        
        for session_id, session_data in self.sessions.items():
            expires_at = datetime.fromisoformat(session_data['expires_at'])
            if now > expires_at:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
    
    def get_user_sessions(self, user_id):
        """Get active sessions for user"""
        user_sessions = []
        
        for session_id, session_data in self.sessions.items():
            if session_data['user_id'] == user_id:
                user_sessions.append({
                    'session_id': session_id,
                    'created': session_data['created'],
                    'last_activity': session_data['last_activity'],
                    'ip_address': session_data.get('ip_address'),
                    'user_agent': session_data.get('user_agent')
                })
        
        return user_sessions
    
    def get_user_api_keys(self, user_id):
        """Get API keys for user"""
        user_keys = []
        
        for key_id, key_data in self.api_keys.items():
            if key_data['user_id'] == user_id and key_data['active']:
                user_keys.append({
                    'key_id': key_id,
                    'name': key_data['name'],
                    'permissions': key_data['permissions'],
                    'created': key_data['created'],
                    'last_used': key_data.get('last_used'),
                    'expires_at': key_data['expires_at']
                })
        
        return user_keys
    
    def update_user_password(self, user_id, current_password, new_password):
        """Update user password"""
        if user_id not in self.users:
            return False
        
        user = self.users[user_id]
        
        # Verify current password
        if not check_password_hash(user['password_hash'], current_password):
            return False
        
        # Validate new password
        if not self._validate_password_strength(new_password):
            raise ValueError("Password does not meet strength requirements")
        
        # Update password
        user['password_hash'] = generate_password_hash(new_password)
        user['password_changed'] = datetime.utcnow().isoformat()
        
        self._save_auth_configs()
        
        logger.info(f"Password updated for user: {user_id}")
        return True
    
    def enable_mfa(self, user_id):
        """Enable MFA for user"""
        if user_id not in self.users:
            return None
        
        if user_id not in self.mfa_secrets:
            secret = self._setup_mfa(user_id, self.users[user_id]['username'])
        else:
            secret = self.mfa_secrets[user_id]['secret']
        
        self.users[user_id]['mfa_enabled'] = True
        self._save_auth_configs()
        
        return secret
    
    def disable_mfa(self, user_id, current_password):
        """Disable MFA for user (requires password confirmation)"""
        if user_id not in self.users:
            return False
        
        user = self.users[user_id]
        
        # Verify current password
        if not check_password_hash(user['password_hash'], current_password):
            return False
        
        user['mfa_enabled'] = False
        if user_id in self.mfa_secrets:
            del self.mfa_secrets[user_id]
        
        self._save_auth_configs()
        
        logger.info(f"MFA disabled for user: {user_id}")
        return True


# Initialize global auth manager
auth_manager = None

def init_auth_manager(config_dir=None):
    """Initialize the global auth manager"""
    global auth_manager
    if config_dir is None:
        config_dir = os.getenv('HOMENETMON_AUTH_CONFIG', '/etc/homenetmon/auth')
    
    auth_manager = RemoteAuthManager(config_dir)
    return auth_manager

def get_auth_manager():
    """Get the global auth manager instance"""
    global auth_manager
    if auth_manager is None:
        auth_manager = init_auth_manager()
    return auth_manager

# Flask decorators for authentication
def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = get_auth_manager()
        
        # Check session token
        session_token = session.get('session_token') or request.headers.get('Authorization')
        if session_token and session_token.startswith('Bearer '):
            session_token = session_token[7:]
        
        user_data = None
        if session_token:
            user_data = auth.validate_session(session_token)
        
        # Check API key if no session
        if not user_data:
            api_key = request.headers.get('X-API-Key')
            if api_key:
                user_data = auth.validate_api_key(api_key)
        
        if not user_data:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            else:
                return redirect(url_for('remote_auth.login'))
        
        # Add user data to request context
        request.current_user = user_data
        return f(*args, **kwargs)
    
    return decorated_function

def require_role(role):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            if request.current_user['role'] != role and request.current_user['role'] != 'admin':
                if request.is_json:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                else:
                    flash('Insufficient permissions', 'error')
                    return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator