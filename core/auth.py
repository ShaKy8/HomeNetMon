import logging
import jwt
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from functools import wraps
from flask import request, jsonify, current_app, g
from werkzeug.security import check_password_hash, generate_password_hash
import secrets
import hashlib

logger = logging.getLogger(__name__)

class AuthManager:
    """Manages JWT-based authentication and authorization."""
    
    def __init__(self, app=None, secret_key: Optional[str] = None):
        self.app = app
        self.secret_key = secret_key or os.environ.get('JWT_SECRET_KEY') or secrets.token_urlsafe(32)
        self.algorithm = 'HS256'
        self.access_token_expires = timedelta(hours=1)
        self.refresh_token_expires = timedelta(days=7)
        
        # In-memory user store (replace with database in production)
        self.users = {}
        self.refresh_tokens = {}
        self.revoked_tokens = set()
        
        if app:
            self.init_app(app)
            
        logger.info("AuthManager initialized")
        
    def init_app(self, app):
        """Initialize the auth manager with a Flask app."""
        self.app = app
        app.config['JWT_SECRET_KEY'] = self.secret_key
        
        # Register error handlers
        @app.errorhandler(401)
        def unauthorized(error):
            return jsonify({'error': 'Unauthorized access'}), 401
            
        @app.errorhandler(403)
        def forbidden(error):
            return jsonify({'error': 'Forbidden'}), 403
            
        # Create default admin user if not exists
        self._create_default_admin()
        
    def _create_default_admin(self):
        """Create a default admin user if none exists."""
        if 'admin' not in self.users:
            admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme123')
            self.create_user('admin', admin_password, roles=['admin', 'user'])
            logger.info("Created default admin user (password from ADMIN_PASSWORD env or 'changeme123')")
            
    def create_user(self, username: str, password: str, roles: List[str] = None) -> bool:
        """Create a new user."""
        if username in self.users:
            logger.warning(f"User {username} already exists")
            return False
            
        self.users[username] = {
            'username': username,
            'password_hash': generate_password_hash(password),
            'roles': roles or ['user'],
            'created_at': datetime.now(timezone.utc),
            'is_active': True
        }
        
        logger.info(f"Created user: {username} with roles: {roles}")
        return True
        
    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate a user with username and password."""
        user = self.users.get(username)
        
        if not user:
            logger.warning(f"Authentication failed: user {username} not found")
            return None
            
        if not user['is_active']:
            logger.warning(f"Authentication failed: user {username} is inactive")
            return None
            
        if not check_password_hash(user['password_hash'], password):
            logger.warning(f"Authentication failed: invalid password for {username}")
            return None
            
        logger.info(f"User {username} authenticated successfully")
        return {
            'username': user['username'],
            'roles': user['roles']
        }
        
    def generate_tokens(self, user: Dict[str, Any]) -> Dict[str, str]:
        """Generate access and refresh tokens for a user."""
        now = datetime.now(timezone.utc)
        
        # Access token payload
        access_payload = {
            'username': user['username'],
            'roles': user['roles'],
            'type': 'access',
            'iat': now,
            'exp': now + self.access_token_expires,
            'jti': secrets.token_urlsafe(16)  # JWT ID for revocation
        }
        
        # Refresh token payload
        refresh_payload = {
            'username': user['username'],
            'type': 'refresh',
            'iat': now,
            'exp': now + self.refresh_token_expires,
            'jti': secrets.token_urlsafe(16)
        }
        
        access_token = jwt.encode(access_payload, self.secret_key, algorithm=self.algorithm)
        refresh_token = jwt.encode(refresh_payload, self.secret_key, algorithm=self.algorithm)
        
        # Store refresh token
        self.refresh_tokens[refresh_payload['jti']] = {
            'username': user['username'],
            'expires': refresh_payload['exp']
        }
        
        logger.debug(f"Generated tokens for user {user['username']}")
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer'
        }
        
    def verify_token(self, token: str, token_type: str = 'access') -> Optional[Dict[str, Any]]:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check token type
            if payload.get('type') != token_type:
                logger.warning(f"Invalid token type: expected {token_type}, got {payload.get('type')}")
                return None
                
            # Check if token is revoked
            if payload.get('jti') in self.revoked_tokens:
                logger.warning(f"Token {payload.get('jti')} is revoked")
                return None
                
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
            
    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """Generate a new access token using a refresh token."""
        payload = self.verify_token(refresh_token, token_type='refresh')
        
        if not payload:
            return None
            
        # Check if refresh token is still valid
        jti = payload.get('jti')
        if jti not in self.refresh_tokens:
            logger.warning(f"Refresh token {jti} not found")
            return None
            
        user = self.users.get(payload['username'])
        if not user or not user['is_active']:
            logger.warning(f"User {payload['username']} not found or inactive")
            return None
            
        # Generate new access token only
        now = datetime.now(timezone.utc)
        access_payload = {
            'username': user['username'],
            'roles': user['roles'],
            'type': 'access',
            'iat': now,
            'exp': now + self.access_token_expires,
            'jti': secrets.token_urlsafe(16)
        }
        
        access_token = jwt.encode(access_payload, self.secret_key, algorithm=self.algorithm)
        
        return {
            'access_token': access_token,
            'token_type': 'Bearer'
        }
        
    def revoke_token(self, token: str) -> bool:
        """Revoke a token."""
        payload = self.verify_token(token)
        if payload and 'jti' in payload:
            self.revoked_tokens.add(payload['jti'])
            
            # Remove from refresh tokens if it's a refresh token
            if payload.get('type') == 'refresh' and payload['jti'] in self.refresh_tokens:
                del self.refresh_tokens[payload['jti']]
                
            logger.info(f"Revoked token {payload['jti']}")
            return True
        return False
        
    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """Get the current authenticated user from the request context."""
        return g.get('current_user')
        
    def cleanup_expired_tokens(self):
        """Clean up expired tokens from storage."""
        now = datetime.now(timezone.utc)
        
        # Clean up expired refresh tokens
        expired_tokens = []
        for jti, data in self.refresh_tokens.items():
            if data['expires'] < now:
                expired_tokens.append(jti)
                
        for jti in expired_tokens:
            del self.refresh_tokens[jti]
            
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired refresh tokens")


def auth_required(f):
    """Decorator to require authentication for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            logger.warning("No authorization header provided")
            return jsonify({'error': 'Authorization header required'}), 401
            
        try:
            # Extract token from "Bearer <token>" format
            parts = auth_header.split()
            if len(parts) != 2 or parts[0] != 'Bearer':
                return jsonify({'error': 'Invalid authorization header format'}), 401
                
            token = parts[1]
            auth_manager = current_app.extensions.get('auth_manager')
            
            if not auth_manager:
                logger.error("AuthManager not initialized")
                return jsonify({'error': 'Authentication system not configured'}), 500
                
            payload = auth_manager.verify_token(token)
            
            if not payload:
                return jsonify({'error': 'Invalid or expired token'}), 401
                
            # Set current user in request context
            g.current_user = {
                'username': payload['username'],
                'roles': payload.get('roles', [])
            }
            
            return f(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return jsonify({'error': 'Authentication failed'}), 401
            
    return decorated_function


def roles_required(*required_roles):
    """Decorator to require specific roles for a route."""
    def decorator(f):
        @wraps(f)
        @auth_required
        def decorated_function(*args, **kwargs):
            current_user = g.get('current_user')
            
            if not current_user:
                return jsonify({'error': 'Authentication required'}), 401
                
            user_roles = set(current_user.get('roles', []))
            required_roles_set = set(required_roles)
            
            if not user_roles.intersection(required_roles_set):
                logger.warning(f"User {current_user['username']} lacks required roles: {required_roles}")
                return jsonify({'error': 'Insufficient permissions'}), 403
                
            return f(*args, **kwargs)
            
        return decorated_function
    return decorator


def admin_required(f):
    """Decorator to require admin role for a route."""
    return roles_required('admin')(f)