"""
Authentication module for HomeNetMon
Provides user authentication and session management
"""

import os
import hashlib
import secrets
from functools import wraps
from datetime import datetime, timedelta
from flask import session, redirect, url_for, request, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Session
import logging

logger = logging.getLogger(__name__)

class AuthManager:
    """Manages authentication and user sessions"""

    def __init__(self, app=None):
        self.app = app
        self.admin_password = os.environ.get('ADMIN_PASSWORD')
        self.session_timeout = int(os.environ.get('SESSION_TIMEOUT', '3600'))  # 1 hour default

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the authentication manager with the Flask app"""
        self.app = app
        app.auth_manager = self

        # Setup session configuration
        app.config['SESSION_COOKIE_SECURE'] = os.environ.get('HTTPS_ENABLED', 'false').lower() == 'true'
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=self.session_timeout)

        logger.info(f"Authentication manager initialized (admin_password={'set' if self.admin_password else 'not set'})")

    def create_default_admin(self):
        """Create default admin user if it doesn't exist"""
        try:
            admin = User.query.filter_by(username='admin').first()
            if not admin and self.admin_password:
                admin = User(
                    username='admin',
                    email='admin@localhost',
                    role='admin',
                    is_active=True
                )
                admin.set_password(self.admin_password)
                db.session.add(admin)
                db.session.commit()
                logger.info("Default admin user created")
            elif admin and self.admin_password:
                # Update password if ADMIN_PASSWORD env var changed
                admin.set_password(self.admin_password)
                db.session.commit()
                logger.info("Admin password updated from environment variable")
        except Exception as e:
            logger.error(f"Error creating default admin: {e}")
            db.session.rollback()

    def authenticate(self, username, password):
        """Authenticate a user with username and password"""
        if not username or not password:
            return None

        # Check database users
        user = User.query.filter_by(username=username, is_active=True).first()
        if user and user.check_password(password):
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            logger.info(f"User {username} authenticated successfully")
            return user

        # Fallback to environment variable for admin (backwards compatibility)
        if username == 'admin' and self.admin_password and password == self.admin_password:
            # Create or get admin user
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                self.create_default_admin()
                admin = User.query.filter_by(username='admin').first()
            return admin

        logger.warning(f"Failed authentication attempt for username: {username}")
        return None

    def login(self, user):
        """Log in a user by creating a session"""
        try:
            # Clear any existing session
            session.clear()

            # Set session data
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['logged_in'] = True
            session['login_time'] = datetime.utcnow().isoformat()
            session.permanent = True

            # Create database session record
            session_token = secrets.token_urlsafe(32)
            user_session = Session(
                user_id=user.id,
                token=session_token,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')[:200]
            )
            db.session.add(user_session)
            db.session.commit()

            session['session_token'] = session_token
            logger.info(f"User {user.username} logged in successfully")
            return True
        except Exception as e:
            logger.error(f"Error during login: {e}")
            return False

    def logout(self):
        """Log out the current user"""
        try:
            if 'session_token' in session:
                # Invalidate database session
                user_session = Session.query.filter_by(token=session['session_token']).first()
                if user_session:
                    db.session.delete(user_session)
                    db.session.commit()

            username = session.get('username', 'Unknown')
            session.clear()
            logger.info(f"User {username} logged out")
            return True
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            session.clear()
            return False

    def is_authenticated(self):
        """Check if the current session is authenticated"""
        if not session.get('logged_in'):
            return False

        # Check session token validity
        if 'session_token' in session:
            user_session = Session.query.filter_by(
                token=session['session_token'],
                is_active=True
            ).first()

            if not user_session:
                session.clear()
                return False

            # Check session expiry
            if user_session.is_expired():
                user_session.is_active = False
                db.session.commit()
                session.clear()
                return False

        return True

    def get_current_user(self):
        """Get the current logged-in user"""
        if self.is_authenticated() and 'user_id' in session:
            return User.query.get(session['user_id'])
        return None

    def has_role(self, role):
        """Check if the current user has a specific role"""
        return session.get('role') == role

    def cleanup_expired_sessions(self):
        """Clean up expired sessions from the database"""
        try:
            expired_time = datetime.utcnow() - timedelta(seconds=self.session_timeout)
            expired_sessions = Session.query.filter(
                Session.created_at < expired_time,
                Session.is_active == True
            ).all()

            for sess in expired_sessions:
                sess.is_active = False

            db.session.commit()
            if expired_sessions:
                logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        except Exception as e:
            logger.error(f"Error cleaning up sessions: {e}")
            db.session.rollback()

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_manager = getattr(request, 'auth_manager', None)
        if not auth_manager:
            # Fallback for routes without middleware
            from flask import current_app
            auth_manager = getattr(current_app, 'auth_manager', None)

        if not auth_manager or not auth_manager.is_authenticated():
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_manager = getattr(request, 'auth_manager', None)
        if not auth_manager:
            from flask import current_app
            auth_manager = getattr(current_app, 'auth_manager', None)

        if not auth_manager or not auth_manager.is_authenticated():
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))

        if not auth_manager.has_role('admin'):
            if request.is_json:
                return jsonify({'error': 'Admin access required'}), 403
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))

        return f(*args, **kwargs)
    return decorated_function

def api_key_required(f):
    """Decorator to require API key for API routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')

        if not api_key:
            return jsonify({'error': 'API key required'}), 401

        # Validate API key against database
        from models import APIKey
        key = APIKey.query.filter_by(key=api_key, is_active=True).first()

        if not key:
            return jsonify({'error': 'Invalid API key'}), 401

        if key.is_expired():
            return jsonify({'error': 'API key expired'}), 401

        # Update last used timestamp
        key.last_used = datetime.utcnow()
        key.usage_count += 1
        db.session.commit()

        # Store API key info in request context
        request.api_key = key
        return f(*args, **kwargs)
    return decorated_function