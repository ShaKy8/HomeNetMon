import logging
import threading
from typing import Dict, Any, Set, Optional, Callable
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask import request
from functools import wraps
import time
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class WebSocketManager:
    """Manages WebSocket connections and events with proper lifecycle management."""
    
    def __init__(self, socketio: SocketIO, max_connections_per_client: int = 5):
        self.socketio = socketio
        self.max_connections_per_client = max_connections_per_client
        
        # Connection tracking
        self.connections: Dict[str, Set[str]] = defaultdict(set)  # client_id -> set of session_ids
        self.session_info: Dict[str, Dict] = {}  # session_id -> connection info
        self.rooms: Dict[str, Set[str]] = defaultdict(set)  # room -> set of session_ids
        
        # Rate limiting
        self.message_counts: Dict[str, int] = defaultdict(int)
        self.message_reset_time: Dict[str, datetime] = {}
        
        # Metrics
        self.metrics = {
            'total_connections': 0,
            'active_connections': 0,
            'messages_sent': 0,
            'messages_received': 0,
            'errors': 0
        }
        
        logger.info(f"WebSocketManager initialized with max_connections_per_client={max_connections_per_client}")

        # Start periodic cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._periodic_cleanup_loop,
            daemon=True,
            name="WebSocketCleanup"
        )
        self._cleanup_running = True
        self._cleanup_thread.start()
        
    def register_handlers(self):
        """Register core WebSocket event handlers."""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection."""
            session_id = request.sid
            client_ip = request.remote_addr or 'unknown'
            
            # Check connection limit
            if len(self.connections[client_ip]) >= self.max_connections_per_client:
                logger.warning(f"Connection limit exceeded for {client_ip}")
                return False
                
            # Track connection
            self.connections[client_ip].add(session_id)
            self.session_info[session_id] = {
                'client_ip': client_ip,
                'connected_at': datetime.now(),
                'rooms': set()
            }
            
            # Update metrics
            self.metrics['total_connections'] += 1
            self.metrics['active_connections'] = len(self.session_info)
            
            logger.info(f"Client connected: {session_id} from {client_ip}")
            emit('connected', {'session_id': session_id})
            return True
            
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection."""
            session_id = request.sid
            
            if session_id in self.session_info:
                info = self.session_info[session_id]
                client_ip = info['client_ip']
                
                # Clean up rooms
                for room in info['rooms']:
                    self.rooms[room].discard(session_id)
                    
                # Clean up connection tracking
                self.connections[client_ip].discard(session_id)
                if not self.connections[client_ip]:
                    del self.connections[client_ip]
                    
                del self.session_info[session_id]
                
                # Update metrics
                self.metrics['active_connections'] = len(self.session_info)
                
                logger.info(f"Client disconnected: {session_id}")
                
        @self.socketio.on('join_room')
        def handle_join_room(data):
            """Handle room join request."""
            room = data.get('room')
            session_id = request.sid
            
            if not room:
                emit('error', {'message': 'Room name required'})
                return
                
            if session_id in self.session_info:
                join_room(room)
                self.session_info[session_id]['rooms'].add(room)
                self.rooms[room].add(session_id)
                
                emit('joined_room', {'room': room})
                logger.debug(f"Session {session_id} joined room {room}")
                
        @self.socketio.on('leave_room')
        def handle_leave_room(data):
            """Handle room leave request."""
            room = data.get('room')
            session_id = request.sid
            
            if not room:
                emit('error', {'message': 'Room name required'})
                return
                
            if session_id in self.session_info:
                leave_room(room)
                self.session_info[session_id]['rooms'].discard(room)
                self.rooms[room].discard(session_id)
                
                emit('left_room', {'room': room})
                logger.debug(f"Session {session_id} left room {room}")
                
    def rate_limit(self, max_messages: int = 100, window_seconds: int = 60):
        """Decorator for rate limiting WebSocket events."""
        def decorator(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                session_id = request.sid
                now = datetime.now()
                
                # Reset window if needed
                if session_id not in self.message_reset_time or \
                   now - self.message_reset_time[session_id] > timedelta(seconds=window_seconds):
                    self.message_counts[session_id] = 0
                    self.message_reset_time[session_id] = now
                    
                # Check rate limit
                if self.message_counts[session_id] >= max_messages:
                    emit('error', {'message': 'Rate limit exceeded'})
                    logger.warning(f"Rate limit exceeded for session {session_id}")
                    return
                    
                self.message_counts[session_id] += 1
                self.metrics['messages_received'] += 1
                
                return f(*args, **kwargs)
            return wrapped
        return decorator
        
    def broadcast(self, event: str, data: Any, room: Optional[str] = None,
                 include_self: bool = True, namespace: str = '/'):
        """Broadcast message to all clients or specific room."""
        try:
            self.socketio.emit(event, data, room=room, 
                             include_self=include_self, namespace=namespace)
            self.metrics['messages_sent'] += 1
            logger.debug(f"Broadcast {event} to room={room or 'all'}")
        except Exception as e:
            logger.error(f"Broadcast error: {e}")
            self.metrics['errors'] += 1
            
    def emit_to_session(self, session_id: str, event: str, data: Any):
        """Send message to specific session."""
        try:
            self.socketio.emit(event, data, room=session_id)
            self.metrics['messages_sent'] += 1
            logger.debug(f"Emitted {event} to session {session_id}")
        except Exception as e:
            logger.error(f"Emit error to {session_id}: {e}")
            self.metrics['errors'] += 1
            
    def get_connection_count(self) -> int:
        """Get current active connection count."""
        return len(self.session_info)
        
    def get_room_members(self, room: str) -> Set[str]:
        """Get all session IDs in a room."""
        return self.rooms.get(room, set()).copy()
        
    def disconnect_client(self, session_id: str):
        """Force disconnect a client."""
        try:
            self.socketio.server.disconnect(session_id)
            logger.info(f"Force disconnected session {session_id}")
        except Exception as e:
            logger.error(f"Error disconnecting {session_id}: {e}")
            
    def get_metrics(self) -> Dict[str, Any]:
        """Get WebSocket metrics."""
        return {
            **self.metrics,
            'rooms': {room: len(members) for room, members in self.rooms.items()},
            'clients_by_ip': {ip: len(sessions) for ip, sessions in self.connections.items()}
        }
        
    def cleanup_stale_connections(self, max_age_hours: int = 24):
        """Clean up stale connections."""
        now = datetime.now()
        stale_threshold = timedelta(hours=max_age_hours)
        
        stale_sessions = []
        for session_id, info in self.session_info.items():
            if now - info['connected_at'] > stale_threshold:
                stale_sessions.append(session_id)
                
        for session_id in stale_sessions:
            logger.info(f"Cleaning up stale session {session_id}")
            self.disconnect_client(session_id)

        return len(stale_sessions)

    def cleanup_stale_rate_limits(self, max_age_minutes: int = 10):
        """Clean up stale rate limit entries for disconnected sessions."""
        now = datetime.now()
        stale_threshold = timedelta(minutes=max_age_minutes)

        # Find stale entries (sessions no longer connected)
        stale_sessions = []
        for session_id in list(self.message_reset_time.keys()):
            if session_id not in self.session_info:
                # Session disconnected, check if entry is old enough to remove
                reset_time = self.message_reset_time.get(session_id)
                if reset_time and now - reset_time > stale_threshold:
                    stale_sessions.append(session_id)

        # Clean up stale entries
        for session_id in stale_sessions:
            self.message_counts.pop(session_id, None)
            self.message_reset_time.pop(session_id, None)

        if stale_sessions:
            logger.debug(f"Cleaned up {len(stale_sessions)} stale rate limit entries")

        return len(stale_sessions)

    def _periodic_cleanup_loop(self):
        """Background thread that runs periodic cleanup tasks."""
        logger.info("WebSocket cleanup thread started")

        while self._cleanup_running:
            try:
                # Run cleanup every 5 minutes
                time.sleep(300)

                if not self._cleanup_running:
                    break

                # Clean up stale connections (24 hours old)
                stale_connections = self.cleanup_stale_connections(max_age_hours=24)

                # Clean up stale rate limit entries (10 minutes old)
                stale_rate_limits = self.cleanup_stale_rate_limits(max_age_minutes=10)

                if stale_connections > 0 or stale_rate_limits > 0:
                    logger.info(f"Cleanup complete: {stale_connections} stale connections, "
                               f"{stale_rate_limits} stale rate limits")

            except Exception as e:
                logger.error(f"Error in cleanup thread: {e}")

        logger.info("WebSocket cleanup thread stopped")

    def stop_cleanup(self):
        """Stop the periodic cleanup thread."""
        self._cleanup_running = False
        
    def register_monitoring_events(self, monitor, alert_manager):
        """Register monitoring-specific WebSocket events."""
        
        @self.socketio.on('request_device_status')
        @self.rate_limit(max_messages=50, window_seconds=60)
        def handle_device_status_request():
            """Handle device status request."""
            from models import Device, MonitoringData
            
            devices = Device.query.filter_by(is_active=True).all()
            status_data = []
            
            for device in devices:
                latest_data = device.get_latest_monitoring_data()
                status_data.append({
                    'id': device.id,
                    'ip': device.ip_address,
                    'name': device.display_name,
                    'status': device.status,
                    'response_time': latest_data.response_time if latest_data else None,
                    'last_seen': device.last_seen.isoformat() if device.last_seen else None
                })
                
            emit('device_status_update', {'devices': status_data})
            
        @self.socketio.on('request_monitoring_summary')
        @self.rate_limit(max_messages=30, window_seconds=60)
        def handle_monitoring_summary():
            """Handle monitoring summary request."""
            from models import Device
            
            total = Device.query.filter_by(is_active=True).count()
            online = Device.query.filter_by(is_active=True, status='online').count()
            offline = total - online
            
            emit('monitoring_summary', {
                'total_devices': total,
                'online_devices': online,
                'offline_devices': offline,
                'timestamp': datetime.now().isoformat()
            })
            
        logger.info("Registered monitoring WebSocket events")