"""
WebSocket Memory Management and Event Optimization
Fixes memory leaks and optimizes WebSocket event handling for production.
"""

import gc
import weakref
import threading
import time
import logging
from typing import Dict, Set, Any, Optional, List
from collections import defaultdict, deque
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class WebSocketConnectionManager:
    """Manages WebSocket connections with memory leak prevention."""
    
    def __init__(self, socketio, max_connections_per_ip=10):
        self.socketio = socketio
        self.max_connections_per_ip = max_connections_per_ip
        
        # Connection tracking with weak references to prevent memory leaks
        self._connection_metadata = {}  # sid -> metadata
        self._ip_connections = defaultdict(set)  # ip -> set of sids
        self._room_subscriptions = defaultdict(set)  # room -> set of sids
        self._client_last_activity = {}  # sid -> timestamp
        
        # Event queues with size limits to prevent unbounded growth
        self._event_queues = defaultdict(lambda: deque(maxlen=100))
        self._pending_broadcasts = deque(maxlen=1000)
        
        # Cleanup and monitoring
        self._cleanup_thread = None
        self._cleanup_stop_event = threading.Event()
        self._memory_stats = {'peak_connections': 0, 'total_events': 0, 'cleanup_runs': 0}
        
        self._start_cleanup_thread()
        
        logger.info(f"WebSocket Connection Manager initialized with max {max_connections_per_ip} connections per IP")
    
    def register_connection(self, sid: str, client_ip: str, user_agent: str = ""):
        """Register a new WebSocket connection."""
        
        # Check connection limits per IP
        if len(self._ip_connections[client_ip]) >= self.max_connections_per_ip:
            logger.warning(f"Connection limit exceeded for IP {client_ip}: {len(self._ip_connections[client_ip])} connections")
            return False
        
        # Store connection metadata
        self._connection_metadata[sid] = {
            'ip': client_ip,
            'user_agent': user_agent,
            'connected_at': datetime.utcnow(),
            'last_activity': datetime.utcnow(),
            'subscriptions': set(),
            'event_count': 0
        }
        
        # Track connections by IP
        self._ip_connections[client_ip].add(sid)
        self._client_last_activity[sid] = time.time()
        
        # Update stats
        current_connections = len(self._connection_metadata)
        if current_connections > self._memory_stats['peak_connections']:
            self._memory_stats['peak_connections'] = current_connections
        
        logger.info(f"Registered WebSocket connection {sid} from {client_ip} (total: {current_connections})")
        return True
    
    def unregister_connection(self, sid: str):
        """Unregister a WebSocket connection and clean up resources."""
        
        if sid not in self._connection_metadata:
            return
        
        metadata = self._connection_metadata[sid]
        client_ip = metadata['ip']
        
        # Remove from IP tracking
        self._ip_connections[client_ip].discard(sid)
        if not self._ip_connections[client_ip]:
            del self._ip_connections[client_ip]
        
        # Remove from room subscriptions
        for room in metadata['subscriptions']:
            self._room_subscriptions[room].discard(sid)
            if not self._room_subscriptions[room]:
                del self._room_subscriptions[room]
        
        # Clean up queues
        if sid in self._event_queues:
            del self._event_queues[sid]
        
        # Remove metadata
        del self._connection_metadata[sid]
        if sid in self._client_last_activity:
            del self._client_last_activity[sid]
        
        logger.info(f"Unregistered WebSocket connection {sid} from {client_ip}")
    
    def subscribe_to_room(self, sid: str, room: str) -> bool:
        """Subscribe connection to a room."""
        
        if sid not in self._connection_metadata:
            return False
        
        # Add to room subscription tracking
        self._room_subscriptions[room].add(sid)
        self._connection_metadata[sid]['subscriptions'].add(room)
        
        # Update activity
        self._client_last_activity[sid] = time.time()
        
        logger.debug(f"Connection {sid} subscribed to room {room}")
        return True
    
    def unsubscribe_from_room(self, sid: str, room: str) -> bool:
        """Unsubscribe connection from a room."""
        
        if sid not in self._connection_metadata:
            return False
        
        # Remove from room subscription tracking
        self._room_subscriptions[room].discard(sid)
        if not self._room_subscriptions[room]:
            del self._room_subscriptions[room]
        
        self._connection_metadata[sid]['subscriptions'].discard(room)
        
        logger.debug(f"Connection {sid} unsubscribed from room {room}")
        return True
    
    def broadcast_to_room(self, room: str, event: str, data: Any, skip_sid: str = None):
        """Efficiently broadcast event to all connections in a room."""
        
        if room not in self._room_subscriptions:
            return 0
        
        connections = self._room_subscriptions[room].copy()  # Copy to avoid modification during iteration
        if skip_sid and skip_sid in connections:
            connections.remove(skip_sid)
        
        if not connections:
            return 0
        
        # Batch emit for efficiency
        try:
            self.socketio.emit(event, data, room=room, skip_sid=skip_sid)
            
            # Update event counters
            for sid in connections:
                if sid in self._connection_metadata:
                    self._connection_metadata[sid]['event_count'] += 1
                    self._client_last_activity[sid] = time.time()
            
            self._memory_stats['total_events'] += len(connections)
            
        except Exception as e:
            logger.error(f"Error broadcasting to room {room}: {e}")
            return 0
        
        return len(connections)
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get current connection statistics."""
        
        current_connections = len(self._connection_metadata)
        room_count = len(self._room_subscriptions)
        total_subscriptions = sum(len(subs) for subs in self._room_subscriptions.values())
        
        return {
            'current_connections': current_connections,
            'peak_connections': self._memory_stats['peak_connections'],
            'total_rooms': room_count,
            'total_subscriptions': total_subscriptions,
            'total_events_sent': self._memory_stats['total_events'],
            'cleanup_runs': self._memory_stats['cleanup_runs'],
            'connections_by_ip': {ip: len(sids) for ip, sids in self._ip_connections.items()},
            'active_rooms': list(self._room_subscriptions.keys())
        }
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread."""
        
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            return
        
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name='WebSocketCleanup'
        )
        self._cleanup_thread.start()
    
    def _cleanup_loop(self):
        """Background cleanup loop to prevent memory leaks."""
        
        logger.info("WebSocket cleanup thread started")
        
        while not self._cleanup_stop_event.wait(60):  # Run every minute
            try:
                self._run_cleanup()
            except Exception as e:
                logger.error(f"Error in WebSocket cleanup: {e}")
    
    def _run_cleanup(self):
        """Run cleanup tasks to prevent memory leaks."""
        
        now = time.time()
        cleanup_count = 0
        
        # Clean up inactive connections (no activity for 30+ minutes)
        inactive_threshold = now - (30 * 60)  # 30 minutes
        inactive_connections = [
            sid for sid, last_activity in self._client_last_activity.items()
            if last_activity < inactive_threshold
        ]
        
        for sid in inactive_connections:
            logger.info(f"Cleaning up inactive WebSocket connection: {sid}")
            self.unregister_connection(sid)
            cleanup_count += 1
        
        # Clean up empty rooms
        empty_rooms = [room for room, sids in self._room_subscriptions.items() if not sids]
        for room in empty_rooms:
            del self._room_subscriptions[room]
        
        # Clean up old event queues
        old_queues = [sid for sid in self._event_queues.keys() if sid not in self._connection_metadata]
        for sid in old_queues:
            del self._event_queues[sid]
        
        # Limit pending broadcasts queue
        while len(self._pending_broadcasts) > 500:
            self._pending_broadcasts.popleft()
        
        # Force garbage collection if we cleaned up connections
        if cleanup_count > 0:
            collected = gc.collect()
            logger.info(f"Cleaned up {cleanup_count} inactive connections, {len(empty_rooms)} empty rooms. GC collected {collected} objects.")
        
        self._memory_stats['cleanup_runs'] += 1
        
        # Log statistics periodically
        if self._memory_stats['cleanup_runs'] % 5 == 0:  # Every 5 minutes
            stats = self.get_connection_stats()
            logger.info(f"WebSocket Stats: {stats['current_connections']} connections, {stats['total_rooms']} rooms")
    
    def shutdown(self):
        """Shutdown the connection manager and cleanup resources."""
        
        logger.info("Shutting down WebSocket Connection Manager...")
        
        # Stop cleanup thread
        if self._cleanup_thread:
            self._cleanup_stop_event.set()
            self._cleanup_thread.join(timeout=5)
        
        # Clear all data structures
        self._connection_metadata.clear()
        self._ip_connections.clear()
        self._room_subscriptions.clear()
        self._client_last_activity.clear()
        self._event_queues.clear()
        self._pending_broadcasts.clear()
        
        # Force garbage collection
        collected = gc.collect()
        logger.info(f"WebSocket Connection Manager shut down. GC collected {collected} objects.")


def fix_websocket_memory_leaks(app, socketio):
    """Apply WebSocket memory leak fixes to the application."""
    
    # Create connection manager
    connection_manager = WebSocketConnectionManager(socketio)
    
    # Import request for WebSocket handlers
    from flask import request
    
    # Override default SocketIO handlers to use our connection manager
    @socketio.on('connect')
    def handle_connect():
        client_ip = request.environ.get('REMOTE_ADDR', '127.0.0.1')
        user_agent = request.headers.get('User-Agent', '')
        
        if connection_manager.register_connection(request.sid, client_ip, user_agent):
            logger.info(f"WebSocket client connected: {request.sid} from {client_ip}")
            socketio.emit('connection_established', {'sid': request.sid})
        else:
            logger.warning(f"WebSocket connection rejected for {client_ip}: too many connections")
            return False  # Reject connection
    
    @socketio.on('disconnect')
    def handle_disconnect():
        logger.info(f"WebSocket client disconnected: {request.sid}")
        connection_manager.unregister_connection(request.sid)
    
    @socketio.on('join_room')
    def handle_join_room(data):
        room = data.get('room')
        if room:
            socketio.join_room(room)
            connection_manager.subscribe_to_room(request.sid, room)
            logger.debug(f"Client {request.sid} joined room {room}")
    
    @socketio.on('leave_room')
    def handle_leave_room(data):
        room = data.get('room')
        if room:
            socketio.leave_room(room)
            connection_manager.unsubscribe_from_room(request.sid, room)
            logger.debug(f"Client {request.sid} left room {room}")
    
    # Store connection manager in app for access by other parts
    app.websocket_connection_manager = connection_manager
    
    # Add cleanup on app teardown
    @app.teardown_appcontext
    def cleanup_websocket_resources(error):
        if hasattr(app, 'websocket_connection_manager'):
            # Don't shutdown on every request, just clean up if needed
            pass
    
    # Add stats endpoint
    @app.route('/api/websocket/stats')
    def websocket_stats():
        stats = connection_manager.get_connection_stats()
        return jsonify(stats)
    
    logger.info("WebSocket memory leak fixes applied")
    return connection_manager