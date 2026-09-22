"""
WebSocket Memory Management and Event Optimization
Fixes memory leaks and optimizes WebSocket event handling for production.
"""

import gc
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

        # Housekeeping runs opportunistically from register_connection (no thread)
        self._last_cleanup = time.time()
        self._memory_stats = {'peak_connections': 0, 'total_events': 0, 'cleanup_runs': 0}

        logger.info(f"WebSocket Connection Manager initialized with max {max_connections_per_ip} connections per IP")

    def register_connection(self, sid: str, client_ip: str, user_agent: str = ""):
        self._maybe_cleanup()
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

    def _maybe_cleanup(self):
        """Prune stale connection state at most once a minute, on the caller's thread."""
        if time.time() - self._last_cleanup < 60:
            return
        self._last_cleanup = time.time()
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

    # Import Flask helpers used by the routes and handlers below
    from flask import jsonify, request

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

    # Store connection manager in app for access by other parts
    app.websocket_connection_manager = connection_manager

    logger.info("WebSocket memory leak fixes applied")
    return connection_manager
