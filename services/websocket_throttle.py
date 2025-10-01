"""
WebSocket Event Throttling Service

This service provides intelligent throttling for WebSocket events to prevent spam
and reduce bandwidth usage while maintaining real-time responsiveness.

Key Features:
- Device-specific throttling (avoid spamming updates for same device)
- Global event rate limiting 
- Smart aggregation of similar events
- Configurable throttle periods per event type
- Memory-efficient implementation
"""

import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Set, Optional, Any
import logging

logger = logging.getLogger(__name__)


class WebSocketThrottle:
    """Intelligent WebSocket event throttling with device-specific and global limits"""
    
    def __init__(self):
        self._device_last_update = {}  # device_id -> timestamp
        self._global_last_update = {}  # event_type -> timestamp
        self._pending_updates = {}     # device_id -> pending data
        self._lock = threading.RLock()
        
        # PERFORMANCE OPTIMIZATION: More aggressive throttle periods for better performance
        self.throttle_periods = {
            'device_status_update': 5.0,      # Max 1 update per device every 5 seconds (was 2)
            'monitoring_summary': 10.0,       # Max 1 summary every 10 seconds (was 5)
            'chart_data_update': 8.0,         # Max 1 chart update every 8 seconds (was 3)
            'performance_metrics_update': 15.0, # Max 1 perf update every 15 seconds (was 10)
            'alert_update': 1.0               # Max 1 alert update every 1 second (was 0.5)
        }
        
        # More aggressive global rate limits (events per minute)
        self.global_rate_limits = {
            'device_status_update': 30,       # Max 30 device updates per minute (was 60)
            'monitoring_summary': 6,          # Max 6 summaries per minute (was 12)
            'chart_data_update': 10,          # Max 10 chart updates per minute (was 20)
            'performance_metrics_update': 4,  # Max 4 perf updates per minute (was 6)
            'alert_update': 60               # Max 60 alert updates per minute (was 120)
        }
        
        # Add event counters for rate limiting
        self._event_counters = {}             # event_type -> [(timestamp, count), ...]
        self._last_significant_change = {}   # device_id -> {status, response_time, etc.}
        
        # Keep track of recent events for rate limiting
        self._recent_events = {}  # event_type -> list of timestamps
        
        # Cleanup thread for memory management
        self._cleanup_thread = None
        self._cleanup_stop_event = threading.Event()
        self._start_cleanup_thread()
    
    def _start_cleanup_thread(self):
        """Start background thread to cleanup old throttle data"""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            return
        
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_old_data,
            daemon=True,
            name='WebSocketThrottleCleanup'
        )
        self._cleanup_thread.start()
    
    def _cleanup_old_data(self):
        """Background cleanup of old throttle data to prevent memory leaks"""
        while not self._cleanup_stop_event.wait(300):  # Run every 5 minutes
            try:
                current_time = time.time()
                cutoff_time = current_time - 3600  # Remove data older than 1 hour
                
                with self._lock:
                    # Cleanup device last update times
                    old_devices = [
                        device_id for device_id, timestamp in self._device_last_update.items()
                        if timestamp < cutoff_time
                    ]
                    for device_id in old_devices:
                        del self._device_last_update[device_id]
                    
                    # Cleanup pending updates for old devices
                    for device_id in old_devices:
                        self._pending_updates.pop(device_id, None)
                    
                    # Cleanup recent events lists
                    for event_type, timestamps in self._recent_events.items():
                        self._recent_events[event_type] = [
                            ts for ts in timestamps if ts > cutoff_time
                        ]
                    
                    if old_devices:
                        logger.debug(f"Cleaned up throttle data for {len(old_devices)} old devices")
                        
            except Exception as e:
                logger.error(f"Error during WebSocket throttle cleanup: {e}")
    
    def _is_significant_change(self, device_id: int, event_data: Dict[str, Any]) -> bool:
        """Check if device data has changed significantly enough to warrant an update"""
        with self._lock:
            if device_id not in self._last_significant_change:
                # First update is always significant
                self._last_significant_change[device_id] = event_data.copy()
                return True
            
            last_data = self._last_significant_change[device_id]
            
            # Check for significant changes
            significant_changes = []
            
            # Status change is always significant
            if event_data.get('status') != last_data.get('status'):
                significant_changes.append('status')
            
            # Response time changes > 20% or crossing thresholds
            old_rt = last_data.get('response_time')
            new_rt = event_data.get('response_time')
            
            if old_rt is None and new_rt is not None:
                significant_changes.append('response_time')  # Device came online
            elif old_rt is not None and new_rt is None:
                significant_changes.append('response_time')  # Device went offline
            elif old_rt is not None and new_rt is not None:
                # Check percentage change
                if abs(new_rt - old_rt) / max(old_rt, 1) > 0.2:  # 20% change
                    significant_changes.append('response_time')
                # Check threshold crossings (1000ms warning threshold)
                elif (old_rt <= 1000 < new_rt) or (new_rt <= 1000 < old_rt):
                    significant_changes.append('response_time')
            
            # Update stored data if significant
            if significant_changes:
                self._last_significant_change[device_id] = event_data.copy()
                logger.debug(f"Significant changes for device {device_id}: {significant_changes}")
                return True
            
            return False

    def should_emit_device_update(self, device_id: int, event_data: Dict[str, Any]) -> bool:
        """
        Check if a device status update should be emitted based on throttling rules
        
        Args:
            device_id: ID of the device
            event_data: Data to be sent with the event
            
        Returns:
            True if event should be emitted, False if throttled
        """
        with self._lock:
            current_time = time.time()
            event_type = 'device_status_update'
            throttle_period = self.throttle_periods[event_type]
            
            # PERFORMANCE OPTIMIZATION: Check if change is significant first
            if not self._is_significant_change(device_id, event_data):
                logger.debug(f"No significant changes for device {device_id}, skipping update")
                return False
            
            # Check device-specific throttling
            last_update = self._device_last_update.get(device_id, 0)
            if current_time - last_update < throttle_period:
                # Store pending update (latest data wins)
                self._pending_updates[device_id] = {
                    'data': event_data,
                    'timestamp': current_time
                }
                logger.debug(f"Throttled device update for device {device_id}")
                return False
            
            # Check global rate limiting
            if not self._check_global_rate_limit(event_type, current_time):
                # Store pending update
                self._pending_updates[device_id] = {
                    'data': event_data,
                    'timestamp': current_time
                }
                logger.debug(f"Global rate limit exceeded for {event_type}")
                return False
            
            # Update throttle tracking
            self._device_last_update[device_id] = current_time
            self._record_event(event_type, current_time)
            
            # Remove any pending update since we're emitting now
            self._pending_updates.pop(device_id, None)
            
            return True
    
    def should_emit_global_event(self, event_type: str) -> bool:
        """
        Check if a global event (like monitoring_summary) should be emitted
        
        Args:
            event_type: Type of event to check
            
        Returns:
            True if event should be emitted, False if throttled
        """
        with self._lock:
            current_time = time.time()
            
            # Check global throttling for this event type
            throttle_period = self.throttle_periods.get(event_type, 1.0)
            last_update = self._global_last_update.get(event_type, 0)
            
            if current_time - last_update < throttle_period:
                logger.debug(f"Throttled global event: {event_type}")
                return False
            
            # Check global rate limiting
            if not self._check_global_rate_limit(event_type, current_time):
                logger.debug(f"Global rate limit exceeded for {event_type}")
                return False
            
            # Update throttle tracking
            self._global_last_update[event_type] = current_time
            self._record_event(event_type, current_time)
            
            return True
    
    def _check_global_rate_limit(self, event_type: str, current_time: float) -> bool:
        """Check if event exceeds global rate limit"""
        rate_limit = self.global_rate_limits.get(event_type)
        if not rate_limit:
            return True
        
        # Clean up old events (older than 1 minute)
        minute_ago = current_time - 60
        if event_type not in self._recent_events:
            self._recent_events[event_type] = []
        
        self._recent_events[event_type] = [
            ts for ts in self._recent_events[event_type] if ts > minute_ago
        ]
        
        # Check if we're under the rate limit
        return len(self._recent_events[event_type]) < rate_limit
    
    def _record_event(self, event_type: str, timestamp: float):
        """Record an event for rate limiting purposes"""
        if event_type not in self._recent_events:
            self._recent_events[event_type] = []
        
        self._recent_events[event_type].append(timestamp)
    
    def get_pending_updates(self) -> Dict[int, Dict[str, Any]]:
        """
        Get all pending device updates that should be flushed
        
        Returns:
            Dictionary mapping device_id to pending update data
        """
        with self._lock:
            current_time = time.time()
            ready_updates = {}
            
            for device_id, pending in list(self._pending_updates.items()):
                # Check if enough time has passed for this device
                last_update = self._device_last_update.get(device_id, 0)
                throttle_period = self.throttle_periods['device_status_update']
                
                if current_time - last_update >= throttle_period:
                    # Check global rate limit
                    if self._check_global_rate_limit('device_status_update', current_time):
                        ready_updates[device_id] = pending['data']
                        
                        # Update tracking
                        self._device_last_update[device_id] = current_time
                        self._record_event('device_status_update', current_time)
                        
                        # Remove from pending
                        del self._pending_updates[device_id]
            
            return ready_updates
    
    def flush_pending_updates(self, socketio, app=None):
        """
        Flush all pending updates that are ready to be sent
        
        Args:
            socketio: SocketIO instance to emit events
            app: Flask app for context (optional)
        """
        ready_updates = self.get_pending_updates()
        
        if ready_updates:
            for device_id, event_data in ready_updates.items():
                try:
                    if app:
                        with app.app_context():
                            # Emit to specific room for device status updates
                            socketio.emit('device_status_update', event_data, room='updates_device_status')
                    else:
                        socketio.emit('device_status_update', event_data, room='updates_device_status')
                except Exception as e:
                    logger.error(f"Error emitting pending update for device {device_id}: {e}")
            
            logger.debug(f"Flushed {len(ready_updates)} pending device updates")
    
    def get_throttle_stats(self) -> Dict[str, Any]:
        """Get throttling statistics for monitoring and debugging"""
        with self._lock:
            current_time = time.time()
            
            stats = {
                'active_device_throttles': len(self._device_last_update),
                'pending_updates': len(self._pending_updates),
                'throttle_periods': self.throttle_periods.copy(),
                'global_rate_limits': self.global_rate_limits.copy(),
                'recent_events': {}
            }
            
            # Count recent events
            for event_type, timestamps in self._recent_events.items():
                minute_ago = current_time - 60
                recent_count = len([ts for ts in timestamps if ts > minute_ago])
                stats['recent_events'][event_type] = {
                    'last_minute': recent_count,
                    'rate_limit': self.global_rate_limits.get(event_type, 'unlimited')
                }
            
            return stats
    
    def stop(self):
        """Stop the throttling service and cleanup threads"""
        self._cleanup_stop_event.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5)


# Global throttle instance
websocket_throttle = WebSocketThrottle()