"""
WebSocket Performance Optimizer for HomeNetMon
Provides high-performance WebSocket operations with minimal database impact
"""
import json
import time
import asyncio
import logging
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from threading import Lock, RLock
import hashlib

logger = logging.getLogger(__name__)

@dataclass
class DeviceState:
    """Efficient device state representation"""
    id: int
    ip_address: str
    display_name: str
    status: str
    response_time: Optional[float]
    last_seen: Optional[str]
    active_alerts: int
    checksum: str = ""
    
    def __post_init__(self):
        """Calculate checksum for change detection"""
        data = f"{self.status}:{self.response_time}:{self.active_alerts}:{self.last_seen}"
        self.checksum = hashlib.md5(data.encode()).hexdigest()[:8]

class HighPerformanceWebSocketManager:
    """Ultra-high performance WebSocket manager with intelligent caching and batching"""
    
    def __init__(self, db, socketio, max_cache_size=1000, batch_size=50):
        self.db = db
        self.socketio = socketio
        self.max_cache_size = max_cache_size
        self.batch_size = batch_size
        
        # State management
        self._device_states: Dict[int, DeviceState] = {}
        self._client_subscriptions: Dict[str, Set[str]] = defaultdict(set)
        self._update_queue = deque(maxlen=1000)
        self._dirty_devices: Set[int] = set()
        
        # Performance tracking
        self._performance_metrics = {
            'cache_hits': 0,
            'cache_misses': 0,
            'delta_updates_sent': 0,
            'full_updates_sent': 0,
            'batch_updates': 0
        }
        
        # Threading
        self._state_lock = RLock()
        self._queue_lock = Lock()
        
        # Timing
        self._last_full_refresh = time.time()
        self._last_cleanup = time.time()
        
    def get_optimized_device_data(self, force_refresh=False) -> List[Dict[str, Any]]:
        """Get device data with aggressive caching and optimization"""
        with self._state_lock:
            current_time = time.time()
            
            # Force refresh every 5 minutes or if requested
            if force_refresh or (current_time - self._last_full_refresh) > 300:
                self._refresh_device_cache()
                self._last_full_refresh = current_time
                self._performance_metrics['cache_misses'] += 1
            else:
                self._performance_metrics['cache_hits'] += 1
            
            # Convert cached states to API format
            return [asdict(state) for state in self._device_states.values()]
    
    def get_device_delta_update(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get only changed devices since last update for a specific client"""
        with self._state_lock:
            if not self._dirty_devices:
                return None
            
            # Get changes for dirty devices only
            changed_devices = []
            for device_id in list(self._dirty_devices):
                if device_id in self._device_states:
                    changed_devices.append(asdict(self._device_states[device_id]))
            
            if not changed_devices:
                return None
            
            # Clear dirty flag after sending
            self._dirty_devices.clear()
            
            self._performance_metrics['delta_updates_sent'] += 1
            
            return {
                'type': 'delta_update',
                'devices': changed_devices,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'count': len(changed_devices)
            }
    
    def update_device_state(self, device_id: int, **updates):
        """Efficiently update a single device state"""
        with self._state_lock:
            if device_id not in self._device_states:
                # Device not in cache, trigger refresh
                self._mark_device_dirty(device_id)
                return
            
            current_state = self._device_states[device_id]
            old_checksum = current_state.checksum
            
            # Update fields
            for field, value in updates.items():
                if hasattr(current_state, field):
                    setattr(current_state, field, value)
            
            # Recalculate checksum
            current_state.__post_init__()
            
            # Mark as dirty if changed
            if current_state.checksum != old_checksum:
                self._mark_device_dirty(device_id)
    
    def batch_update_devices(self, updates: List[Dict[str, Any]]):
        """Process multiple device updates in a single batch"""
        with self._state_lock:
            changes_detected = 0
            
            for update in updates:
                device_id = update.get('device_id')
                if not device_id:
                    continue
                
                old_checksum = None
                if device_id in self._device_states:
                    old_checksum = self._device_states[device_id].checksum
                
                # Update or create state
                self._update_single_device_state(device_id, update)
                
                # Check if changed
                if device_id in self._device_states:
                    new_checksum = self._device_states[device_id].checksum
                    if old_checksum != new_checksum:
                        self._mark_device_dirty(device_id)
                        changes_detected += 1
            
            if changes_detected > 0:
                self._performance_metrics['batch_updates'] += 1
                logger.debug(f"Batch update processed {changes_detected} changes")
    
    def subscribe_client(self, client_id: str, subscription_types: List[str]):
        """Subscribe client to specific update types"""
        self._client_subscriptions[client_id].update(subscription_types)
        logger.debug(f"Client {client_id} subscribed to: {subscription_types}")
    
    def unsubscribe_client(self, client_id: str, subscription_types: List[str] = None):
        """Unsubscribe client from update types"""
        if subscription_types:
            self._client_subscriptions[client_id] -= set(subscription_types)
        else:
            # Unsubscribe from all
            self._client_subscriptions.pop(client_id, None)
        
        logger.debug(f"Client {client_id} unsubscribed from: {subscription_types or 'all'}")
    
    def emit_optimized_update(self, update_type: str, data: Any, room: str = None):
        """Emit update with performance optimizations"""
        # Compress data if large
        if isinstance(data, (dict, list)):
            json_str = json.dumps(data)
            if len(json_str) > 10000:  # 10KB threshold
                # For large payloads, use delta updates or pagination
                if update_type == 'device_update' and isinstance(data, list):
                    self._emit_paginated_device_update(data, room)
                    return
        
        # Regular emit
        if room:
            self.socketio.emit(update_type, data, room=room)
        else:
            self.socketio.emit(update_type, data)
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        with self._state_lock:
            hit_rate = 0
            total_requests = self._performance_metrics['cache_hits'] + self._performance_metrics['cache_misses']
            if total_requests > 0:
                hit_rate = self._performance_metrics['cache_hits'] / total_requests
            
            return {
                'cache_size': len(self._device_states),
                'max_cache_size': self.max_cache_size,
                'cache_hit_rate': hit_rate,
                'dirty_devices': len(self._dirty_devices),
                'active_subscriptions': len(self._client_subscriptions),
                'performance_metrics': self._performance_metrics.copy(),
                'memory_usage_estimate_kb': self._estimate_memory_usage()
            }
    
    def cleanup(self):
        """Periodic cleanup of stale data"""
        current_time = time.time()
        
        if (current_time - self._last_cleanup) > 300:  # Every 5 minutes
            with self._state_lock:
                # Remove stale client subscriptions
                stale_clients = []
                for client_id in self._client_subscriptions:
                    # In a real implementation, check if client is still connected
                    # For now, keep all subscriptions
                    pass
                
                for client_id in stale_clients:
                    self._client_subscriptions.pop(client_id, None)
                
                # Limit cache size
                if len(self._device_states) > self.max_cache_size:
                    # Remove oldest entries (simple LRU)
                    excess = len(self._device_states) - self.max_cache_size
                    keys_to_remove = list(self._device_states.keys())[:excess]
                    for key in keys_to_remove:
                        self._device_states.pop(key, None)
                
                self._last_cleanup = current_time
                logger.debug("WebSocket cache cleanup completed")
    
    def _refresh_device_cache(self):
        """Refresh device cache from database"""
        try:
            from models import Device, MonitoringData, Alert
            from sqlalchemy import text, func, and_
            
            # Use the optimized single-query approach
            query = text("""
            SELECT 
                d.id, d.ip_address, 
                COALESCE(d.custom_name, d.hostname, d.ip_address) as display_name,
                d.last_seen,
                (SELECT response_time FROM monitoring_data 
                 WHERE device_id = d.id ORDER BY timestamp DESC LIMIT 1) as response_time,
                (SELECT COUNT(*) FROM alerts 
                 WHERE device_id = d.id AND resolved = 0) as active_alerts
            FROM devices d
            WHERE d.is_monitored = 1
            ORDER BY d.id
            """)
            
            result = self.db.session.execute(query)
            
            # Clear existing cache
            self._device_states.clear()
            
            # Populate cache
            for row in result:
                # Compute status efficiently
                status = 'unknown'
                if row.last_seen:
                    threshold = datetime.utcnow() - timedelta(seconds=600)
                    if row.last_seen >= threshold:
                        if row.response_time is None:
                            status = 'down'
                        elif row.response_time > 1000:
                            status = 'warning'
                        else:
                            status = 'up'
                    else:
                        status = 'down'
                
                device_state = DeviceState(
                    id=row.id,
                    ip_address=row.ip_address,
                    display_name=row.display_name,
                    status=status,
                    response_time=row.response_time,
                    last_seen=row.last_seen.isoformat() if row.last_seen else None,
                    active_alerts=row.active_alerts or 0
                )
                
                self._device_states[row.id] = device_state
            
            logger.info(f"Device cache refreshed with {len(self._device_states)} devices")
            
        except Exception as e:
            logger.error(f"Error refreshing device cache: {e}")
    
    def _update_single_device_state(self, device_id: int, update_data: Dict[str, Any]):
        """Update a single device state from update data"""
        # Implementation depends on update_data format
        # This is a placeholder for the actual update logic
        pass
    
    def _mark_device_dirty(self, device_id: int):
        """Mark device as dirty for delta updates"""
        self._dirty_devices.add(device_id)
    
    def _emit_paginated_device_update(self, devices: List[Dict], room: str = None):
        """Emit device updates in pages for large datasets"""
        page_size = 20
        total_pages = (len(devices) + page_size - 1) // page_size
        
        for page_num in range(total_pages):
            start_idx = page_num * page_size
            end_idx = min(start_idx + page_size, len(devices))
            
            page_data = {
                'type': 'device_page_update',
                'devices': devices[start_idx:end_idx],
                'page': page_num + 1,
                'total_pages': total_pages,
                'total_devices': len(devices),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            if room:
                self.socketio.emit('device_page_update', page_data, room=room)
            else:
                self.socketio.emit('device_page_update', page_data)
    
    def _estimate_memory_usage(self) -> int:
        """Estimate memory usage in KB"""
        # Rough estimate: each DeviceState ~200 bytes
        return len(self._device_states) * 200 // 1024

# Factory function
def create_websocket_optimizer(db, socketio) -> HighPerformanceWebSocketManager:
    """Create and configure WebSocket optimizer"""
    optimizer = HighPerformanceWebSocketManager(db, socketio)
    
    # Set up periodic cleanup
    import threading
    def cleanup_thread():
        while True:
            try:
                optimizer.cleanup()
                time.sleep(300)  # Every 5 minutes
            except Exception as e:
                logger.error(f"WebSocket cleanup error: {e}")
                time.sleep(60)  # Retry in 1 minute
    
    cleanup_worker = threading.Thread(target=cleanup_thread, daemon=True)
    cleanup_worker.start()
    
    logger.info("High-performance WebSocket optimizer initialized")
    return optimizer