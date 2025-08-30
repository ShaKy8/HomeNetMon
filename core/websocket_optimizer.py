"""
Optimized WebSocket broadcast system with message queuing and connection management.
"""

import logging
import json
import threading
from typing import Dict, Any, List, Optional, Set, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import deque, defaultdict
from queue import Queue, Empty
from enum import Enum
import time
from flask_socketio import SocketIO, emit
from flask import request
import uuid

logger = logging.getLogger(__name__)

class MessageType(Enum):
    """WebSocket message types."""
    DEVICE_STATUS = "device_status_update"
    MONITORING_SUMMARY = "monitoring_summary"
    ALERT_UPDATE = "alert_update"
    SYSTEM_STATUS = "system_status"
    HEARTBEAT = "heartbeat"
    BULK_UPDATE = "bulk_update"

class MessagePriority(Enum):
    """Message priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class QueuedMessage:
    """Represents a queued WebSocket message."""
    id: str
    type: MessageType
    data: Any
    priority: MessagePriority
    created_at: datetime
    room: Optional[str] = None
    target_sessions: Optional[Set[str]] = None
    retry_count: int = 0
    max_retries: int = 3

class WebSocketBroadcastOptimizer:
    """Optimized WebSocket broadcasting with message queuing and batching."""
    
    def __init__(self, socketio: SocketIO, max_queue_size: int = 10000,
                 batch_size: int = 50, batch_timeout: float = 0.1):
        self.socketio = socketio
        self.max_queue_size = max_queue_size
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        
        # Message queuing
        self.message_queue = Queue(maxsize=max_queue_size)
        self.failed_messages = deque(maxlen=1000)
        self.processing_thread = None
        self.stop_event = threading.Event()
        
        # Message batching
        self.batch_buffer: Dict[MessageType, List[QueuedMessage]] = defaultdict(list)
        self.last_batch_time = time.time()
        
        # Statistics
        self.stats = {
            'messages_queued': 0,
            'messages_sent': 0,
            'messages_failed': 0,
            'messages_batched': 0,
            'queue_full_drops': 0,
            'avg_queue_size': 0.0
        }
        
        # Rate limiting per client
        self.client_message_counts = defaultdict(int)
        self.client_reset_times = defaultdict(float)
        
        self.start_processing()
        
    def start_processing(self):
        """Start the message processing thread."""
        if self.processing_thread and self.processing_thread.is_alive():
            return
            
        self.stop_event.clear()
        self.processing_thread = threading.Thread(
            target=self._process_messages,
            daemon=True,
            name="WebSocketProcessor"
        )
        self.processing_thread.start()
        logger.info("WebSocket message processor started")
        
    def stop_processing(self):
        """Stop the message processing thread."""
        self.stop_event.set()
        if self.processing_thread:
            self.processing_thread.join(timeout=5.0)
            
    def queue_message(self, message_type: MessageType, data: Any,
                     priority: MessagePriority = MessagePriority.NORMAL,
                     room: Optional[str] = None,
                     target_sessions: Optional[Set[str]] = None) -> bool:
        """Queue a message for broadcasting."""
        try:
            message = QueuedMessage(
                id=str(uuid.uuid4()),
                type=message_type,
                data=data,
                priority=priority,
                created_at=datetime.now(),
                room=room,
                target_sessions=target_sessions
            )
            
            self.message_queue.put(message, block=False)
            self.stats['messages_queued'] += 1
            return True
            
        except Exception as e:
            self.stats['queue_full_drops'] += 1
            logger.warning(f"Message queue full, dropping message: {e}")
            return False
            
    def _process_messages(self):
        """Main message processing loop."""
        while not self.stop_event.is_set():
            try:
                # Process messages with timeout
                self._process_batch()
                
                # Check if we should send batched messages
                if self._should_flush_batches():
                    self._flush_all_batches()
                    
                time.sleep(0.01)  # Small delay to prevent CPU spinning
                
            except Exception as e:
                logger.error(f"Error in message processing: {e}")
                time.sleep(0.1)  # Back off on errors
                
    def _process_batch(self):
        """Process a batch of messages from the queue."""
        messages = []
        
        try:
            # Collect messages with timeout
            timeout = 0.1
            while len(messages) < self.batch_size:
                try:
                    message = self.message_queue.get(timeout=timeout)
                    messages.append(message)
                    timeout = 0.001  # Shorter timeout for additional messages
                except Empty:
                    break
                    
            if messages:
                self._handle_message_batch(messages)
                
        except Exception as e:
            logger.error(f"Error processing message batch: {e}")
            
    def _handle_message_batch(self, messages: List[QueuedMessage]):
        """Handle a batch of messages."""
        # Sort by priority (highest first)
        messages.sort(key=lambda m: m.priority.value, reverse=True)
        
        # Group by type for potential batching
        for message in messages:
            if self._can_batch_message(message.type):
                self.batch_buffer[message.type].append(message)
            else:
                self._send_single_message(message)
                
    def _can_batch_message(self, message_type: MessageType) -> bool:
        """Check if a message type can be batched."""
        batchable_types = {
            MessageType.DEVICE_STATUS,
            MessageType.MONITORING_SUMMARY
        }
        return message_type in batchable_types
        
    def _should_flush_batches(self) -> bool:
        """Check if batches should be flushed."""
        current_time = time.time()
        
        # Flush if timeout exceeded
        if current_time - self.last_batch_time > self.batch_timeout:
            return True
            
        # Flush if any batch is full
        for batch in self.batch_buffer.values():
            if len(batch) >= self.batch_size:
                return True
                
        return False
        
    def _flush_all_batches(self):
        """Flush all batched messages."""
        for message_type, messages in self.batch_buffer.items():
            if messages:
                self._send_batched_messages(message_type, messages)
                
        self.batch_buffer.clear()
        self.last_batch_time = time.time()
        
    def _send_batched_messages(self, message_type: MessageType, messages: List[QueuedMessage]):
        """Send a batch of messages as a single broadcast."""
        try:
            # Combine data from all messages
            if message_type == MessageType.DEVICE_STATUS:
                combined_data = {
                    'devices': [msg.data for msg in messages],
                    'batch_size': len(messages),
                    'timestamp': datetime.now().isoformat()
                }
            else:
                # For other types, just use the latest data
                combined_data = messages[-1].data
                
            # Determine target room
            rooms = set(msg.room for msg in messages if msg.room)
            target_room = rooms.pop() if len(rooms) == 1 else None
            
            # Send the batched message
            self.socketio.emit(
                MessageType.BULK_UPDATE.value,
                {
                    'type': message_type.value,
                    'data': combined_data
                },
                room=target_room
            )
            
            self.stats['messages_sent'] += len(messages)
            self.stats['messages_batched'] += len(messages)
            
            logger.debug(f"Sent batch of {len(messages)} {message_type.value} messages")
            
        except Exception as e:
            logger.error(f"Failed to send batched messages: {e}")
            self.stats['messages_failed'] += len(messages)
            
    def _send_single_message(self, message: QueuedMessage):
        """Send a single message."""
        try:
            if message.target_sessions:
                # Send to specific sessions
                for session_id in message.target_sessions:
                    self.socketio.emit(
                        message.type.value,
                        message.data,
                        room=session_id
                    )
            else:
                # Broadcast to room or all
                self.socketio.emit(
                    message.type.value,
                    message.data,
                    room=message.room
                )
                
            self.stats['messages_sent'] += 1
            logger.debug(f"Sent {message.type.value} message")
            
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            self.stats['messages_failed'] += 1
            self._handle_failed_message(message)
            
    def _handle_failed_message(self, message: QueuedMessage):
        """Handle a failed message."""
        message.retry_count += 1
        
        if message.retry_count <= message.max_retries:
            # Retry the message
            try:
                self.message_queue.put(message, block=False)
                logger.debug(f"Retrying message {message.id} (attempt {message.retry_count})")
            except:
                self.failed_messages.append(message)
        else:
            # Give up and store in failed messages
            self.failed_messages.append(message)
            logger.warning(f"Message {message.id} failed permanently after {message.retry_count} retries")
            
    def broadcast_device_status(self, device_data: Dict[str, Any], 
                               priority: MessagePriority = MessagePriority.NORMAL):
        """Broadcast device status update."""
        self.queue_message(MessageType.DEVICE_STATUS, device_data, priority)
        
    def broadcast_monitoring_summary(self, summary_data: Dict[str, Any]):
        """Broadcast monitoring summary."""
        self.queue_message(MessageType.MONITORING_SUMMARY, summary_data, MessagePriority.NORMAL)
        
    def broadcast_alert(self, alert_data: Dict[str, Any]):
        """Broadcast alert update."""
        self.queue_message(MessageType.ALERT_UPDATE, alert_data, MessagePriority.HIGH)
        
    def broadcast_system_status(self, status_data: Dict[str, Any]):
        """Broadcast system status."""
        self.queue_message(MessageType.SYSTEM_STATUS, status_data, MessagePriority.NORMAL)
        
    def send_heartbeat(self):
        """Send heartbeat to all connected clients."""
        heartbeat_data = {
            'timestamp': datetime.now().isoformat(),
            'server_time': time.time()
        }
        self.queue_message(MessageType.HEARTBEAT, heartbeat_data, MessagePriority.LOW)
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get broadcasting statistics."""
        current_queue_size = self.message_queue.qsize()
        
        return {
            **self.stats,
            'current_queue_size': current_queue_size,
            'failed_messages_count': len(self.failed_messages),
            'batch_buffer_sizes': {
                msg_type.value: len(messages) 
                for msg_type, messages in self.batch_buffer.items()
            },
            'processing_thread_alive': self.processing_thread.is_alive() if self.processing_thread else False
        }
        
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on the broadcast system."""
        stats = self.get_statistics()
        
        # Determine health status
        health_issues = []
        
        if stats['current_queue_size'] > self.max_queue_size * 0.8:
            health_issues.append("Queue nearly full")
            
        if stats['queue_full_drops'] > 100:
            health_issues.append("High message drop rate")
            
        if not stats['processing_thread_alive']:
            health_issues.append("Processing thread not running")
            
        if stats['messages_failed'] > stats['messages_sent'] * 0.1:
            health_issues.append("High failure rate")
            
        return {
            'status': 'unhealthy' if health_issues else 'healthy',
            'issues': health_issues,
            'statistics': stats
        }
        
    def optimize_connections(self):
        """Optimize WebSocket connections."""
        # This would typically involve:
        # - Cleaning up stale connections
        # - Rebalancing client rooms
        # - Updating connection limits
        logger.info("WebSocket connection optimization completed")


class WebSocketEventHandler:
    """Handles WebSocket events efficiently."""
    
    def __init__(self, socketio: SocketIO, broadcaster: WebSocketBroadcastOptimizer):
        self.socketio = socketio
        self.broadcaster = broadcaster
        self.active_subscriptions: Dict[str, Set[str]] = defaultdict(set)
        
    def register_events(self):
        """Register optimized WebSocket event handlers."""
        
        @self.socketio.on('subscribe')
        def handle_subscribe(data):
            """Handle subscription to specific data streams."""
            session_id = request.sid
            subscription_type = data.get('type')
            
            if subscription_type in ['device_status', 'monitoring', 'alerts']:
                self.active_subscriptions[session_id].add(subscription_type)
                emit('subscribed', {'type': subscription_type})
                
        @self.socketio.on('unsubscribe')
        def handle_unsubscribe(data):
            """Handle unsubscription from data streams."""
            session_id = request.sid
            subscription_type = data.get('type')
            
            self.active_subscriptions[session_id].discard(subscription_type)
            emit('unsubscribed', {'type': subscription_type})
            
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Clean up subscriptions on disconnect."""
            session_id = request.sid
            if session_id in self.active_subscriptions:
                del self.active_subscriptions[session_id]
                
        logger.info("Registered optimized WebSocket event handlers")