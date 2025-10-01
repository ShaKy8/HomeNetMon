"""
WebSocket Optimization Service for HomeNetMon
Provides optimized data fetching and delta updates for WebSocket handlers.
"""
import json
import time
import logging
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict
from sqlalchemy.orm import joinedload, selectinload
from sqlalchemy import and_, desc, func

logger = logging.getLogger(__name__)

class WebSocketDataOptimizer:
    """Optimizes data fetching for WebSocket handlers to prevent N+1 queries"""
    
    def __init__(self, db, socketio):
        self.db = db
        self.socketio = socketio
        self._last_device_states = {}
        self._last_alert_states = {}
        self._batch_update_cache = {}
        self._cache_ttl = 30  # 30 seconds
        
    def get_optimized_device_data(self) -> List[Dict[str, Any]]:
        """Get device data with cached optimization - MUCH FASTER"""
        try:
            # PERFORMANCE OPTIMIZATION: Use cached device data instead of expensive queries
            from services.query_cache import get_cached_device_list
            
            # Get app context from Flask
            from flask import current_app
            if current_app:
                device_list = get_cached_device_list(current_app.app_context)
                logger.debug(f"WebSocket optimizer using cached data for {len(device_list)} devices")
                return device_list
            else:
                logger.warning("No Flask app context available for cached data, falling back to database")
                return self._get_device_data_fallback_optimized()
                
        except Exception as e:
            logger.error(f"Error getting cached device data for WebSocket: {e}")
            return self._get_device_data_fallback_optimized()
    
    def _get_device_data_fallback_optimized(self) -> List[Dict[str, Any]]:
        """Fallback method with optimized queries"""
        from models import Device, MonitoringData, Alert, PerformanceMetrics
        
        try:
            # Single query to get all devices with their latest monitoring data
            # Using subquery to get latest monitoring data efficiently
            latest_monitoring_subquery = self.db.session.query(
                MonitoringData.device_id,
                func.max(MonitoringData.timestamp).label('latest_timestamp')
            ).group_by(MonitoringData.device_id).subquery()
            
            # Join devices with their latest monitoring data
            devices_with_monitoring = self.db.session.query(
                Device,
                MonitoringData.response_time,
                MonitoringData.timestamp.label('last_monitoring')
            ).outerjoin(
                latest_monitoring_subquery,
                Device.id == latest_monitoring_subquery.c.device_id
            ).outerjoin(
                MonitoringData,
                and_(
                    Device.id == MonitoringData.device_id,
                    MonitoringData.timestamp == latest_monitoring_subquery.c.latest_timestamp
                )
            ).all()
            
            # Get alert counts in a single query
            alert_counts = dict(
                self.db.session.query(
                    Alert.device_id,
                    func.count(Alert.id)
                ).filter(
                    Alert.resolved == False
                ).group_by(Alert.device_id).all()
            )
            
            # Get latest performance metrics in a single query
            latest_performance_subquery = self.db.session.query(
                PerformanceMetrics.device_id,
                func.max(PerformanceMetrics.timestamp).label('latest_perf_timestamp')
            ).group_by(PerformanceMetrics.device_id).subquery()
            
            performance_data = dict(
                self.db.session.query(
                    PerformanceMetrics.device_id,
                    PerformanceMetrics.health_score
                ).join(
                    latest_performance_subquery,
                    and_(
                        PerformanceMetrics.device_id == latest_performance_subquery.c.device_id,
                        PerformanceMetrics.timestamp == latest_performance_subquery.c.latest_perf_timestamp
                    )
                ).all()
            )
            
            # Build optimized device data
            devices_data = []
            for device, response_time, last_monitoring in devices_with_monitoring:
                device_data = self._build_device_data(
                    device, 
                    response_time, 
                    last_monitoring,
                    alert_counts.get(device.id, 0),
                    performance_data.get(device.id)
                )
                devices_data.append(device_data)
            
            return devices_data
            
        except Exception as e:
            logger.error(f"Error getting optimized device data: {e}")
            # Fallback to original method
            return self._get_device_data_fallback()
    
    def get_device_delta_update(self) -> Dict[str, Any]:
        """Get only changed device data for delta updates"""
        current_devices = self.get_optimized_device_data()
        
        delta_update = {
            'full_update': False,
            'changes': [],
            'removals': [],
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        # Create current state map
        current_state = {device['id']: device for device in current_devices}
        current_device_ids = set(current_state.keys())
        
        # Detect changes
        if self._last_device_states:
            last_device_ids = set(self._last_device_states.keys())
            
            # Find new and updated devices
            for device_id in current_device_ids:
                current_device = current_state[device_id]
                
                if device_id not in self._last_device_states:
                    # New device
                    delta_update['changes'].append({
                        'type': 'new',
                        'device': current_device
                    })
                else:
                    # Check for changes
                    last_device = self._last_device_states[device_id]
                    if self._device_has_changed(last_device, current_device):
                        delta_update['changes'].append({
                            'type': 'update',
                            'device': current_device,
                            'changed_fields': self._get_changed_fields(last_device, current_device)
                        })
            
            # Find removed devices
            for device_id in last_device_ids - current_device_ids:
                delta_update['removals'].append(device_id)
        else:
            # First time - send everything as new
            delta_update['full_update'] = True
            delta_update['changes'] = [{'type': 'new', 'device': device} for device in current_devices]
        
        # Update last state
        self._last_device_states = current_state
        
        # Only send delta if there are changes
        if delta_update['changes'] or delta_update['removals'] or delta_update['full_update']:
            return delta_update
        
        return None
    
    def get_optimized_alert_data(self) -> List[Dict[str, Any]]:
        """Get alert data with optimized queries"""
        from models import Alert, Device
        
        try:
            # Single query with join to get alerts with device info
            alerts_with_devices = self.db.session.query(
                Alert,
                Device.ip_address,
                Device.hostname,
                Device.custom_name
            ).join(
                Device, Alert.device_id == Device.id
            ).filter(
                Alert.resolved == False
            ).order_by(
                desc(Alert.created_at)
            ).all()
            
            alert_data = []
            for alert, ip_address, hostname, custom_name in alerts_with_devices:
                alert_dict = {
                    'id': alert.id,
                    'device_id': alert.device_id,
                    'device_name': custom_name or hostname or ip_address,
                    'device_ip': ip_address,
                    'alert_type': alert.alert_type,
                    'message': alert.message,
                    'severity': alert.severity,
                    'created_at': alert.created_at.isoformat() + 'Z',
                    'acknowledged': alert.acknowledged,
                    'acknowledged_at': alert.acknowledged_at.isoformat() + 'Z' if alert.acknowledged_at else None,
                    'acknowledged_by': alert.acknowledged_by
                }
                alert_data.append(alert_dict)
            
            return alert_data
            
        except Exception as e:
            logger.error(f"Error getting optimized alert data: {e}")
            return []
    
    def get_optimized_chart_data(self, chart_type: str, device_id: int = None, hours: int = 24) -> Dict[str, Any]:
        """Get chart data with optimized queries"""
        from models import MonitoringData, Device, PerformanceMetrics
        
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            if chart_type == 'response_time' and device_id:
                # Optimized query for single device response time
                data_points = self.db.session.query(
                    MonitoringData.timestamp,
                    MonitoringData.response_time
                ).filter(
                    and_(
                        MonitoringData.device_id == device_id,
                        MonitoringData.timestamp >= cutoff_time,
                        MonitoringData.response_time.isnot(None)
                    )
                ).order_by(MonitoringData.timestamp).limit(1000).all()
                
                chart_data = [{
                    'timestamp': point.timestamp.isoformat() + 'Z',
                    'value': point.response_time
                } for point in data_points]
                
            elif chart_type == 'network_overview':
                # Optimized query for network overview
                # Get average response time per device for the last hour
                hourly_avg = self.db.session.query(
                    Device.ip_address,
                    Device.custom_name,
                    Device.hostname,
                    func.avg(MonitoringData.response_time).label('avg_response_time'),
                    func.count(MonitoringData.id).label('ping_count')
                ).join(
                    MonitoringData, Device.id == MonitoringData.device_id
                ).filter(
                    and_(
                        MonitoringData.timestamp >= cutoff_time,
                        MonitoringData.response_time.isnot(None)
                    )
                ).group_by(Device.id).all()
                
                chart_data = []
                for device_ip, custom_name, hostname, avg_rt, ping_count in hourly_avg:
                    chart_data.append({
                        'device_name': custom_name or hostname or device_ip,
                        'device_ip': device_ip,
                        'avg_response_time': round(float(avg_rt), 2) if avg_rt else None,
                        'ping_count': ping_count
                    })
            
            else:
                chart_data = []
            
            return {
                'type': chart_type,
                'device_id': device_id,
                'data': chart_data,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
        except Exception as e:
            logger.error(f"Error getting optimized chart data: {e}")
            return {'type': chart_type, 'data': [], 'error': str(e)}
    
    def _build_device_data(self, device, response_time, last_monitoring, alert_count, health_score):
        """Build device data dictionary with optimized field access"""
        # Calculate status without triggering additional queries
        status = self._calculate_status(device, response_time, last_monitoring)
        
        # Calculate performance grade from health score
        performance_grade = self._calculate_performance_grade(health_score)
        performance_status = self._calculate_performance_status(health_score)
        
        return {
            'id': device.id,
            'ip_address': device.ip_address,
            'mac_address': device.mac_address,
            'hostname': device.hostname,
            'vendor': device.vendor,
            'custom_name': device.custom_name,
            'display_name': device.custom_name or device.hostname or device.ip_address,
            'device_type': device.device_type,
            'device_group': device.device_group,
            'is_monitored': device.is_monitored,
            'status': status,
            'latest_response_time': response_time,
            'last_seen': device.last_seen.isoformat() + 'Z' if device.last_seen else None,
            'active_alerts': alert_count,
            'current_health_score': health_score,
            'performance_grade': performance_grade,
            'performance_status': performance_status,
            'created_at': device.created_at.isoformat() + 'Z',
            'last_updated': device.last_updated.isoformat() + 'Z' if device.last_updated else None
        }
    
    def _calculate_status(self, device, response_time, last_monitoring):
        """Calculate device status without additional queries"""
        if not device.last_seen:
            return 'unknown'
        
        threshold = datetime.utcnow() - timedelta(seconds=600)
        if device.last_seen < threshold:
            return 'down'
        
        if response_time is None:
            return 'down'
        elif response_time > 1000:
            return 'warning'
        
        return 'up'
    
    def _calculate_performance_grade(self, health_score):
        """Calculate performance grade from health score"""
        if health_score is None:
            return 'N/A'
        elif health_score >= 95:
            return 'A+'
        elif health_score >= 90:
            return 'A'
        elif health_score >= 85:
            return 'B+'
        elif health_score >= 80:
            return 'B'
        elif health_score >= 75:
            return 'C+'
        elif health_score >= 70:
            return 'C'
        elif health_score >= 65:
            return 'D+'
        elif health_score >= 60:
            return 'D'
        else:
            return 'F'
    
    def _calculate_performance_status(self, health_score):
        """Calculate performance status from health score"""
        if health_score is None:
            return 'unknown'
        elif health_score >= 90:
            return 'excellent'
        elif health_score >= 80:
            return 'good'
        elif health_score >= 70:
            return 'fair'
        elif health_score >= 60:
            return 'poor'
        else:
            return 'critical'
    
    def _device_has_changed(self, old_device: Dict, new_device: Dict) -> bool:
        """Check if device data has changed significantly"""
        # Fields to check for changes
        check_fields = [
            'status', 'latest_response_time', 'last_seen', 'active_alerts',
            'current_health_score', 'performance_grade', 'performance_status',
            'custom_name', 'hostname', 'is_monitored'
        ]
        
        for field in check_fields:
            if old_device.get(field) != new_device.get(field):
                return True
        
        return False
    
    def _get_changed_fields(self, old_device: Dict, new_device: Dict) -> List[str]:
        """Get list of changed fields"""
        changed_fields = []
        check_fields = [
            'status', 'latest_response_time', 'last_seen', 'active_alerts',
            'current_health_score', 'performance_grade', 'performance_status',
            'custom_name', 'hostname', 'is_monitored'
        ]
        
        for field in check_fields:
            if old_device.get(field) != new_device.get(field):
                changed_fields.append(field)
        
        return changed_fields
    
    def _get_device_data_fallback(self):
        """Fallback method using original approach"""
        from models import Device
        devices = Device.query.all()
        return [device.to_dict() for device in devices]
    
    def get_batch_update_summary(self) -> Dict[str, Any]:
        """Get summary of batch updates for monitoring"""
        return {
            'cache_size': len(self._batch_update_cache),
            'last_device_states': len(self._last_device_states),
            'last_alert_states': len(self._last_alert_states),
            'cache_ttl': self._cache_ttl
        }
    
    def clear_update_cache(self):
        """Clear the update cache"""
        self._last_device_states.clear()
        self._last_alert_states.clear()
        self._batch_update_cache.clear()

# Global instance (will be initialized in app.py)
websocket_optimizer = None

def init_websocket_optimizer(db, socketio):
    """Initialize the global websocket optimizer"""
    global websocket_optimizer
    websocket_optimizer = WebSocketDataOptimizer(db, socketio)
    return websocket_optimizer