import logging
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from werkzeug.security import generate_password_hash, check_password_hash
import json
import secrets
logger = logging.getLogger(__name__)

# Import performance cache decorators
try:
    from services.performance_cache import cached_property, cache_invalidator
except ImportError:
    # Fallback if cache service not available
    def cached_property(ttl=300, key_func=None, invalidate_on=None):
        def decorator(func):
            return property(func)
        return decorator
    
    class DummyInvalidator:
        def invalidate_device_cache(self, device_id):
            pass
    
    cache_invalidator = DummyInvalidator()

db = SQLAlchemy()


class Device(db.Model):
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), unique=True, nullable=False, index=True)
    mac_address = db.Column(db.String(17), index=True)
    hostname = db.Column(db.String(255))
    vendor = db.Column(db.String(255))
    custom_name = db.Column(db.String(255))
    device_type = db.Column(db.String(50))  # router, computer, phone, iot, etc.
    device_group = db.Column(db.String(100))  # Custom grouping
    room_location = db.Column(db.String(100))  # Home-friendly room assignment (Living Room, Kitchen, etc.)
    device_priority = db.Column(db.String(20), default='normal')  # critical, important, normal, optional
    is_monitored = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_seen = db.Column(db.DateTime, index=True)  # Index for status checks and sorting

    # Relationships
    monitoring_data = db.relationship('MonitoringData', backref='device', cascade='all, delete-orphan', lazy=True)
    alerts = db.relationship('Alert', backref='device', cascade='all, delete-orphan', lazy=True)
    
    def __repr__(self):
        return f'<Device {self.ip_address} ({self.display_name})>'
    
    @property
    def display_name(self):
        return self.custom_name or self.hostname or self.ip_address
    
    @cached_property(ttl=30, key_func=lambda self: f"device_{self.id}_status")
    def status(self):
        if not self.last_seen:
            return 'unknown'

        # Consider device down if not seen for more than 15 minutes (900 seconds)
        # This accounts for ping interval (600s) plus buffer for network delays
        from config import Config
        threshold = datetime.utcnow() - timedelta(seconds=900)

        if self.last_seen < threshold:
            return 'down'

        # Check latest monitoring data for response time to determine warning state
        # Only check if device was seen recently (within threshold)
        latest_data = MonitoringData.query.filter_by(device_id=self.id)\
                                         .order_by(MonitoringData.timestamp.desc())\
                                         .first()

        if latest_data:
            # Don't mark as down based on single failed ping if recently seen
            # Only check for high response time (warning state)
            if latest_data.response_time is not None and latest_data.response_time > 1000:  # >1 second
                return 'warning'

        return 'up'
    
    @cached_property(ttl=30, key_func=lambda self: f"device_{self.id}_response_time")
    def latest_response_time(self):
        """Get the latest response time for this device"""
        try:
            with db.session.begin():
                latest_data = db.session.query(MonitoringData).filter_by(device_id=self.id)\
                                             .order_by(MonitoringData.timestamp.desc())\
                                             .first()
                return latest_data.response_time if latest_data else None
        except Exception:
            return None
    
    @cached_property(ttl=60, key_func=lambda self: f"device_{self.id}_active_alerts")
    def active_alerts(self):
        """Get count of active (unresolved) alerts for this device"""
        try:
            with db.session.begin():
                return db.session.query(Alert).filter_by(device_id=self.id, resolved=False).count()
        except Exception:
            return 0
    
    def uptime_percentage(self, days=7):
        """Calculate uptime percentage with intelligent downtime detection"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        # Get all monitoring data for the time period, ordered by timestamp
        monitoring_data = MonitoringData.query.filter(
            MonitoringData.device_id == self.id,
            MonitoringData.timestamp >= cutoff
        ).order_by(MonitoringData.timestamp).all()
        
        if not monitoring_data:
            return 0
        
        # Use sliding window approach to identify true downtime periods
        # This reduces impact of isolated ping failures and focuses on sustained downtime
        total_time_seconds = (datetime.utcnow() - cutoff).total_seconds()
        downtime_seconds = 0
        
        # Group consecutive failures to identify downtime periods
        failure_periods = []
        current_failure_start = None
        consecutive_failures = 0
        
        for i, data_point in enumerate(monitoring_data):
            is_failure = data_point.response_time is None
            
            if is_failure:
                consecutive_failures += 1
                if current_failure_start is None:
                    current_failure_start = data_point.timestamp
            else:
                # Success - check if we need to close a failure period
                if current_failure_start is not None and consecutive_failures >= 2:
                    # Only count as downtime if there were 2+ consecutive failures
                    # This filters out isolated ping timeouts that don't represent real downtime
                    failure_periods.append({
                        'start': current_failure_start,
                        'end': data_point.timestamp,
                        'duration': (data_point.timestamp - current_failure_start).total_seconds()
                    })
                
                # Reset failure tracking
                current_failure_start = None
                consecutive_failures = 0
        
        # Handle case where failure period extends to the end
        if current_failure_start is not None and consecutive_failures >= 2:
            failure_periods.append({
                'start': current_failure_start,
                'end': datetime.utcnow(),
                'duration': (datetime.utcnow() - current_failure_start).total_seconds()
            })
        
        # Sum up downtime from all failure periods
        total_downtime_seconds = sum(period['duration'] for period in failure_periods)
        
        # Calculate uptime percentage
        if total_time_seconds <= 0:
            return 0
        
        uptime_seconds = total_time_seconds - total_downtime_seconds
        uptime_percentage = (uptime_seconds / total_time_seconds) * 100
        
        # Ensure we don't go below 0 or above 100
        uptime_percentage = max(0, min(100, uptime_percentage))
        
        return round(uptime_percentage, 2)
    
    def get_current_bandwidth(self):
        """Get current bandwidth usage for this device"""
        try:
            latest_bandwidth = db.session.query(db.func.max(db.table('bandwidth_data').c.id))\
                                        .filter(db.table('bandwidth_data').c.device_id == self.id)\
                                        .scalar()
            if latest_bandwidth:
                bandwidth_data = db.session.execute(
                    db.text("SELECT bandwidth_in_mbps, bandwidth_out_mbps, timestamp FROM bandwidth_data WHERE id = :id"),
                    {'id': latest_bandwidth}
                ).fetchone()
                if bandwidth_data:
                    return {
                        'in_mbps': bandwidth_data[0],
                        'out_mbps': bandwidth_data[1], 
                        'total_mbps': bandwidth_data[0] + bandwidth_data[1],
                        'timestamp': bandwidth_data[2]
                    }
        except Exception:
            # Return None if bandwidth data is not available
            pass
        return None
    
    def get_bandwidth_usage_24h(self):
        """Get 24-hour bandwidth usage statistics"""
        try:
            cutoff = datetime.utcnow() - timedelta(hours=24)
            result = db.session.execute(
                db.text("""
                    SELECT 
                        SUM(bytes_in) as total_bytes_in,
                        SUM(bytes_out) as total_bytes_out,
                        AVG(bandwidth_in_mbps) as avg_bandwidth_in,
                        AVG(bandwidth_out_mbps) as avg_bandwidth_out,
                        MAX(bandwidth_in_mbps + bandwidth_out_mbps) as peak_bandwidth
                    FROM bandwidth_data 
                    WHERE device_id = :device_id AND timestamp >= :cutoff
                """),
                {'device_id': self.id, 'cutoff': cutoff}
            ).fetchone()
            
            if result and result[0] is not None:
                return {
                    'total_gb_in': round(result[0] / (1024**3), 2) if result[0] else 0,
                    'total_gb_out': round(result[1] / (1024**3), 2) if result[1] else 0,
                    'avg_mbps_in': round(result[2], 2) if result[2] else 0,
                    'avg_mbps_out': round(result[3], 2) if result[3] else 0,
                    'peak_mbps': round(result[4], 2) if result[4] else 0
                }
        except Exception:
            # Return None if bandwidth data is not available
            pass
        return None
    
    @cached_property(ttl=120, key_func=lambda self: f"device_{self.id}_health_score")
    def current_health_score(self):
        """Get the latest health score for this device"""
        try:
            with db.session.begin():
                latest_performance = db.session.query(PerformanceMetrics).filter_by(device_id=self.id)\
                                                             .order_by(PerformanceMetrics.timestamp.desc())\
                                                             .first()
                return latest_performance.health_score if latest_performance else None
        except Exception:
            return None
    
    @cached_property(ttl=120, key_func=lambda self: f"device_{self.id}_performance_grade")
    def performance_grade(self):
        """Get performance grade based on current health score"""
        health_score = self.current_health_score
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
    
    @cached_property(ttl=120, key_func=lambda self: f"device_{self.id}_performance_status")
    def performance_status(self):
        """Get performance status based on current health score"""
        health_score = self.current_health_score
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
    
    def get_performance_metrics(self, hours=24):
        """Get performance metrics for specified time period"""
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            metrics = PerformanceMetrics.query.filter(
                PerformanceMetrics.device_id == self.id,
                PerformanceMetrics.timestamp >= cutoff
            ).order_by(PerformanceMetrics.timestamp.desc()).all()
            
            return [metric.to_dict() for metric in metrics]
        except Exception:
            return []
    
    def get_performance_summary(self, hours=24):
        """Get summarized performance metrics"""
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            
            # Get response time statistics
            response_stats = db.session.execute(
                db.text("""
                    SELECT 
                        AVG(response_time) as avg_response,
                        MIN(response_time) as min_response,
                        MAX(response_time) as max_response,
                        COUNT(*) as total_checks,
                        COUNT(CASE WHEN response_time IS NOT NULL THEN 1 END) as successful_checks
                    FROM monitoring_data 
                    WHERE device_id = :device_id AND timestamp >= :cutoff
                """),
                {'device_id': self.id, 'cutoff': cutoff}
            ).fetchone()
            
            # Get bandwidth statistics
            bandwidth_stats = db.session.execute(
                db.text("""
                    SELECT 
                        AVG(bandwidth_in_mbps) as avg_in,
                        AVG(bandwidth_out_mbps) as avg_out,
                        MAX(bandwidth_in_mbps) as peak_in,
                        MAX(bandwidth_out_mbps) as peak_out,
                        SUM(bytes_in) as total_bytes_in,
                        SUM(bytes_out) as total_bytes_out
                    FROM bandwidth_data 
                    WHERE device_id = :device_id AND timestamp >= :cutoff
                """),
                {'device_id': self.id, 'cutoff': cutoff}
            ).fetchone()
            
            # Get latest performance metrics
            latest_performance = PerformanceMetrics.query.filter_by(device_id=self.id)\
                                                         .order_by(PerformanceMetrics.timestamp.desc())\
                                                         .first()
            
            # Calculate uptime percentage
            uptime_pct = 0
            if response_stats and response_stats[3] > 0:  # total_checks > 0
                uptime_pct = (response_stats[4] / response_stats[3]) * 100  # successful/total
            
            return {
                'device_id': self.id,
                'device_name': self.display_name,
                'device_ip': self.ip_address,
                'period_hours': hours,
                'summary_timestamp': datetime.utcnow().isoformat() + 'Z',
                
                # Response time metrics
                'response_metrics': {
                    'avg_ms': round(response_stats[0], 2) if response_stats and response_stats[0] else None,
                    'min_ms': round(response_stats[1], 2) if response_stats and response_stats[1] else None,
                    'max_ms': round(response_stats[2], 2) if response_stats and response_stats[2] else None,
                    'total_checks': response_stats[3] if response_stats else 0,
                    'successful_checks': response_stats[4] if response_stats else 0
                },
                
                # Availability metrics
                'availability_metrics': {
                    'uptime_percentage': round(uptime_pct, 2),
                    'status': self.status
                },
                
                # Bandwidth metrics
                'bandwidth_metrics': {
                    'avg_in_mbps': round(bandwidth_stats[0], 2) if bandwidth_stats and bandwidth_stats[0] else 0,
                    'avg_out_mbps': round(bandwidth_stats[1], 2) if bandwidth_stats and bandwidth_stats[1] else 0,
                    'peak_in_mbps': round(bandwidth_stats[2], 2) if bandwidth_stats and bandwidth_stats[2] else 0,
                    'peak_out_mbps': round(bandwidth_stats[3], 2) if bandwidth_stats and bandwidth_stats[3] else 0,
                    'total_gb_in': round((bandwidth_stats[4] or 0) / (1024**3), 3),
                    'total_gb_out': round((bandwidth_stats[5] or 0) / (1024**3), 3)
                },
                
                # Health scores
                'health_scores': {
                    'overall_health': latest_performance.health_score if latest_performance else None,
                    'responsiveness': latest_performance.responsiveness_score if latest_performance else None,
                    'reliability': latest_performance.reliability_score if latest_performance else None,
                    'efficiency': latest_performance.efficiency_score if latest_performance else None,
                    'stability': latest_performance.connection_stability_score if latest_performance else None,
                    'performance_grade': self.performance_grade,
                    'performance_status': self.performance_status
                }
            }
            
        except Exception as e:
            print(f"Error getting performance summary for device {self.id}: {e}")
            return {
                'device_id': self.id,
                'device_name': self.display_name,
                'device_ip': self.ip_address,
                'error': str(e)
            }
    
    def get_avg_response_time(self, hours=24):
        """Get average response time for specified time period, excluding timeouts"""
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            
            # Get all monitoring data with valid response times (exclude timeouts/failures)
            avg_response = db.session.query(db.func.avg(MonitoringData.response_time))\
                .filter(
                    MonitoringData.device_id == self.id,
                    MonitoringData.timestamp >= cutoff,
                    MonitoringData.response_time.isnot(None),
                    MonitoringData.response_time > 0
                ).scalar()
            
            return round(avg_response, 2) if avg_response else None
            
        except Exception as e:
            print(f"Error calculating average response time for device {self.id}: {e}")
            return None
    
    def is_online(self):
        """Check if device is currently online based on last_seen timestamp"""
        if not self.last_seen:
            return False
        
        # Consider device online if seen within last 10 minutes (600 seconds)
        threshold = datetime.utcnow() - timedelta(seconds=600)
        return self.last_seen > threshold
    
    def get_status_history(self, hours=6):
        """Get device status history for specified time period"""
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            
            # Get monitoring data ordered by timestamp
            monitoring_data = MonitoringData.query.filter(
                MonitoringData.device_id == self.id,
                MonitoringData.timestamp >= cutoff
            ).order_by(MonitoringData.timestamp).all()
            
            history = []
            for data in monitoring_data:
                # Determine status based on response time and packet loss
                if data.response_time is None:
                    status = 'down'
                elif data.response_time > 1000:  # 1 second threshold
                    status = 'warning'
                else:
                    status = 'up'
                
                history.append({
                    'timestamp': data.timestamp,
                    'status': status,
                    'response_time': data.response_time,
                    'packet_loss': data.packet_loss
                })
            
            return history
            
        except Exception as e:
            print(f"Error getting status history for device {self.id}: {e}")
            return []
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'hostname': self.hostname,
            'vendor': self.vendor,
            'custom_name': self.custom_name,
            'device_type': self.device_type,
            'device_group': self.device_group,
            'room_location': self.room_location,
            'device_priority': self.device_priority,
            'display_name': self.display_name,
            'is_monitored': self.is_monitored,
            'status': self.status,
            'uptime_percentage': self.uptime_percentage(),
            'current_bandwidth': self.get_current_bandwidth(),
            'bandwidth_usage_24h': self.get_bandwidth_usage_24h(),
            'health_score': self.current_health_score,
            'performance_grade': self.performance_grade,
            'performance_status': self.performance_status,
            'created_at': (self.created_at.isoformat() + 'Z') if self.created_at else None,
            'updated_at': (self.updated_at.isoformat() + 'Z') if self.updated_at else None,
            'last_seen': (self.last_seen.isoformat() + 'Z') if self.last_seen else None,
        }

    def to_dict_fast(self, monitoring_data=None, alert_count=0, uptime_pct=None):
        """
        Fast serialization that uses pre-fetched data instead of per-device queries.
        Use with batch_get_device_data() for N+1 query elimination.
        """
        # Calculate status from last_seen without additional queries
        status = 'unknown'
        if self.last_seen:
            threshold = datetime.utcnow() - timedelta(seconds=900)
            if self.last_seen >= threshold:
                # Check for warning state from pre-fetched monitoring data
                if monitoring_data and monitoring_data.response_time is not None:
                    if monitoring_data.response_time > 1000:
                        status = 'warning'
                    else:
                        status = 'up'
                else:
                    status = 'up'
            else:
                status = 'down'

        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'hostname': self.hostname,
            'vendor': self.vendor,
            'custom_name': self.custom_name,
            'device_type': self.device_type,
            'device_group': self.device_group,
            'room_location': self.room_location,
            'device_priority': self.device_priority,
            'display_name': self.display_name,
            'is_monitored': self.is_monitored,
            'status': status,
            'uptime_percentage': uptime_pct if uptime_pct is not None else 0,
            'active_alerts': alert_count,
            'latest_response_time': monitoring_data.response_time if monitoring_data else None,
            'latest_check': monitoring_data.timestamp.isoformat() + 'Z' if monitoring_data else None,
            'created_at': (self.created_at.isoformat() + 'Z') if self.created_at else None,
            'updated_at': (self.updated_at.isoformat() + 'Z') if self.updated_at else None,
            'last_seen': (self.last_seen.isoformat() + 'Z') if self.last_seen else None,
        }

    @classmethod
    def batch_get_device_data(cls, device_ids, include_uptime=False, uptime_days=7):
        """
        Batch fetch all related data for multiple devices in minimal queries.
        Returns dict with monitoring_data, alert_counts, and optionally uptime_percentages.

        This eliminates N+1 queries by fetching all data upfront.
        """
        from sqlalchemy import func, and_

        result = {
            'monitoring_data': {},  # device_id -> MonitoringData
            'alert_counts': {},     # device_id -> count
            'uptime_percentages': {}  # device_id -> percentage (if include_uptime=True)
        }

        if not device_ids:
            return result

        # 1. Get latest monitoring data for all devices in ONE query
        latest_monitoring_subquery = db.session.query(
            MonitoringData.device_id,
            func.max(MonitoringData.timestamp).label('max_timestamp')
        ).filter(MonitoringData.device_id.in_(device_ids)).group_by(MonitoringData.device_id).subquery()

        latest_monitoring = db.session.query(MonitoringData).join(
            latest_monitoring_subquery,
            and_(
                MonitoringData.device_id == latest_monitoring_subquery.c.device_id,
                MonitoringData.timestamp == latest_monitoring_subquery.c.max_timestamp
            )
        ).all()

        result['monitoring_data'] = {md.device_id: md for md in latest_monitoring}

        # 2. Get active alert counts for all devices in ONE query
        alert_counts = db.session.query(
            Alert.device_id,
            func.count(Alert.id).label('count')
        ).filter(
            Alert.device_id.in_(device_ids),
            Alert.resolved == False
        ).group_by(Alert.device_id).all()

        result['alert_counts'] = {ac.device_id: ac.count for ac in alert_counts}

        # 3. Calculate uptime percentages if requested (requires more data)
        if include_uptime:
            cutoff = datetime.utcnow() - timedelta(days=uptime_days)

            # Get success/failure counts per device in ONE query
            uptime_stats = db.session.query(
                MonitoringData.device_id,
                func.count(MonitoringData.id).label('total'),
                func.count(MonitoringData.response_time).label('successful')
            ).filter(
                MonitoringData.device_id.in_(device_ids),
                MonitoringData.timestamp >= cutoff
            ).group_by(MonitoringData.device_id).all()

            for stat in uptime_stats:
                if stat.total > 0:
                    pct = (stat.successful / stat.total) * 100
                    result['uptime_percentages'][stat.device_id] = round(pct, 2)

        return result

    @classmethod
    def get_all_with_batch_data(cls, query=None, include_uptime=False):
        """
        Get devices with all related data pre-fetched.
        Returns list of (device, monitoring_data, alert_count, uptime_pct) tuples.
        """
        if query is None:
            query = cls.query

        devices = query.all()
        device_ids = [d.id for d in devices]

        batch_data = cls.batch_get_device_data(device_ids, include_uptime=include_uptime)

        results = []
        for device in devices:
            monitoring_data = batch_data['monitoring_data'].get(device.id)
            alert_count = batch_data['alert_counts'].get(device.id, 0)
            uptime_pct = batch_data['uptime_percentages'].get(device.id, 0) if include_uptime else None
            results.append((device, monitoring_data, alert_count, uptime_pct))

        return results


# Event listener to invalidate status cache when last_seen changes
@event.listens_for(Device.last_seen, 'set')
def invalidate_status_cache_on_last_seen_change(target, value, oldvalue, initiator):
    """Invalidate device status cache when last_seen changes to prevent stale status."""
    if value != oldvalue and target.id:
        try:
            cache_invalidator.invalidate_device_cache(target.id)
        except Exception:
            pass  # Don't let cache issues break the update


class DeviceIpHistory(db.Model):
    """Track IP address changes for devices over time"""
    __tablename__ = 'device_ip_history'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    old_ip_address = db.Column(db.String(15), nullable=True)  # Previous IP (null for first record)
    new_ip_address = db.Column(db.String(15), nullable=False)  # New/current IP
    change_detected_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    change_source = db.Column(db.String(50), default='auto_discovery')  # auto_discovery, manual_update, etc.
    notes = db.Column(db.String(500))  # Optional notes about the change
    
    # Relationship back to device
    device = db.relationship('Device', backref='ip_history', lazy=True)
    
    def __repr__(self):
        return f'<DeviceIpHistory {self.device_id}: {self.old_ip_address} -> {self.new_ip_address}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'old_ip_address': self.old_ip_address,
            'new_ip_address': self.new_ip_address,
            'change_detected_at': self.change_detected_at.isoformat() + 'Z' if self.change_detected_at else None,
            'change_source': self.change_source,
            'notes': self.notes
        }

class MonitoringData(db.Model):
    __tablename__ = 'monitoring_data'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    response_time = db.Column(db.Float)  # in milliseconds, None if no response
    packet_loss = db.Column(db.Float, default=0.0)  # percentage
    additional_data = db.Column(db.Text)  # JSON string for extra metrics
    
    def __repr__(self):
        return f'<MonitoringData {self.device.ip_address} at {self.timestamp}>'
    
    def is_successful(self):
        """Check if this monitoring data represents a successful ping"""
        # Consider it successful if we have a response time and packet loss is not 100%
        return (self.response_time is not None and 
                self.response_time > 0 and 
                self.packet_loss < 100.0)
    
    def get_quality_score(self):
        """Calculate a quality score (0-100) based on response time and packet loss"""
        if self.response_time is None or self.packet_loss >= 100.0:
            return 0  # Complete failure
        
        # Base score starts at 100
        score = 100.0
        
        # Reduce score based on response time (more aggressive penalty)
        if self.response_time > 0:
            # Excellent: 0-10ms, Good: 10-30ms, Fair: 30-100ms, Poor: 100ms+
            if self.response_time <= 10:
                response_penalty = 0
            elif self.response_time <= 30:
                response_penalty = (self.response_time - 10) * 1.0  # Up to 20 point penalty
            elif self.response_time <= 100:
                response_penalty = 20 + (self.response_time - 30) * 0.5  # Up to 55 point penalty
            else:
                response_penalty = 55 + min((self.response_time - 100) * 0.3, 35)  # Up to 90 point penalty
            
            score -= response_penalty
        
        # Reduce score based on packet loss (linear)
        packet_loss_penalty = self.packet_loss * 2  # 2 points per 1% packet loss
        score -= packet_loss_penalty
        
        # Ensure score is between 0 and 100
        return max(0, min(100, int(score)))
    
    def get_performance_category(self):
        """Get performance category based on quality score"""
        # Special case for timeouts/failures
        if self.response_time is None or self.packet_loss >= 100.0:
            return 'failed'
            
        quality_score = self.get_quality_score()
        
        if quality_score >= 85:
            return 'excellent'
        elif quality_score >= 65:
            return 'good'
        elif quality_score >= 40:
            return 'fair'
        else:
            return 'poor'

    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'timestamp': self.timestamp.isoformat() + 'Z',  # Add Z to indicate UTC timezone
            'response_time': self.response_time,
            'packet_loss': self.packet_loss,
            'additional_data': json.loads(self.additional_data) if self.additional_data else None,
        }

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    alert_type = db.Column(db.String(50), nullable=False, index=True)  # device_down, high_latency, etc.
    alert_subtype = db.Column(db.String(50), nullable=True)  # performance_critical, performance_warning, etc.
    severity = db.Column(db.String(20), default='warning', index=True)  # info, warning, critical
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    acknowledged = db.Column(db.Boolean, default=False, index=True)
    acknowledged_at = db.Column(db.DateTime)
    acknowledged_by = db.Column(db.String(100))  # username or system
    resolved = db.Column(db.Boolean, default=False, index=True)
    resolved_at = db.Column(db.DateTime)
    
    # Priority scoring fields
    priority_score = db.Column(db.Integer, default=50)  # 0-100 priority score
    priority_level = db.Column(db.String(20), default='MEDIUM')  # CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
    priority_breakdown = db.Column(db.Text)  # JSON string of priority calculation breakdown
    
    # Notification correlation
    notification_sent = db.Column(db.Boolean, default=False)  # Whether notification was sent for this alert
    notification_count = db.Column(db.Integer, default=0)  # Number of notifications sent
    last_notification_at = db.Column(db.DateTime)  # When last notification was sent
    notification_status = db.Column(db.String(20), default='pending')  # pending, sent, failed, none
    
    def __repr__(self):
        return f'<Alert {self.alert_type} for {self.device.ip_address}>'
    
    def acknowledge(self, acknowledged_by='system'):
        self.acknowledged = True
        self.acknowledged_at = datetime.utcnow()
        self.acknowledged_by = acknowledged_by
        db.session.commit()
    
    def resolve(self):
        self.resolved = True
        self.resolved_at = datetime.utcnow()
        db.session.commit()
    
    def calculate_and_update_priority(self, app=None):
        """Calculate and update the priority score for this alert"""
        try:
            from services.alert_priority import AlertPriorityScorer
            
            scorer = AlertPriorityScorer(app)
            score, level, breakdown = scorer.calculate_priority_score(self)
            
            self.priority_score = score
            self.priority_level = level
            self.priority_breakdown = json.dumps(breakdown)
            
            return score, level, breakdown
            
        except Exception as e:
            # Fallback to default values if calculation fails
            self.priority_score = 50
            self.priority_level = 'MEDIUM'
            self.priority_breakdown = json.dumps({'error': str(e)})
            return 50, 'MEDIUM', {'error': str(e)}
    
    def is_active(self):
        """Check if alert is currently active (not resolved)"""
        return not self.resolved
    
    def get_age_seconds(self):
        """Get alert age in seconds"""
        if not self.created_at:
            return 0
        return int((datetime.utcnow() - self.created_at).total_seconds())
    
    def get_age_minutes(self):
        """Get alert age in minutes"""
        return self.get_age_seconds() // 60
    
    def get_age_hours(self):
        """Get alert age in hours"""
        return self.get_age_minutes() // 60
    
    def should_escalate(self):
        """Determine if alert should be escalated based on age and severity"""
        if self.resolved:
            return False
        
        age_minutes = self.get_age_minutes()
        
        # Escalation thresholds based on severity
        if self.severity == 'critical':
            return age_minutes >= 15  # Escalate critical alerts after 15 minutes
        elif self.severity == 'warning':
            return age_minutes >= 60  # Escalate warning alerts after 1 hour
        elif self.severity == 'info':
            return age_minutes >= 240  # Escalate info alerts after 4 hours
        
        return False
    
    def get_severity_weight(self):
        """Get numeric weight for severity level"""
        severity_weights = {
            'critical': 100,
            'warning': 50,
            'info': 10
        }
        return severity_weights.get(self.severity, 25)  # Default to 25 for unknown severity

    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': self.device.display_name,
            'device_ip': self.device.ip_address,
            'alert_type': self.alert_type,
            'alert_subtype': self.alert_subtype,
            'severity': self.severity,
            'message': self.message,
            'created_at': self.created_at.isoformat() + 'Z',
            'acknowledged': self.acknowledged,
            'acknowledged_at': (self.acknowledged_at.isoformat() + 'Z') if self.acknowledged_at else None,
            'acknowledged_by': self.acknowledged_by,
            'resolved': self.resolved,
            'resolved_at': (self.resolved_at.isoformat() + 'Z') if self.resolved_at else None,
            'priority_score': self.priority_score,
            'priority_level': self.priority_level,
            'priority_breakdown': json.loads(self.priority_breakdown) if self.priority_breakdown else None,
            'notification_sent': self.notification_sent,
            'notification_count': self.notification_count,
            'last_notification_at': (self.last_notification_at.isoformat() + 'Z') if self.last_notification_at else None,
            'notification_status': self.notification_status,
        }

# Composite indexes for common alert query patterns
db.Index('idx_alert_device_resolved', Alert.device_id, Alert.resolved)  # For queries like: device alerts that are unresolved
db.Index('idx_alert_resolved_created', Alert.resolved, Alert.created_at.desc())  # For queries like: unresolved alerts by date
db.Index('idx_alert_severity_resolved', Alert.severity, Alert.resolved)  # For queries like: critical unresolved alerts
db.Index('idx_alert_acknowledged_resolved', Alert.acknowledged, Alert.resolved)  # For queries like: unacknowledged alerts
db.Index('idx_alert_type_resolved', Alert.alert_type, Alert.resolved)  # For queries like: device_down alerts that are active
db.Index('idx_alert_device_type_resolved', Alert.device_id, Alert.alert_type, Alert.resolved)  # For complex device queries

# Composite indexes for common monitoring data query patterns
db.Index('idx_monitoring_device_timestamp', MonitoringData.device_id, MonitoringData.timestamp.desc())  # For "latest data per device" queries

class Configuration(db.Model):
    __tablename__ = 'configuration'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    version = db.Column(db.Integer, default=1)  # Version tracking for hot-reload detection
    
    def __repr__(self):
        return f'<Configuration {self.key}={self.value}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'key': self.key,
            'value': self.value,
            'description': self.description,
            'version': self.version,
            'created_at': self.created_at.isoformat() + 'Z',
            'updated_at': self.updated_at.isoformat() + 'Z',
        }
    
    @classmethod
    def get_value(cls, key, default=None):
        config = cls.query.filter_by(key=key).first()
        return config.value if config else default
    
    @classmethod
    def set_value(cls, key, value, description=None):
        config = cls.query.filter_by(key=key).first()
        if config:
            # Only increment version if value actually changed
            if config.value != value:
                config.version = (config.version or 0) + 1
            config.value = value
            if description:
                config.description = description
        else:
            config = cls(key=key, value=value, description=description, version=1)
            db.session.add(config)
        db.session.commit()
        return config
    
    @classmethod
    def get_config_version(cls, key):
        """Get the current version number for a configuration key"""
        config = cls.query.filter_by(key=key).first()
        return config.version if config else 0
    
    @classmethod
    def get_latest_config_timestamp(cls):
        """Get the timestamp of the most recently updated configuration"""
        latest_config = cls.query.order_by(cls.updated_at.desc()).first()
        return latest_config.updated_at if latest_config else datetime.utcnow()

class ConfigurationHistory(db.Model):
    """Model for tracking configuration changes and rollback history"""
    __tablename__ = 'configuration_history'
    
    id = db.Column(db.Integer, primary_key=True)
    config_key = db.Column(db.String(100), nullable=False, index=True)
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    changed_by = db.Column(db.String(100), default='system')
    change_reason = db.Column(db.Text)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Validation and rollback info
    validated = db.Column(db.Boolean, default=True)
    rollback_available = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<ConfigurationHistory {self.config_key}: {self.old_value} -> {self.new_value}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'config_key': self.config_key,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'changed_by': self.changed_by,
            'change_reason': self.change_reason,
            'changed_at': self.changed_at.isoformat() + 'Z',
            'validated': self.validated,
            'rollback_available': self.rollback_available
        }
    
    @classmethod
    def log_change(cls, key, old_value, new_value, changed_by='system', reason=None, validated=True):
        """Log a configuration change"""
        try:
            history = cls(
                config_key=key,
                old_value=str(old_value) if old_value is not None else None,
                new_value=str(new_value) if new_value is not None else None,
                changed_by=changed_by,
                change_reason=reason,
                validated=validated
            )
            db.session.add(history)
            db.session.commit()
            return history
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error logging configuration change: {e}")
            return None

class BandwidthData(db.Model):
    """Model for storing bandwidth usage data"""
    __tablename__ = 'bandwidth_data'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    bytes_in = db.Column(db.BigInteger, default=0)  # bytes received
    bytes_out = db.Column(db.BigInteger, default=0)  # bytes transmitted
    packets_in = db.Column(db.Integer, default=0)
    packets_out = db.Column(db.Integer, default=0)
    bandwidth_in_mbps = db.Column(db.Float, default=0.0)  # calculated incoming bandwidth
    bandwidth_out_mbps = db.Column(db.Float, default=0.0)  # calculated outgoing bandwidth
    
    # Relationships
    device = db.relationship('Device', backref=db.backref('bandwidth_data', lazy=True))
    
    def __repr__(self):
        return f'<BandwidthData {self.device.ip_address if self.device else "Unknown"} at {self.timestamp}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'timestamp': self.timestamp.isoformat() + 'Z',
            'bytes_in': self.bytes_in,
            'bytes_out': self.bytes_out,
            'packets_in': self.packets_in,
            'packets_out': self.packets_out,
            'bandwidth_in_mbps': self.bandwidth_in_mbps,
            'bandwidth_out_mbps': self.bandwidth_out_mbps,
            'total_mbps': self.bandwidth_in_mbps + self.bandwidth_out_mbps
        }



class NotificationHistory(db.Model):
    """Model for tracking sent push notifications"""
    __tablename__ = 'notification_history'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=True, index=True)  # Nullable for system notifications
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), nullable=True, index=True)  # Link to source alert
    notification_type = db.Column(db.String(50), nullable=False, index=True)  # device_down, device_up, new_device, scan_complete, etc.
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), default='default')  # min, low, default, high, urgent
    tags = db.Column(db.String(255))  # Emoji tags
    delivery_status = db.Column(db.String(20), default='unknown')  # success, failed, unknown
    error_message = db.Column(db.Text)  # If delivery failed
    sent_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Metadata fields  
    notification_metadata = db.Column(db.Text)  # JSON string for additional data
    
    # Read receipt and engagement tracking
    read_count = db.Column(db.Integer, default=0)  # Number of times opened/read
    click_count = db.Column(db.Integer, default=0)  # Number of times clicked
    first_read_at = db.Column(db.DateTime)  # When first opened
    last_read_at = db.Column(db.DateTime)  # When last opened
    total_read_time_seconds = db.Column(db.Integer, default=0)  # Total time spent reading
    unique_readers = db.Column(db.Integer, default=0)  # Number of unique users who read
    
    # Relationships
    device = db.relationship('Device', backref=db.backref('notification_history', lazy=True))
    alert = db.relationship('Alert', backref=db.backref('notifications', lazy=True))
    
    def __repr__(self):
        device_name = self.device.display_name if self.device else 'System'
        return f'<NotificationHistory {self.notification_type} for {device_name} at {self.sent_at}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': self.device.display_name if self.device else 'System',
            'alert_id': self.alert_id,
            'notification_type': self.notification_type,
            'title': self.title,
            'message': self.message,
            'priority': self.priority,
            'tags': self.tags,
            'delivery_status': self.delivery_status,
            'error_message': self.error_message,
            'sent_at': self.sent_at.isoformat() + 'Z',
            'metadata': json.loads(self.notification_metadata) if self.notification_metadata else {}
        }
    
    @classmethod
    def log_notification(cls, device_id=None, alert_id=None, notification_type='', title='', message='', 
                        priority='default', tags='', delivery_status='unknown', 
                        error_message=None, metadata=None):
        """Log a sent notification"""
        try:
            notification = cls(
                device_id=device_id,
                alert_id=alert_id,
                notification_type=notification_type,
                title=title,
                message=message,
                priority=priority,
                tags=tags,
                delivery_status=delivery_status,
                error_message=error_message,
                notification_metadata=json.dumps(metadata) if metadata else None
            )
            db.session.add(notification)
            db.session.commit()
            return notification
        except Exception as e:
            db.session.rollback()
            print(f"Error logging notification: {e}")
            return None

class NotificationReceipt(db.Model):
    """Model for tracking notification read receipts and engagement"""
    __tablename__ = 'notification_receipts'
    
    id = db.Column(db.Integer, primary_key=True)
    notification_id = db.Column(db.Integer, db.ForeignKey('notification_history.id'), nullable=False, index=True)
    
    # Tracking information
    tracking_token = db.Column(db.String(64), unique=True, nullable=False, index=True)  # Unique tracking identifier
    user_identifier = db.Column(db.String(255))  # User ID, email, or device identifier
    ip_address = db.Column(db.String(45))  # IPv4 or IPv6 address
    user_agent = db.Column(db.Text)  # Browser/device information
    
    # Engagement tracking
    interaction_type = db.Column(db.String(20), nullable=False)  # opened, clicked, dismissed, delivered
    read_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    read_duration_seconds = db.Column(db.Integer)  # How long notification was viewed
    
    # Delivery channel context
    delivery_channel = db.Column(db.String(50))  # email, push, webhook, sms
    device_type = db.Column(db.String(50))  # mobile, desktop, tablet
    
    # Privacy and retention
    anonymized = db.Column(db.Boolean, default=False)  # Whether PII has been removed
    expires_at = db.Column(db.DateTime)  # When this receipt data should be purged
    
    # Metadata
    receipt_metadata = db.Column(db.Text)  # JSON string for additional context
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    notification = db.relationship('NotificationHistory', backref=db.backref('receipts', lazy=True, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<NotificationReceipt {self.interaction_type} for notification {self.notification_id} at {self.read_at}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'notification_id': self.notification_id,
            'tracking_token': self.tracking_token,
            'user_identifier': self.user_identifier if not self.anonymized else '[anonymized]',
            'interaction_type': self.interaction_type,
            'read_at': self.read_at.isoformat() + 'Z',
            'read_duration_seconds': self.read_duration_seconds,
            'delivery_channel': self.delivery_channel,
            'device_type': self.device_type,
            'anonymized': self.anonymized,
            'metadata': json.loads(self.receipt_metadata) if self.receipt_metadata else {}
        }
    
    @classmethod
    def create_tracking_token(cls):
        """Generate a unique tracking token"""
        import secrets
        return secrets.token_urlsafe(32)
    
    @classmethod
    def log_receipt(cls, notification_id, interaction_type, user_identifier=None, 
                   ip_address=None, user_agent=None, delivery_channel=None, 
                   device_type=None, read_duration=None, metadata=None):
        """Log a notification receipt/interaction"""
        try:
            # Check if this is a duplicate receipt (same notification + user + interaction within 5 minutes)
            recent_cutoff = datetime.utcnow() - timedelta(minutes=5)
            existing = cls.query.filter(
                cls.notification_id == notification_id,
                cls.user_identifier == user_identifier,
                cls.interaction_type == interaction_type,
                cls.read_at >= recent_cutoff
            ).first()
            
            if existing:
                # Update existing receipt instead of creating duplicate
                if read_duration and not existing.read_duration_seconds:
                    existing.read_duration_seconds = read_duration
                if metadata:
                    existing_meta = json.loads(existing.receipt_metadata) if existing.receipt_metadata else {}
                    existing_meta.update(metadata)
                    existing.receipt_metadata = json.dumps(existing_meta)
                db.session.commit()
                return existing
            
            # Create new receipt
            receipt = cls(
                notification_id=notification_id,
                tracking_token=cls.create_tracking_token(),
                user_identifier=user_identifier,
                ip_address=ip_address,
                user_agent=user_agent,
                interaction_type=interaction_type,
                delivery_channel=delivery_channel,
                device_type=device_type,
                read_duration_seconds=read_duration,
                receipt_metadata=json.dumps(metadata) if metadata else None,
                expires_at=datetime.utcnow() + timedelta(days=90)  # Default 90-day retention
            )
            
            db.session.add(receipt)
            db.session.commit()
            return receipt
            
        except Exception as e:
            db.session.rollback()
            print(f"Error logging notification receipt: {e}")
            return None
    
    def anonymize(self):
        """Remove personally identifiable information"""
        self.user_identifier = '[anonymized]'
        self.ip_address = None
        self.user_agent = '[anonymized]'
        self.anonymized = True
        
        # Anonymize metadata
        if self.receipt_metadata:
            metadata = json.loads(self.receipt_metadata)
            # Remove potentially identifying fields
            for key in ['email', 'username', 'device_id']:
                if key in metadata:
                    metadata[key] = '[anonymized]'
            self.receipt_metadata = json.dumps(metadata)
        
        db.session.commit()

class AlertSuppression(db.Model):
    """Model for alert suppression rules"""
    __tablename__ = 'alert_suppressions'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    enabled = db.Column(db.Boolean, default=True)
    
    # Suppression criteria
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=True)  # Specific device or null for all
    alert_type = db.Column(db.String(50), nullable=True)  # Specific alert type or null for all
    severity = db.Column(db.String(20), nullable=True)  # Specific severity or null for all
    
    # Time-based suppression
    start_time = db.Column(db.DateTime, nullable=True)  # Start of suppression window
    end_time = db.Column(db.DateTime, nullable=True)    # End of suppression window
    daily_start_hour = db.Column(db.Integer, nullable=True)  # Daily recurring start hour (0-23)
    daily_end_hour = db.Column(db.Integer, nullable=True)    # Daily recurring end hour (0-23)
    
    # Suppression type
    suppression_type = db.Column(db.String(20), default='silence')  # 'silence', 'reduce_priority', 'delay'
    priority_reduction = db.Column(db.Integer, default=0)  # Points to reduce from priority score
    delay_minutes = db.Column(db.Integer, default=0)      # Minutes to delay alert creation
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(100), default='user')
    
    # Relationships
    device = db.relationship('Device', backref=db.backref('suppressions', lazy=True))
    
    def __repr__(self):
        return f'<AlertSuppression {self.name} ({"enabled" if self.enabled else "disabled"})>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'enabled': self.enabled,
            'device_id': self.device_id,
            'device_name': self.device.display_name if self.device else 'All devices',
            'alert_type': self.alert_type or 'All alert types',
            'severity': self.severity or 'All severities',
            'start_time': self.start_time.isoformat() + 'Z' if self.start_time else None,
            'end_time': self.end_time.isoformat() + 'Z' if self.end_time else None,
            'daily_start_hour': self.daily_start_hour,
            'daily_end_hour': self.daily_end_hour,
            'suppression_type': self.suppression_type,
            'priority_reduction': self.priority_reduction,
            'delay_minutes': self.delay_minutes,
            'created_at': self.created_at.isoformat() + 'Z',
            'updated_at': self.updated_at.isoformat() + 'Z',
            'created_by': self.created_by
        }
    
    def is_currently_active(self) -> bool:
        """Check if this suppression rule is currently active"""
        if not self.enabled:
            return False
            
        now = datetime.utcnow()
        current_hour = now.hour
        
        # Check absolute time window
        if self.start_time and self.end_time:
            if not (self.start_time <= now <= self.end_time):
                return False
        
        # Check daily recurring time window
        if self.daily_start_hour is not None and self.daily_end_hour is not None:
            if self.daily_start_hour <= self.daily_end_hour:
                # Normal case: 9-17 (9 AM to 5 PM)
                if not (self.daily_start_hour <= current_hour < self.daily_end_hour):
                    return False
            else:
                # Overnight case: 22-6 (10 PM to 6 AM)
                if not (current_hour >= self.daily_start_hour or current_hour < self.daily_end_hour):
                    return False
        
        return True
    
    def matches_alert(self, device_id: int, alert_type: str, severity: str) -> bool:
        """Check if this suppression rule matches the given alert criteria"""
        if not self.is_currently_active():
            return False
            
        # Check device match
        if self.device_id is not None and self.device_id != device_id:
            return False
            
        # Check alert type match
        if self.alert_type is not None and self.alert_type != alert_type:
            return False
            
        # Check severity match
        if self.severity is not None and self.severity != severity:
            return False
            
        return True

class AutomationRule(db.Model):
    """Model for storing user-defined automation rules"""
    __tablename__ = 'automation_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    enabled = db.Column(db.Boolean, default=True)
    
    # Rule definition
    condition_json = db.Column(db.Text, nullable=False)  # JSON string of conditions
    action_json = db.Column(db.Text, nullable=False)     # JSON string of actions
    
    # Execution settings
    cooldown_minutes = db.Column(db.Integer, default=5)  # Minimum time between executions
    max_executions_per_hour = db.Column(db.Integer, default=10)  # Rate limiting
    
    # Priority and categorization
    priority = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    category = db.Column(db.String(50), default='general')  # device, network, security, maintenance
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(100), default='user')
    last_executed_at = db.Column(db.DateTime)
    execution_count = db.Column(db.Integer, default=0)
    
    # Relationships
    executions = db.relationship('RuleExecution', backref='rule', cascade='all, delete-orphan', lazy=True)
    
    def __repr__(self):
        return f'<AutomationRule {self.name} ({"enabled" if self.enabled else "disabled"})>'
    
    @property
    def conditions(self):
        """Parse condition JSON into a Python object"""
        try:
            return json.loads(self.condition_json) if self.condition_json else {}
        except (json.JSONDecodeError, TypeError) as e:
            logger.debug(f"Error parsing condition JSON: {e}")
            return {}
    
    @conditions.setter
    def conditions(self, value):
        """Set conditions as JSON string"""
        self.condition_json = json.dumps(value) if value else '{}'
    
    @property
    def actions(self):
        """Parse action JSON into a Python object"""
        try:
            return json.loads(self.action_json) if self.action_json else {}
        except (json.JSONDecodeError, TypeError) as e:
            logger.debug(f"Error parsing action JSON: {e}")
            return {}
    
    @actions.setter
    def actions(self, value):
        """Set actions as JSON string"""
        self.action_json = json.dumps(value) if value else '{}'
    
    def can_execute(self):
        """Check if rule can be executed (cooldown and rate limiting)"""
        if not self.enabled:
            return False
        
        now = datetime.utcnow()
        
        # Check cooldown
        if self.last_executed_at:
            cooldown_time = self.last_executed_at + timedelta(minutes=self.cooldown_minutes)
            if now < cooldown_time:
                return False
        
        # Check rate limiting (executions per hour)
        hour_ago = now - timedelta(hours=1)
        recent_executions = RuleExecution.query.filter(
            RuleExecution.rule_id == self.id,
            RuleExecution.executed_at >= hour_ago
        ).count()
        
        if recent_executions >= self.max_executions_per_hour:
            return False
        
        return True
    
    def mark_executed(self, success=True, result_data=None):
        """Mark rule as executed and update counters"""
        self.last_executed_at = datetime.utcnow()
        self.execution_count += 1
        db.session.commit()
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'enabled': self.enabled,
            'conditions': self.conditions,
            'actions': self.actions,
            'cooldown_minutes': self.cooldown_minutes,
            'max_executions_per_hour': self.max_executions_per_hour,
            'priority': self.priority,
            'category': self.category,
            'created_at': self.created_at.isoformat() + 'Z',
            'updated_at': self.updated_at.isoformat() + 'Z',
            'last_executed_at': self.last_executed_at.isoformat() + 'Z' if self.last_executed_at else None,
            'execution_count': self.execution_count,
            'can_execute': self.can_execute()
        }

class RuleExecution(db.Model):
    """Model for tracking rule execution history"""
    __tablename__ = 'rule_executions'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('automation_rules.id'), nullable=False, index=True)
    executed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Execution results
    success = db.Column(db.Boolean, default=False)
    error_message = db.Column(db.Text)
    execution_time_ms = db.Column(db.Integer)  # Execution duration in milliseconds
    
    # Context and results
    trigger_context = db.Column(db.Text)  # JSON string of what triggered the rule
    action_results = db.Column(db.Text)   # JSON string of action execution results
    
    def __repr__(self):
        status = "SUCCESS" if self.success else "FAILED"
        return f'<RuleExecution {self.rule.name} {status} at {self.executed_at}>'
    
    @property
    def trigger_data(self):
        """Parse trigger context JSON"""
        try:
            return json.loads(self.trigger_context) if self.trigger_context else {}
        except (json.JSONDecodeError, TypeError) as e:
            logger.debug(f"Error parsing trigger context JSON: {e}")
            return {}
    
    @trigger_data.setter
    def trigger_data(self, value):
        """Set trigger context as JSON string"""
        self.trigger_context = json.dumps(value) if value else '{}'
    
    @property
    def results(self):
        """Parse action results JSON"""
        try:
            return json.loads(self.action_results) if self.action_results else {}
        except (json.JSONDecodeError, TypeError) as e:
            logger.debug(f"Error parsing action results JSON: {e}")
            return {}
    
    @results.setter
    def results(self, value):
        """Set action results as JSON string"""
        self.action_results = json.dumps(value) if value else '{}'
    
    def to_dict(self):
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'rule_name': self.rule.name if self.rule else 'Unknown',
            'executed_at': self.executed_at.isoformat() + 'Z',
            'success': self.success,
            'error_message': self.error_message,
            'execution_time_ms': self.execution_time_ms,
            'trigger_data': self.trigger_data,
            'results': self.results
        }

class PerformanceMetrics(db.Model):
    """Model for storing comprehensive device performance metrics"""
    __tablename__ = 'performance_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Response time metrics
    avg_response_time = db.Column(db.Float)  # Average response time in ms over collection period
    min_response_time = db.Column(db.Float)  # Minimum response time in ms
    max_response_time = db.Column(db.Float)  # Maximum response time in ms
    response_time_std_dev = db.Column(db.Float)  # Standard deviation of response times
    
    # Availability metrics
    uptime_percentage = db.Column(db.Float)  # Uptime percentage over collection period
    total_checks = db.Column(db.Integer)  # Total ping checks performed
    successful_checks = db.Column(db.Integer)  # Successful ping responses
    failed_checks = db.Column(db.Integer)  # Failed ping attempts
    
    # Bandwidth metrics
    avg_bandwidth_in_mbps = db.Column(db.Float)  # Average incoming bandwidth
    avg_bandwidth_out_mbps = db.Column(db.Float)  # Average outgoing bandwidth
    peak_bandwidth_in_mbps = db.Column(db.Float)  # Peak incoming bandwidth
    peak_bandwidth_out_mbps = db.Column(db.Float)  # Peak outgoing bandwidth
    total_bytes_in = db.Column(db.BigInteger)  # Total bytes received
    total_bytes_out = db.Column(db.BigInteger)  # Total bytes transmitted
    
    # Performance quality metrics
    jitter_ms = db.Column(db.Float)  # Network jitter in milliseconds
    packet_loss_percentage = db.Column(db.Float)  # Packet loss percentage
    connection_stability_score = db.Column(db.Float)  # 0-100 stability score
    
    # Health scores
    health_score = db.Column(db.Float)  # Overall device health score (0-100)
    responsiveness_score = db.Column(db.Float)  # Response time performance score (0-100)
    reliability_score = db.Column(db.Float)  # Uptime/availability score (0-100)
    efficiency_score = db.Column(db.Float)  # Bandwidth utilization efficiency score (0-100)
    
    # Collection metadata
    collection_period_minutes = db.Column(db.Integer, default=60)  # Period over which metrics were collected
    sample_count = db.Column(db.Integer)  # Number of samples collected
    anomaly_count = db.Column(db.Integer, default=0)  # Number of anomalies detected
    
    # Relationships
    device = db.relationship('Device', backref=db.backref('performance_metrics', lazy=True, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<PerformanceMetrics {self.device.ip_address if self.device else "Unknown"} at {self.timestamp}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': self.device.display_name if self.device else 'Unknown',
            'device_ip': self.device.ip_address if self.device else 'Unknown',
            'timestamp': self.timestamp.isoformat() + 'Z',
            
            # Response time metrics
            'response_time_metrics': {
                'avg_ms': self.avg_response_time,
                'min_ms': self.min_response_time,
                'max_ms': self.max_response_time,
                'std_dev_ms': self.response_time_std_dev,
                'jitter_ms': self.jitter_ms
            },
            
            # Availability metrics
            'availability_metrics': {
                'uptime_percentage': self.uptime_percentage,
                'total_checks': self.total_checks,
                'successful_checks': self.successful_checks,
                'failed_checks': self.failed_checks,
                'packet_loss_percentage': self.packet_loss_percentage
            },
            
            # Bandwidth metrics
            'bandwidth_metrics': {
                'avg_in_mbps': self.avg_bandwidth_in_mbps,
                'avg_out_mbps': self.avg_bandwidth_out_mbps,
                'peak_in_mbps': self.peak_bandwidth_in_mbps,
                'peak_out_mbps': self.peak_bandwidth_out_mbps,
                'total_gb_in': round((self.total_bytes_in or 0) / (1024**3), 3),
                'total_gb_out': round((self.total_bytes_out or 0) / (1024**3), 3),
                'total_gb': round(((self.total_bytes_in or 0) + (self.total_bytes_out or 0)) / (1024**3), 3)
            },
            
            # Health scores
            'health_scores': {
                'overall_health': self.health_score,
                'responsiveness': self.responsiveness_score,
                'reliability': self.reliability_score,
                'efficiency': self.efficiency_score,
                'stability': self.connection_stability_score
            },
            
            # Collection metadata
            'metadata': {
                'collection_period_minutes': self.collection_period_minutes,
                'sample_count': self.sample_count,
                'anomaly_count': self.anomaly_count
            }
        }
    
    @property
    def performance_grade(self):
        """Get performance grade based on health score"""
        if self.health_score is None:
            return 'N/A'
        elif self.health_score >= 95:
            return 'A+'
        elif self.health_score >= 90:
            return 'A'
        elif self.health_score >= 85:
            return 'B+'
        elif self.health_score >= 80:
            return 'B'
        elif self.health_score >= 75:
            return 'C+'
        elif self.health_score >= 70:
            return 'C'
        elif self.health_score >= 65:
            return 'D+'
        elif self.health_score >= 60:
            return 'D'
        else:
            return 'F'
    
    @property
    def performance_status(self):
        """Get performance status based on health score"""
        if self.health_score is None:
            return 'unknown'
        elif self.health_score >= 90:
            return 'excellent'
        elif self.health_score >= 80:
            return 'good'
        elif self.health_score >= 70:
            return 'fair'
        elif self.health_score >= 60:
            return 'poor'
        else:
            return 'critical'
    
    @classmethod
    def calculate_health_score(cls, response_metrics, availability_metrics, bandwidth_metrics, quality_metrics):
        """Calculate overall health score from component metrics"""
        try:
            # Weights for different performance aspects
            weights = {
                'responsiveness': 0.30,  # 30% - Response time performance
                'reliability': 0.35,     # 35% - Uptime and availability  
                'efficiency': 0.20,      # 20% - Bandwidth utilization
                'stability': 0.15        # 15% - Connection stability/jitter
            }
            
            # Calculate responsiveness score (lower response time = higher score)
            avg_response = response_metrics.get('avg_ms', 0) or 0
            if avg_response <= 10:
                responsiveness = 100
            elif avg_response <= 50:
                responsiveness = 90 - ((avg_response - 10) / 40 * 20)  # 90-70
            elif avg_response <= 100:
                responsiveness = 70 - ((avg_response - 50) / 50 * 20)  # 70-50
            elif avg_response <= 500:
                responsiveness = 50 - ((avg_response - 100) / 400 * 30)  # 50-20
            else:
                responsiveness = max(0, 20 - ((avg_response - 500) / 1000 * 20))  # 20-0
            
            # Calculate reliability score (uptime percentage)
            uptime = availability_metrics.get('uptime_percentage', 0) or 0
            reliability = uptime  # Direct mapping
            
            # Calculate efficiency score (bandwidth utilization relative to capacity)
            # This is a simplified calculation - in practice would consider device capacity
            avg_total = ((bandwidth_metrics.get('avg_in_mbps', 0) or 0) + 
                        (bandwidth_metrics.get('avg_out_mbps', 0) or 0))
            if avg_total <= 1:  # Low utilization
                efficiency = 90 + (avg_total * 10)  # 90-100
            elif avg_total <= 10:  # Moderate utilization
                efficiency = 80 + ((avg_total - 1) / 9 * 10)  # 80-90
            elif avg_total <= 50:  # High utilization
                efficiency = 60 + ((avg_total - 10) / 40 * 20)  # 60-80
            else:  # Very high utilization
                efficiency = max(0, 60 - ((avg_total - 50) / 50 * 60))  # 60-0
            
            # Calculate stability score (lower jitter/packet loss = higher score)
            jitter = quality_metrics.get('jitter_ms', 0) or 0
            packet_loss = quality_metrics.get('packet_loss_percentage', 0) or 0
            
            # Jitter component (0-50 points)
            if jitter <= 1:
                jitter_score = 50
            elif jitter <= 5:
                jitter_score = 45 - ((jitter - 1) / 4 * 15)  # 45-30
            elif jitter <= 20:
                jitter_score = 30 - ((jitter - 5) / 15 * 20)  # 30-10
            else:
                jitter_score = max(0, 10 - ((jitter - 20) / 20 * 10))  # 10-0
            
            # Packet loss component (0-50 points)
            if packet_loss <= 0.1:
                loss_score = 50
            elif packet_loss <= 1:
                loss_score = 45 - ((packet_loss - 0.1) / 0.9 * 15)  # 45-30
            elif packet_loss <= 5:
                loss_score = 30 - ((packet_loss - 1) / 4 * 20)  # 30-10
            else:
                loss_score = max(0, 10 - ((packet_loss - 5) / 5 * 10))  # 10-0
            
            stability = jitter_score + loss_score
            
            # Calculate weighted overall score
            overall_score = (
                responsiveness * weights['responsiveness'] +
                reliability * weights['reliability'] +
                efficiency * weights['efficiency'] +
                stability * weights['stability']
            )
            
            return {
                'overall_health': round(min(100, max(0, overall_score)), 2),
                'responsiveness': round(min(100, max(0, responsiveness)), 2),
                'reliability': round(min(100, max(0, reliability)), 2),
                'efficiency': round(min(100, max(0, efficiency)), 2),
                'stability': round(min(100, max(0, stability)), 2)
            }
            
        except Exception as e:
            print(f"Error calculating health score: {e}")
            return {
                'overall_health': 0,
                'responsiveness': 0,
                'reliability': 0,
                'efficiency': 0,
                'stability': 0
            }

# Database event listeners for cleanup
@event.listens_for(MonitoringData, 'before_insert')
def cleanup_old_monitoring_data(mapper, connection, target):
    from config import Config
    cutoff = datetime.utcnow() - timedelta(days=Config.DATA_RETENTION_DAYS)
    
    # Delete old monitoring data
    connection.execute(
        MonitoringData.__table__.delete().where(
            MonitoringData.__table__.c.timestamp < cutoff
        )
    )

def init_db(app):
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
        
        # Handle schema migrations
        try:
            # Check if version column exists by trying to access it
            db.session.execute(db.text("SELECT version FROM configuration LIMIT 1"))
        except Exception:
            # Version column doesn't exist, add it
            try:
                db.session.execute(db.text("ALTER TABLE configuration ADD COLUMN version INTEGER DEFAULT 1"))
                db.session.commit()
                print("Added version column to configuration table")
            except Exception as e:
                print(f"Could not add version column: {e}")
                # If we can't add the column, recreate the table
                db.drop_all()
                db.create_all()
                print("Recreated database tables with new schema")
        
        # Initialize default configuration
        default_configs = [
            ('network_range', '192.168.86.0/24', 'Network range to monitor'),
            ('ping_interval', '30', 'Ping interval in seconds'),
            ('scan_interval', '300', 'Network scan interval in seconds'),
            ('bandwidth_interval', '60', 'Bandwidth monitoring interval in seconds'),
            ('alert_email_enabled', 'false', 'Enable email alerts'),
            ('alert_webhook_enabled', 'false', 'Enable webhook alerts'),
        ]
        
        for key, value, description in default_configs:
            try:
                if not Configuration.query.filter_by(key=key).first():
                    Configuration.set_value(key, value, description)
            except Exception as e:
                print(f"Error initializing configuration {key}: {e}")

class EscalationRule(db.Model):
    """Escalation rules for notification failures and alert management"""
    __tablename__ = 'escalation_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    enabled = db.Column(db.Boolean, default=True, nullable=False, index=True)
    priority = db.Column(db.Integer, default=1, nullable=False, index=True)  # Lower number = higher priority
    
    # Trigger conditions
    trigger_type = db.Column(db.String(50), nullable=False, index=True)  # notification_failure, alert_unresolved, device_offline, etc.
    trigger_conditions = db.Column(db.JSON)  # Flexible JSON conditions
    
    # Timing configuration
    delay_minutes = db.Column(db.Integer, default=0)  # Delay before first escalation
    max_escalations = db.Column(db.Integer, default=3)  # Maximum number of escalations
    escalation_interval_minutes = db.Column(db.Integer, default=60)  # Time between escalations
    
    # Escalation actions
    escalation_actions = db.Column(db.JSON, nullable=False)  # List of actions to take
    
    # Scope and filtering
    applies_to_device_types = db.Column(db.JSON)  # List of device types, null = all
    applies_to_notification_types = db.Column(db.JSON)  # List of notification types, null = all
    applies_to_severity_levels = db.Column(db.JSON)  # List of severity levels, null = all
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by = db.Column(db.String(100))
    
    # Relationships
    escalation_executions = db.relationship('EscalationExecution', backref='rule', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<EscalationRule {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'enabled': self.enabled,
            'priority': self.priority,
            'trigger_type': self.trigger_type,
            'trigger_conditions': self.trigger_conditions,
            'delay_minutes': self.delay_minutes,
            'max_escalations': self.max_escalations,
            'escalation_interval_minutes': self.escalation_interval_minutes,
            'escalation_actions': self.escalation_actions,
            'applies_to_device_types': self.applies_to_device_types,
            'applies_to_notification_types': self.applies_to_notification_types,
            'applies_to_severity_levels': self.applies_to_severity_levels,
            'created_at': self.created_at.isoformat() + 'Z',
            'updated_at': self.updated_at.isoformat() + 'Z',
            'created_by': self.created_by,
            'total_executions': self.escalation_executions.count()
        }
    
    def matches_conditions(self, context):
        """Check if this rule matches the given context"""
        if not self.enabled:
            return False
        
        # Check device type filter
        if self.applies_to_device_types and context.get('device_type'):
            if context['device_type'] not in self.applies_to_device_types:
                return False
        
        # Check notification type filter
        if self.applies_to_notification_types and context.get('notification_type'):
            if context['notification_type'] not in self.applies_to_notification_types:
                return False
        
        # Check severity level filter
        if self.applies_to_severity_levels and context.get('severity'):
            if context['severity'] not in self.applies_to_severity_levels:
                return False
        
        # Check specific trigger conditions
        if self.trigger_conditions:
            for condition_key, condition_value in self.trigger_conditions.items():
                if condition_key not in context:
                    return False
                
                context_value = context[condition_key]
                
                # Handle different condition types
                if isinstance(condition_value, dict):
                    # Complex condition with operators
                    if 'equals' in condition_value and context_value != condition_value['equals']:
                        return False
                    if 'greater_than' in condition_value and context_value <= condition_value['greater_than']:
                        return False
                    if 'less_than' in condition_value and context_value >= condition_value['less_than']:
                        return False
                    if 'contains' in condition_value and condition_value['contains'] not in str(context_value):
                        return False
                else:
                    # Simple equality check
                    if context_value != condition_value:
                        return False
        
        return True

class EscalationExecution(db.Model):
    """Track individual escalation executions"""
    __tablename__ = 'escalation_executions'
    
    id = db.Column(db.Integer, primary_key=True)
    escalation_rule_id = db.Column(db.Integer, db.ForeignKey('escalation_rules.id'), nullable=False, index=True)
    
    # Context of the escalation
    triggered_by_type = db.Column(db.String(50), nullable=False)  # notification, alert, device
    triggered_by_id = db.Column(db.Integer, nullable=False, index=True)  # ID of the triggering entity
    trigger_context = db.Column(db.JSON)  # Full context that triggered this escalation
    
    # Execution status
    status = db.Column(db.String(20), default='pending', nullable=False, index=True)  # pending, in_progress, completed, failed, cancelled
    current_escalation_level = db.Column(db.Integer, default=0, nullable=False)
    
    # Timing
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    scheduled_for = db.Column(db.DateTime, nullable=False, index=True)  # When to execute next action
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Results
    last_action_result = db.Column(db.JSON)  # Result of last executed action
    total_actions_executed = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    
    # Relationships
    escalation_actions = db.relationship('EscalationActionLog', backref='execution', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<EscalationExecution {self.id} for Rule {self.escalation_rule_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'escalation_rule_id': self.escalation_rule_id,
            'rule_name': self.rule.name if self.rule else 'Unknown',
            'triggered_by_type': self.triggered_by_type,
            'triggered_by_id': self.triggered_by_id,
            'trigger_context': self.trigger_context,
            'status': self.status,
            'current_escalation_level': self.current_escalation_level,
            'created_at': self.created_at.isoformat() + 'Z',
            'scheduled_for': self.scheduled_for.isoformat() + 'Z',
            'started_at': self.started_at.isoformat() + 'Z' if self.started_at else None,
            'completed_at': self.completed_at.isoformat() + 'Z' if self.completed_at else None,
            'last_action_result': self.last_action_result,
            'total_actions_executed': self.total_actions_executed,
            'error_message': self.error_message,
            'actions_count': self.escalation_actions.count()
        }

class EscalationActionLog(db.Model):
    """Log individual escalation actions"""
    __tablename__ = 'escalation_action_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    escalation_execution_id = db.Column(db.Integer, db.ForeignKey('escalation_executions.id'), nullable=False, index=True)
    
    # Action details
    action_type = db.Column(db.String(50), nullable=False)  # email, webhook, sms, push_notification, etc.
    action_config = db.Column(db.JSON, nullable=False)  # Configuration for this action
    escalation_level = db.Column(db.Integer, nullable=False)
    
    # Execution details
    executed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(20), nullable=False)  # success, failed, skipped
    result = db.Column(db.JSON)  # Result data from action execution
    error_message = db.Column(db.Text)
    duration_ms = db.Column(db.Integer)  # Execution time in milliseconds
    
    def __repr__(self):
        return f'<EscalationActionLog {self.id} {self.action_type}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'escalation_execution_id': self.escalation_execution_id,
            'action_type': self.action_type,
            'action_config': self.action_config,
            'escalation_level': self.escalation_level,
            'executed_at': self.executed_at.isoformat() + 'Z',
            'status': self.status,
            'result': self.result,
            'error_message': self.error_message,
            'duration_ms': self.duration_ms
        }

# Security-related models for Phase 10: Security & Compliance

class SecurityScan(db.Model):
    """Store individual port scan results"""
    __tablename__ = 'security_scans'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    ip_address = db.Column(db.String(15), nullable=False, index=True)
    port = db.Column(db.Integer, nullable=False, index=True)
    state = db.Column(db.String(20), nullable=False)  # open, closed, filtered
    service = db.Column(db.String(100))
    version = db.Column(db.String(255))
    product = db.Column(db.String(255))
    extra_info = db.Column(db.Text)
    confidence = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Float, default=0.0)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    device = db.relationship('Device', backref='security_scans')
    
    def __repr__(self):
        return f'<SecurityScan {self.device_id}:{self.port} {self.service}>'

class SecurityVulnerability(db.Model):
    """Store vulnerability findings"""
    __tablename__ = 'security_vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    category = db.Column(db.String(50), nullable=False, index=True)  # network, service, certificate, etc.
    severity = db.Column(db.String(20), nullable=False, index=True)  # info, low, medium, high, critical
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    evidence = db.Column(db.JSON)
    risk_score = db.Column(db.Float, nullable=False)
    remediation = db.Column(db.JSON)  # List of remediation steps
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    last_verified = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(20), default='open', nullable=False, index=True)  # open, acknowledged, remediated, false_positive
    cvss_score = db.Column(db.Float)
    cve_references = db.Column(db.JSON)  # List of CVE references
    compliance_violations = db.Column(db.JSON)  # List of compliance frameworks violated
    
    # Relationships
    device = db.relationship('Device', backref='vulnerabilities')
    
    def __repr__(self):
        return f'<SecurityVulnerability {self.finding_id} {self.severity}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'device_id': self.device_id,
            'device_name': self.device.display_name if self.device else 'Unknown',
            'category': self.category,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'evidence': self.evidence,
            'risk_score': self.risk_score,
            'remediation': self.remediation,
            'discovered_at': self.discovered_at.isoformat() + 'Z',
            'last_verified': self.last_verified.isoformat() + 'Z',
            'status': self.status,
            'cvss_score': self.cvss_score,
            'cve_references': self.cve_references,
            'compliance_violations': self.compliance_violations
        }

class SecurityEvent(db.Model):
    """Store security events and incidents"""
    __tablename__ = 'security_events'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), index=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)  # scan_completed, vulnerability_detected, etc.
    severity = db.Column(db.String(20), nullable=False, index=True)
    message = db.Column(db.Text, nullable=False)
    event_metadata = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    device = db.relationship('Device', backref='security_events')
    
    def __repr__(self):
        return f'<SecurityEvent {self.event_type} {self.severity}>'

class ComplianceResult(db.Model):
    """Store compliance check results"""
    __tablename__ = 'compliance_results'
    
    id = db.Column(db.Integer, primary_key=True)
    check_id = db.Column(db.String(255), nullable=False, index=True)
    framework = db.Column(db.String(50), nullable=False, index=True)  # cis, nist, pci_dss, iso27001
    rule_id = db.Column(db.String(100), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, index=True)  # pass, fail, not_applicable
    evidence = db.Column(db.JSON)
    remediation = db.Column(db.JSON)
    checked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def __repr__(self):
        return f'<ComplianceResult {self.framework} {self.rule_id} {self.status}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'check_id': self.check_id,
            'framework': self.framework,
            'rule_id': self.rule_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'checked_at': self.checked_at.isoformat() + 'Z'
        }

class DeviceOSInfo(db.Model):
    """Store OS detection results"""
    __tablename__ = 'device_os_info'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    os_name = db.Column(db.String(255))
    os_family = db.Column(db.String(100))
    os_version = db.Column(db.String(100))
    accuracy = db.Column(db.Integer, default=0)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    device = db.relationship('Device', backref='os_info', uselist=False)
    
    def __repr__(self):
        return f'<DeviceOSInfo {self.device_id} {self.os_name}>'

class SecurityIncident(db.Model):
    """Store security incidents and responses"""
    __tablename__ = 'security_incidents'
    
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), nullable=False, index=True)  # low, medium, high, critical
    status = db.Column(db.String(20), default='open', nullable=False, index=True)  # open, investigating, contained, resolved
    category = db.Column(db.String(50), nullable=False, index=True)  # malware, intrusion, policy_violation, etc.
    
    # Affected resources
    affected_devices = db.Column(db.JSON)  # List of affected device IDs
    affected_services = db.Column(db.JSON)  # List of affected services
    
    # Timeline
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    reported_at = db.Column(db.DateTime)
    contained_at = db.Column(db.DateTime)
    resolved_at = db.Column(db.DateTime)
    
    # Response details
    assigned_to = db.Column(db.String(255))  # Person/team handling the incident
    response_actions = db.Column(db.JSON)  # List of response actions taken
    resolution_notes = db.Column(db.Text)
    lessons_learned = db.Column(db.Text)
    
    # Risk assessment
    risk_score = db.Column(db.Float, default=0.0)
    business_impact = db.Column(db.String(20))  # low, medium, high, critical
    
    def __repr__(self):
        return f'<SecurityIncident {self.incident_id} {self.severity}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'incident_id': self.incident_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'category': self.category,
            'affected_devices': self.affected_devices,
            'affected_services': self.affected_services,
            'detected_at': self.detected_at.isoformat() + 'Z',
            'reported_at': self.reported_at.isoformat() + 'Z' if self.reported_at else None,
            'contained_at': self.contained_at.isoformat() + 'Z' if self.contained_at else None,
            'resolved_at': self.resolved_at.isoformat() + 'Z' if self.resolved_at else None,
            'assigned_to': self.assigned_to,
            'response_actions': self.response_actions,
            'resolution_notes': self.resolution_notes,
            'lessons_learned': self.lessons_learned,
            'risk_score': self.risk_score,
            'business_impact': self.business_impact
        }


class PerformanceSnapshot(db.Model):
    """Model for storing detailed performance snapshots from the performance analyzer"""
    __tablename__ = 'performance_snapshots'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    metric_type = db.Column(db.String(50), nullable=False, index=True)  # latency, jitter, packet_loss, etc.
    value = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(10), nullable=False)  # ms, %, mbps, etc.
    metric_metadata = db.Column(db.JSON)  # Additional metric-specific data
    
    # Performance analysis
    baseline_value = db.Column(db.Float)  # Expected/baseline value
    deviation_percentage = db.Column(db.Float)  # Percentage deviation from baseline
    performance_level = db.Column(db.String(20))  # excellent, good, fair, poor, critical
    
    # Relationships
    device = db.relationship('Device', backref=db.backref('performance_snapshots', lazy=True, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<PerformanceSnapshot {self.device.ip_address if self.device else "Unknown"} {self.metric_type}={self.value}{self.unit}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': self.device.display_name if self.device else 'Unknown',
            'timestamp': self.timestamp.isoformat() + 'Z',
            'metric_type': self.metric_type,
            'value': self.value,
            'unit': self.unit,
            'metadata': self.metric_metadata,
            'baseline_value': self.baseline_value,
            'deviation_percentage': self.deviation_percentage,
            'performance_level': self.performance_level
        }


class BandwidthTest(db.Model):
    """Model for storing bandwidth test results"""
    __tablename__ = 'bandwidth_tests'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    test_type = db.Column(db.String(20), default='speedtest')  # speedtest, iperf, custom
    
    # Test results
    download_mbps = db.Column(db.Float, nullable=False)
    upload_mbps = db.Column(db.Float, nullable=False)
    ping_ms = db.Column(db.Float, nullable=False)
    jitter_ms = db.Column(db.Float, default=0.0)
    
    # Test server information
    server_host = db.Column(db.String(255))
    server_location = db.Column(db.String(100))
    server_country = db.Column(db.String(2))
    server_distance_km = db.Column(db.Float)
    
    # Test metadata
    test_duration_seconds = db.Column(db.Float)
    bytes_sent = db.Column(db.BigInteger)
    bytes_received = db.Column(db.BigInteger)
    test_config = db.Column(db.JSON)  # Test-specific configuration
    
    # Quality metrics
    connection_quality_score = db.Column(db.Float)  # 0-100 score
    performance_grade = db.Column(db.String(2))  # A+, A, B+, etc.
    
    def __repr__(self):
        return f'<BandwidthTest {self.download_mbps:.1f}↓/{self.upload_mbps:.1f}↑ Mbps @ {self.timestamp}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() + 'Z',
            'test_type': self.test_type,
            'download_mbps': self.download_mbps,
            'upload_mbps': self.upload_mbps,
            'ping_ms': self.ping_ms,
            'jitter_ms': self.jitter_ms,
            'server_host': self.server_host,
            'server_location': self.server_location,
            'server_country': self.server_country,
            'server_distance_km': self.server_distance_km,
            'test_duration_seconds': self.test_duration_seconds,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'test_config': self.test_config,
            'connection_quality_score': self.connection_quality_score,
            'performance_grade': self.performance_grade
        }


class LatencyAnalysis(db.Model):
    """Model for storing detailed latency analysis results"""
    __tablename__ = 'latency_analysis'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    analysis_period_minutes = db.Column(db.Integer, default=60)  # Analysis window size
    
    # Latency statistics
    min_latency_ms = db.Column(db.Float, nullable=False)
    max_latency_ms = db.Column(db.Float, nullable=False)
    avg_latency_ms = db.Column(db.Float, nullable=False)
    median_latency_ms = db.Column(db.Float)
    p95_latency_ms = db.Column(db.Float)  # 95th percentile
    p99_latency_ms = db.Column(db.Float)  # 99th percentile
    
    # Variability metrics
    jitter_ms = db.Column(db.Float, nullable=False)
    coefficient_of_variation = db.Column(db.Float)  # Standard deviation / mean
    latency_stability_score = db.Column(db.Float)  # 0-100 stability score
    
    # Quality metrics
    packet_loss_percentage = db.Column(db.Float, default=0.0)
    sample_count = db.Column(db.Integer, nullable=False)
    timeout_count = db.Column(db.Integer, default=0)
    
    # Performance classification
    latency_grade = db.Column(db.String(2))  # A+, A, B+, B, C+, C, D+, D, F
    performance_category = db.Column(db.String(20))  # excellent, good, fair, poor, critical
    network_quality_score = db.Column(db.Float)  # Overall network quality (0-100)
    
    # Trend analysis
    trend_direction = db.Column(db.String(20))  # improving, stable, degrading
    trend_strength = db.Column(db.Float)  # 0-1 correlation coefficient
    
    # Relationships
    device = db.relationship('Device', backref=db.backref('latency_analyses', lazy=True, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<LatencyAnalysis {self.device.ip_address if self.device else "Unknown"} avg={self.avg_latency_ms:.1f}ms>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': self.device.display_name if self.device else 'Unknown',
            'timestamp': self.timestamp.isoformat() + 'Z',
            'analysis_period_minutes': self.analysis_period_minutes,
            'min_latency_ms': self.min_latency_ms,
            'max_latency_ms': self.max_latency_ms,
            'avg_latency_ms': self.avg_latency_ms,
            'median_latency_ms': self.median_latency_ms,
            'p95_latency_ms': self.p95_latency_ms,
            'p99_latency_ms': self.p99_latency_ms,
            'jitter_ms': self.jitter_ms,
            'coefficient_of_variation': self.coefficient_of_variation,
            'latency_stability_score': self.latency_stability_score,
            'packet_loss_percentage': self.packet_loss_percentage,
            'sample_count': self.sample_count,
            'timeout_count': self.timeout_count,
            'latency_grade': self.latency_grade,
            'performance_category': self.performance_category,
            'network_quality_score': self.network_quality_score,
            'trend_direction': self.trend_direction,
            'trend_strength': self.trend_strength
        }


class PerformanceAlert(db.Model):
    """Model for storing performance-related alerts"""
    __tablename__ = 'performance_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    metric_type = db.Column(db.String(50), nullable=False, index=True)
    
    # Alert details
    severity = db.Column(db.String(20), nullable=False, index=True)  # low, medium, high, critical
    threshold_value = db.Column(db.Float, nullable=False)
    actual_value = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    
    # Timestamps
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    acknowledged_at = db.Column(db.DateTime)
    resolved_at = db.Column(db.DateTime)
    
    # Status and resolution
    status = db.Column(db.String(20), default='active', index=True)  # active, acknowledged, resolved, suppressed
    acknowledged_by = db.Column(db.String(100))
    resolution_notes = db.Column(db.Text)
    
    # Recommendations
    recommendations = db.Column(db.JSON)  # List of recommended actions
    auto_resolved = db.Column(db.Boolean, default=False)
    
    # Relationships
    device = db.relationship('Device', backref=db.backref('performance_alerts', lazy=True, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<PerformanceAlert {self.alert_id} {self.severity} {self.metric_type}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'device_id': self.device_id,
            'device_name': self.device.display_name if self.device else 'Unknown',
            'metric_type': self.metric_type,
            'severity': self.severity,
            'threshold_value': self.threshold_value,
            'actual_value': self.actual_value,
            'description': self.description,
            'detected_at': self.detected_at.isoformat() + 'Z',
            'acknowledged_at': self.acknowledged_at.isoformat() + 'Z' if self.acknowledged_at else None,
            'resolved_at': self.resolved_at.isoformat() + 'Z' if self.resolved_at else None,
            'status': self.status,
            'acknowledged_by': self.acknowledged_by,
            'resolution_notes': self.resolution_notes,
            'recommendations': self.recommendations,
            'auto_resolved': self.auto_resolved
        }


class OptimizationRecommendation(db.Model):
    """Model for storing network optimization recommendations"""
    __tablename__ = 'optimization_recommendations'
    
    id = db.Column(db.Integer, primary_key=True)
    recommendation_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    category = db.Column(db.String(50), nullable=False, index=True)  # network_config, bandwidth, latency, qos, etc.
    priority = db.Column(db.Integer, nullable=False, index=True)  # 1-5, 5 being highest
    
    # Recommendation details
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    impact_assessment = db.Column(db.Text)
    implementation_effort = db.Column(db.String(20))  # low, medium, high
    estimated_improvement = db.Column(db.String(255))
    
    # Implementation details
    implementation_steps = db.Column(db.JSON)  # List of implementation steps
    devices_affected = db.Column(db.JSON)  # List of device IDs
    cost_estimate = db.Column(db.String(100))
    estimated_duration_hours = db.Column(db.Float)
    
    # Status tracking
    status = db.Column(db.String(20), default='pending', index=True)  # pending, approved, rejected, implemented
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    approved_at = db.Column(db.DateTime)
    implemented_at = db.Column(db.DateTime)
    approved_by = db.Column(db.String(100))
    
    # Results tracking
    implementation_notes = db.Column(db.Text)
    actual_improvement = db.Column(db.String(255))
    success_rating = db.Column(db.Integer)  # 1-5 rating of implementation success
    
    def __repr__(self):
        return f'<OptimizationRecommendation {self.recommendation_id} P{self.priority} {self.category}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'recommendation_id': self.recommendation_id,
            'category': self.category,
            'priority': self.priority,
            'title': self.title,
            'description': self.description,
            'impact_assessment': self.impact_assessment,
            'implementation_effort': self.implementation_effort,
            'estimated_improvement': self.estimated_improvement,
            'implementation_steps': self.implementation_steps,
            'devices_affected': self.devices_affected,
            'cost_estimate': self.cost_estimate,
            'estimated_duration_hours': self.estimated_duration_hours,
            'status': self.status,
            'created_at': self.created_at.isoformat() + 'Z',
            'approved_at': self.approved_at.isoformat() + 'Z' if self.approved_at else None,
            'implemented_at': self.implemented_at.isoformat() + 'Z' if self.implemented_at else None,
            'approved_by': self.approved_by,
            'implementation_notes': self.implementation_notes,
            'actual_improvement': self.actual_improvement,
            'success_rating': self.success_rating
        }

# Cache invalidation event handlers
@event.listens_for(MonitoringData, 'after_insert')
@event.listens_for(MonitoringData, 'after_update')
def invalidate_monitoring_data_cache(mapper, connection, target):
    """Invalidate device cache when monitoring data changes"""
    try:
        cache_invalidator.invalidate_device_cache(target.device_id)
    except Exception:
        pass  # Silently fail if cache service not available

@event.listens_for(Alert, 'after_insert')
@event.listens_for(Alert, 'after_update')
@event.listens_for(Alert, 'after_delete')
def invalidate_alert_cache(mapper, connection, target):
    """Invalidate device cache when alerts change"""
    try:
        cache_invalidator.invalidate_device_cache(target.device_id)
    except Exception:
        pass  # Silently fail if cache service not available

@event.listens_for(PerformanceMetrics, 'after_insert')
@event.listens_for(PerformanceMetrics, 'after_update')
def invalidate_performance_cache(mapper, connection, target):
    """Invalidate device cache when performance metrics change"""
    try:
        cache_invalidator.invalidate_device_cache(target.device_id)
    except Exception:
        pass  # Silently fail if cache service not available
