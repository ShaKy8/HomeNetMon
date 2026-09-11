import logging
from datetime import datetime, timedelta

from constants import DEVICE_DOWN_AFTER_SECONDS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
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
    # Nullable: the scanner clears the IP of a stale device when a different MAC
    # takes over its address (DHCP reuse). Such devices are unmonitored until seen again.
    ip_address = db.Column(db.String(15), unique=True, nullable=True, index=True)
    mac_address = db.Column(db.String(17), index=True)
    hostname = db.Column(db.String(255))
    vendor = db.Column(db.String(255))
    custom_name = db.Column(db.String(255))
    device_type = db.Column(db.String(50))  # router, computer, phone, iot, etc.
    device_group = db.Column(db.String(100))  # Custom grouping
    room_location = db.Column(db.String(100))  # Home-friendly room assignment (Living Room, Kitchen, etc.)
    device_priority = db.Column(db.String(20), default='normal')  # critical, important, normal, optional
    notes = db.Column(db.Text)  # free-form operator notes
    tags = db.Column(db.String(255))  # comma-separated labels; exposed as a list
    mdns_services = db.Column(db.String(500))  # comma-separated mDNS service types seen (e.g. _googlecast._tcp)
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

    @property
    def tag_list(self):
        return [t.strip() for t in (self.tags or '').split(',') if t.strip()]

    @property
    def mdns_service_list(self):
        return [t.strip() for t in (self.mdns_services or '').split(',') if t.strip()]

    @staticmethod
    def normalize_tags(value):
        """Accept a list or a comma-separated string; return the stored csv (or None)."""
        if value is None:
            return None
        items = value if isinstance(value, (list, tuple)) else str(value).split(',')
        seen = []
        for item in items:
            tag = str(item).strip().lower()[:40]
            if tag and tag not in seen:
                seen.append(tag)
        return ','.join(seen)[:255] or None

    @cached_property(ttl=30, key_func=lambda self: f"device_{self.id}_status")
    def status(self):
        if not self.last_seen:
            return 'unknown'

        # Consider device down if not seen for more than 15 minutes (900 seconds)
        # This accounts for ping interval (600s) plus buffer for network delays
        from config import Config
        threshold = datetime.utcnow() - timedelta(seconds=DEVICE_DOWN_AFTER_SECONDS)

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

    @cached_property(ttl=120, key_func=lambda self: f"device_{self.id}_health_score")
    def current_health_score(self):
        """Get the latest health score for this device"""
        try:
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
            logger.error(f"Error getting performance summary for device {self.id}: {e}")
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
            logger.error(f"Error calculating average response time for device {self.id}: {e}")
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
            logger.error(f"Error getting status history for device {self.id}: {e}")
            return []

    def to_dict(self):
        """Serialize one device with a bounded number of queries.

        Same key set as to_dict_fast() (list endpoints) plus the cached health
        fields. The 7-day uptime_percentage() walk is deliberately NOT here --
        it loads a week of samples per device -- the detail endpoint adds it.
        """
        latest = MonitoringData.query.filter_by(device_id=self.id)\
                                     .order_by(MonitoringData.timestamp.desc()).first()
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
            'tags': self.tag_list,
            'notes': self.notes,
            'mdns_services': self.mdns_service_list,
            'is_monitored': self.is_monitored,
            'status': self.status,
            'active_alerts': self.active_alerts,
            'latest_response_time': latest.response_time if latest else None,
            'latest_check': (latest.timestamp.isoformat() + 'Z') if latest else None,
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
            threshold = datetime.utcnow() - timedelta(seconds=DEVICE_DOWN_AFTER_SECONDS)
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
            'tags': self.tag_list,
            'notes': self.notes,
            'mdns_services': self.mdns_service_list,
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

    def get_severity_weight(self):
        """Get numeric weight for severity level"""
        severity_weights = {
            'critical': 100,
            'warning': 50,
            'info': 10
        }
        return severity_weights.get(self.severity, 25)  # Default to 25 for unknown severity

    ALERT_TITLES = {
        'device_down': 'Device offline',
        'device_recovery': 'Device back online',
        'high_latency': 'High latency',
        'new_device': 'New device discovered',
        'security_new_service': 'New open port',
        'security_suspicious_port': 'Suspicious port open',
        'wan_down': 'Internet down',
        'wan_recovery': 'Internet restored',
        'gateway_down': 'Gateway unreachable',
        'performance': 'Performance degraded',
    }
    PERFORMANCE_TITLES = {
        'performance_critical': 'Performance critical',
        'performance_warning': 'Performance degraded',
        'performance_responsiveness': 'Slow responses',
        'performance_reliability': 'Unreliable connectivity',
    }

    @property
    def title(self):
        """Short human heading for the alert (cards, toasts, email/Discord subjects)."""
        if self.alert_type == 'performance' and self.alert_subtype in self.PERFORMANCE_TITLES:
            return self.PERFORMANCE_TITLES[self.alert_subtype]
        if self.alert_type in self.ALERT_TITLES:
            return self.ALERT_TITLES[self.alert_type]
        return (self.alert_type or 'alert').replace('_', ' ').capitalize()

    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': self.device.display_name,
            'device_ip': self.device.ip_address,
            'alert_type': self.alert_type,
            'alert_subtype': self.alert_subtype,
            'title': self.title,
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


class InterfaceBandwidth(db.Model):
    """Throughput of one host network interface over one sampling interval.

    This is the only bandwidth series HomeNetMon can measure honestly from the
    host it runs on: /proc/net/dev byte counters, differenced per interval.
    Per-device accounting would require router/SNMP integration.
    """
    __tablename__ = 'interface_bandwidth'
    __table_args__ = (
        db.Index('idx_interface_bandwidth_iface_ts', 'interface', 'timestamp'),
    )

    id = db.Column(db.Integer, primary_key=True)
    interface = db.Column(db.String(32), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    interval_seconds = db.Column(db.Float, nullable=False)
    bytes_in = db.Column(db.BigInteger, default=0)
    bytes_out = db.Column(db.BigInteger, default=0)
    packets_in = db.Column(db.Integer, default=0)
    packets_out = db.Column(db.Integer, default=0)
    mbps_in = db.Column(db.Float, default=0.0)
    mbps_out = db.Column(db.Float, default=0.0)

    def __repr__(self):
        return f'<InterfaceBandwidth {self.interface} at {self.timestamp}>'

    def to_dict(self):
        return {
            'id': self.id,
            'interface': self.interface,
            'timestamp': self.timestamp.isoformat() + 'Z',
            'interval_seconds': self.interval_seconds,
            'bytes_in': self.bytes_in,
            'bytes_out': self.bytes_out,
            'packets_in': self.packets_in,
            'packets_out': self.packets_out,
            'mbps_in': self.mbps_in,
            'mbps_out': self.mbps_out,
            'total_mbps': (self.mbps_in or 0) + (self.mbps_out or 0),
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
            logger.error(f"Error logging notification: {e}")
            return None

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
        # Daily windows ("quiet hours 23-7") are entered by a person in local time,
        # so evaluate them against the local clock. Absolute windows stay UTC like
        # every other timestamp in the database.
        current_hour = datetime.now().hour

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
                'sample_count': self.sample_count
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
    def calculate_health_score(cls, response_metrics, availability_metrics, bandwidth_metrics=None, quality_metrics=None):
        """Calculate an overall 0-100 health score from ping-derived metrics.

        Returns None when there were no checks in the window: a device with no
        ping data has no health, and scoring it produced a constant that fired
        false alerts. `bandwidth_metrics` is accepted for call compatibility and
        ignored -- per-device bandwidth is not measurable from the host.
        """
        try:
            quality_metrics = quality_metrics or {}
            if not (availability_metrics or {}).get('total_checks'):
                return None

            weights = {
                'responsiveness': 0.35,  # response time
                'reliability': 0.45,     # uptime within the window
                'stability': 0.20,       # jitter + packet loss
            }

            avg_response = response_metrics.get('avg_ms')
            successful = availability_metrics.get('successful_checks')
            if avg_response is None or successful == 0:
                responsiveness = 0          # nothing answered: no responsiveness credit
            elif avg_response <= 10:
                responsiveness = 100
            elif avg_response <= 50:
                responsiveness = 90 - ((avg_response - 10) / 40 * 20)   # 90-70
            elif avg_response <= 100:
                responsiveness = 70 - ((avg_response - 50) / 50 * 20)   # 70-50
            elif avg_response <= 500:
                responsiveness = 50 - ((avg_response - 100) / 400 * 30) # 50-20
            else:
                responsiveness = max(0, 20 - ((avg_response - 500) / 1000 * 20))

            reliability = availability_metrics.get('uptime_percentage', 0) or 0

            jitter = quality_metrics.get('jitter_ms', 0) or 0
            packet_loss = quality_metrics.get('packet_loss_percentage', 0) or 0
            if jitter <= 1:
                jitter_score = 50
            elif jitter <= 5:
                jitter_score = 45 - ((jitter - 1) / 4 * 15)
            elif jitter <= 20:
                jitter_score = 30 - ((jitter - 5) / 15 * 20)
            else:
                jitter_score = max(0, 10 - ((jitter - 20) / 20 * 10))
            if packet_loss <= 0.1:
                loss_score = 50
            elif packet_loss <= 1:
                loss_score = 45 - ((packet_loss - 0.1) / 0.9 * 15)
            elif packet_loss <= 5:
                loss_score = 30 - ((packet_loss - 1) / 4 * 20)
            else:
                loss_score = max(0, 10 - ((packet_loss - 5) / 5 * 10))
            stability = jitter_score + loss_score

            overall = (responsiveness * weights['responsiveness']
                       + reliability * weights['reliability']
                       + stability * weights['stability'])

            clamp = lambda v: round(min(100, max(0, v)), 2)
            return {
                'overall_health': clamp(overall),
                'responsiveness': clamp(responsiveness),
                'reliability': clamp(reliability),
                'efficiency': None,
                'stability': clamp(stability),
            }

        except Exception as e:
            logging.getLogger(__name__).error(f"Error calculating health score: {e}")
            return None

# Retention (deleting old rows from the time-series tables) is handled by
# services/retention.py on a schedule -- never from insert hooks.


def init_db(app):
    db.init_app(app)

    with app.app_context():
        # Pin SQLite pragmas on every new connection. WAL was already active at
        # runtime but not in code, and the others were at defaults — mmap_size=0
        # disables memory-mapped I/O entirely, which hurts large sequential reads.
        if db.engine.url.get_backend_name() == 'sqlite':
            @event.listens_for(db.engine, 'connect')
            def _set_sqlite_pragmas(dbapi_connection, _connection_record):
                cursor = dbapi_connection.cursor()
                try:
                    cursor.execute("PRAGMA journal_mode=WAL")
                    cursor.execute("PRAGMA synchronous=NORMAL")
                    cursor.execute("PRAGMA mmap_size=268435456")
                    cursor.execute("PRAGMA temp_store=MEMORY")
                    cursor.execute("PRAGMA cache_size=-65536")  # ~64 MB page cache
                finally:
                    cursor.close()

        db.create_all()

        # Columns added after a table already existed. create_all() never alters
        # tables, so each is added idempotently here (and by
        # scripts/db/v250_schema_cleanup.py during a maintenance window).
        _ensure_columns('configuration', {'version': 'INTEGER DEFAULT 1'})
        _ensure_columns('devices', {'notes': 'TEXT', 'tags': 'VARCHAR(255)', 'mdns_services': 'VARCHAR(500)'})

        seed_default_configuration()


def _ensure_columns(table, columns):
    """Add any of ``columns`` ({name: ddl}) missing from ``table``. Returns the names added.

    Never falls back to drop_all()/create_all(): on a locked or partially migrated
    production database that would destroy every table. Fails loudly instead.
    """
    if db.engine.url.get_backend_name() == 'sqlite':
        rows = db.session.execute(db.text(f"PRAGMA table_info({table})")).fetchall()
        existing = {row[1] for row in rows}
    else:
        rows = db.session.execute(db.text(
            "SELECT column_name FROM information_schema.columns WHERE table_name = :t"), {'t': table}).fetchall()
        existing = {row[0] for row in rows}
    added = []
    for name, ddl in columns.items():
        if name in existing:
            continue
        try:
            db.session.execute(db.text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
            db.session.commit()
            logger.info(f"Added column {table}.{name}")
            added.append(name)
        except Exception as e:
            db.session.rollback()
            raise RuntimeError(f"Could not add column {table}.{name}; refusing to start with an inconsistent schema") from e
    return added


def seed_default_configuration():
    """Seed runtime Configuration rows that are missing; must run inside an app context.

    Runtime values always win over the environment afterwards, so seeds come
    from config.py (which reads .env) -- the old hardcoded 30 s / 300 s / 60 s
    seeds made every fresh install run 20x faster than documented. Existing
    rows that differ from the environment are reported, not overwritten.
    """
    from config import Config
    default_configs = [
        ('network_range', Config.NETWORK_RANGE, 'Network range to monitor'),
        ('ping_interval', str(Config.PING_INTERVAL), 'Ping interval in seconds'),
        ('scan_interval', str(Config.SCAN_INTERVAL), 'Network scan interval in seconds'),
        ('bandwidth_interval', str(Config.BANDWIDTH_INTERVAL), 'Bandwidth monitoring interval in seconds'),
        ('alert_email_enabled', 'false', 'Enable email alerts'),
        ('alert_webhook_enabled', 'false', 'Enable webhook alerts'),
    ]

    seed_logger = logging.getLogger(__name__)
    for key, value, description in default_configs:
        try:
            existing = Configuration.query.filter_by(key=key).first()
            if not existing:
                Configuration.set_value(key, value, description)
            elif existing.value != value and key in ('ping_interval', 'scan_interval',
                                                      'bandwidth_interval', 'network_range'):
                # Runtime override differs from the environment. Surface it so an
                # operator editing .env understands why nothing changed.
                seed_logger.warning(
                    f"Runtime setting {key}={existing.value!r} overrides {key.upper()}={value!r} "
                    f"from the environment (edit it in Settings or via /api/config/{key})")
        except Exception as e:
            seed_logger.error(f"Error initializing configuration {key}: {e}")


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
