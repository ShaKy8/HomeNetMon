"""
Device metrics service - moves complex calculations from models to service layer.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy import func, and_, or_
from flask_sqlalchemy import SQLAlchemy
import statistics

logger = logging.getLogger(__name__)

class DeviceMetricsService:
    """Service for calculating device metrics and statistics."""
    
    def __init__(self, db: SQLAlchemy):
        self.db = db
        
    def calculate_device_status(self, device_id: int) -> str:
        """
        Calculate device status based on monitoring data.
        Moved from Device model to reduce model complexity.
        """
        from models import Device, MonitoringData
        
        device = Device.query.get(device_id)
        if not device:
            return 'unknown'
            
        if not device.last_seen:
            return 'unknown'
            
        # Consider device down if not seen for more than 10 minutes
        threshold = datetime.utcnow() - timedelta(seconds=600)
        
        if device.last_seen < threshold:
            return 'down'
            
        # Check latest monitoring data
        latest_data = MonitoringData.query.filter_by(device_id=device_id)\
                                         .order_by(MonitoringData.timestamp.desc())\
                                         .first()
                                         
        if latest_data:
            if latest_data.response_time is None:
                return 'down'
            elif latest_data.response_time > 1000:  # >1 second
                return 'warning'
                
        return 'up'
        
    def calculate_uptime_percentage(self, device_id: int, days: int = 7) -> float:
        """
        Calculate uptime percentage with intelligent downtime detection.
        Moved from Device model for better performance and testability.
        """
        from models import MonitoringData
        
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        # Use aggregation for efficient calculation
        stats = self.db.session.query(
            func.count(MonitoringData.id).label('total_checks'),
            func.sum(
                func.cast(MonitoringData.response_time.isnot(None), self.db.Integer)
            ).label('successful_checks')
        ).filter(
            MonitoringData.device_id == device_id,
            MonitoringData.timestamp >= cutoff
        ).first()
        
        if not stats or not stats.total_checks:
            return 0.0
            
        return (stats.successful_checks / stats.total_checks) * 100
        
    def get_response_time_stats(self, device_id: int, hours: int = 24) -> Dict[str, float]:
        """
        Calculate response time statistics for a device.
        """
        from models import MonitoringData
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get response times
        response_times = self.db.session.query(MonitoringData.response_time)\
            .filter(
                MonitoringData.device_id == device_id,
                MonitoringData.timestamp >= cutoff,
                MonitoringData.response_time.isnot(None)
            ).all()
            
        if not response_times:
            return {
                'avg': 0.0,
                'min': 0.0,
                'max': 0.0,
                'median': 0.0,
                'percentile_95': 0.0,
                'std_dev': 0.0
            }
            
        times = [rt[0] for rt in response_times]
        
        return {
            'avg': statistics.mean(times),
            'min': min(times),
            'max': max(times),
            'median': statistics.median(times),
            'percentile_95': self._percentile(times, 95),
            'std_dev': statistics.stdev(times) if len(times) > 1 else 0.0
        }
        
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile value."""
        if not data:
            return 0.0
        size = len(data)
        sorted_data = sorted(data)
        index = (percentile / 100) * size
        if index.is_integer():
            return sorted_data[int(index) - 1]
        else:
            lower = sorted_data[int(index) - 1]
            upper = sorted_data[int(index)]
            return (lower + upper) / 2
            
    def get_availability_report(self, device_id: int, days: int = 30) -> Dict[str, Any]:
        """
        Generate comprehensive availability report for a device.
        """
        from models import Device, MonitoringData, Alert
        
        device = Device.query.get(device_id)
        if not device:
            return {}
            
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        # Get monitoring data efficiently
        monitoring_query = MonitoringData.query.filter(
            MonitoringData.device_id == device_id,
            MonitoringData.timestamp >= cutoff
        )
        
        total_checks = monitoring_query.count()
        failed_checks = monitoring_query.filter(
            MonitoringData.response_time.is_(None)
        ).count()
        
        # Calculate downtime periods
        downtime_periods = self._calculate_downtime_periods(device_id, days)
        
        # Get alert statistics
        alert_count = Alert.query.filter(
            Alert.device_id == device_id,
            Alert.created_at >= cutoff
        ).count()
        
        # Calculate metrics
        uptime_percentage = ((total_checks - failed_checks) / total_checks * 100) if total_checks else 0
        total_downtime_minutes = sum(period['duration_minutes'] for period in downtime_periods)
        
        return {
            'device_name': device.display_name,
            'period_days': days,
            'uptime_percentage': round(uptime_percentage, 2),
            'total_checks': total_checks,
            'failed_checks': failed_checks,
            'downtime_periods': downtime_periods,
            'total_downtime_minutes': total_downtime_minutes,
            'alerts_triggered': alert_count,
            'response_time_stats': self.get_response_time_stats(device_id, hours=days*24)
        }
        
    def _calculate_downtime_periods(self, device_id: int, days: int) -> List[Dict[str, Any]]:
        """
        Calculate distinct downtime periods for a device.
        """
        from models import MonitoringData
        
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        # Get all monitoring data ordered by timestamp
        monitoring_data = MonitoringData.query.filter(
            MonitoringData.device_id == device_id,
            MonitoringData.timestamp >= cutoff
        ).order_by(MonitoringData.timestamp).all()
        
        if not monitoring_data:
            return []
            
        downtime_periods = []
        current_downtime_start = None
        
        for data in monitoring_data:
            if data.response_time is None:  # Device is down
                if current_downtime_start is None:
                    current_downtime_start = data.timestamp
            else:  # Device is up
                if current_downtime_start is not None:
                    # End of downtime period
                    duration = (data.timestamp - current_downtime_start).total_seconds() / 60
                    downtime_periods.append({
                        'start': current_downtime_start.isoformat(),
                        'end': data.timestamp.isoformat(),
                        'duration_minutes': round(duration, 2)
                    })
                    current_downtime_start = None
                    
        # Handle ongoing downtime
        if current_downtime_start is not None:
            duration = (datetime.utcnow() - current_downtime_start).total_seconds() / 60
            downtime_periods.append({
                'start': current_downtime_start.isoformat(),
                'end': None,
                'duration_minutes': round(duration, 2),
                'ongoing': True
            })
            
        return downtime_periods
        
    def get_network_health_summary(self) -> Dict[str, Any]:
        """
        Get overall network health summary.
        """
        from models import Device, Alert
        
        # Get device counts by status
        total_devices = Device.query.filter_by(is_monitored=True).count()
        
        # Calculate device statuses efficiently
        device_statuses = {}
        for device in Device.query.filter_by(is_monitored=True).all():
            status = self.calculate_device_status(device.id)
            device_statuses[status] = device_statuses.get(status, 0) + 1
            
        # Get active alerts
        active_alerts = Alert.query.filter_by(resolved=False).count()
        
        # Calculate average response times
        avg_response = self.db.session.query(
            func.avg(func.cast(func.nullif(
                self.db.session.query(func.avg('monitoring_data.response_time'))
                .filter('monitoring_data.device_id = devices.id')
                .filter('monitoring_data.timestamp > :cutoff')
                .scalar_subquery(), 0
            ), self.db.Float))
        ).params(cutoff=datetime.utcnow() - timedelta(hours=1)).scalar()
        
        return {
            'total_devices': total_devices,
            'devices_up': device_statuses.get('up', 0),
            'devices_down': device_statuses.get('down', 0),
            'devices_warning': device_statuses.get('warning', 0),
            'devices_unknown': device_statuses.get('unknown', 0),
            'active_alerts': active_alerts,
            'network_health_score': self._calculate_health_score(device_statuses, total_devices),
            'average_response_time': round(avg_response, 2) if avg_response else 0
        }
        
    def _calculate_health_score(self, device_statuses: Dict[str, int], total_devices: int) -> float:
        """
        Calculate overall network health score (0-100).
        """
        if total_devices == 0:
            return 100.0
            
        # Weighted scoring
        weights = {
            'up': 100,
            'warning': 70,
            'down': 0,
            'unknown': 50
        }
        
        total_score = sum(
            weights.get(status, 0) * count 
            for status, count in device_statuses.items()
        )
        
        return round(total_score / total_devices, 2)
        
    def get_trending_metrics(self, device_id: int, hours: int = 24, 
                           interval_minutes: int = 60) -> List[Dict[str, Any]]:
        """
        Get trending metrics for a device over time.
        """
        from models import MonitoringData
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        interval = timedelta(minutes=interval_minutes)
        
        # Generate time buckets
        buckets = []
        current_time = cutoff
        while current_time < datetime.utcnow():
            bucket_end = current_time + interval
            
            # Get metrics for this bucket
            metrics = self.db.session.query(
                func.avg(MonitoringData.response_time).label('avg_response'),
                func.count(MonitoringData.id).label('total_checks'),
                func.sum(
                    func.cast(MonitoringData.response_time.is_(None), self.db.Integer)
                ).label('failed_checks')
            ).filter(
                MonitoringData.device_id == device_id,
                MonitoringData.timestamp >= current_time,
                MonitoringData.timestamp < bucket_end
            ).first()
            
            if metrics and metrics.total_checks:
                buckets.append({
                    'timestamp': current_time.isoformat(),
                    'avg_response_time': float(metrics.avg_response or 0),
                    'success_rate': ((metrics.total_checks - (metrics.failed_checks or 0)) / 
                                   metrics.total_checks * 100),
                    'total_checks': metrics.total_checks
                })
                
            current_time = bucket_end
            
        return buckets