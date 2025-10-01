"""
Query Optimizer for HomeNetMon
Optimizes database queries for maximum performance.
"""

from sqlalchemy import text
from sqlalchemy.orm import joinedload, selectinload, Load
from models import Device, MonitoringData, Alert
import logging

logger = logging.getLogger(__name__)

class QueryOptimizer:
    """Optimize database queries to prevent N+1 and improve performance."""
    
    @staticmethod
    def get_devices_optimized(db_session, limit=None):
        """Get devices with all related data in a single optimized query."""
        
        # Use eager loading to prevent N+1 queries
        query = db_session.query(Device)\
            .options(
                selectinload(Device.monitoring_data),
                selectinload(Device.alerts)
            )\
            .filter(Device.is_monitored == True)
        
        if limit:
            query = query.limit(limit)
        
        # Execute with compiled query for better performance
        return query.all()
    
    @staticmethod
    def get_device_with_recent_data(db_session, device_id, hours=24):
        """Get device with recent monitoring data in single query."""
        
        from datetime import datetime, timedelta
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Single query with filtered eager loading
        device = db_session.query(Device)\
            .options(
                selectinload(Device.monitoring_data).filter(
                    MonitoringData.timestamp >= cutoff
                ),
                selectinload(Device.alerts).filter(
                    Alert.resolved == False
                )
            )\
            .filter(Device.id == device_id)\
            .first()
        
        return device
    
    @staticmethod
    def get_dashboard_data_optimized(db_session):
        """Get all dashboard data in minimal queries."""
        
        # Use raw SQL for complex aggregations
        result = db_session.execute(text("""
            WITH device_stats AS (
                SELECT 
                    COUNT(*) as total_devices,
                    SUM(CASE WHEN last_seen > datetime('now', '-10 minutes') THEN 1 ELSE 0 END) as online_devices,
                    SUM(CASE WHEN last_seen <= datetime('now', '-10 minutes') THEN 1 ELSE 0 END) as offline_devices
                FROM devices
                WHERE is_monitored = 1
            ),
            alert_stats AS (
                SELECT 
                    COUNT(*) as active_alerts,
                    COUNT(DISTINCT device_id) as affected_devices
                FROM alerts
                WHERE resolved = 0
            ),
            response_stats AS (
                SELECT 
                    AVG(response_time) as avg_response,
                    MIN(response_time) as min_response,
                    MAX(response_time) as max_response
                FROM monitoring_data
                WHERE timestamp > datetime('now', '-1 hour')
                AND response_time IS NOT NULL
            )
            SELECT * FROM device_stats, alert_stats, response_stats
        """))
        
        return result.fetchone()
