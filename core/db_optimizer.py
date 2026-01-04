"""
Database query optimizer to prevent N+1 queries and improve performance.
"""

import logging
from typing import List, Dict, Any, Optional, Type
from sqlalchemy.orm import Query, joinedload, selectinload, subqueryload, contains_eager
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.sql import func
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import time

logger = logging.getLogger(__name__)

class QueryOptimizer:
    """Optimizes database queries to prevent N+1 problems and improve performance."""
    
    def __init__(self, db: SQLAlchemy):
        self.db = db
        self.query_stats = {
            'total_queries': 0,
            'optimized_queries': 0,
            'n1_prevented': 0,
            'avg_query_time': 0
        }
        
    def optimize_query(self, query: Query, relationships: List[str] = None, 
                      strategy: str = 'joinedload') -> Query:
        """
        Optimize a query by eagerly loading relationships.
        
        Args:
            query: SQLAlchemy query object
            relationships: List of relationship names to eagerly load
            strategy: Loading strategy ('joinedload', 'selectinload', 'subqueryload')
            
        Returns:
            Optimized query
        """
        if not relationships:
            return query
            
        strategies = {
            'joinedload': joinedload,
            'selectinload': selectinload,
            'subqueryload': subqueryload
        }
        
        loader = strategies.get(strategy, joinedload)
        
        for relationship in relationships:
            # Support nested relationships (e.g., 'device.monitoring_data')
            if '.' in relationship:
                parts = relationship.split('.')
                option = loader(parts[0])
                for part in parts[1:]:
                    option = option.joinedload(part)
                query = query.options(option)
            else:
                query = query.options(loader(relationship))
                
        self.query_stats['optimized_queries'] += 1
        logger.debug(f"Optimized query with {strategy} for relationships: {relationships}")
        
        return query
        
    def get_devices_with_monitoring_data(self, limit: Optional[int] = None) -> List:
        """
        Get devices with their monitoring data efficiently.
        Prevents N+1 queries when accessing device.monitoring_data.
        """
        from models import Device, MonitoringData
        
        query = self.db.session.query(Device)
        
        # Eagerly load monitoring data with the latest entry
        query = query.options(
            selectinload(Device.monitoring_data).joinedload(MonitoringData.device)
        )
        
        if limit:
            query = query.limit(limit)
            
        self.query_stats['n1_prevented'] += 1
        return query.all()
        
    def get_devices_with_alerts(self, active_only: bool = True) -> List:
        """
        Get devices with their alerts efficiently.
        Prevents N+1 queries when accessing device.alerts.
        """
        from models import Device, Alert
        
        query = self.db.session.query(Device)
        
        if active_only:
            # Join with alerts and filter
            query = query.join(Alert).filter(Alert.resolved == False)
            query = query.options(contains_eager(Device.alerts))
        else:
            # Load all alerts
            query = query.options(selectinload(Device.alerts))
            
        self.query_stats['n1_prevented'] += 1
        return query.all()
        
    def get_device_summary(self) -> Dict[str, Any]:
        """
        Get device summary statistics efficiently using aggregation.
        Avoids multiple queries for counts.
        """
        from models import Device, Alert, MonitoringData
        
        # Single query for device statistics
        stats = self.db.session.query(
            func.count(Device.id).label('total_devices'),
            func.sum(func.cast(Device.is_monitored, self.db.Integer)).label('monitored_devices'),
            func.count(func.distinct(Device.device_group)).label('device_groups')
        ).first()
        
        # Single query for alert statistics
        alert_stats = self.db.session.query(
            func.count(Alert.id).label('total_alerts'),
            func.sum(func.cast(Alert.resolved == False, self.db.Integer)).label('active_alerts')
        ).first()
        
        # Get latest monitoring timestamp
        latest_monitoring = self.db.session.query(
            func.max(MonitoringData.timestamp)
        ).scalar()
        
        self.query_stats['n1_prevented'] += 3
        
        return {
            'total_devices': stats.total_devices or 0,
            'monitored_devices': stats.monitored_devices or 0,
            'device_groups': stats.device_groups or 0,
            'total_alerts': alert_stats.total_alerts or 0,
            'active_alerts': alert_stats.active_alerts or 0,
            'latest_monitoring': latest_monitoring
        }
        
    def batch_update_devices(self, updates: List[Dict[str, Any]]) -> int:
        """
        Perform batch updates efficiently.
        
        Args:
            updates: List of dicts with 'id' and fields to update
            
        Returns:
            Number of devices updated
        """
        from models import Device
        
        if not updates:
            return 0
            
        # Use bulk_update_mappings for efficiency
        try:
            self.db.session.bulk_update_mappings(Device, updates)
            self.db.session.commit()
            
            logger.info(f"Batch updated {len(updates)} devices")
            return len(updates)
            
        except Exception as e:
            logger.error(f"Batch update failed: {e}")
            self.db.session.rollback()
            return 0
            
    def profile_query(self, func):
        """
        Decorator to profile query execution time.
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            result = func(*args, **kwargs)
            
            execution_time = time.time() - start_time
            self.query_stats['total_queries'] += 1
            
            # Update average query time
            current_avg = self.query_stats['avg_query_time']
            total_queries = self.query_stats['total_queries']
            new_avg = ((current_avg * (total_queries - 1)) + execution_time) / total_queries
            self.query_stats['avg_query_time'] = new_avg
            
            if execution_time > 1.0:  # Log slow queries (>1 second)
                logger.warning(f"Slow query detected in {func.__name__}: {execution_time:.2f}s")
                
            return result
        return wrapper
        
    def get_stats(self) -> Dict[str, Any]:
        """Get query optimization statistics."""
        return self.query_stats.copy()


class OptimizedQueries:
    """Collection of optimized query methods for common operations."""
    
    def __init__(self, db: SQLAlchemy, optimizer: QueryOptimizer):
        self.db = db
        self.optimizer = optimizer
        
    def get_all_devices_for_monitoring(self):
        """Get all devices with necessary data for monitoring."""
        from models import Device
        
        query = self.db.session.query(Device).filter(Device.is_monitored == True)
        
        # Eagerly load relationships needed for monitoring
        query = self.optimizer.optimize_query(
            query,
            relationships=['monitoring_data', 'alerts'],
            strategy='selectinload'
        )
        
        return query.all()
        
    def get_devices_for_dashboard(self):
        """Get devices optimized for dashboard display."""
        from models import Device, MonitoringData
        from sqlalchemy import and_
        
        # Subquery for latest monitoring data per device
        subquery = self.db.session.query(
            MonitoringData.device_id,
            func.max(MonitoringData.timestamp).label('max_timestamp')
        ).group_by(MonitoringData.device_id).subquery()
        
        # Main query with optimized joins
        query = self.db.session.query(Device, MonitoringData).join(
            subquery,
            Device.id == subquery.c.device_id
        ).join(
            MonitoringData,
            and_(
                MonitoringData.device_id == subquery.c.device_id,
                MonitoringData.timestamp == subquery.c.max_timestamp
            )
        )
        
        results = query.all()
        
        # Format results
        devices_data = []
        for device, monitoring in results:
            devices_data.append({
                'device': device,
                'latest_monitoring': monitoring
            })
            
        return devices_data
        
    def get_alerts_with_devices(self, resolved: bool = False):
        """Get alerts with device information efficiently."""
        from models import Alert, Device
        
        query = self.db.session.query(Alert).filter(Alert.resolved == resolved)
        
        # Eagerly load device information
        query = query.options(joinedload(Alert.device))
        
        return query.all()
        
    def get_device_metrics(self, device_id: int, hours: int = 24):
        """Get device metrics for a specific time period."""
        from models import MonitoringData
        from datetime import datetime, timedelta
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Use aggregation for efficient metrics calculation
        metrics = self.db.session.query(
            func.avg(MonitoringData.response_time).label('avg_response'),
            func.min(MonitoringData.response_time).label('min_response'),
            func.max(MonitoringData.response_time).label('max_response'),
            func.count(MonitoringData.id).label('total_pings'),
            func.sum(
                func.cast(MonitoringData.response_time.is_(None), self.db.Integer)
            ).label('failed_pings')
        ).filter(
            MonitoringData.device_id == device_id,
            MonitoringData.timestamp >= cutoff
        ).first()
        
        return {
            'avg_response_time': float(metrics.avg_response or 0),
            'min_response_time': float(metrics.min_response or 0),
            'max_response_time': float(metrics.max_response or 0),
            'total_pings': metrics.total_pings or 0,
            'failed_pings': metrics.failed_pings or 0,
            'success_rate': ((metrics.total_pings - (metrics.failed_pings or 0)) / 
                           metrics.total_pings * 100) if metrics.total_pings else 0
        }


class DatabaseIndexManager:
    """Manages database indexes for performance optimization."""
    
    def __init__(self, db: SQLAlchemy):
        self.db = db
        
    def create_performance_indexes(self):
        """Create indexes for frequently queried columns."""
        index_definitions = [
            # Device indexes
            'CREATE INDEX IF NOT EXISTS idx_device_status ON devices(last_seen)',
            'CREATE INDEX IF NOT EXISTS idx_device_group ON devices(device_group)',
            'CREATE INDEX IF NOT EXISTS idx_device_monitored ON devices(is_monitored)',
            
            # MonitoringData indexes
            'CREATE INDEX IF NOT EXISTS idx_monitoring_timestamp ON monitoring_data(timestamp DESC)',
            'CREATE INDEX IF NOT EXISTS idx_monitoring_device_timestamp ON monitoring_data(device_id, timestamp DESC)',
            'CREATE INDEX IF NOT EXISTS idx_monitoring_response ON monitoring_data(response_time)',
            
            # Alert indexes
            'CREATE INDEX IF NOT EXISTS idx_alert_resolved ON alerts(resolved)',
            'CREATE INDEX IF NOT EXISTS idx_alert_device_resolved ON alerts(device_id, resolved)',
            'CREATE INDEX IF NOT EXISTS idx_alert_created ON alerts(created_at DESC)',
            
            # Composite indexes for common queries
            'CREATE INDEX IF NOT EXISTS idx_device_monitoring ON devices(id, is_monitored) WHERE is_monitored = 1',
            'CREATE INDEX IF NOT EXISTS idx_active_alerts ON alerts(device_id, resolved) WHERE resolved = 0',

            # BandwidthData indexes (for "latest bandwidth per device" queries)
            'CREATE INDEX IF NOT EXISTS idx_bandwidth_device_timestamp ON bandwidth_data(device_id, timestamp DESC)',

            # PerformanceMetrics indexes (for "latest metrics per device" queries)
            'CREATE INDEX IF NOT EXISTS idx_performance_device_timestamp ON performance_metrics(device_id, timestamp DESC)',

            # Composite index for monitored device status checks
            'CREATE INDEX IF NOT EXISTS idx_devices_monitored_last_seen ON devices(is_monitored, last_seen DESC)'
        ]
        
        try:
            for index_sql in index_definitions:
                self.db.session.execute(index_sql)
            self.db.session.commit()
            logger.info(f"Created {len(index_definitions)} performance indexes")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create indexes: {e}")
            self.db.session.rollback()
            return False
            
    def analyze_tables(self):
        """Run ANALYZE on tables to update query planner statistics."""
        tables = ['devices', 'monitoring_data', 'alerts']
        
        try:
            for table in tables:
                self.db.session.execute(f'ANALYZE {table}')
            self.db.session.commit()
            logger.info(f"Analyzed {len(tables)} tables for query optimization")
            return True
            
        except Exception as e:
            logger.error(f"Failed to analyze tables: {e}")
            self.db.session.rollback()
            return False