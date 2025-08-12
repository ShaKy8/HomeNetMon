from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
import json

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
    is_monitored = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_seen = db.Column(db.DateTime)
    
    # Relationships
    monitoring_data = db.relationship('MonitoringData', backref='device', cascade='all, delete-orphan', lazy=True)
    alerts = db.relationship('Alert', backref='device', cascade='all, delete-orphan', lazy=True)
    
    def __repr__(self):
        return f'<Device {self.ip_address} ({self.display_name})>'
    
    @property
    def display_name(self):
        return self.custom_name or self.hostname or self.ip_address
    
    @property
    def status(self):
        if not self.last_seen:
            return 'unknown'
        
        # Consider device down if not seen for more than 10 minutes (600 seconds)
        # This is more forgiving than the previous 3*ping_interval approach
        from config import Config
        threshold = datetime.utcnow() - timedelta(seconds=600)
        
        if self.last_seen < threshold:
            return 'down'
        
        # Check latest monitoring data for response time
        latest_data = MonitoringData.query.filter_by(device_id=self.id)\
                                         .order_by(MonitoringData.timestamp.desc())\
                                         .first()
        
        if latest_data:
            if latest_data.response_time is None:
                return 'down'
            elif latest_data.response_time > 1000:  # >1 second
                return 'warning'
        
        return 'up'
    
    @property
    def latest_response_time(self):
        """Get the latest response time for this device"""
        latest_data = MonitoringData.query.filter_by(device_id=self.id)\
                                         .order_by(MonitoringData.timestamp.desc())\
                                         .first()
        return latest_data.response_time if latest_data else None
    
    @property
    def active_alerts(self):
        """Get count of active (unresolved) alerts for this device"""
        return Alert.query.filter_by(device_id=self.id, resolved=False).count()
    
    @property
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
            'display_name': self.display_name,
            'is_monitored': self.is_monitored,
            'status': self.status,
            'uptime_percentage': self.uptime_percentage,
            'created_at': (self.created_at.isoformat() + 'Z') if self.created_at else None,
            'updated_at': (self.updated_at.isoformat() + 'Z') if self.updated_at else None,
            'last_seen': (self.last_seen.isoformat() + 'Z') if self.last_seen else None,
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
    alert_type = db.Column(db.String(50), nullable=False)  # device_down, high_latency, etc.
    severity = db.Column(db.String(20), default='warning')  # info, warning, critical
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_at = db.Column(db.DateTime)
    acknowledged_by = db.Column(db.String(100))  # username or system
    resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime)
    
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
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': self.device.display_name,
            'device_ip': self.device.ip_address,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'message': self.message,
            'created_at': self.created_at.isoformat() + 'Z',
            'acknowledged': self.acknowledged,
            'acknowledged_at': (self.acknowledged_at.isoformat() + 'Z') if self.acknowledged_at else None,
            'acknowledged_by': self.acknowledged_by,
            'resolved': self.resolved,
            'resolved_at': (self.resolved_at.isoformat() + 'Z') if self.resolved_at else None,
        }

class Configuration(db.Model):
    __tablename__ = 'configuration'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Configuration {self.key}={self.value}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'key': self.key,
            'value': self.value,
            'description': self.description,
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
            config.value = value
            if description:
                config.description = description
        else:
            config = cls(key=key, value=value, description=description)
            db.session.add(config)
        db.session.commit()
        return config

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
        
        # Initialize default configuration
        default_configs = [
            ('network_range', '192.168.86.0/24', 'Network range to monitor'),
            ('ping_interval', '30', 'Ping interval in seconds'),
            ('scan_interval', '300', 'Network scan interval in seconds'),
            ('alert_email_enabled', 'false', 'Enable email alerts'),
            ('alert_webhook_enabled', 'false', 'Enable webhook alerts'),
        ]
        
        for key, value, description in default_configs:
            if not Configuration.query.filter_by(key=key).first():
                Configuration.set_value(key, value, description)