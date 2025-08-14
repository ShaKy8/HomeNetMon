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
            'current_bandwidth': self.get_current_bandwidth(),
            'bandwidth_usage_24h': self.get_bandwidth_usage_24h(),
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

class SecurityScan(db.Model):
    """Model for storing security scan results"""
    __tablename__ = 'security_scans'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    state = db.Column(db.String(20), nullable=False)  # open, closed, filtered
    service = db.Column(db.String(50))
    version = db.Column(db.String(100))
    product = db.Column(db.String(100))
    extra_info = db.Column(db.Text)
    confidence = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Float, default=0.0)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    device = db.relationship('Device', backref=db.backref('security_scans', lazy=True))
    
    def __repr__(self):
        return f'<SecurityScan {self.ip_address}:{self.port} - {self.service}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': self.device.display_name if self.device else 'Unknown',
            'ip_address': self.ip_address,
            'port': self.port,
            'state': self.state,
            'service': self.service,
            'version': self.version,
            'product': self.product,
            'extra_info': self.extra_info,
            'confidence': self.confidence,
            'risk_score': self.risk_score,
            'scanned_at': self.scanned_at.isoformat() + 'Z'
        }

class SecurityEvent(db.Model):
    """Model for tracking security events and changes"""
    __tablename__ = 'security_events'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)  # scan_completed, new_service, service_removed, etc.
    severity = db.Column(db.String(20), default='info')    # info, low, medium, high, critical
    message = db.Column(db.Text, nullable=False)
    event_metadata = db.Column(db.Text)  # JSON metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    device = db.relationship('Device', backref=db.backref('security_events', lazy=True))
    
    def __repr__(self):
        return f'<SecurityEvent {self.event_type} for {self.device.ip_address if self.device else "Unknown"}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': self.device.display_name if self.device else 'Unknown',
            'event_type': self.event_type,
            'severity': self.severity,
            'message': self.message,
            'event_metadata': self.event_metadata,
            'created_at': self.created_at.isoformat() + 'Z'
        }

class NotificationHistory(db.Model):
    """Model for tracking sent push notifications"""
    __tablename__ = 'notification_history'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=True, index=True)  # Nullable for system notifications
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
    
    # Relationships
    device = db.relationship('Device', backref=db.backref('notification_history', lazy=True))
    
    def __repr__(self):
        device_name = self.device.display_name if self.device else 'System'
        return f'<NotificationHistory {self.notification_type} for {device_name} at {self.sent_at}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'device_name': self.device.display_name if self.device else 'System',
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
    def log_notification(cls, device_id=None, notification_type='', title='', message='', 
                        priority='default', tags='', delivery_status='unknown', 
                        error_message=None, metadata=None):
        """Log a sent notification"""
        try:
            notification = cls(
                device_id=device_id,
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
        except:
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
        except:
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
        except:
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
        except:
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