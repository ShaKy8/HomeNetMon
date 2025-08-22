# HomeNetMon Multi-Tenant Models
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, JSON, ForeignKey, Float, Enum as SQLEnum, Index, UniqueConstraint
from sqlalchemy.orm import relationship, declarative_base, sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.dialects.postgresql import UUID
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from enum import Enum
import uuid
import hashlib
from typing import Optional, Dict, Any, List
import json

# Tenant-aware base model
class TenantMixin:
    """Mixin to add tenant isolation to any model"""
    
    @declared_attr
    def tenant_id(cls):
        return Column(String(36), ForeignKey('tenants.id'), nullable=False, index=True)
    
    @declared_attr
    def tenant(cls):
        return relationship("Tenant", back_populates=f"{cls.__tablename__}")

# Subscription tiers and plans
class SubscriptionTier(Enum):
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"

class BillingInterval(Enum):
    MONTHLY = "monthly"
    YEARLY = "yearly"
    ONE_TIME = "one_time"

class TenantStatus(Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CANCELLED = "cancelled"
    PENDING = "pending"
    TRIAL = "trial"

class UsageMetricType(Enum):
    DEVICES_MONITORED = "devices_monitored"
    API_CALLS = "api_calls"
    DATA_RETENTION_DAYS = "data_retention_days"
    ALERTS_PER_MONTH = "alerts_per_month"
    USERS_PER_TENANT = "users_per_tenant"
    STORAGE_GB = "storage_gb"
    BANDWIDTH_GB = "bandwidth_gb"
    CUSTOM_INTEGRATIONS = "custom_integrations"

# Core tenant model
class Tenant(db.Model):
    """Multi-tenant organization model"""
    __tablename__ = 'tenants'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    subdomain = Column(String(63), unique=True, nullable=False, index=True)
    custom_domain = Column(String(255), unique=True, nullable=True)
    
    # Contact and billing information
    admin_email = Column(String(255), nullable=False)
    company_name = Column(String(255), nullable=True)
    billing_email = Column(String(255), nullable=True)
    phone = Column(String(50), nullable=True)
    
    # Address information
    address_line1 = Column(String(255), nullable=True)
    address_line2 = Column(String(255), nullable=True)
    city = Column(String(100), nullable=True)
    state_province = Column(String(100), nullable=True)
    postal_code = Column(String(20), nullable=True)
    country = Column(String(2), nullable=True)  # ISO country code
    
    # Tenant status and lifecycle
    status = Column(SQLEnum(TenantStatus), default=TenantStatus.TRIAL, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    trial_ends_at = Column(DateTime, nullable=True)
    suspended_at = Column(DateTime, nullable=True)
    suspension_reason = Column(Text, nullable=True)
    
    # Configuration and customization
    settings = Column(JSON, default=dict, nullable=False)
    branding = Column(JSON, default=dict, nullable=False)
    feature_flags = Column(JSON, default=dict, nullable=False)
    
    # Database isolation settings
    database_schema = Column(String(63), nullable=True)  # For schema-based isolation
    database_url = Column(String(500), nullable=True)    # For database-based isolation
    encryption_key = Column(String(64), nullable=True)   # For data encryption
    
    # Relationships
    subscription = relationship("TenantSubscription", back_populates="tenant", uselist=False)
    users = relationship("TenantUser", back_populates="tenant")
    usage_records = relationship("UsageRecord", back_populates="tenant")
    audit_logs = relationship("TenantAuditLog", back_populates="tenant")
    
    # Tenant-specific device models
    devices = relationship("TenantDevice", back_populates="tenant")
    monitoring_data = relationship("TenantMonitoringData", back_populates="tenant")
    alerts = relationship("TenantAlert", back_populates="tenant")
    
    def __repr__(self):
        return f'<Tenant {self.name} ({self.subdomain})>'
    
    @property
    def is_active(self):
        return self.status == TenantStatus.ACTIVE
    
    @property
    def is_trial(self):
        return self.status == TenantStatus.TRIAL
    
    @property
    def trial_expired(self):
        if self.trial_ends_at:
            return datetime.utcnow() > self.trial_ends_at
        return False
    
    @property
    def full_domain(self):
        """Get the full domain for this tenant"""
        if self.custom_domain:
            return self.custom_domain
        return f"{self.subdomain}.homenetmon.com"
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a tenant-specific setting"""
        return self.settings.get(key, default)
    
    def set_setting(self, key: str, value: Any):
        """Set a tenant-specific setting"""
        if self.settings is None:
            self.settings = {}
        self.settings[key] = value
    
    def get_quota(self, metric: UsageMetricType) -> Optional[int]:
        """Get quota for a specific usage metric"""
        if self.subscription:
            return self.subscription.get_quota(metric)
        return None
    
    def get_usage(self, metric: UsageMetricType, period_days: int = 30) -> float:
        """Get current usage for a metric"""
        from sqlalchemy import func
        since = datetime.utcnow() - timedelta(days=period_days)
        
        usage = db.session.query(func.sum(UsageRecord.quantity)).filter(
            UsageRecord.tenant_id == self.id,
            UsageRecord.metric_type == metric,
            UsageRecord.recorded_at >= since
        ).scalar()
        
        return float(usage) if usage else 0.0

class SubscriptionPlan(db.Model):
    """Subscription plan definitions"""
    __tablename__ = 'subscription_plans'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    tier = Column(SQLEnum(SubscriptionTier), nullable=False)
    billing_interval = Column(SQLEnum(BillingInterval), nullable=False)
    
    # Pricing
    price_cents = Column(Integer, nullable=False)  # Price in cents
    currency = Column(String(3), default='USD', nullable=False)
    
    # Plan features and limits
    quotas = Column(JSON, default=dict, nullable=False)  # Usage quotas
    features = Column(JSON, default=dict, nullable=False)  # Feature flags
    
    # Plan metadata
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    subscriptions = relationship("TenantSubscription", back_populates="plan")
    
    def __repr__(self):
        return f'<SubscriptionPlan {self.name} ({self.tier.value})>'
    
    @property
    def price_dollars(self):
        return self.price_cents / 100.0
    
    def get_quota(self, metric: UsageMetricType) -> Optional[int]:
        """Get quota for a specific metric"""
        return self.quotas.get(metric.value)
    
    def has_feature(self, feature: str) -> bool:
        """Check if plan includes a specific feature"""
        return self.features.get(feature, False)

class TenantSubscription(db.Model):
    """Tenant subscription and billing information"""
    __tablename__ = 'tenant_subscriptions'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey('tenants.id'), nullable=False, unique=True)
    plan_id = Column(String(36), ForeignKey('subscription_plans.id'), nullable=False)
    
    # Subscription lifecycle
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    current_period_start = Column(DateTime, default=datetime.utcnow, nullable=False)
    current_period_end = Column(DateTime, nullable=False)
    cancelled_at = Column(DateTime, nullable=True)
    cancel_at_period_end = Column(Boolean, default=False, nullable=False)
    
    # Billing information
    external_subscription_id = Column(String(255), nullable=True)  # Stripe, etc.
    payment_method_id = Column(String(255), nullable=True)
    last_payment_at = Column(DateTime, nullable=True)
    next_billing_date = Column(DateTime, nullable=True)
    
    # Usage and overages
    current_usage = Column(JSON, default=dict, nullable=False)
    overage_charges = Column(Integer, default=0, nullable=False)  # In cents
    
    # Relationships
    tenant = relationship("Tenant", back_populates="subscription")
    plan = relationship("SubscriptionPlan", back_populates="subscriptions")
    invoices = relationship("Invoice", back_populates="subscription")
    
    def __repr__(self):
        return f'<TenantSubscription {self.tenant.name} - {self.plan.name}>'
    
    @property
    def is_active(self):
        now = datetime.utcnow()
        return (not self.cancelled_at or self.cancelled_at > now) and \
               self.current_period_end > now
    
    @property
    def days_until_renewal(self):
        if self.current_period_end:
            delta = self.current_period_end - datetime.utcnow()
            return max(0, delta.days)
        return 0
    
    def get_quota(self, metric: UsageMetricType) -> Optional[int]:
        """Get quota for a specific usage metric"""
        return self.plan.get_quota(metric)
    
    def get_current_usage(self, metric: UsageMetricType) -> float:
        """Get current usage for a metric"""
        return self.current_usage.get(metric.value, 0.0)
    
    def is_over_quota(self, metric: UsageMetricType) -> bool:
        """Check if tenant is over quota for a metric"""
        quota = self.get_quota(metric)
        if quota is None:
            return False
        
        usage = self.get_current_usage(metric)
        return usage > quota

class TenantUser(db.Model):
    """Tenant-specific user accounts"""
    __tablename__ = 'tenant_users'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey('tenants.id'), nullable=False)
    
    # User information
    email = Column(String(255), nullable=False)
    username = Column(String(100), nullable=True)
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    
    # Authentication
    password_hash = Column(String(255), nullable=True)
    is_sso_user = Column(Boolean, default=False, nullable=False)
    sso_provider = Column(String(50), nullable=True)
    sso_subject = Column(String(255), nullable=True)
    
    # Authorization
    role = Column(String(50), default='user', nullable=False)
    permissions = Column(JSON, default=list, nullable=False)
    is_tenant_admin = Column(Boolean, default=False, nullable=False)
    
    # Account status
    is_active = Column(Boolean, default=True, nullable=False)
    email_verified = Column(Boolean, default=False, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    
    # Unique constraint for email per tenant
    __table_args__ = (
        UniqueConstraint('tenant_id', 'email', name='_tenant_user_email_uc'),
        Index('ix_tenant_users_tenant_email', 'tenant_id', 'email'),
    )
    
    def __repr__(self):
        return f'<TenantUser {self.email} @ {self.tenant.name}>'
    
    @property
    def full_name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.email
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission"""
        return permission in self.permissions or self.is_tenant_admin

class UsageRecord(db.Model):
    """Usage tracking for billing and quotas"""
    __tablename__ = 'usage_records'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey('tenants.id'), nullable=False)
    
    # Usage details
    metric_type = Column(SQLEnum(UsageMetricType), nullable=False)
    quantity = Column(Float, nullable=False)
    unit = Column(String(20), default='count', nullable=False)
    
    # Timing
    recorded_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    period_start = Column(DateTime, nullable=True)
    period_end = Column(DateTime, nullable=True)
    
    # Metadata
    metadata = Column(JSON, default=dict, nullable=False)
    source = Column(String(100), nullable=True)  # API, background job, etc.
    
    # Relationships
    tenant = relationship("Tenant", back_populates="usage_records")
    
    # Indexes for efficient querying
    __table_args__ = (
        Index('ix_usage_records_tenant_metric_time', 'tenant_id', 'metric_type', 'recorded_at'),
        Index('ix_usage_records_period', 'period_start', 'period_end'),
    )
    
    def __repr__(self):
        return f'<UsageRecord {self.metric_type.value}: {self.quantity}>'

class Invoice(db.Model):
    """Billing invoices"""
    __tablename__ = 'invoices'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    subscription_id = Column(String(36), ForeignKey('tenant_subscriptions.id'), nullable=False)
    
    # Invoice details
    invoice_number = Column(String(50), unique=True, nullable=False)
    amount_cents = Column(Integer, nullable=False)
    currency = Column(String(3), default='USD', nullable=False)
    
    # Billing period
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    
    # Status
    status = Column(String(20), default='draft', nullable=False)  # draft, sent, paid, failed
    due_date = Column(DateTime, nullable=False)
    paid_at = Column(DateTime, nullable=True)
    
    # External payment system
    external_invoice_id = Column(String(255), nullable=True)
    payment_method = Column(String(50), nullable=True)
    
    # Invoice items
    line_items = Column(JSON, default=list, nullable=False)
    
    # Relationships
    subscription = relationship("TenantSubscription", back_populates="invoices")
    
    def __repr__(self):
        return f'<Invoice {self.invoice_number}: ${self.amount_cents/100}>'
    
    @property
    def amount_dollars(self):
        return self.amount_cents / 100.0
    
    @property
    def is_overdue(self):
        return self.status != 'paid' and datetime.utcnow() > self.due_date

class TenantAuditLog(db.Model):
    """Audit logging for tenant activities"""
    __tablename__ = 'tenant_audit_logs'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey('tenants.id'), nullable=False)
    
    # Event details
    event_type = Column(String(100), nullable=False)
    event_category = Column(String(50), nullable=False)  # auth, billing, admin, etc.
    description = Column(Text, nullable=False)
    
    # Actor information
    user_id = Column(String(36), nullable=True)
    user_email = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Context
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(36), nullable=True)
    before_state = Column(JSON, nullable=True)
    after_state = Column(JSON, nullable=True)
    
    # Timing
    occurred_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="audit_logs")
    
    # Indexes
    __table_args__ = (
        Index('ix_audit_logs_tenant_time', 'tenant_id', 'occurred_at'),
        Index('ix_audit_logs_event_type', 'event_type'),
        Index('ix_audit_logs_user', 'user_id', 'user_email'),
    )
    
    def __repr__(self):
        return f'<TenantAuditLog {self.event_type} @ {self.occurred_at}>'

# Tenant-aware versions of core HomeNetMon models
class TenantDevice(db.Model, TenantMixin):
    """Tenant-isolated device model"""
    __tablename__ = 'tenant_devices'
    
    id = Column(Integer, primary_key=True)
    display_name = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=False)
    mac_address = Column(String(17), nullable=True)
    device_type = Column(String(50), nullable=True)
    vendor = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    
    # Monitoring configuration
    monitoring_enabled = Column(Boolean, default=True, nullable=False)
    ping_interval = Column(Integer, default=60, nullable=False)
    
    # Current status
    status = Column(String(20), default='unknown', nullable=False)
    last_seen = Column(DateTime, nullable=True)
    uptime_percentage = Column(Float, default=0.0, nullable=False)
    latest_response_time = Column(Float, nullable=True)
    active_alerts = Column(Integer, default=0, nullable=False)
    
    # Device grouping
    device_group = Column(String(100), nullable=True)
    tags = Column(JSON, default=list, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    monitoring_data = relationship("TenantMonitoringData", back_populates="device", cascade="all, delete-orphan")
    alerts = relationship("TenantAlert", back_populates="device")
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('tenant_id', 'ip_address', name='_tenant_device_ip_uc'),
        Index('ix_tenant_devices_tenant_status', 'tenant_id', 'status'),
        Index('ix_tenant_devices_monitoring', 'tenant_id', 'monitoring_enabled'),
    )
    
    def __repr__(self):
        return f'<TenantDevice {self.display_name} ({self.ip_address})>'

class TenantMonitoringData(db.Model, TenantMixin):
    """Tenant-isolated monitoring data"""
    __tablename__ = 'tenant_monitoring_data'
    
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey('tenant_devices.id'), nullable=False)
    
    # Monitoring metrics
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    response_time = Column(Float, nullable=True)
    packet_loss = Column(Float, default=0.0, nullable=False)
    status = Column(String(20), nullable=False)
    
    # Additional metrics
    jitter = Column(Float, nullable=True)
    bandwidth_up = Column(Float, nullable=True)
    bandwidth_down = Column(Float, nullable=True)
    
    # Metadata
    metadata = Column(JSON, default=dict, nullable=False)
    
    # Relationships
    device = relationship("TenantDevice", back_populates="monitoring_data")
    
    # Indexes for efficient time-series queries
    __table_args__ = (
        Index('ix_tenant_monitoring_data_device_time', 'tenant_id', 'device_id', 'timestamp'),
        Index('ix_tenant_monitoring_data_time', 'timestamp'),
    )
    
    def __repr__(self):
        return f'<TenantMonitoringData {self.device.display_name} @ {self.timestamp}>'

class TenantAlert(db.Model, TenantMixin):
    """Tenant-isolated alerts"""
    __tablename__ = 'tenant_alerts'
    
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey('tenant_devices.id'), nullable=False)
    
    # Alert details
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    message = Column(Text, nullable=False)
    alert_type = Column(String(50), nullable=False)
    
    # Status
    acknowledged = Column(Boolean, default=False, nullable=False)
    acknowledged_by = Column(String(255), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved = Column(Boolean, default=False, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    
    # Timing
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Metadata
    metadata = Column(JSON, default=dict, nullable=False)
    
    # Relationships
    device = relationship("TenantDevice", back_populates="alerts")
    
    # Indexes
    __table_args__ = (
        Index('ix_tenant_alerts_tenant_status', 'tenant_id', 'acknowledged', 'resolved'),
        Index('ix_tenant_alerts_device_time', 'device_id', 'created_at'),
        Index('ix_tenant_alerts_severity', 'severity', 'created_at'),
    )
    
    def __repr__(self):
        return f'<TenantAlert {self.severity}: {self.message[:50]}>'