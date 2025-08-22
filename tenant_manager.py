# HomeNetMon Tenant Management System
from flask import Flask, request, g, session, abort, current_app
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool
from contextlib import contextmanager
from typing import Optional, Dict, Any, List, Union
import logging
import hashlib
import secrets
import re
from datetime import datetime, timedelta
from tenant_models import *
from cloud_config import get_config

logger = logging.getLogger(__name__)

class TenantIsolationStrategy(Enum):
    """Tenant isolation strategies"""
    SHARED_DATABASE = "shared_database"      # Single DB with tenant_id
    SCHEMA_PER_TENANT = "schema_per_tenant"  # Separate schemas
    DATABASE_PER_TENANT = "database_per_tenant"  # Separate databases

class TenantManager:
    """Comprehensive tenant management and isolation"""
    
    def __init__(self, app: Flask = None, isolation_strategy: TenantIsolationStrategy = None):
        self.app = app
        self.isolation_strategy = isolation_strategy or TenantIsolationStrategy.SHARED_DATABASE
        self.tenant_engines = {}  # Cache for tenant-specific database engines
        self.current_tenant = None
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize tenant manager with Flask app"""
        self.app = app
        
        # Configure tenant isolation strategy
        self.isolation_strategy = TenantIsolationStrategy(
            get_config('TENANT_ISOLATION_STRATEGY', 'shared_database')
        )
        
        # Set up request context processors
        app.before_request(self.load_tenant_context)
        app.teardown_appcontext(self.cleanup_tenant_context)
        
        # Add tenant-aware database session
        self.setup_tenant_database()
        
        logger.info(f"TenantManager initialized with {self.isolation_strategy.value} strategy")
    
    def setup_tenant_database(self):
        """Setup tenant-aware database configuration"""
        if self.isolation_strategy == TenantIsolationStrategy.SHARED_DATABASE:
            # Use shared database with tenant_id filtering
            self.setup_shared_database()
        elif self.isolation_strategy == TenantIsolationStrategy.SCHEMA_PER_TENANT:
            # Use schema-based isolation
            self.setup_schema_isolation()
        elif self.isolation_strategy == TenantIsolationStrategy.DATABASE_PER_TENANT:
            # Use database-based isolation
            self.setup_database_isolation()
    
    def setup_shared_database(self):
        """Configure shared database with tenant filtering"""
        # Add automatic tenant_id filtering to all queries
        @event.listens_for(db.session, 'before_bulk_insert')
        def add_tenant_to_bulk_insert(query_context, result):
            if hasattr(g, 'current_tenant') and g.current_tenant:
                if hasattr(query_context.compiled.statement.table.c, 'tenant_id'):
                    query_context.values['tenant_id'] = g.current_tenant.id
        
        # Add tenant filtering to queries
        self.setup_query_filters()
    
    def setup_schema_isolation(self):
        """Configure schema-based tenant isolation"""
        # Override session to use tenant-specific schema
        original_session = db.session
        
        def get_tenant_session():
            if hasattr(g, 'current_tenant') and g.current_tenant:
                schema = g.current_tenant.database_schema or 'public'
                # Set search path for this session
                db.session.execute(f"SET search_path TO {schema}")
            return original_session
        
        # Replace db.session with tenant-aware version
        db.session = property(lambda self: get_tenant_session())
    
    def setup_database_isolation(self):
        """Configure database-based tenant isolation"""
        # Each tenant gets their own database connection
        pass  # Implemented in get_tenant_engine()
    
    def setup_query_filters(self):
        """Setup automatic tenant filtering for queries"""
        # Add tenant_id filter to all tenant-aware models
        for model_class in [TenantDevice, TenantMonitoringData, TenantAlert, UsageRecord]:
            @event.listens_for(model_class, 'before_insert')
            def add_tenant_id(mapper, connection, target):
                if hasattr(g, 'current_tenant') and g.current_tenant:
                    target.tenant_id = g.current_tenant.id
            
            # Add query filter
            @event.listens_for(db.session, 'before_query')
            def filter_by_tenant(query_context):
                if hasattr(g, 'current_tenant') and g.current_tenant:
                    query = query_context.statement
                    if hasattr(query, 'column_descriptions'):
                        for desc in query.column_descriptions:
                            if desc['entity'] and hasattr(desc['entity'], 'tenant_id'):
                                query = query.filter(desc['entity'].tenant_id == g.current_tenant.id)
    
    def load_tenant_context(self):
        """Load tenant context from request"""
        tenant = None
        
        # Try different methods to identify tenant
        tenant = (self.get_tenant_from_subdomain() or 
                 self.get_tenant_from_header() or 
                 self.get_tenant_from_api_key() or
                 self.get_tenant_from_session())
        
        if tenant:
            g.current_tenant = tenant
            self.current_tenant = tenant
            self.validate_tenant_access(tenant)
            self.setup_tenant_database_connection(tenant)
        
        logger.debug(f"Loaded tenant context: {tenant.name if tenant else 'None'}")
    
    def get_tenant_from_subdomain(self) -> Optional[Tenant]:
        """Extract tenant from subdomain"""
        if not request or not hasattr(request, 'host'):
            return None
            
        host = request.host.lower()
        
        # Remove port if present
        if ':' in host:
            host = host.split(':')[0]
        
        # Check for custom domain
        tenant = Tenant.query.filter_by(custom_domain=host).first()
        if tenant:
            return tenant
        
        # Check for subdomain
        if '.' in host:
            subdomain = host.split('.')[0]
            if subdomain != 'www' and subdomain != 'api':
                tenant = Tenant.query.filter_by(subdomain=subdomain).first()
                if tenant:
                    return tenant
        
        return None
    
    def get_tenant_from_header(self) -> Optional[Tenant]:
        """Extract tenant from X-Tenant-ID header"""
        tenant_id = request.headers.get('X-Tenant-ID')
        if tenant_id:
            return Tenant.query.filter_by(id=tenant_id).first()
        
        # Also check for tenant subdomain in header
        tenant_subdomain = request.headers.get('X-Tenant-Subdomain')
        if tenant_subdomain:
            return Tenant.query.filter_by(subdomain=tenant_subdomain).first()
        
        return None
    
    def get_tenant_from_api_key(self) -> Optional[Tenant]:
        """Extract tenant from API key"""
        api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization')
        
        if api_key and api_key.startswith('Bearer '):
            api_key = api_key[7:]
        
        if api_key:
            # Decode API key to extract tenant info
            # Format: tenant_id.encoded_data.signature
            try:
                parts = api_key.split('.')
                if len(parts) >= 2:
                    tenant_id = parts[0]
                    return Tenant.query.filter_by(id=tenant_id).first()
            except Exception:
                pass
        
        return None
    
    def get_tenant_from_session(self) -> Optional[Tenant]:
        """Extract tenant from user session"""
        if 'tenant_id' in session:
            return Tenant.query.filter_by(id=session['tenant_id']).first()
        return None
    
    def validate_tenant_access(self, tenant: Tenant):
        """Validate that tenant has access to the system"""
        if not tenant.is_active:
            if tenant.status == TenantStatus.SUSPENDED:
                abort(403, description=f"Tenant suspended: {tenant.suspension_reason}")
            elif tenant.status == TenantStatus.CANCELLED:
                abort(403, description="Tenant subscription cancelled")
            elif tenant.status == TenantStatus.TRIAL and tenant.trial_expired:
                abort(402, description="Trial period expired")
            else:
                abort(403, description="Tenant access denied")
        
        # Check subscription status
        if tenant.subscription and not tenant.subscription.is_active:
            abort(402, description="Subscription inactive")
    
    def setup_tenant_database_connection(self, tenant: Tenant):
        """Setup database connection for tenant"""
        if self.isolation_strategy == TenantIsolationStrategy.DATABASE_PER_TENANT:
            engine = self.get_tenant_engine(tenant)
            # Use tenant-specific engine for this request
            g.tenant_db_engine = engine
        elif self.isolation_strategy == TenantIsolationStrategy.SCHEMA_PER_TENANT:
            # Set schema search path
            schema = tenant.database_schema or f"tenant_{tenant.id.replace('-', '_')}"
            db.session.execute(f"SET search_path TO {schema}, public")
    
    def get_tenant_engine(self, tenant: Tenant):
        """Get database engine for specific tenant"""
        if tenant.id in self.tenant_engines:
            return self.tenant_engines[tenant.id]
        
        # Create tenant-specific database URL
        if tenant.database_url:
            database_url = tenant.database_url
        else:
            # Generate tenant-specific database URL
            base_url = get_config('DATABASE_URL', 'sqlite:///homenetmon.db')
            if base_url.startswith('sqlite'):
                database_url = f"sqlite:///tenant_{tenant.id}.db"
            else:
                # For PostgreSQL/MySQL, append tenant database name
                db_name = f"homenetmon_tenant_{tenant.id.replace('-', '_')}"
                database_url = base_url.rsplit('/', 1)[0] + f"/{db_name}"
        
        # Create engine with tenant-specific connection
        engine = create_engine(
            database_url,
            poolclass=StaticPool,
            pool_pre_ping=True,
            echo=get_config('SQL_ECHO', False)
        )
        
        # Cache the engine
        self.tenant_engines[tenant.id] = engine
        
        # Create tables if they don't exist
        with engine.connect() as conn:
            db.metadata.create_all(engine)
        
        return engine
    
    def cleanup_tenant_context(self, exception=None):
        """Cleanup tenant context after request"""
        if hasattr(g, 'current_tenant'):
            delattr(g, 'current_tenant')
        
        if hasattr(g, 'tenant_db_engine'):
            delattr(g, 'tenant_db_engine')
        
        self.current_tenant = None
    
    @contextmanager
    def tenant_context(self, tenant: Union[Tenant, str]):
        """Context manager for executing code in tenant context"""
        if isinstance(tenant, str):
            tenant = self.get_tenant_by_id(tenant)
        
        if not tenant:
            raise ValueError("Tenant not found")
        
        # Save current context
        old_tenant = getattr(g, 'current_tenant', None)
        
        try:
            # Set new tenant context
            g.current_tenant = tenant
            self.current_tenant = tenant
            self.setup_tenant_database_connection(tenant)
            yield tenant
        finally:
            # Restore old context
            if old_tenant:
                g.current_tenant = old_tenant
                self.current_tenant = old_tenant
            else:
                if hasattr(g, 'current_tenant'):
                    delattr(g, 'current_tenant')
                self.current_tenant = None
    
    def create_tenant(self, name: str, subdomain: str, admin_email: str, 
                     company_name: str = None, **kwargs) -> Tenant:
        """Create a new tenant"""
        # Validate subdomain
        if not self.is_valid_subdomain(subdomain):
            raise ValueError("Invalid subdomain format")
        
        if self.subdomain_exists(subdomain):
            raise ValueError("Subdomain already exists")
        
        # Create tenant
        tenant = Tenant(
            name=name,
            subdomain=subdomain.lower(),
            admin_email=admin_email.lower(),
            company_name=company_name,
            **kwargs
        )
        
        # Set default trial period
        tenant.trial_ends_at = datetime.utcnow() + timedelta(days=14)
        
        # Generate database schema name for schema-based isolation
        if self.isolation_strategy == TenantIsolationStrategy.SCHEMA_PER_TENANT:
            schema_name = f"tenant_{tenant.id.replace('-', '_')}"
            tenant.database_schema = schema_name
        
        # Save tenant
        db.session.add(tenant)
        db.session.commit()
        
        # Initialize tenant infrastructure
        self.initialize_tenant_infrastructure(tenant)
        
        # Create default subscription (free trial)
        self.create_default_subscription(tenant)
        
        # Log tenant creation
        self.log_tenant_event(tenant, 'tenant_created', 'Tenant created successfully')
        
        logger.info(f"Created tenant: {tenant.name} ({tenant.subdomain})")
        return tenant
    
    def initialize_tenant_infrastructure(self, tenant: Tenant):
        """Initialize tenant-specific infrastructure"""
        if self.isolation_strategy == TenantIsolationStrategy.DATABASE_PER_TENANT:
            # Create tenant database and tables
            engine = self.get_tenant_engine(tenant)
            with engine.connect() as conn:
                db.metadata.create_all(engine)
        
        elif self.isolation_strategy == TenantIsolationStrategy.SCHEMA_PER_TENANT:
            # Create tenant schema
            schema_name = tenant.database_schema
            db.session.execute(f"CREATE SCHEMA IF NOT EXISTS {schema_name}")
            db.session.execute(f"SET search_path TO {schema_name}")
            
            # Create tables in tenant schema
            db.metadata.create_all(db.engine)
            
            # Reset search path
            db.session.execute("SET search_path TO public")
            db.session.commit()
    
    def create_default_subscription(self, tenant: Tenant):
        """Create default subscription for new tenant"""
        # Get or create free trial plan
        free_plan = SubscriptionPlan.query.filter_by(tier=SubscriptionTier.FREE).first()
        
        if not free_plan:
            free_plan = SubscriptionPlan(
                name="Free Trial",
                tier=SubscriptionTier.FREE,
                billing_interval=BillingInterval.MONTHLY,
                price_cents=0,
                quotas={
                    UsageMetricType.DEVICES_MONITORED.value: 10,
                    UsageMetricType.API_CALLS.value: 1000,
                    UsageMetricType.DATA_RETENTION_DAYS.value: 7,
                    UsageMetricType.ALERTS_PER_MONTH.value: 50,
                    UsageMetricType.USERS_PER_TENANT.value: 2
                },
                features={
                    'basic_monitoring': True,
                    'email_alerts': True,
                    'api_access': True,
                    'mobile_app': False,
                    'integrations': False,
                    'advanced_analytics': False
                }
            )
            db.session.add(free_plan)
            db.session.commit()
        
        # Create subscription
        subscription = TenantSubscription(
            tenant_id=tenant.id,
            plan_id=free_plan.id,
            current_period_end=tenant.trial_ends_at
        )
        
        db.session.add(subscription)
        db.session.commit()
    
    def is_valid_subdomain(self, subdomain: str) -> bool:
        """Validate subdomain format"""
        if not subdomain or len(subdomain) < 2 or len(subdomain) > 63:
            return False
        
        # Check format: alphanumeric and hyphens, can't start/end with hyphen
        pattern = r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$'
        if not re.match(pattern, subdomain.lower()):
            return False
        
        # Reserved subdomains
        reserved = {'www', 'api', 'admin', 'mail', 'ftp', 'blog', 'help', 'support', 'docs'}
        if subdomain.lower() in reserved:
            return False
        
        return True
    
    def subdomain_exists(self, subdomain: str) -> bool:
        """Check if subdomain already exists"""
        return Tenant.query.filter_by(subdomain=subdomain.lower()).first() is not None
    
    def get_tenant_by_id(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant by ID"""
        return Tenant.query.filter_by(id=tenant_id).first()
    
    def get_tenant_by_subdomain(self, subdomain: str) -> Optional[Tenant]:
        """Get tenant by subdomain"""
        return Tenant.query.filter_by(subdomain=subdomain.lower()).first()
    
    def get_current_tenant(self) -> Optional[Tenant]:
        """Get current tenant from context"""
        return getattr(g, 'current_tenant', None)
    
    def require_tenant(self) -> Tenant:
        """Require tenant context, abort if not available"""
        tenant = self.get_current_tenant()
        if not tenant:
            abort(400, description="Tenant context required")
        return tenant
    
    def update_tenant(self, tenant: Tenant, **kwargs):
        """Update tenant information"""
        old_values = {}
        
        for key, value in kwargs.items():
            if hasattr(tenant, key):
                old_values[key] = getattr(tenant, key)
                setattr(tenant, key, value)
        
        db.session.commit()
        
        # Log the update
        self.log_tenant_event(
            tenant, 'tenant_updated', 
            f"Tenant updated: {', '.join(kwargs.keys())}",
            before_state=old_values,
            after_state=kwargs
        )
    
    def suspend_tenant(self, tenant: Tenant, reason: str):
        """Suspend tenant access"""
        tenant.status = TenantStatus.SUSPENDED
        tenant.suspended_at = datetime.utcnow()
        tenant.suspension_reason = reason
        
        db.session.commit()
        
        self.log_tenant_event(tenant, 'tenant_suspended', f"Tenant suspended: {reason}")
        logger.warning(f"Suspended tenant {tenant.name}: {reason}")
    
    def reactivate_tenant(self, tenant: Tenant):
        """Reactivate suspended tenant"""
        tenant.status = TenantStatus.ACTIVE
        tenant.suspended_at = None
        tenant.suspension_reason = None
        
        db.session.commit()
        
        self.log_tenant_event(tenant, 'tenant_reactivated', "Tenant reactivated")
        logger.info(f"Reactivated tenant {tenant.name}")
    
    def delete_tenant(self, tenant: Tenant, hard_delete: bool = False):
        """Delete tenant (soft delete by default)"""
        if hard_delete:
            # Hard delete: remove all data
            with self.tenant_context(tenant):
                # Delete tenant-specific data
                TenantAlert.query.filter_by(tenant_id=tenant.id).delete()
                TenantMonitoringData.query.filter_by(tenant_id=tenant.id).delete()
                TenantDevice.query.filter_by(tenant_id=tenant.id).delete()
                UsageRecord.query.filter_by(tenant_id=tenant.id).delete()
                TenantUser.query.filter_by(tenant_id=tenant.id).delete()
                TenantAuditLog.query.filter_by(tenant_id=tenant.id).delete()
                
                # Delete subscription data
                if tenant.subscription:
                    Invoice.query.filter_by(subscription_id=tenant.subscription.id).delete()
                    db.session.delete(tenant.subscription)
                
                # Delete tenant
                db.session.delete(tenant)
                db.session.commit()
            
            # Drop tenant database/schema if using isolation
            if self.isolation_strategy == TenantIsolationStrategy.DATABASE_PER_TENANT:
                # Drop tenant database (implementation depends on database type)
                pass
            elif self.isolation_strategy == TenantIsolationStrategy.SCHEMA_PER_TENANT:
                if tenant.database_schema:
                    db.session.execute(f"DROP SCHEMA IF EXISTS {tenant.database_schema} CASCADE")
                    db.session.commit()
            
            logger.info(f"Hard deleted tenant {tenant.name}")
        else:
            # Soft delete: just mark as cancelled
            tenant.status = TenantStatus.CANCELLED
            db.session.commit()
            
            self.log_tenant_event(tenant, 'tenant_deleted', "Tenant soft deleted")
            logger.info(f"Soft deleted tenant {tenant.name}")
    
    def log_tenant_event(self, tenant: Tenant, event_type: str, description: str,
                        user_id: str = None, user_email: str = None,
                        resource_type: str = None, resource_id: str = None,
                        before_state: Dict = None, after_state: Dict = None):
        """Log tenant audit event"""
        # Extract user info from request context if available
        if not user_id and hasattr(g, 'current_user'):
            user_id = getattr(g.current_user, 'id', None)
            user_email = getattr(g.current_user, 'email', None)
        
        # Extract request info
        ip_address = None
        user_agent = None
        if request:
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
        
        audit_log = TenantAuditLog(
            tenant_id=tenant.id,
            event_type=event_type,
            event_category='admin',  # Could be determined from event_type
            description=description,
            user_id=user_id,
            user_email=user_email,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type=resource_type,
            resource_id=resource_id,
            before_state=before_state,
            after_state=after_state
        )
        
        db.session.add(audit_log)
        db.session.commit()
    
    def track_usage(self, tenant: Tenant, metric_type: UsageMetricType, 
                   quantity: float, metadata: Dict = None):
        """Track usage for billing and quotas"""
        usage_record = UsageRecord(
            tenant_id=tenant.id,
            metric_type=metric_type,
            quantity=quantity,
            metadata=metadata or {}
        )
        
        db.session.add(usage_record)
        
        # Update current usage in subscription
        if tenant.subscription:
            current_usage = tenant.subscription.current_usage.copy()
            current_usage[metric_type.value] = current_usage.get(metric_type.value, 0) + quantity
            tenant.subscription.current_usage = current_usage
        
        db.session.commit()
    
    def check_quota(self, tenant: Tenant, metric_type: UsageMetricType, 
                   requested_quantity: float = 1) -> bool:
        """Check if tenant can use more of a resource"""
        if not tenant.subscription:
            return False
        
        quota = tenant.subscription.get_quota(metric_type)
        if quota is None:
            return True  # No limit
        
        current_usage = tenant.subscription.get_current_usage(metric_type)
        return (current_usage + requested_quantity) <= quota
    
    def enforce_quota(self, metric_type: UsageMetricType, requested_quantity: float = 1):
        """Decorator to enforce quotas"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                tenant = self.get_current_tenant()
                if tenant and not self.check_quota(tenant, metric_type, requested_quantity):
                    abort(429, description=f"Quota exceeded for {metric_type.value}")
                
                # Track usage after successful operation
                result = func(*args, **kwargs)
                
                if tenant:
                    self.track_usage(tenant, metric_type, requested_quantity)
                
                return result
            return wrapper
        return decorator

# Global tenant manager instance
tenant_manager = TenantManager()

# Convenience functions
def get_current_tenant() -> Optional[Tenant]:
    """Get current tenant from context"""
    return tenant_manager.get_current_tenant()

def require_tenant() -> Tenant:
    """Require tenant context"""
    return tenant_manager.require_tenant()

def tenant_context(tenant: Union[Tenant, str]):
    """Context manager for tenant operations"""
    return tenant_manager.tenant_context(tenant)

def track_usage(metric_type: UsageMetricType, quantity: float = 1, metadata: Dict = None):
    """Track usage for current tenant"""
    tenant = get_current_tenant()
    if tenant:
        tenant_manager.track_usage(tenant, metric_type, quantity, metadata)

def enforce_quota(metric_type: UsageMetricType, quantity: float = 1):
    """Decorator to enforce quotas"""
    return tenant_manager.enforce_quota(metric_type, quantity)