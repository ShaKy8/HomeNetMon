# HomeNetMon Subscription and Billing System
from flask import Flask, current_app
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from decimal import Decimal
import stripe
import logging
import json
import uuid
from enum import Enum
from dataclasses import dataclass, asdict
from tenant_models import *
from tenant_manager import get_current_tenant, tenant_context
from cloud_config import get_config

logger = logging.getLogger(__name__)

class PaymentProvider(Enum):
    STRIPE = "stripe"
    PAYPAL = "paypal"
    SQUARE = "square"
    MANUAL = "manual"

class InvoiceStatus(Enum):
    DRAFT = "draft"
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"

class PaymentStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"

@dataclass
class BillingEvent:
    """Billing event for webhooks and notifications"""
    event_type: str
    tenant_id: str
    subscription_id: str
    data: Dict[str, Any]
    timestamp: datetime
    provider: PaymentProvider

class BillingManager:
    """Comprehensive billing and subscription management"""
    
    def __init__(self, app: Flask = None):
        self.app = app
        self.stripe_client = None
        self.webhook_handlers = {}
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize billing manager with Flask app"""
        self.app = app
        
        # Initialize payment providers
        self.init_stripe()
        
        # Set up webhook handlers
        self.setup_webhook_handlers()
        
        logger.info("BillingManager initialized")
    
    def init_stripe(self):
        """Initialize Stripe client"""
        stripe_secret_key = get_config('STRIPE_SECRET_KEY')
        if stripe_secret_key:
            stripe.api_key = stripe_secret_key
            self.stripe_client = stripe
            logger.info("Stripe client initialized")
        else:
            logger.warning("Stripe not configured - no STRIPE_SECRET_KEY found")
    
    def setup_webhook_handlers(self):
        """Setup webhook handlers for different events"""
        self.webhook_handlers.update({
            'invoice.payment_succeeded': self.handle_payment_succeeded,
            'invoice.payment_failed': self.handle_payment_failed,
            'customer.subscription.updated': self.handle_subscription_updated,
            'customer.subscription.deleted': self.handle_subscription_cancelled,
            'customer.subscription.trial_will_end': self.handle_trial_ending,
            'invoice.created': self.handle_invoice_created,
            'payment_intent.succeeded': self.handle_payment_intent_succeeded,
            'payment_intent.payment_failed': self.handle_payment_intent_failed,
        })
    
    # ========================================================================
    # Subscription Plans Management
    # ========================================================================
    
    def create_subscription_plan(self, name: str, tier: SubscriptionTier, 
                               billing_interval: BillingInterval, price_cents: int,
                               quotas: Dict[str, int], features: Dict[str, bool],
                               description: str = None) -> SubscriptionPlan:
        """Create a new subscription plan"""
        plan = SubscriptionPlan(
            name=name,
            tier=tier,
            billing_interval=billing_interval,
            price_cents=price_cents,
            quotas=quotas,
            features=features,
            description=description
        )
        
        db.session.add(plan)
        db.session.commit()
        
        # Create corresponding plan in payment provider
        if self.stripe_client:
            self.create_stripe_plan(plan)
        
        logger.info(f"Created subscription plan: {plan.name}")
        return plan
    
    def create_stripe_plan(self, plan: SubscriptionPlan):
        """Create plan in Stripe"""
        try:
            # Create product
            stripe_product = self.stripe_client.Product.create(
                name=plan.name,
                description=plan.description,
                metadata={
                    'homenetmon_plan_id': plan.id,
                    'tier': plan.tier.value
                }
            )
            
            # Create price
            interval = 'month' if plan.billing_interval == BillingInterval.MONTHLY else 'year'
            
            stripe_price = self.stripe_client.Price.create(
                product=stripe_product.id,
                unit_amount=plan.price_cents,
                currency=plan.currency.lower(),
                recurring={'interval': interval} if plan.billing_interval != BillingInterval.ONE_TIME else None,
                metadata={
                    'homenetmon_plan_id': plan.id
                }
            )
            
            # Update plan with Stripe IDs
            plan.external_product_id = stripe_product.id
            plan.external_price_id = stripe_price.id
            db.session.commit()
            
            logger.info(f"Created Stripe plan for {plan.name}")
            
        except Exception as e:
            logger.error(f"Failed to create Stripe plan: {e}")
    
    def get_default_plans(self) -> List[SubscriptionPlan]:
        """Get default subscription plans"""
        plans = []
        
        # Free plan
        free_plan = SubscriptionPlan(
            name="Free",
            tier=SubscriptionTier.FREE,
            billing_interval=BillingInterval.MONTHLY,
            price_cents=0,
            quotas={
                UsageMetricType.DEVICES_MONITORED.value: 5,
                UsageMetricType.API_CALLS.value: 500,
                UsageMetricType.DATA_RETENTION_DAYS.value: 7,
                UsageMetricType.ALERTS_PER_MONTH.value: 25,
                UsageMetricType.USERS_PER_TENANT.value: 1,
                UsageMetricType.STORAGE_GB.value: 1
            },
            features={
                'basic_monitoring': True,
                'email_alerts': True,
                'api_access': True,
                'mobile_app': False,
                'integrations': False,
                'advanced_analytics': False,
                'custom_domains': False,
                'priority_support': False
            },
            description="Perfect for getting started with basic network monitoring"
        )
        plans.append(free_plan)
        
        # Starter plan
        starter_plan = SubscriptionPlan(
            name="Starter",
            tier=SubscriptionTier.STARTER,
            billing_interval=BillingInterval.MONTHLY,
            price_cents=1999,  # $19.99
            quotas={
                UsageMetricType.DEVICES_MONITORED.value: 25,
                UsageMetricType.API_CALLS.value: 5000,
                UsageMetricType.DATA_RETENTION_DAYS.value: 30,
                UsageMetricType.ALERTS_PER_MONTH.value: 500,
                UsageMetricType.USERS_PER_TENANT.value: 3,
                UsageMetricType.STORAGE_GB.value: 5
            },
            features={
                'basic_monitoring': True,
                'email_alerts': True,
                'api_access': True,
                'mobile_app': True,
                'integrations': True,
                'advanced_analytics': False,
                'custom_domains': False,
                'priority_support': False
            },
            description="Great for small businesses and home offices"
        )
        plans.append(starter_plan)
        
        # Professional plan
        pro_plan = SubscriptionPlan(
            name="Professional",
            tier=SubscriptionTier.PROFESSIONAL,
            billing_interval=BillingInterval.MONTHLY,
            price_cents=4999,  # $49.99
            quotas={
                UsageMetricType.DEVICES_MONITORED.value: 100,
                UsageMetricType.API_CALLS.value: 25000,
                UsageMetricType.DATA_RETENTION_DAYS.value: 90,
                UsageMetricType.ALERTS_PER_MONTH.value: 2000,
                UsageMetricType.USERS_PER_TENANT.value: 10,
                UsageMetricType.STORAGE_GB.value: 25
            },
            features={
                'basic_monitoring': True,
                'email_alerts': True,
                'api_access': True,
                'mobile_app': True,
                'integrations': True,
                'advanced_analytics': True,
                'custom_domains': True,
                'priority_support': True,
                'webhooks': True,
                'custom_reports': True
            },
            description="Perfect for growing businesses with advanced needs"
        )
        plans.append(pro_plan)
        
        # Enterprise plan
        enterprise_plan = SubscriptionPlan(
            name="Enterprise",
            tier=SubscriptionTier.ENTERPRISE,
            billing_interval=BillingInterval.MONTHLY,
            price_cents=19999,  # $199.99
            quotas={
                UsageMetricType.DEVICES_MONITORED.value: 1000,
                UsageMetricType.API_CALLS.value: 250000,
                UsageMetricType.DATA_RETENTION_DAYS.value: 365,
                UsageMetricType.ALERTS_PER_MONTH.value: 10000,
                UsageMetricType.USERS_PER_TENANT.value: 50,
                UsageMetricType.STORAGE_GB.value: 100
            },
            features={
                'basic_monitoring': True,
                'email_alerts': True,
                'api_access': True,
                'mobile_app': True,
                'integrations': True,
                'advanced_analytics': True,
                'custom_domains': True,
                'priority_support': True,
                'webhooks': True,
                'custom_reports': True,
                'sso': True,
                'audit_logs': True,
                'dedicated_support': True,
                'custom_integrations': True
            },
            description="For large organizations with comprehensive monitoring needs"
        )
        plans.append(enterprise_plan)
        
        return plans
    
    def initialize_default_plans(self):
        """Initialize default subscription plans if they don't exist"""
        existing_plans = SubscriptionPlan.query.count()
        if existing_plans == 0:
            plans = self.get_default_plans()
            for plan in plans:
                db.session.add(plan)
            db.session.commit()
            logger.info(f"Initialized {len(plans)} default subscription plans")
    
    # ========================================================================
    # Subscription Management
    # ========================================================================
    
    def create_subscription(self, tenant: Tenant, plan: SubscriptionPlan,
                          payment_method_id: str = None, trial_days: int = None) -> TenantSubscription:
        """Create a new subscription for tenant"""
        # Calculate billing dates
        now = datetime.utcnow()
        if trial_days:
            trial_end = now + timedelta(days=trial_days)
            current_period_end = trial_end
        else:
            if plan.billing_interval == BillingInterval.MONTHLY:
                current_period_end = now + timedelta(days=30)
            elif plan.billing_interval == BillingInterval.YEARLY:
                current_period_end = now + timedelta(days=365)
            else:
                current_period_end = now
        
        # Create subscription
        subscription = TenantSubscription(
            tenant_id=tenant.id,
            plan_id=plan.id,
            current_period_start=now,
            current_period_end=current_period_end,
            payment_method_id=payment_method_id
        )
        
        db.session.add(subscription)
        db.session.commit()
        
        # Create in payment provider
        if self.stripe_client and payment_method_id:
            self.create_stripe_subscription(subscription, trial_days)
        
        # Update tenant status
        if trial_days:
            tenant.status = TenantStatus.TRIAL
            tenant.trial_ends_at = trial_end
        else:
            tenant.status = TenantStatus.ACTIVE
        
        db.session.commit()
        
        logger.info(f"Created subscription for tenant {tenant.name}: {plan.name}")
        return subscription
    
    def create_stripe_subscription(self, subscription: TenantSubscription, trial_days: int = None):
        """Create subscription in Stripe"""
        try:
            tenant = subscription.tenant
            plan = subscription.plan
            
            # Create or get Stripe customer
            stripe_customer = self.get_or_create_stripe_customer(tenant)
            
            # Create subscription in Stripe
            stripe_subscription_params = {
                'customer': stripe_customer.id,
                'items': [{'price': plan.external_price_id}],
                'metadata': {
                    'homenetmon_tenant_id': tenant.id,
                    'homenetmon_subscription_id': subscription.id
                }
            }
            
            if trial_days:
                stripe_subscription_params['trial_period_days'] = trial_days
            
            if subscription.payment_method_id:
                stripe_subscription_params['default_payment_method'] = subscription.payment_method_id
            
            stripe_subscription = self.stripe_client.Subscription.create(**stripe_subscription_params)
            
            # Update local subscription with Stripe ID
            subscription.external_subscription_id = stripe_subscription.id
            db.session.commit()
            
            logger.info(f"Created Stripe subscription {stripe_subscription.id}")
            
        except Exception as e:
            logger.error(f"Failed to create Stripe subscription: {e}")
            raise
    
    def get_or_create_stripe_customer(self, tenant: Tenant):
        """Get or create Stripe customer for tenant"""
        # Check if customer already exists
        if hasattr(tenant, 'stripe_customer_id') and tenant.stripe_customer_id:
            try:
                return self.stripe_client.Customer.retrieve(tenant.stripe_customer_id)
            except:
                pass
        
        # Create new customer
        customer_data = {
            'email': tenant.admin_email,
            'name': tenant.company_name or tenant.name,
            'metadata': {
                'homenetmon_tenant_id': tenant.id
            }
        }
        
        # Add address if available
        if tenant.address_line1:
            customer_data['address'] = {
                'line1': tenant.address_line1,
                'line2': tenant.address_line2,
                'city': tenant.city,
                'state': tenant.state_province,
                'postal_code': tenant.postal_code,
                'country': tenant.country
            }
        
        stripe_customer = self.stripe_client.Customer.create(**customer_data)
        
        # Store customer ID
        tenant.stripe_customer_id = stripe_customer.id
        db.session.commit()
        
        return stripe_customer
    
    def upgrade_subscription(self, subscription: TenantSubscription, new_plan: SubscriptionPlan,
                           prorate: bool = True) -> TenantSubscription:
        """Upgrade/downgrade subscription to new plan"""
        old_plan = subscription.plan
        
        # Calculate prorated amount
        prorated_amount = 0
        if prorate:
            prorated_amount = self.calculate_proration(subscription, new_plan)
        
        # Update subscription
        subscription.plan_id = new_plan.id
        
        # Reset usage counters for new billing period
        subscription.current_usage = {}
        
        db.session.commit()
        
        # Update in payment provider
        if self.stripe_client and subscription.external_subscription_id:
            self.update_stripe_subscription(subscription, new_plan)
        
        # Create invoice for proration if needed
        if prorated_amount != 0:
            self.create_proration_invoice(subscription, prorated_amount)
        
        logger.info(f"Updated subscription from {old_plan.name} to {new_plan.name}")
        return subscription
    
    def calculate_proration(self, subscription: TenantSubscription, new_plan: SubscriptionPlan) -> int:
        """Calculate prorated amount for plan change"""
        old_plan = subscription.plan
        now = datetime.utcnow()
        
        # Calculate remaining time in current period
        total_period = (subscription.current_period_end - subscription.current_period_start).total_seconds()
        remaining_period = (subscription.current_period_end - now).total_seconds()
        
        if total_period <= 0:
            return 0
        
        # Calculate unused portion of old plan
        unused_old = int((old_plan.price_cents * remaining_period) / total_period)
        
        # Calculate cost of new plan for remaining period
        new_cost = int((new_plan.price_cents * remaining_period) / total_period)
        
        return new_cost - unused_old
    
    def cancel_subscription(self, subscription: TenantSubscription, 
                          immediate: bool = False, reason: str = None):
        """Cancel subscription"""
        if immediate:
            subscription.cancelled_at = datetime.utcnow()
            subscription.current_period_end = datetime.utcnow()
            
            # Update tenant status
            subscription.tenant.status = TenantStatus.CANCELLED
        else:
            subscription.cancel_at_period_end = True
        
        db.session.commit()
        
        # Cancel in payment provider
        if self.stripe_client and subscription.external_subscription_id:
            self.cancel_stripe_subscription(subscription, immediate)
        
        logger.info(f"Cancelled subscription for {subscription.tenant.name}")
    
    # ========================================================================
    # Invoice and Payment Management
    # ========================================================================
    
    def create_invoice(self, subscription: TenantSubscription, 
                      amount_cents: int, description: str,
                      due_date: datetime = None, auto_finalize: bool = True) -> Invoice:
        """Create invoice for subscription"""
        if not due_date:
            due_date = datetime.utcnow() + timedelta(days=30)
        
        invoice = Invoice(
            subscription_id=subscription.id,
            invoice_number=self.generate_invoice_number(),
            amount_cents=amount_cents,
            currency=subscription.plan.currency,
            period_start=subscription.current_period_start,
            period_end=subscription.current_period_end,
            due_date=due_date,
            status=InvoiceStatus.DRAFT.value,
            line_items=[{
                'description': description,
                'amount': amount_cents,
                'quantity': 1
            }]
        )
        
        db.session.add(invoice)
        db.session.commit()
        
        # Create in payment provider
        if self.stripe_client:
            self.create_stripe_invoice(invoice)
        
        if auto_finalize:
            self.finalize_invoice(invoice)
        
        return invoice
    
    def generate_invoice_number(self) -> str:
        """Generate unique invoice number"""
        timestamp = datetime.utcnow().strftime('%Y%m%d')
        random_suffix = str(uuid.uuid4())[:8].upper()
        return f"INV-{timestamp}-{random_suffix}"
    
    def finalize_invoice(self, invoice: Invoice):
        """Finalize and send invoice"""
        invoice.status = InvoiceStatus.PENDING.value
        db.session.commit()
        
        # Finalize in payment provider
        if self.stripe_client and invoice.external_invoice_id:
            try:
                self.stripe_client.Invoice.finalize_invoice(invoice.external_invoice_id)
                logger.info(f"Finalized invoice {invoice.invoice_number}")
            except Exception as e:
                logger.error(f"Failed to finalize Stripe invoice: {e}")
    
    def process_payment(self, invoice: Invoice, payment_method_id: str = None) -> Dict[str, Any]:
        """Process payment for invoice"""
        try:
            if self.stripe_client:
                return self.process_stripe_payment(invoice, payment_method_id)
            else:
                return {'success': False, 'error': 'No payment provider configured'}
        except Exception as e:
            logger.error(f"Payment processing failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def process_stripe_payment(self, invoice: Invoice, payment_method_id: str = None) -> Dict[str, Any]:
        """Process payment through Stripe"""
        try:
            if invoice.external_invoice_id:
                # Pay existing Stripe invoice
                result = self.stripe_client.Invoice.pay(
                    invoice.external_invoice_id,
                    payment_method=payment_method_id
                )
            else:
                # Create payment intent
                tenant = invoice.subscription.tenant
                stripe_customer = self.get_or_create_stripe_customer(tenant)
                
                payment_intent = self.stripe_client.PaymentIntent.create(
                    amount=invoice.amount_cents,
                    currency=invoice.currency.lower(),
                    customer=stripe_customer.id,
                    payment_method=payment_method_id,
                    confirm=True,
                    metadata={
                        'homenetmon_invoice_id': invoice.id,
                        'homenetmon_tenant_id': tenant.id
                    }
                )
                
                result = payment_intent
            
            if result.status in ['succeeded', 'paid']:
                self.mark_invoice_paid(invoice)
                return {'success': True, 'payment_id': result.id}
            else:
                return {'success': False, 'status': result.status}
                
        except Exception as e:
            logger.error(f"Stripe payment failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def mark_invoice_paid(self, invoice: Invoice):
        """Mark invoice as paid"""
        invoice.status = InvoiceStatus.PAID.value
        invoice.paid_at = datetime.utcnow()
        
        # Update subscription
        subscription = invoice.subscription
        subscription.last_payment_at = datetime.utcnow()
        
        # Calculate next billing date
        if subscription.plan.billing_interval == BillingInterval.MONTHLY:
            subscription.next_billing_date = datetime.utcnow() + timedelta(days=30)
        elif subscription.plan.billing_interval == BillingInterval.YEARLY:
            subscription.next_billing_date = datetime.utcnow() + timedelta(days=365)
        
        # Ensure tenant is active
        subscription.tenant.status = TenantStatus.ACTIVE
        
        db.session.commit()
        
        logger.info(f"Marked invoice {invoice.invoice_number} as paid")
    
    # ========================================================================
    # Usage Tracking and Billing
    # ========================================================================
    
    def calculate_usage_charges(self, subscription: TenantSubscription) -> int:
        """Calculate overage charges for usage beyond quotas"""
        total_charges = 0
        usage_pricing = self.get_usage_pricing(subscription.plan)
        
        for metric_type, price_per_unit in usage_pricing.items():
            quota = subscription.get_quota(UsageMetricType(metric_type))
            usage = subscription.get_current_usage(UsageMetricType(metric_type))
            
            if quota and usage > quota:
                overage = usage - quota
                charge = int(overage * price_per_unit * 100)  # Convert to cents
                total_charges += charge
                
                logger.info(f"Overage charge for {metric_type}: {overage} units @ ${price_per_unit} = ${charge/100}")
        
        return total_charges
    
    def get_usage_pricing(self, plan: SubscriptionPlan) -> Dict[str, float]:
        """Get overage pricing for plan"""
        # Base pricing for overages (dollars per unit)
        base_pricing = {
            UsageMetricType.DEVICES_MONITORED.value: 2.0,
            UsageMetricType.API_CALLS.value: 0.001,
            UsageMetricType.STORAGE_GB.value: 0.5,
            UsageMetricType.BANDWIDTH_GB.value: 0.1
        }
        
        # Adjust pricing based on plan tier
        multiplier = {
            SubscriptionTier.FREE: 1.5,
            SubscriptionTier.STARTER: 1.2,
            SubscriptionTier.PROFESSIONAL: 1.0,
            SubscriptionTier.ENTERPRISE: 0.8
        }.get(plan.tier, 1.0)
        
        return {k: v * multiplier for k, v in base_pricing.items()}
    
    def generate_monthly_invoices(self):
        """Generate monthly invoices for all active subscriptions"""
        # Get subscriptions that need billing
        due_subscriptions = TenantSubscription.query.filter(
            TenantSubscription.next_billing_date <= datetime.utcnow(),
            TenantSubscription.cancelled_at.is_(None)
        ).all()
        
        invoices_created = 0
        
        for subscription in due_subscriptions:
            try:
                # Calculate base amount
                base_amount = subscription.plan.price_cents
                
                # Calculate usage overages
                overage_amount = self.calculate_usage_charges(subscription)
                
                total_amount = base_amount + overage_amount
                
                if total_amount > 0:
                    # Create invoice
                    description = f"{subscription.plan.name} subscription"
                    if overage_amount > 0:
                        description += f" + usage overages (${overage_amount/100:.2f})"
                    
                    invoice = self.create_invoice(
                        subscription, 
                        total_amount, 
                        description
                    )
                    
                    invoices_created += 1
                    logger.info(f"Created invoice {invoice.invoice_number} for ${total_amount/100:.2f}")
                
                # Update billing period
                if subscription.plan.billing_interval == BillingInterval.MONTHLY:
                    subscription.current_period_start = subscription.current_period_end
                    subscription.current_period_end = subscription.current_period_end + timedelta(days=30)
                    subscription.next_billing_date = subscription.current_period_end
                
                # Reset usage counters
                subscription.current_usage = {}
                subscription.overage_charges = 0
                
                db.session.commit()
                
            except Exception as e:
                logger.error(f"Failed to create invoice for subscription {subscription.id}: {e}")
                db.session.rollback()
        
        logger.info(f"Generated {invoices_created} monthly invoices")
        return invoices_created
    
    # ========================================================================
    # Webhook Handlers
    # ========================================================================
    
    def handle_stripe_webhook(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Stripe webhook events"""
        event_type = event_data.get('type')
        
        if event_type in self.webhook_handlers:
            try:
                handler = self.webhook_handlers[event_type]
                return handler(event_data)
            except Exception as e:
                logger.error(f"Webhook handler failed for {event_type}: {e}")
                return {'success': False, 'error': str(e)}
        else:
            logger.warning(f"Unhandled webhook event: {event_type}")
            return {'success': True, 'message': 'Event ignored'}
    
    def handle_payment_succeeded(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle successful payment"""
        invoice_data = event_data['data']['object']
        
        # Find our invoice
        external_invoice_id = invoice_data['id']
        invoice = Invoice.query.filter_by(external_invoice_id=external_invoice_id).first()
        
        if invoice:
            self.mark_invoice_paid(invoice)
            return {'success': True}
        
        return {'success': False, 'error': 'Invoice not found'}
    
    def handle_payment_failed(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle failed payment"""
        invoice_data = event_data['data']['object']
        
        # Find our invoice
        external_invoice_id = invoice_data['id']
        invoice = Invoice.query.filter_by(external_invoice_id=external_invoice_id).first()
        
        if invoice:
            invoice.status = InvoiceStatus.FAILED.value
            db.session.commit()
            
            # Handle failed payment (suspend tenant, send notifications, etc.)
            self.handle_failed_payment(invoice)
            
            return {'success': True}
        
        return {'success': False, 'error': 'Invoice not found'}
    
    def handle_failed_payment(self, invoice: Invoice):
        """Handle failed payment consequences"""
        tenant = invoice.subscription.tenant
        
        # Grace period before suspension
        grace_period_days = 3
        suspension_date = datetime.utcnow() + timedelta(days=grace_period_days)
        
        # Send notification email
        # ... email sending logic ...
        
        # Schedule suspension if not resolved
        # ... scheduling logic ...
        
        logger.warning(f"Payment failed for tenant {tenant.name}, grace period until {suspension_date}")
    
    def handle_subscription_updated(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription updates from Stripe"""
        # Implementation for subscription updates
        return {'success': True}
    
    def handle_subscription_cancelled(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription cancellation from Stripe"""
        # Implementation for subscription cancellation
        return {'success': True}
    
    def handle_trial_ending(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle trial ending notification"""
        # Implementation for trial ending
        return {'success': True}
    
    def handle_invoice_created(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle invoice creation in Stripe"""
        # Implementation for invoice creation
        return {'success': True}
    
    def handle_payment_intent_succeeded(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle successful payment intent"""
        # Implementation for payment intent success
        return {'success': True}
    
    def handle_payment_intent_failed(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle failed payment intent"""
        # Implementation for payment intent failure
        return {'success': True}

# Global billing manager instance
billing_manager = BillingManager()

# Convenience functions
def create_subscription(tenant: Tenant, plan: SubscriptionPlan, **kwargs) -> TenantSubscription:
    """Create subscription for tenant"""
    return billing_manager.create_subscription(tenant, plan, **kwargs)

def upgrade_subscription(subscription: TenantSubscription, new_plan: SubscriptionPlan, **kwargs) -> TenantSubscription:
    """Upgrade subscription to new plan"""
    return billing_manager.upgrade_subscription(subscription, new_plan, **kwargs)

def process_payment(invoice: Invoice, payment_method_id: str = None) -> Dict[str, Any]:
    """Process payment for invoice"""
    return billing_manager.process_payment(invoice, payment_method_id)

def handle_stripe_webhook(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """Handle Stripe webhook"""
    return billing_manager.handle_stripe_webhook(event_data)