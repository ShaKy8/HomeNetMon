"""
Escalation Execution Service

Handles the execution of escalation rules, background processing of escalation actions,
and integration with various notification channels and external systems.
"""

import threading
import time
import logging
from datetime import datetime, timedelta
from models import db, EscalationRule, EscalationExecution, EscalationActionLog, NotificationHistory, Alert
from sqlalchemy import and_, or_
import json
import requests
import subprocess
from collections import defaultdict

logger = logging.getLogger(__name__)

class EscalationExecutionService:
    """Service for executing escalation rules and managing escalation workflows"""
    
    def __init__(self, app=None):
        self.app = app
        self.is_running = False
        self.execution_thread = None
        self.stop_event = threading.Event()
        
        # Action executors
        self.action_executors = {
            'email': self._execute_email_action,
            'webhook': self._execute_webhook_action,
            'push_notification': self._execute_push_notification_action,
            'sms': self._execute_sms_action,
            'create_ticket': self._execute_create_ticket_action,
            'run_script': self._execute_run_script_action
        }
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize service with Flask app"""
        self.app = app
        
        # Configuration
        self.execution_interval = app.config.get('ESCALATION_EXECUTION_INTERVAL', 30)  # seconds
        self.max_concurrent_executions = app.config.get('ESCALATION_MAX_CONCURRENT_EXECUTIONS', 5)
        self.action_timeout = app.config.get('ESCALATION_ACTION_TIMEOUT', 300)  # seconds
        self.enable_background_processing = app.config.get('ESCALATION_BACKGROUND_PROCESSING', True)
        
        logger.info("Escalation execution service initialized")
    
    def start_monitoring(self):
        """Start the background escalation monitoring and execution"""
        if self.is_running:
            logger.warning("Escalation service already running")
            return
        
        if not self.enable_background_processing:
            logger.info("Background escalation processing disabled")
            return
        
        self.is_running = True
        self.stop_event.clear()
        
        self.execution_thread = threading.Thread(
            target=self._execution_loop,
            daemon=True,
            name='EscalationExecutionService'
        )
        self.execution_thread.start()
        logger.info("Started escalation execution service")
    
    def stop_monitoring(self):
        """Stop the background monitoring"""
        if not self.is_running:
            return
        
        self.is_running = False
        self.stop_event.set()
        
        if self.execution_thread and self.execution_thread.is_alive():
            self.execution_thread.join(timeout=10)
        
        logger.info("Stopped escalation execution service")
    
    def trigger_escalation(self, trigger_type, trigger_context):
        """
        Trigger escalation rules based on context
        
        Args:
            trigger_type: Type of trigger (notification_failure, alert_unresolved, etc.)
            trigger_context: Dictionary containing trigger context and metadata
            
        Returns:
            list: List of created escalation executions
        """
        try:
            # Find matching rules
            matching_rules = EscalationRule.query.filter(
                EscalationRule.enabled == True,
                EscalationRule.trigger_type == trigger_type
            ).order_by(EscalationRule.priority.asc()).all()
            
            created_executions = []
            
            for rule in matching_rules:
                try:
                    if rule.matches_conditions(trigger_context):
                        execution = self._create_escalation_execution(rule, trigger_context)
                        if execution:
                            created_executions.append(execution)
                            logger.info(f"Created escalation execution {execution.id} for rule {rule.name}")
                        
                except Exception as e:
                    logger.error(f"Error evaluating rule {rule.name}: {e}")
                    continue
            
            return created_executions
            
        except Exception as e:
            logger.error(f"Error triggering escalation for {trigger_type}: {e}")
            return []
    
    def _create_escalation_execution(self, rule, trigger_context):
        """Create a new escalation execution"""
        try:
            # Calculate when to start execution
            scheduled_for = datetime.utcnow() + timedelta(minutes=rule.delay_minutes)
            
            execution = EscalationExecution(
                escalation_rule_id=rule.id,
                triggered_by_type=trigger_context.get('triggered_by_type', 'unknown'),
                triggered_by_id=trigger_context.get('triggered_by_id', 0),
                trigger_context=trigger_context,
                scheduled_for=scheduled_for
            )
            
            db.session.add(execution)
            db.session.commit()
            
            return execution
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating escalation execution: {e}")
            return None
    
    def _execution_loop(self):
        """Main execution loop for processing escalations"""
        logger.info("Starting escalation execution loop")
        
        while self.is_running and not self.stop_event.is_set():
            try:
                with self.app.app_context():
                    self._process_pending_escalations()
                    self._cleanup_old_executions()
                
                # Wait for next iteration
                self.stop_event.wait(self.execution_interval)
                
            except Exception as e:
                logger.error(f"Error in escalation execution loop: {e}")
                self.stop_event.wait(60)  # Wait longer on error
        
        logger.info("Escalation execution loop stopped")
    
    def _process_pending_escalations(self):
        """Process all pending escalation executions"""
        try:
            # Get pending executions that are ready to run
            pending_executions = EscalationExecution.query.filter(
                EscalationExecution.status == 'pending',
                EscalationExecution.scheduled_for <= datetime.utcnow()
            ).order_by(EscalationExecution.scheduled_for.asc()).all()
            
            # Process up to max concurrent executions
            for execution in pending_executions[:self.max_concurrent_executions]:
                try:
                    self._execute_escalation(execution)
                except Exception as e:
                    logger.error(f"Error executing escalation {execution.id}: {e}")
                    self._mark_execution_failed(execution, str(e))
            
        except Exception as e:
            logger.error(f"Error processing pending escalations: {e}")
    
    def _execute_escalation(self, execution):
        """Execute a single escalation"""
        try:
            execution.status = 'in_progress'
            execution.started_at = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"Executing escalation {execution.id} for rule {execution.rule.name}")
            
            # Get actions for current escalation level
            current_level = execution.current_escalation_level
            rule_actions = execution.rule.escalation_actions
            
            if current_level >= len(rule_actions):
                # No more actions to execute
                execution.status = 'completed'
                execution.completed_at = datetime.utcnow()
                db.session.commit()
                return
            
            # Execute actions for current level
            level_actions = rule_actions[current_level] if isinstance(rule_actions[0], list) else rule_actions
            
            all_actions_successful = True
            
            for action in level_actions:
                success = self._execute_action(execution, action, current_level)
                if not success:
                    all_actions_successful = False
            
            # Update execution state
            execution.current_escalation_level += 1
            execution.total_actions_executed += len(level_actions)
            
            # Check if we should schedule next escalation
            if (execution.current_escalation_level < execution.rule.max_escalations and
                execution.current_escalation_level < len(rule_actions)):
                
                # Schedule next escalation level
                next_scheduled = datetime.utcnow() + timedelta(minutes=execution.rule.escalation_interval_minutes)
                execution.scheduled_for = next_scheduled
                execution.status = 'pending'
                
            else:
                # All escalations completed
                execution.status = 'completed'
                execution.completed_at = datetime.utcnow()
            
            db.session.commit()
            
            if all_actions_successful:
                logger.info(f"Successfully executed escalation level {current_level} for execution {execution.id}")
            else:
                logger.warning(f"Some actions failed in escalation level {current_level} for execution {execution.id}")
            
        except Exception as e:
            logger.error(f"Error executing escalation {execution.id}: {e}")
            self._mark_execution_failed(execution, str(e))
    
    def _execute_action(self, execution, action, escalation_level):
        """Execute a single escalation action"""
        start_time = datetime.utcnow()
        action_type = action.get('action_type')
        action_config = action.get('config', {})
        
        try:
            # Create action log entry
            action_log = EscalationActionLog(
                escalation_execution_id=execution.id,
                action_type=action_type,
                action_config=action_config,
                escalation_level=escalation_level
            )
            
            # Execute the action
            if action_type in self.action_executors:
                result = self.action_executors[action_type](execution, action_config)
                
                action_log.status = 'success' if result.get('success', False) else 'failed'
                action_log.result = result
                action_log.error_message = result.get('error') if not result.get('success', False) else None
                
            else:
                # Unknown action type
                action_log.status = 'failed'
                action_log.error_message = f"Unknown action type: {action_type}"
                result = {'success': False, 'error': action_log.error_message}
            
            # Calculate duration and save log
            duration = (datetime.utcnow() - start_time).total_seconds() * 1000
            action_log.duration_ms = int(duration)
            
            db.session.add(action_log)
            db.session.commit()
            
            return result.get('success', False)
            
        except Exception as e:
            # Save failed action log
            try:
                action_log.status = 'failed'
                action_log.error_message = str(e)
                action_log.duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
                db.session.add(action_log)
                db.session.commit()
            except:
                pass
            
            logger.error(f"Error executing action {action_type}: {e}")
            return False
    
    def _execute_email_action(self, execution, config):
        """Execute email notification action"""
        try:
            # Template the email content with context
            subject = self._template_string(config.get('subject', 'Escalation Alert'), execution.trigger_context)
            body = self._template_string(config.get('body', 'Escalation triggered'), execution.trigger_context)
            
            # Import email service (assuming it exists)
            try:
                from services.email_service import send_email
                
                result = send_email(
                    to=config.get('to', []),
                    subject=subject,
                    body=body,
                    priority=config.get('priority', 'normal')
                )
                
                return {'success': True, 'result': result}
                
            except ImportError:
                logger.warning("Email service not available")
                return {'success': False, 'error': 'Email service not configured'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _execute_webhook_action(self, execution, config):
        """Execute webhook action"""
        try:
            url = config.get('url')
            method = config.get('method', 'POST').upper()
            headers = config.get('headers', {})
            timeout = config.get('timeout', self.action_timeout)
            
            # Prepare payload
            payload = {
                'escalation_execution_id': execution.id,
                'rule_name': execution.rule.name,
                'trigger_type': execution.triggered_by_type,
                'trigger_context': execution.trigger_context,
                'escalation_level': execution.current_escalation_level,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            # Set default headers
            headers.setdefault('Content-Type', 'application/json')
            headers.setdefault('User-Agent', 'HomeNetMon-Escalation-Service/1.0')
            
            # Make request
            response = requests.request(
                method=method,
                url=url,
                json=payload,
                headers=headers,
                timeout=timeout
            )
            
            response.raise_for_status()
            
            return {
                'success': True,
                'status_code': response.status_code,
                'response_body': response.text[:1000]  # Limit response size
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _execute_push_notification_action(self, execution, config):
        """Execute push notification action"""
        try:
            # Template the notification content
            title = self._template_string(config.get('title', 'Escalation Alert'), execution.trigger_context)
            message = self._template_string(config.get('message', 'Escalation triggered'), execution.trigger_context)
            
            # Import push notification service
            try:
                from services.push_notifications import PushNotificationService
                push_service = PushNotificationService()
                
                success = push_service.send_notification(
                    title=title,
                    message=message,
                    priority=config.get('priority', 'default'),
                    tags=config.get('tags', '⚠️')
                )
                
                return {'success': success}
                
            except ImportError:
                logger.warning("Push notification service not available")
                return {'success': False, 'error': 'Push notification service not configured'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _execute_sms_action(self, execution, config):
        """Execute SMS action"""
        try:
            # Template the SMS message
            message = self._template_string(config.get('message', 'Escalation alert'), execution.trigger_context)
            
            # Import SMS service (assuming it exists)
            try:
                from services.sms_service import send_sms
                
                result = send_sms(
                    to=config.get('to', []),
                    message=message
                )
                
                return {'success': True, 'result': result}
                
            except ImportError:
                logger.warning("SMS service not available")
                return {'success': False, 'error': 'SMS service not configured'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _execute_create_ticket_action(self, execution, config):
        """Execute create ticket action"""
        try:
            # Template ticket content
            title = self._template_string(config.get('title', 'Escalation Alert'), execution.trigger_context)
            description = self._template_string(config.get('description', 'Escalation triggered'), execution.trigger_context)
            
            # Import ticketing service (assuming it exists)
            try:
                from services.ticketing_service import create_ticket
                
                result = create_ticket(
                    system=config.get('system'),
                    project=config.get('project'),
                    title=title,
                    description=description,
                    priority=config.get('priority', 'medium')
                )
                
                return {'success': True, 'ticket_id': result.get('ticket_id')}
                
            except ImportError:
                logger.warning("Ticketing service not available")
                return {'success': False, 'error': 'Ticketing service not configured'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _execute_run_script_action(self, execution, config):
        """Execute run script action"""
        try:
            command = config.get('command')
            args = config.get('args', [])
            timeout = config.get('timeout', self.action_timeout)
            working_directory = config.get('working_directory')
            
            if not command:
                return {'success': False, 'error': 'No command specified'}
            
            # Build full command
            full_command = [command] + (args if isinstance(args, list) else [args])
            
            # Execute command
            result = subprocess.run(
                full_command,
                cwd=working_directory,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                'success': result.returncode == 0,
                'return_code': result.returncode,
                'stdout': result.stdout[:1000],  # Limit output size
                'stderr': result.stderr[:1000]
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Script execution timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _template_string(self, template, context):
        """Simple template substitution for action strings"""
        try:
            # Simple {{key}} replacement
            result = template
            for key, value in context.items():
                placeholder = f"{{{{{key}}}}}"
                result = result.replace(placeholder, str(value))
            return result
        except Exception as e:
            logger.error(f"Error templating string '{template}': {e}")
            return template
    
    def _mark_execution_failed(self, execution, error_message):
        """Mark an execution as failed"""
        try:
            execution.status = 'failed'
            execution.error_message = error_message
            execution.completed_at = datetime.utcnow()
            db.session.commit()
        except Exception as e:
            logger.error(f"Error marking execution {execution.id} as failed: {e}")
    
    def _cleanup_old_executions(self):
        """Clean up old completed escalation executions"""
        try:
            # Keep executions for 30 days
            cutoff = datetime.utcnow() - timedelta(days=30)
            
            deleted_count = EscalationExecution.query.filter(
                EscalationExecution.completed_at < cutoff,
                EscalationExecution.status.in_(['completed', 'failed', 'cancelled'])
            ).delete()
            
            if deleted_count > 0:
                db.session.commit()
                logger.info(f"Cleaned up {deleted_count} old escalation executions")
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error cleaning up old executions: {e}")
    
    def cancel_execution(self, execution_id):
        """Cancel a pending or in-progress escalation execution"""
        try:
            execution = EscalationExecution.query.get(execution_id)
            if not execution:
                return {'success': False, 'error': 'Execution not found'}
            
            if execution.status not in ['pending', 'in_progress']:
                return {'success': False, 'error': f'Cannot cancel execution with status: {execution.status}'}
            
            execution.status = 'cancelled'
            execution.completed_at = datetime.utcnow()
            execution.error_message = 'Cancelled by user'
            
            db.session.commit()
            
            logger.info(f"Cancelled escalation execution {execution_id}")
            return {'success': True}
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error cancelling execution {execution_id}: {e}")
            return {'success': False, 'error': str(e)}

# Global service instance
escalation_service = EscalationExecutionService()