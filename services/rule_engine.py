import threading
import time
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class TriggerContext:
    """Context data for rule triggers"""
    event_type: str  # device_status_change, alert_created, scan_complete, etc.
    device_id: Optional[int] = None
    device: Optional[Dict] = None
    alert: Optional[Dict] = None
    monitoring_data: Optional[Dict] = None
    timestamp: datetime = None
    metadata: Dict = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.metadata is None:
            self.metadata = {}

class ConditionEvaluator:
    """Evaluates rule conditions against trigger context"""
    
    def __init__(self):
        self.operators = {
            'eq': lambda a, b: a == b,
            'ne': lambda a, b: a != b,
            'gt': lambda a, b: float(a) > float(b),
            'gte': lambda a, b: float(a) >= float(b),
            'lt': lambda a, b: float(a) < float(b),
            'lte': lambda a, b: float(a) <= float(b),
            'contains': lambda a, b: str(b) in str(a),
            'starts_with': lambda a, b: str(a).startswith(str(b)),
            'ends_with': lambda a, b: str(a).endswith(str(b)),
            'in': lambda a, b: a in b if isinstance(b, list) else False,
            'not_in': lambda a, b: a not in b if isinstance(b, list) else True
        }
    
    def evaluate(self, conditions: Dict, context: TriggerContext) -> bool:
        """Evaluate rule conditions against trigger context"""
        try:
            if not conditions:
                return False
            
            # Handle logical operators
            if 'and' in conditions:
                return all(self.evaluate(cond, context) for cond in conditions['and'])
            
            if 'or' in conditions:
                return any(self.evaluate(cond, context) for cond in conditions['or'])
            
            if 'not' in conditions:
                return not self.evaluate(conditions['not'], context)
            
            # Handle basic condition
            field = conditions.get('field')
            operator = conditions.get('operator', 'eq')
            value = conditions.get('value')
            
            if not field or operator not in self.operators:
                return False
            
            # Get field value from context
            field_value = self._get_field_value(field, context)
            
            # Handle special cases for None values
            if field_value is None:
                return operator in ['ne', 'not_in'] and value is not None
            
            # Apply operator
            return self.operators[operator](field_value, value)
            
        except Exception as e:
            logger.error(f"Error evaluating condition: {e}")
            return False
    
    def _get_field_value(self, field: str, context: TriggerContext) -> Any:
        """Extract field value from trigger context"""
        try:
            # Handle dot notation (e.g., device.status, alert.severity)
            parts = field.split('.')
            
            if parts[0] == 'device' and context.device:
                obj = context.device
            elif parts[0] == 'alert' and context.alert:
                obj = context.alert
            elif parts[0] == 'monitoring' and context.monitoring_data:
                obj = context.monitoring_data
            elif parts[0] == 'context':
                obj = {
                    'event_type': context.event_type,
                    'device_id': context.device_id,
                    'timestamp': context.timestamp.isoformat(),
                    'metadata': context.metadata
                }
            else:
                return None
            
            # Navigate through nested fields
            for part in parts[1:]:
                if isinstance(obj, dict):
                    obj = obj.get(part)
                else:
                    obj = getattr(obj, part, None)
                
                if obj is None:
                    return None
            
            return obj
            
        except Exception as e:
            logger.error(f"Error getting field value for {field}: {e}")
            return None

class ActionExecutor:
    """Executes rule actions"""
    
    def __init__(self, app=None):
        self.app = app
    
    def execute(self, actions: List[Dict], context: TriggerContext) -> Dict:
        """Execute a list of actions and return results"""
        results = {
            'success': True,
            'actions_executed': 0,
            'actions_failed': 0,
            'details': []
        }
        
        for action in actions:
            try:
                action_type = action.get('type')
                action_params = action.get('params', {})
                
                result = self._execute_single_action(action_type, action_params, context)
                results['details'].append({
                    'action': action_type,
                    'success': result['success'],
                    'message': result.get('message', ''),
                    'data': result.get('data', {})
                })
                
                if result['success']:
                    results['actions_executed'] += 1
                else:
                    results['actions_failed'] += 1
                    results['success'] = False
                    
            except Exception as e:
                logger.error(f"Error executing action {action}: {e}")
                results['actions_failed'] += 1
                results['success'] = False
                results['details'].append({
                    'action': action.get('type', 'unknown'),
                    'success': False,
                    'message': str(e)
                })
        
        return results
    
    def _execute_single_action(self, action_type: str, params: Dict, context: TriggerContext) -> Dict:
        """Execute a single action"""
        try:
            if action_type == 'send_notification':
                return self._send_notification(params, context)
            elif action_type == 'create_alert':
                return self._create_alert(params, context)
            elif action_type == 'trigger_scan':
                return self._trigger_scan(params, context)
            elif action_type == 'update_device':
                return self._update_device(params, context)
            elif action_type == 'log_event':
                return self._log_event(params, context)
            elif action_type == 'webhook':
                return self._send_webhook(params, context)
            else:
                return {'success': False, 'message': f'Unknown action type: {action_type}'}
                
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _send_notification(self, params: Dict, context: TriggerContext) -> Dict:
        """Send push notification"""
        try:
            from services.push_notifications import push_service
            
            title = params.get('title', 'Automation Alert')
            message = params.get('message', 'Rule triggered')
            priority = params.get('priority', 'default')
            tags = params.get('tags', 'robot_face,gear')
            
            # Template substitution
            title = self._substitute_template(title, context)
            message = self._substitute_template(message, context)
            
            success = push_service.send_notification(
                title=title,
                message=message,
                priority=priority,
                tags=tags
            )
            
            return {
                'success': success,
                'message': 'Notification sent' if success else 'Failed to send notification',
                'data': {'title': title, 'message': message}
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _create_alert(self, params: Dict, context: TriggerContext) -> Dict:
        """Create system alert"""
        try:
            if not self.app or not context.device_id:
                return {'success': False, 'message': 'No app context or device ID'}
            
            with self.app.app_context():
                from models import db, Alert
                
                alert_type = params.get('type', 'automation')
                severity = params.get('severity', 'warning')
                message = params.get('message', 'Alert created by automation rule')
                
                # Template substitution
                message = self._substitute_template(message, context)
                
                alert = Alert(
                    device_id=context.device_id,
                    alert_type=alert_type,
                    severity=severity,
                    message=message
                )
                
                db.session.add(alert)
                db.session.commit()
                
                return {
                    'success': True,
                    'message': 'Alert created',
                    'data': {'alert_id': alert.id, 'message': message}
                }
                
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _trigger_scan(self, params: Dict, context: TriggerContext) -> Dict:
        """Trigger network scan"""
        try:
            scan_type = params.get('type', 'network')
            
            if scan_type == 'network':
                # Trigger network scan with proper integration
                logger.info("Network scan triggered by automation rule")
                
                # Get the scanner service from app if available
                if self.app and hasattr(self.app, '_scanner'):
                    scanner = self.app._scanner
                    # Check if scanner is currently running a scan
                    if hasattr(scanner, 'is_scanning') and scanner.is_scanning:
                        return {'success': False, 'message': 'Network scan already in progress'}
                    
                    # Trigger the scan in a background thread
                    import threading
                    def run_scan():
                        try:
                            scanner.scan_network()
                        except Exception as e:
                            logger.error(f"Background scan error: {e}")
                    
                    scan_thread = threading.Thread(target=run_scan, daemon=True, name='RuleEngine-NetworkScan')
                    scan_thread.start()
                    return {'success': True, 'message': 'Network scan triggered successfully'}
                else:
                    logger.warning("Scanner service not available")
                    return {'success': False, 'message': 'Scanner service not available'}
                    
            elif scan_type == 'security' and context.device_id:
                # Trigger security scan for specific device
                logger.info(f"Security scan triggered for device {context.device_id}")
                
                # Get the security scanner service from app if available
                if self.app and hasattr(self.app, 'security_scanner'):
                    security_scanner = self.app.security_scanner
                    # Trigger security scan for the device
                    import threading
                    def run_security_scan():
                        try:
                            with self.app.app_context():
                                security_scanner.scan_device(context.device_id)
                        except Exception as e:
                            logger.error(f"Security scan error for device {context.device_id}: {e}")
                    
                    scan_thread = threading.Thread(target=run_security_scan, daemon=True, name='RuleEngine-SecurityScan')
                    scan_thread.start()
                    return {'success': True, 'message': f'Security scan triggered for device {context.device_id}'}
                else:
                    logger.warning("Security scanner service not available")
                    return {'success': False, 'message': 'Security scanner service not available'}
            else:
                return {'success': False, 'message': 'Invalid scan type or missing device'}
                
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _update_device(self, params: Dict, context: TriggerContext) -> Dict:
        """Update device properties"""
        try:
            if not self.app or not context.device_id:
                return {'success': False, 'message': 'No app context or device ID'}
            
            with self.app.app_context():
                from models import db, Device
                
                device = Device.query.get(context.device_id)
                if not device:
                    return {'success': False, 'message': 'Device not found'}
                
                # Update specified fields
                updated_fields = []
                for field, value in params.items():
                    if hasattr(device, field) and field not in ['id', 'created_at']:
                        setattr(device, field, value)
                        updated_fields.append(field)
                
                db.session.commit()
                
                return {
                    'success': True,
                    'message': f'Device updated: {", ".join(updated_fields)}',
                    'data': {'updated_fields': updated_fields}
                }
                
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _log_event(self, params: Dict, context: TriggerContext) -> Dict:
        """Log custom event"""
        level = params.get('level', 'info')
        message = params.get('message', 'Automation rule triggered')
        
        # Template substitution
        message = self._substitute_template(message, context)
        
        if level == 'error':
            logger.error(f"AUTOMATION: {message}")
        elif level == 'warning':
            logger.warning(f"AUTOMATION: {message}")
        else:
            logger.info(f"AUTOMATION: {message}")
        
        return {'success': True, 'message': 'Event logged', 'data': {'log_message': message}}
    
    def _send_webhook(self, params: Dict, context: TriggerContext) -> Dict:
        """Send webhook request"""
        try:
            import requests
            
            url = params.get('url')
            method = params.get('method', 'POST').upper()
            headers = params.get('headers', {})
            data = params.get('data', {})
            
            if not url:
                return {'success': False, 'message': 'No webhook URL specified'}
            
            # Add context data
            webhook_data = {
                'context': {
                    'event_type': context.event_type,
                    'device_id': context.device_id,
                    'timestamp': context.timestamp.isoformat()
                },
                **data
            }
            
            response = requests.request(
                method=method,
                url=url,
                json=webhook_data,
                headers=headers,
                timeout=10
            )
            
            return {
                'success': response.status_code < 400,
                'message': f'Webhook {method} to {url}: {response.status_code}',
                'data': {'status_code': response.status_code}
            }
            
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def _substitute_template(self, template: str, context: TriggerContext) -> str:
        """Simple template substitution"""
        try:
            if not template or '{' not in template:
                return template
            
            substitutions = {
                'device_name': context.device.get('display_name', 'Unknown') if context.device else 'Unknown',
                'device_ip': context.device.get('ip_address', 'Unknown') if context.device else 'Unknown',
                'event_type': context.event_type,
                'timestamp': context.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            for key, value in substitutions.items():
                template = template.replace(f'{{{key}}}', str(value))
            
            return template
            
        except Exception:
            return template

class RuleEngineService:
    """Main rule engine service that manages and executes automation rules"""
    
    def __init__(self, app=None):
        self.app = app
        self.running = False
        self.condition_evaluator = ConditionEvaluator()
        self.action_executor = ActionExecutor(app)
        self._stop_event = threading.Event()
    
    def start_monitoring(self):
        """Start the rule engine monitoring loop"""
        if self.running:
            logger.warning("Rule engine already running")
            return
        
        self.running = True
        logger.info("Starting rule engine service")
        
        def monitoring_loop():
            while not self._stop_event.is_set():
                try:
                    # Rule engine runs every 30 seconds
                    self._stop_event.wait(30)
                except Exception as e:
                    logger.error(f"Error in rule engine loop: {e}")
                    time.sleep(60)
        
        monitoring_thread = threading.Thread(
            target=monitoring_loop,
            daemon=True,
            name='RuleEngine'
        )
        monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop the rule engine"""
        self.running = False
        self._stop_event.set()
        logger.info("Rule engine stopped")
    
    def evaluate_rules(self, context: TriggerContext) -> List[Dict]:
        """Evaluate all rules against the given context and execute matching ones"""
        if not self.app:
            logger.error("No Flask app context available")
            return []
        
        execution_results = []
        
        try:
            with self.app.app_context():
                from models import AutomationRule, RuleExecution, db
                
                # Get all enabled rules
                rules = AutomationRule.query.filter_by(enabled=True).all()
                
                for rule in rules:
                    try:
                        # Check if rule can execute (cooldown, rate limiting)
                        if not rule.can_execute():
                            continue
                        
                        # Evaluate conditions
                        if self.condition_evaluator.evaluate(rule.conditions, context):
                            logger.info(f"Rule '{rule.name}' triggered by {context.event_type}")
                            
                            # Execute actions
                            start_time = datetime.utcnow()
                            action_results = self.action_executor.execute(rule.actions, context)
                            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
                            
                            # Create execution record
                            execution = RuleExecution(
                                rule_id=rule.id,
                                success=action_results['success'],
                                execution_time_ms=int(execution_time),
                                trigger_context=json.dumps({
                                    'event_type': context.event_type,
                                    'device_id': context.device_id,
                                    'timestamp': context.timestamp.isoformat(),
                                    'metadata': context.metadata
                                }),
                                action_results=json.dumps(action_results)
                            )
                            
                            if not action_results['success']:
                                execution.error_message = f"Actions failed: {action_results.get('details', [])}"
                            
                            db.session.add(execution)
                            
                            # Update rule execution tracking
                            rule.mark_executed(action_results['success'])
                            
                            execution_results.append({
                                'rule_id': rule.id,
                                'rule_name': rule.name,
                                'success': action_results['success'],
                                'results': action_results
                            })
                            
                    except Exception as e:
                        logger.error(f"Error executing rule '{rule.name}': {e}")
                        
                        # Create failed execution record
                        execution = RuleExecution(
                            rule_id=rule.id,
                            success=False,
                            error_message=str(e),
                            trigger_context=json.dumps({
                                'event_type': context.event_type,
                                'device_id': context.device_id,
                                'timestamp': context.timestamp.isoformat()
                            })
                        )
                        db.session.add(execution)
                        rule.mark_executed(False)
                
                db.session.commit()
                
        except Exception as e:
            logger.error(f"Error in rule evaluation: {e}")
        
        return execution_results
    
    def test_rule(self, rule_id: int, test_context: Dict) -> Dict:
        """Test a rule with sample context data"""
        if not self.app:
            return {'success': False, 'error': 'No app context'}
        
        try:
            with self.app.app_context():
                from models import AutomationRule
                
                rule = AutomationRule.query.get(rule_id)
                if not rule:
                    return {'success': False, 'error': 'Rule not found'}
                
                # Create test context
                context = TriggerContext(
                    event_type=test_context.get('event_type', 'test'),
                    device_id=test_context.get('device_id'),
                    device=test_context.get('device', {}),
                    metadata={'test_mode': True}
                )
                
                # Test condition evaluation
                condition_result = self.condition_evaluator.evaluate(rule.conditions, context)
                
                result = {
                    'success': True,
                    'rule_name': rule.name,
                    'condition_result': condition_result,
                    'would_execute': condition_result and rule.can_execute()
                }
                
                # If conditions pass and test execution is requested
                if condition_result and test_context.get('execute_actions', False):
                    action_results = self.action_executor.execute(rule.actions, context)
                    result['action_results'] = action_results
                
                return result
                
        except Exception as e:
            return {'success': False, 'error': str(e)}

# Global rule engine instance
rule_engine_service = RuleEngineService()