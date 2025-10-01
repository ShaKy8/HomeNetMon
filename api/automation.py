from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from models import db, AutomationRule, RuleExecution, Device
from services.rule_engine import rule_engine_service, TriggerContext
from sqlalchemy import desc
import json
from api.rate_limited_endpoints import create_endpoint_limiter

automation_bp = Blueprint('automation', __name__)

@automation_bp.route('/rules', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_rules():
    """Get all automation rules"""
    try:
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        category = request.args.get('category')
        enabled = request.args.get('enabled')
        
        query = AutomationRule.query
        
        # Filter by category
        if category:
            query = query.filter(AutomationRule.category == category)
        
        # Filter by enabled status
        if enabled is not None:
            enabled_bool = enabled.lower() == 'true'
            query = query.filter(AutomationRule.enabled == enabled_bool)
        
        # Order by most recently updated
        query = query.order_by(desc(AutomationRule.updated_at))
        
        # Paginate
        pagination = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        rules = [rule.to_dict() for rule in pagination.items]
        
        return jsonify({
            'rules': rules,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@automation_bp.route('/rules', methods=['POST'])
@create_endpoint_limiter('strict')
def create_rule():
    """Create a new automation rule"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        if not data.get('name'):
            return jsonify({'error': 'Rule name is required'}), 400
        
        if not data.get('conditions'):
            return jsonify({'error': 'Rule conditions are required'}), 400
        
        if not data.get('actions'):
            return jsonify({'error': 'Rule actions are required'}), 400
        
        # Create new rule
        rule = AutomationRule(
            name=data['name'],
            description=data.get('description', ''),
            enabled=data.get('enabled', True),
            cooldown_minutes=data.get('cooldown_minutes', 5),
            max_executions_per_hour=data.get('max_executions_per_hour', 10),
            priority=data.get('priority', 'medium'),
            category=data.get('category', 'general')
        )
        
        # Set conditions and actions (using property setters)
        rule.conditions = data['conditions']
        rule.actions = data['actions']
        
        db.session.add(rule)
        db.session.commit()
        
        return jsonify({
            'message': 'Rule created successfully',
            'rule': rule.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@automation_bp.route('/rules/<int:rule_id>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_rule(rule_id):
    """Get a specific rule"""
    try:
        rule = AutomationRule.query.get(rule_id)
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        return jsonify(rule.to_dict())
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@automation_bp.route('/rules/<int:rule_id>', methods=['PUT'])
@create_endpoint_limiter('strict')
def update_rule(rule_id):
    """Update an automation rule"""
    try:
        rule = AutomationRule.query.get(rule_id)
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update fields
        if 'name' in data:
            rule.name = data['name']
        if 'description' in data:
            rule.description = data['description']
        if 'enabled' in data:
            rule.enabled = data['enabled']
        if 'conditions' in data:
            rule.conditions = data['conditions']
        if 'actions' in data:
            rule.actions = data['actions']
        if 'cooldown_minutes' in data:
            rule.cooldown_minutes = data['cooldown_minutes']
        if 'max_executions_per_hour' in data:
            rule.max_executions_per_hour = data['max_executions_per_hour']
        if 'priority' in data:
            rule.priority = data['priority']
        if 'category' in data:
            rule.category = data['category']
        
        rule.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Rule updated successfully',
            'rule': rule.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@automation_bp.route('/rules/<int:rule_id>', methods=['DELETE'])
@create_endpoint_limiter('critical')
def delete_rule(rule_id):
    """Delete an automation rule"""
    try:
        rule = AutomationRule.query.get(rule_id)
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        rule_name = rule.name
        db.session.delete(rule)
        db.session.commit()
        
        return jsonify({
            'message': f'Rule "{rule_name}" deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@automation_bp.route('/rules/<int:rule_id>/toggle', methods=['POST'])
@create_endpoint_limiter('strict')
def toggle_rule(rule_id):
    """Toggle rule enabled/disabled status"""
    try:
        rule = AutomationRule.query.get(rule_id)
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        rule.enabled = not rule.enabled
        rule.updated_at = datetime.utcnow()
        db.session.commit()
        
        status = 'enabled' if rule.enabled else 'disabled'
        return jsonify({
            'message': f'Rule "{rule.name}" {status}',
            'enabled': rule.enabled
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@automation_bp.route('/rules/<int:rule_id>/test', methods=['POST'])
@create_endpoint_limiter('critical')
def test_rule(rule_id):
    """Test a rule with sample data"""
    try:
        data = request.get_json() or {}
        
        # Default test context
        test_context = {
            'event_type': data.get('event_type', 'test'),
            'device_id': data.get('device_id'),
            'execute_actions': data.get('execute_actions', False)
        }
        
        # If device_id provided, get device data
        if test_context['device_id']:
            device = Device.query.get(test_context['device_id'])
            if device:
                test_context['device'] = {
                    'id': device.id,
                    'display_name': device.display_name,
                    'ip_address': device.ip_address,
                    'status': device.status,
                    'device_type': device.device_type,
                    'is_monitored': device.is_monitored
                }
        
        result = rule_engine_service.test_rule(rule_id, test_context)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@automation_bp.route('/executions', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_executions():
    """Get rule execution history"""
    try:
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)
        rule_id = request.args.get('rule_id', type=int)
        success = request.args.get('success')
        hours = request.args.get('hours', type=int, default=24)
        
        query = RuleExecution.query
        
        # Filter by time range
        if hours:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            query = query.filter(RuleExecution.executed_at >= cutoff)
        
        # Filter by rule
        if rule_id:
            query = query.filter(RuleExecution.rule_id == rule_id)
        
        # Filter by success status
        if success is not None:
            success_bool = success.lower() == 'true'
            query = query.filter(RuleExecution.success == success_bool)
        
        # Order by most recent first
        query = query.order_by(desc(RuleExecution.executed_at))
        
        # Paginate
        pagination = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        executions = [execution.to_dict() for execution in pagination.items]
        
        return jsonify({
            'executions': executions,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@automation_bp.route('/stats', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_automation_stats():
    """Get automation statistics"""
    try:
        hours = request.args.get('hours', type=int, default=24)
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get basic rule counts
        total_rules = AutomationRule.query.count()
        enabled_rules = AutomationRule.query.filter_by(enabled=True).count()
        
        # Get execution stats
        executions = RuleExecution.query.filter(RuleExecution.executed_at >= cutoff).all()
        
        stats = {
            'total_rules': total_rules,
            'enabled_rules': enabled_rules,
            'disabled_rules': total_rules - enabled_rules,
            'executions_last_24h': len(executions),
            'successful_executions': sum(1 for e in executions if e.success),
            'failed_executions': sum(1 for e in executions if not e.success),
            'success_rate': 0.0,
            'avg_execution_time_ms': 0.0,
            'most_active_rules': [],
            'execution_by_category': {},
            'recent_executions': []
        }
        
        if executions:
            # Calculate success rate
            stats['success_rate'] = (stats['successful_executions'] / len(executions)) * 100
            
            # Calculate average execution time
            execution_times = [e.execution_time_ms for e in executions if e.execution_time_ms]
            if execution_times:
                stats['avg_execution_time_ms'] = sum(execution_times) / len(execution_times)
            
            # Most active rules
            rule_counts = {}
            category_counts = {}
            
            for execution in executions:
                rule_name = execution.rule.name if execution.rule else 'Unknown'
                rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1
                
                if execution.rule:
                    category = execution.rule.category
                    category_counts[category] = category_counts.get(category, 0) + 1
            
            stats['most_active_rules'] = sorted(
                rule_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
            
            stats['execution_by_category'] = category_counts
        
        # Recent executions (last 10)
        recent = RuleExecution.query.filter(
            RuleExecution.executed_at >= cutoff
        ).order_by(desc(RuleExecution.executed_at)).limit(10).all()
        
        stats['recent_executions'] = [execution.to_dict() for execution in recent]
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@automation_bp.route('/templates', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_rule_templates():
    """Get pre-built rule templates"""
    templates = [
        {
            'id': 'router_down_alert',
            'name': 'Router Down Critical Alert',
            'description': 'Send critical alert when router goes down',
            'category': 'device',
            'conditions': {
                'and': [
                    {'field': 'device.device_type', 'operator': 'eq', 'value': 'router'},
                    {'field': 'device.status', 'operator': 'eq', 'value': 'down'},
                    {'field': 'context.event_type', 'operator': 'eq', 'value': 'device_status_change'}
                ]
            },
            'actions': [
                {
                    'type': 'send_notification',
                    'params': {
                        'title': '🔴 Router Offline: {device_name}',
                        'message': 'Critical: Router {device_name} ({device_ip}) is offline. Network connectivity may be affected.',
                        'priority': 'urgent',
                        'tags': 'rotating_light,red_circle,router'
                    }
                },
                {
                    'type': 'create_alert',
                    'params': {
                        'type': 'router_down',
                        'severity': 'critical',
                        'message': 'Router {device_name} is offline - network connectivity affected'
                    }
                }
            ]
        },
        {
            'id': 'new_device_security',
            'name': 'New Device Security Check',
            'description': 'Automatically scan new devices for security',
            'category': 'security',
            'conditions': {
                'field': 'context.event_type',
                'operator': 'eq',
                'value': 'new_device_discovered'
            },
            'actions': [
                {
                    'type': 'send_notification',
                    'params': {
                        'title': '🆕 New Device: {device_name}',
                        'message': 'New device {device_name} ({device_ip}) detected. Security scan initiated.',
                        'priority': 'default',
                        'tags': 'new,shield,computer'
                    }
                },
                {
                    'type': 'trigger_scan',
                    'params': {
                        'type': 'security'
                    }
                },
                {
                    'type': 'update_device',
                    'params': {
                        'device_group': 'new_devices'
                    }
                }
            ]
        },
        {
            'id': 'high_latency_alert',
            'name': 'High Latency Warning',
            'description': 'Alert when device latency is consistently high',
            'category': 'network',
            'conditions': {
                'and': [
                    {'field': 'monitoring.response_time', 'operator': 'gt', 'value': 500},
                    {'field': 'context.event_type', 'operator': 'eq', 'value': 'monitoring_data'}
                ]
            },
            'actions': [
                {
                    'type': 'send_notification',
                    'params': {
                        'title': '⚠️ High Latency: {device_name}',
                        'message': 'Device {device_name} has high network latency. Performance may be affected.',
                        'priority': 'default',
                        'tags': 'warning,hourglass_not_done,yellow_circle'
                    }
                },
                {
                    'type': 'log_event',
                    'params': {
                        'level': 'warning',
                        'message': 'High latency detected on {device_name} ({device_ip})'
                    }
                }
            ]
        },
        {
            'id': 'daily_network_summary',
            'name': 'Daily Network Summary',
            'description': 'Send daily network status summary',
            'category': 'maintenance',
            'conditions': {
                'and': [
                    {'field': 'context.event_type', 'operator': 'eq', 'value': 'scheduled'},
                    {'field': 'context.metadata.schedule', 'operator': 'eq', 'value': 'daily'}
                ]
            },
            'actions': [
                {
                    'type': 'send_notification',
                    'params': {
                        'title': '📊 Daily Network Summary',
                        'message': 'Daily network monitoring summary is ready. Check the dashboard for details.',
                        'priority': 'low',
                        'tags': 'chart_with_upwards_trend,blue_circle,information_source'
                    }
                },
                {
                    'type': 'trigger_scan',
                    'params': {
                        'type': 'network'
                    }
                }
            ]
        }
    ]
    
    return jsonify({'templates': templates})

@automation_bp.route('/templates/<template_id>', methods=['POST'])
@create_endpoint_limiter('strict')
def create_rule_from_template(template_id):
    """Create a rule from a template"""
    try:
        templates = {t['id']: t for t in get_rule_templates().get_json()['templates']}
        
        if template_id not in templates:
            return jsonify({'error': 'Template not found'}), 404
        
        template = templates[template_id]
        data = request.get_json() or {}
        
        # Create rule from template with optional customizations
        rule = AutomationRule(
            name=data.get('name', template['name']),
            description=data.get('description', template['description']),
            category=template['category'],
            enabled=data.get('enabled', True),
            cooldown_minutes=data.get('cooldown_minutes', 5),
            max_executions_per_hour=data.get('max_executions_per_hour', 10)
        )
        
        # Use template conditions and actions (can be overridden)
        rule.conditions = data.get('conditions', template['conditions'])
        rule.actions = data.get('actions', template['actions'])
        
        db.session.add(rule)
        db.session.commit()
        
        return jsonify({
            'message': f'Rule created from template "{template["name"]}"',
            'rule': rule.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500