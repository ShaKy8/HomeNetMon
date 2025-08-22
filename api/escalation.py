"""
Escalation Management API

Provides endpoints for managing escalation rules, viewing escalation executions,
and configuring automated escalation workflows for notification failures and alerts.
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from models import db, EscalationRule, EscalationExecution, EscalationActionLog, NotificationHistory, Alert
from sqlalchemy import and_, desc, func, or_
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)
escalation_bp = Blueprint('escalation', __name__)

@escalation_bp.route('/rules', methods=['GET'])
def get_escalation_rules():
    """Get all escalation rules with optional filtering"""
    try:
        # Query parameters
        enabled_only = request.args.get('enabled_only', 'false').lower() == 'true'
        trigger_type = request.args.get('trigger_type')
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)
        
        # Build query
        query = EscalationRule.query
        
        if enabled_only:
            query = query.filter(EscalationRule.enabled == True)
        
        if trigger_type:
            query = query.filter(EscalationRule.trigger_type == trigger_type)
        
        # Order by priority (lower number = higher priority), then by name
        query = query.order_by(EscalationRule.priority.asc(), EscalationRule.name.asc())
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
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
        logger.error(f"Error getting escalation rules: {e}")
        return jsonify({'error': str(e)}), 500

@escalation_bp.route('/rules', methods=['POST'])
def create_escalation_rule():
    """Create a new escalation rule"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'trigger_type', 'escalation_actions']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Validate escalation actions format
        if not isinstance(data['escalation_actions'], list) or len(data['escalation_actions']) == 0:
            return jsonify({'error': 'escalation_actions must be a non-empty list'}), 400
        
        # Create rule
        rule = EscalationRule(
            name=data['name'],
            description=data.get('description'),
            enabled=data.get('enabled', True),
            priority=data.get('priority', 1),
            trigger_type=data['trigger_type'],
            trigger_conditions=data.get('trigger_conditions'),
            delay_minutes=data.get('delay_minutes', 0),
            max_escalations=data.get('max_escalations', 3),
            escalation_interval_minutes=data.get('escalation_interval_minutes', 60),
            escalation_actions=data['escalation_actions'],
            applies_to_device_types=data.get('applies_to_device_types'),
            applies_to_notification_types=data.get('applies_to_notification_types'),
            applies_to_severity_levels=data.get('applies_to_severity_levels'),
            created_by=data.get('created_by', 'api_user')
        )
        
        db.session.add(rule)
        db.session.commit()
        
        logger.info(f"Created escalation rule: {rule.name}")
        return jsonify(rule.to_dict()), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating escalation rule: {e}")
        return jsonify({'error': str(e)}), 500

@escalation_bp.route('/rules/<int:rule_id>', methods=['GET'])
def get_escalation_rule(rule_id):
    """Get a specific escalation rule"""
    try:
        rule = EscalationRule.query.get_or_404(rule_id)
        
        # Include execution statistics
        rule_data = rule.to_dict()
        
        # Get recent executions
        recent_executions = EscalationExecution.query.filter_by(escalation_rule_id=rule_id)\
                                                    .order_by(EscalationExecution.created_at.desc())\
                                                    .limit(10).all()
        
        rule_data['recent_executions'] = [execution.to_dict() for execution in recent_executions]
        
        # Get execution statistics
        total_executions = rule.escalation_executions.count()
        successful_executions = rule.escalation_executions.filter_by(status='completed').count()
        failed_executions = rule.escalation_executions.filter_by(status='failed').count()
        
        rule_data['statistics'] = {
            'total_executions': total_executions,
            'successful_executions': successful_executions,
            'failed_executions': failed_executions,
            'success_rate': (successful_executions / total_executions * 100) if total_executions > 0 else 0
        }
        
        return jsonify(rule_data)
        
    except Exception as e:
        logger.error(f"Error getting escalation rule {rule_id}: {e}")
        return jsonify({'error': str(e)}), 500

@escalation_bp.route('/rules/<int:rule_id>', methods=['PUT'])
def update_escalation_rule(rule_id):
    """Update an escalation rule"""
    try:
        rule = EscalationRule.query.get_or_404(rule_id)
        data = request.get_json()
        
        # Update fields
        updatable_fields = [
            'name', 'description', 'enabled', 'priority', 'trigger_conditions',
            'delay_minutes', 'max_escalations', 'escalation_interval_minutes',
            'escalation_actions', 'applies_to_device_types', 'applies_to_notification_types',
            'applies_to_severity_levels'
        ]
        
        for field in updatable_fields:
            if field in data:
                setattr(rule, field, data[field])
        
        rule.updated_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Updated escalation rule: {rule.name}")
        return jsonify(rule.to_dict())
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating escalation rule {rule_id}: {e}")
        return jsonify({'error': str(e)}), 500

@escalation_bp.route('/rules/<int:rule_id>', methods=['DELETE'])
def delete_escalation_rule(rule_id):
    """Delete an escalation rule"""
    try:
        rule = EscalationRule.query.get_or_404(rule_id)
        
        # Check for active executions
        active_executions = rule.escalation_executions.filter(
            EscalationExecution.status.in_(['pending', 'in_progress'])
        ).count()
        
        if active_executions > 0:
            return jsonify({
                'error': f'Cannot delete rule with {active_executions} active executions. Cancel them first.'
            }), 400
        
        rule_name = rule.name
        db.session.delete(rule)
        db.session.commit()
        
        logger.info(f"Deleted escalation rule: {rule_name}")
        return jsonify({'message': f'Escalation rule "{rule_name}" deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting escalation rule {rule_id}: {e}")
        return jsonify({'error': str(e)}), 500

@escalation_bp.route('/rules/<int:rule_id>/test', methods=['POST'])
def test_escalation_rule(rule_id):
    """Test an escalation rule with provided context"""
    try:
        rule = EscalationRule.query.get_or_404(rule_id)
        data = request.get_json()
        
        test_context = data.get('context', {})
        
        # Test if rule matches the context
        matches = rule.matches_conditions(test_context)
        
        result = {
            'rule_id': rule_id,
            'rule_name': rule.name,
            'matches': matches,
            'test_context': test_context,
            'rule_conditions': {
                'trigger_type': rule.trigger_type,
                'trigger_conditions': rule.trigger_conditions,
                'applies_to_device_types': rule.applies_to_device_types,
                'applies_to_notification_types': rule.applies_to_notification_types,
                'applies_to_severity_levels': rule.applies_to_severity_levels
            }
        }
        
        if matches:
            result['would_execute'] = {
                'delay_minutes': rule.delay_minutes,
                'max_escalations': rule.max_escalations,
                'escalation_interval_minutes': rule.escalation_interval_minutes,
                'actions': rule.escalation_actions
            }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error testing escalation rule {rule_id}: {e}")
        return jsonify({'error': str(e)}), 500

@escalation_bp.route('/executions', methods=['GET'])
def get_escalation_executions():
    """Get escalation executions with filtering and pagination"""
    try:
        # Query parameters
        rule_id = request.args.get('rule_id', type=int)
        status = request.args.get('status')
        triggered_by_type = request.args.get('triggered_by_type')
        hours = request.args.get('hours', type=int, default=24)
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)
        
        # Build query
        query = EscalationExecution.query
        
        if rule_id:
            query = query.filter(EscalationExecution.escalation_rule_id == rule_id)
        
        if status:
            query = query.filter(EscalationExecution.status == status)
        
        if triggered_by_type:
            query = query.filter(EscalationExecution.triggered_by_type == triggered_by_type)
        
        if hours:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            query = query.filter(EscalationExecution.created_at >= cutoff)
        
        # Order by most recent first
        query = query.order_by(EscalationExecution.created_at.desc())
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
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
        logger.error(f"Error getting escalation executions: {e}")
        return jsonify({'error': str(e)}), 500

@escalation_bp.route('/executions/<int:execution_id>', methods=['GET'])
def get_escalation_execution(execution_id):
    """Get a specific escalation execution with full details"""
    try:
        execution = EscalationExecution.query.get_or_404(execution_id)
        
        execution_data = execution.to_dict()
        
        # Include action logs
        action_logs = EscalationActionLog.query.filter_by(escalation_execution_id=execution_id)\
                                               .order_by(EscalationActionLog.executed_at.desc())\
                                               .all()
        
        execution_data['action_logs'] = [log.to_dict() for log in action_logs]
        
        return jsonify(execution_data)
        
    except Exception as e:
        logger.error(f"Error getting escalation execution {execution_id}: {e}")
        return jsonify({'error': str(e)}), 500

@escalation_bp.route('/executions/<int:execution_id>/cancel', methods=['POST'])
def cancel_escalation_execution(execution_id):
    """Cancel a pending or in-progress escalation execution"""
    try:
        execution = EscalationExecution.query.get_or_404(execution_id)
        
        if execution.status not in ['pending', 'in_progress']:
            return jsonify({
                'error': f'Cannot cancel execution with status: {execution.status}'
            }), 400
        
        execution.status = 'cancelled'
        execution.completed_at = datetime.utcnow()
        execution.error_message = 'Manually cancelled via API'
        
        db.session.commit()
        
        logger.info(f"Cancelled escalation execution {execution_id}")
        return jsonify(execution.to_dict())
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error cancelling escalation execution {execution_id}: {e}")
        return jsonify({'error': str(e)}), 500

@escalation_bp.route('/statistics', methods=['GET'])
def get_escalation_statistics():
    """Get escalation system statistics"""
    try:
        hours = request.args.get('hours', type=int, default=24)
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Basic counts
        stats = {
            'time_range_hours': hours,
            'total_rules': EscalationRule.query.count(),
            'enabled_rules': EscalationRule.query.filter_by(enabled=True).count(),
            'total_executions': EscalationExecution.query.filter(EscalationExecution.created_at >= cutoff).count(),
            'pending_executions': EscalationExecution.query.filter(
                EscalationExecution.status == 'pending',
                EscalationExecution.created_at >= cutoff
            ).count(),
            'completed_executions': EscalationExecution.query.filter(
                EscalationExecution.status == 'completed',
                EscalationExecution.created_at >= cutoff
            ).count(),
            'failed_executions': EscalationExecution.query.filter(
                EscalationExecution.status == 'failed',
                EscalationExecution.created_at >= cutoff
            ).count()
        }
        
        # Success rate
        total_finished = stats['completed_executions'] + stats['failed_executions']
        stats['success_rate'] = (stats['completed_executions'] / total_finished * 100) if total_finished > 0 else 0
        
        # Executions by trigger type
        trigger_type_stats = db.session.query(
            EscalationExecution.triggered_by_type,
            func.count(EscalationExecution.id).label('count')
        ).filter(EscalationExecution.created_at >= cutoff)\
         .group_by(EscalationExecution.triggered_by_type).all()
        
        stats['executions_by_trigger_type'] = {trigger_type: count for trigger_type, count in trigger_type_stats}
        
        # Most active rules
        active_rules_stats = db.session.query(
            EscalationRule.name,
            func.count(EscalationExecution.id).label('execution_count')
        ).join(EscalationExecution)\
         .filter(EscalationExecution.created_at >= cutoff)\
         .group_by(EscalationRule.id, EscalationRule.name)\
         .order_by(func.count(EscalationExecution.id).desc())\
         .limit(5).all()
        
        stats['most_active_rules'] = [
            {'rule_name': name, 'execution_count': count}
            for name, count in active_rules_stats
        ]
        
        # Recent action types
        action_type_stats = db.session.query(
            EscalationActionLog.action_type,
            func.count(EscalationActionLog.id).label('count')
        ).join(EscalationExecution)\
         .filter(EscalationExecution.created_at >= cutoff)\
         .group_by(EscalationActionLog.action_type).all()
        
        stats['actions_by_type'] = {action_type: count for action_type, count in action_type_stats}
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting escalation statistics: {e}")
        return jsonify({'error': str(e)}), 500

@escalation_bp.route('/trigger-types', methods=['GET'])
def get_trigger_types():
    """Get available escalation trigger types"""
    try:
        trigger_types = {
            'notification_failure': {
                'name': 'Notification Failure',
                'description': 'Triggered when a notification fails to deliver',
                'context_fields': ['notification_id', 'notification_type', 'failure_count', 'error_message']
            },
            'alert_unresolved': {
                'name': 'Alert Unresolved',
                'description': 'Triggered when an alert remains unresolved for a specified time',
                'context_fields': ['alert_id', 'severity', 'device_id', 'device_type', 'duration_minutes']
            },
            'device_offline': {
                'name': 'Device Offline',
                'description': 'Triggered when a device goes offline for an extended period',
                'context_fields': ['device_id', 'device_type', 'offline_duration_minutes', 'last_seen']
            },
            'high_failure_rate': {
                'name': 'High Failure Rate',
                'description': 'Triggered when notification failure rate exceeds threshold',
                'context_fields': ['failure_rate', 'time_window_minutes', 'notification_type']
            },
            'manual_trigger': {
                'name': 'Manual Trigger',
                'description': 'Manually triggered escalation',
                'context_fields': ['triggered_by', 'reason', 'manual_context']
            }
        }
        
        return jsonify(trigger_types)
        
    except Exception as e:
        logger.error(f"Error getting trigger types: {e}")
        return jsonify({'error': str(e)}), 500

@escalation_bp.route('/action-types', methods=['GET'])
def get_action_types():
    """Get available escalation action types"""
    try:
        action_types = {
            'email': {
                'name': 'Email Notification',
                'description': 'Send escalation email to specified recipients',
                'config_schema': {
                    'to': 'List of email addresses',
                    'subject': 'Email subject template',
                    'body': 'Email body template',
                    'priority': 'Email priority (normal, high, urgent)'
                }
            },
            'webhook': {
                'name': 'Webhook',
                'description': 'Send HTTP POST to external webhook URL',
                'config_schema': {
                    'url': 'Webhook URL',
                    'method': 'HTTP method (POST, PUT)',
                    'headers': 'Custom headers',
                    'timeout': 'Request timeout in seconds'
                }
            },
            'push_notification': {
                'name': 'Push Notification',
                'description': 'Send push notification using configured service',
                'config_schema': {
                    'title': 'Notification title',
                    'message': 'Notification message',
                    'priority': 'Notification priority',
                    'tags': 'Notification tags'
                }
            },
            'sms': {
                'name': 'SMS',
                'description': 'Send SMS message (requires SMS service configuration)',
                'config_schema': {
                    'to': 'Phone number(s)',
                    'message': 'SMS message template'
                }
            },
            'create_ticket': {
                'name': 'Create Ticket',
                'description': 'Create ticket in external system (requires integration)',
                'config_schema': {
                    'system': 'Ticketing system (jira, servicenow, etc.)',
                    'project': 'Project/queue identifier',
                    'title': 'Ticket title template',
                    'description': 'Ticket description template',
                    'priority': 'Ticket priority'
                }
            },
            'run_script': {
                'name': 'Run Script',
                'description': 'Execute custom script or command',
                'config_schema': {
                    'command': 'Command to execute',
                    'args': 'Command arguments',
                    'timeout': 'Execution timeout in seconds',
                    'working_directory': 'Working directory for execution'
                }
            }
        }
        
        return jsonify(action_types)
        
    except Exception as e:
        logger.error(f"Error getting action types: {e}")
        return jsonify({'error': str(e)}), 500

@escalation_bp.route('/rules/templates', methods=['GET'])
def get_rule_templates():
    """Get common escalation rule templates"""
    try:
        templates = [
            {
                'name': 'Basic Notification Failure Escalation',
                'description': 'Escalate when notifications fail repeatedly',
                'template': {
                    'trigger_type': 'notification_failure',
                    'trigger_conditions': {
                        'failure_count': {'greater_than': 2}
                    },
                    'delay_minutes': 5,
                    'max_escalations': 3,
                    'escalation_interval_minutes': 30,
                    'escalation_actions': [
                        {
                            'action_type': 'email',
                            'config': {
                                'to': ['admin@company.com'],
                                'subject': 'Notification Delivery Failure - {{notification_type}}',
                                'body': 'Multiple notification delivery failures detected. Details: {{context}}'
                            }
                        }
                    ]
                }
            },
            {
                'name': 'Critical Alert Escalation',
                'description': 'Escalate unresolved critical alerts',
                'template': {
                    'trigger_type': 'alert_unresolved',
                    'trigger_conditions': {
                        'severity': 'critical',
                        'duration_minutes': {'greater_than': 15}
                    },
                    'applies_to_severity_levels': ['critical'],
                    'delay_minutes': 0,
                    'max_escalations': 5,
                    'escalation_interval_minutes': 15,
                    'escalation_actions': [
                        {
                            'action_type': 'push_notification',
                            'config': {
                                'title': 'CRITICAL ALERT ESCALATION',
                                'message': 'Critical alert {{alert_id}} on {{device_name}} requires immediate attention',
                                'priority': 'urgent'
                            }
                        },
                        {
                            'action_type': 'email',
                            'config': {
                                'to': ['oncall@company.com'],
                                'subject': 'ESCALATION: Critical Alert {{alert_id}}',
                                'priority': 'high'
                            }
                        }
                    ]
                }
            },
            {
                'name': 'High Notification Failure Rate',
                'description': 'Escalate when notification failure rate is high',
                'template': {
                    'trigger_type': 'high_failure_rate',
                    'trigger_conditions': {
                        'failure_rate': {'greater_than': 20}
                    },
                    'delay_minutes': 10,
                    'max_escalations': 2,
                    'escalation_interval_minutes': 60,
                    'escalation_actions': [
                        {
                            'action_type': 'webhook',
                            'config': {
                                'url': 'https://api.company.com/alerts/notification-service-degraded',
                                'method': 'POST'
                            }
                        }
                    ]
                }
            }
        ]
        
        return jsonify({'templates': templates})
        
    except Exception as e:
        logger.error(f"Error getting rule templates: {e}")
        return jsonify({'error': str(e)}), 500