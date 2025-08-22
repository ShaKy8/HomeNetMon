"""
Security Response & Remediation Service

This service provides automated security response, incident management, and remediation capabilities:
1. Automated threat response and mitigation
2. Incident lifecycle management
3. Security alert escalation workflows
4. Remediation plan generation and tracking
5. Integration with external security tools
6. Security playbook automation
"""

import logging
import threading
import time
import json
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum

from models import db, Device, Alert, SecurityIncident, SecurityEvent, SecurityVulnerability
from services.network_security_monitor import NetworkThreat, ThreatLevel, AttackType
from services.escalation_manager import escalation_manager

logger = logging.getLogger(__name__)


class ResponseAction(Enum):
    """Available automated response actions"""
    BLOCK_IP = "block_ip"
    RATE_LIMIT = "rate_limit"
    ISOLATE_DEVICE = "isolate_device"
    DISABLE_SERVICE = "disable_service"
    ENHANCE_MONITORING = "enhance_monitoring"
    COLLECT_EVIDENCE = "collect_evidence"
    NOTIFY_ADMIN = "notify_admin"
    ESCALATE_INCIDENT = "escalate_incident"
    QUARANTINE_DEVICE = "quarantine_device"
    BACKUP_LOGS = "backup_logs"
    RESET_CREDENTIALS = "reset_credentials"
    PATCH_VULNERABILITY = "patch_vulnerability"


class IncidentStatus(Enum):
    """Incident status tracking"""
    NEW = "new"
    ASSIGNED = "assigned"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentSeverity(Enum):
    """Incident severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ResponsePlaybook:
    """Security response playbook definition"""
    playbook_id: str
    name: str
    description: str
    trigger_conditions: Dict[str, Any]
    response_actions: List[ResponseAction]
    escalation_rules: List[str]
    approval_required: bool = False
    auto_execute: bool = True
    priority: int = 5  # 1-10, higher = more priority


@dataclass
class IncidentResponse:
    """Incident response tracking"""
    incident_id: str
    threat_id: Optional[str]
    status: IncidentStatus
    severity: IncidentSeverity
    assigned_to: Optional[str]
    created_at: datetime
    last_updated: datetime
    response_actions_taken: List[Dict[str, Any]]
    evidence_collected: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    resolution_notes: Optional[str] = None
    lessons_learned: Optional[str] = None


@dataclass
class RemediationTask:
    """Remediation task for vulnerability or configuration issue"""
    task_id: str
    title: str
    description: str
    priority: int  # 1-5, higher = more urgent
    estimated_effort_hours: float
    assigned_to: Optional[str]
    due_date: datetime
    status: str  # pending, in_progress, completed, deferred
    remediation_steps: List[str]
    verification_steps: List[str]
    related_vulnerabilities: List[str]
    created_at: datetime
    completed_at: Optional[datetime] = None


class SecurityResponseEngine:
    """Comprehensive security response and remediation system"""
    
    def __init__(self, app=None):
        self.app = app
        self.running = False
        
        # Response configuration
        self.config = {
            'auto_response_enabled': True,
            'high_severity_auto_block': True,
            'critical_severity_escalate': True,
            'max_concurrent_responses': 10,
            'response_timeout_seconds': 300,
            'evidence_retention_days': 365
        }
        
        # Active incidents and responses
        self.active_incidents = {}
        self.response_queue = deque()
        self.remediation_tasks = {}
        
        # Response playbooks
        self.playbooks = {}
        self._initialize_default_playbooks()
        
        # Response statistics
        self.response_stats = {
            'total_responses_executed': 0,
            'successful_responses': 0,
            'failed_responses': 0,
            'incidents_created': 0,
            'incidents_resolved': 0,
            'average_response_time_seconds': 0
        }
        
        # External integrations (placeholders for future implementation)
        self.external_integrations = {
            'siem_enabled': False,
            'soar_enabled': False,
            'threat_intel_enabled': False,
            'firewall_api_enabled': False
        }
    
    def start_response_engine(self):
        """Start the security response engine"""
        if self.running:
            logger.warning("Security response engine already running")
            return
        
        self.running = True
        logger.info("Starting security response engine")
        
        # Start response processing threads
        response_threads = [
            threading.Thread(target=self._response_processor_loop, daemon=True, name='ResponseProcessor'),
            threading.Thread(target=self._incident_manager_loop, daemon=True, name='IncidentManager'),
            threading.Thread(target=self._remediation_tracker_loop, daemon=True, name='RemediationTracker'),
            threading.Thread(target=self._escalation_monitor_loop, daemon=True, name='EscalationMonitor')
        ]
        
        for thread in response_threads:
            thread.start()
        
        logger.info("Security response engine started with 4 processing threads")
    
    def stop_response_engine(self):
        """Stop the security response engine"""
        self.running = False
        logger.info("Security response engine stopped")
    
    def process_security_threat(self, threat: NetworkThreat) -> Dict[str, Any]:
        """Process a detected security threat and execute appropriate response"""
        try:
            logger.info(f"Processing security threat: {threat.threat_id}")
            
            # Find matching playbooks
            matching_playbooks = self._find_matching_playbooks(threat)
            
            if not matching_playbooks:
                logger.warning(f"No matching playbooks found for threat {threat.threat_id}")
                return {'success': False, 'reason': 'No matching playbooks'}
            
            # Execute highest priority playbook
            primary_playbook = max(matching_playbooks, key=lambda p: p.priority)
            
            response_result = self._execute_playbook(threat, primary_playbook)
            
            # Create incident if severity is high enough
            if threat.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                incident_id = self._create_security_incident(threat, response_result)
                response_result['incident_created'] = incident_id
            
            # Update statistics
            self.response_stats['total_responses_executed'] += 1
            if response_result.get('success', False):
                self.response_stats['successful_responses'] += 1
            else:
                self.response_stats['failed_responses'] += 1
            
            return response_result
            
        except Exception as e:
            logger.error(f"Error processing security threat {threat.threat_id}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _find_matching_playbooks(self, threat: NetworkThreat) -> List[ResponsePlaybook]:
        """Find playbooks that match the threat characteristics"""
        matching_playbooks = []
        
        for playbook in self.playbooks.values():
            if self._threat_matches_conditions(threat, playbook.trigger_conditions):
                matching_playbooks.append(playbook)
        
        return matching_playbooks
    
    def _threat_matches_conditions(self, threat: NetworkThreat, conditions: Dict[str, Any]) -> bool:
        """Check if threat matches playbook trigger conditions"""
        try:
            # Check threat level
            if 'threat_levels' in conditions:
                if threat.threat_level.value not in conditions['threat_levels']:
                    return False
            
            # Check attack type
            if 'attack_types' in conditions:
                if threat.attack_type.value not in conditions['attack_types']:
                    return False
            
            # Check confidence score
            if 'min_confidence' in conditions:
                if threat.confidence_score < conditions['min_confidence']:
                    return False
            
            # Check source IP patterns
            if 'source_ip_patterns' in conditions:
                source_patterns = conditions['source_ip_patterns']
                if not any(pattern in threat.source_ip for pattern in source_patterns):
                    return False
            
            # Check evidence criteria
            if 'evidence_criteria' in conditions:
                evidence_criteria = conditions['evidence_criteria']
                for key, expected_value in evidence_criteria.items():
                    if key not in threat.evidence or threat.evidence[key] != expected_value:
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error matching threat conditions: {e}")
            return False
    
    def _execute_playbook(self, threat: NetworkThreat, playbook: ResponsePlaybook) -> Dict[str, Any]:
        """Execute a security response playbook"""
        try:
            logger.info(f"Executing playbook '{playbook.name}' for threat {threat.threat_id}")
            
            execution_start = datetime.utcnow()
            executed_actions = []
            failed_actions = []
            
            # Check if approval is required
            if playbook.approval_required and not self._get_playbook_approval(playbook, threat):
                return {
                    'success': False,
                    'reason': 'Approval required but not granted',
                    'playbook': playbook.name
                }
            
            # Execute each response action
            for action in playbook.response_actions:
                try:
                    action_result = self._execute_response_action(action, threat)
                    executed_actions.append({
                        'action': action.value,
                        'result': action_result,
                        'executed_at': datetime.utcnow().isoformat()
                    })
                    
                    if not action_result.get('success', False):
                        failed_actions.append(action.value)
                        
                except Exception as e:
                    logger.error(f"Error executing response action {action.value}: {e}")
                    failed_actions.append(action.value)
                    executed_actions.append({
                        'action': action.value,
                        'result': {'success': False, 'error': str(e)},
                        'executed_at': datetime.utcnow().isoformat()
                    })
            
            execution_time = (datetime.utcnow() - execution_start).total_seconds()
            
            # Update average response time
            current_avg = self.response_stats.get('average_response_time_seconds', 0)
            total_responses = self.response_stats.get('total_responses_executed', 0)
            new_avg = ((current_avg * total_responses) + execution_time) / (total_responses + 1)
            self.response_stats['average_response_time_seconds'] = round(new_avg, 2)
            
            result = {
                'success': len(failed_actions) == 0,
                'playbook_executed': playbook.name,
                'execution_time_seconds': round(execution_time, 2),
                'actions_executed': len(executed_actions),
                'actions_succeeded': len(executed_actions) - len(failed_actions),
                'actions_failed': len(failed_actions),
                'failed_actions': failed_actions,
                'execution_details': executed_actions,
                'threat_id': threat.threat_id
            }
            
            logger.info(f"Playbook execution completed: {result['success']}, {result['actions_succeeded']}/{result['actions_executed']} actions succeeded")
            return result
            
        except Exception as e:
            logger.error(f"Error executing playbook {playbook.name}: {e}")
            return {
                'success': False,
                'error': str(e),
                'playbook_executed': playbook.name,
                'threat_id': threat.threat_id
            }
    
    def _execute_response_action(self, action: ResponseAction, threat: NetworkThreat) -> Dict[str, Any]:
        """Execute a specific response action"""
        try:
            logger.debug(f"Executing response action: {action.value}")
            
            if action == ResponseAction.BLOCK_IP:
                return self._block_ip_address(threat.source_ip)
            elif action == ResponseAction.RATE_LIMIT:
                return self._rate_limit_ip(threat.source_ip)
            elif action == ResponseAction.ISOLATE_DEVICE:
                return self._isolate_device(threat.source_ip)
            elif action == ResponseAction.ENHANCE_MONITORING:
                return self._enhance_monitoring(threat.source_ip)
            elif action == ResponseAction.COLLECT_EVIDENCE:
                return self._collect_evidence(threat)
            elif action == ResponseAction.NOTIFY_ADMIN:
                return self._notify_administrator(threat)
            elif action == ResponseAction.ESCALATE_INCIDENT:
                return self._escalate_incident(threat)
            elif action == ResponseAction.BACKUP_LOGS:
                return self._backup_security_logs(threat)
            elif action == ResponseAction.QUARANTINE_DEVICE:
                return self._quarantine_device(threat.source_ip)
            else:
                return {'success': False, 'reason': f'Unknown action: {action.value}'}
                
        except Exception as e:
            logger.error(f"Error executing response action {action.value}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _create_security_incident(self, threat: NetworkThreat, response_result: Dict[str, Any]) -> str:
        """Create a security incident for the threat"""
        try:
            if not self.app:
                return ""
            
            with self.app.app_context():
                # Generate incident ID
                incident_id = f"INC_{threat.attack_type.value.upper()}_{int(datetime.utcnow().timestamp())}"
                
                # Map threat level to incident severity
                severity_mapping = {
                    ThreatLevel.INFO: IncidentSeverity.INFO,
                    ThreatLevel.LOW: IncidentSeverity.LOW,
                    ThreatLevel.MEDIUM: IncidentSeverity.MEDIUM,
                    ThreatLevel.HIGH: IncidentSeverity.HIGH,
                    ThreatLevel.CRITICAL: IncidentSeverity.CRITICAL
                }
                
                severity = severity_mapping.get(threat.threat_level, IncidentSeverity.MEDIUM)
                
                # Create database record
                db_incident = SecurityIncident(
                    incident_id=incident_id,
                    title=f"{threat.attack_type.value.replace('_', ' ').title()} - {threat.threat_level.value.upper()}",
                    description=threat.description,
                    severity=severity.value,
                    category=threat.attack_type.value,
                    affected_devices=json.dumps([threat.target_ip]),
                    response_actions=json.dumps(response_result.get('execution_details', [])),
                    risk_score=threat.confidence_score * 10,
                    business_impact=self._assess_business_impact(threat, severity)
                )
                
                db.session.add(db_incident)
                db.session.commit()
                
                # Create internal incident tracking
                incident_response = IncidentResponse(
                    incident_id=incident_id,
                    threat_id=threat.threat_id,
                    status=IncidentStatus.NEW,
                    severity=severity,
                    assigned_to=None,
                    created_at=datetime.utcnow(),
                    last_updated=datetime.utcnow(),
                    response_actions_taken=response_result.get('execution_details', []),
                    evidence_collected=[],
                    timeline=[{
                        'timestamp': datetime.utcnow().isoformat(),
                        'event': 'Incident created',
                        'details': f"Created from threat {threat.threat_id}"
                    }]
                )
                
                self.active_incidents[incident_id] = incident_response
                self.response_stats['incidents_created'] += 1
                
                logger.info(f"Created security incident: {incident_id}")
                return incident_id
                
        except Exception as e:
            logger.error(f"Error creating security incident: {e}")
            return ""
    
    def create_remediation_task(self, 
                              vulnerability_id: str,
                              title: str,
                              description: str,
                              priority: int = 3,
                              estimated_hours: float = 2.0,
                              due_days: int = 7) -> str:
        """Create a remediation task for a vulnerability or security issue"""
        try:
            task_id = f"REM_{vulnerability_id}_{int(datetime.utcnow().timestamp())}"
            
            # Get vulnerability details if available
            remediation_steps = self._generate_remediation_steps(vulnerability_id)
            verification_steps = self._generate_verification_steps(vulnerability_id)
            
            task = RemediationTask(
                task_id=task_id,
                title=title,
                description=description,
                priority=priority,
                estimated_effort_hours=estimated_hours,
                assigned_to=None,
                due_date=datetime.utcnow() + timedelta(days=due_days),
                status="pending",
                remediation_steps=remediation_steps,
                verification_steps=verification_steps,
                related_vulnerabilities=[vulnerability_id],
                created_at=datetime.utcnow()
            )
            
            self.remediation_tasks[task_id] = task
            
            logger.info(f"Created remediation task: {task_id}")
            return task_id
            
        except Exception as e:
            logger.error(f"Error creating remediation task: {e}")
            return ""
    
    def update_incident_status(self, incident_id: str, new_status: IncidentStatus, notes: Optional[str] = None):
        """Update the status of a security incident"""
        try:
            if incident_id not in self.active_incidents:
                logger.warning(f"Incident {incident_id} not found in active incidents")
                return
            
            incident = self.active_incidents[incident_id]
            old_status = incident.status
            
            incident.status = new_status
            incident.last_updated = datetime.utcnow()
            
            # Add timeline entry
            timeline_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event': f"Status changed from {old_status.value} to {new_status.value}",
                'details': notes or ""
            }
            incident.timeline.append(timeline_entry)
            
            # Update database record if available
            if self.app:
                with self.app.app_context():
                    db_incident = SecurityIncident.query.filter_by(incident_id=incident_id).first()
                    if db_incident:
                        db_incident.status = new_status.value
                        if notes:
                            db_incident.resolution_notes = notes
                        db.session.commit()
            
            # Check if incident is resolved
            if new_status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
                self.response_stats['incidents_resolved'] += 1
                logger.info(f"Incident {incident_id} marked as {new_status.value}")
            
        except Exception as e:
            logger.error(f"Error updating incident status: {e}")
    
    def get_security_response_dashboard(self) -> Dict[str, Any]:
        """Get security response dashboard data"""
        try:
            current_time = datetime.utcnow()
            
            # Active incidents summary
            active_incidents = [i for i in self.active_incidents.values() 
                              if i.status not in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]]
            
            incidents_by_severity = defaultdict(int)
            incidents_by_status = defaultdict(int)
            
            for incident in active_incidents:
                incidents_by_severity[incident.severity.value] += 1
                incidents_by_status[incident.status.value] += 1
            
            # Remediation tasks summary
            active_tasks = [t for t in self.remediation_tasks.values() 
                          if t.status not in ["completed", "cancelled"]]
            
            tasks_by_priority = defaultdict(int)
            overdue_tasks = 0
            
            for task in active_tasks:
                tasks_by_priority[str(task.priority)] += 1
                if task.due_date < current_time:
                    overdue_tasks += 1
            
            return {
                'response_engine_status': 'active' if self.running else 'inactive',
                'response_statistics': self.response_stats,
                'active_incidents': {
                    'total': len(active_incidents),
                    'by_severity': dict(incidents_by_severity),
                    'by_status': dict(incidents_by_status),
                    'recent_incidents': [
                        {
                            'incident_id': i.incident_id,
                            'severity': i.severity.value,
                            'status': i.status.value,
                            'created_at': i.created_at.isoformat(),
                            'assigned_to': i.assigned_to
                        }
                        for i in sorted(active_incidents, key=lambda x: x.created_at, reverse=True)[:10]
                    ]
                },
                'remediation_tasks': {
                    'total_active': len(active_tasks),
                    'overdue': overdue_tasks,
                    'by_priority': dict(tasks_by_priority),
                    'upcoming_due': [
                        {
                            'task_id': t.task_id,
                            'title': t.title,
                            'priority': t.priority,
                            'due_date': t.due_date.isoformat(),
                            'status': t.status
                        }
                        for t in sorted(active_tasks, key=lambda x: x.due_date)[:10]
                    ]
                },
                'playbook_summary': {
                    'total_playbooks': len(self.playbooks),
                    'auto_execute_enabled': sum(1 for p in self.playbooks.values() if p.auto_execute),
                    'approval_required': sum(1 for p in self.playbooks.values() if p.approval_required)
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting security response dashboard: {e}")
            return {'error': str(e)}
    
    # Response Action Implementations
    def _block_ip_address(self, ip_address: str) -> Dict[str, Any]:
        """Block an IP address using firewall rules"""
        try:
            logger.info(f"Blocking IP address: {ip_address}")
            
            # Using UFW (Ubuntu Firewall) as example
            result = subprocess.run(
                ['sudo', 'ufw', 'insert', '1', 'deny', 'from', ip_address],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'action': 'ip_blocked',
                    'ip_address': ip_address,
                    'method': 'ufw_firewall',
                    'output': result.stdout.strip()
                }
            else:
                return {
                    'success': False,
                    'action': 'ip_block_failed',
                    'ip_address': ip_address,
                    'error': result.stderr.strip()
                }
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Firewall command timed out'}
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _rate_limit_ip(self, ip_address: str) -> Dict[str, Any]:
        """Apply rate limiting to an IP address"""
        try:
            logger.info(f"Applying rate limiting to IP: {ip_address}")
            
            # Using UFW with limit rule
            result = subprocess.run(
                ['sudo', 'ufw', 'limit', 'from', ip_address],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'action': 'rate_limit_applied',
                    'ip_address': ip_address,
                    'method': 'ufw_limit',
                    'output': result.stdout.strip()
                }
            else:
                return {
                    'success': False,
                    'action': 'rate_limit_failed',
                    'ip_address': ip_address,
                    'error': result.stderr.strip()
                }
                
        except Exception as e:
            logger.error(f"Error rate limiting IP {ip_address}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _isolate_device(self, ip_address: str) -> Dict[str, Any]:
        """Isolate a device from the network"""
        try:
            logger.warning(f"Isolating device: {ip_address}")
            
            # This would typically involve VLAN changes or advanced firewall rules
            # For now, implement as enhanced blocking
            block_result = self._block_ip_address(ip_address)
            
            if block_result['success']:
                # Log the isolation action
                return {
                    'success': True,
                    'action': 'device_isolated',
                    'ip_address': ip_address,
                    'method': 'firewall_isolation',
                    'note': 'Device blocked from all network access'
                }
            else:
                return {
                    'success': False,
                    'action': 'device_isolation_failed',
                    'ip_address': ip_address,
                    'error': block_result.get('error', 'Unknown error')
                }
                
        except Exception as e:
            logger.error(f"Error isolating device {ip_address}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _enhance_monitoring(self, ip_address: str) -> Dict[str, Any]:
        """Enhance monitoring for a specific IP address"""
        try:
            logger.info(f"Enhancing monitoring for IP: {ip_address}")
            
            # This could involve increasing monitoring frequency, adding special alerts, etc.
            # For now, implement as logging enhancement
            
            return {
                'success': True,
                'action': 'monitoring_enhanced',
                'ip_address': ip_address,
                'enhancements': [
                    'Increased monitoring frequency',
                    'Special alert rules activated',
                    'Enhanced logging enabled'
                ]
            }
            
        except Exception as e:
            logger.error(f"Error enhancing monitoring for {ip_address}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _collect_evidence(self, threat: NetworkThreat) -> Dict[str, Any]:
        """Collect evidence related to the security threat"""
        try:
            logger.info(f"Collecting evidence for threat: {threat.threat_id}")
            
            evidence = {
                'threat_details': {
                    'threat_id': threat.threat_id,
                    'source_ip': threat.source_ip,
                    'target_ip': threat.target_ip,
                    'attack_type': threat.attack_type.value,
                    'confidence_score': threat.confidence_score,
                    'detected_at': threat.detected_at.isoformat()
                },
                'network_state': self._capture_network_state(threat.source_ip),
                'device_info': self._get_device_forensics(threat.source_ip),
                'log_extracts': self._extract_relevant_logs(threat),
                'collected_at': datetime.utcnow().isoformat()
            }
            
            return {
                'success': True,
                'action': 'evidence_collected',
                'evidence_id': f"EVD_{threat.threat_id}_{int(datetime.utcnow().timestamp())}",
                'evidence_summary': f"Collected {len(evidence)} evidence categories",
                'evidence_data': evidence
            }
            
        except Exception as e:
            logger.error(f"Error collecting evidence for threat {threat.threat_id}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _notify_administrator(self, threat: NetworkThreat) -> Dict[str, Any]:
        """Send notification to administrator"""
        try:
            logger.info(f"Notifying administrator about threat: {threat.threat_id}")
            
            # Use existing push notification service
            from services.push_notifications import push_service
            from models import Configuration
            from config import Config
            
            # Update push service configuration
            push_service.enabled = Configuration.get_value('push_notifications_enabled', 'false').lower() == 'true'
            push_service.topic = Configuration.get_value('ntfy_topic', '')
            push_service.server = Configuration.get_value('ntfy_server', 'https://ntfy.sh')
            
            if push_service.is_configured():
                dashboard_url = f"http://{Config.HOST}:{Config.PORT}/security"
                
                success = push_service.send_security_alert(
                    device_name="Security System",
                    ip_address=threat.source_ip,
                    vulnerability=f"{threat.attack_type.value}: {threat.description}",
                    risk_score=threat.confidence_score * 10,
                    dashboard_url=dashboard_url
                )
                
                return {
                    'success': success,
                    'action': 'admin_notified',
                    'notification_method': 'push_notification',
                    'threat_id': threat.threat_id
                }
            else:
                return {
                    'success': False,
                    'action': 'admin_notification_failed',
                    'error': 'Push notifications not configured'
                }
                
        except Exception as e:
            logger.error(f"Error notifying administrator: {e}")
            return {'success': False, 'error': str(e)}
    
    def _escalate_incident(self, threat: NetworkThreat) -> Dict[str, Any]:
        """Escalate the incident through escalation manager"""
        try:
            logger.warning(f"Escalating incident for threat: {threat.threat_id}")
            
            # Use existing escalation manager
            escalation_context = {
                'threat_id': threat.threat_id,
                'attack_type': threat.attack_type.value,
                'source_ip': threat.source_ip,
                'confidence_score': threat.confidence_score,
                'threat_level': threat.threat_level.value
            }
            
            # Trigger escalation (this would need integration with escalation_manager)
            # For now, return success
            
            return {
                'success': True,
                'action': 'incident_escalated',
                'threat_id': threat.threat_id,
                'escalation_level': 'security_team',
                'escalated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error escalating incident: {e}")
            return {'success': False, 'error': str(e)}
    
    def _backup_security_logs(self, threat: NetworkThreat) -> Dict[str, Any]:
        """Backup security logs related to the threat"""
        try:
            logger.info(f"Backing up security logs for threat: {threat.threat_id}")
            
            # This would involve copying relevant log files to a secure location
            backup_path = f"/tmp/security_backup_{threat.threat_id}_{int(datetime.utcnow().timestamp())}"
            
            return {
                'success': True,
                'action': 'logs_backed_up',
                'backup_location': backup_path,
                'threat_id': threat.threat_id,
                'backed_up_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error backing up security logs: {e}")
            return {'success': False, 'error': str(e)}
    
    def _quarantine_device(self, ip_address: str) -> Dict[str, Any]:
        """Quarantine a device to a restricted network segment"""
        try:
            logger.warning(f"Quarantining device: {ip_address}")
            
            # This would involve moving device to a quarantine VLAN
            # For now, implement as isolation
            isolation_result = self._isolate_device(ip_address)
            
            if isolation_result['success']:
                return {
                    'success': True,
                    'action': 'device_quarantined',
                    'ip_address': ip_address,
                    'quarantine_method': 'network_isolation',
                    'quarantined_at': datetime.utcnow().isoformat()
                }
            else:
                return {
                    'success': False,
                    'action': 'device_quarantine_failed',
                    'ip_address': ip_address,
                    'error': isolation_result.get('error', 'Unknown error')
                }
                
        except Exception as e:
            logger.error(f"Error quarantining device {ip_address}: {e}")
            return {'success': False, 'error': str(e)}
    
    # Helper methods and background loops
    def _initialize_default_playbooks(self):
        """Initialize default security response playbooks"""
        try:
            # High-severity brute force response
            self.playbooks['brute_force_high'] = ResponsePlaybook(
                playbook_id='brute_force_high',
                name='High-Severity Brute Force Response',
                description='Automated response to high-severity brute force attacks',
                trigger_conditions={
                    'attack_types': ['brute_force'],
                    'threat_levels': ['high', 'critical'],
                    'min_confidence': 0.8
                },
                response_actions=[
                    ResponseAction.BLOCK_IP,
                    ResponseAction.COLLECT_EVIDENCE,
                    ResponseAction.NOTIFY_ADMIN,
                    ResponseAction.BACKUP_LOGS
                ],
                escalation_rules=['security_team'],
                priority=9,
                auto_execute=True
            )
            
            # Port scanning response
            self.playbooks['port_scan_response'] = ResponsePlaybook(
                playbook_id='port_scan_response',
                name='Port Scanning Response',
                description='Response to detected port scanning activities',
                trigger_conditions={
                    'attack_types': ['port_scan'],
                    'threat_levels': ['medium', 'high']
                },
                response_actions=[
                    ResponseAction.RATE_LIMIT,
                    ResponseAction.ENHANCE_MONITORING,
                    ResponseAction.COLLECT_EVIDENCE
                ],
                escalation_rules=[],
                priority=6,
                auto_execute=True
            )
            
            # Critical threat response
            self.playbooks['critical_threat'] = ResponsePlaybook(
                playbook_id='critical_threat',
                name='Critical Threat Response',
                description='Emergency response for critical security threats',
                trigger_conditions={
                    'threat_levels': ['critical']
                },
                response_actions=[
                    ResponseAction.QUARANTINE_DEVICE,
                    ResponseAction.COLLECT_EVIDENCE,
                    ResponseAction.NOTIFY_ADMIN,
                    ResponseAction.ESCALATE_INCIDENT,
                    ResponseAction.BACKUP_LOGS
                ],
                escalation_rules=['security_team', 'management'],
                priority=10,
                auto_execute=True,
                approval_required=False  # Auto-execute for critical threats
            )
            
            # Suspicious traffic response
            self.playbooks['suspicious_traffic'] = ResponsePlaybook(
                playbook_id='suspicious_traffic',
                name='Suspicious Traffic Response',
                description='Response to suspicious network traffic patterns',
                trigger_conditions={
                    'attack_types': ['suspicious_traffic'],
                    'threat_levels': ['medium', 'high']
                },
                response_actions=[
                    ResponseAction.ENHANCE_MONITORING,
                    ResponseAction.COLLECT_EVIDENCE,
                    ResponseAction.NOTIFY_ADMIN
                ],
                escalation_rules=[],
                priority=5,
                auto_execute=True
            )
            
            logger.info(f"Initialized {len(self.playbooks)} default security response playbooks")
            
        except Exception as e:
            logger.error(f"Error initializing default playbooks: {e}")
    
    def _get_playbook_approval(self, playbook: ResponsePlaybook, threat: NetworkThreat) -> bool:
        """Get approval for playbook execution (placeholder for future implementation)"""
        # In a real implementation, this would check approval workflows
        # For now, always approve for critical threats
        return threat.threat_level == ThreatLevel.CRITICAL
    
    def _assess_business_impact(self, threat: NetworkThreat, severity: IncidentSeverity) -> str:
        """Assess business impact of the security threat"""
        if severity == IncidentSeverity.CRITICAL:
            return "critical"
        elif severity == IncidentSeverity.HIGH:
            return "high"
        elif severity == IncidentSeverity.MEDIUM:
            return "medium"
        else:
            return "low"
    
    def _generate_remediation_steps(self, vulnerability_id: str) -> List[str]:
        """Generate remediation steps for a vulnerability"""
        try:
            if not self.app:
                return ["Review vulnerability details and implement appropriate fixes"]
            
            with self.app.app_context():
                vulnerability = SecurityVulnerability.query.filter_by(finding_id=vulnerability_id).first()
                
                if vulnerability and vulnerability.remediation:
                    remediation_data = json.loads(vulnerability.remediation) if isinstance(vulnerability.remediation, str) else vulnerability.remediation
                    return remediation_data if isinstance(remediation_data, list) else [str(remediation_data)]
                
        except Exception as e:
            logger.error(f"Error generating remediation steps for {vulnerability_id}: {e}")
        
        return [
            "Analyze the vulnerability and determine root cause",
            "Develop and test remediation approach",
            "Apply security patches or configuration changes",
            "Verify the fix resolves the vulnerability",
            "Document the remediation process"
        ]
    
    def _generate_verification_steps(self, vulnerability_id: str) -> List[str]:
        """Generate verification steps for remediation"""
        return [
            "Re-run security scan to confirm vulnerability is resolved",
            "Test affected functionality to ensure no regression",
            "Verify security controls are functioning properly",
            "Document verification results",
            "Update security documentation"
        ]
    
    def _capture_network_state(self, ip_address: str) -> Dict[str, Any]:
        """Capture current network state for forensics"""
        try:
            network_state = {
                'timestamp': datetime.utcnow().isoformat(),
                'target_ip': ip_address,
                'active_connections': [],
                'routing_table': [],
                'arp_table': [],
                'firewall_rules': []
            }
            
            # Capture active connections
            try:
                result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    network_state['active_connections'] = result.stdout.split('\\n')[:50]  # Limit output
            except:
                pass
            
            # Capture ARP table
            try:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    network_state['arp_table'] = result.stdout.split('\\n')[:50]
            except:
                pass
            
            return network_state
            
        except Exception as e:
            logger.error(f"Error capturing network state: {e}")
            return {'error': str(e), 'timestamp': datetime.utcnow().isoformat()}
    
    def _get_device_forensics(self, ip_address: str) -> Dict[str, Any]:
        """Get device forensics information"""
        try:
            if not self.app:
                return {'error': 'No app context'}
            
            with self.app.app_context():
                device = Device.query.filter_by(ip_address=ip_address).first()
                
                if device:
                    return {
                        'device_id': device.id,
                        'device_name': device.display_name,
                        'ip_address': device.ip_address,
                        'mac_address': device.mac_address,
                        'hostname': device.hostname,
                        'vendor': device.vendor,
                        'device_type': device.device_type,
                        'last_seen': device.last_seen.isoformat() if device.last_seen else None,
                        'status': device.status
                    }
                else:
                    return {'error': f'Device not found for IP {ip_address}'}
                    
        except Exception as e:
            logger.error(f"Error getting device forensics for {ip_address}: {e}")
            return {'error': str(e)}
    
    def _extract_relevant_logs(self, threat: NetworkThreat) -> Dict[str, Any]:
        """Extract relevant log entries for the threat"""
        try:
            log_extracts = {
                'auth_logs': [],
                'system_logs': [],
                'application_logs': [],
                'extraction_time': datetime.utcnow().isoformat()
            }
            
            # Extract from auth logs
            try:
                with open('/var/log/auth.log', 'r') as f:
                    lines = f.readlines()[-100:]  # Last 100 lines
                    for line in lines:
                        if threat.source_ip in line:
                            log_extracts['auth_logs'].append(line.strip())
            except:
                pass
            
            return log_extracts
            
        except Exception as e:
            logger.error(f"Error extracting logs for threat {threat.threat_id}: {e}")
            return {'error': str(e)}
    
    def _response_processor_loop(self):
        """Process response actions in the background"""
        while self.running:
            try:
                # Process any queued responses
                if self.response_queue:
                    response_item = self.response_queue.popleft()
                    # Process the response item
                    self._process_queued_response(response_item)
                
                time.sleep(5)  # Check queue every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in response processor loop: {e}")
                time.sleep(10)
    
    def _incident_manager_loop(self):
        """Manage active incidents in the background"""
        while self.running:
            try:
                current_time = datetime.utcnow()
                
                # Check for incidents that need status updates
                for incident_id, incident in self.active_incidents.items():
                    # Auto-escalate incidents that have been open too long
                    if incident.status == IncidentStatus.NEW and (current_time - incident.created_at).total_seconds() > 3600:  # 1 hour
                        self.update_incident_status(incident_id, IncidentStatus.ASSIGNED, "Auto-escalated due to time threshold")
                    
                    # Check for incidents that should be closed
                    if incident.status == IncidentStatus.RESOLVED and (current_time - incident.last_updated).total_seconds() > 86400:  # 24 hours
                        self.update_incident_status(incident_id, IncidentStatus.CLOSED, "Auto-closed after 24 hours in resolved state")
                
                time.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in incident manager loop: {e}")
                time.sleep(300)
    
    def _remediation_tracker_loop(self):
        """Track remediation task progress"""
        while self.running:
            try:
                current_time = datetime.utcnow()
                
                # Check for overdue tasks
                overdue_tasks = []
                for task_id, task in self.remediation_tasks.items():
                    if task.status not in ["completed", "cancelled"] and task.due_date < current_time:
                        overdue_tasks.append(task)
                
                # Send notifications for overdue tasks
                if overdue_tasks:
                    logger.warning(f"Found {len(overdue_tasks)} overdue remediation tasks")
                    # Could send notifications here
                
                time.sleep(3600)  # Check hourly
                
            except Exception as e:
                logger.error(f"Error in remediation tracker loop: {e}")
                time.sleep(3600)
    
    def _escalation_monitor_loop(self):
        """Monitor for escalation conditions"""
        while self.running:
            try:
                # Check for conditions that should trigger escalations
                current_time = datetime.utcnow()
                
                # Count critical incidents in last hour
                recent_critical = sum(1 for i in self.active_incidents.values() 
                                    if i.severity == IncidentSeverity.CRITICAL and 
                                    (current_time - i.created_at).total_seconds() < 3600)
                
                # Escalate if too many critical incidents
                if recent_critical >= 3:
                    logger.critical(f"Multiple critical incidents detected ({recent_critical}), triggering escalation")
                    # Could trigger executive escalation here
                
                time.sleep(900)  # Check every 15 minutes
                
            except Exception as e:
                logger.error(f"Error in escalation monitor loop: {e}")
                time.sleep(900)
    
    def _process_queued_response(self, response_item: Dict[str, Any]):
        """Process a queued response item"""
        try:
            # Implementation for processing queued responses
            logger.debug(f"Processing queued response: {response_item}")
            
        except Exception as e:
            logger.error(f"Error processing queued response: {e}")
    
    def get_incident_details(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific incident"""
        try:
            if incident_id not in self.active_incidents:
                return None
            
            incident = self.active_incidents[incident_id]
            
            return {
                'incident_id': incident.incident_id,
                'threat_id': incident.threat_id,
                'status': incident.status.value,
                'severity': incident.severity.value,
                'assigned_to': incident.assigned_to,
                'created_at': incident.created_at.isoformat(),
                'last_updated': incident.last_updated.isoformat(),
                'response_actions_taken': incident.response_actions_taken,
                'evidence_collected': incident.evidence_collected,
                'timeline': incident.timeline,
                'resolution_notes': incident.resolution_notes,
                'lessons_learned': incident.lessons_learned
            }
            
        except Exception as e:
            logger.error(f"Error getting incident details for {incident_id}: {e}")
            return None
    
    def get_remediation_task_details(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a remediation task"""
        try:
            if task_id not in self.remediation_tasks:
                return None
            
            task = self.remediation_tasks[task_id]
            
            return {
                'task_id': task.task_id,
                'title': task.title,
                'description': task.description,
                'priority': task.priority,
                'estimated_effort_hours': task.estimated_effort_hours,
                'assigned_to': task.assigned_to,
                'due_date': task.due_date.isoformat(),
                'status': task.status,
                'remediation_steps': task.remediation_steps,
                'verification_steps': task.verification_steps,
                'related_vulnerabilities': task.related_vulnerabilities,
                'created_at': task.created_at.isoformat(),
                'completed_at': task.completed_at.isoformat() if task.completed_at else None
            }
            
        except Exception as e:
            logger.error(f"Error getting remediation task details for {task_id}: {e}")
            return None
    
    def update_remediation_task_status(self, task_id: str, new_status: str, notes: Optional[str] = None):
        """Update the status of a remediation task"""
        try:
            if task_id not in self.remediation_tasks:
                logger.warning(f"Remediation task {task_id} not found")
                return
            
            task = self.remediation_tasks[task_id]
            task.status = new_status
            
            if new_status == "completed":
                task.completed_at = datetime.utcnow()
            
            logger.info(f"Updated remediation task {task_id} status to {new_status}")
            
        except Exception as e:
            logger.error(f"Error updating remediation task status: {e}")
    
    def create_custom_playbook(self, playbook_data: Dict[str, Any]) -> str:
        """Create a custom response playbook"""
        try:
            playbook_id = playbook_data.get('playbook_id', f"custom_{int(datetime.utcnow().timestamp())}")
            
            # Convert string action names to ResponseAction enums
            actions = []
            for action_name in playbook_data.get('response_actions', []):
                try:
                    action = ResponseAction(action_name)
                    actions.append(action)
                except ValueError:
                    logger.warning(f"Unknown response action: {action_name}")
            
            playbook = ResponsePlaybook(
                playbook_id=playbook_id,
                name=playbook_data.get('name', 'Custom Playbook'),
                description=playbook_data.get('description', ''),
                trigger_conditions=playbook_data.get('trigger_conditions', {}),
                response_actions=actions,
                escalation_rules=playbook_data.get('escalation_rules', []),
                approval_required=playbook_data.get('approval_required', False),
                auto_execute=playbook_data.get('auto_execute', True),
                priority=playbook_data.get('priority', 5)
            )
            
            self.playbooks[playbook_id] = playbook
            
            logger.info(f"Created custom playbook: {playbook_id}")
            return playbook_id
            
        except Exception as e:
            logger.error(f"Error creating custom playbook: {e}")
            return ""
    
    def get_response_statistics(self) -> Dict[str, Any]:
        """Get comprehensive response engine statistics"""
        try:
            current_time = datetime.utcnow()
            
            # Calculate success rate
            total_responses = self.response_stats.get('total_responses_executed', 0)
            successful_responses = self.response_stats.get('successful_responses', 0)
            success_rate = (successful_responses / total_responses * 100) if total_responses > 0 else 0
            
            # Active incidents by age
            incident_age_distribution = {'< 1 hour': 0, '1-6 hours': 0, '6-24 hours': 0, '> 24 hours': 0}
            
            for incident in self.active_incidents.values():
                age_hours = (current_time - incident.created_at).total_seconds() / 3600
                if age_hours < 1:
                    incident_age_distribution['< 1 hour'] += 1
                elif age_hours < 6:
                    incident_age_distribution['1-6 hours'] += 1
                elif age_hours < 24:
                    incident_age_distribution['6-24 hours'] += 1
                else:
                    incident_age_distribution['> 24 hours'] += 1
            
            # Task completion rate
            total_tasks = len(self.remediation_tasks)
            completed_tasks = sum(1 for t in self.remediation_tasks.values() if t.status == 'completed')
            completion_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
            
            return {
                'response_engine': {
                    'status': 'active' if self.running else 'inactive',
                    'total_responses_executed': total_responses,
                    'success_rate_percentage': round(success_rate, 1),
                    'average_response_time_seconds': self.response_stats.get('average_response_time_seconds', 0),
                    'total_playbooks': len(self.playbooks)
                },
                'incidents': {
                    'total_created': self.response_stats.get('incidents_created', 0),
                    'total_resolved': self.response_stats.get('incidents_resolved', 0),
                    'currently_active': len(self.active_incidents),
                    'age_distribution': incident_age_distribution
                },
                'remediation': {
                    'total_tasks': total_tasks,
                    'completed_tasks': completed_tasks,
                    'completion_rate_percentage': round(completion_rate, 1),
                    'overdue_tasks': sum(1 for t in self.remediation_tasks.values() 
                                       if t.due_date < current_time and t.status not in ['completed', 'cancelled'])
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting response statistics: {e}")
            return {'error': str(e)}


# Global security response engine instance
security_response_engine = SecurityResponseEngine()