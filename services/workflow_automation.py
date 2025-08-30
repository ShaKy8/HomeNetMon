"""
Intelligent Workflow Automation Engine

This module provides comprehensive workflow automation capabilities:

1. Event-driven automation with intelligent triggers
2. Conditional logic and decision trees for complex workflows
3. Automated remediation and response workflows
4. Multi-step workflow orchestration
5. Integration with external systems for automated actions
6. Workflow templates and customizable automation rules
7. Approval workflows and human-in-the-loop automation
8. Workflow monitoring, logging, and performance analytics
"""

import asyncio
import threading
import time
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict, deque
import uuid
import copy
from concurrent.futures import ThreadPoolExecutor
import traceback

from models import db, Device, Alert, MonitoringData
from services.integration_manager import integration_manager
from services.notification import notification_service

logger = logging.getLogger(__name__)


class WorkflowStatus(Enum):
    """Workflow execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"
    WAITING_APPROVAL = "waiting_approval"


class TriggerType(Enum):
    """Types of workflow triggers"""
    EVENT = "event"                    # Triggered by specific events
    SCHEDULE = "schedule"              # Time-based triggers
    MANUAL = "manual"                  # Manually triggered
    CONDITION = "condition"            # Triggered when conditions are met
    WEBHOOK = "webhook"               # Triggered by external webhooks
    API = "api"                       # Triggered via API call
    CHAIN = "chain"                   # Triggered by another workflow


class ActionType(Enum):
    """Types of workflow actions"""
    NOTIFICATION = "notification"       # Send notifications
    INTEGRATION = "integration"        # Call external system integration
    SCRIPT = "script"                  # Execute script or command
    API_CALL = "api_call"              # Make HTTP API call
    DATABASE = "database"              # Database operations
    CONDITIONAL = "conditional"        # Conditional branching
    LOOP = "loop"                      # Loop/iteration
    WAIT = "wait"                      # Wait/delay action
    APPROVAL = "approval"              # Request human approval
    PARALLEL = "parallel"              # Execute actions in parallel
    CHAIN_WORKFLOW = "chain_workflow"  # Trigger another workflow


class ConditionOperator(Enum):
    """Operators for condition evaluation"""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_EQUAL = "greater_equal"
    LESS_EQUAL = "less_equal"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    REGEX_MATCH = "regex_match"
    IN_LIST = "in_list"
    NOT_IN_LIST = "not_in_list"
    IS_NULL = "is_null"
    IS_NOT_NULL = "is_not_null"


@dataclass
class WorkflowCondition:
    """Condition for workflow logic"""
    field: str
    operator: ConditionOperator
    value: Any
    case_sensitive: bool = True


@dataclass
class WorkflowAction:
    """Individual action within a workflow"""
    action_id: str
    action_type: ActionType
    name: str
    description: str = ""
    
    # Action configuration
    config: Dict[str, Any] = field(default_factory=dict)
    
    # Conditional execution
    conditions: List[WorkflowCondition] = field(default_factory=list)
    condition_logic: str = "AND"  # AND, OR
    
    # Error handling
    on_error: str = "stop"  # stop, continue, retry
    max_retries: int = 3
    retry_delay_seconds: int = 5
    
    # Timeout
    timeout_seconds: int = 300  # 5 minutes default
    
    # Dependencies
    depends_on: List[str] = field(default_factory=list)  # Action IDs this depends on
    
    # Output mapping
    output_mapping: Dict[str, str] = field(default_factory=dict)


@dataclass
class WorkflowTrigger:
    """Trigger configuration for workflows"""
    trigger_id: str
    trigger_type: TriggerType
    name: str
    description: str = ""
    
    # Trigger configuration
    config: Dict[str, Any] = field(default_factory=dict)
    
    # Conditions for trigger activation
    conditions: List[WorkflowCondition] = field(default_factory=list)
    condition_logic: str = "AND"
    
    # Rate limiting
    cooldown_seconds: int = 0
    max_executions_per_hour: int = 0
    
    # Status
    enabled: bool = True
    last_triggered: Optional[datetime] = None


@dataclass
class WorkflowDefinition:
    """Complete workflow definition"""
    workflow_id: str
    name: str
    description: str
    version: str = "1.0"
    
    # Workflow configuration
    triggers: List[WorkflowTrigger] = field(default_factory=list)
    actions: List[WorkflowAction] = field(default_factory=list)
    
    # Workflow metadata
    category: str = "general"
    tags: List[str] = field(default_factory=list)
    created_by: str = "system"
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    # Execution settings
    timeout_minutes: int = 60
    max_concurrent_executions: int = 1
    requires_approval: bool = False
    approval_required_for: List[str] = field(default_factory=list)  # Action IDs requiring approval
    
    # Status
    enabled: bool = True
    
    # Variables and context
    variables: Dict[str, Any] = field(default_factory=dict)
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowExecution:
    """Runtime workflow execution instance"""
    execution_id: str
    workflow_id: str
    status: WorkflowStatus
    
    # Execution context
    triggered_by: str
    trigger_data: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    
    # Timing
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    
    # Progress tracking
    current_action: Optional[str] = None
    completed_actions: List[str] = field(default_factory=list)
    failed_actions: List[str] = field(default_factory=list)
    action_results: Dict[str, Any] = field(default_factory=dict)
    
    # Error handling
    error_message: Optional[str] = None
    error_details: Optional[str] = None
    
    # Approval tracking
    pending_approvals: List[str] = field(default_factory=list)
    approved_actions: List[str] = field(default_factory=list)
    
    # Performance metrics
    total_actions: int = 0
    execution_time_seconds: float = 0.0


@dataclass
class WorkflowStats:
    """Statistics for workflow performance"""
    workflow_id: str
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    average_execution_time: float = 0.0
    last_execution: Optional[datetime] = None
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None


class IntelligentWorkflowEngine:
    """
    Advanced workflow automation engine with intelligent decision-making,
    conditional logic, and comprehensive integration capabilities.
    """
    
    def __init__(self, app=None):
        self.app = app
        self.running = False
        self.execution_thread = None
        self.trigger_thread = None
        
        # Workflow management
        self.workflows: Dict[str, WorkflowDefinition] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self.workflow_stats: Dict[str, WorkflowStats] = {}
        
        # Execution queue and management
        self.execution_queue = deque(maxlen=10000)
        self.running_executions: Dict[str, asyncio.Task] = {}
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # Trigger management
        self.active_triggers: Dict[str, WorkflowTrigger] = {}
        self.trigger_history = deque(maxlen=1000)
        
        # Built-in action handlers
        self.action_handlers: Dict[ActionType, Callable] = {}
        
        # Configuration
        self.config = {
            'max_concurrent_workflows': 10,
            'execution_timeout_minutes': 60,
            'cleanup_completed_hours': 24,
            'stats_retention_days': 30,
            'approval_timeout_hours': 24,
            'trigger_check_interval': 30  # seconds
        }
        
        # Statistics
        self.engine_stats = {
            'total_workflows': 0,
            'active_workflows': 0,
            'total_executions': 0,
            'running_executions': 0,
            'queued_executions': 0,
            'last_execution': None
        }
        
        # Initialize built-in handlers
        self._register_builtin_action_handlers()
        
        # Load built-in workflow templates
        self._load_builtin_workflows()
    
    def start_workflow_engine(self):
        """Start the workflow automation engine"""
        if self.running:
            logger.warning("Workflow engine is already running")
            return
        
        self.running = True
        
        # Start execution thread
        self.execution_thread = threading.Thread(target=self._execution_loop, daemon=True)
        self.execution_thread.start()
        
        # Start trigger monitoring thread
        self.trigger_thread = threading.Thread(target=self._trigger_loop, daemon=True)
        self.trigger_thread.start()
        
        logger.info("Intelligent workflow automation engine started")
    
    def stop_workflow_engine(self):
        """Stop the workflow automation engine"""
        self.running = False
        
        # Cancel running executions
        for execution_id, task in self.running_executions.items():
            task.cancel()
        
        # Wait for threads to stop
        if self.execution_thread and self.execution_thread.is_alive():
            self.execution_thread.join(timeout=30)
        
        if self.trigger_thread and self.trigger_thread.is_alive():
            self.trigger_thread.join(timeout=30)
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        logger.info("Workflow automation engine stopped")
    
    def register_workflow(self, workflow: WorkflowDefinition) -> bool:
        """Register a new workflow definition"""
        try:
            # Validate workflow
            if not self._validate_workflow(workflow):
                logger.error(f"Invalid workflow definition: {workflow.workflow_id}")
                return False
            
            # Register workflow
            self.workflows[workflow.workflow_id] = workflow
            self.workflow_stats[workflow.workflow_id] = WorkflowStats(workflow_id=workflow.workflow_id)
            
            # Register triggers
            for trigger in workflow.triggers:
                if trigger.enabled:
                    self.active_triggers[trigger.trigger_id] = trigger
            
            logger.info(f"Registered workflow {workflow.workflow_id} ({workflow.name})")
            self._update_engine_stats()
            
            return True
            
        except Exception as e:
            logger.error(f"Error registering workflow {workflow.workflow_id}: {e}")
            return False
    
    def unregister_workflow(self, workflow_id: str) -> bool:
        """Unregister a workflow"""
        try:
            if workflow_id not in self.workflows:
                logger.warning(f"Workflow {workflow_id} not found")
                return False
            
            workflow = self.workflows[workflow_id]
            
            # Remove triggers
            for trigger in workflow.triggers:
                if trigger.trigger_id in self.active_triggers:
                    del self.active_triggers[trigger.trigger_id]
            
            # Cancel running executions for this workflow
            executions_to_cancel = [
                exec_id for exec_id, execution in self.executions.items()
                if execution.workflow_id == workflow_id and execution.status == WorkflowStatus.RUNNING
            ]
            
            for exec_id in executions_to_cancel:
                self.cancel_execution(exec_id)
            
            # Remove workflow data
            del self.workflows[workflow_id]
            if workflow_id in self.workflow_stats:
                del self.workflow_stats[workflow_id]
            
            logger.info(f"Unregistered workflow {workflow_id}")
            self._update_engine_stats()
            
            return True
            
        except Exception as e:
            logger.error(f"Error unregistering workflow {workflow_id}: {e}")
            return False
    
    def trigger_workflow(self, workflow_id: str, trigger_data: Dict[str, Any] = None,
                        triggered_by: str = "manual") -> Optional[str]:
        """Manually trigger a workflow execution"""
        try:
            if workflow_id not in self.workflows:
                logger.error(f"Workflow {workflow_id} not found")
                return None
            
            workflow = self.workflows[workflow_id]
            if not workflow.enabled:
                logger.warning(f"Workflow {workflow_id} is disabled")
                return None
            
            # Create execution
            execution = WorkflowExecution(
                execution_id=str(uuid.uuid4()),
                workflow_id=workflow_id,
                status=WorkflowStatus.PENDING,
                triggered_by=triggered_by,
                trigger_data=trigger_data or {},
                total_actions=len(workflow.actions)
            )
            
            # Add to queue
            self.executions[execution.execution_id] = execution
            self.execution_queue.append(execution.execution_id)
            
            logger.info(f"Triggered workflow {workflow_id}, execution {execution.execution_id}")
            self._update_engine_stats()
            
            return execution.execution_id
            
        except Exception as e:
            logger.error(f"Error triggering workflow {workflow_id}: {e}")
            return None
    
    def cancel_execution(self, execution_id: str) -> bool:
        """Cancel a running workflow execution"""
        try:
            if execution_id not in self.executions:
                logger.warning(f"Execution {execution_id} not found")
                return False
            
            execution = self.executions[execution_id]
            
            # Cancel running task if exists
            if execution_id in self.running_executions:
                task = self.running_executions[execution_id]
                task.cancel()
                del self.running_executions[execution_id]
            
            # Update execution status
            execution.status = WorkflowStatus.CANCELLED
            execution.completed_at = datetime.utcnow()
            
            logger.info(f"Cancelled workflow execution {execution_id}")
            self._update_engine_stats()
            
            return True
            
        except Exception as e:
            logger.error(f"Error cancelling execution {execution_id}: {e}")
            return False
    
    def approve_action(self, execution_id: str, action_id: str, approved_by: str) -> bool:
        """Approve a pending action in a workflow"""
        try:
            if execution_id not in self.executions:
                logger.warning(f"Execution {execution_id} not found")
                return False
            
            execution = self.executions[execution_id]
            
            if action_id not in execution.pending_approvals:
                logger.warning(f"Action {action_id} is not pending approval")
                return False
            
            # Move from pending to approved
            execution.pending_approvals.remove(action_id)
            execution.approved_actions.append(action_id)
            
            # Log approval
            logger.info(f"Action {action_id} approved by {approved_by} for execution {execution_id}")
            
            # Resume execution if it was waiting for this approval
            if execution.status == WorkflowStatus.WAITING_APPROVAL:
                execution.status = WorkflowStatus.RUNNING
            
            return True
            
        except Exception as e:
            logger.error(f"Error approving action: {e}")
            return False
    
    def _execution_loop(self):
        """Main execution loop for processing workflow queue"""
        logger.info("Starting workflow execution loop")
        
        while self.running:
            try:
                # Process execution queue
                self._process_execution_queue()
                
                # Clean up completed executions
                self._cleanup_old_executions()
                
                # Update statistics
                self._update_engine_stats()
                
                time.sleep(5)  # Process every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in workflow execution loop: {e}")
                time.sleep(10)
    
    def _trigger_loop(self):
        """Loop for monitoring and processing triggers"""
        logger.info("Starting workflow trigger monitoring loop")
        
        while self.running:
            try:
                # Check scheduled triggers
                self._check_scheduled_triggers()
                
                # Check condition-based triggers
                self._check_condition_triggers()
                
                time.sleep(self.config['trigger_check_interval'])
                
            except Exception as e:
                logger.error(f"Error in trigger monitoring loop: {e}")
                time.sleep(30)
    
    def _process_execution_queue(self):
        """Process pending workflow executions"""
        # Limit concurrent executions
        if len(self.running_executions) >= self.config['max_concurrent_workflows']:
            return
        
        # Get next execution from queue
        while self.execution_queue and len(self.running_executions) < self.config['max_concurrent_workflows']:
            execution_id = self.execution_queue.popleft()
            
            if execution_id in self.executions:
                execution = self.executions[execution_id]
                
                if execution.status == WorkflowStatus.PENDING:
                    # Start execution
                    task = asyncio.create_task(self._execute_workflow(execution))
                    self.running_executions[execution_id] = task
                    
                    # Set up task completion callback
                    task.add_done_callback(lambda t, eid=execution_id: self._execution_completed(eid, t))
    
    def _execution_completed(self, execution_id: str, task: asyncio.Task):
        """Handle completion of workflow execution"""
        try:
            # Remove from running executions
            if execution_id in self.running_executions:
                del self.running_executions[execution_id]
            
            # Update statistics
            if execution_id in self.executions:
                execution = self.executions[execution_id]
                stats = self.workflow_stats.get(execution.workflow_id)
                
                if stats:
                    stats.total_executions += 1
                    stats.last_execution = execution.completed_at
                    
                    if execution.status == WorkflowStatus.COMPLETED:
                        stats.successful_executions += 1
                        stats.last_success = execution.completed_at
                    elif execution.status == WorkflowStatus.FAILED:
                        stats.failed_executions += 1
                        stats.last_failure = execution.completed_at
                    
                    # Update average execution time
                    if execution.execution_time_seconds > 0:
                        if stats.average_execution_time == 0:
                            stats.average_execution_time = execution.execution_time_seconds
                        else:
                            stats.average_execution_time = (stats.average_execution_time + execution.execution_time_seconds) / 2
            
            self._update_engine_stats()
            
        except Exception as e:
            logger.error(f"Error handling execution completion: {e}")
    
    async def _execute_workflow(self, execution: WorkflowExecution):
        """Execute a complete workflow"""
        start_time = time.time()
        
        try:
            execution.status = WorkflowStatus.RUNNING
            execution.started_at = datetime.utcnow()
            
            workflow = self.workflows[execution.workflow_id]
            logger.info(f"Starting execution {execution.execution_id} for workflow {workflow.name}")
            
            # Initialize context with trigger data and workflow variables
            execution.context.update(execution.trigger_data)
            execution.context.update(workflow.variables)
            
            # Execute actions in dependency order
            action_execution_order = self._calculate_action_execution_order(workflow.actions)
            
            for action in action_execution_order:
                if not self.running or execution.status in [WorkflowStatus.CANCELLED, WorkflowStatus.FAILED]:
                    break
                
                # Check if action requires approval
                if (workflow.requires_approval and 
                    action.action_id in workflow.approval_required_for and
                    action.action_id not in execution.approved_actions):
                    
                    execution.pending_approvals.append(action.action_id)
                    execution.status = WorkflowStatus.WAITING_APPROVAL
                    
                    # Send approval notification
                    await self._send_approval_notification(execution, action)
                    
                    # Wait for approval (with timeout)
                    approval_timeout = self.config['approval_timeout_hours'] * 3600
                    start_wait = time.time()
                    
                    while (action.action_id not in execution.approved_actions and
                           time.time() - start_wait < approval_timeout and
                           self.running):
                        await asyncio.sleep(10)
                    
                    if action.action_id not in execution.approved_actions:
                        execution.status = WorkflowStatus.FAILED
                        execution.error_message = f"Approval timeout for action {action.action_id}"
                        break
                    
                    execution.status = WorkflowStatus.RUNNING
                
                # Execute the action
                execution.current_action = action.action_id
                
                try:
                    # Check action conditions
                    if not self._evaluate_conditions(action.conditions, execution.context, action.condition_logic):
                        logger.info(f"Skipping action {action.action_id} - conditions not met")
                        continue
                    
                    # Execute action with retries
                    action_result = await self._execute_action_with_retries(action, execution)
                    
                    execution.action_results[action.action_id] = action_result
                    execution.completed_actions.append(action.action_id)
                    
                    # Apply output mapping to context
                    if action.output_mapping and action_result:
                        for source_key, target_key in action.output_mapping.items():
                            if source_key in action_result:
                                execution.context[target_key] = action_result[source_key]
                    
                except Exception as e:
                    logger.error(f"Action {action.action_id} failed: {e}")
                    execution.failed_actions.append(action.action_id)
                    
                    if action.on_error == "stop":
                        execution.status = WorkflowStatus.FAILED
                        execution.error_message = f"Action {action.action_id} failed: {str(e)}"
                        execution.error_details = traceback.format_exc()
                        break
                    # Continue with next action if on_error is "continue"
            
            # Mark workflow as completed if not already failed or cancelled
            if execution.status == WorkflowStatus.RUNNING:
                execution.status = WorkflowStatus.COMPLETED
            
            execution.completed_at = datetime.utcnow()
            execution.execution_time_seconds = time.time() - start_time
            
            logger.info(f"Workflow execution {execution.execution_id} completed with status {execution.status.value}")
            
        except Exception as e:
            execution.status = WorkflowStatus.FAILED
            execution.error_message = str(e)
            execution.error_details = traceback.format_exc()
            execution.completed_at = datetime.utcnow()
            execution.execution_time_seconds = time.time() - start_time
            
            logger.error(f"Workflow execution {execution.execution_id} failed: {e}")
    
    async def _execute_action_with_retries(self, action: WorkflowAction, execution: WorkflowExecution) -> Any:
        """Execute an action with retry logic"""
        last_error = None
        
        for attempt in range(action.max_retries + 1):
            try:
                # Execute the action
                result = await self._execute_single_action(action, execution)
                return result
                
            except Exception as e:
                last_error = e
                logger.warning(f"Action {action.action_id} attempt {attempt + 1} failed: {e}")
                
                if attempt < action.max_retries:
                    await asyncio.sleep(action.retry_delay_seconds)
                else:
                    raise last_error
    
    async def _execute_single_action(self, action: WorkflowAction, execution: WorkflowExecution) -> Any:
        """Execute a single workflow action"""
        handler = self.action_handlers.get(action.action_type)
        if not handler:
            raise ValueError(f"No handler found for action type {action.action_type.value}")
        
        # Create action timeout
        try:
            result = await asyncio.wait_for(
                handler(action, execution),
                timeout=action.timeout_seconds
            )
            return result
            
        except asyncio.TimeoutError:
            raise Exception(f"Action {action.action_id} timed out after {action.timeout_seconds} seconds")
    
    def _register_builtin_action_handlers(self):
        """Register built-in action handlers"""
        self.action_handlers[ActionType.NOTIFICATION] = self._handle_notification_action
        self.action_handlers[ActionType.INTEGRATION] = self._handle_integration_action
        self.action_handlers[ActionType.API_CALL] = self._handle_api_call_action
        self.action_handlers[ActionType.WAIT] = self._handle_wait_action
        self.action_handlers[ActionType.CONDITIONAL] = self._handle_conditional_action
        self.action_handlers[ActionType.DATABASE] = self._handle_database_action
        self.action_handlers[ActionType.SCRIPT] = self._handle_script_action
        self.action_handlers[ActionType.CHAIN_WORKFLOW] = self._handle_chain_workflow_action
    
    async def _handle_notification_action(self, action: WorkflowAction, execution: WorkflowExecution) -> Dict[str, Any]:
        """Handle notification action"""
        try:
            message = self._resolve_template(action.config.get("message", ""), execution.context)
            subject = self._resolve_template(action.config.get("subject", "Workflow Notification"), execution.context)
            level = action.config.get("level", "info")
            
            notification_service.send_notification(
                subject=subject,
                message=message,
                level=level
            )
            
            return {
                "success": True,
                "message": "Notification sent successfully",
                "subject": subject
            }
            
        except Exception as e:
            raise Exception(f"Failed to send notification: {e}")
    
    async def _handle_integration_action(self, action: WorkflowAction, execution: WorkflowExecution) -> Dict[str, Any]:
        """Handle external system integration action"""
        try:
            integration_id = action.config.get("integration_id")
            event_type = action.config.get("event_type")
            data = action.config.get("data", {})
            
            if not integration_id or not event_type:
                raise ValueError("integration_id and event_type are required")
            
            # Resolve template variables in data
            resolved_data = self._resolve_dict_templates(data, execution.context)
            
            success = integration_manager.send_event(
                integration_id=integration_id,
                event_type=event_type,
                data=resolved_data,
                source_system="workflow_engine",
                source_id=execution.execution_id
            )
            
            if not success:
                raise Exception("Failed to send integration event")
            
            return {
                "success": True,
                "integration_id": integration_id,
                "event_type": event_type,
                "data": resolved_data
            }
            
        except Exception as e:
            raise Exception(f"Integration action failed: {e}")
    
    async def _handle_api_call_action(self, action: WorkflowAction, execution: WorkflowExecution) -> Dict[str, Any]:
        """Handle HTTP API call action"""
        try:
            import aiohttp
            
            url = self._resolve_template(action.config.get("url", ""), execution.context)
            method = action.config.get("method", "GET").upper()
            headers = action.config.get("headers", {})
            data = action.config.get("data")
            params = action.config.get("params")
            
            # Resolve templates in headers, data, and params
            resolved_headers = self._resolve_dict_templates(headers, execution.context)
            resolved_data = self._resolve_dict_templates(data, execution.context) if data else None
            resolved_params = self._resolve_dict_templates(params, execution.context) if params else None
            
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=method,
                    url=url,
                    headers=resolved_headers,
                    json=resolved_data,
                    params=resolved_params
                ) as response:
                    response_data = await response.text()
                    
                    if response.status >= 400:
                        raise Exception(f"API call failed with status {response.status}: {response_data}")
                    
                    # Try to parse as JSON
                    try:
                        response_json = await response.json()
                        return {
                            "success": True,
                            "status_code": response.status,
                            "response": response_json
                        }
                    except:
                        return {
                            "success": True,
                            "status_code": response.status,
                            "response": response_data
                        }
            
        except Exception as e:
            raise Exception(f"API call action failed: {e}")
    
    async def _handle_wait_action(self, action: WorkflowAction, execution: WorkflowExecution) -> Dict[str, Any]:
        """Handle wait/delay action"""
        try:
            wait_seconds = action.config.get("seconds", 5)
            
            # Allow template resolution for wait time
            if isinstance(wait_seconds, str):
                wait_seconds = float(self._resolve_template(wait_seconds, execution.context))
            
            await asyncio.sleep(wait_seconds)
            
            return {
                "success": True,
                "waited_seconds": wait_seconds
            }
            
        except Exception as e:
            raise Exception(f"Wait action failed: {e}")
    
    async def _handle_conditional_action(self, action: WorkflowAction, execution: WorkflowExecution) -> Dict[str, Any]:
        """Handle conditional branching action"""
        try:
            conditions = action.config.get("conditions", [])
            true_actions = action.config.get("true_actions", [])
            false_actions = action.config.get("false_actions", [])
            condition_logic = action.config.get("condition_logic", "AND")
            
            # Parse conditions
            workflow_conditions = []
            for cond in conditions:
                workflow_conditions.append(WorkflowCondition(
                    field=cond["field"],
                    operator=ConditionOperator(cond["operator"]),
                    value=cond["value"],
                    case_sensitive=cond.get("case_sensitive", True)
                ))
            
            # Evaluate conditions
            result = self._evaluate_conditions(workflow_conditions, execution.context, condition_logic)
            
            # Execute appropriate actions
            actions_to_execute = true_actions if result else false_actions
            results = []
            
            for action_config in actions_to_execute:
                # Create temporary action
                temp_action = WorkflowAction(
                    action_id=f"{action.action_id}_conditional_{len(results)}",
                    action_type=ActionType(action_config["action_type"]),
                    name=action_config.get("name", "Conditional Action"),
                    config=action_config.get("config", {})
                )
                
                action_result = await self._execute_single_action(temp_action, execution)
                results.append(action_result)
            
            return {
                "success": True,
                "condition_result": result,
                "executed_actions": len(results),
                "results": results
            }
            
        except Exception as e:
            raise Exception(f"Conditional action failed: {e}")
    
    async def _handle_database_action(self, action: WorkflowAction, execution: WorkflowExecution) -> Dict[str, Any]:
        """Handle database operation action"""
        try:
            operation = action.config.get("operation")  # select, insert, update, delete
            table = action.config.get("table")
            
            if operation == "select":
                # For now, return placeholder - would need actual DB query implementation
                return {
                    "success": True,
                    "operation": "select",
                    "table": table,
                    "results": []
                }
            else:
                return {
                    "success": True,
                    "operation": operation,
                    "table": table,
                    "affected_rows": 0
                }
            
        except Exception as e:
            raise Exception(f"Database action failed: {e}")
    
    async def _handle_script_action(self, action: WorkflowAction, execution: WorkflowExecution) -> Dict[str, Any]:
        """Handle script execution action"""
        try:
            import subprocess
            
            script = self._resolve_template(action.config.get("script", ""), execution.context)
            shell = action.config.get("shell", False)
            
            # Execute script in thread pool to avoid blocking
            result = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                lambda: subprocess.run(
                    script,
                    shell=shell,
                    capture_output=True,
                    text=True,
                    timeout=action.timeout_seconds
                )
            )
            
            if result.returncode != 0:
                raise Exception(f"Script failed with return code {result.returncode}: {result.stderr}")
            
            return {
                "success": True,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
        except Exception as e:
            raise Exception(f"Script action failed: {e}")
    
    async def _handle_chain_workflow_action(self, action: WorkflowAction, execution: WorkflowExecution) -> Dict[str, Any]:
        """Handle chaining another workflow"""
        try:
            target_workflow_id = action.config.get("workflow_id")
            trigger_data = action.config.get("trigger_data", {})
            
            # Resolve template variables in trigger data
            resolved_trigger_data = self._resolve_dict_templates(trigger_data, execution.context)
            
            chained_execution_id = self.trigger_workflow(
                workflow_id=target_workflow_id,
                trigger_data=resolved_trigger_data,
                triggered_by=f"workflow_chain:{execution.execution_id}"
            )
            
            if not chained_execution_id:
                raise Exception(f"Failed to trigger workflow {target_workflow_id}")
            
            return {
                "success": True,
                "chained_workflow_id": target_workflow_id,
                "chained_execution_id": chained_execution_id
            }
            
        except Exception as e:
            raise Exception(f"Chain workflow action failed: {e}")
    
    def _resolve_template(self, template: str, context: Dict[str, Any]) -> str:
        """Resolve template variables in a string"""
        try:
            # Simple template resolution using string formatting
            # In a production system, you might want to use a more sophisticated template engine
            resolved = template
            
            for key, value in context.items():
                placeholder = f"{{{key}}}"
                if placeholder in resolved:
                    resolved = resolved.replace(placeholder, str(value))
            
            return resolved
            
        except Exception as e:
            logger.error(f"Error resolving template: {e}")
            return template
    
    def _resolve_dict_templates(self, data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve template variables in a dictionary"""
        if not isinstance(data, dict):
            return data
        
        resolved = {}
        for key, value in data.items():
            if isinstance(value, str):
                resolved[key] = self._resolve_template(value, context)
            elif isinstance(value, dict):
                resolved[key] = self._resolve_dict_templates(value, context)
            elif isinstance(value, list):
                resolved[key] = [
                    self._resolve_template(item, context) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                resolved[key] = value
        
        return resolved
    
    def _evaluate_conditions(self, conditions: List[WorkflowCondition], 
                           context: Dict[str, Any], logic: str = "AND") -> bool:
        """Evaluate workflow conditions"""
        if not conditions:
            return True
        
        results = []
        
        for condition in conditions:
            field_value = context.get(condition.field)
            result = self._evaluate_single_condition(condition, field_value)
            results.append(result)
        
        if logic.upper() == "OR":
            return any(results)
        else:  # AND
            return all(results)
    
    def _evaluate_single_condition(self, condition: WorkflowCondition, field_value: Any) -> bool:
        """Evaluate a single condition"""
        try:
            value = condition.value
            
            # Handle case sensitivity for string comparisons
            if isinstance(field_value, str) and isinstance(value, str) and not condition.case_sensitive:
                field_value = field_value.lower()
                value = value.lower()
            
            if condition.operator == ConditionOperator.EQUALS:
                return field_value == value
            elif condition.operator == ConditionOperator.NOT_EQUALS:
                return field_value != value
            elif condition.operator == ConditionOperator.GREATER_THAN:
                return field_value > value
            elif condition.operator == ConditionOperator.LESS_THAN:
                return field_value < value
            elif condition.operator == ConditionOperator.GREATER_EQUAL:
                return field_value >= value
            elif condition.operator == ConditionOperator.LESS_EQUAL:
                return field_value <= value
            elif condition.operator == ConditionOperator.CONTAINS:
                return str(value) in str(field_value)
            elif condition.operator == ConditionOperator.NOT_CONTAINS:
                return str(value) not in str(field_value)
            elif condition.operator == ConditionOperator.IN_LIST:
                return field_value in value if isinstance(value, list) else False
            elif condition.operator == ConditionOperator.NOT_IN_LIST:
                return field_value not in value if isinstance(value, list) else True
            elif condition.operator == ConditionOperator.IS_NULL:
                return field_value is None
            elif condition.operator == ConditionOperator.IS_NOT_NULL:
                return field_value is not None
            elif condition.operator == ConditionOperator.REGEX_MATCH:
                import re
                return bool(re.search(str(value), str(field_value)))
            
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating condition: {e}")
            return False
    
    def _calculate_action_execution_order(self, actions: List[WorkflowAction]) -> List[WorkflowAction]:
        """Calculate the execution order based on dependencies"""
        # Simple topological sort for action dependencies
        ordered_actions = []
        remaining_actions = actions.copy()
        action_dict = {action.action_id: action for action in actions}
        
        while remaining_actions:
            # Find actions with no unresolved dependencies
            ready_actions = []
            
            for action in remaining_actions:
                dependencies_met = all(
                    dep_id in [a.action_id for a in ordered_actions]
                    for dep_id in action.depends_on
                    if dep_id in action_dict
                )
                
                if dependencies_met:
                    ready_actions.append(action)
            
            if not ready_actions:
                # Circular dependency or invalid dependency - add remaining actions anyway
                ready_actions = remaining_actions
            
            # Add ready actions to ordered list
            for action in ready_actions:
                ordered_actions.append(action)
                remaining_actions.remove(action)
        
        return ordered_actions
    
    async def _send_approval_notification(self, execution: WorkflowExecution, action: WorkflowAction):
        """Send approval notification for an action"""
        try:
            workflow = self.workflows[execution.workflow_id]
            
            notification_service.send_notification(
                subject=f"Workflow Approval Required: {workflow.name}",
                message=f"""
Workflow Approval Required:
- Workflow: {workflow.name}
- Execution: {execution.execution_id}
- Action: {action.name}
- Description: {action.description}
- Triggered by: {execution.triggered_by}

Please review and approve this action to continue workflow execution.
                """.strip(),
                level="warning"
            )
            
        except Exception as e:
            logger.error(f"Error sending approval notification: {e}")
    
    def _check_scheduled_triggers(self):
        """Check for scheduled workflow triggers"""
        # Implementation for time-based triggers would go here
        # This would check cron expressions, intervals, etc.
        pass
    
    def _check_condition_triggers(self):
        """Check for condition-based workflow triggers"""
        # Implementation for condition-based triggers would go here
        # This would evaluate triggers based on system state
        pass
    
    def _cleanup_old_executions(self):
        """Clean up old completed executions"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=self.config['cleanup_completed_hours'])
            
            executions_to_remove = []
            for execution_id, execution in self.executions.items():
                if (execution.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED, WorkflowStatus.CANCELLED] and
                    execution.completed_at and execution.completed_at < cutoff_time):
                    executions_to_remove.append(execution_id)
            
            for execution_id in executions_to_remove:
                del self.executions[execution_id]
                
        except Exception as e:
            logger.error(f"Error cleaning up old executions: {e}")
    
    def _validate_workflow(self, workflow: WorkflowDefinition) -> bool:
        """Validate workflow definition"""
        try:
            # Check required fields
            if not workflow.workflow_id or not workflow.name:
                return False
            
            # Validate actions
            action_ids = set()
            for action in workflow.actions:
                if not action.action_id or action.action_id in action_ids:
                    return False
                action_ids.add(action.action_id)
                
                # Check action type is valid
                if action.action_type not in self.action_handlers:
                    logger.error(f"Unsupported action type: {action.action_type}")
                    return False
            
            # Validate dependencies
            for action in workflow.actions:
                for dep_id in action.depends_on:
                    if dep_id not in action_ids:
                        logger.error(f"Invalid dependency: {dep_id}")
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating workflow: {e}")
            return False
    
    def _load_builtin_workflows(self):
        """Load built-in workflow templates"""
        # Example: Device Down Response Workflow
        device_down_workflow = WorkflowDefinition(
            workflow_id="device_down_response",
            name="Device Down Response",
            description="Automated response workflow for device down alerts",
            category="incident_response",
            tags=["device", "monitoring", "incident"],
            triggers=[
                WorkflowTrigger(
                    trigger_id="device_down_trigger",
                    trigger_type=TriggerType.EVENT,
                    name="Device Down Event",
                    config={"event_type": "device_down"},
                    conditions=[
                        WorkflowCondition(
                            field="severity",
                            operator=ConditionOperator.IN_LIST,
                            value=["high", "critical"]
                        )
                    ]
                )
            ],
            actions=[
                WorkflowAction(
                    action_id="send_notification",
                    action_type=ActionType.NOTIFICATION,
                    name="Send Alert Notification",
                    config={
                        "subject": "Device Down Alert: {device_name}",
                        "message": "Device {device_name} ({device_ip}) is down. Please investigate.",
                        "level": "error"
                    }
                ),
                WorkflowAction(
                    action_id="create_incident",
                    action_type=ActionType.INTEGRATION,
                    name="Create ITSM Incident",
                    config={
                        "integration_id": "servicenow",
                        "event_type": "create_incident",
                        "data": {
                            "title": "Device Down: {device_name}",
                            "description": "Network device {device_name} at {device_ip} is not responding",
                            "severity": "high"
                        }
                    },
                    depends_on=["send_notification"]
                )
            ]
        )
        
        self.register_workflow(device_down_workflow)
    
    def _update_engine_stats(self):
        """Update engine statistics"""
        try:
            self.engine_stats['total_workflows'] = len(self.workflows)
            self.engine_stats['active_workflows'] = sum(1 for w in self.workflows.values() if w.enabled)
            self.engine_stats['running_executions'] = len(self.running_executions)
            self.engine_stats['queued_executions'] = len(self.execution_queue)
            self.engine_stats['total_executions'] = len(self.executions)
            
            # Update last execution time
            if self.executions:
                latest_execution = max(self.executions.values(), key=lambda e: e.started_at)
                self.engine_stats['last_execution'] = latest_execution.started_at
            
        except Exception as e:
            logger.error(f"Error updating engine stats: {e}")
    
    # Public API methods
    
    def get_workflows_summary(self) -> Dict[str, Any]:
        """Get summary of all workflows"""
        try:
            workflows_data = []
            
            for workflow_id, workflow in self.workflows.items():
                stats = self.workflow_stats.get(workflow_id, WorkflowStats(workflow_id=workflow_id))
                
                workflows_data.append({
                    "workflow_id": workflow_id,
                    "name": workflow.name,
                    "description": workflow.description,
                    "category": workflow.category,
                    "enabled": workflow.enabled,
                    "total_actions": len(workflow.actions),
                    "total_triggers": len(workflow.triggers),
                    "total_executions": stats.total_executions,
                    "success_rate": (stats.successful_executions / stats.total_executions * 100) if stats.total_executions > 0 else 0,
                    "last_execution": stats.last_execution.isoformat() + 'Z' if stats.last_execution else None,
                    "average_execution_time": stats.average_execution_time
                })
            
            return {
                "workflows": workflows_data,
                "engine_stats": self.engine_stats
            }
            
        except Exception as e:
            logger.error(f"Error getting workflows summary: {e}")
            return {"workflows": [], "engine_stats": self.engine_stats}
    
    def get_workflow_details(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific workflow"""
        try:
            if workflow_id not in self.workflows:
                return None
            
            workflow = self.workflows[workflow_id]
            stats = self.workflow_stats.get(workflow_id, WorkflowStats(workflow_id=workflow_id))
            
            # Get recent executions
            recent_executions = [
                asdict(execution) for execution in self.executions.values()
                if execution.workflow_id == workflow_id
            ]
            recent_executions.sort(key=lambda e: e['started_at'], reverse=True)
            recent_executions = recent_executions[:10]  # Last 10 executions
            
            return {
                "workflow": asdict(workflow),
                "statistics": asdict(stats),
                "recent_executions": recent_executions
            }
            
        except Exception as e:
            logger.error(f"Error getting workflow details: {e}")
            return None
    
    def get_execution_details(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a workflow execution"""
        try:
            if execution_id not in self.executions:
                return None
            
            execution = self.executions[execution_id]
            return asdict(execution)
            
        except Exception as e:
            logger.error(f"Error getting execution details: {e}")
            return None
    
    def get_engine_status(self) -> Dict[str, Any]:
        """Get workflow engine status"""
        return {
            "running": self.running,
            "engine_stats": self.engine_stats,
            "configuration": self.config
        }


# Global workflow engine instance
workflow_engine = IntelligentWorkflowEngine()