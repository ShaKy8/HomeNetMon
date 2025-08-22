"""
Security API Endpoints

This module provides comprehensive REST API endpoints for security operations:
1. Vulnerability management and scanning
2. Threat monitoring and response
3. Incident management
4. Compliance reporting
5. Security configuration and settings
6. Remediation task management
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import logging

from services.security_scanner import security_scanner, ComplianceFramework
from services.network_security_monitor import network_security_monitor
from services.security_response import security_response_engine
from services.compliance_reporting import compliance_reporting_engine, ReportType, ReportFormat
from models import db, Device, SecurityVulnerability, SecurityIncident, ComplianceResult

logger = logging.getLogger(__name__)

# Create security API blueprint
security_api = Blueprint('security_api', __name__, url_prefix='/api/security')


# Security Scanning Endpoints
@security_api.route('/scan/start', methods=['POST'])
def start_security_scan():
    """Start a comprehensive security scan"""
    try:
        data = request.get_json() or {}
        device_id = data.get('device_id')
        
        if device_id:
            # Scan specific device
            device = Device.query.get(device_id)
            if not device:
                return jsonify({'error': 'Device not found'}), 404
            
            result = security_scanner.manual_scan_device(device_id)
        else:
            # Scan all devices
            result = security_scanner.start_background_scan()
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error starting security scan: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/scan/progress', methods=['GET'])
def get_scan_progress():
    """Get current security scan progress"""
    try:
        progress = security_scanner.get_scan_progress()
        return jsonify(progress)
        
    except Exception as e:
        logger.error(f"Error getting scan progress: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Get security vulnerabilities"""
    try:
        # Parse query parameters
        device_id = request.args.get('device_id', type=int)
        severity = request.args.get('severity')
        status = request.args.get('status', 'open')
        days = request.args.get('days', 30, type=int)
        
        # Build query
        query = SecurityVulnerability.query
        
        if device_id:
            query = query.filter_by(device_id=device_id)
        
        if severity:
            query = query.filter_by(severity=severity)
        
        if status:
            query = query.filter_by(status=status)
        
        # Filter by date range
        start_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(SecurityVulnerability.discovered_at >= start_date)
        
        vulnerabilities = query.order_by(SecurityVulnerability.risk_score.desc()).all()
        
        return jsonify({
            'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities],
            'total_count': len(vulnerabilities),
            'filters': {
                'device_id': device_id,
                'severity': severity,
                'status': status,
                'days': days
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/vulnerabilities/<string:finding_id>', methods=['GET'])
def get_vulnerability_detail(finding_id):
    """Get detailed information about a specific vulnerability"""
    try:
        vulnerability = SecurityVulnerability.query.filter_by(finding_id=finding_id).first()
        
        if not vulnerability:
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        return jsonify(vulnerability.to_dict())
        
    except Exception as e:
        logger.error(f"Error getting vulnerability detail: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/vulnerabilities/<string:finding_id>/status', methods=['PUT'])
def update_vulnerability_status():
    """Update vulnerability status"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if new_status not in ['open', 'acknowledged', 'remediated', 'false_positive']:
            return jsonify({'error': 'Invalid status'}), 400
        
        vulnerability = SecurityVulnerability.query.filter_by(finding_id=finding_id).first()
        
        if not vulnerability:
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        vulnerability.status = new_status
        vulnerability.last_verified = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'finding_id': finding_id,
            'new_status': new_status,
            'updated_at': vulnerability.last_verified.isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error updating vulnerability status: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# Threat Monitoring Endpoints
@security_api.route('/threats', methods=['GET'])
def get_security_threats():
    """Get recent security threats"""
    try:
        hours = request.args.get('hours', 24, type=int)
        threats = network_security_monitor.get_recent_threats(hours)
        
        return jsonify({
            'threats': threats,
            'total_count': len(threats),
            'time_period_hours': hours
        })
        
    except Exception as e:
        logger.error(f"Error getting security threats: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/monitoring/status', methods=['GET'])
def get_monitoring_status():
    """Get network security monitoring status"""
    try:
        status = network_security_monitor.get_monitoring_statistics()
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting monitoring status: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/monitoring/start', methods=['POST'])
def start_security_monitoring():
    """Start network security monitoring"""
    try:
        network_security_monitor.start_monitoring()
        return jsonify({
            'success': True,
            'message': 'Network security monitoring started',
            'started_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error starting security monitoring: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/monitoring/stop', methods=['POST'])
def stop_security_monitoring():
    """Stop network security monitoring"""
    try:
        network_security_monitor.stop_monitoring()
        return jsonify({
            'success': True,
            'message': 'Network security monitoring stopped',
            'stopped_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error stopping security monitoring: {e}")
        return jsonify({'error': str(e)}), 500


# Incident Management Endpoints
@security_api.route('/incidents', methods=['GET'])
def get_security_incidents():
    """Get security incidents"""
    try:
        status = request.args.get('status')
        severity = request.args.get('severity')
        days = request.args.get('days', 30, type=int)
        
        # Build query
        query = SecurityIncident.query
        
        if status:
            query = query.filter_by(status=status)
        
        if severity:
            query = query.filter_by(severity=severity)
        
        # Filter by date range
        start_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(SecurityIncident.detected_at >= start_date)
        
        incidents = query.order_by(SecurityIncident.detected_at.desc()).all()
        
        return jsonify({
            'incidents': [incident.to_dict() for incident in incidents],
            'total_count': len(incidents),
            'filters': {
                'status': status,
                'severity': severity,
                'days': days
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting security incidents: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/incidents/<string:incident_id>', methods=['GET'])
def get_incident_detail(incident_id):
    """Get detailed information about a specific incident"""
    try:
        # First check database
        db_incident = SecurityIncident.query.filter_by(incident_id=incident_id).first()
        
        if not db_incident:
            return jsonify({'error': 'Incident not found'}), 404
        
        incident_data = db_incident.to_dict()
        
        # Try to get additional details from response engine
        response_details = security_response_engine.get_incident_details(incident_id)
        if response_details:
            incident_data.update(response_details)
        
        return jsonify(incident_data)
        
    except Exception as e:
        logger.error(f"Error getting incident detail: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/incidents/<string:incident_id>/status', methods=['PUT'])
def update_incident_status(incident_id):
    """Update incident status"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        notes = data.get('notes')
        
        if new_status not in ['new', 'assigned', 'investigating', 'containing', 'eradicating', 'recovering', 'resolved', 'closed']:
            return jsonify({'error': 'Invalid status'}), 400
        
        # Update database record
        db_incident = SecurityIncident.query.filter_by(incident_id=incident_id).first()
        
        if not db_incident:
            return jsonify({'error': 'Incident not found'}), 404
        
        db_incident.status = new_status
        if notes:
            db_incident.resolution_notes = notes
        
        db.session.commit()
        
        # Update response engine if running
        try:
            from services.security_response import IncidentStatus
            status_enum = IncidentStatus(new_status.upper())
            security_response_engine.update_incident_status(incident_id, status_enum, notes)
        except:
            pass  # Continue even if response engine update fails
        
        return jsonify({
            'success': True,
            'incident_id': incident_id,
            'new_status': new_status,
            'updated_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error updating incident status: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# Response Management Endpoints
@security_api.route('/response/status', methods=['GET'])
def get_response_status():
    """Get security response engine status"""
    try:
        dashboard = security_response_engine.get_security_response_dashboard()
        return jsonify(dashboard)
        
    except Exception as e:
        logger.error(f"Error getting response status: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/response/start', methods=['POST'])
def start_response_engine():
    """Start security response engine"""
    try:
        security_response_engine.start_response_engine()
        return jsonify({
            'success': True,
            'message': 'Security response engine started',
            'started_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error starting response engine: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/response/stop', methods=['POST'])
def stop_response_engine():
    """Stop security response engine"""
    try:
        security_response_engine.stop_response_engine()
        return jsonify({
            'success': True,
            'message': 'Security response engine stopped',
            'stopped_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error stopping response engine: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/response/playbooks', methods=['GET'])
def get_response_playbooks():
    """Get available response playbooks"""
    try:
        playbooks = []
        for playbook_id, playbook in security_response_engine.playbooks.items():
            playbooks.append({
                'playbook_id': playbook.playbook_id,
                'name': playbook.name,
                'description': playbook.description,
                'trigger_conditions': playbook.trigger_conditions,
                'response_actions': [action.value for action in playbook.response_actions],
                'priority': playbook.priority,
                'auto_execute': playbook.auto_execute,
                'approval_required': playbook.approval_required
            })
        
        return jsonify({
            'playbooks': playbooks,
            'total_count': len(playbooks)
        })
        
    except Exception as e:
        logger.error(f"Error getting response playbooks: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/response/playbooks', methods=['POST'])
def create_response_playbook():
    """Create a custom response playbook"""
    try:
        data = request.get_json()
        
        if not data or 'name' not in data:
            return jsonify({'error': 'Playbook name is required'}), 400
        
        playbook_id = security_response_engine.create_custom_playbook(data)
        
        if playbook_id:
            return jsonify({
                'success': True,
                'playbook_id': playbook_id,
                'message': 'Custom playbook created successfully'
            })
        else:
            return jsonify({'error': 'Failed to create playbook'}), 500
        
    except Exception as e:
        logger.error(f"Error creating response playbook: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/remediation/tasks', methods=['GET'])
def get_remediation_tasks():
    """Get remediation tasks"""
    try:
        status = request.args.get('status')
        priority = request.args.get('priority', type=int)
        
        tasks = []
        for task_id, task in security_response_engine.remediation_tasks.items():
            if status and task.status != status:
                continue
            if priority and task.priority != priority:
                continue
            
            task_data = security_response_engine.get_remediation_task_details(task_id)
            if task_data:
                tasks.append(task_data)
        
        return jsonify({
            'tasks': tasks,
            'total_count': len(tasks),
            'filters': {
                'status': status,
                'priority': priority
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting remediation tasks: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/remediation/tasks', methods=['POST'])
def create_remediation_task():
    """Create a new remediation task"""
    try:
        data = request.get_json()
        
        if not data or 'vulnerability_id' not in data or 'title' not in data:
            return jsonify({'error': 'vulnerability_id and title are required'}), 400
        
        task_id = security_response_engine.create_remediation_task(
            vulnerability_id=data['vulnerability_id'],
            title=data['title'],
            description=data.get('description', ''),
            priority=data.get('priority', 3),
            estimated_hours=data.get('estimated_hours', 2.0),
            due_days=data.get('due_days', 7)
        )
        
        if task_id:
            return jsonify({
                'success': True,
                'task_id': task_id,
                'message': 'Remediation task created successfully'
            })
        else:
            return jsonify({'error': 'Failed to create remediation task'}), 500
        
    except Exception as e:
        logger.error(f"Error creating remediation task: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/remediation/tasks/<string:task_id>/status', methods=['PUT'])
def update_remediation_task_status(task_id):
    """Update remediation task status"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        notes = data.get('notes')
        
        if new_status not in ['pending', 'in_progress', 'completed', 'deferred', 'cancelled']:
            return jsonify({'error': 'Invalid status'}), 400
        
        security_response_engine.update_remediation_task_status(task_id, new_status, notes)
        
        return jsonify({
            'success': True,
            'task_id': task_id,
            'new_status': new_status,
            'updated_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error updating remediation task status: {e}")
        return jsonify({'error': str(e)}), 500


# Compliance Endpoints
@security_api.route('/compliance/assess', methods=['POST'])
def run_compliance_assessment():
    """Run compliance assessment"""
    try:
        data = request.get_json() or {}
        framework_name = data.get('framework', 'cis')
        device_id = data.get('device_id')
        
        # Validate framework
        try:
            framework = ComplianceFramework(framework_name)
        except ValueError:
            return jsonify({'error': f'Invalid framework: {framework_name}'}), 400
        
        if device_id:
            # Assess specific device
            device = Device.query.get(device_id)
            if not device:
                return jsonify({'error': 'Device not found'}), 404
            
            compliance_checks = security_scanner.perform_compliance_assessment(device, framework)
            
            # Store results
            if compliance_checks:
                security_scanner.store_compliance_results(compliance_checks)
            
            return jsonify({
                'success': True,
                'framework': framework.value,
                'device_id': device_id,
                'checks_performed': len(compliance_checks),
                'results': [
                    {
                        'check_id': check.check_id,
                        'rule_id': check.rule_id,
                        'title': check.title,
                        'status': check.status,
                        'severity': check.severity.value
                    }
                    for check in compliance_checks
                ]
            })
        else:
            # Assess all devices (would be implemented similarly)
            return jsonify({'error': 'Full network compliance assessment not yet implemented'}), 501
        
    except Exception as e:
        logger.error(f"Error running compliance assessment: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/compliance/results', methods=['GET'])
def get_compliance_results():
    """Get compliance assessment results"""
    try:
        framework = request.args.get('framework')
        days = request.args.get('days', 30, type=int)
        
        # Build query
        query = ComplianceResult.query
        
        if framework:
            query = query.filter_by(framework=framework)
        
        # Filter by date range
        start_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(ComplianceResult.checked_at >= start_date)
        
        results = query.order_by(ComplianceResult.checked_at.desc()).all()
        
        return jsonify({
            'results': [result.to_dict() for result in results],
            'total_count': len(results),
            'filters': {
                'framework': framework,
                'days': days
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting compliance results: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/compliance/report', methods=['POST'])
def generate_compliance_report():
    """Generate compliance report"""
    try:
        data = request.get_json()
        
        if not data or 'framework' not in data:
            return jsonify({'error': 'Framework is required'}), 400
        
        framework_name = data['framework']
        report_type_name = data.get('report_type', 'executive_summary')
        format_name = data.get('format', 'json')
        period_days = data.get('period_days', 30)
        
        # Validate inputs
        try:
            framework = ComplianceFramework(framework_name)
            report_type = ReportType(report_type_name)
            report_format = ReportFormat(format_name)
        except ValueError as e:
            return jsonify({'error': f'Invalid parameter: {e}'}), 400
        
        # Generate report
        report = compliance_reporting_engine.generate_compliance_report(
            framework=framework,
            report_type=report_type,
            period_days=period_days
        )
        
        # Export report in requested format
        if report_format == ReportFormat.JSON:
            exported_content = compliance_reporting_engine.export_report(report, report_format)
            return jsonify({
                'success': True,
                'report_id': report.report_id,
                'framework': framework.value,
                'report_type': report_type.value,
                'format': report_format.value,
                'generated_at': report.generated_at.isoformat(),
                'report_data': exported_content if isinstance(exported_content, dict) else None,
                'report_content': exported_content if isinstance(exported_content, str) else None
            })
        else:
            # For non-JSON formats, return metadata and download info
            exported_file = compliance_reporting_engine.export_report(report, report_format, f"/tmp/compliance_report_{report.report_id}.{report_format.value}")
            return jsonify({
                'success': True,
                'report_id': report.report_id,
                'framework': framework.value,
                'report_type': report_type.value,
                'format': report_format.value,
                'generated_at': report.generated_at.isoformat(),
                'download_path': exported_file,
                'message': f'Report generated and saved to {exported_file}'
            })
        
    except Exception as e:
        logger.error(f"Error generating compliance report: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/compliance/trends', methods=['GET'])
def get_compliance_trends():
    """Get compliance trends over time"""
    try:
        framework_name = request.args.get('framework', 'cis')
        days = request.args.get('days', 90, type=int)
        
        try:
            framework = ComplianceFramework(framework_name)
        except ValueError:
            return jsonify({'error': f'Invalid framework: {framework_name}'}), 400
        
        trends = compliance_reporting_engine.get_compliance_trends(framework, days)
        
        return jsonify(trends)
        
    except Exception as e:
        logger.error(f"Error getting compliance trends: {e}")
        return jsonify({'error': str(e)}), 500


# Security Configuration Endpoints
@security_api.route('/config', methods=['GET'])
def get_security_config():
    """Get security configuration"""
    try:
        config = {
            'scanner': {
                'monitoring_enabled': security_scanner.running if hasattr(security_scanner, 'running') else False,
                'scan_interval': getattr(security_scanner, 'scan_interval', 3600),
                'scan_config': getattr(security_scanner, 'scan_config', {})
            },
            'monitoring': {
                'enabled': network_security_monitor.running,
                'config': network_security_monitor.monitoring_config,
                'thresholds': network_security_monitor.attack_thresholds
            },
            'response': {
                'enabled': security_response_engine.running,
                'config': security_response_engine.config,
                'total_playbooks': len(security_response_engine.playbooks)
            },
            'compliance': {
                'reporting_enabled': True,
                'config': compliance_reporting_engine.config,
                'supported_frameworks': [f.value for f in ComplianceFramework]
            }
        }
        
        return jsonify(config)
        
    except Exception as e:
        logger.error(f"Error getting security config: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/summary', methods=['GET'])
def get_security_summary():
    """Get comprehensive security summary"""
    try:
        hours = request.args.get('hours', 24, type=int)
        
        # Get scanner summary
        scanner_summary = security_scanner.get_security_summary(hours)
        
        # Get vulnerability summary
        vulnerability_summary = security_scanner.get_vulnerability_summary(hours)
        
        # Get monitoring summary
        monitoring_summary = network_security_monitor.get_monitoring_statistics()
        
        # Get response summary
        response_summary = security_response_engine.get_response_statistics()
        
        # Get compliance summary
        compliance_summary = security_scanner.get_compliance_summary(hours=hours)
        
        return jsonify({
            'time_period_hours': hours,
            'generated_at': datetime.utcnow().isoformat(),
            'scanner': scanner_summary,
            'vulnerabilities': vulnerability_summary,
            'monitoring': monitoring_summary,
            'response': response_summary,
            'compliance': compliance_summary
        })
        
    except Exception as e:
        logger.error(f"Error getting security summary: {e}")
        return jsonify({'error': str(e)}), 500


@security_api.route('/device/<int:device_id>/posture', methods=['GET'])
def get_device_security_posture(device_id):
    """Get comprehensive security posture for a specific device"""
    try:
        posture = security_scanner.get_device_security_posture(device_id)
        return jsonify(posture)
        
    except Exception as e:
        logger.error(f"Error getting device security posture: {e}")
        return jsonify({'error': str(e)}), 500


# Error handler for the security API blueprint
@security_api.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@security_api.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500