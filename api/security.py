from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from services.security_scanner import security_scanner
from models import db, Device, SecurityScan, SecurityEvent, Alert
from api.rate_limited_endpoints import create_endpoint_limiter
import json

security_bp = Blueprint('security', __name__)

@security_bp.route('/status', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_security_status():
    """Get security scanner status"""
    try:
        status = {
            'running': security_scanner.running,
            'scan_interval': security_scanner.scan_interval,
            'scan_config': security_scanner.scan_config,
            'suspicious_ports': list(security_scanner.suspicious_ports.keys()),
            'last_scan': 'unknown'  # Could be enhanced with actual last scan time
        }
        
        return jsonify({
            'success': True,
            'status': status
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/summary', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_security_summary():
    """Get security summary statistics"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        
        # Cap at 30 days
        if hours > 720:
            hours = 720
        
        summary = security_scanner.get_security_summary(hours)
        
        return jsonify({
            'success': True,
            'summary': summary,
            'period_hours': hours
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/alerts', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_security_alerts():
    """Get recent security alerts"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        limit = request.args.get('limit', default=50, type=int)
        
        # Cap limits
        if hours > 720:
            hours = 720
        if limit > 100:
            limit = 100
        
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Query security alerts
        alerts = db.session.query(Alert).filter(
            Alert.alert_type.like('security_%'),
            Alert.created_at >= start_time
        ).order_by(
            Alert.created_at.desc()
        ).limit(limit).all()
        
        alerts_data = []
        for alert in alerts:
            try:
                metadata = json.loads(alert.metadata or '{}')
            except:
                metadata = {}
            
            alert_data = {
                'id': alert.id,
                'device_id': alert.device_id,
                'device_name': alert.device.display_name if alert.device else f"Device {alert.device_id}",
                'alert_type': alert.alert_type.replace('security_', ''),
                'severity': alert.severity,
                'message': alert.message,
                'port': metadata.get('port'),
                'service': metadata.get('service'),
                'version': metadata.get('version'),
                'risk_score': metadata.get('risk_score'),
                'created_at': alert.created_at.isoformat() + 'Z',
                'acknowledged': alert.acknowledged,
                'acknowledged_at': alert.acknowledged_at.isoformat() + 'Z' if alert.acknowledged_at else None
            }
            alerts_data.append(alert_data)
        
        return jsonify({
            'success': True,
            'alerts': alerts_data,
            'count': len(alerts_data),
            'period_hours': hours
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/scans', methods=['GET'])
@create_endpoint_limiter('critical')
def get_scan_results():
    """Get recent scan results"""
    try:
        device_id = request.args.get('device_id', type=int)
        hours = request.args.get('hours', default=24, type=int)
        limit = request.args.get('limit', default=100, type=int)
        
        # Cap limits
        if hours > 720:
            hours = 720
        if limit > 500:
            limit = 500
        
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Build query
        query = db.session.query(SecurityScan).filter(
            SecurityScan.scanned_at >= start_time
        )
        
        if device_id:
            query = query.filter(SecurityScan.device_id == device_id)
        
        scans = query.order_by(
            SecurityScan.scanned_at.desc()
        ).limit(limit).all()
        
        scans_data = [scan.to_dict() for scan in scans]
        
        return jsonify({
            'success': True,
            'scans': scans_data,
            'count': len(scans_data),
            'period_hours': hours
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/device/<int:device_id>/scan', methods=['POST'])
@create_endpoint_limiter('critical')
def scan_device(device_id):
    """Manually trigger a security scan for a specific device"""
    try:
        result = security_scanner.manual_scan_device(device_id)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/device/<int:device_id>/ports', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_ports(device_id):
    """Get open ports and services for a specific device"""
    try:
        device = Device.query.get(device_id)
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        hours = request.args.get('hours', default=24, type=int)
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get recent scan results for this device
        scans = db.session.query(SecurityScan).filter(
            SecurityScan.device_id == device_id,
            SecurityScan.scanned_at >= start_time,
            SecurityScan.state == 'open'
        ).order_by(
            SecurityScan.port
        ).all()
        
        ports_data = []
        total_risk_score = 0
        
        for scan in scans:
            port_info = {
                'port': scan.port,
                'service': scan.service,
                'version': scan.version,
                'product': scan.product,
                'risk_score': scan.risk_score,
                'confidence': scan.confidence,
                'scanned_at': scan.scanned_at.isoformat() + 'Z'
            }
            ports_data.append(port_info)
            total_risk_score += scan.risk_score
        
        # Calculate average risk score
        avg_risk_score = total_risk_score / len(ports_data) if ports_data else 0
        
        # Determine overall security status
        if avg_risk_score >= 7:
            security_status = 'critical'
        elif avg_risk_score >= 5:
            security_status = 'high'
        elif avg_risk_score >= 3:
            security_status = 'medium'
        else:
            security_status = 'low'
        
        return jsonify({
            'success': True,
            'device_id': device_id,
            'device_name': device.display_name,
            'open_ports': ports_data,
            'port_count': len(ports_data),
            'avg_risk_score': avg_risk_score,
            'security_status': security_status,
            'period_hours': hours
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/network-overview', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_network_security_overview():
    """Get network-wide security overview"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get all monitored devices
        devices = Device.query.filter_by(is_monitored=True).all()
        
        network_data = {
            'total_devices': len(devices),
            'scanned_devices': 0,
            'devices_with_open_ports': 0,
            'total_open_ports': 0,
            'high_risk_devices': 0,
            'devices': []
        }
        
        for device in devices:
            # Get recent scans for this device
            scans = db.session.query(SecurityScan).filter(
                SecurityScan.device_id == device.id,
                SecurityScan.scanned_at >= start_time,
                SecurityScan.state == 'open'
            ).all()
            
            if scans:
                network_data['scanned_devices'] += 1
                
                open_ports = len(scans)
                if open_ports > 0:
                    network_data['devices_with_open_ports'] += 1
                    network_data['total_open_ports'] += open_ports
                
                # Calculate device risk
                total_risk = sum(scan.risk_score for scan in scans)
                avg_risk = total_risk / open_ports if open_ports > 0 else 0
                
                if avg_risk >= 6:
                    network_data['high_risk_devices'] += 1
                    security_status = 'high'
                elif avg_risk >= 4:
                    security_status = 'medium'
                else:
                    security_status = 'low'
                
                device_info = {
                    'id': device.id,
                    'name': device.display_name,
                    'ip_address': device.ip_address,
                    'open_ports': open_ports,
                    'avg_risk_score': avg_risk,
                    'security_status': security_status,
                    'services': list(set(scan.service for scan in scans))
                }
                network_data['devices'].append(device_info)
        
        return jsonify({
            'success': True,
            'network_overview': network_data,
            'period_hours': hours
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/run-scan', methods=['POST'])
@create_endpoint_limiter('critical')
def run_network_scan():
    """Manually trigger a network-wide security scan"""
    try:
        # Start the background security scan
        result = security_scanner.start_background_scan()
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': result['message'],
                'scan_started': True
            })
        else:
            return jsonify({
                'success': False,
                'error': result['error']
            }), 400
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/scan-progress', methods=['GET'])
@create_endpoint_limiter('critical')
def get_scan_progress():
    """Get current scan progress"""
    try:
        progress = security_scanner.get_scan_progress()

        # Add duration if scan is running or completed
        if progress['start_time']:
            start_time = progress['start_time']
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))

            if progress['status'] == 'running':
                duration = (datetime.utcnow() - start_time).total_seconds()
            elif progress['end_time']:
                end_time = progress['end_time']
                if isinstance(end_time, str):
                    end_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                duration = (end_time - start_time).total_seconds()
            else:
                duration = 0

            progress['duration_seconds'] = int(duration)
            progress['duration_formatted'] = f"{int(duration // 60)}m {int(duration % 60)}s"

        return jsonify({
            'success': True,
            'progress': progress
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/stop-scan', methods=['POST'])
@create_endpoint_limiter('critical')
def stop_network_scan():
    """Stop the currently running network security scan"""
    try:
        result = security_scanner.stop_current_scan()

        if result['success']:
            return jsonify({
                'success': True,
                'message': result['message'],
                'scan_stopped': True
            })
        else:
            return jsonify({
                'success': False,
                'error': result['error']
            }), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@security_bp.route('/risk-assessment', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_risk_assessment():
    """Get network risk assessment"""
    try:
        hours = request.args.get('hours', default=168, type=int)  # Default 7 days
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get all security alerts in the time period
        security_alerts = db.session.query(Alert).filter(
            Alert.alert_type.like('security_%'),
            Alert.created_at >= start_time
        ).all()
        
        # Analyze risk trends
        risk_data = {
            'overall_risk_level': 'low',
            'risk_score': 0,
            'critical_issues': 0,
            'high_risk_issues': 0,
            'medium_risk_issues': 0,
            'low_risk_issues': 0,
            'recommendations': []
        }
        
        for alert in security_alerts:
            if alert.severity == 'critical':
                risk_data['critical_issues'] += 1
                risk_data['risk_score'] += 10
            elif alert.severity == 'high':
                risk_data['high_risk_issues'] += 1
                risk_data['risk_score'] += 7
            elif alert.severity == 'medium':
                risk_data['medium_risk_issues'] += 1
                risk_data['risk_score'] += 4
            else:
                risk_data['low_risk_issues'] += 1
                risk_data['risk_score'] += 1
        
        # Determine overall risk level
        if risk_data['critical_issues'] > 0 or risk_data['risk_score'] > 50:
            risk_data['overall_risk_level'] = 'critical'
        elif risk_data['high_risk_issues'] > 2 or risk_data['risk_score'] > 30:
            risk_data['overall_risk_level'] = 'high'
        elif risk_data['medium_risk_issues'] > 5 or risk_data['risk_score'] > 15:
            risk_data['overall_risk_level'] = 'medium'
        
        # Generate recommendations
        if risk_data['critical_issues'] > 0:
            risk_data['recommendations'].append("Immediate attention required: Critical security issues detected")
        if risk_data['high_risk_issues'] > 0:
            risk_data['recommendations'].append("Review and secure high-risk services")
        
        # Add more specific recommendations based on common issues
        risk_data['recommendations'].extend([
            "Enable automatic security scanning",
            "Regularly update device firmware",
            "Consider using a network firewall",
            "Monitor for unauthorized devices"
        ])
        
        return jsonify({
            'success': True,
            'risk_assessment': risk_data,
            'period_hours': hours
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500