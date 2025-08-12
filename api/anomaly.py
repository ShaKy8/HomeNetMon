from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from services.anomaly_detection import anomaly_detection_service
from models import db, Alert, Device
import json

anomaly_bp = Blueprint('anomaly', __name__)

@anomaly_bp.route('/statistics', methods=['GET'])
def get_anomaly_statistics():
    """Get anomaly detection statistics"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        
        # Cap at 30 days
        if hours > 720:
            hours = 720
        
        stats = anomaly_detection_service.get_anomaly_statistics(hours)
        
        return jsonify({
            'success': True,
            'statistics': stats,
            'period_hours': hours
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@anomaly_bp.route('/alerts', methods=['GET'])
def get_anomaly_alerts():
    """Get recent anomaly alerts"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        limit = request.args.get('limit', default=50, type=int)
        
        # Cap limits
        if hours > 720:
            hours = 720
        if limit > 100:
            limit = 100
        
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Query anomaly alerts
        alerts = db.session.query(Alert).filter(
            Alert.alert_type.like('anomaly_%'),
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
                'alert_type': alert.alert_type.replace('anomaly_', ''),
                'severity': alert.severity,
                'message': alert.message,
                'confidence': metadata.get('confidence', 0.0),
                'baseline_value': metadata.get('baseline_value'),
                'current_value': metadata.get('current_value'),
                'threshold': metadata.get('threshold'),
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

@anomaly_bp.route('/status', methods=['GET'])
def get_anomaly_detection_status():
    """Get anomaly detection engine status"""
    try:
        status = {
            'running': anomaly_detection_service.running,
            'detection_interval': anomaly_detection_service.detection_interval,
            'min_data_points': anomaly_detection_service.min_data_points,
            'baseline_hours': anomaly_detection_service.baseline_hours,
            'anomaly_threshold': anomaly_detection_service.anomaly_threshold,
            'settings': anomaly_detection_service.detection_settings
        }
        
        return jsonify({
            'success': True,
            'status': status
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@anomaly_bp.route('/settings', methods=['GET', 'POST'])
def manage_anomaly_settings():
    """Get or update anomaly detection settings"""
    try:
        if request.method == 'GET':
            return jsonify({
                'success': True,
                'settings': anomaly_detection_service.detection_settings
            })
        
        elif request.method == 'POST':
            data = request.get_json()
            
            # Update settings
            if 'response_time' in data:
                anomaly_detection_service.detection_settings['response_time'].update(
                    data['response_time']
                )
            
            if 'uptime_pattern' in data:
                anomaly_detection_service.detection_settings['uptime_pattern'].update(
                    data['uptime_pattern']
                )
            
            if 'connectivity_pattern' in data:
                anomaly_detection_service.detection_settings['connectivity_pattern'].update(
                    data['connectivity_pattern']
                )
            
            # Update global settings
            if 'detection_interval' in data:
                anomaly_detection_service.detection_interval = data['detection_interval']
            
            if 'baseline_hours' in data:
                anomaly_detection_service.baseline_hours = data['baseline_hours']
            
            if 'anomaly_threshold' in data:
                anomaly_detection_service.anomaly_threshold = data['anomaly_threshold']
            
            return jsonify({
                'success': True,
                'message': 'Anomaly detection settings updated',
                'settings': anomaly_detection_service.detection_settings
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@anomaly_bp.route('/run-detection', methods=['POST'])
def run_manual_detection():
    """Manually trigger anomaly detection cycle"""
    try:
        # Run detection for a specific device or all devices
        data = request.get_json() or {}
        device_id = data.get('device_id')
        
        if device_id:
            # Run detection for specific device
            device = Device.query.get(device_id)
            if not device:
                return jsonify({'error': 'Device not found'}), 404
            
            anomalies = anomaly_detection_service.detect_device_anomalies(device)
            
            if anomalies:
                anomaly_detection_service.process_anomalies(anomalies)
            
            return jsonify({
                'success': True,
                'message': f'Detection completed for device {device.display_name}',
                'anomalies_detected': len(anomalies),
                'anomalies': [
                    {
                        'type': a.anomaly_type,
                        'severity': a.severity,
                        'confidence': a.confidence,
                        'message': a.message
                    } for a in anomalies
                ]
            })
        else:
            # Run full detection cycle
            anomaly_detection_service.run_detection_cycle()
            
            return jsonify({
                'success': True,
                'message': 'Full anomaly detection cycle completed'
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@anomaly_bp.route('/device/<int:device_id>/baseline', methods=['GET'])
def get_device_baseline(device_id):
    """Get baseline statistics for a specific device"""
    try:
        device = Device.query.get(device_id)
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        hours = request.args.get('hours', default=168, type=int)  # 7 days default
        baseline_start = datetime.utcnow() - timedelta(hours=hours)
        recent_start = datetime.utcnow() - timedelta(hours=1)
        
        # Get baseline statistics
        from sqlalchemy import func, and_, case
        from models import MonitoringData
        
        # Response time baseline
        response_stats = db.session.query(
            func.avg(MonitoringData.response_time).label('avg_response'),
            func.stddev(MonitoringData.response_time).label('std_response'),
            func.min(MonitoringData.response_time).label('min_response'),
            func.max(MonitoringData.response_time).label('max_response'),
            func.count(MonitoringData.id).label('total_checks'),
            func.sum(case((MonitoringData.response_time.isnot(None), 1), else_=0)).label('successful_checks')
        ).filter(
            and_(
                MonitoringData.device_id == device_id,
                MonitoringData.timestamp >= baseline_start,
                MonitoringData.timestamp < recent_start
            )
        ).first()
        
        # Recent statistics for comparison
        recent_stats = db.session.query(
            func.avg(MonitoringData.response_time).label('avg_response'),
            func.count(MonitoringData.id).label('total_checks'),
            func.sum(case((MonitoringData.response_time.isnot(None), 1), else_=0)).label('successful_checks')
        ).filter(
            and_(
                MonitoringData.device_id == device_id,
                MonitoringData.timestamp >= recent_start
            )
        ).first()
        
        baseline_data = {
            'device_id': device_id,
            'device_name': device.display_name,
            'baseline_period_hours': hours,
            'baseline_stats': {
                'avg_response_time': float(response_stats.avg_response or 0),
                'std_response_time': float(response_stats.std_response or 0),
                'min_response_time': float(response_stats.min_response or 0),
                'max_response_time': float(response_stats.max_response or 0),
                'uptime_percentage': (response_stats.successful_checks / response_stats.total_checks * 100) if response_stats.total_checks > 0 else 0,
                'total_data_points': response_stats.total_checks or 0
            },
            'recent_stats': {
                'avg_response_time': float(recent_stats.avg_response or 0),
                'uptime_percentage': (recent_stats.successful_checks / recent_stats.total_checks * 100) if recent_stats.total_checks > 0 else 0,
                'total_data_points': recent_stats.total_checks or 0
            }
        }
        
        # Get hourly patterns
        hourly_patterns = anomaly_detection_service.get_hourly_uptime_pattern(
            device, baseline_start, recent_start
        )
        baseline_data['hourly_uptime_patterns'] = hourly_patterns
        
        return jsonify({
            'success': True,
            'baseline': baseline_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500