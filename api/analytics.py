import logging
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_
from models import db, Device, MonitoringData, Alert
from collections import defaultdict
import statistics
from api.rate_limited_endpoints import create_endpoint_limiter

logger = logging.getLogger(__name__)

# Import health score calculation function for consistency
from api.health import calculate_health_score

# Import device analytics service for ML classification
from services.device_analytics import DeviceBehaviorAnalytics
from services.device_learning import DeviceLearningSystem
from services.predictive_failure import FailurePredictionEngine
from services.network_topology import NetworkTopologyEngine
from services.anomaly_detection import AnomalyDetectionEngine

analytics_bp = Blueprint('analytics', __name__)

# Initialize device analytics service
device_analytics = DeviceBehaviorAnalytics()
device_learning = DeviceLearningSystem()
predictive_failure = FailurePredictionEngine()
network_topology = NetworkTopologyEngine()
anomaly_detection = AnomalyDetectionEngine()

@analytics_bp.route('/network-health-score', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_network_health_score():
    """Calculate overall network health score"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        # Consolidated query for device stats (2 counts in one query)
        device_stats = db.session.query(
            func.count(Device.id).label('total_devices'),
            func.sum(
                func.cast(Device.last_seen >= cutoff, db.Integer)
            ).label('devices_up')
        ).filter(Device.is_monitored == True).first()

        total_devices = device_stats.total_devices or 0
        if total_devices == 0:
            return jsonify({'error': 'No monitored devices found'}), 404

        devices_up = device_stats.devices_up or 0

        # Consolidated query for monitoring metrics (avg, total, successful in one query)
        monitoring_stats = db.session.query(
            func.avg(MonitoringData.response_time).label('avg_response'),
            func.count(MonitoringData.id).label('total_pings'),
            func.count(MonitoringData.response_time).label('successful_pings')
        ).filter(MonitoringData.timestamp >= cutoff).first()

        avg_response = monitoring_stats.avg_response or 0
        total_pings = monitoring_stats.total_pings or 0
        successful_pings = monitoring_stats.successful_pings or 0

        success_rate = (successful_pings / total_pings * 100) if total_pings > 0 else 0
        uptime_percentage = (devices_up / total_devices * 100)

        # Active alerts count
        active_alerts = Alert.query.filter_by(resolved=False).count()
        
        # Use standardized health score calculation (consistent with Health Overview)
        health_score = calculate_health_score(
            devices_up, total_devices, avg_response, active_alerts, success_rate
        )
        
        # Determine health status
        if health_score >= 90:
            status = 'excellent'
            status_color = '#28a745'
        elif health_score >= 75:
            status = 'good'
            status_color = '#17a2b8'
        elif health_score >= 60:
            status = 'fair'
            status_color = '#ffc107'
        elif health_score >= 40:
            status = 'poor'
            status_color = '#fd7e14'
        else:
            status = 'critical'
            status_color = '#dc3545'
        
        return jsonify({
            'health_score': round(health_score, 1),
            'status': status,
            'status_color': status_color,
            'metrics': {
                'total_devices': total_devices,
                'devices_up': devices_up,
                'devices_online': devices_up,  # Alias for consistency with Health Overview
                'uptime_percentage': round(uptime_percentage, 1),
                'avg_response_time': round(avg_response, 2),
                'success_rate': round(success_rate, 1),
                'total_pings': total_pings,
                'successful_pings': successful_pings,
                'active_alerts': active_alerts
            },
            'recommendations': generate_health_recommendations(health_score, avg_response, success_rate, active_alerts)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/device-insights', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_general_device_insights():
    """Get insights about device patterns and behavior"""
    try:
        hours = request.args.get('hours', default=168, type=int)  # Default 7 days
        uptime_days = hours // 24 if hours >= 24 else 1

        # Fetch all monitored devices once
        devices = Device.query.filter_by(is_monitored=True).all()
        device_ids = [d.id for d in devices]

        # Batch fetch uptime and monitoring data to avoid N+1 queries
        batch_data = Device.batch_get_device_data(device_ids, include_uptime=True, uptime_days=uptime_days)

        # Build device list with uptime from batch data
        devices_with_uptime = []
        fastest_devices = []
        for device in devices:
            uptime = batch_data['uptime_percentages'].get(device.id, 0)
            devices_with_uptime.append({
                'id': device.id,
                'name': device.display_name,
                'ip': device.ip_address,
                'uptime': uptime,
                'type': device.device_type
            })

            # Get response time from batch monitoring data
            monitoring_data = batch_data['monitoring_data'].get(device.id)
            if monitoring_data and monitoring_data.response_time is not None:
                fastest_devices.append({
                    'id': device.id,
                    'name': device.display_name,
                    'ip': device.ip_address,
                    'response_time': monitoring_data.response_time
                })

        # Sort by uptime
        most_reliable = sorted(devices_with_uptime, key=lambda x: x['uptime'], reverse=True)[:5]
        least_reliable = sorted(devices_with_uptime, key=lambda x: x['uptime'])[:5]

        # Device type analysis
        type_stats = defaultdict(lambda: {'count': 0, 'avg_uptime': 0, 'total_uptime': 0})
        for device_data in devices_with_uptime:
            device_type = device_data['type'] or 'Unknown'
            type_stats[device_type]['count'] += 1
            type_stats[device_type]['total_uptime'] += device_data['uptime']

        # Calculate average uptime per type
        for type_name, stats in type_stats.items():
            stats['avg_uptime'] = round(stats['total_uptime'] / stats['count'], 1)

        # Convert to list for JSON
        device_types = [
            {
                'type': type_name,
                'count': stats['count'],
                'avg_uptime': stats['avg_uptime']
            }
            for type_name, stats in type_stats.items()
        ]
        device_types.sort(key=lambda x: x['avg_uptime'], reverse=True)

        # Sort response times
        fastest_devices.sort(key=lambda x: x['response_time'])
        fastest_top5 = fastest_devices[:5]
        slowest_top5 = fastest_devices[-5:] if len(fastest_devices) >= 5 else []

        return jsonify({
            'most_reliable': most_reliable,
            'least_reliable': least_reliable,
            'device_types': device_types,
            'fastest_devices': fastest_top5,
            'slowest_devices': slowest_top5,
            'summary': {
                'total_monitored': len(devices_with_uptime),
                'avg_network_uptime': round(statistics.mean([d['uptime'] for d in devices_with_uptime]) if devices_with_uptime else 0, 1),
                'device_type_count': len(device_types)
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/usage-patterns', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_usage_patterns():
    """Analyze device usage patterns over time"""
    try:
        days = request.args.get('days', default=7, type=int)
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        # Hourly activity pattern
        hourly_activity = defaultdict(lambda: {'total_pings': 0, 'successful_pings': 0})
        
        # Get monitoring data grouped by hour
        monitoring_data = MonitoringData.query.filter(
            MonitoringData.timestamp >= cutoff
        ).all()
        
        for data in monitoring_data:
            hour = data.timestamp.hour
            hourly_activity[hour]['total_pings'] += 1
            if data.response_time is not None:
                hourly_activity[hour]['successful_pings'] += 1
        
        # Convert to chart data
        hourly_chart = []
        for hour in range(24):
            activity = hourly_activity[hour]
            success_rate = (activity['successful_pings'] / activity['total_pings'] * 100) if activity['total_pings'] > 0 else 0
            hourly_chart.append({
                'hour': f"{hour:02d}:00",
                'total_pings': activity['total_pings'],
                'success_rate': round(success_rate, 1)
            })
        
        # Daily patterns
        daily_activity = defaultdict(lambda: {'devices_seen': 0, 'total_responses': 0, 'avg_response': 0})
        
        # Group by day
        for data in monitoring_data:
            day_key = data.timestamp.strftime('%Y-%m-%d')
            daily_activity[day_key]['total_responses'] += 1
            if data.response_time is not None:
                daily_activity[day_key]['avg_response'] += data.response_time
        
        # Calculate daily averages
        daily_chart = []
        for day_key, activity in daily_activity.items():
            avg_response = activity['avg_response'] / activity['total_responses'] if activity['total_responses'] > 0 else 0
            daily_chart.append({
                'date': day_key,
                'total_responses': activity['total_responses'],
                'avg_response_time': round(avg_response, 2)
            })
        
        daily_chart.sort(key=lambda x: x['date'])
        
        # Peak usage analysis
        peak_hour = max(hourly_activity.items(), key=lambda x: x[1]['total_pings'])
        quiet_hour = min(hourly_activity.items(), key=lambda x: x[1]['total_pings'])
        
        return jsonify({
            'hourly_patterns': hourly_chart,
            'daily_trends': daily_chart,
            'insights': {
                'peak_hour': f"{peak_hour[0]:02d}:00",
                'peak_activity': peak_hour[1]['total_pings'],
                'quiet_hour': f"{quiet_hour[0]:02d}:00",
                'quiet_activity': quiet_hour[1]['total_pings'],
                'total_data_points': len(monitoring_data)
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/network-trends', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_network_trends():
    """Get network performance trends over time"""
    try:
        days = request.args.get('days', default=30, type=int)
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        # Daily performance metrics
        daily_metrics = defaultdict(lambda: {
            'response_times': [],
            'success_count': 0,
            'total_count': 0,
            'unique_devices': set()
        })
        
        # Get all monitoring data for the period
        monitoring_data = MonitoringData.query.filter(
            MonitoringData.timestamp >= cutoff
        ).all()
        
        for data in monitoring_data:
            day_key = data.timestamp.strftime('%Y-%m-%d')
            daily_metrics[day_key]['total_count'] += 1
            daily_metrics[day_key]['unique_devices'].add(data.device_id)
            
            if data.response_time is not None:
                daily_metrics[day_key]['success_count'] += 1
                daily_metrics[day_key]['response_times'].append(data.response_time)
        
        # Process into trend data
        trend_data = []
        for day_key, metrics in daily_metrics.items():
            avg_response = statistics.mean(metrics['response_times']) if metrics['response_times'] else 0
            success_rate = (metrics['success_count'] / metrics['total_count'] * 100) if metrics['total_count'] > 0 else 0
            
            trend_data.append({
                'date': day_key,
                'avg_response_time': round(avg_response, 2),
                'success_rate': round(success_rate, 1),
                'total_pings': metrics['total_count'],
                'active_devices': len(metrics['unique_devices'])
            })
        
        trend_data.sort(key=lambda x: x['date'])
        
        # Calculate trend direction
        if len(trend_data) >= 2:
            recent_avg = statistics.mean([d['avg_response_time'] for d in trend_data[-7:] if d['avg_response_time'] > 0])
            older_avg = statistics.mean([d['avg_response_time'] for d in trend_data[-14:-7] if d['avg_response_time'] > 0])
            
            response_trend = 'improving' if recent_avg < older_avg else 'degrading' if recent_avg > older_avg else 'stable'
            
            recent_success = statistics.mean([d['success_rate'] for d in trend_data[-7:]])
            older_success = statistics.mean([d['success_rate'] for d in trend_data[-14:-7]])
            
            reliability_trend = 'improving' if recent_success > older_success else 'degrading' if recent_success < older_success else 'stable'
        else:
            response_trend = reliability_trend = 'insufficient_data'
        
        return jsonify({
            'trend_data': trend_data,
            'analysis': {
                'response_trend': response_trend,
                'reliability_trend': reliability_trend,
                'data_points': len(monitoring_data),
                'date_range': {
                    'start': cutoff.strftime('%Y-%m-%d'),
                    'end': datetime.utcnow().strftime('%Y-%m-%d')
                }
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_health_recommendations(health_score, avg_response, success_rate, active_alerts=0):
    """Generate health improvement recommendations"""
    recommendations = []
    
    if health_score < 60:
        recommendations.append("⚠️ Network health is below acceptable levels. Immediate attention required.")
    
    if active_alerts > 0:
        recommendations.append(f"🚨 {active_alerts} active alert{'s' if active_alerts > 1 else ''} detected. Review alerts page for details.")
    
    if avg_response > 1000:
        recommendations.append("🐌 High response times detected. Check network congestion or device issues.")
    
    if success_rate < 90:
        recommendations.append("📡 Low ping success rate. Verify device connectivity and network stability.")
    
    if success_rate < 70:
        recommendations.append("🔧 Consider checking network infrastructure and device configurations.")
    
    if health_score >= 90 and active_alerts == 0:
        recommendations.append("✅ Excellent network performance! Keep up the great monitoring.")
    elif health_score >= 75 and active_alerts <= 2:
        recommendations.append("👍 Good network health. Minor optimizations could improve performance.")
    
    if len(recommendations) == 0:
        recommendations.append("📊 Monitor trends over time to identify patterns and potential issues.")
    
    return recommendations

# Machine Learning Device Classification Endpoints

@analytics_bp.route('/devices/<int:device_id>/classify', methods=['POST'])
@create_endpoint_limiter('strict')
def classify_device(device_id):
    """Classify a device using machine learning behavior analysis"""
    try:
        days = request.json.get('days', 7) if request.is_json else request.args.get('days', default=7, type=int)
        
        # Validate device exists
        device = Device.query.get_or_404(device_id)
        
        # Perform classification
        classification_result = device_analytics.classify_device(device_id, days=days)
        
        return jsonify({
            'device_id': device_id,
            'device_name': device.display_name,
            'classification': classification_result,
            'analysis_period_days': days,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/devices/<int:device_id>/insights', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_insights(device_id):
    """Get comprehensive device insights including behavior analysis"""
    try:
        days = request.args.get('days', default=7, type=int)
        
        # Validate device exists
        device = Device.query.get_or_404(device_id)
        
        # Get device insights
        insights = device_analytics.get_device_insights(device_id, days=days)
        
        return jsonify({
            'device_id': device_id,
            'device_name': device.display_name,
            'insights': insights,
            'analysis_period_days': days,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/devices/<int:device_id>/behavior', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_behavior(device_id):
    """Get detailed device behavior analysis"""
    try:
        days = request.args.get('days', default=7, type=int)
        
        # Validate device exists
        device = Device.query.get_or_404(device_id)
        
        # Get behavior analysis
        behavior = device_analytics.analyze_device_behavior(device_id, days=days)
        
        return jsonify({
            'device_id': device_id,
            'device_name': device.display_name,
            'behavior_analysis': {
                'response_time_characteristics': behavior.response_time_characteristics,
                'uptime_patterns': behavior.uptime_patterns,
                'vendor_analysis': behavior.vendor_analysis,
                'hostname_analysis': behavior.hostname_analysis,
                'confidence_scores': behavior.confidence_scores,
                'reasoning': behavior.reasoning
            },
            'analysis_period_days': days,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/devices/classify-all', methods=['POST'])
@create_endpoint_limiter('bulk')
def classify_all_devices():
    """Classify all monitored devices using machine learning"""
    try:
        days = request.json.get('days', 7) if request.is_json else 7
        
        # Get all monitored devices
        devices = Device.query.filter_by(is_monitored=True).all()
        
        if not devices:
            return jsonify({'error': 'No monitored devices found'}), 404
        
        results = []
        for device in devices:
            try:
                classification = device_analytics.classify_device(device.id, days=days)
                results.append({
                    'device_id': device.id,
                    'device_name': device.display_name,
                    'ip_address': device.ip_address,
                    'current_type': device.device_type,
                    'classification': classification
                })
            except Exception as e:
                results.append({
                    'device_id': device.id,
                    'device_name': device.display_name,
                    'ip_address': device.ip_address,
                    'error': str(e)
                })
        
        return jsonify({
            'total_devices': len(devices),
            'successful_classifications': len([r for r in results if 'classification' in r]),
            'failed_classifications': len([r for r in results if 'error' in r]),
            'results': results,
            'analysis_period_days': days,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/analytics/summary', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_analytics_summary():
    """Get system-wide analytics summary including ML insights"""
    try:
        days = request.args.get('days', default=7, type=int)
        
        # Get all monitored devices
        devices = Device.query.filter_by(is_monitored=True).all()
        
        if not devices:
            return jsonify({'error': 'No monitored devices found'}), 404
        
        # Classify all devices and gather statistics
        device_classifications = {}
        classification_confidence = {}
        device_type_distribution = defaultdict(int)
        high_confidence_classifications = 0
        
        for device in devices:
            try:
                classification = device_analytics.classify_device(device.id, days=days)
                device_classifications[device.id] = classification
                
                predicted_type = classification.get('device_type', 'unknown')
                confidence = classification.get('confidence', 0)
                
                device_type_distribution[predicted_type] += 1
                classification_confidence[device.id] = confidence
                
                if confidence >= 0.8:  # High confidence threshold
                    high_confidence_classifications += 1
                    
            except Exception as e:
                device_classifications[device.id] = {'error': str(e)}
        
        # Calculate analytics summary
        total_devices = len(devices)
        successful_classifications = len([c for c in device_classifications.values() if 'error' not in c])
        avg_confidence = statistics.mean([c for c in classification_confidence.values()]) if classification_confidence else 0
        
        # Device type insights
        most_common_type = max(device_type_distribution.items(), key=lambda x: x[1]) if device_type_distribution else ('unknown', 0)
        
        # Performance insights
        performance_summary = device_analytics.get_performance_summary(days=days)
        
        return jsonify({
            'summary': {
                'total_devices': total_devices,
                'successful_classifications': successful_classifications,
                'classification_success_rate': round((successful_classifications / total_devices * 100), 1),
                'high_confidence_classifications': high_confidence_classifications,
                'average_confidence': round(avg_confidence, 3),
                'most_common_device_type': most_common_type[0],
                'most_common_type_count': most_common_type[1]
            },
            'device_type_distribution': dict(device_type_distribution),
            'confidence_distribution': {
                'high_confidence': len([c for c in classification_confidence.values() if c >= 0.8]),
                'medium_confidence': len([c for c in classification_confidence.values() if 0.6 <= c < 0.8]),
                'low_confidence': len([c for c in classification_confidence.values() if c < 0.6])
            },
            'performance_insights': performance_summary,
            'analysis_period_days': days,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/analytics/learning-status', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_learning_status():
    """Get status of the machine learning system"""
    try:
        return jsonify({
            'learning_enabled': device_analytics.learning_enabled,
            'cached_profiles': len(device_analytics.device_profiles),
            'confidence_thresholds': device_analytics.confidence_thresholds,
            'classification_rules_loaded': len(device_analytics.classification_rules),
            'last_analysis_cache_size': len(device_analytics._analysis_cache) if hasattr(device_analytics, '_analysis_cache') else 0,
            'system_status': 'active' if device_analytics.learning_enabled else 'disabled',
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/analytics/performance-trends', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_performance_trends():
    """Get performance trends across all devices using analytics"""
    try:
        days = request.args.get('days', default=30, type=int)
        
        # Get performance summary from analytics service
        performance_summary = device_analytics.get_performance_summary(days=days)
        
        # Get trend analysis
        trend_analysis = device_analytics.analyze_performance_trends(days=days)
        
        return jsonify({
            'performance_summary': performance_summary,
            'trend_analysis': trend_analysis,
            'analysis_period_days': days,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Device Fingerprinting Endpoints

@analytics_bp.route('/devices/<int:device_id>/fingerprint', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_fingerprint(device_id):
    """Generate unique device fingerprint based on behavioral patterns"""
    try:
        days = request.args.get('days', default=14, type=int)
        
        # Validate device exists
        device = Device.query.get_or_404(device_id)
        
        # Generate fingerprint
        fingerprint = device_analytics.generate_device_fingerprint(device_id, days=days)
        
        return jsonify(fingerprint)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/devices/<int:device_id1>/compare/<int:device_id2>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def compare_device_fingerprints(device_id1, device_id2):
    """Compare behavioral fingerprints between two devices"""
    try:
        days = request.args.get('days', default=14, type=int)
        
        # Validate devices exist
        device1 = Device.query.get_or_404(device_id1)
        device2 = Device.query.get_or_404(device_id2)
        
        # Compare fingerprints
        comparison = device_analytics.compare_device_fingerprints(device_id1, device_id2, days=days)
        
        return jsonify(comparison)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/analytics/fingerprints/similar', methods=['GET'])
@create_endpoint_limiter('relaxed')
def find_similar_devices():
    """Find devices with similar behavioral fingerprints"""
    try:
        days = request.args.get('days', default=14, type=int)
        similarity_threshold = request.args.get('threshold', default=0.7, type=float)
        
        # Get all monitored devices
        devices = Device.query.filter_by(is_monitored=True).all()
        
        if len(devices) < 2:
            return jsonify({'error': 'Need at least 2 devices for comparison'}), 400
        
        similar_groups = []
        processed_devices = set()
        
        for i, device1 in enumerate(devices):
            if device1.id in processed_devices:
                continue
                
            similar_devices = [device1]
            
            for j, device2 in enumerate(devices[i+1:], i+1):
                if device2.id in processed_devices:
                    continue
                    
                try:
                    comparison = device_analytics.compare_device_fingerprints(device1.id, device2.id, days=days)
                    
                    if 'error' not in comparison:
                        overall_similarity = comparison['similarity_scores']['overall']
                        
                        if overall_similarity >= similarity_threshold:
                            similar_devices.append(device2)
                            processed_devices.add(device2.id)
                            
                except Exception as e:
                    logger.warning(f"Error comparing devices {device1.id} and {device2.id}: {e}")
                    continue
            
            if len(similar_devices) > 1:
                group_info = {
                    'group_id': f"group_{i}",
                    'devices': [
                        {
                            'id': dev.id,
                            'name': dev.display_name,
                            'ip_address': dev.ip_address,
                            'device_type': dev.device_type
                        } for dev in similar_devices
                    ],
                    'device_count': len(similar_devices)
                }
                similar_groups.append(group_info)
                
                for device in similar_devices:
                    processed_devices.add(device.id)
        
        return jsonify({
            'similar_groups': similar_groups,
            'total_groups': len(similar_groups),
            'similarity_threshold': similarity_threshold,
            'analysis_period_days': days,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/analytics/fingerprints/patterns', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_fingerprint_patterns():
    """Analyze patterns across all device fingerprints"""
    try:
        days = request.args.get('days', default=14, type=int)
        
        # Get all monitored devices
        devices = Device.query.filter_by(is_monitored=True).all()
        
        if not devices:
            return jsonify({'error': 'No monitored devices found'}), 404
        
        # Generate fingerprints for all devices
        fingerprints = []
        pattern_analysis = {
            'response_patterns': defaultdict(int),
            'temporal_patterns': defaultdict(int),
            'failure_patterns': defaultdict(int),
            'vendor_patterns': defaultdict(int),
            'hostname_patterns': defaultdict(int)
        }
        
        for device in devices:
            try:
                fp = device_analytics.generate_device_fingerprint(device.id, days=days)
                
                if 'error' not in fp:
                    fingerprints.append(fp)
                    
                    # Extract patterns for analysis
                    components = fp['components']
                    
                    response_sig = components.get('response_signature', {})
                    pattern_analysis['response_patterns'][response_sig.get('pattern_type', 'unknown')] += 1
                    
                    temporal_sig = components.get('temporal_signature', {})
                    pattern_analysis['temporal_patterns'][temporal_sig.get('temporal_pattern_type', 'unknown')] += 1
                    
                    failure_sig = components.get('failure_signature', {})
                    pattern_analysis['failure_patterns'][failure_sig.get('failure_pattern_type', 'unknown')] += 1
                    
                    network_sig = components.get('network_signature', {})
                    vendor = network_sig.get('mac_vendor_analysis', {}).get('vendor', 'unknown')
                    pattern_analysis['vendor_patterns'][vendor] += 1
                    
                    hostname_pattern = network_sig.get('hostname_analysis', {}).get('pattern', 'unknown')
                    pattern_analysis['hostname_patterns'][hostname_pattern] += 1
                    
            except Exception as e:
                logger.warning(f"Error generating fingerprint for device {device.id}: {e}")
                continue
        
        # Calculate pattern statistics
        total_fingerprints = len(fingerprints)
        
        pattern_summary = {}
        for pattern_type, patterns in pattern_analysis.items():
            pattern_summary[pattern_type] = {
                'most_common': max(patterns.items(), key=lambda x: x[1]) if patterns else ('none', 0),
                'distribution': dict(patterns),
                'unique_patterns': len(patterns)
            }
        
        # Calculate fingerprint diversity
        unique_fingerprints = len(set(fp['fingerprint_hash'] for fp in fingerprints))
        diversity_score = unique_fingerprints / total_fingerprints if total_fingerprints > 0 else 0
        
        return jsonify({
            'summary': {
                'total_devices': len(devices),
                'successful_fingerprints': total_fingerprints,
                'unique_fingerprints': unique_fingerprints,
                'diversity_score': round(diversity_score, 3)
            },
            'pattern_analysis': pattern_summary,
            'fingerprints': fingerprints,
            'analysis_period_days': days,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Device Learning System Endpoints

@analytics_bp.route('/devices/<int:device_id>/feedback', methods=['POST'])
@create_endpoint_limiter('strict')
def submit_device_feedback():
    """Submit user feedback for device classification learning"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        data = request.get_json()
        device_id = data.get('device_id')
        predicted_type = data.get('predicted_type', '')
        actual_type = data.get('actual_type', '')
        confidence = data.get('confidence', 0.0)
        feedback_type = data.get('feedback_type', 'correction')
        
        if not all([device_id, predicted_type, actual_type]):
            return jsonify({'error': 'device_id, predicted_type, and actual_type are required'}), 400
        
        # Validate device exists
        device = Device.query.get_or_404(device_id)
        
        # Record feedback
        result = device_learning.record_user_feedback(
            device_id=device_id,
            predicted_type=predicted_type,
            actual_type=actual_type,
            confidence=confidence,
            feedback_type=feedback_type
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/devices/<int:device_id>/classify-learned', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_learned_classification(device_id):
    """Get device classification enhanced with learning data"""
    try:
        # Validate device exists
        device = Device.query.get_or_404(device_id)
        
        # Get learned classification
        classification = device_learning.get_learned_classification(device_id)
        
        return jsonify({
            'device_id': device_id,
            'device_name': device.display_name,
            'classification': classification,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/learning/train-historical', methods=['POST'])
@create_endpoint_limiter('strict')
def train_on_historical_data():
    """Train learning system on historical device behavior data"""
    try:
        days = request.json.get('days', 30) if request.is_json else 30
        
        # Run historical training
        result = device_learning.train_on_historical_data(days=days)
        
        return jsonify({
            'training_results': result,
            'training_period_days': days,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/learning/statistics', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_learning_statistics():
    """Get comprehensive learning system statistics"""
    try:
        stats = device_learning.get_learning_statistics()
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/learning/export', methods=['GET'])
@create_endpoint_limiter('relaxed')
def export_learning_data():
    """Export learning data for backup or analysis"""
    try:
        export_data = device_learning.export_learning_data()
        
        return jsonify({
            'export_successful': 'error' not in export_data,
            'data': export_data,
            'export_timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/learning/import', methods=['POST'])
@create_endpoint_limiter('strict')
def import_learning_data():
    """Import learning data from backup"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        import_data = request.get_json()
        if 'data' not in import_data:
            return jsonify({'error': 'Missing data field in request'}), 400
        
        # Import learning data
        result = device_learning.import_learning_data(import_data['data'])
        
        return jsonify({
            'import_results': result,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/learning/devices/enhanced-classification', methods=['GET'])
@create_endpoint_limiter('bulk')
def get_all_enhanced_classifications():
    """Get enhanced classifications for all devices using learning data"""
    try:
        # Get all monitored devices
        devices = Device.query.filter_by(is_monitored=True).all()
        
        if not devices:
            return jsonify({'error': 'No monitored devices found'}), 404
        
        enhanced_classifications = []
        learning_improvements = 0
        
        for device in devices:
            try:
                classification = device_learning.get_learned_classification(device.id)
                
                enhanced_classifications.append({
                    'device_id': device.id,
                    'device_name': device.display_name,
                    'ip_address': device.ip_address,
                    'current_type': device.device_type,
                    'enhanced_classification': classification
                })
                
                if classification.get('learning_applied', False):
                    learning_improvements += 1
                    
            except Exception as e:
                enhanced_classifications.append({
                    'device_id': device.id,
                    'device_name': device.display_name,
                    'ip_address': device.ip_address,
                    'error': str(e)
                })
        
        return jsonify({
            'total_devices': len(devices),
            'successful_classifications': len([c for c in enhanced_classifications if 'error' not in c]),
            'learning_improvements': learning_improvements,
            'enhanced_classifications': enhanced_classifications,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/learning/performance-comparison', methods=['GET'])
@create_endpoint_limiter('relaxed')
def compare_learning_performance():
    """Compare base classification vs learned classification performance"""
    try:
        # Get all monitored devices
        devices = Device.query.filter_by(is_monitored=True).all()
        
        if not devices:
            return jsonify({'error': 'No monitored devices found'}), 404
        
        comparison_results = {
            'base_vs_learned': [],
            'improvements': 0,
            'confidence_increases': 0,
            'type_changes': 0
        }
        
        for device in devices:
            try:
                # Get base classification
                base_classification = device_analytics.classify_device(device.id, days=7)
                
                # Get learned classification
                learned_classification = device_learning.get_learned_classification(device.id)
                
                if 'error' not in base_classification and 'error' not in learned_classification:
                    device_comparison = {
                        'device_id': device.id,
                        'device_name': device.display_name,
                        'base_classification': base_classification,
                        'learned_classification': learned_classification,
                        'learning_applied': learned_classification.get('learning_applied', False)
                    }
                    
                    comparison_results['base_vs_learned'].append(device_comparison)
                    
                    # Track improvements
                    if learned_classification.get('learning_applied', False):
                        comparison_results['improvements'] += 1
                        
                        if learned_classification.get('confidence', 0) > base_classification.get('confidence', 0):
                            comparison_results['confidence_increases'] += 1
                        
                        if learned_classification.get('device_type') != base_classification.get('device_type'):
                            comparison_results['type_changes'] += 1
                    
            except Exception as e:
                logger.warning(f"Error comparing classifications for device {device.id}: {e}")
                continue
        
        return jsonify({
            'comparison_summary': {
                'total_devices_compared': len(comparison_results['base_vs_learned']),
                'devices_with_learning': comparison_results['improvements'],
                'confidence_improvements': comparison_results['confidence_increases'],
                'classification_changes': comparison_results['type_changes']
            },
            'detailed_comparison': comparison_results['base_vs_learned'],
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Predictive Failure Analysis Endpoints

@analytics_bp.route('/devices/<int:device_id>/failure-risk', methods=['GET'])
@create_endpoint_limiter('relaxed')
def analyze_device_failure_risk(device_id):
    """Analyze failure risk for a specific device"""
    try:
        days = request.args.get('days', default=30, type=int)
        
        # Validate device exists
        device = Device.query.get_or_404(device_id)
        
        # Analyze failure risk
        risk_analysis = predictive_failure.analyze_failure_risk(device_id, days=days)
        
        return jsonify(risk_analysis)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/devices/<int:device_id>/mtbf', methods=['GET'])
@create_endpoint_limiter('relaxed')
def predict_device_mtbf(device_id):
    """Predict Mean Time Between Failures for a device"""
    try:
        days = request.args.get('days', default=90, type=int)
        
        # Validate device exists
        device = Device.query.get_or_404(device_id)
        
        # Predict MTBF
        mtbf_prediction = predictive_failure.predict_device_mtbf(device_id, days=days)
        
        return jsonify(mtbf_prediction)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/failure-patterns', methods=['GET'])
@create_endpoint_limiter('relaxed')
def analyze_failure_patterns():
    """Analyze failure patterns across all devices"""
    try:
        days = request.args.get('days', default=30, type=int)
        
        # Analyze patterns
        pattern_analysis = predictive_failure.analyze_failure_patterns(days=days)
        
        return jsonify(pattern_analysis)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/network-failure-risk', methods=['GET'])
@create_endpoint_limiter('relaxed')
def analyze_network_failure_risk():
    """Analyze overall network failure risk"""
    try:
        days = request.args.get('days', default=14, type=int)
        
        # Analyze network risk
        network_risk = predictive_failure.analyze_network_failure_risk(days=days)
        
        return jsonify(network_risk)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/early-warning/status', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_early_warning_status():
    """Get current early warning system status"""
    try:
        status = predictive_failure.get_early_warning_status()
        return jsonify(status)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/devices/failure-predictions', methods=['GET'])
@create_endpoint_limiter('bulk')
def get_all_failure_predictions():
    """Get failure predictions for all monitored devices"""
    try:
        days = request.args.get('days', default=14, type=int)
        risk_threshold = request.args.get('threshold', default='low', type=str)
        
        # Map threshold names to values
        threshold_map = {
            'minimal': 0.0,
            'low': 0.25,
            'medium': 0.50,
            'high': 0.70,
            'critical': 0.85
        }
        
        threshold_value = threshold_map.get(risk_threshold, 0.25)
        
        # Get all monitored devices
        devices = Device.query.filter_by(is_monitored=True).all()
        
        if not devices:
            return jsonify({'error': 'No monitored devices found'}), 404
        
        predictions = []
        high_risk_count = 0
        critical_risk_count = 0
        
        for device in devices:
            try:
                risk_analysis = predictive_failure.analyze_failure_risk(device.id, days=days)
                
                if 'error' not in risk_analysis:
                    risk_score = risk_analysis.get('risk_score', 0)
                    risk_level = risk_analysis.get('risk_level', 'minimal')
                    
                    # Only include devices above threshold
                    if risk_score >= threshold_value:
                        predictions.append({
                            'device_id': device.id,
                            'device_name': device.display_name,
                            'ip_address': device.ip_address,
                            'device_type': device.device_type,
                            'risk_analysis': risk_analysis
                        })
                        
                        if risk_level in ['high', 'critical']:
                            high_risk_count += 1
                        if risk_level == 'critical':
                            critical_risk_count += 1
                
            except Exception as e:
                logger.warning(f"Error analyzing device {device.id}: {e}")
                continue
        
        return jsonify({
            'total_devices_analyzed': len(devices),
            'devices_above_threshold': len(predictions),
            'high_risk_devices': high_risk_count,
            'critical_risk_devices': critical_risk_count,
            'threshold_used': risk_threshold,
            'predictions': predictions,
            'analysis_period_days': days,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/failure-cascades', methods=['GET'])
@create_endpoint_limiter('relaxed')
def analyze_failure_cascades():
    """Analyze potential failure cascade scenarios"""
    try:
        days = request.args.get('days', default=30, type=int)
        
        # Get failure patterns which include cascade analysis
        patterns = predictive_failure.analyze_failure_patterns(days=days)
        
        if 'error' in patterns:
            return jsonify(patterns), 500
        
        # Extract cascade-specific information
        cascade_analysis = {
            'historical_cascades': patterns['pattern_analysis']['failure_cascades'],
            'cascade_risk_factors': patterns['pattern_analysis']['network_impact_analysis'],
            'temporal_patterns': patterns['pattern_analysis']['temporal_patterns'],
            'common_sequences': patterns['pattern_analysis']['common_failure_sequences'],
            'analysis_summary': {
                'total_cascades_detected': len(patterns['pattern_analysis']['failure_cascades']),
                'analysis_period_days': days,
                'total_failures_analyzed': patterns['total_failures']
            }
        }
        
        # Add cascade probability assessment
        network_risk = predictive_failure.analyze_network_failure_risk(days=days)
        if 'error' not in network_risk:
            cascade_analysis['current_cascade_probability'] = network_risk['network_risk_analysis']['cascade_probability']
            cascade_analysis['infrastructure_risk'] = network_risk['network_risk_analysis']['infrastructure_risk']
        
        return jsonify({
            'cascade_analysis': cascade_analysis,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/failure-hotspots', methods=['GET'])
@create_endpoint_limiter('relaxed')
def identify_failure_hotspots():
    """Identify network failure hotspots and problem areas"""
    try:
        days = request.args.get('days', default=30, type=int)
        
        # Get failure patterns
        patterns = predictive_failure.analyze_failure_patterns(days=days)
        
        if 'error' in patterns:
            return jsonify(patterns), 500
        
        # Analyze hotspots
        pattern_data = patterns['pattern_analysis']
        
        # Device type hotspots
        device_type_hotspots = []
        for device_type, stats in pattern_data['device_type_patterns'].items():
            if stats['total_devices'] > 0:
                failure_rate = stats['failures'] / stats['total_devices']
                if failure_rate > 0.1:  # 10% or more devices of this type failing
                    device_type_hotspots.append({
                        'device_type': device_type,
                        'failure_rate': round(failure_rate, 3),
                        'affected_devices': stats['failures'],
                        'total_devices': stats['total_devices'],
                        'severity': 'high' if failure_rate > 0.3 else 'medium'
                    })
        
        # Vendor hotspots
        vendor_hotspots = []
        for vendor, stats in pattern_data['vendor_patterns'].items():
            if stats['total_devices'] > 1:  # Only consider vendors with multiple devices
                failure_rate = stats['failures'] / stats['total_devices']
                if failure_rate > 0.2:  # 20% or more devices from this vendor failing
                    vendor_hotspots.append({
                        'vendor': vendor,
                        'failure_rate': round(failure_rate, 3),
                        'affected_devices': stats['failures'],
                        'total_devices': stats['total_devices'],
                        'severity': 'high' if failure_rate > 0.4 else 'medium'
                    })
        
        # Temporal hotspots
        temporal_patterns = pattern_data['temporal_patterns']
        peak_failure_times = temporal_patterns.get('peak_failure_times', [])
        
        # Get current high-risk devices for location analysis
        network_risk = predictive_failure.analyze_network_failure_risk(days=days)
        geographic_hotspots = []
        
        if 'error' not in network_risk:
            high_risk_devices = network_risk['network_risk_analysis']['high_risk_devices']
            
            # Group by IP subnet to identify geographic hotspots
            subnet_failures = defaultdict(list)
            for device_info in high_risk_devices:
                ip = device_info['ip_address']
                if ip:
                    subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
                    subnet_failures[subnet].append(device_info)
            
            for subnet, devices in subnet_failures.items():
                if len(devices) >= 2:  # At least 2 devices in same subnet
                    geographic_hotspots.append({
                        'subnet': subnet,
                        'affected_devices': len(devices),
                        'devices': devices,
                        'severity': 'high' if len(devices) >= 3 else 'medium'
                    })
        
        return jsonify({
            'failure_hotspots': {
                'device_type_hotspots': sorted(device_type_hotspots, key=lambda x: x['failure_rate'], reverse=True),
                'vendor_hotspots': sorted(vendor_hotspots, key=lambda x: x['failure_rate'], reverse=True),
                'temporal_hotspots': peak_failure_times,
                'geographic_hotspots': geographic_hotspots
            },
            'analysis_summary': {
                'analysis_period_days': days,
                'hotspot_criteria': {
                    'device_type_threshold': '10% failure rate',
                    'vendor_threshold': '20% failure rate (min 2 devices)',
                    'geographic_threshold': '2+ high-risk devices in same subnet'
                }
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Network Topology Discovery & Visualization Endpoints

@analytics_bp.route('/topology/discover', methods=['GET', 'POST'])
@create_endpoint_limiter('strict')
def discover_network_topology():
    """Perform comprehensive network topology discovery"""
    try:
        force_refresh = request.args.get('force_refresh', default=False, type=bool)
        if request.method == 'POST' and request.is_json:
            force_refresh = request.json.get('force_refresh', False)
        
        # Discover network topology
        topology = network_topology.discover_network_topology(force_refresh=force_refresh)
        
        return jsonify({
            'topology_discovery': topology,
            'request_timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/topology/visualization', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_topology_visualization():
    """Get network topology data optimized for visualization"""
    try:
        force_refresh = request.args.get('force_refresh', default=False, type=bool)
        
        # Get full topology
        topology = network_topology.discover_network_topology(force_refresh=force_refresh)
        
        if 'error' in topology:
            return jsonify(topology), 500
        
        # Extract visualization-specific data
        visualization_data = topology.get('visualization_data', {})
        
        # Enhance with additional metadata for visualization
        enhanced_visualization = {
            'nodes': visualization_data.get('nodes', []),
            'edges': visualization_data.get('edges', []),
            'clusters': visualization_data.get('clusters', []),
            'layout_hints': visualization_data.get('layout_hints', {}),
            'metadata': {
                'total_nodes': len(visualization_data.get('nodes', [])),
                'total_edges': len(visualization_data.get('edges', [])),
                'total_clusters': len(visualization_data.get('clusters', [])),
                'discovery_timestamp': topology['discovery_metadata']['discovered_at'],
                'network_segments': len(topology.get('network_segments', {})),
                'infrastructure_devices': len(topology.get('infrastructure_devices', {}).get('critical_services', []))
            },
            'legend': {
                'node_types': {
                    'infrastructure': 'Network infrastructure devices (routers, switches)',
                    'endpoint': 'End devices (computers, phones, IoT)'
                },
                'node_sizes': {
                    'xlarge': 'Gateway/Router devices',
                    'large': 'Infrastructure devices',
                    'medium': 'Regular network devices'
                },
                'edge_types': {
                    'parent_child': 'Gateway dependency relationship',
                    'latency_peer': 'Devices with similar response patterns',
                    'subnet_gateway': 'Subnet gateway relationship'
                }
            }
        }
        
        return jsonify({
            'visualization': enhanced_visualization,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/topology/devices/<int:device_id>/relationships', methods=['GET'])
@create_endpoint_limiter('relaxed')
def analyze_device_relationships(device_id):
    """Analyze relationships for a specific device"""
    try:
        # Validate device exists
        device = Device.query.get_or_404(device_id)
        
        # Analyze device relationships
        relationships = network_topology.analyze_device_relationships(device_id)
        
        return jsonify({
            'device_relationships': relationships,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/topology/network-paths', methods=['GET'])
@create_endpoint_limiter('relaxed')
def analyze_network_paths():
    """Get detailed network path analysis"""
    try:
        force_refresh = request.args.get('force_refresh', default=False, type=bool)
        
        # Get topology with path analysis
        topology = network_topology.discover_network_topology(force_refresh=force_refresh)
        
        if 'error' in topology:
            return jsonify(topology), 500
        
        # Extract network paths information
        network_paths = topology.get('network_paths', {})
        
        return jsonify({
            'network_paths': network_paths,
            'path_summary': {
                'critical_paths_count': len(network_paths.get('critical_paths', [])),
                'backup_paths_count': len(network_paths.get('backup_paths', [])),
                'redundancy_analysis': network_paths.get('path_redundancy_analysis', {}),
                'bottleneck_analysis': network_paths.get('bottleneck_analysis', {})
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/topology/infrastructure', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_infrastructure_analysis():
    """Get infrastructure device analysis"""
    try:
        force_refresh = request.args.get('force_refresh', default=False, type=bool)
        
        # Get topology data
        topology = network_topology.discover_network_topology(force_refresh=force_refresh)
        
        if 'error' in topology:
            return jsonify(topology), 500
        
        # Extract infrastructure information
        infrastructure = topology.get('infrastructure_devices', {})
        
        return jsonify({
            'infrastructure_analysis': infrastructure,
            'summary': {
                'total_gateways': len(infrastructure.get('gateways', [])),
                'total_routers': len(infrastructure.get('routers', [])),
                'total_switches': len(infrastructure.get('switches', [])),
                'total_access_points': len(infrastructure.get('access_points', [])),
                'total_servers': len(infrastructure.get('servers', [])),
                'critical_services_count': len(infrastructure.get('critical_services', []))
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/topology/network-segments', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_network_segments():
    """Get network segment analysis"""
    try:
        force_refresh = request.args.get('force_refresh', default=False, type=bool)
        
        # Get topology data
        topology = network_topology.discover_network_topology(force_refresh=force_refresh)
        
        if 'error' in topology:
            return jsonify(topology), 500
        
        # Extract network segments
        network_segments = topology.get('network_segments', {})
        
        # Calculate segment statistics
        segment_stats = {
            'total_segments': len(network_segments),
            'total_devices_across_segments': sum(segment['device_count'] for segment in network_segments.values()),
            'segments_with_gateways': sum(1 for segment in network_segments.values() if segment.get('estimated_gateway')),
            'average_devices_per_segment': round(
                sum(segment['device_count'] for segment in network_segments.values()) / max(1, len(network_segments)), 1
            ),
            'healthiest_segment': max(network_segments.items(), key=lambda x: x[1]['segment_health'])[0] if network_segments else None,
            'average_segment_health': round(
                sum(segment['segment_health'] for segment in network_segments.values()) / max(1, len(network_segments)), 3
            )
        }
        
        return jsonify({
            'network_segments': network_segments,
            'segment_statistics': segment_stats,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/topology/connectivity-matrix', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_connectivity_matrix():
    """Get device connectivity matrix"""
    try:
        force_refresh = request.args.get('force_refresh', default=False, type=bool)
        
        # Get topology data
        topology = network_topology.discover_network_topology(force_refresh=force_refresh)
        
        if 'error' in topology:
            return jsonify(topology), 500
        
        # Extract connectivity matrix
        connectivity_matrix = topology.get('network_paths', {}).get('connectivity_matrix', {})
        
        return jsonify({
            'connectivity_matrix': connectivity_matrix,
            'matrix_summary': {
                'total_subnets': len(connectivity_matrix.get('subnet_connections', {})),
                'devices_with_latency_data': len(connectivity_matrix.get('latency_matrix', {})),
                'devices_with_reachability_data': len(connectivity_matrix.get('reachability_matrix', {}))
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/topology/redundancy-analysis', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_redundancy_analysis():
    """Get network redundancy and failover analysis"""
    try:
        force_refresh = request.args.get('force_refresh', default=False, type=bool)
        
        # Get topology data
        topology = network_topology.discover_network_topology(force_refresh=force_refresh)
        
        if 'error' in topology:
            return jsonify(topology), 500
        
        # Extract redundancy analysis
        redundancy_analysis = topology.get('network_paths', {}).get('path_redundancy_analysis', {})
        
        return jsonify({
            'redundancy_analysis': redundancy_analysis,
            'redundancy_summary': redundancy_analysis.get('redundancy_summary', {}),
            'recommendations': redundancy_analysis.get('redundancy_recommendations', []),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/topology/bottleneck-analysis', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_bottleneck_analysis():
    """Get network bottleneck and performance analysis"""
    try:
        force_refresh = request.args.get('force_refresh', default=False, type=bool)
        
        # Get topology data
        topology = network_topology.discover_network_topology(force_refresh=force_refresh)
        
        if 'error' in topology:
            return jsonify(topology), 500
        
        # Extract bottleneck analysis
        bottleneck_analysis = topology.get('network_paths', {}).get('bottleneck_analysis', {})
        
        return jsonify({
            'bottleneck_analysis': bottleneck_analysis,
            'performance_summary': {
                'bottleneck_devices_count': len(bottleneck_analysis.get('bottleneck_devices', [])),
                'performance_concerns_count': len(bottleneck_analysis.get('performance_concerns', [])),
                'optimization_recommendations_count': len(bottleneck_analysis.get('optimization_recommendations', []))
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/topology/topology-metrics', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_topology_metrics():
    """Get comprehensive network topology metrics"""
    try:
        force_refresh = request.args.get('force_refresh', default=False, type=bool)
        
        # Get topology data
        topology = network_topology.discover_network_topology(force_refresh=force_refresh)
        
        if 'error' in topology:
            return jsonify(topology), 500
        
        # Extract topology metrics
        topology_metrics = topology.get('topology_metrics', {})
        path_metrics = topology.get('network_paths', {}).get('path_metrics', {})
        
        # Combine all metrics
        comprehensive_metrics = {
            'topology_metrics': topology_metrics,
            'path_metrics': path_metrics,
            'discovery_metadata': topology.get('discovery_metadata', {}),
            'overall_assessment': {
                'network_health': path_metrics.get('network_resilience', {}).get('resilience_level', 'unknown'),
                'redundancy_score': path_metrics.get('redundancy_metrics', {}).get('redundancy_score', 0),
                'connectivity_score': topology_metrics.get('connectivity_score', 0),
                'infrastructure_coverage': len(topology.get('infrastructure_devices', {}).get('critical_services', [])),
                'segment_diversity': len(topology.get('network_segments', {}))
            }
        }
        
        return jsonify({
            'comprehensive_metrics': comprehensive_metrics,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/topology/monitor-changes', methods=['GET'])
@create_endpoint_limiter('relaxed')
def monitor_topology_changes():
    """Monitor for topology changes and updates"""
    try:
        # Monitor topology changes
        change_analysis = network_topology.monitor_topology_changes()
        
        return jsonify({
            'change_monitoring': change_analysis,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/topology/export', methods=['GET'])
@create_endpoint_limiter('relaxed')
def export_topology_data():
    """Export complete topology data for analysis or backup"""
    try:
        format_type = request.args.get('format', default='json', type=str)
        include_raw_data = request.args.get('include_raw', default=False, type=bool)
        
        # Get comprehensive topology
        topology = network_topology.discover_network_topology(force_refresh=True)
        
        if 'error' in topology:
            return jsonify(topology), 500
        
        export_data = {
            'export_metadata': {
                'export_timestamp': datetime.utcnow().isoformat(),
                'format': format_type,
                'includes_raw_data': include_raw_data,
                'topology_version': '1.0'
            },
            'topology_data': topology
        }
        
        # Remove raw monitoring data if not requested
        if not include_raw_data:
            # Remove detailed monitoring data to reduce size
            if 'network_paths' in export_data['topology_data']:
                if 'connectivity_matrix' in export_data['topology_data']['network_paths']:
                    # Keep summary but remove detailed matrices
                    connectivity = export_data['topology_data']['network_paths']['connectivity_matrix']
                    export_data['topology_data']['network_paths']['connectivity_matrix'] = {
                        'summary': {
                            'total_subnets': len(connectivity.get('subnet_connections', {})),
                            'devices_with_latency': len(connectivity.get('latency_matrix', {})),
                            'devices_with_reachability': len(connectivity.get('reachability_matrix', {}))
                        }
                    }
        
        return jsonify({
            'export_successful': True,
            'export_data': export_data,
            'export_size_estimate': 'large' if include_raw_data else 'medium'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Anomaly Detection Engine Endpoints

@analytics_bp.route('/anomalies/detect', methods=['GET', 'POST'])
@create_endpoint_limiter('strict')
def detect_anomalies():
    """Perform comprehensive anomaly detection analysis"""
    try:
        # Get parameters from request
        device_id = None
        hours = 24
        
        if request.method == 'GET':
            device_id = request.args.get('device_id', type=int)
            hours = request.args.get('hours', default=24, type=int)
        elif request.method == 'POST' and request.is_json:
            data = request.get_json()
            device_id = data.get('device_id')
            hours = data.get('hours', 24)
        
        # Perform enhanced anomaly detection
        results = anomaly_detection.detect_enhanced_anomalies(device_id=device_id, hours=hours)
        
        return jsonify({
            'anomaly_detection_results': results,
            'request_timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/anomalies/detect-legacy', methods=['GET', 'POST'])
@create_endpoint_limiter('strict')
def detect_legacy_anomalies():
    """Legacy anomaly detection for backward compatibility"""
    try:
        device_id = None
        hours = 24
        
        if request.method == 'GET':
            device_id = request.args.get('device_id', type=int)
            hours = request.args.get('hours', default=24, type=int)
        elif request.method == 'POST' and request.is_json:
            data = request.get_json()
            device_id = data.get('device_id')
            hours = data.get('hours', 24)
        
        # Use legacy detection method
        if device_id:
            device = Device.query.get_or_404(device_id)
            legacy_anomalies = anomaly_detection.detect_device_anomalies(device)
            results = {
                'device_id': device_id,
                'device_name': device.display_name,
                'anomalies': [vars(anomaly) for anomaly in legacy_anomalies],
                'total_anomalies': len(legacy_anomalies)
            }
        else:
            # Run detection cycle for all devices
            anomaly_detection.run_detection_cycle()
            results = {
                'message': 'Legacy anomaly detection cycle completed',
                'check_alerts': 'Check alerts table for detected anomalies'
            }
        
        return jsonify({
            'legacy_detection_results': results,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/anomalies/devices/<int:device_id>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_anomalies(device_id):
    """Get anomaly analysis for a specific device"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        
        # Validate device exists
        device = Device.query.get_or_404(device_id)
        
        # Get device-specific anomaly detection
        results = anomaly_detection.detect_enhanced_anomalies(device_id=device_id, hours=hours)
        
        if 'error' in results:
            return jsonify(results), 500
        
        # Extract device-specific information
        device_summary = results.get('device_summaries', {}).get(device_id, {})
        device_anomalies = [a for a in results.get('anomalies', []) if a['device_id'] == device_id]
        
        return jsonify({
            'device_id': device_id,
            'device_name': device.display_name,
            'device_summary': device_summary,
            'anomalies': device_anomalies,
            'analysis_period_hours': hours,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/anomalies/network-wide', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_network_wide_anomalies():
    """Get network-wide anomaly analysis"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        
        # Perform network-wide anomaly detection
        results = anomaly_detection.detect_enhanced_anomalies(hours=hours)
        
        if 'error' in results:
            return jsonify(results), 500
        
        # Extract network-wide information
        network_summary = results.get('network_summary', {})
        network_anomalies = [a for a in results.get('anomalies', []) if a['device_id'] == 0]
        correlation_analysis = results.get('correlation_analysis', {})
        
        return jsonify({
            'network_summary': network_summary,
            'network_anomalies': network_anomalies,
            'correlation_analysis': correlation_analysis,
            'recommendations': results.get('recommendations', []),
            'analysis_period_hours': hours,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/anomalies/statistics', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_anomaly_statistics():
    """Get comprehensive anomaly detection statistics"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        
        # Get legacy statistics for backward compatibility
        legacy_stats = anomaly_detection.get_anomaly_statistics(hours=hours)
        
        # Get enhanced statistics from detection engine
        engine_stats = {
            'detection_configuration': anomaly_detection.enhanced_detection_config,
            'monitoring_status': {
                'is_monitoring_active': anomaly_detection._monitoring_active,
                'last_baseline_update': anomaly_detection._last_baseline_update.isoformat(),
                'detection_interval': anomaly_detection.detection_interval
            },
            'performance_metrics': anomaly_detection._detection_statistics,
            'active_anomalies_count': len(anomaly_detection.active_anomalies),
            'anomaly_history_size': len(anomaly_detection.anomaly_history),
            'baseline_coverage': {
                'devices_with_baselines': len(anomaly_detection.device_baselines),
                'network_baselines': len(anomaly_detection.network_baselines)
            }
        }
        
        return jsonify({
            'legacy_statistics': legacy_stats,
            'enhanced_statistics': engine_stats,
            'analysis_period_hours': hours,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/anomalies/correlations', methods=['GET'])
@create_endpoint_limiter('relaxed')
def analyze_anomaly_correlations():
    """Analyze correlations between recent anomalies"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        
        # Get recent anomaly detection results
        results = anomaly_detection.detect_enhanced_anomalies(hours=hours)
        
        if 'error' in results:
            return jsonify(results), 500
        
        # Extract correlation analysis
        correlation_analysis = results.get('correlation_analysis', {})
        
        # Add additional correlation insights
        anomalies = results.get('anomalies', [])
        
        correlation_insights = {
            'correlation_analysis': correlation_analysis,
            'insights': {
                'total_correlations_found': (
                    len(correlation_analysis.get('temporal_correlations', [])) +
                    len(correlation_analysis.get('device_correlations', [])) +
                    len(correlation_analysis.get('type_correlations', []))
                ),
                'most_correlated_devices': correlation_analysis.get('device_correlations', [])[:5],
                'most_common_combinations': correlation_analysis.get('type_correlations', [])[:3],
                'temporal_hotspots': len([c for c in correlation_analysis.get('temporal_correlations', []) if c.get('correlation_strength', 0) > 0.5])
            },
            'recommendation_priority': 'high' if len(correlation_analysis.get('temporal_correlations', [])) > 3 else 'medium'
        }
        
        return jsonify({
            'correlation_insights': correlation_insights,
            'analysis_period_hours': hours,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/anomalies/types/<anomaly_type>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_anomalies_by_type(anomaly_type):
    """Get anomalies filtered by specific type"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        
        # Perform anomaly detection
        results = anomaly_detection.detect_enhanced_anomalies(hours=hours)
        
        if 'error' in results:
            return jsonify(results), 500
        
        # Filter anomalies by type
        filtered_anomalies = [
            a for a in results.get('anomalies', [])
            if a['anomaly_type'] == anomaly_type
        ]
        
        # Calculate type-specific statistics
        if filtered_anomalies:
            severity_distribution = defaultdict(int)
            confidence_scores = []
            
            for anomaly in filtered_anomalies:
                severity_distribution[anomaly['severity']] += 1
                confidence_scores.append(anomaly['confidence'])
            
            type_statistics = {
                'total_anomalies': len(filtered_anomalies),
                'severity_distribution': dict(severity_distribution),
                'average_confidence': round(statistics.mean(confidence_scores), 3),
                'max_confidence': max(confidence_scores),
                'affected_devices': len(set([a['device_id'] for a in filtered_anomalies if a['device_id'] > 0]))
            }
        else:
            type_statistics = {
                'total_anomalies': 0,
                'severity_distribution': {},
                'average_confidence': 0.0,
                'max_confidence': 0.0,
                'affected_devices': 0
            }
        
        return jsonify({
            'anomaly_type': anomaly_type,
            'type_statistics': type_statistics,
            'anomalies': filtered_anomalies,
            'analysis_period_hours': hours,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/anomalies/severity/<severity_level>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_anomalies_by_severity(severity_level):
    """Get anomalies filtered by severity level"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        
        # Validate severity level
        valid_severities = ['low', 'medium', 'high', 'critical']
        if severity_level not in valid_severities:
            return jsonify({'error': f'Invalid severity level. Must be one of: {valid_severities}'}), 400
        
        # Perform anomaly detection
        results = anomaly_detection.detect_enhanced_anomalies(hours=hours)
        
        if 'error' in results:
            return jsonify(results), 500
        
        # Filter anomalies by severity
        filtered_anomalies = [
            a for a in results.get('anomalies', [])
            if a['severity'] == severity_level
        ]
        
        # Calculate severity-specific insights
        if filtered_anomalies:
            type_distribution = defaultdict(int)
            device_distribution = defaultdict(int)
            
            for anomaly in filtered_anomalies:
                type_distribution[anomaly['anomaly_type']] += 1
                if anomaly['device_id'] > 0:
                    device_distribution[anomaly['device_id']] += 1
            
            severity_insights = {
                'total_anomalies': len(filtered_anomalies),
                'type_distribution': dict(type_distribution),
                'most_affected_devices': [
                    {'device_id': device_id, 'anomaly_count': count}
                    for device_id, count in sorted(device_distribution.items(), 
                                                 key=lambda x: x[1], reverse=True)[:5]
                ],
                'urgency_assessment': 'immediate' if severity_level == 'critical' else 'high' if severity_level == 'high' else 'moderate'
            }
        else:
            severity_insights = {
                'total_anomalies': 0,
                'type_distribution': {},
                'most_affected_devices': [],
                'urgency_assessment': 'none'
            }
        
        return jsonify({
            'severity_level': severity_level,
            'severity_insights': severity_insights,
            'anomalies': filtered_anomalies,
            'analysis_period_hours': hours,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/anomalies/monitoring/start', methods=['POST'])
@create_endpoint_limiter('strict')
def start_anomaly_monitoring():
    """Start continuous anomaly monitoring"""
    try:
        # Start the monitoring system
        anomaly_detection.start_monitoring()
        
        return jsonify({
            'monitoring_started': True,
            'message': 'Anomaly detection monitoring started successfully',
            'monitoring_interval': anomaly_detection.detection_interval,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/anomalies/monitoring/stop', methods=['POST'])
@create_endpoint_limiter('strict')
def stop_anomaly_monitoring():
    """Stop continuous anomaly monitoring"""
    try:
        # Stop the monitoring system
        anomaly_detection.stop_monitoring()
        
        return jsonify({
            'monitoring_stopped': True,
            'message': 'Anomaly detection monitoring stopped successfully',
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/anomalies/monitoring/status', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_anomaly_monitoring_status():
    """Get current anomaly monitoring status"""
    try:
        status = {
            'is_monitoring': anomaly_detection.running,
            'is_enhanced_monitoring': anomaly_detection._monitoring_active,
            'detection_interval': anomaly_detection.detection_interval,
            'last_baseline_update': anomaly_detection._last_baseline_update.isoformat(),
            'active_anomalies': len(anomaly_detection.active_anomalies),
            'detection_statistics': anomaly_detection._detection_statistics,
            'configuration': {
                'enhanced_config': anomaly_detection.enhanced_detection_config,
                'alert_thresholds': {k.value: v for k, v in anomaly_detection.alert_thresholds.items()}
            }
        }
        
        return jsonify({
            'monitoring_status': status,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/anomalies/configuration', methods=['GET', 'PUT'])
@create_endpoint_limiter('strict')
def manage_anomaly_configuration():
    """Get or update anomaly detection configuration"""
    try:
        if request.method == 'GET':
            # Return current configuration
            config = {
                'enhanced_detection_config': anomaly_detection.enhanced_detection_config,
                'detection_settings': anomaly_detection.detection_settings,
                'alert_thresholds': {k.value: v for k, v in anomaly_detection.alert_thresholds.items()},
                'detection_interval': anomaly_detection.detection_interval
            }
            
            return jsonify({
                'configuration': config,
                'timestamp': datetime.utcnow().isoformat()
            })
            
        elif request.method == 'PUT':
            if not request.is_json:
                return jsonify({'error': 'Request must be JSON'}), 400
            
            config_updates = request.get_json()
            
            # Update configuration (simplified - in production, add validation)
            if 'detection_interval' in config_updates:
                anomaly_detection.detection_interval = config_updates['detection_interval']
            
            if 'enhanced_detection_config' in config_updates:
                anomaly_detection.enhanced_detection_config.update(config_updates['enhanced_detection_config'])
            
            # Reload configuration
            anomaly_detection.reload_configuration()
            
            return jsonify({
                'configuration_updated': True,
                'message': 'Anomaly detection configuration updated successfully',
                'timestamp': datetime.utcnow().isoformat()
            })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/anomalies/recommendations', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_anomaly_recommendations():
    """Get actionable recommendations based on recent anomalies"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        severity_filter = request.args.get('severity')
        
        # Get anomaly detection results
        results = anomaly_detection.detect_enhanced_anomalies(hours=hours)
        
        if 'error' in results:
            return jsonify(results), 500
        
        # Filter by severity if specified
        anomalies = results.get('anomalies', [])
        if severity_filter:
            anomalies = [a for a in anomalies if a['severity'] == severity_filter]
        
        # Get recommendations
        recommendations = results.get('recommendations', [])
        
        # Prioritize recommendations based on anomaly severity and count
        critical_count = len([a for a in anomalies if a['severity'] == 'critical'])
        high_count = len([a for a in anomalies if a['severity'] == 'high'])
        
        priority_recommendations = {
            'immediate_actions': [],
            'short_term_actions': [],
            'long_term_improvements': []
        }
        
        for rec in recommendations:
            if 'URGENT' in rec or 'critical' in rec.lower():
                priority_recommendations['immediate_actions'].append(rec)
            elif 'review' in rec.lower() or 'check' in rec.lower():
                priority_recommendations['short_term_actions'].append(rec)
            else:
                priority_recommendations['long_term_improvements'].append(rec)
        
        return jsonify({
            'recommendations': {
                'all_recommendations': recommendations,
                'prioritized_recommendations': priority_recommendations,
                'recommendation_context': {
                    'total_anomalies': len(anomalies),
                    'critical_anomalies': critical_count,
                    'high_severity_anomalies': high_count,
                    'urgency_level': 'critical' if critical_count > 0 else 'high' if high_count > 0 else 'moderate'
                }
            },
            'analysis_period_hours': hours,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analytics_bp.route('/anomalies/export', methods=['GET'])
@create_endpoint_limiter('relaxed')
def export_anomaly_data():
    """Export comprehensive anomaly data for analysis"""
    try:
        hours = request.args.get('hours', default=168, type=int)  # Default 1 week
        format_type = request.args.get('format', default='json', type=str)
        include_raw_data = request.args.get('include_raw', default=False, type=bool)
        
        # Get comprehensive anomaly data
        results = anomaly_detection.detect_enhanced_anomalies(hours=hours)
        
        if 'error' in results:
            return jsonify(results), 500
        
        export_data = {
            'export_metadata': {
                'export_timestamp': datetime.utcnow().isoformat(),
                'format': format_type,
                'includes_raw_data': include_raw_data,
                'analysis_period_hours': hours,
                'anomaly_detection_version': '2.0'
            },
            'anomaly_data': results
        }
        
        # Add additional context if raw data is requested
        if include_raw_data:
            export_data['configuration'] = {
                'detection_config': anomaly_detection.enhanced_detection_config,
                'alert_thresholds': {k.value: v for k, v in anomaly_detection.alert_thresholds.items()},
                'monitoring_status': {
                    'is_active': anomaly_detection._monitoring_active,
                    'detection_statistics': anomaly_detection._detection_statistics
                }
            }
        
        return jsonify({
            'export_successful': True,
            'export_data': export_data,
            'export_size_estimate': 'large' if include_raw_data else 'medium'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500