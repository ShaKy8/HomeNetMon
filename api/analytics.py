from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_
from models import db, Device, MonitoringData, Alert
from collections import defaultdict
import statistics

# Import health score calculation function for consistency
from api.health import calculate_health_score

analytics_bp = Blueprint('analytics', __name__)

@analytics_bp.route('/network-health-score', methods=['GET'])
def get_network_health_score():
    """Calculate overall network health score"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get all monitored devices
        total_devices = Device.query.filter_by(is_monitored=True).count()
        if total_devices == 0:
            return jsonify({'error': 'No monitored devices found'}), 404
        
        # Calculate various health metrics
        devices_up = Device.query.filter_by(is_monitored=True).filter(
            Device.last_seen >= cutoff
        ).count()
        
        # Average response time
        avg_response = db.session.query(func.avg(MonitoringData.response_time)).filter(
            MonitoringData.timestamp >= cutoff,
            MonitoringData.response_time.isnot(None)
        ).scalar() or 0
        
        # Success rate
        total_pings = MonitoringData.query.filter(MonitoringData.timestamp >= cutoff).count()
        successful_pings = MonitoringData.query.filter(
            MonitoringData.timestamp >= cutoff,
            MonitoringData.response_time.isnot(None)
        ).count()
        
        success_rate = (successful_pings / total_pings * 100) if total_pings > 0 else 0
        uptime_percentage = (devices_up / total_devices * 100)
        
        # Get active alerts count for standardized health score calculation
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
def get_device_insights():
    """Get insights about device patterns and behavior"""
    try:
        hours = request.args.get('hours', default=168, type=int)  # Default 7 days
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Most reliable devices
        devices_with_uptime = []
        for device in Device.query.filter_by(is_monitored=True).all():
            uptime = device.uptime_percentage
            if uptime is not None:
                devices_with_uptime.append({
                    'id': device.id,
                    'name': device.display_name,
                    'ip': device.ip_address,
                    'uptime': uptime,
                    'type': device.device_type
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
        
        # Response time leaders
        fastest_devices = []
        for device in Device.query.filter_by(is_monitored=True).all():
            latest_response = device.latest_response_time
            if latest_response is not None:
                fastest_devices.append({
                    'id': device.id,
                    'name': device.display_name,
                    'ip': device.ip_address,
                    'response_time': latest_response
                })
        
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