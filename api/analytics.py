import logging
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_
from models import db, Device, MonitoringData, Alert
from collections import defaultdict
import statistics
from api.rate_limited_endpoints import create_endpoint_limiter

logger = logging.getLogger(__name__)

from services.health_score import calculate_health_score, generate_health_recommendations
from services.network_topology import NetworkTopologyEngine

analytics_bp = Blueprint('analytics', __name__)


def _window_hours(default: int, max_days: int = 90) -> int:
    """Time window from ``?hours=`` or ``?days=`` (the analytics page sends either)."""
    days = request.args.get('days', type=int)
    if days is not None and days > 0:
        return min(days, max_days) * 24
    hours = request.args.get('hours', default=default, type=int)
    return max(1, min(hours, max_days * 24))



@analytics_bp.route('/network-health-score', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_network_health_score():
    """Calculate overall network health score"""
    try:
        hours = _window_hours(default=24)
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        # Device counts share one definition with /api/monitoring/summary and the dashboard
        from services.device_counts import summarize
        counts = summarize()
        total_devices = counts['monitored_devices']
        if total_devices == 0:
            return jsonify({'error': 'No monitored devices found'}), 404

        devices_up = counts['devices_up']

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

        active_alerts = counts['active_alerts']

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
        hours = _window_hours(default=168)  # Default 7 days
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


# The network map (templates/topology.html) reads this; the engine keeps its own cache.
network_topology = NetworkTopologyEngine()


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
