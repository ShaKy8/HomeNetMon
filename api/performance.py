from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from sqlalchemy import func, desc
from models import db, Device, PerformanceMetrics, MonitoringData, BandwidthData
from api.rate_limited_endpoints import create_endpoint_limiter

performance_bp = Blueprint('performance', __name__)

@performance_bp.route('/summary', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_performance_summary():
    """Get network-wide performance summary"""
    try:
        # Query parameters
        hours = request.args.get('hours', default=24, type=int)
        
        # Get performance monitor service
        from services.performance_monitor import performance_monitor
        
        summary = performance_monitor.get_network_performance_summary(hours)
        
        if summary:
            return jsonify(summary)
        else:
            return jsonify({
                'error': 'Unable to generate performance summary',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }), 500
            
    except Exception as e:
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500

@performance_bp.route('/devices', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_devices_performance():
    """Get performance metrics for all devices"""
    try:
        # Query parameters
        hours = request.args.get('hours', default=24, type=int)
        sort_by = request.args.get('sort_by', default='health_score', type=str)
        order = request.args.get('order', default='desc', type=str)
        device_type = request.args.get('device_type', type=str)
        min_health_score = request.args.get('min_health_score', type=float)
        limit = request.args.get('limit', default=100, type=int)
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Base query for latest performance metrics per device
        query = db.session.query(
            Device.id,
            Device.display_name,
            Device.ip_address,
            Device.device_type,
            Device.status,
            PerformanceMetrics.health_score,
            PerformanceMetrics.responsiveness_score,
            PerformanceMetrics.reliability_score,
            PerformanceMetrics.efficiency_score,
            PerformanceMetrics.connection_stability_score,
            PerformanceMetrics.uptime_percentage,
            PerformanceMetrics.avg_response_time,
            PerformanceMetrics.timestamp
        ).outerjoin(
            PerformanceMetrics,
            Device.id == PerformanceMetrics.device_id
        ).filter(
            Device.is_monitored == True
        )
        
        # Filter by device type if specified
        if device_type:
            query = query.filter(Device.device_type == device_type)
        
        # Filter by minimum health score if specified
        if min_health_score is not None:
            query = query.filter(PerformanceMetrics.health_score >= min_health_score)
        
        # Get latest performance metrics per device
        subquery = query.filter(
            PerformanceMetrics.timestamp >= cutoff
        ).distinct(Device.id).subquery()
        
        # Main query with latest metrics
        main_query = db.session.query(subquery).order_by(
            desc(subquery.c.health_score) if order == 'desc' else subquery.c.health_score
        )
        
        # Apply sorting
        if sort_by == 'name':
            main_query = main_query.order_by(
                desc(subquery.c.display_name) if order == 'desc' else subquery.c.display_name
            )
        elif sort_by == 'response_time':
            main_query = main_query.order_by(
                desc(subquery.c.avg_response_time) if order == 'desc' else subquery.c.avg_response_time
            )
        elif sort_by == 'uptime':
            main_query = main_query.order_by(
                desc(subquery.c.uptime_percentage) if order == 'desc' else subquery.c.uptime_percentage
            )
        
        # Apply limit
        results = main_query.limit(limit).all()
        
        # Format results
        devices_performance = []
        for row in results:
            device_data = {
                'device_id': row[0],
                'device_name': row[1],
                'device_ip': row[2],
                'device_type': row[3] or 'unknown',
                'device_status': row[4],
                'performance_metrics': {
                    'health_score': row[5],
                    'responsiveness_score': row[6],
                    'reliability_score': row[7],
                    'efficiency_score': row[8],
                    'stability_score': row[9],
                    'uptime_percentage': row[10],
                    'avg_response_time_ms': row[11],
                    'last_updated': row[12].isoformat() + 'Z' if row[12] else None
                },
                'performance_grade': _get_performance_grade(row[5]),
                'performance_status': _get_performance_status(row[5])
            }
            devices_performance.append(device_data)
        
        return jsonify({
            'devices': devices_performance,
            'count': len(devices_performance),
            'period_hours': hours,
            'filters': {
                'device_type': device_type,
                'min_health_score': min_health_score,
                'sort_by': sort_by,
                'order': order
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500

@performance_bp.route('/device/<int:device_id>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_performance(device_id):
    """Get detailed performance metrics for a specific device"""
    try:
        # Query parameters
        hours = request.args.get('hours', default=24, type=int)
        include_raw_data = request.args.get('include_raw', default=False, type=bool)
        
        # Get device
        device = Device.query.get_or_404(device_id)
        
        if include_raw_data:
            # Get performance summary from device model
            performance_summary = device.get_performance_summary(hours)
            
            # Get raw performance metrics
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            raw_metrics = PerformanceMetrics.query.filter(
                PerformanceMetrics.device_id == device_id,
                PerformanceMetrics.timestamp >= cutoff
            ).order_by(PerformanceMetrics.timestamp.desc()).all()
            
            return jsonify({
                'device': {
                    'id': device.id,
                    'name': device.display_name,
                    'ip_address': device.ip_address,
                    'device_type': device.device_type,
                    'status': device.status
                },
                'performance_summary': performance_summary,
                'raw_metrics': [metric.to_dict() for metric in raw_metrics],
                'period_hours': hours,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
        else:
            # Get performance summary only
            performance_summary = device.get_performance_summary(hours)
            
            return jsonify({
                'device': {
                    'id': device.id,
                    'name': device.display_name,
                    'ip_address': device.ip_address,
                    'device_type': device.device_type,
                    'status': device.status
                },
                'performance_summary': performance_summary,
                'period_hours': hours,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500

@performance_bp.route('/device/<int:device_id>/timeline', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_performance_timeline(device_id):
    """Get performance metrics timeline for a specific device"""
    try:
        # Query parameters
        hours = request.args.get('hours', default=24, type=int)
        granularity = request.args.get('granularity', default='hour', type=str)  # hour, day
        
        # Get device
        device = Device.query.get_or_404(device_id)
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get performance metrics
        metrics = PerformanceMetrics.query.filter(
            PerformanceMetrics.device_id == device_id,
            PerformanceMetrics.timestamp >= cutoff
        ).order_by(PerformanceMetrics.timestamp).all()
        
        # Group by time granularity
        timeline_data = []
        
        if granularity == 'hour':
            # Group by hour
            hour_groups = {}
            for metric in metrics:
                hour_key = metric.timestamp.replace(minute=0, second=0, microsecond=0)
                if hour_key not in hour_groups:
                    hour_groups[hour_key] = []
                hour_groups[hour_key].append(metric)
            
            for hour, hour_metrics in sorted(hour_groups.items()):
                # Calculate averages for the hour
                health_scores = [m.health_score for m in hour_metrics if m.health_score is not None]
                response_times = [m.avg_response_time for m in hour_metrics if m.avg_response_time is not None]
                uptime_percentages = [m.uptime_percentage for m in hour_metrics if m.uptime_percentage is not None]
                
                timeline_data.append({
                    'timestamp': hour.isoformat() + 'Z',
                    'health_score': sum(health_scores) / len(health_scores) if health_scores else None,
                    'avg_response_time': sum(response_times) / len(response_times) if response_times else None,
                    'uptime_percentage': sum(uptime_percentages) / len(uptime_percentages) if uptime_percentages else None,
                    'sample_count': len(hour_metrics)
                })
        
        return jsonify({
            'device': {
                'id': device.id,
                'name': device.display_name,
                'ip_address': device.ip_address
            },
            'timeline': timeline_data,
            'period_hours': hours,
            'granularity': granularity,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500

@performance_bp.route('/health-scores', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_health_scores_distribution():
    """Get distribution of health scores across all devices"""
    try:
        # Query parameters
        hours = request.args.get('hours', default=24, type=int)
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get latest health scores
        health_scores = db.session.execute(
            db.text("""
                SELECT 
                    d.device_type,
                    pm.health_score,
                    pm.responsiveness_score,
                    pm.reliability_score,
                    pm.efficiency_score,
                    pm.connection_stability_score
                FROM devices d
                JOIN (
                    SELECT DISTINCT
                        device_id,
                        health_score,
                        responsiveness_score,
                        reliability_score,
                        efficiency_score,
                        connection_stability_score,
                        ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY timestamp DESC) as rn
                    FROM performance_metrics
                    WHERE timestamp >= :cutoff
                ) pm ON d.id = pm.device_id AND pm.rn = 1
                WHERE d.is_monitored = 1 AND pm.health_score IS NOT NULL
            """),
            {'cutoff': cutoff}
        ).fetchall()
        
        # Calculate distributions
        score_ranges = {
            'excellent': 0,  # 90-100
            'good': 0,       # 80-89
            'fair': 0,       # 70-79
            'poor': 0,       # 60-69
            'critical': 0    # 0-59
        }
        
        type_scores = {}
        component_scores = {
            'responsiveness': [],
            'reliability': [],
            'efficiency': [],
            'stability': []
        }
        
        for row in health_scores:
            device_type = row[0] or 'unknown'
            health_score = row[1]
            
            # Overall health distribution
            if health_score >= 90:
                score_ranges['excellent'] += 1
            elif health_score >= 80:
                score_ranges['good'] += 1
            elif health_score >= 70:
                score_ranges['fair'] += 1
            elif health_score >= 60:
                score_ranges['poor'] += 1
            else:
                score_ranges['critical'] += 1
            
            # By device type
            if device_type not in type_scores:
                type_scores[device_type] = []
            type_scores[device_type].append(health_score)
            
            # Component scores
            if row[2] is not None:
                component_scores['responsiveness'].append(row[2])
            if row[3] is not None:
                component_scores['reliability'].append(row[3])
            if row[4] is not None:
                component_scores['efficiency'].append(row[4])
            if row[5] is not None:
                component_scores['stability'].append(row[5])
        
        # Calculate averages by device type
        type_averages = {}
        for device_type, scores in type_scores.items():
            type_averages[device_type] = {
                'avg_health_score': round(sum(scores) / len(scores), 2),
                'device_count': len(scores),
                'min_score': min(scores),
                'max_score': max(scores)
            }
        
        # Calculate component averages
        component_averages = {}
        for component, scores in component_scores.items():
            if scores:
                component_averages[component] = round(sum(scores) / len(scores), 2)
            else:
                component_averages[component] = 0
        
        return jsonify({
            'health_score_distribution': score_ranges,
            'device_type_breakdown': type_averages,
            'component_averages': component_averages,
            'total_devices': len(health_scores),
            'period_hours': hours,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500

@performance_bp.route('/top-performers', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_top_performers():
    """Get top performing devices"""
    try:
        # Query parameters
        hours = request.args.get('hours', default=24, type=int)
        limit = request.args.get('limit', default=10, type=int)
        metric = request.args.get('metric', default='health_score', type=str)
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Get top performers based on specified metric
        order_column = PerformanceMetrics.health_score
        if metric == 'responsiveness':
            order_column = PerformanceMetrics.responsiveness_score
        elif metric == 'reliability':
            order_column = PerformanceMetrics.reliability_score
        elif metric == 'efficiency':
            order_column = PerformanceMetrics.efficiency_score
        elif metric == 'stability':
            order_column = PerformanceMetrics.connection_stability_score
        elif metric == 'uptime':
            order_column = PerformanceMetrics.uptime_percentage
        
        # Get latest metrics per device
        top_performers = db.session.query(
            Device.id,
            Device.display_name,
            Device.ip_address,
            Device.device_type,
            PerformanceMetrics.health_score,
            PerformanceMetrics.responsiveness_score,
            PerformanceMetrics.reliability_score,
            PerformanceMetrics.efficiency_score,
            PerformanceMetrics.connection_stability_score,
            PerformanceMetrics.uptime_percentage,
            PerformanceMetrics.timestamp
        ).join(
            PerformanceMetrics,
            Device.id == PerformanceMetrics.device_id
        ).filter(
            Device.is_monitored == True,
            PerformanceMetrics.timestamp >= cutoff
        ).order_by(
            desc(order_column)
        ).limit(limit).all()
        
        performers_list = []
        for row in top_performers:
            performers_list.append({
                'device_id': row[0],
                'device_name': row[1],
                'device_ip': row[2],
                'device_type': row[3] or 'unknown',
                'performance_metrics': {
                    'health_score': row[4],
                    'responsiveness_score': row[5],
                    'reliability_score': row[6],
                    'efficiency_score': row[7],
                    'stability_score': row[8],
                    'uptime_percentage': row[9],
                    'last_updated': row[10].isoformat() + 'Z'
                },
                'performance_grade': _get_performance_grade(row[4]),
                'performance_status': _get_performance_status(row[4])
            })
        
        return jsonify({
            'top_performers': performers_list,
            'metric': metric,
            'period_hours': hours,
            'limit': limit,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500

@performance_bp.route('/collect/<int:device_id>', methods=['POST'])
@create_endpoint_limiter('critical')
def trigger_device_performance_collection(device_id):
    """Manually trigger performance metrics collection for a specific device"""
    try:
        # Get device
        device = Device.query.get_or_404(device_id)
        
        # Get performance monitor service
        from services.performance_monitor import performance_monitor
        
        # Trigger collection
        result = performance_monitor.collect_device_performance_metrics(device_id)
        
        if result:
            return jsonify({
                'success': True,
                'message': f'Performance metrics collected for {device.display_name}',
                'performance_metrics': result.to_dict(),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
        else:
            return jsonify({
                'success': False,
                'message': f'Failed to collect performance metrics for {device.display_name}',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }), 500
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500

@performance_bp.route('/collect', methods=['POST'])
@create_endpoint_limiter('critical')
def trigger_all_performance_collection():
    """Manually trigger performance metrics collection for all devices"""
    try:
        # Get performance monitor service
        from services.performance_monitor import performance_monitor
        
        # Trigger collection for all devices
        performance_monitor.collect_all_devices_performance()
        
        return jsonify({
            'success': True,
            'message': 'Performance metrics collection triggered for all devices',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500

# Helper functions
def _get_performance_grade(health_score):
    """Get performance grade based on health score"""
    if health_score is None:
        return 'N/A'
    elif health_score >= 95:
        return 'A+'
    elif health_score >= 90:
        return 'A'
    elif health_score >= 85:
        return 'B+'
    elif health_score >= 80:
        return 'B'
    elif health_score >= 75:
        return 'C+'
    elif health_score >= 70:
        return 'C'
    elif health_score >= 65:
        return 'D+'
    elif health_score >= 60:
        return 'D'
    else:
        return 'F'

def _get_performance_status(health_score):
    """Get performance status based on health score"""
    if health_score is None:
        return 'unknown'
    elif health_score >= 90:
        return 'excellent'
    elif health_score >= 80:
        return 'good'
    elif health_score >= 70:
        return 'fair'
    elif health_score >= 60:
        return 'poor'
    else:
        return 'critical'

@performance_bp.route('/alerts/summary', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_performance_alerts_summary():
    """Get summary of current performance alerts"""
    try:
        # Get performance monitor service
        from services.performance_monitor import performance_monitor
        
        summary = performance_monitor.get_performance_alert_summary()
        
        if summary:
            summary['timestamp'] = datetime.utcnow().isoformat() + 'Z'
            return jsonify(summary)
        else:
            return jsonify({
                'total_active': 0,
                'by_severity': {'critical': 0, 'warning': 0, 'info': 0},
                'by_subtype': {},
                'recent_alerts': [],
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
            
    except Exception as e:
        return jsonify({
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500