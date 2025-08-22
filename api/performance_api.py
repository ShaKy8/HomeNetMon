"""
Performance Analytics API Endpoints

This module provides comprehensive REST API endpoints for performance analytics:
1. Performance metrics and snapshots
2. Bandwidth monitoring and testing
3. Latency analysis and trends
4. Performance alerts management
5. Optimization recommendations
6. Performance reporting and analytics
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import logging
import statistics

from services.performance_analyzer import performance_analyzer
from models import (db, Device, PerformanceSnapshot, BandwidthTest, LatencyAnalysis, 
                   PerformanceAlert, OptimizationRecommendation, PerformanceMetrics)

logger = logging.getLogger(__name__)

# Create performance API blueprint
performance_api = Blueprint('performance_api', __name__, url_prefix='/api/performance')


# Performance Analysis Endpoints
@performance_api.route('/start', methods=['POST'])
def start_performance_analysis():
    """Start the performance analysis engine"""
    try:
        performance_analyzer.start_analysis()
        return jsonify({
            'success': True,
            'message': 'Performance analysis started',
            'started_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error starting performance analysis: {e}")
        return jsonify({'error': str(e)}), 500


@performance_api.route('/stop', methods=['POST'])
def stop_performance_analysis():
    """Stop the performance analysis engine"""
    try:
        performance_analyzer.stop_analysis()
        return jsonify({
            'success': True,
            'message': 'Performance analysis stopped',
            'stopped_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error stopping performance analysis: {e}")
        return jsonify({'error': str(e)}), 500


@performance_api.route('/status', methods=['GET'])
def get_performance_status():
    """Get performance analyzer status"""
    try:
        statistics = performance_analyzer.get_performance_statistics()
        return jsonify(statistics)
        
    except Exception as e:
        logger.error(f"Error getting performance status: {e}")
        return jsonify({'error': str(e)}), 500


@performance_api.route('/summary', methods=['GET'])
def get_performance_summary():
    """Get comprehensive performance summary"""
    try:
        hours = request.args.get('hours', 24, type=int)
        summary = performance_analyzer.get_performance_summary(hours)
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Error getting performance summary: {e}")
        return jsonify({'error': str(e)}), 500


# Device Performance Endpoints
@performance_api.route('/device/<int:device_id>', methods=['GET'])
def get_device_performance(device_id):
    """Get detailed performance analysis for a specific device"""
    try:
        hours = request.args.get('hours', 24, type=int)
        analysis = performance_analyzer.get_device_performance_analysis(device_id, hours)
        return jsonify(analysis)
        
    except Exception as e:
        logger.error(f"Error getting device performance: {e}")
        return jsonify({'error': str(e)}), 500


@performance_api.route('/device/<int:device_id>/metrics', methods=['GET'])
def get_device_metrics_history(device_id):
    """Get historical performance metrics for a device"""
    try:
        hours = request.args.get('hours', 24, type=int)
        metric_type = request.args.get('metric_type')
        
        # Build query
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        query = PerformanceSnapshot.query.filter(
            PerformanceSnapshot.device_id == device_id,
            PerformanceSnapshot.timestamp >= cutoff_time
        )
        
        if metric_type:
            query = query.filter(PerformanceSnapshot.metric_type == metric_type)
        
        snapshots = query.order_by(PerformanceSnapshot.timestamp.desc()).all()
        
        return jsonify({
            'device_id': device_id,
            'time_period_hours': hours,
            'metric_type_filter': metric_type,
            'snapshots': [snapshot.to_dict() for snapshot in snapshots],
            'total_count': len(snapshots)
        })
        
    except Exception as e:
        logger.error(f"Error getting device metrics history: {e}")
        return jsonify({'error': str(e)}), 500


@performance_api.route('/device/<int:device_id>/latency', methods=['GET'])
def get_device_latency_analysis(device_id):
    """Get detailed latency analysis for a device"""
    try:
        hours = request.args.get('hours', 24, type=int)
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        analyses = LatencyAnalysis.query.filter(
            LatencyAnalysis.device_id == device_id,
            LatencyAnalysis.timestamp >= cutoff_time
        ).order_by(LatencyAnalysis.timestamp.desc()).all()
        
        return jsonify({
            'device_id': device_id,
            'time_period_hours': hours,
            'analyses': [analysis.to_dict() for analysis in analyses],
            'total_count': len(analyses)
        })
        
    except Exception as e:
        logger.error(f"Error getting device latency analysis: {e}")
        return jsonify({'error': str(e)}), 500


# Bandwidth Testing Endpoints
@performance_api.route('/bandwidth/test', methods=['POST'])
def trigger_bandwidth_test():
    """Trigger a manual bandwidth test"""
    try:
        # This would trigger the bandwidth test in the performance analyzer
        # For now, return a placeholder response
        return jsonify({
            'success': True,
            'message': 'Bandwidth test initiated',
            'test_id': f"manual_test_{int(datetime.utcnow().timestamp())}",
            'estimated_duration_seconds': 30
        })
        
    except Exception as e:
        logger.error(f"Error triggering bandwidth test: {e}")
        return jsonify({'error': str(e)}), 500


@performance_api.route('/bandwidth/history', methods=['GET'])
def get_bandwidth_history():
    """Get bandwidth test history"""
    try:
        hours = request.args.get('hours', 24, type=int)
        
        # Get from performance analyzer first (in-memory data)
        bandwidth_history = performance_analyzer.get_bandwidth_history(hours)
        
        # Also get from database for longer history
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        db_tests = BandwidthTest.query.filter(
            BandwidthTest.timestamp >= cutoff_time
        ).order_by(BandwidthTest.timestamp.desc()).all()
        
        return jsonify({
            'time_period_hours': hours,
            'analyzer_data': bandwidth_history,
            'database_tests': [test.to_dict() for test in db_tests],
            'total_tests': len(bandwidth_history) + len(db_tests)
        })
        
    except Exception as e:
        logger.error(f"Error getting bandwidth history: {e}")
        return jsonify({'error': str(e)}), 500


@performance_api.route('/bandwidth/latest', methods=['GET'])
def get_latest_bandwidth():
    """Get the latest bandwidth test results"""
    try:
        # Get latest from analyzer
        bandwidth_history = performance_analyzer.get_bandwidth_history(1)  # Last 1 hour
        
        # Get latest from database
        latest_db_test = BandwidthTest.query.order_by(BandwidthTest.timestamp.desc()).first()
        
        result = {
            'analyzer_latest': bandwidth_history[-1] if bandwidth_history else None,
            'database_latest': latest_db_test.to_dict() if latest_db_test else None
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error getting latest bandwidth: {e}")
        return jsonify({'error': str(e)}), 500


# Performance Alerts Endpoints
@performance_api.route('/alerts', methods=['GET'])
def get_performance_alerts():
    """Get performance alerts"""
    try:
        device_id = request.args.get('device_id', type=int)
        hours = request.args.get('hours', 24, type=int)
        status = request.args.get('status', 'active')
        
        # Get from performance analyzer (in-memory alerts)
        analyzer_alerts = performance_analyzer.get_performance_alerts(device_id, hours)
        
        # Get from database
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        query = PerformanceAlert.query.filter(PerformanceAlert.detected_at >= cutoff_time)
        
        if device_id:
            query = query.filter(PerformanceAlert.device_id == device_id)
        
        if status:
            query = query.filter(PerformanceAlert.status == status)
        
        db_alerts = query.order_by(PerformanceAlert.detected_at.desc()).all()
        
        return jsonify({
            'time_period_hours': hours,
            'device_id_filter': device_id,
            'status_filter': status,
            'analyzer_alerts': analyzer_alerts,
            'database_alerts': [alert.to_dict() for alert in db_alerts],
            'total_alerts': len(analyzer_alerts) + len(db_alerts)
        })
        
    except Exception as e:
        logger.error(f"Error getting performance alerts: {e}")
        return jsonify({'error': str(e)}), 500


@performance_api.route('/alerts/<string:alert_id>/acknowledge', methods=['POST'])
def acknowledge_performance_alert(alert_id):
    """Acknowledge a performance alert"""
    try:
        data = request.get_json() or {}
        acknowledged_by = data.get('acknowledged_by', 'api_user')
        notes = data.get('notes', '')
        
        # Try to acknowledge in performance analyzer first
        acknowledged = performance_analyzer.acknowledge_alert(alert_id)
        
        # Also update database record if it exists
        db_alert = PerformanceAlert.query.filter_by(alert_id=alert_id).first()
        if db_alert:
            db_alert.status = 'acknowledged'
            db_alert.acknowledged_at = datetime.utcnow()
            db_alert.acknowledged_by = acknowledged_by
            if notes:
                db_alert.resolution_notes = notes
            db.session.commit()
            acknowledged = True
        
        if acknowledged:
            return jsonify({
                'success': True,
                'alert_id': alert_id,
                'acknowledged_at': datetime.utcnow().isoformat(),
                'acknowledged_by': acknowledged_by
            })
        else:
            return jsonify({'error': 'Alert not found'}), 404
        
    except Exception as e:
        logger.error(f"Error acknowledging performance alert: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# Optimization Recommendations Endpoints
@performance_api.route('/recommendations', methods=['GET'])
def get_optimization_recommendations():
    """Get optimization recommendations"""
    try:
        category = request.args.get('category')
        priority_min = request.args.get('priority_min', 1, type=int)
        status = request.args.get('status', 'pending')
        
        # Get from performance analyzer
        analyzer_recommendations = performance_analyzer.get_optimization_recommendations(
            category, priority_min
        )
        
        # Get from database
        query = OptimizationRecommendation.query.filter(
            OptimizationRecommendation.priority >= priority_min
        )
        
        if category:
            query = query.filter(OptimizationRecommendation.category == category)
        
        if status:
            query = query.filter(OptimizationRecommendation.status == status)
        
        db_recommendations = query.order_by(
            OptimizationRecommendation.priority.desc(),
            OptimizationRecommendation.created_at.desc()
        ).all()
        
        return jsonify({
            'category_filter': category,
            'priority_min_filter': priority_min,
            'status_filter': status,
            'analyzer_recommendations': analyzer_recommendations,
            'database_recommendations': [rec.to_dict() for rec in db_recommendations],
            'total_recommendations': len(analyzer_recommendations) + len(db_recommendations)
        })
        
    except Exception as e:
        logger.error(f"Error getting optimization recommendations: {e}")
        return jsonify({'error': str(e)}), 500


@performance_api.route('/recommendations', methods=['POST'])
def create_optimization_recommendation():
    """Create a new optimization recommendation"""
    try:
        data = request.get_json()
        
        if not data or 'title' not in data or 'category' not in data:
            return jsonify({'error': 'title and category are required'}), 400
        
        # Create new recommendation
        recommendation = OptimizationRecommendation(
            recommendation_id=f"manual_{int(datetime.utcnow().timestamp())}",
            category=data['category'],
            priority=data.get('priority', 3),
            title=data['title'],
            description=data.get('description', ''),
            impact_assessment=data.get('impact_assessment', ''),
            implementation_effort=data.get('implementation_effort', 'medium'),
            estimated_improvement=data.get('estimated_improvement', ''),
            implementation_steps=data.get('implementation_steps', []),
            devices_affected=data.get('devices_affected', []),
            cost_estimate=data.get('cost_estimate'),
            estimated_duration_hours=data.get('estimated_duration_hours')
        )
        
        db.session.add(recommendation)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'recommendation_id': recommendation.recommendation_id,
            'message': 'Optimization recommendation created successfully'
        })
        
    except Exception as e:
        logger.error(f"Error creating optimization recommendation: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@performance_api.route('/recommendations/<string:recommendation_id>/status', methods=['PUT'])
def update_recommendation_status(recommendation_id):
    """Update optimization recommendation status"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        notes = data.get('notes')
        approved_by = data.get('approved_by', 'api_user')
        
        if new_status not in ['pending', 'approved', 'rejected', 'implemented']:
            return jsonify({'error': 'Invalid status'}), 400
        
        recommendation = OptimizationRecommendation.query.filter_by(
            recommendation_id=recommendation_id
        ).first()
        
        if not recommendation:
            return jsonify({'error': 'Recommendation not found'}), 404
        
        # Update status and timestamps
        old_status = recommendation.status
        recommendation.status = new_status
        
        if new_status == 'approved' and old_status != 'approved':
            recommendation.approved_at = datetime.utcnow()
            recommendation.approved_by = approved_by
        elif new_status == 'implemented' and old_status != 'implemented':
            recommendation.implemented_at = datetime.utcnow()
        
        if notes:
            recommendation.implementation_notes = notes
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'recommendation_id': recommendation_id,
            'old_status': old_status,
            'new_status': new_status,
            'updated_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error updating recommendation status: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# Performance Metrics Endpoints
@performance_api.route('/metrics', methods=['GET'])
def get_performance_metrics():
    """Get aggregated performance metrics"""
    try:
        hours = request.args.get('hours', 24, type=int)
        device_id = request.args.get('device_id', type=int)
        metric_types = request.args.getlist('metric_type')
        
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Build query for snapshots
        query = PerformanceSnapshot.query.filter(PerformanceSnapshot.timestamp >= cutoff_time)
        
        if device_id:
            query = query.filter(PerformanceSnapshot.device_id == device_id)
        
        if metric_types:
            query = query.filter(PerformanceSnapshot.metric_type.in_(metric_types))
        
        snapshots = query.order_by(PerformanceSnapshot.timestamp.desc()).all()
        
        # Aggregate by metric type
        metrics_summary = {}
        for snapshot in snapshots:
            metric_type = snapshot.metric_type
            if metric_type not in metrics_summary:
                metrics_summary[metric_type] = {
                    'values': [],
                    'unit': snapshot.unit,
                    'count': 0,
                    'device_count': set()
                }
            
            metrics_summary[metric_type]['values'].append(snapshot.value)
            metrics_summary[metric_type]['count'] += 1
            metrics_summary[metric_type]['device_count'].add(snapshot.device_id)
        
        # Calculate statistics
        for metric_type, data in metrics_summary.items():
            values = data['values']
            if values:
                data['statistics'] = {
                    'average': statistics.mean(values),
                    'min': min(values),
                    'max': max(values),
                    'median': statistics.median(values),
                    'std_dev': statistics.stdev(values) if len(values) > 1 else 0
                }
                data['device_count'] = len(data['device_count'])
            else:
                data['statistics'] = None
                data['device_count'] = 0
            
            # Remove the raw values list to reduce response size
            del data['values']
        
        return jsonify({
            'time_period_hours': hours,
            'device_id_filter': device_id,
            'metric_type_filters': metric_types,
            'metrics_summary': metrics_summary,
            'total_snapshots': len(snapshots)
        })
        
    except Exception as e:
        logger.error(f"Error getting performance metrics: {e}")
        return jsonify({'error': str(e)}), 500


@performance_api.route('/metrics/trends', methods=['GET'])
def get_performance_trends():
    """Get performance trends over time"""
    try:
        hours = request.args.get('hours', 168, type=int)  # Default to 1 week
        device_id = request.args.get('device_id', type=int)
        metric_type = request.args.get('metric_type', 'response_time')
        interval_minutes = request.args.get('interval', 60, type=int)  # Aggregation interval
        
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Build query
        query = PerformanceSnapshot.query.filter(
            PerformanceSnapshot.timestamp >= cutoff_time,
            PerformanceSnapshot.metric_type == metric_type
        )
        
        if device_id:
            query = query.filter(PerformanceSnapshot.device_id == device_id)
        
        snapshots = query.order_by(PerformanceSnapshot.timestamp.asc()).all()
        
        # Aggregate by time intervals
        trends = []
        current_interval_start = cutoff_time
        interval_delta = timedelta(minutes=interval_minutes)
        
        while current_interval_start < datetime.utcnow():
            interval_end = current_interval_start + interval_delta
            
            # Get snapshots in this interval
            interval_snapshots = [
                s for s in snapshots
                if current_interval_start <= s.timestamp < interval_end
            ]
            
            if interval_snapshots:
                values = [s.value for s in interval_snapshots]
                trends.append({
                    'timestamp': current_interval_start.isoformat() + 'Z',
                    'interval_end': interval_end.isoformat() + 'Z',
                    'average': statistics.mean(values),
                    'min': min(values),
                    'max': max(values),
                    'sample_count': len(values),
                    'device_count': len(set(s.device_id for s in interval_snapshots))
                })
            
            current_interval_start = interval_end
        
        return jsonify({
            'time_period_hours': hours,
            'device_id_filter': device_id,
            'metric_type': metric_type,
            'interval_minutes': interval_minutes,
            'trends': trends,
            'total_intervals': len(trends)
        })
        
    except Exception as e:
        logger.error(f"Error getting performance trends: {e}")
        return jsonify({'error': str(e)}), 500


# Network Quality Endpoints
@performance_api.route('/quality/score', methods=['GET'])
def get_network_quality_score():
    """Get overall network quality score"""
    try:
        hours = request.args.get('hours', 24, type=int)
        
        # Get recent performance data
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Calculate quality metrics
        quality_metrics = {}
        
        # Latency quality
        latency_snapshots = PerformanceSnapshot.query.filter(
            PerformanceSnapshot.timestamp >= cutoff_time,
            PerformanceSnapshot.metric_type == 'response_time'
        ).all()
        
        if latency_snapshots:
            avg_latency = statistics.mean([s.value for s in latency_snapshots])
            # Score: 100 for <10ms, 90 for <50ms, 70 for <100ms, 50 for <200ms, 0 for >200ms
            if avg_latency < 10:
                latency_score = 100
            elif avg_latency < 50:
                latency_score = 90
            elif avg_latency < 100:
                latency_score = 70
            elif avg_latency < 200:
                latency_score = 50
            else:
                latency_score = 0
            
            quality_metrics['latency'] = {
                'score': latency_score,
                'average_ms': avg_latency,
                'sample_count': len(latency_snapshots)
            }
        
        # Packet loss quality
        packet_loss_snapshots = PerformanceSnapshot.query.filter(
            PerformanceSnapshot.timestamp >= cutoff_time,
            PerformanceSnapshot.metric_type == 'packet_loss'
        ).all()
        
        if packet_loss_snapshots:
            avg_packet_loss = statistics.mean([s.value for s in packet_loss_snapshots])
            # Score: 100 for 0%, 80 for <1%, 60 for <3%, 40 for <5%, 0 for >5%
            if avg_packet_loss == 0:
                packet_loss_score = 100
            elif avg_packet_loss < 1:
                packet_loss_score = 80
            elif avg_packet_loss < 3:
                packet_loss_score = 60
            elif avg_packet_loss < 5:
                packet_loss_score = 40
            else:
                packet_loss_score = 0
            
            quality_metrics['packet_loss'] = {
                'score': packet_loss_score,
                'average_percent': avg_packet_loss,
                'sample_count': len(packet_loss_snapshots)
            }
        
        # Calculate overall score (weighted average)
        if quality_metrics:
            scores = []
            weights = []
            
            if 'latency' in quality_metrics:
                scores.append(quality_metrics['latency']['score'])
                weights.append(0.6)  # Latency has 60% weight
            
            if 'packet_loss' in quality_metrics:
                scores.append(quality_metrics['packet_loss']['score'])
                weights.append(0.4)  # Packet loss has 40% weight
            
            if scores:
                overall_score = sum(s * w for s, w in zip(scores, weights)) / sum(weights)
            else:
                overall_score = 0
        else:
            overall_score = 0
        
        # Determine quality grade
        if overall_score >= 90:
            quality_grade = 'A'
        elif overall_score >= 80:
            quality_grade = 'B'
        elif overall_score >= 70:
            quality_grade = 'C'
        elif overall_score >= 60:
            quality_grade = 'D'
        else:
            quality_grade = 'F'
        
        return jsonify({
            'time_period_hours': hours,
            'overall_score': round(overall_score, 1),
            'quality_grade': quality_grade,
            'quality_metrics': quality_metrics,
            'calculated_at': datetime.utcnow().isoformat() + 'Z'
        })
        
    except Exception as e:
        logger.error(f"Error getting network quality score: {e}")
        return jsonify({'error': str(e)}), 500


# Error handlers for the performance API blueprint
@performance_api.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@performance_api.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500