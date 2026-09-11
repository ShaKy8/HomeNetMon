"""Per-device performance for the device page.

`/device/<id>` combines the collector's latest scores (services/performance_monitor.py,
PerformanceMetrics) with percentiles computed from the raw ping samples in the window;
`/device/<id>/timeline` buckets the collector rows by hour or day for the chart.
"""

from datetime import datetime, timedelta
from math import ceil

from flask import Blueprint, jsonify, request

from api.rate_limited_endpoints import create_endpoint_limiter
from models import Device, MonitoringData, PerformanceMetrics

performance_bp = Blueprint('performance', __name__)

MAX_HOURS = 24 * 90


def _window_hours(default=24):
    hours = request.args.get('hours', default=default, type=int) or default
    return max(1, min(hours, MAX_HOURS))


def _percentile(values, pct):
    """Nearest-rank percentile of a sorted list (values must be non-empty)."""
    idx = max(0, min(len(values) - 1, ceil(pct / 100 * len(values)) - 1))
    return values[idx]


def window_stats(device_id, hours):
    """Availability and response-time percentiles from MonitoringData over the window."""
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    rows = MonitoringData.query.filter(
        MonitoringData.device_id == device_id, MonitoringData.timestamp >= cutoff,
    ).with_entities(MonitoringData.response_time).all()
    checks = len(rows)
    ok = sorted(r[0] for r in rows if r[0] is not None)
    stats = {
        'hours': hours, 'checks': checks, 'failed': checks - len(ok),
        'uptime_pct': round(len(ok) / checks * 100, 1) if checks else None,
        'avg_ms': None, 'min_ms': None, 'p50_ms': None, 'p95_ms': None, 'max_ms': None,
    }
    if ok:
        stats.update(avg_ms=round(sum(ok) / len(ok), 1), min_ms=round(ok[0], 1), max_ms=round(ok[-1], 1),
                     p50_ms=round(_percentile(ok, 50), 1), p95_ms=round(_percentile(ok, 95), 1))
    return stats


@performance_bp.route('/device/<int:device_id>', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_performance(device_id):
    """Latest collector scores plus window percentiles for one device."""
    try:
        hours = _window_hours(24)
        device = Device.query.get(device_id)
        if device is None:
            return jsonify({'error': 'Device not found'}), 404
        latest = PerformanceMetrics.query.filter_by(device_id=device_id)\
            .order_by(PerformanceMetrics.timestamp.desc()).first()
        latest_view = None
        if latest is not None:
            latest_view = {
                'timestamp': latest.timestamp.isoformat() + 'Z' if latest.timestamp else None,
                'health_score': latest.health_score,
                'responsiveness_score': latest.responsiveness_score,
                'reliability_score': latest.reliability_score,
                'grade': latest.performance_grade,
                'status': latest.performance_status,
            }
        return jsonify({
            'device': {
                'id': device.id, 'name': device.display_name, 'ip_address': device.ip_address,
                'device_type': device.device_type, 'status': device.status,
            },
            'latest': latest_view,
            'window': window_stats(device_id, hours),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@performance_bp.route('/device/<int:device_id>/timeline', methods=['GET'])
@create_endpoint_limiter('relaxed')
def get_device_performance_timeline(device_id):
    """Collector rows bucketed by hour (default) or day: health, response time, uptime."""
    try:
        hours = _window_hours(24)
        granularity = 'day' if request.args.get('granularity') == 'day' else 'hour'
        device = Device.query.get(device_id)
        if device is None:
            return jsonify({'error': 'Device not found'}), 404
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        metrics = PerformanceMetrics.query.filter(
            PerformanceMetrics.device_id == device_id, PerformanceMetrics.timestamp >= cutoff,
        ).order_by(PerformanceMetrics.timestamp).all()

        buckets = {}
        for metric in metrics:
            if granularity == 'day':
                key = metric.timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
            else:
                key = metric.timestamp.replace(minute=0, second=0, microsecond=0)
            buckets.setdefault(key, []).append(metric)

        def avg(values):
            values = [v for v in values if v is not None]
            return round(sum(values) / len(values), 2) if values else None

        timeline = [{
            'timestamp': key.isoformat() + 'Z',
            'health_score': avg(m.health_score for m in rows),
            'avg_response_time': avg(m.avg_response_time for m in rows),
            'uptime_percentage': avg(m.uptime_percentage for m in rows),
            'sample_count': len(rows),
        } for key, rows in sorted(buckets.items())]

        return jsonify({
            'device': {'id': device.id, 'name': device.display_name, 'ip_address': device.ip_address},
            'timeline': timeline,
            'period_hours': hours,
            'granularity': granularity,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
