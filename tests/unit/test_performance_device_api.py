"""/api/performance/device/<id> and /timeline feed the device page's Performance card."""

from datetime import datetime, timedelta

import pytest

from models import Device, MonitoringData, PerformanceMetrics


@pytest.fixture
def device(db_session):
    d = Device(ip_address='192.168.1.95', mac_address='00:aa:00:00:00:95', hostname='perf', device_type='computer', is_monitored=True)
    db_session.add(d); db_session.commit()
    return d


def test_window_percentiles_and_availability(client, db_session, device):
    now = datetime.utcnow()
    samples = [10, 12, 14, 16, 18, 20, 22, 24, 26, 200, None, None]
    db_session.add_all(MonitoringData(device_id=device.id, response_time=v, timestamp=now - timedelta(minutes=i))
                       for i, v in enumerate(samples))
    db_session.commit()
    body = client.get(f'/api/performance/device/{device.id}?hours=1').get_json()
    w = body['window']
    assert w['checks'] == 12 and w['failed'] == 2 and w['uptime_pct'] == 83.3
    assert w['p50_ms'] == 18 and w['p95_ms'] == 200 and w['max_ms'] == 200 and w['min_ms'] == 10
    assert body['latest'] is None


def test_latest_collector_scores(client, db_session, device):
    db_session.add(PerformanceMetrics(device_id=device.id, timestamp=datetime.utcnow(), health_score=88.0,
                                      responsiveness_score=90.0, reliability_score=85.0))
    db_session.commit()
    latest = client.get(f'/api/performance/device/{device.id}').get_json()['latest']
    assert latest['health_score'] == 88.0 and latest['grade'] and latest['status']


def test_timeline_day_granularity(client, db_session, device):
    now = datetime.utcnow()
    db_session.add_all([
        PerformanceMetrics(device_id=device.id, timestamp=now - timedelta(hours=1), health_score=80, avg_response_time=10),
        PerformanceMetrics(device_id=device.id, timestamp=now - timedelta(hours=2), health_score=60, avg_response_time=30),
        PerformanceMetrics(device_id=device.id, timestamp=now - timedelta(days=2), health_score=50, avg_response_time=50),
    ])
    db_session.commit()
    body = client.get(f'/api/performance/device/{device.id}/timeline?hours=168&granularity=day').get_json()
    assert body['granularity'] == 'day' and len(body['timeline']) == 2
    assert body['timeline'][-1]['health_score'] == 70 and body['timeline'][-1]['sample_count'] == 2


def test_unknown_device_is_404(client, db_session):
    assert client.get('/api/performance/device/999999').status_code == 404
