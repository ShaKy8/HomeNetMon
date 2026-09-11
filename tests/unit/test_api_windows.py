"""Range parameters the pages actually send must be honoured by the API."""

from datetime import datetime, timedelta

import pytest

from models import Device, MonitoringData


@pytest.fixture
def device(db_session):
    d = Device(ip_address='192.168.1.90', mac_address='00:ab:00:00:00:90', hostname='win-test',
               device_type='computer', is_monitored=True, last_seen=datetime.utcnow())
    db_session.add(d)
    db_session.commit()
    now = datetime.utcnow()
    db_session.add_all(MonitoringData(device_id=d.id, response_time=float(i), timestamp=now - timedelta(minutes=i))
                       for i in range(60))
    db_session.commit()
    return d


def test_monitoring_data_honours_limit(client, device):
    r = client.get(f'/api/monitoring/data?device_id={device.id}&hours=24&limit=500')
    assert r.status_code == 200
    body = r.get_json()
    assert len(body['monitoring_data']) == 60          # default page size used to cap this at 25
    assert body['pagination']['per_page'] == 500


def test_monitoring_data_limit_is_capped(client, device):
    r = client.get(f'/api/monitoring/data?device_id={device.id}&limit=999999')
    assert r.get_json()['pagination']['per_page'] == 2000


def test_health_score_accepts_days(client, device):
    r = client.get('/api/analytics/network-health-score?days=30')
    assert r.status_code == 200
    assert r.get_json()['metrics']['total_pings'] == 60
    r = client.get('/api/analytics/device-insights?days=30')
    assert r.status_code == 200


def test_scan_status_timestamps_are_utc(client):
    r = client.get('/api/devices/scan-status')
    assert r.status_code == 200
    ts = r.get_json().get('timestamp') or ''
    assert ts.endswith('Z')
