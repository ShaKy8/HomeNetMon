"""GET /api/monitoring/alerts filters, facets and paging; acknowledge-all and bulk routes.
The alerts page used to fetch a 7-day / 50-row window and filter client-side."""

from datetime import datetime, timedelta

import pytest

from models import Alert, Device, db


def _token(client):
    return client.get('/api/csrf-token').get_json()['csrf_token']


@pytest.fixture
def fleet(db_session):
    a = Device(ip_address='192.168.1.60', mac_address='00:aa:00:00:00:60', hostname='printer-lobby', is_monitored=True)
    b = Device(ip_address='192.168.1.61', mac_address='00:aa:00:00:00:61', hostname='nas-01', custom_name='Big NAS', is_monitored=True)
    db_session.add_all([a, b]); db_session.commit()
    now = datetime.utcnow()
    rows = [
        Alert(device_id=a.id, alert_type='device_down', severity='critical', message='printer offline', created_at=now - timedelta(hours=1)),
        Alert(device_id=a.id, alert_type='security_new_service', severity='low', message='port 9100 open', created_at=now - timedelta(hours=2), acknowledged=True, acknowledged_by='ops'),
        Alert(device_id=b.id, alert_type='performance', alert_subtype='performance_warning', severity='warning', message='slow', created_at=now - timedelta(days=2)),
        Alert(device_id=b.id, alert_type='new_device', severity='info', message='new device seen', created_at=now - timedelta(days=10), resolved=True, resolved_at=now - timedelta(days=9)),
        Alert(device_id=b.id, alert_type='high_latency', severity='high', message='latency', created_at=now - timedelta(days=40)),
    ]
    db_session.add_all(rows); db_session.commit()
    return {'a': a, 'b': b, 'alerts': rows}


class TestListFilters:

    def test_defaults_are_active_within_seven_days(self, client, fleet):
        body = client.get('/api/monitoring/alerts').get_json()
        types = sorted(x['alert_type'] for x in body['alerts'])
        assert types == ['device_down', 'performance', 'security_new_service']
        assert body['pagination']['total'] == 3
        assert body['filters']['status'] == 'active' and body['filters']['hours'] == 168

    def test_all_time_and_all_statuses(self, client, fleet):
        body = client.get('/api/monitoring/alerts?status=all&hours=0').get_json()
        assert body['pagination']['total'] == 5

    def test_status_variants(self, client, fleet):
        assert client.get('/api/monitoring/alerts?status=resolved&hours=0').get_json()['pagination']['total'] == 1
        assert client.get('/api/monitoring/alerts?status=acknowledged&hours=0').get_json()['pagination']['total'] == 1
        assert client.get('/api/monitoring/alerts?status=unacknowledged&hours=0').get_json()['pagination']['total'] == 3

    def test_severity_csv(self, client, fleet):
        body = client.get('/api/monitoring/alerts?severity=warning,info&status=all&hours=0').get_json()
        assert sorted(x['severity'] for x in body['alerts']) == ['info', 'warning']

    def test_search_matches_device_names_and_message(self, client, fleet):
        assert client.get('/api/monitoring/alerts?q=Big%20NAS&status=all&hours=0').get_json()['pagination']['total'] == 3
        assert client.get('/api/monitoring/alerts?q=9100&status=all&hours=0').get_json()['pagination']['total'] == 1

    def test_paging(self, client, fleet):
        body = client.get('/api/monitoring/alerts?status=all&hours=0&per_page=2&page=2').get_json()
        assert len(body['alerts']) == 2
        assert body['pagination'] == {'page': 2, 'per_page': 2, 'total': 5, 'pages': 3, 'has_prev': True, 'has_next': True}

    def test_per_page_is_capped(self, client, fleet):
        assert client.get('/api/monitoring/alerts?per_page=5000').get_json()['pagination']['per_page'] == 200

    def test_facets(self, client, fleet):
        body = client.get('/api/monitoring/alerts?hours=0').get_json()
        assert body['facets']['status'] == {'active': 4, 'unacknowledged': 3, 'resolved': 1}
        assert body['facets']['severity']['critical'] == 1 and body['facets']['severity']['warning'] == 1

    def test_legacy_resolved_param_still_works(self, client, fleet):
        body = client.get('/api/monitoring/alerts?resolved=false&hours=0').get_json()
        assert body['pagination']['total'] == 4 and 'count' in body

    def test_priority_sort_does_not_error(self, client, fleet):
        assert client.get('/api/monitoring/alerts?sort=priority_score').status_code == 200

    def test_title_is_present(self, client, fleet):
        titles = {x['alert_type']: x['title'] for x in client.get('/api/monitoring/alerts').get_json()['alerts']}
        assert titles['device_down'] == 'Device offline' and titles['performance'] == 'Performance degraded'


class TestBulkActions:

    def test_acknowledge_all_respects_filters(self, client, fleet):
        r = client.post('/api/monitoring/alerts/acknowledge-all', json={'severity': 'critical'}, headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 200 and r.get_json()['count'] == 1
        assert Alert.query.filter_by(alert_type='device_down').first().acknowledged is True
        assert Alert.query.filter_by(alert_type='performance').first().acknowledged is False

    def test_acknowledge_all_without_filters_covers_every_open_alert(self, client, fleet):
        r = client.post('/api/monitoring/alerts/acknowledge-all', json={}, headers={'X-CSRF-Token': _token(client)})
        assert r.get_json()['count'] == 3           # 4 open, one already acknowledged

    def test_bulk_acknowledge_and_resolve_by_id(self, client, fleet):
        ids = [fleet['alerts'][0].id, fleet['alerts'][2].id]
        r = client.post('/api/monitoring/alerts/bulk-acknowledge', json={'alert_ids': ids}, headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 200 and r.get_json()['acknowledged_count'] == 2
        r = client.post('/api/monitoring/alerts/bulk-resolve', json={'alert_ids': ids}, headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 200 and r.get_json()['resolved_count'] == 2
        assert all(db.session.get(Alert, i).resolved for i in ids)

    def test_bulk_routes_validate_input(self, client, fleet):
        token = _token(client)
        assert client.post('/api/monitoring/alerts/bulk-acknowledge', json={}, headers={'X-CSRF-Token': token}).status_code == 400
        assert client.post('/api/monitoring/alerts/bulk-resolve', json={'alert_ids': ['x']}, headers={'X-CSRF-Token': token}).status_code == 400
