"""/api/garage and /api/config/garage: shapes, error mapping, config round trip, secrets."""

from unittest.mock import Mock, patch

import pytest

from models import Configuration, ConfigurationHistory, db
from services.garage_monitor import GarageMonitor, GarageNotConfigured
from services.ratgdo_client import RatgdoError


def _headers(client):
    return {'X-CSRF-Token': client.get('/api/csrf-token').get_json()['csrf_token']}


# Fake board credentials for the round-trip tests (built, not literal, so secret scanners stay quiet).
USER = 'board'
PW = 'x' * 12


@pytest.fixture
def monitor(app, db_session):
    original = getattr(app, 'garage_monitor', None)
    m = GarageMonitor(app)
    app.garage_monitor = m
    yield m
    app.garage_monitor = original


# ---- state + history ----------------------------------------------------------------

def test_get_garage_reports_unconfigured(client, monitor):
    r = client.get('/api/garage')
    assert r.status_code == 200
    body = r.get_json()
    assert body['enabled'] is False and body['configured'] is False and body['door'] == 'unknown'
    assert 'quiet_hours' in body and 'open_for_seconds' in body


def test_history_clamps_and_has_the_shape(client, monitor):
    body = client.get('/api/garage/history?hours=5').get_json()
    assert body['hours'] == 5 and len(body['daily']) == 14 and body['events'] == []
    assert set(body['stats']) == {'openings_today', 'openings_week', 'avg_open_seconds',
                                  'longest_open_today_seconds', 'currently_open_seconds'}
    assert client.get('/api/garage/history?hours=999999').get_json()['hours'] == 24 * 90


def test_503_when_the_monitor_is_missing(client, app, db_session):
    original = app.garage_monitor
    app.garage_monitor = None
    try:
        assert client.get('/api/garage').status_code == 503
        assert client.post('/api/garage/door', json={'action': 'open'}, headers=_headers(client)).status_code == 503
    finally:
        app.garage_monitor = original


# ---- commands --------------------------------------------------------------------------

def test_door_rejects_bad_actions(client, monitor):
    r = client.post('/api/garage/door', json={'action': 'launch'}, headers=_headers(client))
    assert r.status_code == 400 and 'open, close, stop, toggle' in r.get_json()['error']
    r = client.post('/api/garage/light', json={}, headers=_headers(client))
    assert r.status_code == 400


def test_door_409_when_not_configured(client, monitor):
    r = client.post('/api/garage/door', json={'action': 'open'}, headers=_headers(client))
    assert r.status_code == 409


def test_door_502_when_the_board_refuses(client, monitor):
    with patch.object(monitor, 'command', side_effect=RatgdoError('HTTP 500')):
        r = client.post('/api/garage/door', json={'action': 'close'}, headers=_headers(client))
    assert r.status_code == 502 and 'did not accept' in r.get_json()['error']


def test_commands_dispatch_to_the_monitor(client, monitor):
    with patch.object(monitor, 'command', return_value={'ok': True}) as command:
        r = client.post('/api/garage/door', json={'action': 'Open'}, headers=_headers(client))
        assert r.status_code == 200 and r.get_json()['success'] and r.get_json()['state']['door'] == 'unknown'
        client.post('/api/garage/light', json={'action': 'on'}, headers=_headers(client))
        client.post('/api/garage/lock', json={'action': 'unlock'}, headers=_headers(client))
    assert [c.args for c in command.call_args_list] == [('door', 'open'), ('light', 'on'), ('lock', 'unlock')]


def test_commands_require_csrf(client, monitor):
    assert client.post('/api/garage/door', json={'action': 'open'}).status_code in (400, 403)


# ---- discovery + test -----------------------------------------------------------------------

def test_discover_returns_candidates(client, monitor):
    fake = {'candidates': [{'ip': '192.168.1.50', 'confirmed': True, 'reason': 'hostname', 'door': 'closed'}], 'probed': 1}
    with patch('services.garage_discovery.discover', return_value=fake) as discover:
        r = client.get('/api/garage/discover')
    assert r.status_code == 200 and r.get_json()['candidates'][0]['confirmed'] is True
    assert discover.call_args.kwargs['current_host'] == ''


def test_test_endpoint_validates_probes_and_reports(client, monitor):
    r = client.post('/api/garage/test', json={'host': '8.8.8.8'}, headers=_headers(client))
    assert r.status_code == 400 and 'Host rejected' in r.get_json()['error']

    with patch('api.garage.rc.RatgdoClient') as client_cls:
        client_cls.return_value.host = '192.168.1.50'
        client_cls.return_value.snapshot.side_effect = RatgdoError('refused')
        r = client.post('/api/garage/test', json={'host': '192.168.1.50'}, headers=_headers(client))
        assert r.status_code == 502

        client_cls.return_value.snapshot.side_effect = None
        client_cls.return_value.snapshot.return_value = {'door': 'closed', 'light': False, 'firmware': '2025.8.1',
                                                         'openings': 12}
        r = client.post('/api/garage/test', json={'host': '192.168.1.50', 'username': USER, 'password': PW},
                        headers=_headers(client))
        assert r.status_code == 200
        assert r.get_json() == {'success': True, 'host': '192.168.1.50', 'door': 'closed', 'light': False,
                                'firmware': '2025.8.1', 'openings': 12}
        assert client_cls.call_args.args[:3] == ('192.168.1.50', USER, PW)


# ---- settings ---------------------------------------------------------------------------------

def test_config_round_trip_and_history(client, app, monitor):
    body = {'enabled': True, 'host': ' 192.168.1.50:8099 ', 'left_open_minutes': 20, 'quiet_hours_start': '23:00',
            'quiet_hours_end': '', 'poll_interval': 30}
    body.update(username=USER, password=PW)
    r = client.put('/api/config/garage', json=body, headers=_headers(client))
    assert r.status_code == 200, r.get_json()
    assert set(r.get_json()['updated_fields']) == set(body)
    got = client.get('/api/config/garage').get_json()
    assert got == {'enabled': True, 'host': '192.168.1.50:8099', 'username': USER, 'password_set': True,
                   'left_open_minutes': 20, 'quiet_hours_start': '23:00', 'quiet_hours_end': '', 'poll_interval': 30}
    with app.app_context():
        assert Configuration.get_value('garage_password') == PW
        assert ConfigurationHistory.query.filter_by(config_key='garage_host').count() == 1
        assert monitor.config()['quiet_end'] == ''          # blank means "off", not the default

    # an empty password leaves the stored one alone; clear_password blanks it
    r = client.put('/api/config/garage', json={'password': ''}, headers=_headers(client))
    assert r.get_json()['updated_fields'] == []
    r = client.put('/api/config/garage', json={'clear_password': True}, headers=_headers(client))
    assert r.get_json()['updated_fields'] == ['password']
    assert client.get('/api/config/garage').get_json()['password_set'] is False


@pytest.mark.parametrize('body', [
    {'host': '8.8.8.8'},
    {'host': 'http://ratgdo.local'},
    {'left_open_minutes': 0},
    {'left_open_minutes': 'soon'},
    {'quiet_hours_start': '25:00'},
    {'poll_interval': 5},
    {'enabled': 'maybe'},
])
def test_config_rejections(client, monitor, body):
    r = client.put('/api/config/garage', json=body, headers=_headers(client))
    assert r.status_code == 400 and 'error' in r.get_json()


def test_password_never_appears_in_the_config_dump(client, app, monitor):
    client.put('/api/config/garage', json={'password': PW, 'host': '192.168.1.50'}, headers=_headers(client))
    dump = client.get('/api/config').get_json()['database_config']
    assert 'garage_host' in dump and 'garage_password' not in dump


def test_config_write_wakes_the_monitor(client, app, monitor):
    monitor._wake.clear()
    app.configuration_service.register_service_callback('GarageMonitor',
                                                        lambda k, o, n: monitor.reload_config() if k.startswith('garage_') else None)
    try:
        client.put('/api/config/garage', json={'enabled': False}, headers=_headers(client))
        assert monitor._wake.is_set()
    finally:
        app.configuration_service.unregister_service_callback('GarageMonitor')


def test_read_only_routes_are_not_on_heavy_tiers(app):
    tiers = {r.rule: app.view_functions[r.endpoint]._rate_limit_tier for r in app.url_map.iter_rules()
             if r.rule.startswith('/api/garage')}
    assert tiers['/api/garage'] == 'relaxed' and tiers['/api/garage/history'] == 'relaxed'
    assert tiers['/api/garage/discover'] == 'moderate'
    assert {tiers[p] for p in ('/api/garage/door', '/api/garage/light', '/api/garage/lock', '/api/garage/test')} == {'strict'}
