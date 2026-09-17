"""/api/garage and /api/config/garage: shapes, error mapping, Ring sign-in flow, config round trip."""

from unittest.mock import Mock, patch

import pytest

from models import Configuration, ConfigurationHistory
from services.door_vision import VisionError
from services.garage_monitor import GarageBusy, GarageMonitor, GarageNotConfigured
from services.ring_client import RingAuthError, RingError


def _headers(client):
    return {'X-CSRF-Token': client.get('/api/csrf-token').get_json()['csrf_token']}


# Fake Ring credentials (built, not literal, so secret scanners stay quiet).
EMAIL = 'kyle@example.com'
PW = 'x' * 12


@pytest.fixture
def monitor(app, db_session, tmp_path):
    original = getattr(app, 'garage_monitor', None)
    bridge = Mock()
    bridge.signed_in.return_value = False
    m = GarageMonitor(app, bridge=bridge, frame_dir=tmp_path / 'frames')
    app.garage_monitor = m
    yield m
    app.garage_monitor = original


# ---- state + history ----------------------------------------------------------------

def test_get_garage_reports_unconfigured(client, monitor):
    r = client.get('/api/garage')
    assert r.status_code == 200
    body = r.get_json()
    assert body['enabled'] is False and body['configured'] is False and body['door'] == 'unknown'
    assert body['ring'] == {'signed_in': False} and body['reading'] is None and 'vision' in body


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
        assert client.get('/api/garage/snapshot.jpg').status_code == 503
        assert client.post('/api/garage/check', json={}, headers=_headers(client)).status_code == 503
    finally:
        app.garage_monitor = original


# ---- snapshot --------------------------------------------------------------------------

def test_snapshot_404_until_a_frame_exists_then_no_store(client, monitor, tmp_path):
    assert client.get('/api/garage/snapshot.jpg').status_code == 404
    frames = tmp_path / 'frames'
    frames.mkdir()
    (frames / 'latest.jpg').write_bytes(b'\xff\xd8latest')
    (frames / 'event-7.jpg').write_bytes(b'\xff\xd8event')
    r = client.get('/api/garage/snapshot.jpg')
    assert r.status_code == 200 and r.mimetype == 'image/jpeg' and r.data == b'\xff\xd8latest'
    assert r.headers['Cache-Control'] == 'no-store'
    assert client.get('/api/garage/snapshot.jpg?event=7').data == b'\xff\xd8event'
    assert client.get('/api/garage/snapshot.jpg?event=8').status_code == 404
    assert client.get('/api/garage/snapshot.jpg?event=../latest').status_code == 404   # ids only, never a path
    assert client.get('/api/garage/snapshot.jpg?event=..%2Flatest').status_code == 404


# ---- check --------------------------------------------------------------------------------

def test_check_maps_errors(client, monitor):
    for error, status in ((GarageNotConfigured('off'), 409), (GarageBusy('busy'), 409),
                          (RingAuthError('token'), 409), (RingError('ring down'), 502), (VisionError('claude down'), 502)):
        with patch.object(monitor, 'check_once', side_effect=error):
            r = client.post('/api/garage/check', json={}, headers=_headers(client))
        assert r.status_code == status, error
        assert 'error' in r.get_json()


def test_check_returns_the_state(client, monitor):
    with patch.object(monitor, 'check_once', return_value={'door': 'open'}) as check:
        r = client.post('/api/garage/check', json={}, headers=_headers(client))
    assert r.status_code == 200 and r.get_json() == {'success': True, 'state': {'door': 'open'}}
    check.assert_called_once_with(fresh=True)


def test_check_requires_csrf(client, monitor):
    assert client.post('/api/garage/check', json={}).status_code in (400, 403)


# ---- Ring sign-in -------------------------------------------------------------------------

def test_login_flow(client, monitor):
    r = client.post('/api/garage/ring/login', json={'email': EMAIL}, headers=_headers(client))
    assert r.status_code == 400
    monitor._bridge.login.return_value = {'status': '2fa_required'}
    r = client.post('/api/garage/ring/login', json={'email': EMAIL, 'password': PW}, headers=_headers(client))
    assert r.status_code == 200 and r.get_json()['status'] == '2fa_required'
    monitor._bridge.login.return_value = {'status': 'ok'}
    r = client.post('/api/garage/ring/login', json={'email': EMAIL, 'password': PW, 'otp': ' 123456 '}, headers=_headers(client))
    assert r.status_code == 200 and r.get_json()['status'] == 'ok'
    assert monitor._bridge.login.call_args.args == (EMAIL, PW, '123456')
    monitor._bridge.login.side_effect = RingAuthError('bad')
    assert client.post('/api/garage/ring/login', json={'email': EMAIL, 'password': PW}, headers=_headers(client)).status_code == 401
    monitor._bridge.login.side_effect = RingError('down')
    assert client.post('/api/garage/ring/login', json={'email': EMAIL, 'password': PW}, headers=_headers(client)).status_code == 502
    assert client.post('/api/garage/ring/login', json={'email': EMAIL, 'password': PW}).status_code in (400, 403)   # CSRF


def test_logout_and_cameras(client, monitor):
    r = client.post('/api/garage/ring/logout', json={}, headers=_headers(client))
    assert r.status_code == 200 and monitor._bridge.logout.called
    assert client.get('/api/garage/ring/cameras').status_code == 409
    monitor._bridge.signed_in.return_value = True
    monitor._bridge.cameras.return_value = [{'id': 42, 'name': 'Garage Cam', 'is_battery': True}]
    r = client.get('/api/garage/ring/cameras')
    assert r.status_code == 200 and r.get_json()['cameras'][0]['name'] == 'Garage Cam'
    monitor._bridge.cameras.side_effect = RingError('down')
    assert client.get('/api/garage/ring/cameras').status_code == 502


# ---- settings ---------------------------------------------------------------------------------

def test_config_round_trip_and_history(client, app, monitor):
    body = {'enabled': True, 'camera_id': ' 42 ', 'camera_name': 'Garage Cam', 'check_interval': 600, 'motion_checks': False,
            'vision_model': 'claude-sonnet-5', 'scene_hint': 'white door', 'left_open_minutes': 20,
            'quiet_hours_start': '23:00', 'quiet_hours_end': '', 'reclassify_minutes': 30}
    r = client.put('/api/config/garage', json=body, headers=_headers(client))
    assert r.status_code == 200, r.get_json()
    assert set(r.get_json()['updated_fields']) == set(body)
    got = client.get('/api/config/garage').get_json()
    assert got == {'enabled': True, 'camera_id': '42', 'camera_name': 'Garage Cam', 'check_interval': 600, 'motion_checks': False,
                   'vision_model': 'claude-sonnet-5', 'scene_hint': 'white door', 'left_open_minutes': 20,
                   'quiet_hours_start': '23:00', 'quiet_hours_end': '', 'reclassify_minutes': 30, 'ring_signed_in': False,
                   'api_key_set': got['api_key_set'], 'vision_models': ['claude-opus-5', 'claude-sonnet-5', 'claude-haiku-4-5']}
    with app.app_context():
        assert Configuration.get_value('garage_camera_id') == '42'
        assert ConfigurationHistory.query.filter_by(config_key='garage_camera_id').count() == 1
        assert monitor.config()['quiet_end'] == '' and monitor.config()['vision_model'] == 'claude-sonnet-5'


@pytest.mark.parametrize('body', [
    {'camera_id': 'abc'},
    {'vision_model': 'gpt-4'},
    {'check_interval': 30},
    {'scene_hint': 'x' * 301},
    {'left_open_minutes': 0},
    {'quiet_hours_start': '25:00'},
    {'reclassify_minutes': 1},
    {'enabled': 'maybe'},
])
def test_config_rejections(client, monitor, body):
    r = client.put('/api/config/garage', json=body, headers=_headers(client))
    assert r.status_code == 400 and 'error' in r.get_json()


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
    assert tiers['/api/garage/snapshot.jpg'] == 'relaxed' and tiers['/api/garage/ring/cameras'] == 'moderate'
    assert {tiers[p] for p in ('/api/garage/check', '/api/garage/ring/login', '/api/garage/ring/logout')} == {'strict'}
