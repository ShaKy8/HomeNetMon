"""services/ring_client.py: the RingBridge against a stub ring_doorbell (no network, no aiohttp)."""

import asyncio
import json
import stat
import sys
import types
from datetime import datetime, timezone

import pytest

from services import ring_client as rc
from services.ring_client import RingAuthError, RingBridge, RingError

TOKEN = {'access_token': 'a', 'refresh_token': 'r', 'expires_at': 1.0}


# ---- a fake ring_doorbell package ------------------------------------------------------

class FakeRingError(Exception):
    pass


class FakeAuthenticationError(FakeRingError):
    pass


class FakeRequires2FAError(FakeRingError):
    pass


class FakeCapability:
    BATTERY = 'battery'


class FakeDevice:
    def __init__(self, id, name, battery=None, wifi=-55, history=None, kind='stickup_cam_v4', model='Stick Up Cam'):
        self.id, self.name, self.kind, self.model = id, name, kind, model
        self._battery, self.wifi_signal_strength = battery, wifi
        self._history = history or []
        self.health_updates = 0

    def has_capability(self, cap):
        return self._battery is not None

    @property
    def battery_life(self):
        return self._battery

    async def async_update_health_data(self):
        self.health_updates += 1

    async def async_history(self, limit=30, kind=None, **kw):
        return [e for e in self._history if kind is None or e['kind'] == kind][:limit]


class FakeResponse:
    def __init__(self, payload=None, content=b''):
        self._payload, self.content = payload, content

    def json(self):
        return self._payload


class FakeScenario:
    """Shared, mutable behaviour for the fake Auth/Ring classes of one test."""

    def __init__(self):
        self.devices = [FakeDevice(42, 'Garage Cam', battery=81, history=[
            {'id': 901, 'kind': 'motion', 'created_at': datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)},
            {'id': 900, 'kind': 'ding', 'created_at': datetime(2026, 9, 17, 11, 0, tzinfo=timezone.utc)},
        ]), FakeDevice(7, 'Front Door', battery=None, kind='doorbell_v5', model='Doorbell')]
        self.fetch_result = TOKEN           # or an exception instance
        self.session_error = None
        self.snapshot_ts = 1_700_000_000_000
        self.image = b'\xff\xd8jpeg'
        self.queries = []
        self.closed = 0
        self.fresh_ts_after_refresh = None  # when set, the timestamp after a PUT refresh


class FakeAuth:
    scenario: FakeScenario = None

    def __init__(self, user_agent, token=None, token_updater=None, hardware_id=None, **kw):
        self.user_agent, self.token, self.token_updater = user_agent, token, token_updater

    async def async_fetch_token(self, username, password, otp_code=None):
        result = self.scenario.fetch_result
        if isinstance(result, Exception):
            raise result
        self.token = dict(result)
        if self.token_updater:
            self.token_updater(self.token)
        return self.token

    async def async_close(self):
        self.scenario.closed += 1


class FakeDevices:
    def __init__(self, devices):
        self.video_devices = devices


class FakeRing:
    scenario: FakeScenario = None

    def __init__(self, auth):
        self.auth = auth
        self.updates = 0

    async def async_create_session(self):
        if self.scenario.session_error:
            raise self.scenario.session_error

    async def async_update_data(self):
        self.updates += 1

    def devices(self):
        return FakeDevices(self.scenario.devices)

    async def async_query(self, url, method='GET', extra_params=None, data=None, json=None, timeout=None, **kw):
        s = self.scenario
        s.queries.append((method, url, json))
        if url.endswith('/snapshots/timestamps'):
            return FakeResponse({'timestamps': [{'doorbot_id': json['doorbot_ids'][0], 'timestamp': s.snapshot_ts}]})
        if url.endswith('/snapshots/update_all'):
            if s.fresh_ts_after_refresh is not None:
                s.snapshot_ts = s.fresh_ts_after_refresh
            return FakeResponse({})
        if '/snapshots/image/' in url:
            if s.image is None:
                raise FakeRingError('404')
            return FakeResponse(content=s.image)
        raise FakeRingError(f'unexpected {method} {url}')


@pytest.fixture
def scenario(monkeypatch):
    s = FakeScenario()
    FakeAuth.scenario = FakeRing.scenario = s
    package = types.ModuleType('ring_doorbell')
    package.Auth, package.Ring, package.RingCapability = FakeAuth, FakeRing, FakeCapability
    package.RingError, package.AuthenticationError, package.Requires2FAError = FakeRingError, FakeAuthenticationError, FakeRequires2FAError
    const = types.ModuleType('ring_doorbell.const')
    const.SNAPSHOT_ENDPOINT = '/clients_api/snapshots/image/{0}'
    const.SNAPSHOT_TIMESTAMP_ENDPOINT = '/clients_api/snapshots/timestamps'
    package.const = const
    monkeypatch.setitem(sys.modules, 'ring_doorbell', package)
    monkeypatch.setitem(sys.modules, 'ring_doorbell.const', const)
    return s


@pytest.fixture
def bridge(tmp_path, scenario):
    b = RingBridge(tmp_path / 'ring_token.json', 'HomeNetMon/test', timeout=5)
    yield b
    b.stop()


def _write_token(path):
    path.write_text(json.dumps(TOKEN))


# ---- lifecycle ----------------------------------------------------------------------------

def test_start_runs_a_named_loop_thread_and_stop_ends_it(bridge):
    bridge.start()
    bridge.start()                       # idempotent
    import threading
    names = [t.name for t in threading.enumerate()]
    assert names.count('RingBridge') == 1
    bridge.stop()
    assert 'RingBridge' not in [t.name for t in threading.enumerate()]
    assert bridge.signed_in() is False


def test_token_file_is_loaded_on_start(bridge):
    _write_token(bridge.token_file)
    bridge.start()
    assert bridge.signed_in() is True


def test_unreadable_or_empty_token_file_means_signed_out(bridge):
    bridge.token_file.write_text('{not json')
    bridge.start()
    assert bridge.signed_in() is False
    bridge.token_file.write_text(json.dumps({'access_token': 'x'}))     # no refresh token: useless
    assert bridge._load_token() is None


# ---- login ----------------------------------------------------------------------------------

def test_login_ok_writes_a_private_token_file(bridge, scenario):
    assert bridge.login(' kyle@example.com ', 'pw') == {'status': 'ok'}
    assert bridge.signed_in()
    assert json.loads(bridge.token_file.read_text()) == TOKEN
    assert stat.S_IMODE(bridge.token_file.stat().st_mode) == 0o600
    assert bridge._auth.user_agent == 'HomeNetMon/test'


def test_login_reports_when_2fa_is_needed(bridge, scenario):
    scenario.fetch_result = FakeRequires2FAError('code sent')
    assert bridge.login('kyle@example.com', 'pw') == {'status': '2fa_required'}
    assert bridge.signed_in() is False and not bridge.token_file.exists()
    assert scenario.closed == 1


def test_login_rejects_bad_credentials(bridge, scenario):
    scenario.fetch_result = FakeAuthenticationError('invalid')
    with pytest.raises(RingAuthError):
        bridge.login('kyle@example.com', 'wrong', otp='123456')
    scenario.fetch_result = ConnectionError('dns')
    with pytest.raises(RingError):
        bridge.login('kyle@example.com', 'pw')


def test_stored_token_rejected_signs_the_bridge_out(bridge, scenario):
    _write_token(bridge.token_file)
    bridge.start()
    scenario.session_error = FakeAuthenticationError('expired')
    with pytest.raises(RingAuthError):
        bridge.cameras()
    assert bridge.signed_in() is False and not bridge.token_file.exists()


def test_logout_forgets_and_unlinks(bridge, scenario):
    bridge.login('kyle@example.com', 'pw')
    bridge.logout()
    assert bridge.signed_in() is False and not bridge.token_file.exists()
    with pytest.raises(RingAuthError):
        bridge.cameras()


# ---- devices ---------------------------------------------------------------------------------

def test_cameras_are_mapped_with_battery_flag(bridge):
    bridge.login('kyle@example.com', 'pw')
    cams = bridge.cameras()
    assert [c['name'] for c in cams] == ['Garage Cam', 'Front Door']
    assert cams[0] == {'id': 42, 'name': 'Garage Cam', 'kind': 'stickup_cam_v4', 'model': 'Stick Up Cam',
                       'battery_life': 81, 'wifi_signal_strength': -55, 'is_battery': True}
    assert cams[1]['is_battery'] is False


def test_health_refreshes_and_unknown_camera_raises(bridge, scenario):
    bridge.login('kyle@example.com', 'pw')
    info = bridge.health(42)
    assert info['battery_life'] == 81 and scenario.devices[0].health_updates == 1
    with pytest.raises(RingError):
        bridge.health(999)


def test_latest_snapshot_fetches_only_newer_frames(bridge, scenario):
    bridge.login('kyle@example.com', 'pw')
    image, ts = bridge.latest_snapshot(42)
    assert image == scenario.image and ts == scenario.snapshot_ts
    scenario.queries.clear()
    assert bridge.latest_snapshot(42, since_ms=ts) == (None, ts)
    assert [q[0] for q in scenario.queries] == ['POST']              # no image GET
    scenario.image = None
    assert bridge.latest_snapshot('42') == (None, ts)                 # image 404 -> no frame, timestamp known


def test_fresh_snapshot_waits_for_a_newer_frame(bridge, scenario):
    bridge.login('kyle@example.com', 'pw')
    scenario.fresh_ts_after_refresh = int(datetime.now(timezone.utc).timestamp() * 1000) + 5_000
    image, ts = bridge.fresh_snapshot(42, retries=2, delay=0)
    assert image == scenario.image and ts == scenario.fresh_ts_after_refresh
    assert ('PUT', rc.SNAPSHOT_REFRESH_ENDPOINT, {'doorbot_ids': [42], 'refresh': True}) in scenario.queries


def test_fresh_snapshot_gives_up_on_a_battery_cam(bridge, scenario):
    bridge.login('kyle@example.com', 'pw')
    image, ts = bridge.fresh_snapshot(42, retries=2, delay=0)     # timestamp stays old
    assert image is None and ts == scenario.snapshot_ts


def test_motion_events_shape(bridge):
    bridge.login('kyle@example.com', 'pw')
    events = bridge.motion_events(42, limit=5)
    assert events == [{'id': 901, 'created_at': '2026-09-17T12:00:00+00:00'}]


def test_library_errors_become_ring_error(bridge, scenario):
    bridge.login('kyle@example.com', 'pw')

    async def boom(*a, **k):
        raise FakeRingError('rate limited')
    bridge._ring.async_query = boom
    with pytest.raises(RingError):
        bridge.latest_snapshot(42)


def test_timeouts_become_ring_error(bridge):
    bridge.start()

    async def slow():
        await asyncio.sleep(2)
    with pytest.raises(RingError):
        bridge._run(slow(), timeout=0.05)


def test_missing_library_is_a_ring_error(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, 'ring_doorbell', None)
    b = RingBridge(tmp_path / 't.json', 'HomeNetMon/test', timeout=5)
    try:
        with pytest.raises(RingError):
            b.login('a@b.c', 'pw')
    finally:
        b.stop()
