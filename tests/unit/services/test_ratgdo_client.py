"""services/ratgdo_client.py: ESPHome-ratgdo URL/JSON/SSE handling with no network."""

import threading
from unittest.mock import Mock, patch

import pytest
import requests

from services import ratgdo_client as rc


# ---- parse_host ---------------------------------------------------------------

@pytest.mark.parametrize('value, expected', [
    ('192.168.86.42', ('192.168.86.42', 80)),
    (' 192.168.86.42:8080 ', ('192.168.86.42', 8080)),
    ('127.0.0.1:8099', ('127.0.0.1', 8099)),
    ('ratgdov25i-a1b2c3.local', ('ratgdov25i-a1b2c3.local', 80)),
    ('Ratgdo32-ABCDEF', ('ratgdo32-abcdef', 80)),
])
def test_parse_host_accepts_lan_ips_and_hostnames(value, expected):
    assert rc.parse_host(value) == expected


@pytest.mark.parametrize('value', ['', '   ', '8.8.8.8', '100.99.81.103', 'http://192.168.86.42', '192.168.86.42:abc',
                                   '192.168.86.42:70000', 'bad host!', 'fe80::1'])
def test_parse_host_rejects_public_and_malformed(value):
    with pytest.raises(ValueError):
        rc.parse_host(value)


# ---- entity ids and state mapping -----------------------------------------------

@pytest.mark.parametrize('raw, expected', [
    ('cover-door', ('cover', 'door')),
    ('binary_sensor-obstruction', ('binary_sensor', 'obstruction')),
    ('lock-lock_remotes', ('lock', 'lock_remotes')),
    ('cover/Door', ('cover', 'door')),
    ('text_sensor/Firmware Version', ('text_sensor', 'firmware_version')),
    ('lock/Lock remotes', ('lock', 'lock_remotes')),
    ('cover/Garage/Door', ('cover', 'door')),
])
def test_normalise_entity_id_handles_both_esphome_formats(raw, expected):
    assert rc.normalise_entity_id(raw) == expected


def test_apply_entity_maps_the_cover_states():
    state = rc.empty_state()
    assert rc.apply_entity(state, {'id': 'cover-door', 'state': 'CLOSED', 'value': 0.0, 'current_operation': 'IDLE'}) \
        == {'door': 'closed', 'position': 0.0}
    assert rc.apply_entity(state, {'id': 'cover-door', 'state': 'OPEN', 'value': 0.3, 'current_operation': 'OPENING'}) \
        == {'door': 'opening', 'position': 0.3}
    assert rc.apply_entity(state, {'id': 'cover-door', 'state': 'OPEN', 'value': 1.0, 'current_operation': 'IDLE'}) \
        == {'door': 'open', 'position': 1.0}
    assert rc.apply_entity(state, {'id': 'cover-door', 'state': 'OPEN', 'value': 0.5, 'current_operation': 'CLOSING'}) \
        == {'door': 'closing', 'position': 0.5}
    assert rc.apply_entity(state, {'id': 'cover-door', 'state': 'OPEN', 'value': 0.5, 'current_operation': 'IDLE'}) \
        == {'door': 'stopped'}
    # unchanged document -> no changes
    assert rc.apply_entity(state, {'id': 'cover-door', 'state': 'OPEN', 'value': 0.5, 'current_operation': 'IDLE'}) == {}


def test_apply_entity_maps_the_other_entities():
    state = rc.empty_state()
    assert rc.apply_entity(state, {'id': 'light-light', 'state': 'ON', 'value': True}) == {'light': True}
    assert rc.apply_entity(state, {'id': 'lock/Lock remotes', 'state': 'LOCKED', 'value': True}) == {'lock': True}
    assert rc.apply_entity(state, {'id': 'binary_sensor-obstruction', 'state': 'OFF', 'value': False}) == {'obstruction': False}
    assert rc.apply_entity(state, {'id': 'binary_sensor-motion', 'state': 'ON', 'value': True}) == {'motion': True}
    assert rc.apply_entity(state, {'id': 'binary_sensor-motor', 'state': 'ON', 'value': True}) == {'motor': True}
    assert rc.apply_entity(state, {'id': 'sensor-openings', 'state': '123', 'value': 123.0}) == {'openings': 123}
    assert rc.apply_entity(state, {'id': 'text_sensor/Firmware Version', 'state': '2025.8.1', 'value': '2025.8.1'}) \
        == {'firmware': '2025.8.1'}
    assert rc.apply_entity(state, {'id': 'switch-learn', 'state': 'OFF'}) == {}
    assert rc.apply_entity(state, 'not a dict') == {}
    assert rc.apply_entity(state, {'no': 'id'}) == {}


def test_empty_state_has_the_fixed_key_set():
    assert set(rc.empty_state()) == {'door', 'position', 'light', 'lock', 'obstruction', 'motion', 'motor',
                                     'openings', 'firmware', 'online', 'last_update', 'board'}


# ---- probe ----------------------------------------------------------------------

def _response(status=200, json_data=None, json_error=False):
    r = Mock(status_code=status)
    if json_error:
        r.json.side_effect = ValueError('no json')
    else:
        r.json.return_value = json_data
    return r


def test_probe_returns_the_cover_document():
    doc = {'id': 'cover-door', 'state': 'CLOSED', 'value': 0.0, 'current_operation': 'IDLE'}
    with patch('services.ratgdo_client.requests.get', return_value=_response(200, doc)) as get:
        assert rc.probe('192.168.1.50') == doc
    assert get.call_args.args[0] == 'http://192.168.1.50:80/cover/door'
    assert get.call_args.kwargs['timeout'] == 2.0


@pytest.mark.parametrize('response', [
    _response(200, {'id': 'light-light', 'state': 'ON'}),      # some other ESPHome node
    _response(404, {'error': 'nope'}),
    _response(200, None, json_error=True),
])
def test_probe_rejects_non_ratgdo_answers(response):
    with patch('services.ratgdo_client.requests.get', return_value=response):
        assert rc.probe('192.168.1.50') is None


def test_probe_never_raises():
    with patch('services.ratgdo_client.requests.get', side_effect=requests.ConnectionError('refused')):
        assert rc.probe('192.168.1.50') is None
    assert rc.probe('8.8.8.8') is None        # public address is refused before any request


# ---- RatgdoClient -----------------------------------------------------------------

class FakeSession:
    def __init__(self, responses=None, fail=None):
        self.calls = []
        self.responses = responses or {}
        self.fail = fail

    def get(self, url, **kwargs):
        self.calls.append(('GET', url, kwargs))
        if self.fail:
            raise self.fail
        path = url.split('//', 1)[1].split('/', 1)[1]
        if path in self.responses:
            return _response(200, self.responses[path])
        return _response(404, {'error': 'not found'})

    def post(self, url, **kwargs):
        self.calls.append(('POST', url, kwargs))
        if self.fail:
            raise self.fail
        return Mock(status_code=200)


FULL_BOARD = {
    'cover/door': {'id': 'cover-door', 'state': 'OPEN', 'value': 1.0, 'current_operation': 'IDLE'},
    'light/light': {'id': 'light-light', 'state': 'ON', 'value': True},
    'lock/lock_remotes': {'id': 'lock-lock_remotes', 'state': 'UNLOCKED', 'value': False},
    'binary_sensor/obstruction': {'id': 'binary_sensor-obstruction', 'state': 'OFF', 'value': False},
    'binary_sensor/motion': {'id': 'binary_sensor-motion', 'state': 'OFF', 'value': False},
    'binary_sensor/motor': {'id': 'binary_sensor-motor', 'state': 'OFF', 'value': False},
    'sensor/openings': {'id': 'sensor-openings', 'state': '42', 'value': 42},
    'text_sensor/firmware_version': {'id': 'text_sensor-firmware_version', 'state': '2025.8.1'},
}


def test_snapshot_folds_every_entity():
    session = FakeSession(FULL_BOARD)
    client = rc.RatgdoClient('192.168.1.50', session=session)
    state = client.snapshot()
    assert state['door'] == 'open' and state['light'] is True and state['lock'] is False
    assert state['openings'] == 42 and state['firmware'] == '2025.8.1' and state['online'] is True
    assert state['board']['host'] == '192.168.1.50'
    assert len(session.calls) == len(rc.ENTITIES)
    assert session.calls[0][1] == 'http://192.168.1.50:80/cover/door'


def test_snapshot_tolerates_missing_optional_entities_but_not_the_door():
    only_door = {'cover/door': FULL_BOARD['cover/door']}
    state = rc.RatgdoClient('192.168.1.50', session=FakeSession(only_door)).snapshot()
    assert state['door'] == 'open' and state['light'] is None
    with pytest.raises(rc.RatgdoError):
        rc.RatgdoClient('192.168.1.50', session=FakeSession({})).snapshot()


def test_connection_errors_become_ratgdo_error():
    client = rc.RatgdoClient('192.168.1.50', session=FakeSession(fail=requests.ConnectionError('refused')))
    with pytest.raises(rc.RatgdoError):
        client.snapshot()
    with pytest.raises(rc.RatgdoError):
        client.door('open')


def test_commands_post_the_esphome_urls_with_basic_auth():
    session = FakeSession()
    client = rc.RatgdoClient('ratgdov25i-a1b2c3.local:8080', username='admin', password='secret', session=session)
    client.door('open'); client.light('turn_off'); client.lock('lock'); client.press('sync')
    urls = [c[1] for c in session.calls]
    assert urls == ['http://ratgdov25i-a1b2c3.local:8080/cover/door/open',
                    'http://ratgdov25i-a1b2c3.local:8080/light/light/turn_off',
                    'http://ratgdov25i-a1b2c3.local:8080/lock/lock_remotes/lock',
                    'http://ratgdov25i-a1b2c3.local:8080/button/sync/press']
    auth = session.calls[0][2]['auth']
    assert auth.username == 'admin' and auth.password == 'secret'
    assert session.calls[0][2]['timeout'] == 3.0


def test_commands_validate_actions_before_touching_the_network():
    session = FakeSession()
    client = rc.RatgdoClient('192.168.1.50', session=session)
    for call in (lambda: client.door('explode'), lambda: client.light('on'), lambda: client.lock('close'),
                 lambda: client.press('self_destruct')):
        with pytest.raises(ValueError):
            call()
    assert session.calls == []


def test_command_http_error_carries_the_status():
    session = FakeSession()
    session.post = lambda url, **kw: Mock(status_code=401)
    with pytest.raises(rc.RatgdoError) as info:
        rc.RatgdoClient('192.168.1.50', session=session).door('open')
    assert info.value.status == 401


# ---- SSE ---------------------------------------------------------------------------

class StreamSession:
    """A session whose GET returns a fake streaming response fed from ``lines``."""

    def __init__(self, lines, status=200):
        self.lines = lines
        self.status = status
        self.closed = False
        self.kwargs = None

    def get(self, url, **kwargs):
        self.kwargs = kwargs
        outer = self

        class Response:
            status_code = outer.status

            def iter_lines(self, decode_unicode=True):
                yield from outer.lines

            def close(self):
                outer.closed = True
        return Response()


def test_events_parses_state_and_ping_and_skips_junk():
    lines = [
        'event: ping', 'data: ', '',
        'event: state', 'data: {"id":"cover-door","state":"OPEN","value":0.4,"current_operation":"OPENING"}', '',
        ': comment line', '',
        'event: log', 'data: [I][ratgdo:123]: hello', '',
        'event: state', 'data: {not json', '',
        'event: state', 'data: {"id":"light-light","state":"ON","value":true}',      # stream ends without blank line
    ]
    session = StreamSession(lines)
    states, pings = [], []
    rc.RatgdoClient('192.168.1.50', session=session).events(threading.Event(), states.append, lambda: pings.append(1))
    assert [s['id'] for s in states] == ['cover-door', 'light-light']
    assert pings == [1]
    assert session.closed is True
    assert session.kwargs['stream'] is True and session.kwargs['timeout'] == (3.0, 90)


def test_events_stops_when_asked():
    stop = threading.Event()
    seen = []

    def on_state(doc):
        seen.append(doc)
        stop.set()
    lines = ['event: state', 'data: {"id":"cover-door","state":"CLOSED","value":0,"current_operation":"IDLE"}', '',
             'event: state', 'data: {"id":"light-light","state":"ON"}', '']
    rc.RatgdoClient('192.168.1.50', session=StreamSession(lines)).events(stop, on_state)
    assert len(seen) == 1


def test_events_raises_on_http_error_and_connection_error():
    with pytest.raises(rc.RatgdoError) as info:
        rc.RatgdoClient('192.168.1.50', session=StreamSession([], status=401)).events(threading.Event(), lambda d: None)
    assert info.value.status == 401

    class Broken:
        def get(self, url, **kwargs):
            raise requests.ConnectionError('gone')
    with pytest.raises(rc.RatgdoError):
        rc.RatgdoClient('192.168.1.50', session=Broken()).events(threading.Event(), lambda d: None)
