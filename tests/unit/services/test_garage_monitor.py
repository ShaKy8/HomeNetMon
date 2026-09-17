"""services/garage_monitor.py: transitions -> GarageEvent rows, alerts, offline handling, views."""

import threading
import time
from datetime import datetime, time as dtime, timedelta
from unittest.mock import Mock, patch

import pytest

from models import Alert, Configuration, Device, GarageEvent, db
from services import garage_monitor as gm
from services.garage_monitor import GarageMonitor, GarageNotConfigured, in_quiet_hours
from services.ratgdo_client import RatgdoError

HOST = '192.168.1.50'
T0 = datetime(2026, 9, 17, 14, 0, 0)
DAY = datetime.combine(datetime.utcnow().date(), dtime(12, 0))   # noon UTC today: local date is today in any zone <= +-11


@pytest.fixture
def garage(app, db_session):
    with app.app_context():
        Configuration.set_value('garage_enabled', 'true')
        Configuration.set_value('garage_host', HOST)
        Configuration.set_value('garage_quiet_hours_start', '')
        Configuration.set_value('garage_quiet_hours_end', '')
        db.session.commit()
    monitor = GarageMonitor(app)
    monitor._client = Mock(host=HOST)
    monitor._client_key = (HOST, '', '')
    monitor.state['board'] = {'host': HOST, 'name': None}
    return monitor


def _sync(monitor, **initial):
    """Initial state the board reported (no rows are written for it)."""
    changes = {'door': 'closed', 'position': 0.0, 'light': False, 'lock': False, 'obstruction': False, 'online': True}
    changes.update(initial)
    return monitor.apply_state(changes, now=T0, notify=False)


# ---- quiet hours (pure) --------------------------------------------------------------

@pytest.mark.parametrize('now, start, end, expected', [
    (dtime(23, 0), '22:00', '06:00', True),
    (dtime(2, 30), '22:00', '06:00', True),
    (dtime(6, 0), '22:00', '06:00', False),
    (dtime(12, 0), '22:00', '06:00', False),
    (dtime(9, 0), '08:00', '17:00', True),
    (dtime(17, 0), '08:00', '17:00', False),
    (dtime(23, 0), '', '06:00', False),
    (dtime(23, 0), '22:00', '', False),
    (dtime(23, 0), 'junk', '06:00', False),
    (dtime(23, 0), '22:00', '22:00', False),
])
def test_in_quiet_hours(now, start, end, expected):
    assert in_quiet_hours(now, start, end) is expected


# ---- transitions -> rows ----------------------------------------------------------------

def test_initial_sync_writes_no_rows_but_sets_state(app, garage):
    with app.app_context():
        rows = _sync(garage)
        assert rows == []
        assert garage.state['door'] == 'closed' and garage.state['online'] is True
        assert GarageEvent.query.count() == 0


def test_door_cycle_writes_rows_with_opened_flag_and_duration(app, garage):
    with app.app_context():
        _sync(garage)
        opening = garage.apply_state({'door': 'opening', 'position': 0.1}, now=T0 + timedelta(seconds=1), notify=False)
        assert len(opening) == 1 and opening[0].kind == 'door' and opening[0].value == 'opening'
        assert opening[0].opened is True and opening[0].source == 'external'
        assert garage.state['open_since'] == T0 + timedelta(seconds=1)

        opened = garage.apply_state({'door': 'open', 'position': 1.0}, now=T0 + timedelta(seconds=13), notify=False)
        assert opened[0].value == 'open' and opened[0].opened is False    # already counted at 'opening'

        garage.apply_state({'door': 'closing', 'position': 0.9}, now=T0 + timedelta(minutes=5), notify=False)
        closed = garage.apply_state({'door': 'closed', 'position': 0.0}, now=T0 + timedelta(minutes=5, seconds=12),
                                    notify=False)
        assert closed[0].value == 'closed' and closed[0].duration_s == pytest.approx(311.0)
        assert garage.state['open_since'] is None
        assert [r.value for r in GarageEvent.query.order_by(GarageEvent.id).all()] == ['opening', 'open', 'closing', 'closed']


def test_poll_only_closed_to_open_still_counts_an_opening(app, garage):
    with app.app_context():
        _sync(garage)
        rows = garage.apply_state({'door': 'open', 'position': 1.0}, now=T0 + timedelta(minutes=1), notify=False)
        assert rows[0].opened is True


def test_light_lock_obstruction_and_online_rows(app, garage):
    with app.app_context():
        _sync(garage)
        assert garage.apply_state({'light': True}, now=T0, notify=False)[0].value == 'on'
        assert garage.apply_state({'lock': True}, now=T0, notify=False)[0].value == 'locked'
        assert garage.apply_state({'obstruction': True}, now=T0, notify=False)[0].value == 'detected'
        assert garage.apply_state({'online': False}, now=T0, notify=False)[0].value == 'offline'
        assert garage.apply_state({'motion': True}, now=T0, notify=False) == []   # tracked, but not an event
        assert garage.state['motion'] is True
        assert garage.apply_state({'light': True}, now=T0, notify=False) == []    # no change, no row


def test_source_attribution_window(app, garage):
    with app.app_context():
        _sync(garage)
        garage.record_command('open')
        rows = garage.apply_state({'door': 'opening'}, now=T0, notify=False)
        assert rows[0].source == 'dashboard'
        rows = garage.apply_state({'door': 'open'}, now=T0, notify=False)
        assert rows[0].source == 'external'          # the command was consumed by the first transition
        garage.record_command('close')
        garage._pending_command = ('close', time.monotonic() - gm.COMMAND_ATTRIBUTION_SECONDS - 1)
        rows = garage.apply_state({'door': 'closing'}, now=T0, notify=False)
        assert rows[0].source == 'external'


# ---- alerts ------------------------------------------------------------------------------

def _open_alerts(alert_type):
    return Alert.query.filter_by(alert_type=alert_type, resolved=False).all()


def test_left_open_alert_after_threshold_and_resolution_on_close(app, garage):
    with app.app_context():
        Configuration.set_value('garage_left_open_minutes', '10')
        db.session.commit()
        _sync(garage)
        garage.apply_state({'door': 'open'}, now=T0, notify=False)
        garage.check_alerts(notify=False, now=T0 + timedelta(minutes=9))
        assert _open_alerts('garage_left_open') == []
        garage.check_alerts(notify=False, now=T0 + timedelta(minutes=10))
        alerts = _open_alerts('garage_left_open')
        assert len(alerts) == 1 and alerts[0].severity == 'warning' and alerts[0].alert_subtype == 'garage'
        device = Device.query.get(alerts[0].device_id)
        assert device.ip_address == HOST and device.device_type == 'smart_home' and device.custom_name == 'Garage door (ratgdo)'
        garage.check_alerts(notify=False, now=T0 + timedelta(minutes=20))
        assert len(_open_alerts('garage_left_open')) == 1                       # deduplicated
        garage.apply_state({'door': 'closed'}, now=T0 + timedelta(minutes=21), notify=False)
        assert _open_alerts('garage_left_open') == []
        assert Alert.query.filter_by(alert_type='garage_left_open', resolved=True).count() == 1


def test_quiet_hours_alert_is_informational_and_clears_on_close(app, garage):
    with app.app_context():
        Configuration.set_value('garage_quiet_hours_start', '22:00')
        Configuration.set_value('garage_quiet_hours_end', '06:00')
        db.session.commit()
        _sync(garage)
        garage.apply_state({'door': 'open'}, now=T0, notify=False)
        garage.check_alerts(notify=False, now=T0, local_now=datetime(2026, 9, 17, 12, 0))
        assert _open_alerts('garage_quiet_hours_open') == []
        garage.check_alerts(notify=False, now=T0, local_now=datetime(2026, 9, 17, 23, 30))
        alerts = _open_alerts('garage_quiet_hours_open')
        assert len(alerts) == 1 and alerts[0].severity == 'info' and '23:30' in alerts[0].message
        garage.apply_state({'door': 'closed'}, now=T0 + timedelta(minutes=1), notify=False)
        garage.check_alerts(notify=False, now=T0 + timedelta(minutes=1), local_now=datetime(2026, 9, 17, 23, 31))
        assert _open_alerts('garage_quiet_hours_open') == []


def test_obstruction_alert_follows_the_sensor(app, garage):
    with app.app_context():
        _sync(garage)
        garage.apply_state({'obstruction': True}, now=T0, notify=False)
        assert len(_open_alerts('garage_obstruction')) == 1
        garage.apply_state({'obstruction': False}, now=T0, notify=False)
        assert _open_alerts('garage_obstruction') == []


def test_offline_after_three_failed_polls_and_recovery(app, garage):
    with app.app_context():
        _sync(garage)
        garage._client.snapshot.side_effect = RatgdoError('refused')
        for _ in range(2):
            garage.poll_once(notify=False)
        assert garage.state['online'] is True and _open_alerts('garage_offline') == []
        garage.poll_once(notify=False)
        assert garage.state['online'] is False
        assert len(_open_alerts('garage_offline')) == 1
        assert GarageEvent.query.filter_by(kind='online', value='offline').count() == 1

        good = {'door': 'closed', 'position': 0.0, 'light': False, 'lock': False, 'obstruction': False, 'motion': False,
                'motor': False, 'openings': 7, 'firmware': '2025.8.1', 'online': True, 'last_update': None,
                'board': {'host': HOST, 'name': None}}
        garage._client.snapshot.side_effect = None
        garage._client.snapshot.return_value = good
        garage.poll_once(notify=False)
        assert garage.state['online'] is True and garage.state['openings'] == 7 and garage.state['firmware'] == '2025.8.1'
        assert _open_alerts('garage_offline') == []
        assert garage._offline_polls == 0


def test_alerts_are_skipped_when_disabled(app, garage):
    with app.app_context():
        _sync(garage)
        Configuration.set_value('garage_enabled', 'false')
        db.session.commit()
        garage.apply_state({'obstruction': True}, now=T0, notify=False)
        assert Alert.query.count() == 0


# ---- commands ----------------------------------------------------------------------------------

def test_command_dispatches_and_records_attribution(app, garage):
    with app.app_context():
        with patch('services.garage_monitor.rc.RatgdoClient') as client_cls:
            garage._client = None
            fake = client_cls.return_value
            fake.host = HOST
            assert garage.command('door', 'open') == {'ok': True, 'kind': 'door', 'action': 'open'}
            fake.door.assert_called_once_with('open')
            garage.command('light', 'on')
            fake.light.assert_called_once_with('turn_on')
            garage.command('lock', 'lock')
            fake.lock.assert_called_once_with('lock')
            assert garage._pending_command[0] == 'lock'
            with pytest.raises(ValueError):
                garage.command('light', 'brighter')
            with pytest.raises(ValueError):
                garage.command('window', 'open')
            assert garage._wake.is_set()


def test_command_refuses_when_unconfigured(app, db_session):
    monitor = GarageMonitor(app)
    with app.app_context():
        with pytest.raises(GarageNotConfigured):
            monitor.command('door', 'open')
        Configuration.set_value('garage_enabled', 'true')
        Configuration.set_value('garage_host', '8.8.8.8')     # validation is bypassed here on purpose
        db.session.commit()
        with pytest.raises(GarageNotConfigured):
            monitor.command('door', 'open')
        assert monitor.poll_once(notify=False)['door'] == 'unknown'   # no client -> nothing to poll


# ---- views ----------------------------------------------------------------------------------------

def test_status_shape(app, garage):
    with app.app_context():
        _sync(garage, firmware='2025.8.1')
        garage.apply_state({'door': 'open'}, now=datetime.utcnow() - timedelta(seconds=90), notify=False)
        view = garage.status()
    assert set(view) == {'enabled', 'configured', 'host', 'board', 'online', 'sse_connected', 'consecutive_failures',
                         'door', 'position', 'light', 'lock', 'obstruction', 'motion', 'motor', 'openings',
                         'open_since', 'open_for_seconds', 'last_update', 'last_event', 'left_open_minutes',
                         'quiet_hours', 'poll_interval'}
    assert view['enabled'] and view['configured'] and view['door'] == 'open'
    assert 88 <= view['open_for_seconds'] <= 92
    assert view['board'] == {'host': HOST, 'name': None, 'firmware': '2025.8.1'}
    assert view['last_event']['value'] == 'open'
    assert view['quiet_hours'] == {'start': None, 'end': None, 'active': False}


def test_unconfigured_status(app, db_session):
    with app.app_context():
        view = GarageMonitor(app).status()
    assert view['enabled'] is False and view['configured'] is False and view['host'] is None
    assert view['door'] == 'unknown' and view['light'] is None and view['open_for_seconds'] is None


def test_history_buckets_and_stats(app, garage):
    with app.app_context():
        _sync(garage)
        garage.apply_state({'door': 'open'}, now=DAY, notify=False)
        garage.apply_state({'door': 'closed'}, now=DAY + timedelta(minutes=5), notify=False)
        garage.apply_state({'door': 'open'}, now=DAY + timedelta(minutes=10), notify=False)
        garage.apply_state({'door': 'closed'}, now=DAY + timedelta(minutes=25), notify=False)
        garage.apply_state({'light': True}, now=DAY + timedelta(minutes=26), notify=False)
        view = garage.history(hours=48)
    assert view['hours'] == 48
    assert view['stats']['openings_today'] == 2 and view['stats']['openings_week'] == 2
    assert view['stats']['avg_open_seconds'] == 600.0 and view['stats']['longest_open_today_seconds'] == 900
    assert view['stats']['currently_open_seconds'] is None
    assert len(view['daily']) == 14 and view['daily'][-1]['openings'] == 2 and view['daily'][-1]['open_seconds'] == 1200.0
    assert view['daily'][0]['openings'] == 0
    assert [e['kind'] for e in view['events']] == ['light', 'door', 'door', 'door', 'door']


def test_history_clamps_hours(app, garage):
    with app.app_context():
        assert garage.history(hours=0)['hours'] == 1
        assert garage.history(hours=10 ** 6)['hours'] == 24 * 90


# ---- stream + loop -----------------------------------------------------------------------------

def test_sse_state_events_feed_apply_state(app, garage):
    with app.app_context():
        _sync(garage)
    garage._on_sse_state({'id': 'cover-door', 'state': 'OPEN', 'value': 0.2, 'current_operation': 'OPENING'})
    garage._on_sse_state({'id': 'light-light', 'state': 'ON', 'value': True})
    with app.app_context():
        assert garage.state['door'] == 'opening' and garage.state['light'] is True and garage.state['sse_connected']
        assert [r.kind for r in GarageEvent.query.order_by(GarageEvent.id).all()] == ['door', 'light']


def test_loop_heartbeats_idles_when_disabled_and_stops_promptly(app, db_session):
    with app.app_context():
        Configuration.set_value('garage_enabled', 'false')
        db.session.commit()
    monitor = GarageMonitor(app)
    beats = []
    with patch('services.garage_monitor.record_heartbeat', side_effect=lambda name: beats.append(name)):
        thread = threading.Thread(target=monitor.start_monitoring, daemon=True)
        thread.start()
        deadline = time.time() + 5
        while not beats and time.time() < deadline:
            time.sleep(0.05)
        monitor.stop()
        thread.join(timeout=5)
    assert not thread.is_alive() and beats == ['GarageMonitor'] and monitor._client is None


def test_loop_polls_a_configured_board(app, garage):
    garage._client.snapshot.return_value = {
        'door': 'open', 'position': 1.0, 'light': False, 'lock': False, 'obstruction': False, 'motion': False,
        'motor': False, 'openings': 1, 'firmware': 'x', 'online': True, 'last_update': None,
        'board': {'host': HOST, 'name': None}}
    with patch.object(garage, '_ensure_sse'):
        with app.app_context():
            wait = garage._tick()
    assert garage.state['door'] == 'open' and garage._client.snapshot.call_count == 1 and wait == gm.TICK_SECONDS


def test_watchdog_and_retention_know_the_monitor():
    from core.health import EXPECTED_THREADS
    from services import retention
    assert 'GarageMonitor' in EXPECTED_THREADS
    assert any(r.table == 'garage_events' for r in retention.RETENTION_TABLES)
