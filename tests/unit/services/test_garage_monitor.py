"""services/garage_monitor.py: camera frames -> readings -> GarageEvent rows, alerts, views."""

import io
import threading
import time
from datetime import datetime, time as dtime, timedelta
from unittest.mock import Mock, patch

import pytest
from PIL import Image

from models import Alert, Configuration, Device, GarageEvent, db
from services import garage_monitor as gm
from services.door_vision import DoorReading, VisionError
from services.garage_monitor import GarageBusy, GarageMonitor, GarageNotConfigured, in_quiet_hours
from services.ring_client import RingAuthError, RingError

CAM = '42'
T0 = datetime(2026, 9, 17, 14, 0, 0)
DAY = datetime.combine(datetime.utcnow().date(), dtime(12, 0))   # noon UTC today: local date is today in any zone <= +-11


def _jpeg(color=(40, 60, 80), box=None):
    image = Image.new('RGB', (640, 360), color)
    if box:
        image.paste((240, 240, 240), box)
    out = io.BytesIO()
    image.save(out, format='JPEG')
    return out.getvalue()


CLOSED_FRAME = _jpeg()
OPEN_FRAME = _jpeg(box=(0, 0, 640, 200))


def _reading(state='closed', confidence=0.95, visible=True, night=False):
    return DoorReading(state=state, confidence=confidence, door_visible=visible, night=night, reason=f'looks {state}')


USAGE = {'model': 'claude-opus-5', 'input_tokens': 1100, 'output_tokens': 50, 'cache_read_input_tokens': 0,
         'cache_creation_input_tokens': 0, 'est_cost_usd': 0.00675}


@pytest.fixture
def bridge():
    b = Mock()
    b.signed_in.return_value = True
    b.latest_snapshot.return_value = (CLOSED_FRAME, 1_000)
    b.fresh_snapshot.return_value = (None, 1_000)
    b.motion_events.return_value = []
    b.health.return_value = {'id': 42, 'name': 'Garage Cam', 'model': 'Stick Up Cam', 'battery_life': 80,
                             'wifi_signal_strength': -60, 'is_battery': True}
    return b


@pytest.fixture
def garage(app, db_session, bridge, tmp_path):
    with app.app_context():
        Configuration.set_value('garage_enabled', 'true')
        Configuration.set_value('garage_camera_id', CAM)
        Configuration.set_value('garage_camera_name', 'Garage Cam')
        Configuration.set_value('garage_quiet_hours_start', '')
        Configuration.set_value('garage_quiet_hours_end', '')
        db.session.commit()
    return GarageMonitor(app, bridge=bridge, frame_dir=tmp_path / 'frames')


def _sync(monitor, door='closed'):
    """Initial state (no rows are written for it)."""
    return monitor.apply_state({'door': door, 'online': True}, now=T0, notify=False)


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
        assert _sync(garage) == []
        assert garage.state['door'] == 'closed' and garage.state['online'] is True
        assert GarageEvent.query.count() == 0


def test_door_cycle_writes_camera_rows_with_opened_flag_and_duration(app, garage):
    with app.app_context():
        _sync(garage)
        opened = garage.apply_state({'door': 'open'}, now=T0 + timedelta(minutes=1), notify=False)
        assert len(opened) == 1 and opened[0].kind == 'door' and opened[0].value == 'open'
        assert opened[0].opened is True and opened[0].source == 'camera'
        assert garage.state['open_since'] == T0 + timedelta(minutes=1)
        closed = garage.apply_state({'door': 'closed'}, now=T0 + timedelta(minutes=6), notify=False)
        assert closed[0].value == 'closed' and closed[0].duration_s == pytest.approx(300.0) and closed[0].opened is False
        assert garage.state['open_since'] is None
        assert [r.value for r in GarageEvent.query.order_by(GarageEvent.id).all()] == ['open', 'closed']


def test_online_rows_and_unknown_is_initial(app, garage):
    with app.app_context():
        _sync(garage)
        garage._last_error = 'Ring timeout'
        rows = garage.apply_state({'online': False}, now=T0, notify=False)
        assert rows[0].kind == 'online' and rows[0].value == 'offline' and rows[0].detail == 'Ring timeout'
        assert garage.apply_state({'door': 'unknown'}, now=T0, notify=False)[0].value == 'unknown'   # a real transition
        assert garage.apply_state({'door': 'closed'}, now=T0, notify=False) == []                      # back from unknown: initial


# ---- the check ------------------------------------------------------------------------------

def test_check_classifies_a_new_frame_and_records_the_transition(app, garage, bridge, tmp_path):
    with app.app_context():
        _sync(garage)
        bridge.latest_snapshot.return_value = (OPEN_FRAME, 2_000)
        with patch('services.garage_monitor.door_vision.classify', return_value=(_reading('open', 0.91), USAGE)) as classify:
            view = garage.check_once(notify=False, now=T0 + timedelta(minutes=2))
        classify.assert_called_once()
        assert classify.call_args.args[1] == 'claude-opus-5'
        assert view['door'] == 'open' and view['reading']['state'] == 'open' and view['reading']['confidence'] == 0.91
        assert view['snapshot']['has_frame'] and view['snapshot']['taken_at'].startswith('1970-01-01T00:00:02')
        assert view['vision']['checks_today'] == 1 and view['vision']['est_cost_today_usd'] == pytest.approx(0.0068, abs=1e-4)
        assert view['camera']['name'] == 'Garage Cam' and view['camera']['battery_life'] == 80
        row = GarageEvent.query.filter_by(kind='door').one()
        assert row.value == 'open' and row.detail == f'event-{row.id}.jpg'
        assert (tmp_path / 'frames' / row.detail).exists() and (tmp_path / 'frames' / 'latest.jpg').exists()
        assert garage.frame_path() is not None and garage.frame_path(row.id) is not None
        assert garage.frame_path(row.id + 99) is None and garage.frame_path('x') is None
        bridge.latest_snapshot.assert_called_with(CAM, since_ms=None)


def test_unchanged_frame_skips_the_model_until_the_reread_window(app, garage, bridge):
    with app.app_context():
        _sync(garage)
        with patch('services.garage_monitor.door_vision.classify', return_value=(_reading('closed'), USAGE)) as classify:
            garage.check_once(notify=False)
            bridge.latest_snapshot.return_value = (CLOSED_FRAME, 3_000)          # same picture, newer timestamp
            garage.check_once(notify=False)
            assert classify.call_count == 1
            garage._last_classified_at -= 61 * 60                                 # older than reclassify_minutes (60)
            bridge.latest_snapshot.return_value = (CLOSED_FRAME, 4_000)
            garage.check_once(notify=False)
            assert classify.call_count == 2
        assert bridge.latest_snapshot.call_args.kwargs['since_ms'] == 3_000


def test_no_new_frame_is_a_quiet_success(app, garage, bridge):
    with app.app_context():
        _sync(garage)
        bridge.latest_snapshot.return_value = (None, 1_000)
        with patch('services.garage_monitor.door_vision.classify') as classify:
            view = garage.check_once(notify=False)
        classify.assert_not_called()
        assert view['door'] == 'closed' and view['online'] is True


def test_low_confidence_or_hidden_door_keeps_the_previous_state(app, garage, bridge):
    with app.app_context():
        _sync(garage)
        bridge.latest_snapshot.return_value = (OPEN_FRAME, 2_000)
        with patch('services.garage_monitor.door_vision.classify', return_value=(_reading('open', 0.4), USAGE)):
            view = garage.check_once(notify=False)
        assert view['door'] == 'closed' and view['reading']['state'] == 'open'
        bridge.latest_snapshot.return_value = (_jpeg(color=(0, 0, 0)), 3_000)
        with patch('services.garage_monitor.door_vision.classify', return_value=(_reading('unknown', 0.9, visible=False, night=True), USAGE)):
            view = garage.check_once(notify=False)
        assert view['door'] == 'closed' and view['reading']['night'] is True
        assert GarageEvent.query.filter_by(kind='door').count() == 0


def test_fresh_check_asks_the_camera_then_falls_back(app, garage, bridge):
    with app.app_context():
        _sync(garage)
        bridge.fresh_snapshot.return_value = (None, 1_000)
        with patch('services.garage_monitor.door_vision.classify', return_value=(_reading('closed'), USAGE)):
            garage.check_once(fresh=True, notify=False)
        bridge.fresh_snapshot.assert_called_once_with(CAM)
        bridge.latest_snapshot.assert_called_once()
        bridge.fresh_snapshot.return_value = (OPEN_FRAME, 5_000)
        bridge.latest_snapshot.reset_mock()
        with patch('services.garage_monitor.door_vision.classify', return_value=(_reading('open'), USAGE)):
            view = garage.check_once(fresh=True, notify=False)
        bridge.latest_snapshot.assert_not_called()
        assert view['door'] == 'open'


def test_check_refuses_when_unconfigured_busy_or_signed_out(app, garage, bridge):
    with app.app_context():
        bridge.signed_in.return_value = False
        with pytest.raises(GarageNotConfigured):
            garage.check_once()
        bridge.signed_in.return_value = True
        Configuration.set_value('garage_camera_id', '')
        db.session.commit()
        garage.reload_config()
        with pytest.raises(GarageNotConfigured):
            garage.check_once()
        Configuration.set_value('garage_camera_id', CAM)
        db.session.commit()
        garage.reload_config()
        garage._check_lock.acquire()
        try:
            with pytest.raises(GarageBusy):
                garage.check_once()
        finally:
            garage._check_lock.release()


# ---- alerts ------------------------------------------------------------------------------

def _open_alerts(alert_type):
    return Alert.query.filter_by(alert_type=alert_type, resolved=False).all()


def test_left_open_alert_after_threshold_and_resolution_on_close(app, garage):
    with app.app_context():
        Configuration.set_value('garage_left_open_minutes', '10')
        db.session.commit()
        garage.reload_config()
        _sync(garage)
        garage.apply_state({'door': 'open'}, now=T0, notify=False)
        garage.check_alerts(notify=False, now=T0 + timedelta(minutes=9))
        assert _open_alerts('garage_left_open') == []
        garage.check_alerts(notify=False, now=T0 + timedelta(minutes=10))
        alerts = _open_alerts('garage_left_open')
        assert len(alerts) == 1 and alerts[0].severity == 'warning' and alerts[0].alert_subtype == 'garage'
        device = Device.query.get(alerts[0].device_id)
        assert device.hostname == f'ring-cam-{CAM}' and device.device_type == 'camera' and device.custom_name == 'Garage Cam (Ring)'
        assert device.is_monitored is False
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
        garage.reload_config()
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


def test_three_failures_raise_camera_unavailable_and_success_resolves(app, garage, bridge):
    with app.app_context():
        _sync(garage)
        bridge.latest_snapshot.side_effect = RingError('timeout')
        for _ in range(2):
            with pytest.raises(RingError):
                garage.check_once(notify=False)
        assert garage.state['online'] is True and _open_alerts('garage_offline') == []
        with pytest.raises(RingError):
            garage.check_once(notify=False)
        assert garage.state['online'] is False
        alerts = _open_alerts('garage_offline')
        assert len(alerts) == 1 and 'Garage Cam' in alerts[0].message and 'timeout' in alerts[0].message
        assert GarageEvent.query.filter_by(kind='online', value='offline').count() == 1

        bridge.latest_snapshot.side_effect = None
        bridge.latest_snapshot.return_value = (CLOSED_FRAME, 9_000)
        with patch('services.garage_monitor.door_vision.classify', side_effect=VisionError('rate limit')):
            with pytest.raises(VisionError):
                garage.check_once(notify=False)
        assert garage.state['online'] is False and garage._failures == 4
        with patch('services.garage_monitor.door_vision.classify', return_value=(_reading('closed'), USAGE)):
            garage.check_once(notify=False)
        assert garage.state['online'] is True and _open_alerts('garage_offline') == [] and garage._failures == 0


def test_signed_out_gives_unknown_without_an_alert(app, garage, bridge):
    with app.app_context():
        _sync(garage)
        bridge.latest_snapshot.side_effect = RingAuthError('token rejected')
        for _ in range(4):
            with pytest.raises(RingAuthError):
                garage.check_once(notify=False)
        assert garage.state['online'] is True and Alert.query.count() == 0 and garage._last_error == 'token rejected'


def test_alerts_are_skipped_when_disabled(app, garage):
    with app.app_context():
        _sync(garage)
        Configuration.set_value('garage_enabled', 'false')
        db.session.commit()
        garage.reload_config()
        garage.apply_state({'door': 'open'}, now=T0, notify=False)
        garage.check_alerts(notify=False, now=T0 + timedelta(hours=2))
        assert Alert.query.count() == 0


# ---- motion + ticker -------------------------------------------------------------------------

def test_motion_event_schedules_a_fresh_check(app, garage, bridge):
    with app.app_context():
        _sync(garage)
        garage._last_check = time.monotonic()                     # the scheduled check is not due
        bridge.motion_events.return_value = [{'id': 500, 'created_at': '2026-09-17T12:00:00+00:00'}]
        wait = garage._tick()                                       # first poll only records the latest id
        assert garage._check_due_at is None and wait == gm.TICK_SECONDS
        bridge.motion_events.return_value = [{'id': 501, 'created_at': '2026-09-17T12:05:00+00:00'}]
        wait = garage._tick()
        assert garage._check_due_at is not None and garage._check_reason == 'motion'
        assert wait <= gm.MOTION_CHECK_DELAY + 1
        garage._check_due_at = time.monotonic() - 1                 # now due
        with patch('services.garage_monitor.door_vision.classify', return_value=(_reading('open'), USAGE)):
            bridge.fresh_snapshot.return_value = (OPEN_FRAME, 6_000)
            garage._tick()
        bridge.fresh_snapshot.assert_called_once_with(CAM)
        assert garage.state['door'] == 'open' and garage._check_due_at is None


def test_tick_tears_down_when_disabled_and_idles_when_signed_out(app, garage, bridge):
    with app.app_context():
        _sync(garage)
        bridge.signed_in.return_value = False
        assert garage._tick() == gm.TICK_SECONDS and garage.state['door'] == 'closed'
        Configuration.set_value('garage_enabled', 'false')
        db.session.commit()
        garage.reload_config()
        assert garage._tick() == gm.TICK_SECONDS
        assert garage.state['door'] == 'unknown' and garage.state['online'] is None


def test_frame_cap_prunes_old_event_frames(app, garage, tmp_path):
    with app.app_context():
        frames = tmp_path / 'frames'
        frames.mkdir()
        for i in range(gm.FRAME_CAP + 5):
            path = frames / f'event-{i}.jpg'
            path.write_bytes(b'x')
            import os
            os.utime(path, (i, i))
        garage._prune_frames()
        remaining = sorted(int(p.stem.split('-')[1]) for p in frames.glob('event-*.jpg'))
        assert len(remaining) == gm.FRAME_CAP and remaining[0] == 5


# ---- views ----------------------------------------------------------------------------------------

def test_status_shape(app, garage):
    with app.app_context():
        _sync(garage)
        garage.apply_state({'door': 'open'}, now=datetime.utcnow() - timedelta(seconds=90), notify=False)
        view = garage.status()
    assert set(view) == {'enabled', 'configured', 'door', 'online', 'consecutive_failures', 'last_error', 'open_since',
                         'open_for_seconds', 'last_update', 'last_event', 'left_open_minutes', 'quiet_hours',
                         'check_interval', 'motion_checks', 'next_check_at', 'camera', 'ring', 'snapshot', 'reading',
                         'vision'}
    assert view['enabled'] and view['configured'] and view['door'] == 'open' and view['ring'] == {'signed_in': True}
    assert 88 <= view['open_for_seconds'] <= 92
    assert view['camera'] == {'id': CAM, 'name': 'Garage Cam', 'model': None, 'battery_life': None, 'wifi': None, 'is_battery': None}
    assert view['snapshot'] == {'taken_at': None, 'classified_at': None, 'changed_score': None, 'has_frame': False, 'age_seconds': None}
    assert view['vision']['model'] == 'claude-opus-5' and view['vision']['checks_today'] == 0 and 'api_key_set' in view['vision']
    assert view['last_event']['value'] == 'open' and view['next_check_at']


def test_unconfigured_status(app, db_session):
    with app.app_context():
        view = GarageMonitor(app, bridge=Mock(signed_in=Mock(return_value=False))).status()
    assert view['enabled'] is False and view['configured'] is False and view['camera'] is None
    assert view['door'] == 'unknown' and view['reading'] is None and view['next_check_at'] is None


def test_history_buckets_and_stats(app, garage):
    with app.app_context():
        _sync(garage)
        garage.apply_state({'door': 'open'}, now=DAY, notify=False)
        garage.apply_state({'door': 'closed'}, now=DAY + timedelta(minutes=5), notify=False)
        garage.apply_state({'door': 'open'}, now=DAY + timedelta(minutes=10), notify=False)
        garage.apply_state({'door': 'closed'}, now=DAY + timedelta(minutes=25), notify=False)
        view = garage.history(hours=48)
    assert view['hours'] == 48
    assert view['stats']['openings_today'] == 2 and view['stats']['openings_week'] == 2
    assert view['stats']['avg_open_seconds'] == 600.0 and view['stats']['longest_open_today_seconds'] == 900
    assert view['stats']['currently_open_seconds'] is None
    assert len(view['daily']) == 14 and view['daily'][-1]['openings'] == 2 and view['daily'][-1]['open_seconds'] == 1200.0
    assert [e['value'] for e in view['events']] == ['closed', 'open', 'closed', 'open']


def test_history_clamps_hours(app, garage):
    with app.app_context():
        assert garage.history(hours=0)['hours'] == 1
        assert garage.history(hours=10 ** 6)['hours'] == 24 * 90


# ---- loop + registry --------------------------------------------------------------------------

def test_loop_heartbeats_idles_when_disabled_and_stops_promptly(app, db_session):
    with app.app_context():
        Configuration.set_value('garage_enabled', 'false')
        db.session.commit()
    monitor = GarageMonitor(app, bridge=Mock(signed_in=Mock(return_value=False)))
    beats = []
    with patch('services.garage_monitor.record_heartbeat', side_effect=lambda name: beats.append(name)):
        thread = threading.Thread(target=monitor.start_monitoring, daemon=True)
        thread.start()
        deadline = time.time() + 5
        while not beats and time.time() < deadline:
            time.sleep(0.05)
        monitor.stop()
        thread.join(timeout=5)
    assert not thread.is_alive() and beats == ['GarageMonitor']


def test_watchdog_and_retention_know_the_monitor():
    from core.health import EXPECTED_THREADS
    from services import retention
    assert 'GarageMonitor' in EXPECTED_THREADS
    assert any(r.table == 'garage_events' for r in retention.RETENTION_TABLES)
