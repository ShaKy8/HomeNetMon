"""A stop during a ping cycle used to take 5 to 7 s. systemd's SIGTERM kills every running ping, ping_device counted
each death as a failed attempt, slept 0.5 s and started a fresh ping that nobody signalled (up to two retries for
critical devices), then waited up to 12 s for ARP in the presence check; Python joins the ping pool at exit and
waited for all of it. Once the stop is fast, the interrupted cycle could also write those killed pings as failed
probes. DeviceMonitor.request_stop() (set from the SIGTERM handler, core/shutdown.py) now ends the retries, the
presence check and the cycle's write."""

import threading
import time
import types
from datetime import datetime
from unittest.mock import Mock, patch

import pytest

import monitoring.monitor as monitor_mod
import monitoring.neighbors as neighbors
import monitoring.ping as ping_mod
from monitoring.monitor import SKIPPED, DeviceMonitor


def _device(ip='192.168.1.50', **kw):
    return types.SimpleNamespace(id=kw.get('id', 7), ip_address=ip, device_type=kw.get('device_type', 'computer'),
                                 hostname=kw.get('hostname', 'pc'), display_name='pc', is_monitored=True)


@pytest.fixture
def fake_optimizer(monkeypatch):
    recorded = []
    opt = monitor_mod.iot_optimizer
    monkeypatch.setattr(opt, 'get_optimized_settings', lambda d: {'timeout': 1, 'retries': 1})
    monkeypatch.setattr(opt, 'should_skip_monitoring', lambda d: (False, 0))
    monkeypatch.setattr(opt, 'record_ping_result', lambda d, ok, rt: recorded.append(ok))
    return recorded


def _fake_ping(monkeypatch, behaviour):
    calls = []

    def ping_host(ip, timeout):
        calls.append(ip)
        return behaviour(len(calls))
    monkeypatch.setattr(ping_mod, 'ping_host', ping_host)
    return calls


def test_request_stop_only_sets_the_event():
    """Runs inside a signal handler: no logging, no locks of its own."""
    monitor = DeviceMonitor()
    monitor.is_running = True
    monitor.request_stop()
    assert monitor._stop_event.is_set()
    assert monitor.is_running is True                   # the loop clears it when it actually ends


def test_a_device_not_yet_pinged_is_skipped_once_stopping(monkeypatch, fake_optimizer):
    calls = _fake_ping(monkeypatch, lambda n: 1.0)
    monitor = DeviceMonitor()
    monitor._stop_event.set()
    assert monitor.ping_device(_device()) is SKIPPED
    assert calls == [] and fake_optimizer == []


def test_a_ping_killed_by_the_stop_is_not_retried_or_counted(monkeypatch, fake_optimizer):
    monitor = DeviceMonitor()

    def killed(n):
        monitor._stop_event.set()                          # SIGTERM arrives while the ping runs
        return None
    calls = _fake_ping(monkeypatch, killed)
    assert monitor.ping_device(_device()) is SKIPPED
    assert len(calls) == 1                              # no fresh ping that nobody would signal
    assert fake_optimizer == []                         # not recorded as a failure for the IoT back-off


def test_the_retry_wait_ends_at_the_stop(monkeypatch, fake_optimizer):
    monitor = DeviceMonitor()

    def first_fails(n):
        threading.Timer(0.05, monitor._stop_event.set).start()
        return None
    calls = _fake_ping(monkeypatch, first_fails)
    started = time.monotonic()
    assert monitor.ping_device(_device()) is SKIPPED
    assert time.monotonic() - started < 0.4             # the retry delay is 0.5 s
    assert len(calls) == 1


def test_without_a_stop_a_failed_device_is_still_retried_and_recorded(monkeypatch, fake_optimizer):
    calls = _fake_ping(monkeypatch, lambda n: None)
    assert DeviceMonitor().ping_device(_device()) is None
    assert len(calls) == 2 and fake_optimizer == [False]


def test_the_presence_check_ends_at_the_stop(monkeypatch):
    # The session's app fixture (tests/conftest.py) sets CONFIRM_WAIT to 0: put the real 12 s back
    monkeypatch.setattr(neighbors, 'CONFIRM_WAIT', 12.0)
    monkeypatch.setattr(neighbors, 'state', lambda ip: 'STALE')     # undecided: would poll for 12 s
    monitor = DeviceMonitor()
    threading.Timer(0.1, monitor._stop_event.set).start()
    started = time.monotonic()
    assert monitor._confirm_presence(_device()) is False
    assert time.monotonic() - started < 1.0


def test_the_presence_check_still_waits_without_a_stop(monkeypatch):
    monkeypatch.setattr(neighbors, 'CONFIRM_WAIT', 12.0)            # see the test above
    states = iter(['STALE', 'STALE', 'REACHABLE'])
    monkeypatch.setattr(neighbors, 'state', lambda ip: next(states))
    started = time.monotonic()
    assert DeviceMonitor()._confirm_presence(_device()) is True
    assert time.monotonic() - started >= 0.9            # it really polled: two 0.5 s waits


def test_a_batch_result_finished_during_the_stop_is_dropped(monkeypatch):
    monitor = DeviceMonitor()

    def ping_then_stop(device):
        monitor._stop_event.set()
        return None
    monkeypatch.setattr(monitor, 'ping_device', ping_then_stop)
    monkeypatch.setattr(monitor, '_confirm_presence', lambda d: False)
    assert monitor._ping_device_for_batch(_device()) is None


def _config(overrides):
    return lambda key, default: str(overrides.get(key, default))


def test_an_interrupted_cycle_writes_nothing(app, db_session):
    from tests.unit.test_monitor_collector import _make_devices
    _make_devices(db_session, 3)
    monitor = DeviceMonitor(app=app)

    def ping(device):
        monitor._stop_event.set()
        return {'device_id': device.id, 'response_time': None, 'success': False, 'timestamp': datetime.utcnow()}
    batch = Mock()
    with patch.object(monitor, 'get_config_value', side_effect=_config({'max_workers': 3})), \
         patch.object(monitor, '_ping_device_for_batch', side_effect=ping), \
         patch.object(monitor, '_batch_process_monitoring_results', batch):
        monitor.monitor_all_devices()
    assert batch.call_count == 0


def test_a_single_device_probe_during_the_stop_writes_nothing(monkeypatch):
    monitor = DeviceMonitor(app=Mock())

    def ping_then_stop(device):
        monitor._stop_event.set()
        return None
    monkeypatch.setattr(monitor, 'ping_device', ping_then_stop)
    monkeypatch.setattr(monitor, '_confirm_presence', lambda d: False)
    assert monitor.monitor_device(_device()) is None
    monitor.app.app_context.assert_not_called()
