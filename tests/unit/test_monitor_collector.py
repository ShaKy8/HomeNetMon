"""
Regression tests for the ping collector in DeviceMonitor.monitor_all_devices().

Bug: the collector waited only ping_timeout*3 seconds for the whole batch and
silently dropped every result that missed the deadline (~55% of devices per
cycle on a 131-device network), so offline devices never got a MonitoringData
row. It also treated an IoT "skip this cycle" (None) as a failed ping.
"""

import time
from datetime import datetime, timedelta
from unittest.mock import patch, Mock

import pytest

from models import Device, MonitoringData, db
from monitoring.monitor import DeviceMonitor, SKIPPED


def _make_devices(db_session, count):
    devices = []
    for i in range(count):
        d = Device(
            ip_address=f'192.168.1.{10 + i}',
            mac_address=f'00:11:22:33:44:{i:02x}',
            hostname=f'dev-{i}',
            device_type='computer',
            is_monitored=True,
            last_seen=datetime.utcnow() - timedelta(minutes=5),
        )
        db_session.add(d)
        devices.append(d)
    db_session.commit()
    return devices


def _config(overrides):
    def _get(key, default):
        return str(overrides.get(key, default))
    return _get


class TestCollectorCompleteness:

    def test_every_slow_result_is_collected(self, app, db_session):
        """All results must reach batch processing even when the batch takes far
        longer than ping_timeout*3 (the old, dropped-results deadline)."""
        devices = _make_devices(db_session, 6)
        ids = {d.id for d in devices}

        def slow_ping(device):
            time.sleep(0.15)  # 6 devices / 2 workers = ~0.45 s total >> 3 * 0.05 s
            return {'device_id': device.id, 'response_time': None if device.id % 2 else 5.0,
                    'success': bool(device.id % 2 == 0), 'timestamp': datetime.utcnow()}

        monitor = DeviceMonitor(app=app)
        batch = Mock()
        with patch.object(monitor, 'get_config_value', side_effect=_config({'max_workers': 2, 'ping_timeout': 0.05})), \
             patch.object(monitor, '_ping_device_for_batch', side_effect=slow_ping), \
             patch.object(monitor, '_batch_process_monitoring_results', batch):
            monitor.monitor_all_devices()

        assert batch.call_count == 1
        results = batch.call_args[0][0]
        assert {r['device_id'] for r in results} == ids
        assert sum(1 for r in results if not r['success']) == 3

    def test_worker_exception_is_recorded_as_failed_probe(self, app, db_session):
        devices = _make_devices(db_session, 3)
        boom_id = devices[1].id

        def ping(device):
            if device.id == boom_id:
                raise RuntimeError("ping exploded")
            return {'device_id': device.id, 'response_time': 1.0, 'success': True, 'timestamp': datetime.utcnow()}

        monitor = DeviceMonitor(app=app)
        batch = Mock()
        with patch.object(monitor, 'get_config_value', side_effect=_config({'max_workers': 3})), \
             patch.object(monitor, '_ping_device_for_batch', side_effect=ping), \
             patch.object(monitor, '_batch_process_monitoring_results', batch):
            monitor.monitor_all_devices()

        results = {r['device_id']: r for r in batch.call_args[0][0]}
        assert len(results) == 3
        assert results[boom_id]['success'] is False
        assert results[boom_id]['response_time'] is None

    def test_max_workers_comes_from_configuration(self, app, db_session):
        _make_devices(db_session, 4)
        monitor = DeviceMonitor(app=app)
        seen_threads = set()

        def ping(device):
            import threading
            seen_threads.add(threading.current_thread().name)
            time.sleep(0.05)
            return {'device_id': device.id, 'response_time': 1.0, 'success': True, 'timestamp': datetime.utcnow()}

        with patch.object(monitor, 'get_config_value', side_effect=_config({'max_workers': 1})), \
             patch.object(monitor, '_ping_device_for_batch', side_effect=ping), \
             patch.object(monitor, '_batch_process_monitoring_results', Mock()):
            monitor.monitor_all_devices()

        assert len(seen_threads) == 1, f"expected a single ping worker, got {seen_threads}"


class TestSkippedDevices:

    def test_skipped_device_yields_no_batch_result(self, app, db_session):
        device = _make_devices(db_session, 1)[0]
        monitor = DeviceMonitor(app=app)
        with patch.object(monitor, 'ping_device', return_value=SKIPPED):
            assert monitor._ping_device_for_batch(device) is None

    def test_skipped_devices_are_not_batch_processed(self, app, db_session):
        _make_devices(db_session, 2)
        monitor = DeviceMonitor(app=app)
        batch = Mock()
        with patch.object(monitor, 'get_config_value', side_effect=_config({'max_workers': 2})), \
             patch.object(monitor, 'ping_device', return_value=SKIPPED), \
             patch.object(monitor, '_batch_process_monitoring_results', batch):
            monitor.monitor_all_devices()
        batch.assert_not_called()

    def test_monitor_device_skipped_writes_nothing(self, app, db_session):
        device = _make_devices(db_session, 1)[0]
        monitor = DeviceMonitor(app=app)
        with app.app_context():
            with patch.object(monitor, 'ping_device', return_value=SKIPPED):
                assert monitor.monitor_device(device) is None
            assert MonitoringData.query.filter_by(device_id=device.id).count() == 0

    def test_failed_ping_still_recorded_as_down(self, app, db_session):
        """None (pinged, no reply) must still produce a row — only SKIPPED is silent."""
        device = _make_devices(db_session, 1)[0]
        monitor = DeviceMonitor(app=app)
        with app.app_context():
            with patch.object(monitor, 'ping_device', return_value=None):
                monitor.monitor_device(device)
            rows = MonitoringData.query.filter_by(device_id=device.id).all()
            assert len(rows) == 1 and rows[0].response_time is None

    def test_ping_device_returns_sentinel_when_optimizer_skips(self, app, db_session):
        device = _make_devices(db_session, 1)[0]
        monitor = DeviceMonitor(app=app)
        with patch('monitoring.monitor.iot_optimizer') as opt, patch('subprocess.run') as run:
            opt.get_optimized_settings.return_value = {'timeout': 1, 'retries': 1}
            opt.should_skip_monitoring.return_value = (True, 42)
            assert monitor.ping_device(device) is SKIPPED
            run.assert_not_called()


class TestRetryCap:

    def test_non_critical_device_probed_at_most_twice(self, app, db_session):
        device = _make_devices(db_session, 1)[0]  # 192.168.1.10, type computer -> not critical
        monitor = DeviceMonitor(app=app)
        failed = Mock(returncode=1, stdout='')
        with patch('monitoring.monitor.iot_optimizer') as opt, \
             patch('monitoring.monitor.subprocess.run', return_value=failed) as run, \
             patch('monitoring.monitor.time.sleep'):
            opt.get_optimized_settings.return_value = {'timeout': 2, 'retries': 3}  # optimizer default
            opt.should_skip_monitoring.return_value = (False, None)
            assert monitor.ping_device(device) is None
            assert run.call_count == 2


class TestSummaryPush:

    def test_summary_push_uses_shared_counts(self, app, db_session):
        """The Socket.IO summary must carry services/device_counts keys and be built
        inside an app context (it raised 'Working outside of application context'
        once per cycle after the first attempt)."""
        _make_devices(db_session, 2)
        monitor = DeviceMonitor(app=app, socketio=Mock())

        def ping(device):
            return {'device_id': device.id, 'response_time': 5.0, 'success': True, 'timestamp': datetime.utcnow()}

        with patch.object(monitor, 'get_config_value', side_effect=_config({'max_workers': 2, 'ping_timeout': 0.05})), \
             patch.object(monitor, '_ping_device_for_batch', side_effect=ping), \
             patch.object(monitor, '_batch_process_monitoring_results', Mock()), \
             patch('services.websocket_throttle.websocket_throttle.should_emit_global_event', return_value=True):
            monitor.monitor_all_devices()

        pushes = [c for c in monitor.socketio.emit.call_args_list if c.args and c.args[0] == 'monitoring_summary']
        assert pushes, 'no monitoring_summary push'
        payload = pushes[0].args[1]
        assert payload['monitored_devices'] == 2
        assert payload['devices_up'] == 2
        assert payload['timestamp'].endswith('Z')


class TestBatchProcessing:

    def test_real_batch_path_persists_results_without_errors(self, app, db_session, caplog):
        """Runs monitor_all_devices with the real _batch_process_monitoring_results (the
        collector tests mock it); a leftover rule-engine hook made every cycle log an error."""
        import logging
        devices = _make_devices(db_session, 3)

        def ping(device):
            return {'device_id': device.id, 'response_time': 7.0, 'success': True, 'timestamp': datetime.utcnow()}

        monitor = DeviceMonitor(app=app, socketio=Mock())
        with caplog.at_level(logging.ERROR), \
             patch.object(monitor, 'get_config_value', side_effect=_config({'max_workers': 2, 'ping_timeout': 0.05})), \
             patch.object(monitor, '_ping_device_for_batch', side_effect=ping):
            monitor.monitor_all_devices()

        with app.app_context():
            assert MonitoringData.query.filter(MonitoringData.device_id.in_([d.id for d in devices])).count() == 3
            assert all(db.session.get(Device, d.id).last_seen is not None for d in devices)
        assert not [r for r in caplog.records if r.levelno >= logging.ERROR], [r.getMessage() for r in caplog.records]
