"""monitoring/neighbors.py: presence from `ip -4 neigh`, and the monitor's use of it."""

import subprocess
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from models import Device, MonitoringData, db
from monitoring import neighbors
from monitoring.monitor import DeviceMonitor

NEIGH = (
    "192.168.1.1 dev eth0 lladdr 10:ce:02:d8:25:37 REACHABLE\n"
    "192.168.1.2 dev eth0 lladdr 3a:02:45:68:85:2b STALE\n"
    "192.168.1.3 dev eth0  FAILED\n"
    "192.168.1.4 dev eth0 INCOMPLETE\n"
    "192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:05 router REACHABLE\n"
    "192.168.1.5 dev wlan0 lladdr aa:bb:cc:dd:ee:05 STALE\n"
    "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router STALE\n"
)


def test_parse_states_and_macs():
    t = neighbors.parse(NEIGH)
    assert t['192.168.1.1'] == [('10:ce:02:d8:25:37', 'REACHABLE')]
    assert t['192.168.1.3'] == [(None, 'FAILED')]
    assert t['192.168.1.5'] == [('aa:bb:cc:dd:ee:05', 'REACHABLE'), ('aa:bb:cc:dd:ee:05', 'STALE')]
    assert 'fe80::1' not in t


def test_present_hosts_are_reachable_only():
    with patch('monitoring.neighbors.subprocess.run', return_value=Mock(stdout=NEIGH)):
        assert neighbors.present_hosts() == {'192.168.1.1': '10:ce:02:d8:25:37', '192.168.1.5': 'aa:bb:cc:dd:ee:05'}


def _confirm(sequence, wait=12.0):
    """Drive confirm_presence through a sequence of observed states without sleeping."""
    clock = [0.0]
    outputs = iter(sequence)

    def run(args, **kw):
        ip = args[-1]
        st = next(outputs)
        return Mock(stdout='' if st is None else f"{ip} dev eth0 lladdr aa:bb:cc:dd:ee:01 {st}\n")

    def sleep(s):
        clock[0] += s

    with patch('monitoring.neighbors.subprocess.run', side_effect=run):
        return neighbors.confirm_presence('192.168.1.9', wait=wait, interval=0.5, sleep=sleep, clock=lambda: clock[0])


def test_confirm_presence_reachable_after_delay_and_probe():
    assert _confirm(['DELAY', 'DELAY', 'PROBE', 'REACHABLE']) is True


def test_confirm_presence_failed_is_absent():
    assert _confirm(['INCOMPLETE', 'INCOMPLETE', 'FAILED']) is False


def test_confirm_presence_gives_up_at_deadline():
    assert _confirm(['STALE'] * 40, wait=3.0) is False


def test_confirm_presence_no_entry_means_not_on_link():
    # Two polls with no entry at all: the address is routed, ARP cannot answer; do not wait 12 s.
    assert _confirm([None, None, 'REACHABLE'], wait=12.0) is False


def test_confirm_presence_incomplete_then_entry_is_still_polled():
    assert _confirm([None, 'INCOMPLETE', 'REACHABLE'], wait=12.0) is True


def test_confirm_presence_without_ip_tool_is_absent():
    with patch('monitoring.neighbors.subprocess.run', side_effect=FileNotFoundError('ip')):
        assert neighbors.confirm_presence('192.168.1.9', wait=1.0) is False
    with patch('monitoring.neighbors.subprocess.run', side_effect=subprocess.TimeoutExpired('ip', 3)):
        assert neighbors.confirm_presence('192.168.1.9', wait=1.0) is False


class TestMonitorUsesPresence:

    def _device(self, db_session, ip):
        d = Device(ip_address=ip, mac_address='00:aa:00:00:00:' + ip.split('.')[-1].zfill(2)[-2:],
                   hostname=f'phone-{ip.split(".")[-1]}', device_type='phone', is_monitored=True,
                   last_seen=datetime.utcnow() - timedelta(hours=3))
        db_session.add(d)
        db_session.commit()
        return d

    def test_failed_ping_consults_arp(self, app, db_session):
        dev = self._device(db_session, '192.168.1.60')
        monitor = DeviceMonitor(app=app)
        with patch.object(monitor, 'ping_device', return_value=None), \
             patch('monitoring.monitor.neighbors.confirm_presence', return_value=True) as confirm:
            result = monitor._ping_device_for_batch(dev)
        confirm.assert_called_once_with('192.168.1.60')
        assert result['response_time'] is None and result['success'] is False and result['present'] is True

    def test_successful_ping_skips_arp(self, app, db_session):
        dev = self._device(db_session, '192.168.1.61')
        monitor = DeviceMonitor(app=app)
        with patch.object(monitor, 'ping_device', return_value=12.5), \
             patch('monitoring.monitor.neighbors.confirm_presence') as confirm:
            result = monitor._ping_device_for_batch(dev)
        confirm.assert_not_called()
        assert result['present'] is True

    def test_arp_present_device_is_seen_but_the_row_records_no_response(self, app, db_session):
        dev = self._device(db_session, '192.168.1.62')
        monitor = DeviceMonitor(app=app)
        now = datetime.utcnow()
        monitor._batch_process_monitoring_results([
            {'device_id': dev.id, 'response_time': None, 'success': False, 'present': True, 'timestamp': now},
        ])
        db.session.expire_all()
        fresh = db.session.get(Device, dev.id)
        assert fresh.last_seen == now
        row = MonitoringData.query.filter_by(device_id=dev.id).one()
        assert row.response_time is None

    def test_absent_device_is_not_seen(self, app, db_session):
        dev = self._device(db_session, '192.168.1.63')
        before = dev.last_seen
        DeviceMonitor(app=app)._batch_process_monitoring_results([
            {'device_id': dev.id, 'response_time': None, 'success': False, 'present': False,
             'timestamp': datetime.utcnow()},
        ])
        db.session.expire_all()
        assert db.session.get(Device, dev.id).last_seen == before

    def test_status_for_dashboard(self):
        assert DeviceMonitor._status_for(True, None) == 'up'
        assert DeviceMonitor._status_for(True, 1500.0) == 'warning'
        assert DeviceMonitor._status_for(False, None) == 'down'
