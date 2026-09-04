"""
Stale-device archiving: devices unseen for `stale_device_days` stop being
pinged (is_monitored=False) and are re-enabled by the scanner when they
reappear. Also covers the scanner's network-range filter for ARP entries.
"""

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from models import Device, db
from monitoring.monitor import DeviceMonitor
from monitoring.scanner import NetworkScanner


def _device(db_session, ip, mac, last_seen, is_monitored=True):
    d = Device(ip_address=ip, mac_address=mac, hostname=f'h-{ip}', vendor='TestVendor',
               device_type='computer', is_monitored=is_monitored, last_seen=last_seen)
    db_session.add(d)
    db_session.commit()
    return d.id


class TestArchiveStaleDevices:

    def test_only_long_unseen_devices_are_archived(self, app, db_session):
        now = datetime.utcnow()
        old = _device(db_session, '192.168.1.20', '00:aa:00:00:00:01', now - timedelta(days=40))
        recent = _device(db_session, '192.168.1.21', '00:aa:00:00:00:02', now - timedelta(days=5))
        never = _device(db_session, '192.168.1.22', '00:aa:00:00:00:03', None)

        monitor = DeviceMonitor(app=app)
        with patch.object(monitor, 'get_config_value', side_effect=lambda k, d: '30'):
            assert monitor.archive_stale_devices() == 1

        with app.app_context():
            assert Device.query.get(old).is_monitored is False
            assert Device.query.get(recent).is_monitored is True
            assert Device.query.get(never).is_monitored is True

    def test_archiving_is_idempotent(self, app, db_session):
        _device(db_session, '192.168.1.20', '00:aa:00:00:00:01', datetime.utcnow() - timedelta(days=40))
        monitor = DeviceMonitor(app=app)
        with patch.object(monitor, 'get_config_value', side_effect=lambda k, d: '30'):
            assert monitor.archive_stale_devices() == 1
            assert monitor.archive_stale_devices() == 0

    def test_zero_days_disables_archiving(self, app, db_session):
        _device(db_session, '192.168.1.20', '00:aa:00:00:00:01', datetime.utcnow() - timedelta(days=400))
        monitor = DeviceMonitor(app=app)
        with patch.object(monitor, 'get_config_value', side_effect=lambda k, d: '0'):
            assert monitor.archive_stale_devices() == 0

    def test_archived_devices_are_not_pinged(self, app, db_session):
        _device(db_session, '192.168.1.20', '00:aa:00:00:00:01', datetime.utcnow() - timedelta(days=40), is_monitored=False)
        monitor = DeviceMonitor(app=app)
        with patch.object(monitor, '_ping_device_for_batch') as ping, \
             patch.object(monitor, 'get_config_value', side_effect=lambda k, d: str(d)):
            monitor.monitor_all_devices()
        ping.assert_not_called()


class TestScannerReenablesStaleDevices:

    @pytest.fixture
    def scanner(self, app):
        s = NetworkScanner(app=app)
        s._new_devices_found = []
        return s

    def _seen(self, scanner, ip, mac):
        with patch.object(scanner, 'resolve_hostname', return_value=None), \
             patch.object(scanner, 'get_mac_vendor', return_value=None), \
             patch.object(scanner, 'get_config_value', side_effect=lambda k, d: str(d)):
            scanner.process_discovered_device({'ip': ip, 'mac': mac, 'source': 'arp'})
            db.session.commit()

    def test_archived_device_reappearing_resumes_monitoring(self, app, db_session, scanner):
        dev_id = _device(db_session, '192.168.1.30', '00:bb:00:00:00:01',
                         datetime.utcnow() - timedelta(days=45), is_monitored=False)
        with app.app_context():
            self._seen(scanner, '192.168.1.30', '00:bb:00:00:00:01')
            d = Device.query.get(dev_id)
            assert d.is_monitored is True
            assert (datetime.utcnow() - d.last_seen).total_seconds() < 60

    def test_user_disabled_online_device_stays_disabled(self, app, db_session, scanner):
        dev_id = _device(db_session, '192.168.1.31', '00:bb:00:00:00:02',
                         datetime.utcnow() - timedelta(hours=1), is_monitored=False)
        with app.app_context():
            self._seen(scanner, '192.168.1.31', '00:bb:00:00:00:02')
            assert Device.query.get(dev_id).is_monitored is False


class TestNetworkRangeFilter:

    def test_addresses_outside_range_are_dropped(self):
        found = [
            {'ip': '192.168.1.5', 'mac': 'aa:bb:cc:dd:ee:01'},
            {'ip': '172.19.0.2', 'mac': 'aa:bb:cc:dd:ee:02'},   # docker bridge
            {'ip': '192.168.122.10', 'mac': 'aa:bb:cc:dd:ee:03'},  # libvirt
            {'ip': '192.168.1.254', 'mac': 'aa:bb:cc:dd:ee:04'},
            {'ip': 'not-an-ip', 'mac': 'aa:bb:cc:dd:ee:05'},
        ]
        kept = NetworkScanner.filter_to_network_range(found, '192.168.1.0/24')
        assert [d['ip'] for d in kept] == ['192.168.1.5', '192.168.1.254']

    def test_invalid_range_leaves_list_untouched(self):
        found = [{'ip': '10.0.0.1', 'mac': 'aa:bb:cc:dd:ee:01'}]
        assert NetworkScanner.filter_to_network_range(found, 'garbage') == found


class TestIpConflictResolution:
    """DHCP hands a stale device's address to another device (both paths must not raise)."""

    @pytest.fixture
    def scanner(self, app):
        s = NetworkScanner(app=app)
        s._new_devices_found = []
        return s

    def _seen(self, scanner, ip, mac):
        with patch.object(scanner, 'resolve_hostname', return_value=None), \
             patch.object(scanner, 'get_mac_vendor', return_value=None), \
             patch.object(scanner, 'get_config_value', side_effect=lambda k, d: str(d)):
            scanner.process_discovered_device({'ip': ip, 'mac': mac, 'source': 'arp'})
            db.session.commit()

    def test_known_device_moves_onto_stale_devices_ip(self, app, db_session, scanner):
        old = datetime.utcnow() - timedelta(days=3)
        stale_id = _device(db_session, '192.168.1.40', '00:ee:00:00:00:01', old)      # lower id
        mover_id = _device(db_session, '192.168.1.41', '00:ee:00:00:00:02', old)      # higher id
        with app.app_context():
            self._seen(scanner, '192.168.1.40', '00:ee:00:00:00:02')   # mover now holds .40
            stale, mover = Device.query.get(stale_id), Device.query.get(mover_id)
            assert mover.ip_address == '192.168.1.40'
            assert stale.ip_address is None and stale.is_monitored is False

    def test_new_device_appears_on_stale_devices_ip(self, app, db_session, scanner):
        stale_id = _device(db_session, '192.168.1.42', '00:ee:00:00:00:03', datetime.utcnow() - timedelta(days=3))
        with app.app_context():
            self._seen(scanner, '192.168.1.42', '00:ee:00:00:00:04')   # brand-new MAC on .42
            stale = Device.query.get(stale_id)
            newcomer = Device.query.filter_by(mac_address='00:ee:00:00:00:04').one()
            assert newcomer.ip_address == '192.168.1.42' and newcomer.is_monitored is True
            assert stale.ip_address is None and stale.is_monitored is False
