"""Rotated-MAC adoption (monitoring/scanner.py::_adopt_rotated_mac) and identity_key."""

from datetime import datetime, timedelta

from models import Device, DeviceIpHistory, db
from monitoring.device_classifier import ALL_DEVICE_TYPES, DEVICE_TYPES, identity_key
from monitoring.scanner import NetworkScanner

REAL_A = '6c:6e:07:11:e4:3a'
REAL_B = '6c:6e:07:11:e4:3b'
RAND_1 = 'd2:5f:2d:99:a0:47'
RAND_2 = '3a:c1:5f:03:3a:a6'
PRESENT = datetime.utcnow()
ABSENT = datetime.utcnow() - timedelta(hours=6)


def _row(hostname, mac, ip, last_seen=ABSENT, **kw):
    d = Device(hostname=hostname, mac_address=mac, ip_address=ip, last_seen=last_seen, is_monitored=True, **kw)
    db.session.add(d)
    db.session.commit()
    return d


def _scanner(app):
    s = NetworkScanner(app=app)
    s.get_mac_vendor = lambda mac: None
    return s


class TestIdentityKey:

    def test_strips_domain_and_case(self):
        assert identity_key('KSP-Mac.local') == 'ksp-mac'
        assert identity_key('ksp-mac.lan') == 'ksp-mac'
        assert identity_key('printer.home.arpa') == 'printer'
        assert identity_key('bare') == 'bare'
        assert identity_key('') is None and identity_key(None) is None

    def test_one_type_list(self):
        assert set(DEVICE_TYPES) <= set(ALL_DEVICE_TYPES)
        assert {'apple', 'storage', 'switch', 'laptop', 'server', 'nas', 'tablet'} <= set(ALL_DEVICE_TYPES)


class TestAdoption:

    def test_randomized_mac_adopts_absent_row_with_same_name(self, app, db_session):
        with app.app_context():
            old = _row('KSP-Mac.local', RAND_1, '192.168.1.51')
            got = _scanner(app)._adopt_rotated_mac('192.168.1.60', RAND_2, 'ksp-mac.lan', trusted=True)
            assert got is not None and got.id == old.id
            assert got.mac_address == RAND_2 and got.ip_address == '192.168.1.60'
            hist = DeviceIpHistory.query.filter_by(device_id=old.id).one()
            assert hist.change_source == 'mac_rotation' and RAND_1 in hist.notes and RAND_2 in hist.notes

    def test_no_hostname_or_no_match_creates_nothing(self, app, db_session):
        with app.app_context():
            _row('other.lan', RAND_1, '192.168.1.51')
            s = _scanner(app)
            assert s._adopt_rotated_mac('192.168.1.60', RAND_2, None) is None
            assert s._adopt_rotated_mac('192.168.1.60', RAND_2, 'ksp-mac.lan', trusted=True) is None

    def test_two_real_macs_are_never_merged_on(self, app, db_session):
        with app.app_context():
            _row('sonoszp.lan', REAL_A, '192.168.1.20')
            _row('sonoszp.lan', REAL_B, '192.168.1.21')
            assert _scanner(app)._adopt_rotated_mac('192.168.1.22', RAND_1, 'sonoszp.lan', trusted=True) is None

    def test_real_mac_only_adopts_random_or_missing(self, app, db_session):
        with app.app_context():
            real = _row('printer.lan', REAL_A, '192.168.1.30')
            assert _scanner(app)._adopt_rotated_mac('192.168.1.31', REAL_B, 'printer.lan', trusted=True) is None
            real.mac_address = None
            db.session.commit()
            got = _scanner(app)._adopt_rotated_mac('192.168.1.31', REAL_B, 'printer.lan', trusted=True)
            assert got is not None and got.mac_address == REAL_B

    def test_random_mac_adopts_real_row_only_when_absent(self, app, db_session):
        with app.app_context():
            phone = _row('iphone.lan', REAL_A, '192.168.1.40', last_seen=PRESENT)
            s = _scanner(app)
            assert s._adopt_rotated_mac('192.168.1.41', RAND_1, 'iphone.lan', trusted=True) is None
            phone.last_seen = ABSENT
            db.session.commit()
            got = s._adopt_rotated_mac('192.168.1.41', RAND_1, 'iphone.lan', trusted=True)
            assert got is not None and got.id == phone.id and got.mac_address == RAND_1

    def test_reverse_dns_name_needs_same_ip_and_absence(self, app, db_session):
        with app.app_context():
            old = _row('laptop.lan', RAND_1, '192.168.1.70')
            s = _scanner(app)
            assert s._adopt_rotated_mac('192.168.1.71', RAND_2, 'laptop.lan', trusted=False) is None   # different IP
            got = s._adopt_rotated_mac('192.168.1.70', RAND_2, 'laptop.lan', trusted=False)
            assert got is not None and got.id == old.id

    def test_two_candidates_means_new_row(self, app, db_session):
        with app.app_context():
            _row('ipad.lan', RAND_1, '192.168.1.80')
            _row('ipad.lan', RAND_2, '192.168.1.81')
            assert _scanner(app)._adopt_rotated_mac('192.168.1.82', '3a:00:00:00:00:01', 'ipad.lan', trusted=True) is None

    def test_conflicting_ip_row_is_cleared(self, app, db_session):
        with app.app_context():
            old = _row('mac.lan', RAND_1, '192.168.1.90')
            squatter = _row('stale.lan', None, '192.168.1.91')
            got = _scanner(app)._adopt_rotated_mac('192.168.1.91', RAND_2, 'mac.lan', trusted=True)
            db.session.commit()
            assert got.id == old.id and got.ip_address == '192.168.1.91'
            assert squatter.ip_address is None and squatter.is_monitored is False

    def test_process_discovered_device_adopts_instead_of_creating(self, app, db_session):
        with app.app_context():
            old = _row('KSP-Mac.local', RAND_1, '192.168.1.51')
            s = _scanner(app)
            s.resolve_hostname = lambda ip: None
            s.enrich_identity = lambda ip, mac=None: {'hostname': 'KSP-Mac.local', 'services': ['_companion-link._tcp']}
            s._devices_before_scan = {RAND_1}
            s._new_devices_found = []
            s.process_discovered_device({'ip': '192.168.1.60', 'mac': RAND_2, 'hostname': None})
            db.session.commit()
            assert Device.query.count() == 1
            assert old.mac_address == RAND_2 and old.ip_address == '192.168.1.60'
            assert old.mdns_services == '_companion-link._tcp'
            assert s._new_devices_found == []

    def test_reclassify_by_ids(self, app, db_session):
        with app.app_context():
            d = _row('brother-printer.lan', REAL_A, '192.168.1.95', device_type='computer')
            result = _scanner(app).reclassify(device_ids=[d.id])
            assert result['checked'] == 1 and result['changed'] == 1 and d.device_type == 'printer'
