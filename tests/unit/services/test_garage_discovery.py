"""services/garage_discovery.py: DB candidates, probe confirmation, unicast mDNS evidence."""

from datetime import datetime
from unittest.mock import patch

import pytest

from models import Device, db
from services import garage_discovery as gd


@pytest.fixture
def lan(app, db_session):
    rows = [
        Device(ip_address='192.168.1.50', mac_address='aa:00:00:00:00:50', hostname='ratgdov25i-3f2a1c.lan',
               vendor='Espressif', device_type='smart_home', last_seen=datetime.utcnow()),
        Device(ip_address='192.168.1.51', mac_address='aa:00:00:00:00:51', hostname='esp-lamp', vendor='Espressif',
               mdns_services='_esphomelib._tcp.local,_http._tcp.local', last_seen=datetime.utcnow()),
        Device(ip_address='192.168.1.52', mac_address='aa:00:00:00:00:52', hostname=None, vendor='Espressif',
               last_seen=datetime.utcnow()),
        Device(ip_address='192.168.1.53', mac_address='aa:00:00:00:00:53', hostname='printer', vendor='HP',
               last_seen=datetime.utcnow()),
        Device(ip_address=None, mac_address='aa:00:00:00:00:54', hostname='ratgdo-archived', vendor='Espressif',
               last_seen=datetime.utcnow()),
    ]
    db_session.add_all(rows)
    db_session.commit()
    return rows


def test_candidates_are_ranked_by_evidence(app, lan):
    with app.app_context():
        found = gd.candidates_from_db()
    assert [(c['ip'], c['reason']) for c in found] == [('192.168.1.50', 'hostname'), ('192.168.1.51', 'mdns'),
                                                        ('192.168.1.52', 'vendor')]
    assert all(c['confirmed'] is False for c in found)


def test_current_host_sorts_first(app, lan):
    with app.app_context():
        found = gd.candidates_from_db(current_host='192.168.1.52:8080')
    assert found[0]['ip'] == '192.168.1.52' and found[0]['current'] is True


def test_confirm_uses_the_probe_and_mdns_fallback():
    cover = {'id': 'cover-door', 'state': 'CLOSED', 'value': 0.0, 'current_operation': 'IDLE'}
    with patch('services.garage_discovery.rc.probe', return_value=cover):
        got = gd.confirm({'ip': '192.168.1.50', 'reason': 'hostname'})
    assert got['confirmed'] is True and got['door'] == 'closed'

    with patch('services.garage_discovery.rc.probe', return_value=None), \
            patch('services.garage_discovery.query_mdns', return_value={'hostname': 'esp', 'services': ['_esphomelib._tcp.local']}):
        got = gd.confirm({'ip': '192.168.1.52', 'reason': 'vendor'})
    assert got['confirmed'] is False and got['reason'] == 'mdns'

    with patch('services.garage_discovery.rc.probe', return_value=None), \
            patch('services.garage_discovery.query_mdns', side_effect=OSError('no')):
        got = gd.confirm({'ip': '192.168.1.52', 'reason': 'vendor'})
    assert got['reason'] == 'vendor'


def test_discover_puts_confirmed_first_and_is_bounded(app, lan):
    def fake_probe(ip, timeout=2.0, auth=None):
        return {'id': 'cover-door', 'state': 'OPEN', 'value': 1.0, 'current_operation': 'IDLE'} if ip == '192.168.1.52' else None
    with app.app_context(), patch('services.garage_discovery.rc.probe', side_effect=fake_probe), \
            patch('services.garage_discovery.query_mdns', return_value={'services': []}):
        result = gd.discover()
    assert result['probed'] == 3
    assert result['candidates'][0]['ip'] == '192.168.1.52' and result['candidates'][0]['door'] == 'open'


def test_discover_with_an_empty_lan(app, db_session):
    with app.app_context():
        assert gd.discover() == {'candidates': [], 'probed': 0}
