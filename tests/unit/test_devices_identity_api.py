"""Add-device, notes/tags and reclassification through the devices API and scanner."""

from datetime import datetime
from unittest.mock import patch

from models import Device, db


def _token(client):
    return client.get('/api/csrf-token').get_json()['csrf_token']


class TestCreateDevice:

    def test_create_with_tags_notes_and_auto_fill(self, client, app, db_session):
        with patch.object(app._scanner, 'get_mac_vendor', return_value='Sonos'), \
             patch.object(app._scanner, 'resolve_hostname', return_value='sonoszp.lan'):
            r = client.post('/api/devices', json={'ip_address': '192.168.1.140', 'mac_address': 'AA-BB-CC-DD-EE-01',
                                                  'tags': 'Kids, IoT, kids', 'notes': 'Bedroom speaker'},
                            headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 201, r.get_json()
        d = r.get_json()['device']
        assert d['mac_address'] == 'aa:bb:cc:dd:ee:01'
        assert d['vendor'] == 'Sonos' and d['hostname'] == 'sonoszp.lan'
        assert d['device_type'] == 'smart_home'
        assert d['tags'] == ['kids', 'iot'] and d['notes'] == 'Bedroom speaker'

    def test_explicit_type_is_kept(self, client, app, db_session):
        with patch.object(app._scanner, 'resolve_hostname', return_value=None):
            r = client.post('/api/devices', json={'ip_address': '192.168.1.141', 'device_type': 'printer'},
                            headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 201 and r.get_json()['device']['device_type'] == 'printer'

    def test_bad_mac_and_duplicate_ip_are_rejected(self, client, app, db_session):
        token = _token(client)
        assert client.post('/api/devices', json={'ip_address': '192.168.1.142', 'mac_address': 'nope'},
                           headers={'X-CSRF-Token': token}).status_code == 400
        db_session.add(Device(ip_address='192.168.1.143', mac_address='00:aa:00:00:01:43')); db_session.commit()
        assert client.post('/api/devices', json={'ip_address': '192.168.1.143'},
                           headers={'X-CSRF-Token': token}).status_code == 400


class TestUpdateDevice:

    def test_tags_and_notes_round_trip(self, client, db_session):
        d = Device(ip_address='192.168.1.150', mac_address='00:aa:00:00:01:50', hostname='x', device_type='computer')
        db_session.add(d); db_session.commit()
        r = client.put(f'/api/devices/{d.id}', json={'tags': ['Office', 'Critical'], 'notes': 'Under the desk'},
                       headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 200, r.get_json()
        body = client.get(f'/api/devices/{d.id}').get_json()
        device = body.get('device') or body
        assert device['tags'] == ['office', 'critical'] and device['notes'] == 'Under the desk'


class TestReclassify:

    def test_unknowns_are_reclassified_and_user_types_kept(self, client, app, db_session):
        rows = [
            Device(ip_address='192.168.1.160', mac_address='00:aa:00:00:01:60', hostname='sonoszp.lan', device_type='unknown'),
            Device(ip_address='192.168.1.161', mac_address='00:aa:00:00:01:61', hostname='npic2cfbe.lan', device_type=None),
            Device(ip_address='192.168.1.162', mac_address='00:aa:00:00:01:62', hostname='sonoszp2.lan', device_type='computer'),
            Device(ip_address='192.168.1.163', mac_address='02:aa:00:00:01:63', hostname=None, device_type='unknown'),
        ]
        db_session.add_all(rows); db_session.commit()
        r = client.post('/api/devices/reclassify', json={}, headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 200, r.get_json()
        body = r.get_json()
        assert body['changed'] == 2 and body['checked'] == 3
        types = {d.ip_address: d.device_type for d in Device.query.all()}
        assert types['192.168.1.160'] == 'smart_home' and types['192.168.1.161'] == 'printer'
        assert types['192.168.1.162'] == 'computer'            # user-set, untouched
        assert types['192.168.1.163'] == 'unknown'             # nothing to go on

    def test_scan_reclassifies_an_unknown_once_a_hostname_is_learned(self, app, db_session):
        d = Device(ip_address='192.168.1.170', mac_address='00:aa:00:00:01:70', hostname=None, device_type='unknown',
                   last_seen=datetime.utcnow())
        db_session.add(d); db_session.commit()
        scanner = app._scanner
        with app.app_context(), \
             patch('monitoring.mdns.query_mdns', return_value={'hostname': None, 'services': []}):
            scanner._mdns_budget = 5
            scanner.process_discovered_device({'ip': '192.168.1.170', 'mac': '00:aa:00:00:01:70', 'hostname': 'wyze_cam_1.lan'})
            db.session.commit()
            assert db.session.get(Device, d.id).device_type == 'camera'

    def test_scan_uses_mdns_services_when_no_hostname(self, app, db_session):
        d = Device(ip_address='192.168.1.171', mac_address='02:aa:00:00:01:71', hostname=None, device_type='unknown',
                   last_seen=datetime.utcnow())
        db_session.add(d); db_session.commit()
        scanner = app._scanner
        with app.app_context(), \
             patch.object(scanner, 'resolve_hostname', return_value=None), \
             patch('monitoring.mdns.query_mdns', return_value={'hostname': 'kitchen-cast.local', 'services': ['_googlecast._tcp.local']}):
            scanner._mdns_budget = 5
            scanner.process_discovered_device({'ip': '192.168.1.171', 'mac': '02:aa:00:00:01:71', 'hostname': None})
            db.session.commit()
            fresh = db.session.get(Device, d.id)
            assert fresh.device_type == 'media' and fresh.hostname == 'kitchen-cast.local'
            assert fresh.mdns_service_list == ['_googlecast._tcp.local']
