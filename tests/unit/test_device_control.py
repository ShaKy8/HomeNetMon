"""Device-control endpoints: LAN-only targets, valid WoL packets, honest ping parsing."""

from unittest.mock import Mock, patch

import pytest

from services.device_control import DeviceControlService


def _token(client):
    return client.get('/api/csrf-token').get_json()['csrf_token']


class TestTargetValidation:

    @pytest.mark.parametrize('bad', ['-f', '8.8.8.8', 'evil.example.com/x?a=', '224.0.0.1', '0.0.0.0', '', 'localhost'])
    def test_non_lan_or_malformed_targets_are_rejected(self, client, bad):
        with patch('api.device_control.device_control_service.traceroute_to_device') as trace:
            r = client.post('/api/device-control/traceroute', json={'ip_address': bad},
                            headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 400, (bad, r.get_json())
        trace.assert_not_called()

    def test_private_target_is_accepted(self, client):
        with patch('api.device_control.device_control_service.traceroute_to_device', return_value={'success': True}) as trace:
            r = client.post('/api/device-control/traceroute', json={'ip_address': ' 192.168.1.9 '},
                            headers={'X-CSRF-Token': _token(client)})
        assert r.status_code == 200
        trace.assert_called_once_with('192.168.1.9')

    def test_traceroute_and_discover_share_validation(self, client):
        for path in ('/api/device-control/traceroute', '/api/device-control/discover-info', '/api/device-control/port-scan'):
            r = client.post(path, json={'ip_address': '1.1.1.1'}, headers={'X-CSRF-Token': _token(client)})
            assert r.status_code == 400, path


class TestWakeOnLan:

    def test_magic_packet_is_well_formed(self):
        sent = []

        class FakeSock:
            def setsockopt(self, *a): pass
            def sendto(self, data, addr): sent.append((data, addr))
            def close(self): pass

        with patch('services.device_control.socket.socket', return_value=FakeSock()):
            result = DeviceControlService().send_wake_on_lan('aa:bb:cc:dd:ee:ff')
        assert result['success']
        packet = sent[0][0]
        assert len(packet) == 102                       # 6 x 0xFF + 16 x 6-byte MAC
        assert packet[:6] == b'\xff' * 6                # the old b'\\xff' literal made this b'\\xff\\x'
        assert packet[6:12] == bytes.fromhex('aabbccddeeff')
        assert ('255.255.255.255', 9) in [a for _, a in sent]


class TestPingParser:

    def test_received_packets_are_counted(self):
        stdout = ("PING 192.168.1.9 (192.168.1.9) 56(84) bytes of data.\n"
                  "64 bytes from 192.168.1.9: icmp_seq=1 ttl=64 time=1.20 ms\n"
                  "64 bytes from 192.168.1.9: icmp_seq=2 ttl=64 time=2.80 ms\n"
                  "\n--- 192.168.1.9 ping statistics ---\n"
                  "2 packets transmitted, 2 received, 0% packet loss, time 1001ms\n")
        which = Mock(returncode=0)
        run = Mock(returncode=0, stdout=stdout)
        with patch('services.device_control.subprocess.run', side_effect=[which, run]):
            result = DeviceControlService().ping_device('192.168.1.9', count=2)
        assert result['packets_received'] == 2          # was always 0 because of split('\\n')
        assert result['packet_loss_percent'] == 0
        assert result['avg_response_time'] == 2.0
