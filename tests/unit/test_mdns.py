"""monitoring/mdns.py parses unicast mDNS answers and never raises."""

from unittest.mock import patch

import dns.message
import dns.rdatatype
import dns.rrset

from monitoring import mdns


def _fake_udp(message, ip, port=5353, timeout=0.5, ignore_unexpected=True):
    question = message.question[0]
    response = dns.message.make_response(message)
    if question.rdtype == dns.rdatatype.PTR and str(question.name).endswith('in-addr.arpa.'):
        response.answer.append(dns.rrset.from_text(str(question.name), 120, 'IN', 'PTR', 'sonoszp.local.'))
    elif str(question.name) == mdns.SERVICE_ENUM:
        response.answer.append(dns.rrset.from_text(mdns.SERVICE_ENUM, 120, 'IN', 'PTR',
                                                   '_sonos._tcp.local.', '_spotify-connect._tcp.local.'))
    return response


def test_query_parses_hostname_and_services():
    with patch('monitoring.mdns.dns.query.udp', side_effect=_fake_udp):
        result = mdns.query_mdns('192.168.1.40')
    assert result == {'hostname': 'sonoszp.local', 'services': ['_sonos._tcp.local', '_spotify-connect._tcp.local']}


def test_query_swallows_timeouts():
    with patch('monitoring.mdns.dns.query.udp', side_effect=TimeoutError('no answer')):
        assert mdns.query_mdns('192.168.1.41') == {'hostname': None, 'services': []}


def test_dhcp_leases_parser(tmp_path):
    leases = tmp_path / 'dhcp.leases'
    leases.write_text('1757600000 aa:bb:cc:dd:ee:01 192.168.1.5 living-room-tv 01:aa:bb:cc:dd:ee:01\n'
                      '1757600000 aa:bb:cc:dd:ee:02 192.168.1.6 * *\n')
    assert mdns.read_dhcp_leases(str(leases)) == {'aa:bb:cc:dd:ee:01': 'living-room-tv'}
    assert mdns.read_dhcp_leases(str(tmp_path / 'missing')) == {}
