"""A device's first completed port scan is its baseline. get_previous_scan_results compares a scan with the open
ports of the scans in the window before it; a device that had no completed scan there (the speakers that always hit
--host-timeout, a device last scanned weeks ago) got a pushed new-service alert for every open port. Such a scan is
now stored and raises no new-service alert; suspicious-port and high-risk alerts still apply. Every completed scan
leaves a scan_completed record, even with no ports, so a quiet device that opens a port still alerts. A scan that
failed, timed out or was skipped records nothing. The comparison is by port: nmap naming an open port differently
(Sonos 1443 upnp, then ies-lm) is not a new service."""

import logging
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from models import Device, SecurityEvent, SecurityScan
from services import security_scanner as ss

IP = '192.168.1.91'


@pytest.fixture
def scanner(app, monkeypatch):
    monkeypatch.setattr(ss.NetworkSecurityScanner, 'STOP_GRACE', 0.01, raising=False)
    with patch.object(ss.nmap, 'PortScanner'):
        s = ss.NetworkSecurityScanner(app)
    s.nm = MagicMock()
    s._own_addresses = set()
    s.scan_interval = 4 * 3600
    return s


@pytest.fixture
def device(db_session):
    d = Device(ip_address=IP, mac_address='00:11:22:33:44:91', hostname='speaker', device_type='computer',
               is_monitored=True)
    db_session.add(d)
    db_session.commit()
    return d


def _sweep(scanner, ports=None, timed_out=False):
    """One sweep in which nmap finds ``ports`` ({port: service}) open, or gives up on the host. Returns the
    security alerts raised, as (type, port)."""
    def scan(ip, arguments):
        if timed_out:
            scanner.nm.get_nmap_last_output.return_value = b'<host starttime="1" endtime="61" timedout="true">'
            return {'scan': {ip: {'status': {'state': 'up', 'reason': 'user-set'}}}}
        scanner.nm.get_nmap_last_output.return_value = b'<host starttime="1" endtime="9">'
        return {'scan': {ip: {'tcp': {p: {'state': 'open', 'name': n} for p, n in (ports or {}).items()}}}}
    scanner.nm.scan.side_effect = scan
    with patch.object(scanner, 'process_security_alerts') as process:
        scanner.run_security_scan()
    return sorted((a.alert_type, a.port) for call in process.call_args_list for a in call.args[0])


def _completed_records(device):
    return SecurityEvent.query.filter_by(device_id=device.id, event_type='scan_completed').count()


def test_a_first_completed_scan_is_the_baseline(scanner, device, caplog):
    with caplog.at_level(logging.INFO, logger='services.security_scanner'):
        assert _sweep(scanner, {80: 'http', 8080: 'http-proxy'}) == []
    stored = {(r.port, r.service) for r in SecurityScan.query.filter_by(device_id=device.id)}
    assert stored == {(80, 'http'), (8080, 'http-proxy')}
    assert 'speaker: 2 open port(s) recorded as its baseline' in caplog.text


def test_a_port_that_opens_after_the_baseline_alerts(scanner, device):
    assert _sweep(scanner, {80: 'http'}) == []
    assert _sweep(scanner, {80: 'http', 8080: 'http-proxy'}) == [('new_service', 8080)]


def test_a_new_name_on_a_port_that_was_open_is_not_a_new_service(scanner, device):
    assert _sweep(scanner, {1443: 'upnp', 7000: 'rtsp'}) == []
    assert _sweep(scanner, {1443: 'ies-lm', 7000: 'rtsp'}) == []


def test_a_port_that_opens_beside_a_renamed_one_still_alerts(scanner, device):
    assert _sweep(scanner, {1443: 'upnp'}) == []
    assert _sweep(scanner, {1443: 'ies-lm', 8080: 'http-proxy'}) == [('new_service', 8080)]


def test_a_port_nmap_cannot_name_is_stored_as_unknown(scanner, device):
    # python-nmap gives "" (or None for a <service> element without a name), never a missing key
    _sweep(scanner, {80: 'http'})
    scanner.nm.scan.side_effect = lambda ip, arguments: {'scan': {ip: {
        'tcp': {p: {'state': 'open', 'name': n} for p, n in {80: 'http', 8080: 'http-proxy', 40030: '', 40031: None}.items()},
        'udp': {161: {'state': 'open', 'name': ''}}}}}
    with patch.object(scanner, 'process_security_alerts') as process:
        scanner.run_security_scan()
    messages = sorted(a.message for call in process.call_args_list for a in call.args[0])
    assert messages == ['New service detected: http-proxy on port 8080', 'New service detected: udp/unknown on port 161',
                        'New service detected: unknown on port 40030', 'New service detected: unknown on port 40031']
    stored = {(r.port, r.service) for r in SecurityScan.query.filter_by(device_id=device.id)}
    assert stored == {(80, 'http'), (8080, 'http-proxy'), (40030, 'unknown'), (40031, 'unknown'), (161, 'udp/unknown')}


def test_a_new_port_without_a_service_name_says_so_plainly(scanner, device):
    result = ss.PortScanResult(device_id=device.id, ip_address=IP, port=40030, state='open', service='', version='',
                               product='', extra_info='', confidence=0, scanned_at=datetime.utcnow())
    assert [a.message for a in scanner.analyze_security_results(device, [result])] == ['New service detected on port 40030']


def test_a_timed_out_scan_records_nothing_so_the_next_completed_one_is_the_baseline(scanner, device):
    assert _sweep(scanner, timed_out=True) == []
    assert _completed_records(device) == 0
    assert _sweep(scanner, {80: 'http', 8080: 'http-proxy'}) == []


def test_scans_older_than_the_window_give_a_baseline_too(scanner, device, db_session):
    weeks_ago = datetime.utcnow() - timedelta(days=30)
    db_session.add(SecurityScan(device_id=device.id, ip_address=IP, port=80, state='open', service='http',
                                scanned_at=weeks_ago))
    db_session.add(SecurityEvent(device_id=device.id, event_type='scan_completed', severity='info',
                                 message='Security scan completed: 1 open ports found', created_at=weeks_ago))
    db_session.commit()
    assert _sweep(scanner, {80: 'http', 8080: 'http-proxy'}) == []


def test_a_quiet_device_records_its_scan_and_alerts_when_a_port_opens(scanner, device):
    assert _sweep(scanner, {}) == []
    assert _completed_records(device) == 1                  # no ports, but the scan completed
    assert _sweep(scanner, {80: 'http'}) == [('new_service', 80)]


def test_a_baseline_still_raises_risk_alerts(scanner, device):
    assert _sweep(scanner, {23: 'telnet'}) == [('suspicious_port', 23), ('vulnerability', 23)]  # no new_service


def test_a_skipped_device_records_nothing(scanner, device):
    scanner._own_addresses = {IP}
    _sweep(scanner, {80: 'http'})
    assert scanner.nm.scan.call_count == 0
    assert _completed_records(device) == 0


def _messages(scanner, device, port, service, version):
    result = ss.PortScanResult(device_id=device.id, ip_address=IP, port=port, state='open', service=service,
                               version=version, product='', extra_info='', confidence=10,
                               scanned_at=datetime.utcnow())
    return sorted((a.alert_type, a.message) for a in scanner.analyze_security_results(device, [result], baseline=True))


def test_risk_alerts_without_a_version_drop_the_v(scanner, device):
    assert _messages(scanner, device, 23, 'telnet', '') == [
        ('suspicious_port', 'Suspicious service detected: telnet on port 23'),
        ('vulnerability', 'High-risk service: telnet on port 23')]
    assert _messages(scanner, device, 23, 'telnet', '0.17')[1] == ('vulnerability', 'High-risk service: telnet v0.17 on port 23')


def test_risk_alerts_without_a_service_name_say_so_plainly(scanner, device, monkeypatch):
    monkeypatch.setitem(scanner.risk_weights, 'unknown', 7)     # so an unnamed suspicious port also reaches high risk
    assert _messages(scanner, device, 3389, '', '') == [
        ('suspicious_port', 'Suspicious service detected on port 3389'),
        ('vulnerability', 'High-risk service on port 3389')]
