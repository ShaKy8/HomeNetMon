"""When nmap failed on a device (or its output could not be read), scan_device_ports returned an empty or partial
port list, and run_security_scan passed it to resolve_closed_port_alerts, which closed every open-port alert of that
device as "no longer open"; the next good scan opened them again. A host that hits nmap's --host-timeout did the
same without any error: nmap marks it timedout="true" and reports no ports, and python-nmap drops that attribute,
so the scan looked complete with every port closed. A failed or timed-out scan now leaves the alerts alone, and
the loop goes on to the next device. Every test builds its own scanner; services.security_scanner.security_scanner
is shared by the app."""

import logging
from unittest.mock import MagicMock, patch

import nmap
import pytest

from models import Alert, Device
from services import security_scanner as ss


@pytest.fixture
def scanner(app, monkeypatch):
    monkeypatch.setattr(ss.NetworkSecurityScanner, 'STOP_GRACE', 0.01, raising=False)
    with patch.object(ss.nmap, 'PortScanner'):
        s = ss.NetworkSecurityScanner(app)
    s.nm = MagicMock()
    s._own_addresses = set()
    return s


@pytest.fixture
def two_devices_with_port_22_open(db_session):
    first = Device(ip_address='192.168.1.71', mac_address='00:11:22:33:44:71', hostname='nas-1',
                   device_type='computer', is_monitored=True)
    second = Device(ip_address='192.168.1.72', mac_address='00:11:22:33:44:72', hostname='nas-2',
                    device_type='computer', is_monitored=True)
    db_session.add_all([first, second])
    db_session.commit()
    alert = Alert(device_id=first.id, alert_type='security_open_port', alert_subtype='port_22',
                  severity='warning', message='New open port 22', resolved=False)
    db_session.add(alert)
    db_session.commit()
    return first, second, alert


def _open(port, name):
    return {'state': 'open', 'name': name}


def _run(scanner):
    with patch.object(scanner, 'store_scan_results'), patch.object(scanner, 'process_security_alerts'):
        scanner.run_security_scan()


def test_an_nmap_failure_keeps_the_open_port_alerts(scanner, two_devices_with_port_22_open, db_session, caplog):
    first, _second, alert = two_devices_with_port_22_open

    def scan(ip, arguments):
        if ip == first.ip_address:
            raise nmap.PortScannerError("nmap: Failed to open device eth9")
        return {'scan': {ip: {'tcp': {}}}}
    scanner.nm.scan.side_effect = scan
    with caplog.at_level(logging.INFO, logger='services.security_scanner'):
        _run(scanner)
    db_session.refresh(alert)
    assert alert.resolved is False                          # nothing is known about port 22
    assert scanner.nm.scan.call_count == 2                  # the next device is still scanned
    assert any(r.levelno == logging.ERROR and 'Security scan failed for nas-1' in r.getMessage()
               for r in caplog.records)
    assert 'Kept the open-port alerts of nas-1: its port scan failed' in caplog.text


def test_unreadable_output_keeps_the_alerts_of_ports_it_did_not_reach(scanner, two_devices_with_port_22_open,
                                                                       db_session):
    first, _second, alert = two_devices_with_port_22_open

    def scan(ip, arguments):
        if ip == first.ip_address:                          # port 80 parses, then the entry for 22 is garbage
            return {'scan': {ip: {'tcp': {80: _open(80, 'http'), 22: 'garbage'}}}}
        return {'scan': {ip: {'tcp': {}}}}
    scanner.nm.scan.side_effect = scan
    _run(scanner)
    db_session.refresh(alert)
    assert alert.resolved is False
    assert scanner.nm.scan.call_count == 2


def test_a_completed_scan_still_closes_the_alert_of_a_port_that_closed(scanner, two_devices_with_port_22_open,
                                                                       db_session):
    scanner.nm.scan.side_effect = lambda ip, arguments: {'scan': {ip: {'tcp': {80: _open(80, 'http')}}}}
    _run(scanner)
    _first, _second, alert = two_devices_with_port_22_open
    db_session.refresh(alert)
    assert alert.resolved is True


def _nmap_xml(ip, timed_out, ports=()):
    """nmap 7.98's -oX output for one host, trimmed: a host that hits --host-timeout is still "up" but has
    timedout="true" and no <ports>, and python-nmap drops that attribute. After a real scan,
    get_nmap_last_output() returns these bytes."""
    timedout = ' timedout="true"' if timed_out else ''
    port_xml = ''.join(f'<port protocol="tcp" portid="{p}"><state state="open" reason="syn-ack" reason_ttl="0"/>'
                       f'<service name="http" method="probed" conf="10"/></port>' for p in ports)
    ports_xml = '' if timed_out else f'<ports>{port_xml}</ports>\n'
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
            f'<nmaprun scanner="nmap" args="nmap -oX - {ip} --host-timeout 60s" version="7.98">\n'
            f'<host starttime="1" endtime="61"{timedout}><status state="up" reason="user-set" reason_ttl="0"/>\n'
            f'<address addr="{ip}" addrtype="ipv4"/>\n{ports_xml}</host>\n'
            '<runstats><finished time="61" elapsed="60.70" exit="success"/><hosts up="1" down="0" total="1"/>'
            '</runstats>\n</nmaprun>\n').encode()


def _scan_as_nmap_returns_it(scanner, timed_out_ip, as_str=False):
    """nm.scan as python-nmap returns it: a timed-out host has no 'tcp' key, every other host has port 80 open.
    get_nmap_last_output() then gives that scan's raw XML."""
    def scan(ip, arguments):
        timed_out = ip == timed_out_ip
        xml = _nmap_xml(ip, timed_out, ports=() if timed_out else (80,))
        scanner.nm.get_nmap_last_output.return_value = xml.decode() if as_str else xml
        host = {'status': {'state': 'up', 'reason': 'user-set'}}
        if not timed_out:
            host['tcp'] = {80: _open(80, 'http')}
        return {'scan': {ip: host}}
    scanner.nm.scan.side_effect = scan


@pytest.mark.parametrize('as_str', [False, True], ids=['bytes', 'str'])
def test_a_host_timeout_keeps_the_open_port_alerts(scanner, two_devices_with_port_22_open, db_session, caplog,
                                                   as_str):
    first, _second, alert = two_devices_with_port_22_open
    _scan_as_nmap_returns_it(scanner, first.ip_address, as_str)
    with caplog.at_level(logging.INFO, logger='services.security_scanner'):
        _run(scanner)
    db_session.refresh(alert)
    assert alert.resolved is False                          # nmap gave up on the host: nothing is known about 22
    assert scanner.nm.scan.call_count == 2                  # the next device is still scanned
    assert 'Security scan of nas-1 hit its 60s host timeout' in caplog.text
    assert 'Kept the open-port alerts of nas-1' in caplog.text
    assert 'Kept the open-port alerts of nas-2' not in caplog.text


def test_a_completed_scan_after_a_timeout_elsewhere_still_closes_its_alert(scanner, two_devices_with_port_22_open,
                                                                           db_session):
    first, second, alert = two_devices_with_port_22_open
    alert.device_id = second.id                             # the alert is on the device whose scan completed
    db_session.commit()
    _scan_as_nmap_returns_it(scanner, first.ip_address)
    _run(scanner)
    db_session.refresh(alert)
    assert alert.resolved is True


def test_scan_device_ports_reports_a_host_timeout_to_its_caller(scanner):
    device = Device(ip_address='192.168.1.73', hostname='nas-3', device_type='computer', is_monitored=True)
    _scan_as_nmap_returns_it(scanner, device.ip_address)
    outcome = {}
    assert scanner.scan_device_ports(device, outcome) == [] and outcome == {'failed': True}
    _scan_as_nmap_returns_it(scanner, timed_out_ip=None)
    outcome = {}
    assert len(scanner.scan_device_ports(device, outcome)) == 1 and outcome == {}


def test_scan_device_ports_reports_the_failure_to_its_caller(scanner):
    device = Device(ip_address='192.168.1.73', hostname='nas-3', device_type='computer', is_monitored=True)
    scanner.nm.scan.side_effect = nmap.PortScannerError('boom')
    outcome = {}
    assert scanner.scan_device_ports(device, outcome) == [] and outcome == {'failed': True}
    scanner.nm.scan.side_effect = lambda ip, arguments: {'scan': {ip: {'tcp': {}}}}
    outcome = {}
    assert scanner.scan_device_ports(device, outcome) == [] and outcome == {}
    assert scanner.scan_device_ports(device) == []          # the manual-scan route passes no outcome
