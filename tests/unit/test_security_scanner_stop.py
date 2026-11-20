"""systemd's SIGTERM kills every process of the service, a running nmap port scan included. python-nmap then parsed
the half-written XML and raised PortScannerError with that XML as its message, and the security scanner logged it
as an ERROR. It also carried on: the empty port list closed every open-port alert of that device as "no longer
open", and the next device was scanned during the stop. NetworkSecurityScanner.request_stop() (set from the
SIGTERM handler, core/shutdown.py) turns that into one INFO line, scans no further device and records nothing.
Every test builds its own scanner; services.security_scanner.security_scanner is shared by the app."""

import logging
import threading
from unittest.mock import MagicMock, patch

import nmap
import pytest

from models import Alert, Device
from services import security_scanner as ss

PARTIAL_XML = (b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
               b'<nmaprun scanner="nmap" args="nmap -oX - 192.168.1.71 -T4 --top-ports 1000" version="7.98">\n')


@pytest.fixture
def scanner(app):
    with patch.object(ss.nmap, 'PortScanner'):
        s = ss.NetworkSecurityScanner(app)
    s.nm = MagicMock()
    s._own_addresses = set()
    return s


def _killed_by(scanner, stop_after=None):
    """nm.scan as it ends when SIGTERM kills nmap: the stop flag is set now, or ``stop_after`` seconds later (the
    SIGTERM handler runs in the main thread and can come after this thread sees nmap die)."""
    def scan(*args, **kwargs):
        if stop_after is None:
            scanner._stop_event.set()
        else:
            threading.Timer(stop_after, scanner._stop_event.set).start()
        raise nmap.PortScannerError(PARTIAL_XML)
    return scan


def _device(**kw):
    return Device(ip_address=kw.get('ip', '192.168.1.71'), mac_address=kw.get('mac', '00:11:22:33:44:71'),
                  hostname=kw.get('hostname', 'nas-1'), device_type='computer', is_monitored=True)


def _warnings(caplog):
    return [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_request_stop_only_sets_the_event(scanner):
    """Runs inside a signal handler: no logging, no locks of its own."""
    scanner.running = True
    scanner.request_stop()
    assert scanner._stop_event.is_set() and scanner.running is True


def test_nmap_killed_by_the_stop_is_not_an_error(scanner, caplog):
    scanner.nm.scan.side_effect = _killed_by(scanner)
    with caplog.at_level(logging.INFO, logger='services.security_scanner'):
        assert scanner.scan_device_ports(_device()) == []
    assert not _warnings(caplog)
    assert 'cut short by a stop' in caplog.text and '<?xml' not in caplog.text


def test_the_stop_flag_may_come_just_after_nmap_dies(scanner, caplog):
    scanner.nm.scan.side_effect = _killed_by(scanner, stop_after=0.1)
    with caplog.at_level(logging.INFO, logger='services.security_scanner'):
        assert scanner.scan_device_ports(_device()) == []
    assert not _warnings(caplog)


def test_a_real_nmap_failure_is_still_an_error(scanner, caplog, monkeypatch):
    monkeypatch.setattr(ss.NetworkSecurityScanner, 'STOP_GRACE', 0.05, raising=False)
    scanner.nm.scan.side_effect = nmap.PortScannerError('nmap program was not found in path')
    with caplog.at_level(logging.INFO, logger='services.security_scanner'):
        assert scanner.scan_device_ports(_device()) == []
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and errors[0].startswith('Security scan failed for') and 'not found in path' in errors[0]


def test_a_scan_cut_short_by_the_stop_closes_no_alert_and_scans_no_further(scanner, db_session):
    first = _device()
    second = _device(ip='192.168.1.72', mac='00:11:22:33:44:72', hostname='nas-2')
    db_session.add_all([first, second])
    db_session.commit()
    open_port = Alert(device_id=first.id, alert_type='security_open_port', alert_subtype='port_22',
                      severity='warning', message='New open port 22', resolved=False)
    db_session.add(open_port)
    db_session.commit()
    scanner.nm.scan.side_effect = _killed_by(scanner)
    with patch.object(scanner, 'store_scan_results') as store, \
         patch.object(scanner, 'process_security_alerts') as process:
        scanner.run_security_scan()
    assert scanner.nm.scan.call_count == 1                 # the second device is never scanned
    db_session.refresh(open_port)
    assert open_port.resolved is False                     # a killed scan says nothing about port 22
    assert store.call_count == 0 and process.call_count == 0
    assert scanner.current_scan['active'] is False and scanner.current_scan['status'] == 'stopped'


def test_without_a_stop_every_device_is_scanned_and_recorded(scanner, db_session):
    db_session.add_all([_device(), _device(ip='192.168.1.72', mac='00:11:22:33:44:72', hostname='nas-2')])
    db_session.commit()
    scanner.nm.scan.side_effect = lambda ip, arguments: {'scan': {ip: {'tcp': {22: {'state': 'open', 'name': 'ssh'}}}}}
    with patch.object(scanner, 'store_scan_results') as store, \
         patch.object(scanner, 'process_security_alerts'):
        scanner.run_security_scan()
    assert scanner.nm.scan.call_count == 2
    assert store.call_count == 1 and len(store.call_args.args[0]) == 2
    assert scanner.current_scan['status'] == 'completed'
