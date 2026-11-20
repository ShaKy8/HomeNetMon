"""systemd's SIGTERM kills every process of the service, the scanner's nmap sweep included. python-nmap then parses
the half-written XML, raises PortScannerError with that XML as its message, and the scanner logged it as an ERROR;
scan_network went on to process, commit and announce the cut-short scan. NetworkScanner.request_stop() (set from
the SIGTERM handler, core/shutdown.py) turns that into one INFO line and a scan that records nothing."""

import logging
import threading
from unittest.mock import MagicMock, patch

import nmap
import pytest

from monitoring.scanner import NetworkScanner

PARTIAL_XML = (b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
               b'<nmaprun scanner="nmap" args="nmap -oX - -sn -T2 192.168.1.0/24" version="7.98">\n')


@pytest.fixture
def scanner():
    with patch('monitoring.scanner.nmap.PortScanner'), patch('monitoring.scanner.manuf.MacParser'):
        s = NetworkScanner()
    s.nm = MagicMock()
    s._get_excluded_device_ips = list
    return s


def _killed_by(scanner, stop_after=None):
    """nm.scan as it ends when SIGTERM kills nmap: the stop flag is set now, or ``stop_after`` seconds later (the
    SIGTERM handler runs in the main thread and can come after this thread sees nmap die)."""
    def scan(**kwargs):
        if stop_after is None:
            scanner._stop_event.set()
        else:
            threading.Timer(stop_after, scanner._stop_event.set).start()
        raise nmap.PortScannerError(PARTIAL_XML)
    scanner.nm.scan.side_effect = scan


def test_request_stop_only_sets_the_event(scanner):
    """Runs inside a signal handler: no logging, no locks of its own."""
    scanner.is_running = True
    scanner.request_stop()
    assert scanner._stop_event.is_set() and scanner.is_running is True


def test_nmap_killed_by_the_stop_is_not_an_error(scanner, caplog):
    _killed_by(scanner)
    with caplog.at_level(logging.INFO, logger='monitoring.scanner'):
        assert scanner.nmap_scan('192.168.1.0/24') == []
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert 'nmap scan cut short by a stop' in caplog.text
    assert '<?xml' not in caplog.text


def test_the_stop_flag_may_come_just_after_nmap_dies(scanner, caplog):
    _killed_by(scanner, stop_after=0.1)
    with caplog.at_level(logging.INFO, logger='monitoring.scanner'):
        assert scanner.nmap_scan('192.168.1.0/24') == []
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_a_real_nmap_failure_is_still_an_error(scanner, caplog, monkeypatch):
    monkeypatch.setattr(NetworkScanner, 'STOP_GRACE', 0.05, raising=False)
    scanner.nm.scan.side_effect = nmap.PortScannerError('nmap program was not found in path')
    with caplog.at_level(logging.INFO, logger='monitoring.scanner'):
        assert scanner.nmap_scan('192.168.1.0/24') == []
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and errors[0].startswith('Error during nmap scan:') and 'not found in path' in errors[0]


def test_a_scan_cut_short_by_the_stop_records_nothing(scanner, app):
    scanner.app = app
    _killed_by(scanner)
    with patch.object(scanner, 'get_arp_table', return_value=[{'ip': '192.168.1.20', 'mac': 'aa:bb:cc:dd:ee:01'}]), \
         patch.object(scanner, 'process_discovered_device') as process, \
         patch.object(scanner, '_notify_scan_results') as notify, \
         patch.object(scanner, '_emit_scan_progress'):
        scanner.scan_network()
    assert process.call_count == 0 and notify.call_count == 0
    assert scanner.is_scanning is False


def test_without_a_stop_a_scan_after_an_nmap_failure_still_uses_arp(scanner, app, monkeypatch):
    monkeypatch.setattr(NetworkScanner, 'STOP_GRACE', 0.05, raising=False)
    scanner.app = app
    scanner.nm.scan.side_effect = nmap.PortScannerError('boom')
    with patch.object(scanner, 'get_arp_table', return_value=[{'ip': '192.168.1.20', 'mac': 'aa:bb:cc:dd:ee:01'}]), \
         patch.object(scanner, 'process_discovered_device') as process, \
         patch.object(scanner, '_notify_scan_results') as notify, \
         patch.object(scanner, '_emit_scan_progress'):
        scanner.scan_network()
    assert process.call_count == 1 and notify.call_count == 1
