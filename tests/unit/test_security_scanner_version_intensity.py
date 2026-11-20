"""Devices with ports that accept a connection and then stay silent (the Google speakers' 8008, 8009, 8443, 9000 and
10001) never finished a port scan: -sV ran at nmap's default intensity 7, whose probes wait up to 156 s on such a
port, past the 60 s --host-timeout. It now runs at intensity 0: the NULL probe and the probes nmap registers for the
port number. Silent copies of those ports took 46 s at 0 and still timed out at 1 and 2. The Settings switch "Version
detection" only ever chose between 7 and nmap's default, also 7."""

from unittest.mock import MagicMock, patch

import pytest

from models import Device
from services import security_scanner as ss


@pytest.fixture
def scanner(app):
    with patch.object(ss.nmap, 'PortScanner'):
        s = ss.NetworkSecurityScanner(app)
    s.nm = MagicMock()
    s.nm.scan.side_effect = lambda ip, arguments: {'scan': {ip: {'tcp': {}}}}
    s._own_addresses = set()
    return s


def _arguments(scanner):
    scanner.scan_device_ports(Device(ip_address='192.168.1.81', hostname='speaker', device_type='speaker'))
    return scanner.nm.scan.call_args.kwargs['arguments'].split()


@pytest.mark.parametrize('version_detection', [True, False])
def test_service_detection_runs_at_intensity_0(scanner, version_detection):
    scanner.scan_config['version_detection'] = version_detection
    args = _arguments(scanner)
    assert '-sV' in args
    assert args[args.index('--version-intensity') + 1] == '0'
    assert args.count('--version-intensity') == 1


def test_without_service_detection_there_is_no_version_scan(scanner):
    scanner.scan_config['service_detection'] = False
    args = _arguments(scanner)
    assert '-sV' not in args and '--version-intensity' not in args


def test_the_host_timeout_is_unchanged(scanner):
    args = _arguments(scanner)
    assert args[args.index('--host-timeout') + 1] == '60s'
