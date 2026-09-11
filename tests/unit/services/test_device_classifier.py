"""monitoring/device_classifier.py: types from mDNS services, hostnames and vendors.
Hostname patterns come from real unknown devices in the production database."""

import pytest

from monitoring.device_classifier import classify, is_locally_administered


@pytest.mark.parametrize('hostname,expected', [
    ('chromecast-ultra.lan', 'media'),
    ('ring-5c475e95741d.lan', 'camera'),
    ('sonoszp.lan', 'smart_home'),
    ('wyze_cakp2jfus-d03f278458f2.lan', 'camera'),
    ('npic2cfbe.lan', 'printer'),
    ('tl-sg1016de.lan', 'router'),
    ('kylinux.lan', 'computer'),
    ('kyles-mbp.lan', 'apple'),
    ('geekom1', 'computer'),
    ('espressif-3a2b', 'iot'),
    ('nintendoswitch', 'gaming'),
    ('galaxy-s23', 'phone'),
    ('synology-ds920', 'storage'),
    ('nest-thermostat', 'smart_home'),
    ('monitoring-host', 'unknown'),     # 'ring' inside 'monitoring' must not match
    ('apple-pie', 'unknown'),           # 'ap' inside 'apple' must not match router
    ('', 'unknown'),
])
def test_hostname_rules(hostname, expected):
    assert classify(hostname=hostname) == expected


@pytest.mark.parametrize('vendor,expected', [
    ('TexasIns', 'iot'), ('AltoBeam', 'media'), ('WyzeLabs', 'camera'), ('Sonos', 'smart_home'),
    ('Apple', 'apple'), ('Pegatron', 'computer'), ('Google', 'smart_home'), ('OrbitIrr', 'smart_home'),
])
def test_vendor_rules(vendor, expected):
    assert classify(vendor=vendor, mac='00:11:22:33:44:55') == expected


def test_vendor_is_ignored_for_randomized_macs():
    assert is_locally_administered('02:1b:e3:09:99:9e') is True
    assert is_locally_administered('00:1b:e3:09:99:9e') is False
    assert classify(vendor='MS-NLB-PhysServer-27', mac='02:1b:e3:09:99:9e') == 'unknown'


def test_mdns_services_win_over_hostname():
    assert classify(hostname='unknown-thing', services=['_googlecast._tcp.local']) == 'media'
    assert classify(hostname='kylinux', services=['_ipp._tcp.local']) == 'printer'
    assert classify(services=['_airplay._tcp.local', '_raop._tcp.local']) == 'apple'


def test_hostname_wins_over_vendor():
    assert classify(hostname='tl-sg1016de.lan', vendor='WyzeLabs', mac='00:11:22:33:44:55') == 'router'
