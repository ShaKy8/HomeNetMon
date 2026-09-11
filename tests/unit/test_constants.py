"""constants.py holds only values more than one runtime module reads."""

import ipaddress
import re

import constants


def test_version_matches_the_other_three_sources():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    pyproject = re.search(r'^version = "([^"]+)"', (root / 'pyproject.toml').read_text(), re.M).group(1)
    package = json.loads((root / 'package.json').read_text())['version']
    from version import VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH
    assert constants.APP_VERSION == pyproject == package == f'{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH}'


def test_network_defaults():
    ipaddress.ip_network(constants.DEFAULT_NETWORK_RANGE)
    assert constants.DEFAULT_PING_INTERVAL == 600


def test_down_threshold_exceeds_ping_interval():
    assert constants.DEVICE_DOWN_AFTER_SECONDS > constants.DEFAULT_PING_INTERVAL


def test_status_vocabulary():
    assert {constants.DEVICE_STATUS_UP, constants.DEVICE_STATUS_DOWN,
            constants.DEVICE_STATUS_WARNING, constants.DEVICE_STATUS_UNKNOWN} == {'up', 'down', 'warning', 'unknown'}


def test_nothing_else_is_exported():
    public = {n for n in dir(constants) if n.isupper()}
    assert public == {'APP_NAME', 'APP_VERSION', 'APP_DESCRIPTION', 'DEFAULT_NETWORK_RANGE', 'DEFAULT_PING_INTERVAL',
                      'DEVICE_DOWN_AFTER_SECONDS', 'DEVICE_STATUS_UP', 'DEVICE_STATUS_DOWN', 'DEVICE_STATUS_WARNING',
                      'DEVICE_STATUS_UNKNOWN'}
