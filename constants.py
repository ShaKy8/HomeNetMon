"""Constants shared across the runtime.

Only values that more than one module reads live here; per-service tunables stay
next to the service that uses them, and anything an operator may change is a
runtime Configuration row (Settings page) with a .env fallback (config.py).
"""

# Application metadata (keep APP_VERSION equal to version.py, pyproject.toml and package.json)
APP_NAME = "HomeNetMon"
APP_VERSION = "2.8.2"
APP_DESCRIPTION = "Home network monitoring dashboard"

import ipaddress

# Network defaults (config.py reads NETWORK_RANGE / PING_INTERVAL from the environment)
DEFAULT_NETWORK_RANGE = "192.168.86.0/24"
DEFAULT_PING_INTERVAL = 600  # seconds; gentle on home IoT devices

# Carrier-grade NAT range (RFC 6598), which Tailscale uses for tailnet addresses. Not
# routable on the internet, but CPython >= 3.12.4 no longer reports it as is_private,
# so the Socket.IO origin check and device-control target check name it explicitly.
CGNAT_NETWORK = ipaddress.ip_network('100.64.0.0/10')

# A device is considered down when it has not answered for this long. Must exceed the
# ping interval (600 s) plus a buffer; every status derivation and services/device_counts.py
# use this one value.
DEVICE_DOWN_AFTER_SECONDS = 900

# Alerting (monitoring/alerts.py; Settings reports the same defaults)
DEFAULT_DEVICE_DOWN_MINUTES = 45        # regular devices; critical ones alert at 15
DEFAULT_HIGH_LATENCY_MS = 1500
# Device.alert_on_down inherits this per device_type when unset (None). Phones, Apple
# devices and unidentified hosts sleep or rotate addresses; a "down" alert for them is
# noise, not news. Critical devices (Device.is_critical) always alert.
ALERT_ON_DOWN_BY_TYPE = {'phone': False, 'apple': False, 'unknown': False}
# Recoveries created this soon after AlertManager starts are recorded but not pushed:
# after a restart every device "recovers" in the first ping cycle.
ALERT_STARTUP_GRACE_SECONDS = 900

# Device status vocabulary (Device.status, dashboard filters, Socket.IO payloads)
DEVICE_STATUS_UP = "up"
DEVICE_STATUS_DOWN = "down"
DEVICE_STATUS_WARNING = "warning"
DEVICE_STATUS_UNKNOWN = "unknown"
