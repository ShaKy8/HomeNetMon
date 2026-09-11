"""One definition for every headline number the dashboard, the summary API,
the analytics health score and the Socket.IO summary push all report.

Before this module three endpoints answered "how many devices" three ways
(145 / 107 / 60) and "how many alerts" two ways (141 / 70).

- total_devices:     every Device row (the inventory; what /api/devices lists).
- monitored_devices: is_monitored, has an IP address, and that address lies inside
                     the runtime network range: exactly the set DeviceMonitor pings.
- devices_up:        monitored devices seen within constants.DEVICE_DOWN_AFTER_SECONDS.
- devices_down:      monitored_devices - devices_up.
- devices_unknown:   total_devices - monitored_devices (archived, no IP, or outside
                     the range).
- active_alerts:     unresolved alerts over all devices.

All functions must be called inside an app context.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta

from config import Config
from constants import DEVICE_DOWN_AFTER_SECONDS
from models import Alert, Configuration, Device


def current_network_range() -> str:
    """Runtime network range (Settings page) with the .env value as fallback."""
    value = Configuration.get_value('network_range')
    return value if value else Config.NETWORK_RANGE


def parse_network(network_range: str | None):
    try:
        return ipaddress.ip_network(network_range, strict=False)
    except (ValueError, TypeError):
        return None


def ip_in_range(ip_address: str | None, network) -> bool:
    """True when ``ip_address`` lies inside ``network``. An unparsable range
    disables the filter (every address counts) so a typo in Settings cannot
    silently stop all monitoring."""
    if not ip_address:
        return False
    if network is None:
        return True
    try:
        return ipaddress.ip_address(ip_address) in network
    except ValueError:
        return False


def monitored_devices(network_range: str | None = None) -> list[Device]:
    """The devices DeviceMonitor should ping: monitored, addressed, in range."""
    network = parse_network(network_range or current_network_range())
    candidates = Device.query.filter(Device.is_monitored == True, Device.ip_address.isnot(None)).all()
    return [d for d in candidates if ip_in_range(d.ip_address, network)]


def summarize() -> dict:
    total = Device.query.count()
    monitored = monitored_devices()
    threshold = datetime.utcnow() - timedelta(seconds=DEVICE_DOWN_AFTER_SECONDS)
    up = sum(1 for d in monitored if d.last_seen and d.last_seen >= threshold)
    return {
        'total_devices': total,
        'monitored_devices': len(monitored),
        'devices_up': up,
        'devices_down': len(monitored) - up,
        'devices_unknown': total - len(monitored),
        'active_alerts': Alert.query.filter_by(resolved=False).count(),
        'network_range': current_network_range(),
        'down_after_seconds': DEVICE_DOWN_AFTER_SECONDS,
    }
