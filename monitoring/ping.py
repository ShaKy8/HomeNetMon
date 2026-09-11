"""One ICMP echo via the system ``ping`` binary (works without CAP_NET_RAW).

Shared by DeviceMonitor (LAN devices) and WanMonitor (gateway / internet target).
"""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess

logger = logging.getLogger(__name__)

_TIME_RE = re.compile(r'time[=<]([0-9.]+)\s*ms')


def ping_host(ip_address: str, timeout: float = 2.0) -> float | None:
    """Return the round-trip time in ms (0.0 when ping answered but printed no time),
    or None when the host did not answer within ``timeout`` seconds."""
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        logger.warning(f"ping_host: invalid address {ip_address!r}")
        return None
    wait = max(1, round(timeout))
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', str(wait), ip_address],
            capture_output=True, text=True, timeout=timeout + 2, shell=False,
        )
    except subprocess.TimeoutExpired:
        return None
    except OSError as e:
        logger.error(f"ping_host: cannot run ping: {e}")
        return None
    if result.returncode != 0:
        return None
    match = _TIME_RE.search(result.stdout)
    return float(match.group(1)) if match else 0.0
