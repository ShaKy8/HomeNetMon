"""Read-only view of this host's Tailscale node (``tailscale status --json``).

HomeNetMon does not monitor the tailnet. This module exists so the Socket.IO origin
check can accept the node's own MagicDNS name and so the About page can show the
remote-access URL and which peers are online. No thread, no table, no alerts.

The CLI is used rather than ``/var/lib/tailscale``: the daemon's state file is
root-only, while its socket answers the configured operator user.
"""

import json
import logging
import subprocess
import threading
import time
from urllib.parse import urlparse

from config import Config

logger = logging.getLogger(__name__)

CACHE_SECONDS = 30
COMMAND = ['tailscale', 'status', '--json']

_lock = threading.Lock()
_cache: tuple[dict | None, float] = (None, 0.0)
_error: str | None = None
NOT_INSTALLED = 'not_installed'


def _fetch() -> dict | None:
    global _error
    try:
        proc = subprocess.run(COMMAND, capture_output=True, text=True, timeout=3)
    except FileNotFoundError:
        _error = NOT_INSTALLED
        return None
    except (OSError, subprocess.TimeoutExpired) as e:
        _error = type(e).__name__
        logger.debug(f"tailscale status failed: {e}")
        return None
    if proc.returncode != 0:
        _error = (proc.stderr or '').strip().splitlines()[-1:] or [f'exit {proc.returncode}']
        _error = _error[0]
        logger.debug(f"tailscale status exited {proc.returncode}: {_error}")
        return None
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        _error = 'unparsable output'
        return None
    if not isinstance(data, dict):
        _error = 'unparsable output'
        return None
    _error = None
    return data


def status(max_age: float = CACHE_SECONDS) -> dict | None:
    """Parsed ``tailscale status --json``, or None when Tailscale is missing, stopped or
    unreadable. Cached for ``max_age`` seconds so origin checks and page loads never cost
    more than one subprocess per interval, and a tailscaled that starts after the app is
    picked up on the next miss."""
    global _cache
    with _lock:
        cached, at = _cache
        if at and time.monotonic() - at < max_age:
            return cached
        cached = _fetch()
        _cache = (cached, time.monotonic())
        return cached


def reset_cache():
    global _cache, _error
    with _lock:
        _cache = (None, 0.0)
        _error = None


def _strip_dot(name) -> str | None:
    name = (name or '').strip().rstrip('.')
    return name or None


def _last_seen(value) -> str | None:
    # Online peers report the zero time "0001-01-01T00:00:00Z".
    if not value or str(value).startswith('0001-'):
        return None
    return value


def _peer(p: dict) -> dict:
    dns_name = _strip_dot(p.get('DNSName'))
    hostname = (p.get('HostName') or '').strip()
    if hostname in ('', 'localhost') and dns_name:
        # iOS/iPadOS nodes report HostName "localhost"; the MagicDNS label is the real name.
        hostname = dns_name.split('.')[0]
    return {
        'hostname': hostname,
        'dns_name': dns_name,
        'ips': list(p.get('TailscaleIPs') or []),
        'os': p.get('OS') or '',
        'online': bool(p.get('Online')),
        'last_seen': _last_seen(p.get('LastSeen')),
        'exit_node': bool(p.get('ExitNode')),
        # CurAddr is set on a direct WireGuard path; otherwise traffic goes through a DERP relay.
        'relay': 'direct' if p.get('CurAddr') else (p.get('Relay') or None),
        'rx_bytes': int(p.get('RxBytes') or 0),
        'tx_bytes': int(p.get('TxBytes') or 0),
    }


def own_hostnames() -> set[str]:
    """Lower-cased MagicDNS name(s) of this node; empty when Tailscale is unavailable."""
    data = status()
    if not data:
        return set()
    dns = _strip_dot((data.get('Self') or {}).get('DNSName'))
    return {dns.lower()} if dns else set()


def summary() -> dict:
    """What GET /api/system/tailscale returns."""
    data = status()
    if data is None:
        return {
            'installed': _error != NOT_INSTALLED,
            'running': False,
            'backend_state': None,
            'error': _error,
            'version': None,
            'magic_dns_suffix': None,
            'self': None,
            'peers': [],
            'online_peers': 0,
            'total_peers': 0,
        }
    self_node = data.get('Self') or {}
    dns = _strip_dot(self_node.get('DNSName'))
    peers = sorted((_peer(p) for p in (data.get('Peer') or {}).values() if isinstance(p, dict)),
                   key=lambda p: (not p['online'], p['hostname'].lower()))
    if dns and (urlparse(Config.BASE_URL).hostname or '').lower() == dns.lower():
        url = Config.BASE_URL
    elif dns:
        url = f"http://{dns}:{Config.PORT}"
    else:
        url = None
    return {
        'installed': True,
        'running': data.get('BackendState') == 'Running',
        'backend_state': data.get('BackendState'),
        'error': None,
        'version': (data.get('Version') or '').split('-')[0] or None,
        'magic_dns_suffix': data.get('MagicDNSSuffix') or None,
        'self': {
            'hostname': self_node.get('HostName') or '',
            'dns_name': dns,
            'ips': list(self_node.get('TailscaleIPs') or []),
            'online': bool(self_node.get('Online')),
            'os': self_node.get('OS') or '',
            'url': url,
        },
        'peers': peers,
        'online_peers': sum(1 for p in peers if p['online']),
        'total_peers': len(peers),
    }
