"""Find a ratgdo board on the LAN without a network-wide mDNS browse.

``monitoring/mdns.py`` can only ask one host what it advertises, so discovery
starts from what the scanner already knows: ``devices`` rows whose hostname
looks like a ratgdo, whose mDNS list carries ``_esphomelib`` or whose MAC
vendor is Espressif. Each candidate is then confirmed with one 2 s HTTP probe
of ``/cover/door`` (``services.ratgdo_client.probe``). Bounded: at most 20
probes on 8 workers, so the Settings "Find ratgdo" button answers in seconds.

A board the scanner has not seen yet is not found -- the Settings page says
so and the Test button works with a typed host regardless.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from models import Device
from monitoring.mdns import query_mdns
from services import ratgdo_client as rc

logger = logging.getLogger(__name__)

MAX_PROBES = 20
WORKERS = 8
ESPHOME_SERVICE = '_esphomelib._tcp'
REASON_RANK = {'hostname': 0, 'mdns': 1, 'vendor': 2}


def candidates_from_db(current_host: str | None = None, limit: int = MAX_PROBES) -> list[dict]:
    """Devices worth probing, best evidence first, the configured host first of all."""
    current = (current_host or '').split(':')[0].strip().lower()
    found: list[dict] = []
    for device in Device.query.filter(Device.ip_address.isnot(None)).all():
        hostname = (device.hostname or '').lower()
        vendor = (device.vendor or '').lower()
        services = (device.mdns_services or '').lower()
        if 'ratgdo' in hostname or 'ratgdo' in (device.custom_name or '').lower():
            reason = 'hostname'
        elif ESPHOME_SERVICE in services:
            reason = 'mdns'
        elif 'espressif' in vendor:
            reason = 'vendor'
        else:
            continue
        found.append({'ip': device.ip_address, 'device_id': device.id, 'hostname': device.hostname,
                      'name': device.display_name, 'vendor': device.vendor, 'reason': reason,
                      'confirmed': False, 'door': None,
                      'current': bool(current) and current in (device.ip_address, hostname, hostname.split('.')[0])})
    found.sort(key=lambda c: (not c['current'], REASON_RANK[c['reason']], c['ip']))
    return found[:limit]


def confirm(candidate: dict, timeout: float = 2.0) -> dict:
    """Probe one candidate; returns it with ``confirmed``/``door`` filled in. Never raises."""
    result = dict(candidate)
    result.setdefault('confirmed', False)
    result.setdefault('door', None)
    document = rc.probe(candidate['ip'], timeout=timeout)
    if document is not None:
        result['confirmed'] = True
        scratch = rc.empty_state()
        rc.apply_entity(scratch, document)
        result['door'] = scratch['door']
        return result
    if candidate['reason'] == 'vendor':
        try:
            services = query_mdns(candidate['ip'], 0.5).get('services') or []
        except Exception:
            services = []
        if any(ESPHOME_SERVICE in s.lower() for s in services):
            result['reason'] = 'mdns'
    return result


def discover(max_probes: int = MAX_PROBES, current_host: str | None = None) -> dict:
    """``{'candidates': [...confirmed first...], 'probed': n}``; needs an app context for the query."""
    candidates = candidates_from_db(current_host, limit=max_probes)
    if not candidates:
        return {'candidates': [], 'probed': 0}
    with ThreadPoolExecutor(max_workers=min(WORKERS, len(candidates))) as pool:
        results = list(pool.map(confirm, candidates))
    results.sort(key=lambda c: (not c['confirmed'], not c['current'], REASON_RANK[c['reason']], c['ip']))
    return {'candidates': results, 'probed': len(results)}
