"""Unicast mDNS probe: ask a single host what it calls itself and which
services it advertises. Randomized MACs make OUI lookup useless for a growing
share of devices, but most phones, TVs, speakers, printers and cameras answer
these two queries directly on port 5353.
"""

from __future__ import annotations

import logging
import socket

logger = logging.getLogger(__name__)

try:
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:  # pragma: no cover - dnspython is a runtime requirement
    DNS_AVAILABLE = False

SERVICE_ENUM = '_services._dns-sd._udp.local.'
MAX_SERVICES = 12


def _query(ip: str, qname: str, rdtype, timeout: float):
    message = dns.message.make_query(qname, rdtype)
    return dns.query.udp(message, ip, port=5353, timeout=timeout, ignore_unexpected=True)


def _names(response, rdtype) -> list[str]:
    names = []
    for section in (response.answer, response.additional):
        for rrset in section:
            if rrset.rdtype != rdtype:
                continue
            for item in rrset:
                text = str(item.target if hasattr(item, 'target') else item).rstrip('.')
                if text and text not in names:
                    names.append(text)
    return names


def query_mdns(ip: str, timeout: float = 0.5) -> dict:
    """Return {'hostname': str | None, 'services': [str, ...]}; never raises."""
    result = {'hostname': None, 'services': []}
    if not DNS_AVAILABLE or not ip:
        return result
    try:
        rev = _query(ip, dns.reversename.from_address(ip), dns.rdatatype.PTR, timeout)
        names = _names(rev, dns.rdatatype.PTR)
        if names:
            result['hostname'] = names[0]
    except (OSError, socket.timeout, Exception) as e:
        logger.debug(f"mDNS reverse lookup for {ip} failed: {e}")
    try:
        enum = _query(ip, SERVICE_ENUM, dns.rdatatype.PTR, timeout)
        services = [n for n in _names(enum, dns.rdatatype.PTR) if n.startswith('_')]
        result['services'] = services[:MAX_SERVICES]
    except (OSError, socket.timeout, Exception) as e:
        logger.debug(f"mDNS service enumeration for {ip} failed: {e}")
    return result


def read_dhcp_leases(path: str) -> dict[str, str]:
    """MAC -> hostname from a dnsmasq / Pi-hole leases file (``expiry mac ip name clientid``)."""
    leases: dict[str, str] = {}
    if not path:
        return leases
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and ':' in parts[1] and parts[3] not in ('*', ''):
                    leases[parts[1].lower()] = parts[3]
    except OSError as e:
        logger.debug(f"DHCP leases file {path} unreadable: {e}")
    return leases
