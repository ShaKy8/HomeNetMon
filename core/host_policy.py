"""Which hosts and origins are "this server", and which outbound targets are safe.

One definition shared by three checks, so they cannot drift apart:
- the Host header of every request (stops DNS rebinding: a hostile page that rebinds its own
  name to this machine's address would otherwise become same-origin with the whole API);
- the Origin of a Socket.IO connection;
- webhook URLs the server is asked to call.

Accepted names: loopback, private / link-local / CGNAT (Tailscale) addresses, bare,
``.local``, ``.lan`` and ``.home.arpa`` names, this node's Tailscale MagicDNS name, the host of ``BASE_URL``, and
``ALLOWED_ORIGIN_HOSTS``. Public addresses and other names are refused.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from urllib.parse import urlparse

from config import Config
from constants import CGNAT_NETWORK

logger = logging.getLogger(__name__)

# One label, optionally under a suffix that is never delegated in public DNS (mDNS, router DNS, RFC 8375).
_LOCAL_NAME = re.compile(r'^[a-z0-9\-]+(\.(local|lan|home\.arpa))?$')


def _hostname(value: str) -> str | None:
    """Host part of a Host header value ("name:5000", "[::1]:5000", "1.2.3.4")."""
    try:
        return urlparse('//' + value.strip()).hostname if value else None
    except ValueError:
        return None


def host_allowed(host: str | None) -> bool:
    """True when ``host`` (a bare hostname or IP, no port) is one of this server's own names."""
    if not host:
        return False
    host = host.lower().rstrip('.')
    if host == 'localhost' or _LOCAL_NAME.match(host):
        return True
    if host in Config.ALLOWED_ORIGIN_HOSTS or host == (urlparse(Config.BASE_URL).hostname or '').lower():
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Not an IP: only this node's own Tailscale name. Not *.ts.net wholesale, those names
        # resolve publicly and any tailnet could host a rebinding page under one.
        from services import tailscale
        return host in tailscale.own_hostnames()
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip in CGNAT_NETWORK:
        return True
    try:
        return ip in ipaddress.ip_network(Config.NETWORK_RANGE, strict=False)
    except ValueError:
        return False


def host_header_allowed(request_host: str | None) -> bool:
    return host_allowed(_hostname(request_host or ''))


def origin_allowed(origin: str | None) -> bool:
    """Socket.IO origin check: http(s) scheme and an allowed host (the port is not inspected)."""
    if not origin:
        return False
    try:
        parsed = urlparse(origin)
        host = parsed.hostname
    except ValueError:
        return False
    return parsed.scheme in ('http', 'https') and host_allowed(host)


def outbound_url_problem(url: str, resolve=socket.getaddrinfo) -> str | None:
    """Why the server must not POST to ``url``, or None when it may.

    Webhooks legitimately point at LAN services (Home Assistant), so private addresses pass.
    Loopback, link-local and unspecified targets do not: they are this machine's own
    services (and cloud metadata endpoints), reachable by nothing a webhook should touch.
    Names are resolved and every address checked."""
    try:
        parsed = urlparse(str(url).strip())
        host = parsed.hostname
    except ValueError:
        return 'not a valid URL'
    if parsed.scheme not in ('http', 'https') or not host:
        return 'must be an http(s) URL with a host'
    if host.lower() == 'localhost':
        return 'must not point at this machine'
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(info[4][0].split('%')[0]) for info in resolve(host, None)]
        except (OSError, ValueError):
            return 'host does not resolve'
    for ip in addresses:
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            return 'must not point at this machine or a link-local address'
    return None
