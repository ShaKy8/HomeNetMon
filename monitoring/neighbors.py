"""Presence from the kernel neighbour (ARP) table, via ``ip -4 neigh show``.

Phones, tablets and laptops stop answering ICMP while they sleep but keep answering
ARP, and sending anything to an on-link address (the ping itself) makes the kernel
resolve or re-confirm the neighbour entry. So after a failed ping the entry's state
says whether the host is there:

- REACHABLE: it answered ARP within the last reachable_time (15-45 s) -> present.
- FAILED: three unicast probes went unanswered -> absent.
- STALE / DELAY / PROBE / INCOMPLETE: undecided; poll a little longer.

No raw sockets and no root are needed, which is why this is not ``arping``.
"""

import logging
import re
import subprocess
import time

logger = logging.getLogger(__name__)

PRESENT = frozenset({'REACHABLE', 'PERMANENT', 'NOARP'})
ABSENT = frozenset({'FAILED'})
CONFIRM_WAIT = 12.0      # delay_first_probe_time (5 s) + ucast_solicit (3) * retrans (1 s) + slack
CONFIRM_INTERVAL = 0.5

_LINE = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?:dev\s+(?P<dev>\S+)\s+)?(?:lladdr\s+(?P<mac>[0-9a-fA-F:]{17})\s+)?'
    r'(?:\S+\s+)*?(?P<state>[A-Z]+)\s*$'
)


def parse(output: str) -> dict[str, list[tuple[str | None, str]]]:
    """``{ip: [(mac, STATE), ...]}`` from ``ip -4 neigh show`` text (one IP can sit on
    several interfaces, hence the list)."""
    table: dict[str, list[tuple[str | None, str]]] = {}
    for line in (output or '').splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        mac = (m.group('mac') or '').lower() or None
        table.setdefault(m.group('ip'), []).append((mac, m.group('state')))
    return table


def _show(*args: str) -> str:
    return subprocess.run(['ip', '-4', 'neigh', 'show', *args], capture_output=True, text=True, timeout=3).stdout


def table() -> dict[str, list[tuple[str | None, str]]]:
    """The whole neighbour table; raises OSError / TimeoutExpired when ``ip`` is unusable."""
    return parse(_show())


def present_hosts() -> dict[str, str]:
    """``{ip: mac}`` for every neighbour the kernel has confirmed (REACHABLE). STALE entries
    can be hours old and are not evidence that the host is still there."""
    hosts = {}
    for ip, entries in table().items():
        for mac, state in entries:
            if mac and state in PRESENT:
                hosts[ip] = mac
                break
    return hosts


def state(ip: str) -> str | None:
    """Best neighbour state for ``ip``: PRESENT beats ABSENT beats undecided; None when
    there is no entry."""
    states = [s for _, s in parse(_show(ip)).get(ip, [])]
    if not states:
        return None
    for group in (PRESENT, ABSENT):
        for s in states:
            if s in group:
                return s
    return states[0]


def confirm_presence(ip: str, wait: float | None = None, interval: float = CONFIRM_INTERVAL,
                     sleep=time.sleep, clock=time.monotonic) -> bool:
    """Call right after a ping to ``ip`` failed. True once the entry is REACHABLE, False
    once it is FAILED, False if the kernel has not decided within ``wait`` seconds
    (default CONFIRM_WAIT, read at call time so tests can shorten it), False when
    ``ip`` cannot be run, and False at once when no entry appears at all: a ping to an
    on-link address always creates one, so a missing entry means the address is routed
    and ARP cannot say anything about it."""
    deadline = clock() + (CONFIRM_WAIT if wait is None else wait)
    missing = 0
    while True:
        try:
            current = state(ip)
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.debug(f"neighbour lookup for {ip} failed: {e}")
            return False
        if current in PRESENT:
            return True
        if current in ABSENT:
            return False
        missing = missing + 1 if current is None else 0
        if missing >= 2 or clock() >= deadline:
            return False
        sleep(interval)
