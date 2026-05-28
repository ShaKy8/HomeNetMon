"""Thread-heartbeat watchdog.

Background services call ``record_heartbeat(name)`` once per loop iteration.
The ``/api/system/health`` endpoint and the optional self-alert in
``services.resource_monitor`` use ``check()`` to see whether any thread
has gone silent past its expected cadence.

A "stale" thread is one that hasn't recorded a heartbeat within
``MAX_AGE_MULTIPLIER`` x its declared interval — long enough that we're
confident the thread crashed or wedged, not just took a slightly slow
iteration.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

# Map of thread name -> expected seconds between heartbeats.
# Only list threads whose loops actually call ``record_heartbeat`` — listing
# something here without an instrumented loop will silently never alert (the
# code treats "no heartbeat yet" as start-up grace), so a missing entry is
# the safer default. To add a new thread to the watchdog:
#   1. Add `from core.health import record_heartbeat` at the top of the loop
#   2. Call `record_heartbeat('YourThreadName')` once per iteration
#   3. Add the name + interval here
EXPECTED_THREADS: dict[str, int] = {
    'NetworkScanner':     86400,   # daily nmap sweep (Config.SCAN_INTERVAL)
    'DeviceMonitor':      600,     # ping cycle (Config.PING_INTERVAL)
    'AlertManager':       600,     # 10-min alert check (monitoring/alerts.py:727)
    'BandwidthMonitor':   300,     # Config.BANDWIDTH_INTERVAL
    'PerformanceMonitor': 300,     # collection_interval default
    'ResourceMonitor':    300,     # _monitor_loop wait
}

# A thread is "stale" once its last heartbeat is older than
# MAX_AGE_MULTIPLIER x its expected interval. Two cycles of grace
# accommodates a genuinely slow iteration without false-flagging.
MAX_AGE_MULTIPLIER = 2.5

_heartbeats: dict[str, float] = {}
_lock = threading.RLock()


def record_heartbeat(name: str) -> None:
    """Mark `name` as alive right now. Cheap; safe to call from any thread."""
    with _lock:
        _heartbeats[name] = time.time()


def get_heartbeats() -> dict[str, float]:
    """Snapshot of all recorded heartbeats (name -> unix timestamp)."""
    with _lock:
        return dict(_heartbeats)


def check() -> dict[str, Any]:
    """Return overall thread health.

    Shape::

        {
          "healthy": bool,
          "stale": [list of stuck thread names],
          "threads": {name: {"alive": bool, "last_heartbeat_ago_s": float | None,
                              "expected_interval_s": int | None, "stale": bool}, ...}
        }

    "alive" means the OS thread is currently in ``threading.enumerate()``.
    "stale" means the thread is alive but hasn't checked in within budget.
    """
    now = time.time()
    live_names = {t.name for t in threading.enumerate()}
    snapshot = get_heartbeats()

    threads: dict[str, dict[str, Any]] = {}
    stale: list[str] = []

    for name, interval in EXPECTED_THREADS.items():
        last = snapshot.get(name)
        last_ago: float | None = (now - last) if last is not None else None
        alive = name in live_names
        is_stale = False

        if not alive:
            is_stale = True  # crashed or never started
        elif last is None:
            # Thread is alive but hasn't recorded a heartbeat yet. Give it
            # the same budget as one full interval (start-up grace).
            pass
        elif last_ago is not None and last_ago > interval * MAX_AGE_MULTIPLIER:
            is_stale = True

        threads[name] = {
            'alive': alive,
            'last_heartbeat_ago_s': last_ago,
            'expected_interval_s': interval,
            'stale': is_stale,
        }
        if is_stale:
            stale.append(name)

    return {
        'healthy': not stale,
        'stale': stale,
        'threads': threads,
    }
