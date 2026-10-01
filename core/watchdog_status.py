"""Read-only view of the outside watchdog's state file (scripts/ops/homenetmon_watchdog.py).

The watchdog tells you when HomeNetMon is down; this module lets HomeNetMon notice when the
*watchdog* has stopped (timer disabled, python removed after an OS upgrade), which would
otherwise be the same silent failure again. It only reads a small JSON file and never raises.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

# A healthy watchdog checks every minute. Older than this and it has stopped.
STALE_AFTER_SECONDS = 15 * 60


def state_dir() -> Path:
    """Same resolution as scripts/ops/homenetmon_watchdog.py:state_dir (a test pins the two together)."""
    explicit = os.environ.get('WATCHDOG_STATE_DIR')
    if explicit:
        return Path(explicit)
    base = os.environ.get('XDG_STATE_HOME') or str(Path.home() / '.local' / 'state')
    return Path(base) / 'homenetmon-watchdog'


def read(now: float | None = None) -> dict:
    """{'installed': bool, 'last_check_age_s': int | None, 'state': 'ok'|'degraded'|'down'|None, 'paused': bool}

    installed is false when no state file exists (the watchdog was never run on this machine)."""
    now = time.time() if now is None else now
    try:
        data = json.loads((state_dir() / 'state.json').read_text())
        last_run = float(data['last_run'])
    except (OSError, ValueError, KeyError, TypeError):
        return {'installed': False, 'last_check_age_s': None, 'state': None, 'paused': False}
    return {
        'installed': True,
        'last_check_age_s': max(0, int(now - last_run)),
        'state': data.get('kind') or 'ok',
        'paused': float(data.get('paused_until') or 0) > now,
    }


def stale_age(now: float | None = None) -> int | None:
    """Seconds since the watchdog's last check when it is installed but silent; None when fine or absent."""
    status = read(now)
    age = status['last_check_age_s']
    return age if status['installed'] and age is not None and age > STALE_AFTER_SECONDS else None
