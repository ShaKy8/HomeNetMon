#!/usr/bin/python3
"""Outside watchdog for HomeNetMon: tells you (ntfy push) when it is down.

Why this exists: HomeNetMon cannot report its own death. On 2026-09-29 an OS upgrade removed
Python 3.12, the venv stopped importing, systemd crash-looped the service for 44 hours, and
nothing spoke up because the monitor lives inside the thing that failed.

Rules this file keeps, on purpose:
- It runs on the SYSTEM python (/usr/bin/python3) and imports only the standard library, so a
  broken venv, a broken dependency or a broken app cannot silence it. A test enforces this.
- It never writes the application database (it only reads the ntfy settings, read-only).
- It never restarts anything. It tells you; you decide.

Run once a minute by systemd/homenetmon-watchdog.timer. Manual use:

    /usr/bin/python3 scripts/ops/homenetmon_watchdog.py --status
    /usr/bin/python3 scripts/ops/homenetmon_watchdog.py --test          # send a test push
    /usr/bin/python3 scripts/ops/homenetmon_watchdog.py --pause 30      # planned maintenance
    /usr/bin/python3 scripts/ops/homenetmon_watchdog.py --resume

Settings (environment, normally from .env via the unit's EnvironmentFile):
    PORT                      app port (default 5000)
    DATABASE_URL              sqlite:///... path of the app database (for the ntfy topic)
    NTFY_TOPIC, NTFY_SERVER, NTFY_USERNAME, NTFY_PASSWORD, NTFY_ENABLED   used when the database has no topic
    BASE_URL                  opened when you tap the push
    WATCHDOG_FAIL_THRESHOLD   consecutive failed checks before alerting (default 3 = about 3 minutes)
    WATCHDOG_REMINDER_HOURS   repeat the alert this often while still down (default 6)
    WATCHDOG_HEARTBEAT_URL    optional healthchecks.io-style URL, pinged while healthy (see docs/OPERATIONS_GUIDE.md)
    WATCHDOG_STATE_DIR        default ~/.local/state/homenetmon-watchdog
    WATCHDOG_UNIT             systemd user unit to describe in alerts (default homenetmon)
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_PORT = 5000
DEFAULT_THRESHOLD = 3          # consecutive failed 1-minute checks before the first alert
DEFAULT_REMINDER_HOURS = 6
GAP_SECONDS = 10 * 60          # no check for this long = the host was off, suspended or frozen
GAP_NOTICE_RETRY_SECONDS = 3600
PROBE_TIMEOUT = 10
DEFAULT_NTFY_SERVER = 'https://ntfy.sh'

OK, DEGRADED, DOWN = 'ok', 'degraded', 'down'


# ---- settings and paths ---------------------------------------------------------------------

def _int(value, default, minimum=1):
    try:
        return max(minimum, int(value))
    except (TypeError, ValueError):
        return default


def state_dir(env=None) -> Path:
    """Where the state file lives. core/watchdog_status.py resolves the same path (a test pins it)."""
    env = os.environ if env is None else env
    explicit = env.get('WATCHDOG_STATE_DIR')
    if explicit:
        return Path(explicit)
    base = env.get('XDG_STATE_HOME') or str(Path.home() / '.local' / 'state')
    return Path(base) / 'homenetmon-watchdog'


def database_path(env) -> Path | None:
    url = env.get('DATABASE_URL') or ''
    if not url.startswith('sqlite:///') or ':memory:' in url:
        return None if url else REPO_ROOT / 'homeNetMon.db'
    path = url[len('sqlite:///'):]
    return Path(path) if path.startswith('/') else REPO_ROOT / path


def load_settings(env=None) -> dict:
    env = dict(os.environ if env is None else env)
    return {
        'port': _int(env.get('PORT'), DEFAULT_PORT),
        'threshold': _int(env.get('WATCHDOG_FAIL_THRESHOLD'), DEFAULT_THRESHOLD),
        'reminder_seconds': _int(env.get('WATCHDOG_REMINDER_HOURS'), DEFAULT_REMINDER_HOURS) * 3600,
        'heartbeat_url': (env.get('WATCHDOG_HEARTBEAT_URL') or '').strip(),
        'base_url': (env.get('BASE_URL') or '').strip(),
        'unit': env.get('WATCHDOG_UNIT') or 'homenetmon',
        'state_dir': state_dir(env),
        'db_path': database_path(env),
        'env': env,
    }


# ---- state ----------------------------------------------------------------------------------

def load_state(directory: Path) -> dict:
    try:
        data = json.loads((directory / 'state.json').read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(directory: Path, state: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    tmp = directory / 'state.json.tmp'
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
    os.replace(tmp, directory / 'state.json')


@contextlib.contextmanager
def locked(directory: Path):
    """Serialise the timer run and the --pause/--resume CLI so neither loses the other's write."""
    directory.mkdir(parents=True, exist_ok=True)
    with open(directory / 'lock', 'w') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


# ---- probing --------------------------------------------------------------------------------

_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def probe(url: str, timeout: float = PROBE_TIMEOUT) -> dict:
    """GET url without proxies. Never raises: {'status': int|None, 'body': dict|None, 'error': str|None}."""
    try:
        with _LOCAL_OPENER.open(url, timeout=timeout) as response:
            return {'status': response.status, 'body': _json(response.read()), 'error': None}
    except urllib.error.HTTPError as e:
        try:
            body = _json(e.read())
        except OSError:
            body = None
        return {'status': e.code, 'body': body, 'error': f'HTTP {e.code}'}
    except urllib.error.URLError as e:
        return {'status': None, 'body': None, 'error': _reason(e.reason)}
    except (OSError, ValueError) as e:
        return {'status': None, 'body': None, 'error': _reason(e)}


def _json(raw: bytes):
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except ValueError:
        return None


def _reason(reason) -> str:
    text = str(reason)
    if isinstance(reason, ConnectionRefusedError) or 'refused' in text.lower():
        return 'connection refused'
    if isinstance(reason, (TimeoutError, socket.timeout)) or 'timed out' in text.lower():
        return 'timed out'
    return text or type(reason).__name__


def lan_ip() -> str | None:
    """Primary LAN address (no packets are sent); None when it cannot be told."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
    except OSError:
        return None
    return None if ip.startswith('127.') else ip


def evaluate(settings: dict, http=probe, get_lan_ip=lan_ip) -> tuple[str, str]:
    """(kind, detail). ok / degraded (503: a background thread is stale) / down.

    Healthy on 127.0.0.1 is not enough: the app listening on loopback only (HOST=127.0.0.1) is
    invisible to the LAN, so the LAN address is probed too. That catches a wrong bind address.
    It does not catch a firewall, because traffic to our own LAN address travels over lo."""
    port = settings['port']
    path = '/api/system/health'
    local = http(f'http://127.0.0.1:{port}{path}')
    status = local['status']
    if status == 200:
        ip = get_lan_ip()
        if ip:
            lan = http(f'http://{ip}:{port}{path}')
            if lan['status'] is None:
                return DOWN, f'answers on 127.0.0.1 but not on {ip}:{port} ({lan["error"]}); check the bind address (HOST)'
        return OK, ''
    if status == 503:
        stale = (local['body'] or {}).get('stale_threads') or []
        return DEGRADED, ('background threads are stale: ' + ', '.join(map(str, stale))) if stale else 'health check reports degraded'
    if status is None:
        return DOWN, f'no answer on 127.0.0.1:{port} ({local["error"]})'
    return DOWN, f'127.0.0.1:{port} answered HTTP {status}'


# ---- diagnostics ----------------------------------------------------------------------------

def _run(args, timeout=5) -> str:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


def diagnose(unit: str, run=_run) -> str:
    """A few lines about the service for the push body. Best effort; empty when systemd is unreachable."""
    shown = {}
    for line in run(['systemctl', '--user', 'show', unit, '-p', 'ActiveState', '-p', 'SubState',
                     '-p', 'Result', '-p', 'NRestarts']).splitlines():
        key, _, value = line.partition('=')
        shown[key] = value
    lines = []
    active, sub, result = shown.get('ActiveState'), shown.get('SubState'), shown.get('Result')
    if active:
        if active == 'inactive' and result == 'success':
            lines.append(f'Service is stopped (start it with: systemctl --user start {unit}).')
        else:
            restarts = shown.get('NRestarts')
            extra = f', {restarts} restarts' if restarts not in (None, '', '0') else ''
            lines.append(f'Service: {active} ({sub}), result {result}{extra}.')
    journal = [ln.strip() for ln in run(['journalctl', '--user', '-u', unit, '-n', '60', '-o', 'cat', '--no-pager']).splitlines()
               if ln.strip()]
    errors = [ln for ln in journal if re.search(r'Error|Exception|Traceback', ln)]
    last = (errors or journal or [''])[-1]
    if last:
        lines.append('Last log line: ' + last[:200])
    return '\n'.join(lines)


# ---- notifications --------------------------------------------------------------------------

def resolve_ntfy(settings: dict, state: dict) -> dict | None:
    """{'server','topic','enabled','username','password'} from the app database, else .env, else the
    value remembered from the last good run (so a broken database cannot silence an alert)."""
    env = settings['env']
    found = None
    db_path = settings['db_path']
    if db_path is not None:
        try:
            conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True, timeout=3)
            try:
                rows = dict(conn.execute("select key, value from configuration where key in "
                                         "('ntfy_server', 'ntfy_topic', 'push_notifications_enabled')").fetchall())
            finally:
                conn.close()
            if rows.get('ntfy_topic'):
                found = {'server': rows.get('ntfy_server') or DEFAULT_NTFY_SERVER, 'topic': rows['ntfy_topic'],
                         'enabled': str(rows.get('push_notifications_enabled', 'false')).lower() == 'true'}
        except (sqlite3.Error, OSError):
            pass
    if found is None and env.get('NTFY_TOPIC'):
        found = {'server': env.get('NTFY_SERVER') or DEFAULT_NTFY_SERVER, 'topic': env['NTFY_TOPIC'],
                 'enabled': str(env.get('NTFY_ENABLED', 'false')).lower() == 'true'}
    if found is None:
        cached = state.get('ntfy')
        return dict(cached, username=env.get('NTFY_USERNAME'), password=env.get('NTFY_PASSWORD')) if cached else None
    state['ntfy'] = dict(found)
    found['username'] = env.get('NTFY_USERNAME')
    found['password'] = env.get('NTFY_PASSWORD')
    return found


def send_ntfy(ntfy: dict, title: str, message: str, priority: int, tags: list[str], click: str = '',
              opener=urllib.request.urlopen) -> bool:
    """Publish as JSON (no header-encoding limits, so titles may carry any character)."""
    payload = {'topic': ntfy['topic'], 'title': title, 'message': message, 'priority': priority, 'tags': tags}
    if click:
        payload['click'] = click
    headers = {'Content-Type': 'application/json'}
    if ntfy.get('username') and ntfy.get('password'):
        token = base64.b64encode(f"{ntfy['username']}:{ntfy['password']}".encode()).decode()
        headers['Authorization'] = f'Basic {token}'
    request = urllib.request.Request(ntfy['server'].rstrip('/') + '/', data=json.dumps(payload).encode(), headers=headers)
    try:
        with opener(request, timeout=10) as response:
            return 200 <= response.status < 300
    except (OSError, ValueError) as e:
        print(f'watchdog: push failed: {e}', file=sys.stderr)
        return False


def ping_heartbeat(url: str, suffix: str = '', opener=urllib.request.urlopen) -> bool:
    """healthchecks.io-style ping. Failures are ignored: the service on the other end notices silence."""
    if not url:
        return False
    try:
        with opener(url.rstrip('/') + suffix, timeout=10):
            return True
    except (OSError, ValueError):
        return False


def human_duration(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes < 1:
        return 'under a minute'
    if minutes < 60:
        return f'{minutes} min'
    hours, minutes = divmod(minutes, 60)
    return f'{hours} h {minutes:02d} min'


# ---- the check ------------------------------------------------------------------------------

class Deps:
    """Everything with side effects, replaceable in tests."""

    def __init__(self, http=probe, get_lan_ip=lan_ip, diagnose=diagnose, send=send_ntfy, heartbeat=ping_heartbeat):
        self.http, self.get_lan_ip, self.diagnose, self.send, self.heartbeat = http, get_lan_ip, diagnose, send, heartbeat


def _notify(settings, state, deps, title, message, priority, tags) -> bool:
    ntfy = resolve_ntfy(settings, state)
    if ntfy is None or not ntfy.get('enabled'):
        print('watchdog: no ntfy channel (push disabled or no topic); not sending: ' + title, file=sys.stderr)
        return False
    return deps.send(ntfy, 'HomeNetMon watchdog: ' + title, message, priority, tags, settings['base_url'])


def run_check(settings: dict, now: float, deps: Deps | None = None) -> int:
    """One check. Returns 0, or 1 when a push that was due could not be delivered."""
    deps = deps or Deps()
    directory = settings['state_dir']
    with locked(directory):
        state = load_state(directory)
        failed_push = False
        paused = state.get('paused_until', 0) > now
        first_run = 'last_run' not in state

        # The host (or this timer) was not running: say so once, retrying for an hour if the network is not back yet.
        if not first_run and now - state['last_run'] > GAP_SECONDS:
            state['gap_notice'] = {'seconds': now - state['last_run'], 'at': now}
        state['last_run'] = now
        gap = state.get('gap_notice')
        if gap and not paused:
            if now - gap['at'] > GAP_NOTICE_RETRY_SECONDS:
                state.pop('gap_notice')
            elif _notify(settings, state, deps, 'checks were interrupted',
                         f'No checks ran for {human_duration(gap["seconds"])}: this machine was off, suspended or frozen '
                         f'(or the watchdog timer was stopped).', 2, ['zzz']):
                state.pop('gap_notice')

        kind, detail = evaluate(settings, deps.http, deps.get_lan_ip)

        if kind == OK:
            if state.get('alerted'):
                length = human_duration(now - state.get('down_since', now))
                if _notify(settings, state, deps, 'BACK', f'HomeNetMon is healthy again after {length}.', 3,
                           ['white_check_mark']):
                    _reset(state)
                else:
                    failed_push = True
            else:
                _reset(state)
            deps.heartbeat(settings['heartbeat_url'])      # healthy: the external service sees us alive
        else:
            if not state.get('fails'):
                state['down_since'] = now
            state['fails'] = state.get('fails', 0) + 1
            state['kind'] = kind
            state['detail'] = detail
            if state['fails'] >= settings['threshold'] and not paused:
                due_first = state.get('alerted_kind') != kind          # first alert, or degraded turned into down
                due_reminder = state.get('alerted') and now - state.get('last_alert', 0) >= settings['reminder_seconds']
                if due_first or due_reminder:
                    length = human_duration(now - state['down_since'])
                    head = ('STILL ' if not due_first else '') + {'down': 'DOWN', 'degraded': 'DEGRADED'}[kind]
                    body = [f'{detail}.' if detail else '', f'Failing for {length}.' + (' (reminder)' if not due_first else '')]
                    extra = deps.diagnose(settings['unit'])
                    if extra:
                        body.append(extra)
                    delivered = _notify(settings, state, deps, head, '\n'.join(b for b in body if b),
                                        4, ['rotating_light'] if kind == DOWN else ['warning'])
                    if delivered:
                        state['alerted'] = True
                        state['alerted_kind'] = kind
                        state['last_alert'] = now
                        if kind == DOWN:
                            deps.heartbeat(settings['heartbeat_url'], '/fail')   # a second path if ntfy.sh itself is down
                    else:
                        failed_push = True
            if not (state.get('alerted') and state.get('kind') == DOWN):
                deps.heartbeat(settings['heartbeat_url'])      # the machine and this watchdog are alive

        save_state(directory, state)
        return 1 if failed_push else 0


def _reset(state: dict) -> None:
    for key in ('fails', 'kind', 'detail', 'down_since', 'alerted', 'alerted_kind', 'last_alert'):
        state.pop(key, None)


# ---- command line ---------------------------------------------------------------------------

def describe(state: dict, now: float) -> str:
    age = f'{int(now - state["last_run"])} s ago' if 'last_run' in state else 'never'
    paused = state.get('paused_until', 0)
    lines = [f'last check:  {age}',
             f'status:      {state.get("kind") or OK}' + (f' ({state.get("detail")})' if state.get('detail') else ''),
             f'failures:    {state.get("fails", 0)}',
             f'alerted:     {"yes, since " + human_duration(now - state["down_since"]) if state.get("alerted") else "no"}',
             f'paused:      {"until " + time.strftime("%H:%M:%S", time.localtime(paused)) if paused > now else "no"}']
    return '\n'.join(lines)


def main(argv=None, env=None, now=None, deps: Deps | None = None) -> int:
    parser = argparse.ArgumentParser(description='HomeNetMon outside watchdog')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--status', action='store_true', help='print the watchdog state')
    group.add_argument('--test', action='store_true', help='send a test push')
    group.add_argument('--pause', type=int, metavar='MINUTES', help='no alerts for MINUTES (planned maintenance)')
    group.add_argument('--resume', action='store_true', help='end a pause')
    args = parser.parse_args(argv)
    settings = load_settings(env)
    now = time.time() if now is None else now
    deps = deps or Deps()
    directory = settings['state_dir']

    if args.status:
        print(describe(load_state(directory), now))
        return 0
    if args.test:
        with locked(directory):
            state = load_state(directory)
            ok = _notify(settings, state, deps, 'test', 'This is a test push from the HomeNetMon watchdog.', 3,
                         ['white_check_mark'])
            save_state(directory, state)
        print('sent' if ok else 'NOT sent (see messages above)')
        return 0 if ok else 1
    if args.pause is not None or args.resume:
        with locked(directory):
            state = load_state(directory)
            if args.resume:
                state.pop('paused_until', None)
            else:
                state['paused_until'] = now + max(1, args.pause) * 60
            save_state(directory, state)
        print('resumed' if args.resume else f'paused for {args.pause} min')
        return 0
    return run_check(settings, now, deps)


if __name__ == '__main__':
    sys.exit(main())
