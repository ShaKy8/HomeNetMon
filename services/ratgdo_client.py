"""HTTP client for a ratgdo garage-door board running the ESPHome firmware.

A ratgdo (https://paulwieland.github.io/ratgdo/) is a small ESP board wired to
a Chamberlain / LiftMaster opener's wall-console terminals. With the ESPHome
firmware it exposes the standard ESPHome ``web_server`` on port 80: one JSON
document per entity (``GET /cover/door``), one POST per action
(``POST /cover/door/open``) and a Server-Sent-Events stream (``GET /events``)
that replays every entity on connect and pushes each change afterwards.

This module is the only place that knows those URLs. It has no Flask, database
or thread state: ``services/garage_monitor.py`` owns the loop and the rows.
Everything here uses ``requests`` with explicit timeouts and never raises
anything but ``RatgdoError`` (or ``ValueError`` from ``parse_host``).

myQ itself has no local or third-party API (Chamberlain blocks outside
clients), which is why the integration targets this board instead.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
from typing import Callable

import requests
from requests.auth import HTTPBasicAuth

from core.validators import is_lan_address

logger = logging.getLogger(__name__)

DOOR_STATES = ('closed', 'open', 'opening', 'closing', 'stopped', 'unknown')

# (domain, object_id) of every entity the stock esphome-ratgdo YAML exposes
# that the dashboard cares about. object_id = ESPHome name lowercased with
# spaces replaced by underscores ("Lock remotes" -> lock_remotes).
ENTITIES = (
    ('cover', 'door'),
    ('light', 'light'),
    ('lock', 'lock_remotes'),
    ('binary_sensor', 'obstruction'),
    ('binary_sensor', 'motion'),
    ('binary_sensor', 'motor'),
    ('sensor', 'openings'),
    ('text_sensor', 'firmware_version'),
)

DOOR_ACTIONS = ('open', 'close', 'stop', 'toggle')
LIGHT_ACTIONS = ('turn_on', 'turn_off', 'toggle')
LOCK_ACTIONS = ('lock', 'unlock')
BUTTONS = ('toggle_door', 'query_status', 'sync', 'restart')

_HOSTNAME_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*$', re.IGNORECASE)


class RatgdoError(Exception):
    """The board did not answer, or answered with an error status."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def empty_state() -> dict:
    """The normalised state document with nothing known yet (fixed key set)."""
    return {
        'door': 'unknown', 'position': None,
        'light': None, 'lock': None,
        'obstruction': None, 'motion': None, 'motor': None,
        'openings': None, 'firmware': None,
        'online': None, 'last_update': None,
        'board': {'host': None, 'name': None},
    }


def parse_host(value: str) -> tuple[str, int]:
    """Split ``"192.168.86.42"`` / ``"ratgdov25i-a1b2c3.local"`` / ``"host:8099"`` into (host, port).

    IP literals must be LAN addresses (RFC 1918, link-local or loopback -- the
    latter so a local simulator works); a public address is refused because the
    board is a LAN device and the API would otherwise be a proxy to the internet.
    Raises ValueError with a human-readable reason.
    """
    text = (value or '').strip()
    if not text:
        raise ValueError('host is empty')
    if '://' in text:
        raise ValueError('give a host or IP, not a URL')
    text = text.rstrip('/')
    port = 80
    host = text
    if text.count(':') == 1:
        host, port_text = text.split(':', 1)
        try:
            port = int(port_text)
        except ValueError:
            raise ValueError('port must be a number') from None
        if not 1 <= port <= 65535:
            raise ValueError('port must be between 1 and 65535')
    elif ':' in text:
        raise ValueError('IPv6 literals are not supported; use the board hostname')
    host = host.strip().lower()
    if not host:
        raise ValueError('host is empty')
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not _HOSTNAME_RE.match(host):
            raise ValueError('host must be an IP address or a hostname') from None
        return host, port
    if not is_lan_address(ip):
        raise ValueError('the ratgdo must be on the local network (private address)')
    return str(ip), port


def normalise_entity_id(raw: str) -> tuple[str, str]:
    """``"cover-door"`` -> ``("cover", "door")``; ``"cover/Door"`` (ESPHome >= 2026.8) -> the same.

    ESPHome changed the id format from ``domain-object_id`` to ``domain/Entity Name``;
    both are accepted so a firmware update on the board does not break parsing.
    """
    text = str(raw or '').strip()
    if '/' in text:
        domain, _, name = text.partition('/')
        if '/' in name:                       # domain/device_name/entity_name (sub-devices)
            name = name.rsplit('/', 1)[1]
    else:
        domain, _, name = text.partition('-')
    return domain.strip().lower(), re.sub(r'\s+', '_', name.strip()).lower()


def _truthy(entity: dict, on_value: str) -> bool | None:
    state = entity.get('state')
    if isinstance(state, str):
        return state.strip().upper() == on_value
    value = entity.get('value')
    return bool(value) if value is not None else None


def apply_entity(state: dict, entity: dict) -> dict:
    """Map one ESPHome entity document onto the normalised ``state`` in place.

    Pure apart from mutating ``state``; returns ``{key: new_value}`` for the keys
    that changed so callers can detect transitions. Unknown entities are ignored.
    """
    if not isinstance(entity, dict) or 'id' not in entity:
        return {}
    domain, object_id = normalise_entity_id(entity['id'])
    changes: dict = {}

    def put(key, value):
        if state.get(key) != value:
            state[key] = value
            changes[key] = value

    if domain == 'cover' and object_id == 'door':
        operation = str(entity.get('current_operation') or 'IDLE').upper()
        cover_state = str(entity.get('state') or '').upper()
        try:
            position = float(entity['value']) if entity.get('value') is not None else None
        except (TypeError, ValueError):
            position = None
        if operation == 'OPENING':
            door = 'opening'
        elif operation == 'CLOSING':
            door = 'closing'
        elif cover_state == 'CLOSED':
            door = 'closed'
        elif cover_state == 'OPEN':
            door = 'stopped' if position is not None and 0.02 < position < 0.98 else 'open'
        else:
            door = 'unknown'
        put('door', door)
        put('position', position)
    elif domain == 'light' and object_id == 'light':
        put('light', _truthy(entity, 'ON'))
    elif domain == 'lock' and object_id == 'lock_remotes':
        put('lock', _truthy(entity, 'LOCKED'))
    elif domain == 'binary_sensor' and object_id in ('obstruction', 'motion', 'motor'):
        put(object_id, _truthy(entity, 'ON'))
    elif domain == 'sensor' and object_id == 'openings':
        try:
            put('openings', int(float(entity.get('value'))))
        except (TypeError, ValueError):
            pass
    elif domain == 'text_sensor' and object_id == 'firmware_version':
        value = entity.get('state') if entity.get('state') is not None else entity.get('value')
        put('firmware', str(value) if value is not None else None)
    return changes


def _auth(username: str | None, password: str | None):
    return HTTPBasicAuth(username, password or '') if username else None


def probe(host: str, timeout: float = 2.0, auth: tuple | None = None) -> dict | None:
    """``GET http://host/cover/door``; the JSON when it is a cover entity, else None. Never raises."""
    try:
        name, port = parse_host(host)
    except ValueError:
        return None
    url = f'http://{name}:{port}/cover/door'
    try:
        response = requests.get(url, timeout=timeout, auth=_auth(*auth) if auth else None)
        if response.status_code != 200:
            return None
        data = response.json()
    except (requests.RequestException, ValueError) as e:
        logger.debug(f"ratgdo probe of {host} failed: {e}")
        return None
    if isinstance(data, dict) and str(data.get('id', '')).lower().startswith('cover'):
        return data
    return None


class RatgdoClient:
    """Blocking client for one board. Safe to share between threads for GET/POST
    (``requests.Session`` is thread-safe for simple use); ``events()`` should be
    called from exactly one thread because an ESP8266 serves very few SSE clients."""

    def __init__(self, host: str, username: str | None = None, password: str | None = None,
                 timeout: float = 3.0, session: requests.Session | None = None):
        name, port = parse_host(host)
        self.host = name
        self.port = port
        self.base_url = f'http://{name}:{port}'
        self.timeout = timeout
        self._auth = _auth(username, password)
        self._session = session or requests.Session()

    # ---- reads ----------------------------------------------------------------
    def get_entity(self, domain: str, object_id: str) -> dict | None:
        """One entity document, or None when the board answers but not with that entity."""
        url = f'{self.base_url}/{domain}/{object_id}'
        try:
            response = self._session.get(url, timeout=self.timeout, auth=self._auth)
        except requests.RequestException as e:
            raise RatgdoError(f'{self.host}: {e.__class__.__name__}') from e
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise RatgdoError(f'{self.host}: HTTP {response.status_code} for {domain}/{object_id}',
                              status=response.status_code)
        try:
            data = response.json()
        except ValueError as e:
            raise RatgdoError(f'{self.host}: {domain}/{object_id} is not JSON') from e
        return data if isinstance(data, dict) else None

    def snapshot(self) -> dict:
        """Every entity in ``ENTITIES`` folded into a fresh normalised state.

        The cover must answer (otherwise RatgdoError); the rest are best-effort so
        a board with a trimmed YAML still reports its door.
        """
        state = empty_state()
        for domain, object_id in ENTITIES:
            try:
                entity = self.get_entity(domain, object_id)
            except RatgdoError:
                if (domain, object_id) == ('cover', 'door'):
                    raise
                continue
            if entity is None:
                if (domain, object_id) == ('cover', 'door'):
                    raise RatgdoError(f'{self.host} has no cover/door entity (is this a ratgdo?)')
                continue
            apply_entity(state, entity)
        state['online'] = True
        state['board'] = {'host': self.host, 'name': None}
        return state

    # ---- writes ----------------------------------------------------------------
    def command(self, domain: str, object_id: str, action: str) -> None:
        url = f'{self.base_url}/{domain}/{object_id}/{action}'
        try:
            response = self._session.post(url, timeout=self.timeout, auth=self._auth)
        except requests.RequestException as e:
            raise RatgdoError(f'{self.host}: {e.__class__.__name__}') from e
        if not 200 <= response.status_code < 300:
            raise RatgdoError(f'{self.host}: HTTP {response.status_code} for {domain}/{object_id}/{action}',
                              status=response.status_code)

    def door(self, action: str) -> None:
        if action not in DOOR_ACTIONS:
            raise ValueError(f'door action must be one of {DOOR_ACTIONS}')
        self.command('cover', 'door', action)

    def light(self, action: str) -> None:
        if action not in LIGHT_ACTIONS:
            raise ValueError(f'light action must be one of {LIGHT_ACTIONS}')
        self.command('light', 'light', action)

    def lock(self, action: str) -> None:
        if action not in LOCK_ACTIONS:
            raise ValueError(f'lock action must be one of {LOCK_ACTIONS}')
        self.command('lock', 'lock_remotes', action)

    def press(self, button: str) -> None:
        if button not in BUTTONS:
            raise ValueError(f'button must be one of {BUTTONS}')
        self.command('button', button, 'press')

    # ---- server-sent events ----------------------------------------------------
    def events(self, stop: threading.Event, on_state: Callable[[dict], None],
               on_ping: Callable[[], None] | None = None) -> None:
        """One blocking read of ``/events`` until the stream ends, the read times out
        or ``stop`` is set. ``on_state`` gets each ``state`` event's JSON document.

        90 s without any line (ESPHome pings every few seconds) means the link is
        dead; the caller reconnects with backoff. Connection errors surface as
        RatgdoError so the caller can count them.
        """
        url = f'{self.base_url}/events'
        try:
            response = self._session.get(url, stream=True, timeout=(self.timeout, 90), auth=self._auth,
                                         headers={'Accept': 'text/event-stream'})
        except requests.RequestException as e:
            raise RatgdoError(f'{self.host}: {e.__class__.__name__}') from e
        if response.status_code != 200:
            response.close()
            raise RatgdoError(f'{self.host}: HTTP {response.status_code} for /events', status=response.status_code)
        event_name = ''
        data_lines: list[str] = []
        try:
            for line in response.iter_lines(decode_unicode=True):
                if stop.is_set():
                    break
                if line is None:
                    continue
                if line == '':
                    self._dispatch(event_name, data_lines, on_state, on_ping)
                    event_name, data_lines = '', []
                    continue
                if line.startswith(':'):
                    continue
                field, _, value = line.partition(':')
                value = value[1:] if value.startswith(' ') else value
                if field == 'event':
                    event_name = value.strip()
                elif field == 'data':
                    data_lines.append(value)
            if not stop.is_set() and (event_name or data_lines):
                self._dispatch(event_name, data_lines, on_state, on_ping)
        except requests.RequestException as e:
            raise RatgdoError(f'{self.host}: {e.__class__.__name__} while streaming') from e
        finally:
            response.close()

    @staticmethod
    def _dispatch(event_name, data_lines, on_state, on_ping):
        if event_name == 'ping':
            if on_ping:
                on_ping()
            return
        if event_name != 'state':
            return
        payload = '\n'.join(data_lines).strip()
        if not payload:
            return
        try:
            document = json.loads(payload)
        except ValueError:
            logger.debug(f"ratgdo: skipping malformed state event {payload[:80]!r}")
            return
        if isinstance(document, dict) and 'id' in document:
            on_state(document)
