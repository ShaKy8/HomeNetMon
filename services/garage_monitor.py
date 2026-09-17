"""Garage door monitor: keeps HomeNetMon in sync with a ratgdo board.

A ratgdo (ESPHome firmware) wired to the opener replaces the myQ cloud, which
has no third-party API. This service owns the connection to it:

* a ticker thread (``GarageMonitor`` in ``core.health.EXPECTED_THREADS``) that
  re-reads the ``garage_*`` runtime settings, polls the board every
  ``garage_poll_interval`` seconds (faster while the door moves without a live
  stream) and evaluates the alert timers every 30 s -- it runs and heartbeats
  even while the feature is disabled, so the watchdog needs no special case;
* one helper thread (``GarageEvents``) holding the board's single Server-Sent
  Events stream so door changes arrive within a second (an ESP8266 serves very
  few SSE clients, so there is never more than one);
* ``GarageEvent`` rows for every transition (door / light / lock / obstruction /
  online), attributed to ``dashboard`` when a HomeNetMon command preceded it;
* alerts through ``AlertManager.create_alert()`` on the board's ``Device`` row
  (``garage_left_open``, ``garage_quiet_hours_open``, ``garage_obstruction``,
  ``garage_offline``), resolved here when the condition clears;
* ``garage_status`` pushes to the ``updates_monitoring_summary`` room.

Quiet hours use the host's local clock (settings are entered as wall-clock
times); everything stored is UTC like the rest of the app.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import date, datetime, time as dtime, timedelta, timezone

from core.health import record_heartbeat
from models import Alert, Configuration, Device, GarageEvent, db
from services import ratgdo_client as rc

logger = logging.getLogger(__name__)

DEFAULTS = {
    'garage_enabled': 'false',
    'garage_host': '',
    'garage_username': '',
    'garage_password': '',
    'garage_left_open_minutes': 15,
    'garage_quiet_hours_start': '22:00',
    'garage_quiet_hours_end': '06:00',
    'garage_poll_interval': 60,
    'garage_offline_after_polls': 3,
}
TICK_SECONDS = 30                  # alert-timer / heartbeat cadence
MOVING_POLL_SECONDS = 5            # poll cadence while the door travels and no SSE stream is up
COMMAND_ATTRIBUTION_SECONDS = 20   # a change this soon after our command is "dashboard"
SSE_BACKOFF = (2, 4, 8, 16, 32, 60)
TRACKED_KEYS = ('door', 'position', 'light', 'lock', 'obstruction', 'motion', 'motor', 'openings', 'firmware')
DOOR_OPEN_STATES = ('open', 'opening', 'closing', 'stopped')
ALERT_SUBTYPE = 'garage'


class GarageNotConfigured(Exception):
    """The integration is disabled or has no reachable host configured."""


def _parse_clock(text: str) -> dtime | None:
    text = (text or '').strip()
    if not text:
        return None
    try:
        hour, minute = text.split(':', 1)
        return dtime(int(hour), int(minute))
    except (TypeError, ValueError):
        return None


def in_quiet_hours(now_time: dtime, start: str, end: str) -> bool:
    """True when ``now_time`` (local wall clock) falls inside start..end; the window may wrap midnight.

    Either side empty or malformed disables quiet hours; start == end disables too
    (a zero-length window, not a 24 h one).
    """
    start_t, end_t = _parse_clock(start), _parse_clock(end)
    if start_t is None or end_t is None or start_t == end_t:
        return False
    if start_t < end_t:
        return start_t <= now_time < end_t
    return now_time >= start_t or now_time < end_t


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + 'Z' if value else None


def _to_local(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc).astimezone()


class GarageMonitor:
    def __init__(self, app=None):
        self.app = app
        self.state = rc.empty_state()
        self.state.update(open_since=None, door_changed_at=None, sse_connected=False)
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._wake = threading.Event()
        self._client: rc.RatgdoClient | None = None
        self._client_key: tuple | None = None
        self._sse_thread: threading.Thread | None = None
        self._sse_stop = threading.Event()
        self._pending_command: tuple[str, float] | None = None
        self._offline_polls = 0
        self._last_poll = 0.0
        self._last_event: dict | None = None
        self.is_running = False

    # ---- configuration --------------------------------------------------------
    def setting(self, key, default=None):
        """Runtime value, or the default when no row exists. An empty row is a real
        value here (blank quiet hours or host mean "off"), unlike WanMonitor."""
        value = Configuration.get_value(key)
        if value is None:
            return DEFAULTS.get(key) if default is None else default
        return value

    def config(self) -> dict:
        """Typed, clamped view of the garage_* settings. Needs an app context."""
        def as_int(key, lo, hi):
            try:
                return max(lo, min(hi, int(self.setting(key))))
            except (TypeError, ValueError):
                return int(DEFAULTS[key])
        return {
            'enabled': str(self.setting('garage_enabled')).lower() in ('true', '1', 'yes'),
            'host': str(self.setting('garage_host') or '').strip(),
            'username': str(self.setting('garage_username') or '').strip(),
            'password': str(self.setting('garage_password') or ''),
            'left_open_minutes': as_int('garage_left_open_minutes', 1, 1440),
            'quiet_start': str(self.setting('garage_quiet_hours_start') or '').strip(),
            'quiet_end': str(self.setting('garage_quiet_hours_end') or '').strip(),
            'poll_interval': as_int('garage_poll_interval', 15, 600),
            'offline_after': as_int('garage_offline_after_polls', 1, 20),
        }

    def reload_config(self):
        """Called by the configuration service after any garage_* write: wake the loop now."""
        self._wake.set()

    # ---- client / stream lifecycle -----------------------------------------------
    def _ensure_client(self, cfg: dict) -> rc.RatgdoClient | None:
        key = (cfg['host'], cfg['username'], cfg['password'])
        if self._client is not None and key == self._client_key:
            return self._client
        self._stop_sse()
        try:
            self._client = rc.RatgdoClient(cfg['host'], cfg['username'] or None, cfg['password'] or None)
        except ValueError as e:
            logger.warning(f"garage_host {cfg['host']!r} rejected: {e}")
            self._client, self._client_key = None, None
            return None
        self._client_key = key
        self._offline_polls = 0
        self._last_poll = 0.0
        with self._lock:
            self.state['board'] = {'host': self._client.host, 'name': None}
        return self._client

    def _ensure_sse(self, client: rc.RatgdoClient):
        if self._sse_thread is not None and self._sse_thread.is_alive():
            return
        self._sse_stop = threading.Event()
        stop = self._sse_stop
        self._sse_thread = threading.Thread(target=self._run_sse, args=(client, stop), daemon=True, name='GarageEvents')
        self._sse_thread.start()

    def _stop_sse(self):
        self._sse_stop.set()
        self._sse_thread = None
        with self._lock:
            self.state['sse_connected'] = False

    def _teardown(self):
        """Feature disabled or unconfigured: drop the board and forget its state."""
        if self._client is None and self.state['door'] == 'unknown':
            return
        self._stop_sse()
        self._client, self._client_key = None, None
        with self._lock:
            self.state = rc.empty_state()
            self.state.update(open_since=None, door_changed_at=None, sse_connected=False)
        self._offline_polls = 0
        self._push()

    def _run_sse(self, client: rc.RatgdoClient, stop: threading.Event):
        attempt = 0
        while not stop.is_set() and not self._stop_event.is_set():
            received = []

            def on_state(document, _stop=stop, _received=received):
                if _stop.is_set():
                    return
                _received.append(1)
                self._on_sse_state(document)

            def on_ping(_stop=stop, _received=received):
                if _stop.is_set():
                    return
                _received.append(1)
                with self._lock:
                    self.state['sse_connected'] = True

            try:
                client.events(stop, on_state, on_ping)
            except rc.RatgdoError as e:
                logger.debug(f"garage SSE stream ended: {e}")
            except Exception as e:                       # never let the helper thread die silently
                logger.error(f"garage SSE stream failed: {e}")
            with self._lock:
                self.state['sse_connected'] = False
            attempt = 0 if received else attempt + 1
            stop.wait(SSE_BACKOFF[min(attempt, len(SSE_BACKOFF) - 1)])

    def _on_sse_state(self, document: dict):
        with self._lock:
            scratch = {k: self.state.get(k) for k in TRACKED_KEYS}
        changes = rc.apply_entity(scratch, document)
        try:
            with self.app.app_context():
                with self._lock:
                    self.state['sse_connected'] = True
                    self._offline_polls = 0
                    if self.state['online'] is not True:
                        changes['online'] = True
                if changes:
                    self.apply_state(changes)
        except Exception as e:
            logger.error(f"garage SSE state not applied: {e}")
            try:
                with self.app.app_context():
                    db.session.rollback()
            except Exception:
                pass

    # ---- state machine -----------------------------------------------------------------
    def record_command(self, action: str):
        self._pending_command = (action, time.monotonic())

    def _source(self) -> str:
        pending = self._pending_command
        if pending and time.monotonic() - pending[1] <= COMMAND_ATTRIBUTION_SECONDS:
            self._pending_command = None
            return 'dashboard'
        return 'external'

    def apply_state(self, changes: dict, now: datetime | None = None, notify: bool = True) -> list[GarageEvent]:
        """Fold ``changes`` into the state, write GarageEvent rows for transitions, alert, push.

        Must run inside an app context. Initial values (previous value unknown)
        update the state without writing rows -- a restart is not a door event.
        """
        now = now or datetime.utcnow()
        rows: list[GarageEvent] = []
        with self._lock:
            s = self.state
            changed = False
            for key, value in changes.items():
                if key not in TRACKED_KEYS and key != 'online':
                    continue
                previous = s.get(key)
                if previous == value:
                    continue
                s[key] = value
                changed = True
                initial = previous is None or (key == 'door' and previous == 'unknown')
                if key == 'door':
                    if value in DOOR_OPEN_STATES and s['open_since'] is None:
                        s['open_since'] = now
                    if initial:
                        continue
                    s['door_changed_at'] = now
                    opened = previous == 'closed' and value in DOOR_OPEN_STATES
                    duration = None
                    if value == 'closed' and s['open_since'] is not None:
                        duration = round((now - s['open_since']).total_seconds(), 1)
                        s['open_since'] = None
                    rows.append(GarageEvent(timestamp=now, kind='door', value=value, source=self._source(),
                                            position=changes.get('position', s.get('position')),
                                            duration_s=duration, opened=opened))
                elif key == 'light' and not initial:
                    rows.append(GarageEvent(timestamp=now, kind='light', value='on' if value else 'off',
                                            source=self._source()))
                elif key == 'lock' and not initial:
                    rows.append(GarageEvent(timestamp=now, kind='lock', value='locked' if value else 'unlocked',
                                            source=self._source()))
                elif key == 'obstruction' and not initial:
                    rows.append(GarageEvent(timestamp=now, kind='obstruction',
                                            value='detected' if value else 'clear', source='external'))
                elif key == 'online' and not initial:
                    rows.append(GarageEvent(timestamp=now, kind='online', value='online' if value else 'offline',
                                            source='external', detail=s['board'].get('host')))
            if not changed:
                return rows
            s['last_update'] = _iso(now)
            for row in rows:
                db.session.add(row)
            db.session.commit()
            if rows:
                self._last_event = rows[-1].to_dict()
            try:
                self.check_alerts(notify=notify, now=now)
            except Exception as e:
                logger.error(f"garage alerting failed: {e}")
                db.session.rollback()
            self._push()
        return rows

    def poll_once(self, notify: bool = True) -> dict:
        """One REST snapshot of every entity; counts failures towards ``garage_offline``. App context required."""
        self._last_poll = time.monotonic()
        client = self._client
        if client is None:
            return dict(self.state)
        try:
            snapshot = client.snapshot()
        except rc.RatgdoError as e:
            self._offline_polls += 1
            logger.debug(f"garage poll failed ({self._offline_polls}): {e}")
            if self._offline_polls >= self.config()['offline_after'] and self.state['online'] is not False:
                self.apply_state({'online': False}, notify=notify)
            return dict(self.state)
        self._offline_polls = 0
        with self._lock:
            changes = {k: snapshot[k] for k in TRACKED_KEYS if snapshot.get(k) != self.state.get(k)}
            if self.state['online'] is not True:
                changes['online'] = True
        if changes:
            self.apply_state(changes, notify=notify)
        return dict(self.state)

    def command(self, kind: str, action: str) -> dict:
        """Send one command to the board. Raises ValueError (bad action), GarageNotConfigured, RatgdoError."""
        cfg = self.config()
        if not cfg['enabled'] or not cfg['host']:
            raise GarageNotConfigured('Garage door integration is not enabled')
        client = self._ensure_client(cfg)
        if client is None:
            raise GarageNotConfigured(f"garage_host {cfg['host']!r} is not a usable LAN host")
        if kind == 'door':
            client.door(action)                                  # validates the action
        elif kind == 'light':
            mapping = {'on': 'turn_on', 'off': 'turn_off', 'toggle': 'toggle'}
            if action not in mapping:
                raise ValueError('light action must be on, off or toggle')
            client.light(mapping[action])
        elif kind == 'lock':
            client.lock(action)
        else:
            raise ValueError('kind must be door, light or lock')
        self.record_command(action)
        self._last_poll = 0.0             # the ticker polls promptly for boards without a live stream
        self._wake.set()
        return {'ok': True, 'kind': kind, 'action': action}

    # ---- alerts ----------------------------------------------------------------------------
    def _device(self) -> Device | None:
        host = self.state['board'].get('host') or (self._client.host if self._client else None)
        if not host:
            return None
        try:
            import ipaddress
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
        if is_ip:
            device = Device.query.filter_by(ip_address=host).first()
        else:
            short = host.split('.')[0]
            device = Device.query.filter(Device.hostname.ilike(f'{short}%')).first()
        if device is None:
            device = Device(ip_address=host if is_ip else None, hostname='ratgdo' if is_ip else host,
                            custom_name='Garage door (ratgdo)', device_type='smart_home', is_monitored=is_ip,
                            last_seen=datetime.utcnow())
            db.session.add(device)
            db.session.flush()
        return device

    def _open_alert(self, device_id, alert_type):
        return Alert.query.filter_by(device_id=device_id, alert_type=alert_type, resolved=False).first()

    def _resolve(self, alert: Alert):
        alert.resolved = True
        alert.resolved_at = datetime.utcnow()
        db.session.commit()
        try:
            self.app.emit_alert_update(alert, 'resolved')
        except Exception:
            pass

    def check_alerts(self, notify: bool = True, now: datetime | None = None, local_now: datetime | None = None):
        """Create / resolve the four garage alerts from the current state. App context required."""
        manager = getattr(self.app, 'alert_manager', None)
        if manager is None:
            return
        cfg = self.config()
        if not cfg['enabled'] or not cfg['host']:
            return
        device = self._device()
        if device is None:
            return
        now = now or datetime.utcnow()
        local_now = local_now or datetime.now()
        s = self.state
        door_open = s['door'] in DOOR_OPEN_STATES

        def raise_once(alert_type, severity, message):
            if not self._open_alert(device.id, alert_type):
                manager.create_alert(device.id, alert_type, severity, message, subtype=ALERT_SUBTYPE, notify=notify)

        def clear(alert_type):
            alert = self._open_alert(device.id, alert_type)
            if alert:
                self._resolve(alert)

        open_for = (now - s['open_since']).total_seconds() if door_open and s['open_since'] else 0
        if door_open and open_for >= cfg['left_open_minutes'] * 60:
            raise_once('garage_left_open', 'warning',
                       f"Garage door has been open for {int(open_for // 60)} minutes "
                       f"(threshold {cfg['left_open_minutes']} min)")
        elif s['door'] == 'closed':
            clear('garage_left_open')

        if door_open and in_quiet_hours(local_now.time(), cfg['quiet_start'], cfg['quiet_end']):
            raise_once('garage_quiet_hours_open', 'info',
                       f"Garage door is open at {local_now.strftime('%H:%M')} during quiet hours "
                       f"({cfg['quiet_start']}-{cfg['quiet_end']})")
        elif s['door'] == 'closed':
            clear('garage_quiet_hours_open')

        if s['obstruction'] is True:
            raise_once('garage_obstruction', 'warning', 'Garage door obstruction sensor is blocked')
        elif s['obstruction'] is False:
            clear('garage_obstruction')

        if s['online'] is False:
            raise_once('garage_offline', 'warning',
                       f"Garage controller (ratgdo) at {s['board'].get('host')} has not answered "
                       f"{self._offline_polls} polls in a row")
        elif s['online'] is True:
            clear('garage_offline')

    # ---- views -------------------------------------------------------------------------------
    def status(self) -> dict:
        """What GET /api/garage and the garage_status socket event carry. App context required."""
        cfg = self.config()
        with self._lock:
            s = dict(self.state)
        now = datetime.utcnow()
        door_open = s['door'] in DOOR_OPEN_STATES
        open_for = round((now - s['open_since']).total_seconds()) if door_open and s['open_since'] else None
        if self._last_event is None:
            latest = GarageEvent.query.order_by(GarageEvent.timestamp.desc(), GarageEvent.id.desc()).first()
            if latest is not None:
                self._last_event = latest.to_dict()
        configured = cfg['enabled'] and bool(cfg['host']) and self._client is not None
        quiet_active = in_quiet_hours(datetime.now().time(), cfg['quiet_start'], cfg['quiet_end'])
        return {
            'enabled': cfg['enabled'],
            'configured': configured,
            'host': cfg['host'] or None,
            'board': {'host': s['board'].get('host'), 'name': s['board'].get('name'), 'firmware': s['firmware']},
            'online': s['online'],
            'sse_connected': bool(s['sse_connected']),
            'consecutive_failures': self._offline_polls,
            'door': s['door'], 'position': s['position'],
            'light': s['light'], 'lock': s['lock'],
            'obstruction': s['obstruction'], 'motion': s['motion'], 'motor': s['motor'],
            'openings': s['openings'],
            'open_since': _iso(s['open_since']) if door_open else None,
            'open_for_seconds': open_for,
            'last_update': s['last_update'],
            'last_event': self._last_event,
            'left_open_minutes': cfg['left_open_minutes'],
            'quiet_hours': {'start': cfg['quiet_start'] or None, 'end': cfg['quiet_end'] or None, 'active': quiet_active},
            'poll_interval': cfg['poll_interval'],
        }

    def history(self, hours: int = 336) -> dict:
        """Door events in the window plus daily buckets (local dates) and headline stats. App context required."""
        hours = max(1, min(int(hours), 24 * 90))
        now = datetime.utcnow()
        since = now - timedelta(hours=hours)
        door_rows = GarageEvent.query.filter(GarageEvent.kind == 'door', GarageEvent.timestamp >= since) \
            .order_by(GarageEvent.timestamp.asc()).all()
        recent = GarageEvent.query.filter(GarageEvent.timestamp >= since) \
            .order_by(GarageEvent.timestamp.desc(), GarageEvent.id.desc()).limit(200).all()

        today = date.today()
        days = [today - timedelta(days=i) for i in range(13, -1, -1)]
        daily = {d: {'date': d.isoformat(), 'openings': 0, 'open_seconds': 0.0} for d in days}
        openings_today = openings_week = 0
        durations: list[float] = []
        longest_today = 0.0
        week_start = today - timedelta(days=6)
        for row in door_rows:
            local_day = _to_local(row.timestamp).date()
            if row.opened:
                if local_day == today:
                    openings_today += 1
                if local_day >= week_start:
                    openings_week += 1
                if local_day in daily:
                    daily[local_day]['openings'] += 1
            if row.value == 'closed' and row.duration_s is not None:
                durations.append(row.duration_s)
                if local_day in daily:
                    daily[local_day]['open_seconds'] = round(daily[local_day]['open_seconds'] + row.duration_s, 1)
                if local_day == today:
                    longest_today = max(longest_today, row.duration_s)

        with self._lock:
            s = dict(self.state)
        current_open = None
        if s['door'] in DOOR_OPEN_STATES and s['open_since']:
            current_open = round((now - s['open_since']).total_seconds())
            longest_today = max(longest_today, current_open)
        return {
            'hours': hours,
            'stats': {
                'openings_today': openings_today,
                'openings_week': openings_week,
                'avg_open_seconds': round(sum(durations) / len(durations), 1) if durations else None,
                'longest_open_today_seconds': round(longest_today) if longest_today else None,
                'currently_open_seconds': current_open,
            },
            'daily': [daily[d] for d in days],
            'events': [row.to_dict() for row in recent],
        }

    # ---- push + loop -----------------------------------------------------------------------------
    def _push(self):
        socketio = getattr(self.app, 'socketio', None)
        if socketio is None:
            return
        try:
            socketio.emit('garage_status', self.status(), room='updates_monitoring_summary')
        except Exception as e:
            logger.debug(f"garage_status emit skipped: {e}")

    def start_monitoring(self):
        self.is_running = True
        self._stop_event.clear()
        logger.info("Starting garage door monitor")
        while not self._stop_event.is_set():
            record_heartbeat('GarageMonitor')
            wait = TICK_SECONDS
            try:
                with self.app.app_context():
                    wait = self._tick()
            except Exception as e:
                logger.error(f"Garage monitor iteration failed: {e}")
                try:
                    with self.app.app_context():
                        db.session.rollback()
                except Exception:
                    pass
            self._wake.wait(wait)
            self._wake.clear()
        self._stop_sse()
        self.is_running = False

    def _tick(self) -> float:
        """One ticker iteration inside an app context; returns how long to wait."""
        cfg = self.config()
        if not cfg['enabled'] or not cfg['host']:
            self._teardown()
            return TICK_SECONDS
        client = self._ensure_client(cfg)
        if client is None:
            return TICK_SECONDS
        self._ensure_sse(client)
        with self._lock:
            streaming = self.state['sse_connected']
            moving = self.state['door'] in ('opening', 'closing')
        interval = cfg['poll_interval'] if streaming else min(cfg['poll_interval'], TICK_SECONDS)
        if moving and not streaming:
            interval = MOVING_POLL_SECONDS
        if time.monotonic() - self._last_poll >= interval:
            self.poll_once()
        self.check_alerts()
        return MOVING_POLL_SECONDS if (moving and not streaming) else TICK_SECONDS

    def stop(self):
        self._stop_event.set()
        self._sse_stop.set()
        self._wake.set()
