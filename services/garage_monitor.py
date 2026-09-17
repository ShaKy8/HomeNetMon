"""Garage door monitor: reads the door state from the Ring "Garage Cam".

There is no door controller: the camera is the sensor. On a schedule (and
sooner after Ring reports motion) the monitor fetches the camera's latest
stored frame through ``services.ring_client.RingBridge``, drops frames that
look identical to the last one (``services.door_vision.frame_changed``) and
asks Claude vision to read the rest (``door_vision.classify``). A reading that
is confident enough becomes the door state; every transition is a
``GarageEvent`` row with the frame that caused it saved next to the database.

* ticker thread ``GarageMonitor`` (``core.health.EXPECTED_THREADS``): runs and
  heartbeats even while the feature is disabled;
* alerts through ``AlertManager.create_alert()`` on the camera's ``Device``
  row: ``garage_left_open``, ``garage_quiet_hours_open`` (local clock),
  ``garage_offline`` when Ring or Claude keep failing; resolved here;
* ``garage_status`` pushes to the ``updates_monitoring_summary`` room.

Battery cameras only take a new picture every few minutes and never while
recording, so the stored frame is used on the schedule and a fresh one is
requested only after motion and on "Check now".
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import threading
import time
from datetime import date, datetime, time as dtime, timedelta, timezone
from pathlib import Path

from config import Config
from constants import APP_VERSION
from core.health import record_heartbeat
from models import Alert, Configuration, Device, GarageEvent, db
from services import door_vision
from services.ring_client import RingAuthError, RingBridge, RingError

logger = logging.getLogger(__name__)

DEFAULTS = {
    'garage_enabled': 'false',
    'garage_camera_id': '',
    'garage_camera_name': '',
    'garage_check_interval': 900,
    'garage_motion_checks': 'true',
    'garage_vision_model': door_vision.DEFAULT_MODEL,
    'garage_scene_hint': '',
    'garage_left_open_minutes': 15,
    'garage_quiet_hours_start': '22:00',
    'garage_quiet_hours_end': '06:00',
    'garage_reclassify_minutes': 60,
    'garage_offline_after_failures': 3,
}
TICK_SECONDS = 60                  # heartbeat / motion-poll / alert-timer cadence
CONFIG_CACHE_SECONDS = 5           # Configuration reads are cached this long (reload_config() clears it)
MOTION_CHECK_DELAY = 45            # seconds after a Ring motion event before asking for a frame (recording ends)
MIN_CONFIDENCE = 0.6               # readings below this keep the previous state
FRAME_CAP = 100                    # event frames kept on disk
CAMERA_INFO_SECONDS = 600          # how often battery / Wi-Fi are refreshed from Ring
TRACKED_KEYS = ('door',)
DOOR_OPEN_STATES = ('open',)
ALERT_SUBTYPE = 'garage'
EVENT_FRAME_RE = re.compile(r'^event-(\d+)\.jpg$')


class GarageNotConfigured(Exception):
    """The integration is disabled, has no camera, or Ring is not signed in."""


class GarageBusy(Exception):
    """A check is already running."""


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


def _ms_to_iso(ms: int | None) -> str | None:
    if not ms:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).replace(tzinfo=None).isoformat() + 'Z'


def empty_state() -> dict:
    return {
        'door': 'unknown', 'online': None, 'last_update': None,
        'open_since': None, 'door_changed_at': None,
        'camera': None, 'reading': None,
        'snapshot': {'taken_at': None, 'classified_at': None, 'changed_score': None, 'has_frame': False},
    }


class GarageMonitor:
    def __init__(self, app=None, bridge: RingBridge | None = None, frame_dir: str | os.PathLike | None = None):
        self.app = app
        self.state = empty_state()
        self._lock = threading.RLock()
        self._check_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._wake = threading.Event()
        self._bridge = bridge
        self._frame_dir = Path(frame_dir or Config.GARAGE_FRAME_DIR)
        self._last_frame: bytes | None = None
        self._last_frame_ms: int | None = None
        self._last_classified_at = 0.0
        self._last_check = 0.0
        self._check_due_at: float | None = None
        self._check_reason = 'schedule'
        self._failures = 0
        self._last_error: str | None = None
        self._last_motion_id = None
        self._motion_seen = False
        self._camera_checked_at = 0.0
        self._day: date | None = None
        self._checks_today = 0
        self._tokens_today = 0
        self._cost_today = 0.0
        self._last_event: dict | None = None
        self._config_cache: tuple[dict, float] | None = None
        self.is_running = False

    # ---- configuration --------------------------------------------------------
    def setting(self, key, default=None):
        """Runtime value, or the default when no row exists. An empty row is a real
        value here (blank quiet hours mean "off"), unlike WanMonitor."""
        value = Configuration.get_value(key)
        if value is None:
            return DEFAULTS.get(key) if default is None else default
        return value

    def config(self) -> dict:
        """Typed, clamped view of the garage_* settings (cached a few seconds). Needs an app context."""
        cached = self._config_cache
        if cached is not None and time.monotonic() - cached[1] < CONFIG_CACHE_SECONDS:
            return dict(cached[0])
        cfg = self._read_config()
        self._config_cache = (cfg, time.monotonic())
        return dict(cfg)

    def _read_config(self) -> dict:
        def as_int(key, lo, hi):
            try:
                return max(lo, min(hi, int(self.setting(key))))
            except (TypeError, ValueError):
                return int(DEFAULTS[key])
        model = str(self.setting('garage_vision_model') or '').strip()
        return {
            'enabled': str(self.setting('garage_enabled')).lower() in ('true', '1', 'yes'),
            'camera_id': str(self.setting('garage_camera_id') or '').strip(),
            'camera_name': str(self.setting('garage_camera_name') or '').strip()[:100],
            'check_interval': as_int('garage_check_interval', 120, 86400),
            'motion_checks': str(self.setting('garage_motion_checks')).lower() in ('true', '1', 'yes'),
            'vision_model': model if model in door_vision.ALLOWED_MODELS else door_vision.DEFAULT_MODEL,
            'scene_hint': str(self.setting('garage_scene_hint') or '').strip()[:300],
            'left_open_minutes': as_int('garage_left_open_minutes', 1, 1440),
            'quiet_start': str(self.setting('garage_quiet_hours_start') or '').strip(),
            'quiet_end': str(self.setting('garage_quiet_hours_end') or '').strip(),
            'reclassify_minutes': as_int('garage_reclassify_minutes', 5, 1440),
            'offline_after': as_int('garage_offline_after_failures', 1, 20),
        }

    def reload_config(self):
        """Called by the configuration service after any garage_* write: wake the loop now."""
        self._config_cache = None
        self._wake.set()

    # ---- Ring account -----------------------------------------------------------------
    def bridge(self) -> RingBridge:
        if self._bridge is None:
            self._bridge = RingBridge(Config.RING_TOKEN_FILE, f'HomeNetMon/{APP_VERSION}')
        self._bridge.start()
        return self._bridge

    def ring_login(self, email: str, password: str, otp: str | None = None) -> dict:
        result = self.bridge().login(email, password, otp)
        if result.get('status') == 'ok':
            self._failures = 0
            self.reload_config()
        return result

    def ring_logout(self) -> None:
        self.bridge().logout()
        self._teardown()
        self.reload_config()

    def ring_cameras(self) -> list[dict]:
        return self.bridge().cameras()

    def signed_in(self) -> bool:
        try:
            return self.bridge().signed_in()
        except Exception:
            return False

    # ---- the check -----------------------------------------------------------------------
    def check_once(self, fresh: bool = False, notify: bool = True, now: datetime | None = None) -> dict:
        """Fetch a frame, read the door, record the result. App context required.

        ``fresh`` asks the camera for a new picture (motion / "Check now"); otherwise the
        camera's stored frame is used. Raises GarageBusy, GarageNotConfigured, RingError,
        VisionError; failures count towards ``garage_offline``.
        """
        if not self._check_lock.acquire(blocking=False):
            raise GarageBusy('A garage check is already running')
        try:
            cfg = self.config()
            if not cfg['enabled'] or not cfg['camera_id']:
                raise GarageNotConfigured('Garage camera is not enabled or no camera is selected')
            if not self.signed_in():
                raise GarageNotConfigured('Not signed in to Ring')
            self._last_check = time.monotonic()
            self._check_due_at = None
            now = now or datetime.utcnow()
            try:
                frame, taken_ms = self._fetch_frame(cfg, fresh)
                self._refresh_camera_info(cfg)
                if frame is None:
                    self._record_success(notify)
                    self._push()
                    return self.status()
                jpeg = door_vision.prepare_frame(frame)
                changed, score = door_vision.frame_changed(self._last_frame, jpeg)
                stale = time.monotonic() - self._last_classified_at >= cfg['reclassify_minutes'] * 60
                with self._lock:
                    self.state['snapshot'].update(taken_at=_ms_to_iso(taken_ms), changed_score=score, has_frame=True)
                self._last_frame, self._last_frame_ms = jpeg, taken_ms
                self._store_frame(jpeg)
                if changed or stale or self.state['door'] == 'unknown':
                    reading, usage = door_vision.classify(jpeg, cfg['vision_model'], cfg['scene_hint'],
                                                          Config.ANTHROPIC_API_KEY or None)
                    self._count(usage)
                    self._last_classified_at = time.monotonic()
                    state = reading.state if reading.door_visible and reading.confidence >= MIN_CONFIDENCE else 'unknown'
                    with self._lock:
                        self.state['reading'] = {
                            'state': reading.state, 'confidence': round(reading.confidence, 2), 'night': reading.night,
                            'door_visible': reading.door_visible, 'reason': reading.reason, 'model': cfg['vision_model'],
                        }
                        self.state['snapshot']['classified_at'] = _iso(now)
                    if state != 'unknown':
                        rows = self.apply_state({'door': state}, now=now, notify=notify)
                        for row in rows:
                            if row.kind == 'door':
                                self._link_event_frame(row)
                self._record_success(notify)
            except (RingError, door_vision.VisionError) as e:
                self._record_failure(e, notify)
                raise
            self._push()
            return self.status()
        finally:
            self._check_lock.release()

    def _fetch_frame(self, cfg: dict, fresh: bool) -> tuple[bytes | None, int | None]:
        bridge = self.bridge()
        camera_id = cfg['camera_id']
        if fresh:
            frame, taken_ms = bridge.fresh_snapshot(camera_id)
            if frame is not None:
                return frame, taken_ms
        return bridge.latest_snapshot(camera_id, since_ms=self._last_frame_ms)

    def _refresh_camera_info(self, cfg: dict) -> None:
        if time.monotonic() - self._camera_checked_at < CAMERA_INFO_SECONDS:
            return
        self._camera_checked_at = time.monotonic()
        try:
            info = self.bridge().health(cfg['camera_id'])
        except RingError as e:
            logger.debug(f"garage camera info unavailable: {e}")
            return
        with self._lock:
            self.state['camera'] = {'id': info.get('id'), 'name': info.get('name') or cfg['camera_name'],
                                    'model': info.get('model'), 'battery_life': info.get('battery_life'),
                                    'wifi': info.get('wifi_signal_strength'), 'is_battery': bool(info.get('is_battery'))}

    # ---- frames on disk ----------------------------------------------------------------------
    def _store_frame(self, jpeg: bytes) -> Path:
        self._frame_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self._frame_dir / 'latest.jpg'
        tmp = self._frame_dir / 'latest.jpg.tmp'
        tmp.write_bytes(jpeg)
        os.replace(tmp, path)
        return path

    def _link_event_frame(self, row: GarageEvent) -> None:
        if self._last_frame is None or row.id is None:
            return
        name = f'event-{row.id}.jpg'
        try:
            (self._frame_dir / name).write_bytes(self._last_frame)
        except OSError as e:
            logger.warning(f"garage frame not saved: {e}")
            return
        row.detail = name
        db.session.commit()
        self._last_event = row.to_dict()
        self._prune_frames()

    def _prune_frames(self) -> None:
        try:
            frames = sorted((p for p in self._frame_dir.glob('event-*.jpg')), key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            return
        for old in frames[FRAME_CAP:]:
            try:
                old.unlink()
            except OSError:
                pass

    def frame_path(self, event_id: int | None = None) -> Path | None:
        """Path of latest.jpg or of an event frame; None when missing (ids are validated, no path input)."""
        if event_id is None:
            path = self._frame_dir / 'latest.jpg'
        else:
            try:
                path = self._frame_dir / f'event-{int(event_id)}.jpg'
            except (TypeError, ValueError):
                return None
        return path if path.is_file() else None

    # ---- bookkeeping -------------------------------------------------------------------------------
    def _record_failure(self, error: Exception, notify: bool = True) -> None:
        self._failures += 1
        self._last_error = str(error)[:200]
        logger.warning(f"garage check failed ({self._failures}): {error}")
        if isinstance(error, RingAuthError):
            return                                   # signed out: the UI says so, no alert
        if self._failures >= self.config()['offline_after'] and self.state['online'] is not False:
            self.apply_state({'online': False}, notify=notify)

    def _record_success(self, notify: bool = True) -> None:
        self._failures = 0
        self._last_error = None
        if self.state['online'] is not True:
            self.apply_state({'online': True}, notify=notify)

    def _count(self, usage: dict) -> None:
        today = date.today()
        if self._day != today:
            self._day, self._checks_today, self._tokens_today, self._cost_today = today, 0, 0, 0.0
        self._checks_today += 1
        self._tokens_today += int(usage.get('input_tokens', 0) or 0) + int(usage.get('output_tokens', 0) or 0)
        self._cost_today = round(self._cost_today + float(usage.get('est_cost_usd', 0) or 0), 6)

    def _poll_motion(self, cfg: dict) -> None:
        try:
            events = self.bridge().motion_events(cfg['camera_id'], limit=3)
        except RingError as e:
            logger.debug(f"garage motion poll failed: {e}")
            return
        latest = events[0]['id'] if events else None
        if not self._motion_seen:
            self._motion_seen, self._last_motion_id = True, latest
            return
        if latest is not None and latest != self._last_motion_id:
            self._last_motion_id = latest
            self._check_due_at = time.monotonic() + MOTION_CHECK_DELAY
            self._check_reason = 'motion'
            logger.info("Ring motion at the garage; checking the door shortly")

    def _teardown(self) -> None:
        with self._lock:
            self.state = empty_state()
        self._last_frame, self._last_frame_ms = None, None
        self._failures, self._last_error = 0, None
        self._motion_seen, self._last_motion_id = False, None
        self._push()

    # ---- state machine -----------------------------------------------------------------------------
    def apply_state(self, changes: dict, now: datetime | None = None, notify: bool = True) -> list[GarageEvent]:
        """Fold ``changes`` (door / online) into the state, write GarageEvent rows for transitions, alert, push.

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
                    rows.append(GarageEvent(timestamp=now, kind='door', value=value, source='camera',
                                            duration_s=duration, opened=opened))
                elif key == 'online' and not initial:
                    rows.append(GarageEvent(timestamp=now, kind='online', value='online' if value else 'offline',
                                            source='camera', detail=(self._last_error or None) if not value else None))
            if not changed:
                return rows
            s['last_update'] = _iso(now)
            if rows:
                for row in rows:
                    db.session.add(row)
                db.session.commit()
                self._last_event = rows[-1].to_dict()
            try:
                self.check_alerts(notify=notify, now=now)
            except Exception as e:
                logger.error(f"garage alerting failed: {e}")
                db.session.rollback()
            self._push()
        return rows

    # ---- alerts ----------------------------------------------------------------------------
    def _device(self) -> Device | None:
        cfg = self.config()
        if not cfg['camera_id']:
            return None
        hostname = f"ring-cam-{cfg['camera_id']}"
        device = Device.query.filter_by(hostname=hostname).first()
        if device is None:
            device = Device(hostname=hostname, custom_name=f"{cfg['camera_name'] or 'Garage Cam'} (Ring)",
                            device_type='camera', is_monitored=False, last_seen=datetime.utcnow())
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
        """Create / resolve the garage alerts from the current state. App context required."""
        manager = getattr(self.app, 'alert_manager', None)
        if manager is None:
            return
        cfg = self.config()
        if not cfg['enabled'] or not cfg['camera_id']:
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

        if s['online'] is False:
            name = (s['camera'] or {}).get('name') or cfg['camera_name'] or 'Garage Cam'
            raise_once('garage_offline', 'warning',
                       f"Garage camera {name} unavailable: {self._failures} consecutive Ring / vision failures "
                       f"({self._last_error or 'unknown error'})")
        elif s['online'] is True:
            clear('garage_offline')

    # ---- views -------------------------------------------------------------------------------
    def status(self) -> dict:
        """What GET /api/garage and the garage_status socket event carry. App context required."""
        cfg = self.config()
        with self._lock:
            s = dict(self.state)
            snapshot = dict(s['snapshot'])
        now = datetime.utcnow()
        door_open = s['door'] in DOOR_OPEN_STATES
        open_for = round((now - s['open_since']).total_seconds()) if door_open and s['open_since'] else None
        if self._last_event is None:
            latest = GarageEvent.query.order_by(GarageEvent.timestamp.desc(), GarageEvent.id.desc()).first()
            if latest is not None:
                self._last_event = latest.to_dict()
        signed_in = self.signed_in()
        configured = bool(cfg['enabled'] and cfg['camera_id'] and signed_in)
        quiet_active = in_quiet_hours(datetime.now().time(), cfg['quiet_start'], cfg['quiet_end'])
        if snapshot.get('taken_at'):
            try:
                taken = datetime.fromisoformat(snapshot['taken_at'].rstrip('Z'))
                snapshot['age_seconds'] = max(0, round((now - taken).total_seconds()))
            except ValueError:
                snapshot['age_seconds'] = None
        else:
            snapshot['age_seconds'] = None
        next_check = None
        if configured:
            due = self._check_due_at if self._check_due_at is not None else self._last_check + cfg['check_interval']
            next_check = _iso(now + timedelta(seconds=max(0, due - time.monotonic())))
        if self._day != date.today():
            checks, tokens, cost = 0, 0, 0.0
        else:
            checks, tokens, cost = self._checks_today, self._tokens_today, self._cost_today
        camera = s['camera'] or ({'id': cfg['camera_id'], 'name': cfg['camera_name'] or None, 'model': None,
                                  'battery_life': None, 'wifi': None, 'is_battery': None} if cfg['camera_id'] else None)
        return {
            'enabled': cfg['enabled'],
            'configured': configured,
            'door': s['door'], 'online': s['online'],
            'consecutive_failures': self._failures, 'last_error': self._last_error,
            'open_since': _iso(s['open_since']) if door_open else None,
            'open_for_seconds': open_for,
            'last_update': s['last_update'],
            'last_event': self._last_event,
            'left_open_minutes': cfg['left_open_minutes'],
            'quiet_hours': {'start': cfg['quiet_start'] or None, 'end': cfg['quiet_end'] or None, 'active': quiet_active},
            'check_interval': cfg['check_interval'], 'motion_checks': cfg['motion_checks'],
            'next_check_at': next_check,
            'camera': camera,
            'ring': {'signed_in': signed_in},
            'snapshot': snapshot,
            'reading': s['reading'],
            'vision': {'model': cfg['vision_model'], 'checks_today': checks, 'tokens_today': tokens,
                       'est_cost_today_usd': round(cost, 4), 'api_key_set': bool(Config.ANTHROPIC_API_KEY)},
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
        logger.info("Starting garage camera monitor")
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
        if self._bridge is not None:
            self._bridge.stop()
        self.is_running = False

    def _tick(self) -> float:
        """One ticker iteration inside an app context; returns how long to wait."""
        cfg = self.config()
        if not cfg['enabled'] or not cfg['camera_id']:
            if self.state['door'] != 'unknown' or self.state['online'] is not None or self._last_frame is not None:
                self._teardown()
            return TICK_SECONDS
        if not self.signed_in():
            return TICK_SECONDS
        if cfg['motion_checks']:
            self._poll_motion(cfg)
        due = self._check_due_at if self._check_due_at is not None else self._last_check + cfg['check_interval']
        if time.monotonic() >= due:
            reason, self._check_reason = self._check_reason, 'schedule'
            try:
                self.check_once(fresh=(reason == 'motion'))
            except (GarageBusy, GarageNotConfigured, RingError, door_vision.VisionError) as e:
                logger.debug(f"garage check skipped: {e}")
            due = self._check_due_at if self._check_due_at is not None else self._last_check + cfg['check_interval']
        self.check_alerts()
        return max(5.0, min(float(TICK_SECONDS), due - time.monotonic()))

    def stop(self):
        self._stop_event.set()
        self._wake.set()
