"""Internet / gateway reachability monitor.

Every ``wan_check_interval`` seconds (default 60) it pings the default gateway
and one external target (``wan_check_target``, default 1.1.1.1), records a
``WanCheck`` row, pushes ``wan_status`` to subscribed dashboards and, after
``wan_down_after_checks`` consecutive failures, raises ``wan_down`` /
``gateway_down`` alerts through AlertManager.create_alert(); recovery resolves
them and raises an informational ``wan_recovery``.

Alerts need a device row (Alert.device_id is NOT NULL), so they attach to the
gateway's Device, created as a router if the scanner has not seen it yet.
"""

from __future__ import annotations

import logging
import re
import subprocess
import threading
import time
from datetime import datetime, timedelta

from config import Config
from core.health import record_heartbeat
from models import Alert, Configuration, Device, WanCheck, db
from monitoring.ping import ping_host

logger = logging.getLogger(__name__)

DEFAULTS = {
    'wan_check_target': '1.1.1.1',
    'wan_check_interval': 60,
    'wan_down_after_checks': 3,
    'wan_gateway_ip': '',
}


def detect_default_gateway() -> str | None:
    """IPv4 default gateway from the routing table (``ip -4 route show default``)."""
    try:
        out = subprocess.run(['ip', '-4', 'route', 'show', 'default'], capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.debug(f"gateway detection failed: {e}")
        return None
    match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', out)
    return match.group(1) if match else None


class WanMonitor:
    def __init__(self, app=None):
        self.app = app
        self._stop_event = threading.Event()
        self.is_running = False
        self._gateway_cache: tuple[str | None, float] = (None, 0.0)
        self.state = {
            'gateway_ip': None, 'gateway_up': None, 'gateway_rtt_ms': None,
            'target': None, 'internet_up': None, 'target_rtt_ms': None,
            'consecutive_failures': 0, 'gateway_failures': 0,
            'last_check': None, 'last_change': None, 'status': 'unknown',
        }

    # ---- configuration --------------------------------------------------
    def setting(self, key, default=None):
        value = Configuration.get_value(key)
        if value in (None, ''):
            return DEFAULTS.get(key) if default is None else default
        return value

    def interval(self) -> int:
        try:
            return max(30, min(3600, int(self.setting('wan_check_interval'))))
        except (TypeError, ValueError):
            return DEFAULTS['wan_check_interval']

    def down_after(self) -> int:
        try:
            return max(1, min(20, int(self.setting('wan_down_after_checks'))))
        except (TypeError, ValueError):
            return DEFAULTS['wan_down_after_checks']

    def gateway_ip(self) -> str | None:
        override = (self.setting('wan_gateway_ip') or '').strip()
        if override:
            return override
        cached, at = self._gateway_cache
        if cached and time.time() - at < 3600:
            return cached
        detected = detect_default_gateway()
        self._gateway_cache = (detected, time.time())
        return detected

    # ---- one check --------------------------------------------------------
    def check_once(self, notify=True) -> dict:
        """Ping gateway and target once, persist, alert. Must run inside an app context."""
        gateway = self.gateway_ip()
        target = (self.setting('wan_check_target') or DEFAULTS['wan_check_target']).strip()
        gateway_rtt = ping_host(gateway, 2.0) if gateway else None
        target_rtt = ping_host(target, 3.0) if target else None
        now = datetime.utcnow()

        row = WanCheck(timestamp=now, gateway_ip=gateway, gateway_rtt_ms=gateway_rtt,
                       gateway_up=gateway_rtt is not None, target=target, target_rtt_ms=target_rtt,
                       internet_up=target_rtt is not None)
        db.session.add(row)

        s = self.state
        previous_status = s['status']
        s.update(gateway_ip=gateway, gateway_up=gateway_rtt is not None, gateway_rtt_ms=gateway_rtt,
                 target=target, internet_up=target_rtt is not None, target_rtt_ms=target_rtt,
                 last_check=now.isoformat() + 'Z')
        s['consecutive_failures'] = 0 if target_rtt is not None else s['consecutive_failures'] + 1
        s['gateway_failures'] = 0 if gateway_rtt is not None else s['gateway_failures'] + 1
        threshold = self.down_after()
        if target_rtt is not None and gateway_rtt is not None:
            s['status'] = 'up'
        elif s['consecutive_failures'] >= threshold or s['gateway_failures'] >= threshold:
            s['status'] = 'down'
        elif previous_status == 'down':
            s['status'] = 'down'
        else:
            s['status'] = 'degraded' if previous_status != 'unknown' else 'unknown'

        try:
            self._alerting(previous_status, notify)
        except Exception as e:
            logger.error(f"WAN alerting failed: {e}")
        db.session.commit()

        if s['status'] != previous_status:
            s['last_change'] = now.isoformat() + 'Z'
            self._push()
        return dict(s)

    # ---- alerts -------------------------------------------------------------
    def _gateway_device(self):
        gateway = self.state.get('gateway_ip')
        if not gateway:
            return None
        device = Device.query.filter_by(ip_address=gateway).first()
        if device is None:
            device = Device(ip_address=gateway, hostname='gateway', custom_name='Internet gateway',
                            device_type='router', is_monitored=True, last_seen=datetime.utcnow())
            db.session.add(device)
            db.session.flush()
        return device

    def _open_alert(self, device_id, alert_type):
        return Alert.query.filter_by(device_id=device_id, alert_type=alert_type, resolved=False).first()

    def _alerting(self, previous_status, notify):
        s = self.state
        manager = getattr(self.app, 'alert_manager', None)
        device = self._gateway_device()
        if device is None or manager is None:
            return
        threshold = self.down_after()
        if s['gateway_failures'] >= threshold and not self._open_alert(device.id, 'gateway_down'):
            manager.create_alert(device.id, 'gateway_down', 'critical',
                                 f"Gateway {s['gateway_ip']} has not answered {s['gateway_failures']} checks in a row",
                                 subtype='gateway', notify=notify)
        elif s['consecutive_failures'] >= threshold and s['gateway_failures'] < threshold \
                and not self._open_alert(device.id, 'wan_down'):
            manager.create_alert(device.id, 'wan_down', 'critical',
                                 f"Internet unreachable: {s['target']} has not answered {s['consecutive_failures']} checks in a row "
                                 f"(gateway {s['gateway_ip']} is up)", subtype='internet', notify=notify)
        if s['status'] == 'up' and previous_status == 'down':
            resolved = []
            for alert_type in ('wan_down', 'gateway_down'):
                alert = self._open_alert(device.id, alert_type)
                if alert:
                    alert.resolved = True
                    alert.resolved_at = datetime.utcnow()
                    resolved.append(alert_type)
                    try:
                        self.app.emit_alert_update(alert, 'resolved')
                    except Exception:
                        pass
            if resolved:
                manager.create_alert(device.id, 'wan_recovery', 'info',
                                     f"Internet connectivity restored (gateway {s['gateway_ip']}, target {s['target']})",
                                     subtype='internet', notify=notify)

    def _push(self):
        socketio = getattr(self.app, 'socketio', None)
        if socketio is None:
            return
        try:
            socketio.emit('wan_status', dict(self.state), room='updates_monitoring_summary')
        except Exception as e:
            logger.debug(f"wan_status emit skipped: {e}")

    # ---- API view -----------------------------------------------------------
    def status(self, hours: int = 24) -> dict:
        since = datetime.utcnow() - timedelta(hours=hours)
        rows = WanCheck.query.filter(WanCheck.timestamp >= since).order_by(WanCheck.timestamp.asc()).all()
        total = len(rows)
        up = sum(1 for r in rows if r.internet_up)
        rtts = [r.target_rtt_ms for r in rows if r.target_rtt_ms is not None]
        step = max(1, total // 200)
        timeline = [{'t': r.timestamp.isoformat() + 'Z', 'internet_up': r.internet_up, 'gateway_up': r.gateway_up,
                     'target_rtt_ms': r.target_rtt_ms, 'gateway_rtt_ms': r.gateway_rtt_ms}
                    for i, r in enumerate(rows) if i % step == 0]
        s = self.state
        return {
            'status': s['status'],
            'gateway': {'ip': s['gateway_ip'], 'up': s['gateway_up'], 'rtt_ms': s['gateway_rtt_ms']},
            'internet': {'target': s['target'], 'up': s['internet_up'], 'rtt_ms': s['target_rtt_ms']},
            'consecutive_failures': s['consecutive_failures'],
            'last_check': s['last_check'],
            'last_change': s['last_change'],
            'hours': hours,
            'checks': total,
            'availability_pct': round(up / total * 100, 1) if total else None,
            'avg_rtt_ms': round(sum(rtts) / len(rtts), 1) if rtts else None,
            'check_interval': self.interval(),
            'timeline': timeline,
        }

    # ---- loop ---------------------------------------------------------------
    def start_monitoring(self):
        self.is_running = True
        self._stop_event.clear()
        logger.info("Starting WAN monitor")
        while not self._stop_event.is_set():
            record_heartbeat('WanMonitor')
            wait = DEFAULTS['wan_check_interval']
            try:
                with self.app.app_context():
                    self.check_once()
                    wait = self.interval()
            except Exception as e:
                logger.error(f"WAN check failed: {e}")
                try:
                    with self.app.app_context():
                        db.session.rollback()
                except Exception:
                    pass
            self._stop_event.wait(wait)
        self.is_running = False

    def stop(self):
        self._stop_event.set()
