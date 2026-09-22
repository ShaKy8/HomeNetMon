"""Which alerts reach a phone, and when.

Alerts are always recorded (the Alerts page is the log); this policy only decides
whether ``AlertManager.send_alert_notifications`` pushes / mails / posts one, and
whether the scanner announces a finished scan. Runtime settings (Settings >
Alerts & notifications), read at send time so no reload hook is needed:

    notify_device_down       true   ``device_down``
    notify_device_recovery   false  ``device_recovery`` (off by default: the timeline shows it)
    notify_new_device        true   ``new_device``
    notify_security          true   ``security_*``
    notify_scan_complete     false  the "Network Scan Complete" push after every scan
    notify_quiet_hours_start ''     hour 0-23 (local clock); blank = no quiet hours
    notify_quiet_hours_end   ''     hour 0-23; the window may wrap midnight

Everything else (high_latency, performance, wan_down, gateway_down, wan_recovery)
is allowed by type. During quiet hours only ``critical`` alerts get through.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from models import Configuration

DEFAULTS = {
    'notify_device_down': 'true',
    'notify_device_recovery': 'false',
    'notify_new_device': 'true',
    'notify_security': 'true',
    'notify_scan_complete': 'false',
    'notify_quiet_hours_start': '',
    'notify_quiet_hours_end': '',
}
TYPE_KEYS = ('notify_device_down', 'notify_device_recovery', 'notify_new_device', 'notify_security',
             'notify_scan_complete')


def _as_bool(value) -> bool:
    return str(value).strip().lower() in ('true', '1', 'yes', 'on')


def _as_hour(value) -> int | None:
    text = str(value if value is not None else '').strip()
    if text == '':
        return None
    try:
        hour = int(text)
    except ValueError:
        return None
    return hour if 0 <= hour <= 23 else None


@dataclass
class NotificationPolicy:
    device_down: bool = True
    device_recovery: bool = False
    new_device: bool = True
    security: bool = True
    scan_complete: bool = False
    quiet_start: int | None = None
    quiet_end: int | None = None

    @classmethod
    def load(cls) -> 'NotificationPolicy':
        """Read the runtime settings (must run inside an app context)."""
        def setting(key):
            value = Configuration.get_value(key)
            return DEFAULTS[key] if value is None else value
        return cls(
            device_down=_as_bool(setting('notify_device_down')),
            device_recovery=_as_bool(setting('notify_device_recovery')),
            new_device=_as_bool(setting('notify_new_device')),
            security=_as_bool(setting('notify_security')),
            scan_complete=_as_bool(setting('notify_scan_complete')),
            quiet_start=_as_hour(setting('notify_quiet_hours_start')),
            quiet_end=_as_hour(setting('notify_quiet_hours_end')),
        )

    def in_quiet_hours(self, now: datetime | None = None) -> bool:
        """Local wall clock; both hours set and different, window may wrap midnight."""
        if self.quiet_start is None or self.quiet_end is None or self.quiet_start == self.quiet_end:
            return False
        hour = (now or datetime.now()).hour
        if self.quiet_start < self.quiet_end:
            return self.quiet_start <= hour < self.quiet_end
        return hour >= self.quiet_start or hour < self.quiet_end

    def allows(self, alert_type: str, severity: str = 'warning', now: datetime | None = None) -> tuple[bool, str]:
        """(allowed, reason) for one alert; reason is '' when allowed."""
        alert_type = alert_type or ''
        if alert_type == 'device_down' and not self.device_down:
            return False, 'device-down notifications are off'
        if alert_type == 'device_recovery' and not self.device_recovery:
            return False, 'recovery notifications are off'
        if alert_type == 'new_device' and not self.new_device:
            return False, 'new-device notifications are off'
        if alert_type.startswith('security_') and not self.security:
            return False, 'security notifications are off'
        if severity != 'critical' and self.in_quiet_hours(now):
            return False, f'quiet hours ({self.quiet_start:02d}:00-{self.quiet_end:02d}:00)'
        return True, ''

    def allows_event(self, event: str, now: datetime | None = None) -> bool:
        """Non-alert pushes: 'scan_complete'."""
        if event == 'scan_complete':
            return self.scan_complete and not self.in_quiet_hours(now)
        return not self.in_quiet_hours(now)
