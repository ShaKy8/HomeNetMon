"""monitoring/notification_policy.py: which alerts reach a phone, and when."""

from datetime import datetime

from models import Configuration
from monitoring.notification_policy import DEFAULTS, NotificationPolicy


class TestDefaults:

    def test_defaults_recorded_but_quiet_for_recovery_and_scans(self, app, db_session):
        with app.app_context():
            p = NotificationPolicy.load()
        assert p.device_down and p.new_device and p.security
        assert not p.device_recovery and not p.scan_complete
        assert p.quiet_start is None and p.quiet_end is None
        assert DEFAULTS['notify_device_recovery'] == 'false' and DEFAULTS['notify_scan_complete'] == 'false'

    def test_load_reads_runtime_settings(self, app, db_session):
        with app.app_context():
            Configuration.set_value('notify_device_recovery', 'true')
            Configuration.set_value('notify_device_down', 'false')
            Configuration.set_value('notify_quiet_hours_start', '23')
            Configuration.set_value('notify_quiet_hours_end', '7')
            p = NotificationPolicy.load()
        assert p.device_recovery is True and p.device_down is False
        assert (p.quiet_start, p.quiet_end) == (23, 7)

    def test_bad_hours_mean_no_quiet_hours(self, app, db_session):
        with app.app_context():
            Configuration.set_value('notify_quiet_hours_start', 'x')
            Configuration.set_value('notify_quiet_hours_end', '99')
            p = NotificationPolicy.load()
        assert p.quiet_start is None and p.quiet_end is None and not p.in_quiet_hours()


class TestQuietHours:

    def test_window_wraps_midnight(self):
        p = NotificationPolicy(quiet_start=23, quiet_end=7)
        assert p.in_quiet_hours(datetime(2026, 9, 22, 23, 30))
        assert p.in_quiet_hours(datetime(2026, 9, 22, 3, 0))
        assert not p.in_quiet_hours(datetime(2026, 9, 22, 7, 0))
        assert not p.in_quiet_hours(datetime(2026, 9, 22, 12, 0))

    def test_daytime_window(self):
        p = NotificationPolicy(quiet_start=9, quiet_end=17)
        assert p.in_quiet_hours(datetime(2026, 9, 22, 9, 0))
        assert not p.in_quiet_hours(datetime(2026, 9, 22, 17, 0))
        assert not p.in_quiet_hours(datetime(2026, 9, 22, 2, 0))

    def test_same_hours_or_one_missing_disable(self):
        assert not NotificationPolicy(quiet_start=5, quiet_end=5).in_quiet_hours(datetime(2026, 9, 22, 5, 0))
        assert not NotificationPolicy(quiet_start=5).in_quiet_hours(datetime(2026, 9, 22, 5, 0))


class TestAllows:

    def test_type_toggles(self):
        p = NotificationPolicy(device_down=False, device_recovery=True, new_device=False, security=False)
        assert p.allows('device_down')[0] is False
        assert p.allows('device_recovery')[0] is True
        assert p.allows('new_device')[0] is False
        assert p.allows('security_new_service')[0] is False
        assert p.allows('security_suspicious_port')[0] is False
        assert p.allows('high_latency')[0] is True
        assert p.allows('wan_down', 'critical')[0] is True

    def test_quiet_hours_block_everything_but_critical(self):
        p = NotificationPolicy(quiet_start=23, quiet_end=7)
        night = datetime(2026, 9, 22, 1, 0)
        ok, reason = p.allows('device_down', 'warning', now=night)
        assert ok is False and 'quiet hours' in reason
        assert p.allows('device_down', 'critical', now=night) == (True, '')
        assert p.allows('device_down', 'warning', now=datetime(2026, 9, 22, 12, 0)) == (True, '')

    def test_scan_complete_event(self):
        assert NotificationPolicy().allows_event('scan_complete') is False
        assert NotificationPolicy(scan_complete=True).allows_event('scan_complete') is True
        quiet = NotificationPolicy(scan_complete=True, quiet_start=0, quiet_end=23)
        assert quiet.allows_event('scan_complete', now=datetime(2026, 9, 22, 12, 0)) is False
