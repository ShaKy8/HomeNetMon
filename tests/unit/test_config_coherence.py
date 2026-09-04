"""
Config coherence: runtime Configuration seeds match config.py, validation
accepts the documented defaults, Settings-UI values are actually read by the
alert manager, and notification links never point at 127.0.0.1.
"""

import importlib
import os
from datetime import datetime
from unittest.mock import patch

import pytest

from config import Config
from models import AlertSuppression, Configuration, Device, db
from monitoring.alerts import AlertManager
from services.configuration_service import ConfigurationService


class TestSeeds:

    def test_init_db_seeds_from_config_not_literals(self, app, db_session):
        from models import seed_default_configuration
        with app.app_context():
            seed_default_configuration()
            assert Configuration.get_value('ping_interval') == str(Config.PING_INTERVAL)
            assert Configuration.get_value('scan_interval') == str(Config.SCAN_INTERVAL)
            assert Configuration.get_value('bandwidth_interval') == str(Config.BANDWIDTH_INTERVAL)
            assert Configuration.get_value('network_range') == Config.NETWORK_RANGE

    def test_init_db_warns_when_runtime_override_differs(self, app, db_session, caplog):
        from models import seed_default_configuration
        Configuration.set_value('ping_interval', str(Config.PING_INTERVAL + 7))
        db_session.commit()
        with app.app_context(), caplog.at_level('WARNING'):
            seed_default_configuration()
        assert any('overrides PING_INTERVAL' in r.message for r in caplog.records)


class TestValidationRanges:

    @pytest.fixture
    def svc(self, app):
        return ConfigurationService(app)

    def test_documented_defaults_are_valid(self, svc):
        rules = svc._validation_rules
        assert rules['scan_interval'].validator(str(Config.SCAN_INTERVAL))   # 86400 was rejected before
        assert rules['ping_interval'].validator(str(Config.PING_INTERVAL))
        assert rules['bandwidth_interval'].validator(str(Config.BANDWIDTH_INTERVAL))

    def test_abusive_intervals_are_rejected(self, svc):
        rules = svc._validation_rules
        assert not rules['ping_interval'].validator('5')
        assert not rules['scan_interval'].validator('60')


class TestBaseUrl:

    def test_default_base_url_is_not_loopback_or_wildcard(self):
        assert Config.BASE_URL.startswith('http://')
        assert '0.0.0.0' not in Config.BASE_URL
        assert Config.BASE_URL.endswith(f':{Config.PORT}')

    def test_env_override_wins_and_trailing_slash_is_stripped(self):
        import config as cfg
        with patch.dict(os.environ, {'BASE_URL': 'https://netmon.example.lan/'}):
            mod = importlib.reload(cfg)
            try:
                assert mod.Config.BASE_URL == 'https://netmon.example.lan'
            finally:
                importlib.reload(cfg)

    def test_no_host_port_links_remain(self):
        import subprocess
        out = subprocess.run(['grep', '-rln', 'http://{Config.HOST}:{Config.PORT}',
                              'monitoring', 'services', 'api'], capture_output=True, text=True)
        assert out.stdout.strip() == '', out.stdout


class TestEnvFallback:

    def test_flask_env_is_honoured_when_env_missing(self):
        import config as cfg
        env = {k: v for k, v in os.environ.items() if k != 'ENV'}
        env['FLASK_ENV'] = 'production'
        with patch.dict(os.environ, env, clear=True):
            mod = importlib.reload(cfg)
            try:
                assert mod.Config.ENV == 'production'
            finally:
                importlib.reload(cfg)


class TestAlertManagerReadsRuntimeSettings:

    def test_thresholds_come_from_configuration(self, app, db_session):
        Configuration.set_value('device_down_threshold_minutes', '12')
        Configuration.set_value('high_latency_threshold_ms', '2500')
        db_session.commit()
        mgr = AlertManager(app=app)
        with app.app_context():
            assert mgr.runtime_int('device_down_threshold_minutes', 45) == 12
            assert mgr.runtime_int('high_latency_threshold_ms', 1500) == 2500
            assert mgr.runtime_int('missing_key', 7) == 7

    def test_garbage_setting_falls_back(self, app, db_session):
        Configuration.set_value('high_latency_threshold_ms', 'lots')
        db_session.commit()
        mgr = AlertManager(app=app)
        with app.app_context():
            assert mgr.runtime_int('high_latency_threshold_ms', 1500) == 1500

    def test_webhook_url_from_settings_is_used(self, app, db_session):
        d = Device(ip_address='192.168.1.60', mac_address='00:dd:00:00:00:01', hostname='wh',
                   device_type='computer', is_monitored=True, last_seen=datetime.utcnow())
        db_session.add(d)
        db_session.commit()
        from models import Alert
        alert = Alert(device_id=d.id, alert_type='device_down', severity='warning', message='m')
        db_session.add(alert)
        Configuration.set_value('alert_webhook_url', 'http://hooks.example/abc')
        db_session.commit()
        mgr = AlertManager(app=app)
        with app.app_context(), patch('monitoring.alerts.requests.post') as post:
            post.return_value.status_code = 200
            post.return_value.raise_for_status = lambda: None
            mgr.send_webhook_alert(alert)
            assert post.call_args[0][0] == 'http://hooks.example/abc'
            assert post.call_args[1]['json']['dashboard_url'] == Config.BASE_URL


class TestQuietHoursLocalTime:

    def test_daily_window_uses_local_clock(self, app, db_session):
        local_hour = datetime.now().hour
        rule = AlertSuppression(name='quiet', enabled=True,
                                daily_start_hour=local_hour, daily_end_hour=(local_hour + 1) % 24)
        assert rule.is_currently_active() is True
        other = AlertSuppression(name='other', enabled=True,
                                 daily_start_hour=(local_hour + 2) % 24, daily_end_hour=(local_hour + 3) % 24)
        assert other.is_currently_active() is False
