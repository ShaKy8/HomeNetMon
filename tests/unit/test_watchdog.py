"""The outside watchdog (scripts/ops/homenetmon_watchdog.py) and its contract with the app.

Why it exists: HomeNetMon was down for 44 hours (2026-09-29) because an OS upgrade removed the venv's
Python, and nothing could say so. These tests pin the behaviour that would have told the user within
minutes, and the properties that stop the watchdog from failing the same way."""

import ast
import importlib.util
import json
import re
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/ops/homenetmon_watchdog.py'

_spec = importlib.util.spec_from_file_location('homenetmon_watchdog', SCRIPT)
wd = importlib.util.module_from_spec(_spec)
sys.modules['homenetmon_watchdog'] = wd
_spec.loader.exec_module(wd)

T0 = 1_800_000_000.0   # an arbitrary fixed "now"
MIN = 60


class World:
    """Fake network and systemd for one watchdog: health answers, pushes sent, heartbeats pinged."""

    def __init__(self, tmp_path, env=None):
        base = {'PORT': '5000', 'WATCHDOG_STATE_DIR': str(tmp_path / 'state'), 'NTFY_TOPIC': 'test-topic',
                'NTFY_SERVER': 'https://ntfy.example', 'NTFY_ENABLED': 'true', 'DATABASE_URL': 'sqlite:////nonexistent/x.db',
                'BASE_URL': 'http://geekom1.example:5000', 'WATCHDOG_HEARTBEAT_URL': 'https://hc.example/ping/abc'}
        base.update(env or {})
        self.settings = wd.load_settings(base)
        self.local = {'status': 200, 'body': {'success': True}, 'error': None}
        self.lan = {'status': 200, 'body': {'success': True}, 'error': None}
        self.lan_address = '192.168.1.42'
        self.pushes, self.beats, self.push_ok = [], [], True
        self.deps = wd.Deps(http=self._http, get_lan_ip=lambda: self.lan_address, diagnose=lambda unit: 'Service: activating (auto-restart), result exit-code, 120 restarts.\nLast log line: ModuleNotFoundError: No module named \'gunicorn\'',
                            send=self._send, heartbeat=lambda url, suffix='': self.beats.append(suffix) or True)

    def _http(self, url, timeout=10):
        return self.local if url.startswith('http://127.0.0.1') else self.lan

    def _send(self, ntfy, title, message, priority, tags, click=''):
        self.pushes.append({'title': title, 'message': message, 'priority': priority, 'tags': tags, 'click': click, 'topic': ntfy['topic']})
        return self.push_ok

    def down(self, error='connection refused'):
        self.local = {'status': None, 'body': None, 'error': error}

    def up(self):
        self.local = {'status': 200, 'body': {'success': True}, 'error': None}

    def run(self, minute):
        return wd.run_check(self.settings, T0 + minute * MIN, self.deps)

    def run_through(self, start, end, step=5):
        """Check every few minutes like the timer would, so a long outage is not mistaken for a monitoring gap."""
        for minute in range(start, end + 1, step):
            self.run(minute)

    def state(self):
        return wd.load_state(self.settings['state_dir'])


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


class TestOutageLifecycle:

    def test_healthy_checks_send_nothing_and_ping_the_heartbeat(self, world):
        for m in range(3):
            assert world.run(m) == 0
        assert world.pushes == [] and world.beats == ['', '', '']
        assert world.state()['last_run'] == T0 + 2 * MIN

    def test_alerts_on_the_third_failed_check_exactly_once(self, world):
        world.down()
        world.run(0); world.run(1)
        assert world.pushes == []                      # a restart or deploy takes about a minute: not an outage yet
        world.run(2)
        assert len(world.pushes) == 1
        push = world.pushes[0]
        assert push['title'] == 'HomeNetMon watchdog: DOWN' and push['priority'] == 4 and push['tags'] == ['rotating_light']
        assert 'no answer on 127.0.0.1:5000 (connection refused)' in push['message']
        assert "ModuleNotFoundError: No module named 'gunicorn'" in push['message']      # the diagnostic that names the cause
        assert push['click'] == 'http://geekom1.example:5000' and push['topic'] == 'test-topic'
        world.run(3); world.run(4)
        assert len(world.pushes) == 1                   # no repeat every minute

    def test_a_crash_loop_is_not_suppressed(self, world):
        # systemd shows "activating (auto-restart)" for the whole crash loop; the watchdog must not treat that as "starting up"
        world.down()
        for m in range(3):
            world.run(m)
        assert len(world.pushes) == 1

    def test_reminder_after_six_hours_then_every_six(self, world):
        world.down()
        for m in range(3):
            world.run(m)
        world.run_through(5, 5 * 60)                    # 5 h in: quiet
        assert len(world.pushes) == 1
        world.run_through(5 * 60 + 5, 6 * 60 + 5)
        assert len(world.pushes) == 2 and '(reminder)' in world.pushes[1]['message']
        assert world.pushes[1]['title'] == 'HomeNetMon watchdog: STILL DOWN'
        world.run_through(6 * 60 + 10, 12 * 60 + 10)
        assert len(world.pushes) == 3

    def test_back_message_carries_the_outage_length_and_resets(self, world):
        world.down()
        for m in range(3):
            world.run(m)
        world.run_through(5, 44 * 60 + 20)
        world.up()
        world.run(44 * 60 + 25)
        back = world.pushes[-1]
        assert back['title'] == 'HomeNetMon watchdog: BACK' and '44 h 25 min' in back['message']
        assert back['tags'] == ['white_check_mark']
        assert world.state().get('alerted') is None and world.state().get('fails') is None
        titles = [p['title'] for p in world.pushes]
        assert titles.count('HomeNetMon watchdog: BACK') == 1 and titles.count('HomeNetMon watchdog: DOWN') == 1
        assert titles.count('HomeNetMon watchdog: STILL DOWN') == 7                  # one every six hours of the 44
        world.down()
        for m in range(1, 4):
            world.run(44 * 60 + 25 + m)
        titles = [p['title'] for p in world.pushes]
        assert titles[-1] == 'HomeNetMon watchdog: DOWN' and titles.count('HomeNetMon watchdog: DOWN') == 2   # a new outage alerts again

    def test_a_failed_push_is_retried_every_minute_until_it_gets_through(self, world):
        world.down()
        world.push_ok = False
        assert [world.run(m) for m in range(4)] == [0, 0, 1, 1]      # exit 1 = a due push was not delivered
        assert world.state().get('alerted') is None
        world.push_ok = True
        assert world.run(4) == 0 and world.state()['alerted'] is True
        assert len(world.pushes) == 3                    # two failed attempts, one delivered
        world.run(5)
        assert len(world.pushes) == 3

    def test_degraded_names_the_stale_threads_and_escalates_to_down(self, world):
        world.local = {'status': 503, 'body': {'stale_threads': ['WanMonitor', 'AlertManager']}, 'error': 'HTTP 503'}
        for m in range(3):
            world.run(m)
        assert world.pushes[0]['title'] == 'HomeNetMon watchdog: DEGRADED'
        assert 'WanMonitor, AlertManager' in world.pushes[0]['message'] and world.pushes[0]['tags'] == ['warning']
        world.down()
        world.run(3)
        assert world.pushes[1]['title'] == 'HomeNetMon watchdog: DOWN'       # got worse: say so now, not in six hours

    def test_answering_on_loopback_only_is_down(self, world):
        world.lan = {'status': None, 'body': None, 'error': 'connection refused'}
        for m in range(3):
            world.run(m)
        assert 'answers on 127.0.0.1 but not on 192.168.1.42:5000' in world.pushes[0]['message']
        assert 'bind address' in world.pushes[0]['message']

    def test_http_500_is_down(self, world):
        world.local = {'status': 500, 'body': None, 'error': 'HTTP 500'}
        for m in range(3):
            world.run(m)
        assert 'answered HTTP 500' in world.pushes[0]['message']

    def test_threshold_and_reminder_are_configurable(self, tmp_path):
        w = World(tmp_path, {'WATCHDOG_FAIL_THRESHOLD': '1', 'WATCHDOG_REMINDER_HOURS': '1'})
        w.down()
        w.run(0)
        assert len(w.pushes) == 1
        w.run_through(5, 61)
        assert len(w.pushes) == 2


class TestGapNotice:

    def test_silence_after_a_reboot_is_reported_once(self, world):
        world.run(0)
        world.run(47)                                    # 47 minutes without a check
        notices = [p for p in world.pushes if 'interrupted' in p['title']]
        assert len(notices) == 1 and '47 min' in notices[0]['message'] and notices[0]['priority'] == 2
        world.run(48)
        assert len([p for p in world.pushes if 'interrupted' in p['title']]) == 1

    def test_first_run_has_no_gap_and_normal_cadence_has_none(self, world):
        world.run(0)
        world.run(1)
        world.run(10)                                    # exactly the threshold: not a gap
        assert world.pushes == []

    def test_gap_notice_is_retried_when_the_network_is_not_back_yet(self, world):
        world.run(0)
        world.push_ok = False
        world.run(30)
        world.push_ok = True
        world.run(31)
        assert [p['title'] for p in world.pushes].count('HomeNetMon watchdog: checks were interrupted') == 2   # failed, then delivered
        world.run(32)
        assert [p['title'] for p in world.pushes].count('HomeNetMon watchdog: checks were interrupted') == 2


class TestPause:

    def test_pause_suppresses_alerts_then_expires(self, world):
        world.down()
        wd.main(['--pause', '10'], env={'WATCHDOG_STATE_DIR': str(world.settings['state_dir'])}, now=T0)
        for m in range(1, 9):
            world.run(m)
        assert world.pushes == []
        world.run(11)                                    # pause over, still failing for 11 checks
        assert len(world.pushes) == 1

    def test_resume_ends_a_pause(self, world):
        env = {'WATCHDOG_STATE_DIR': str(world.settings['state_dir'])}
        wd.main(['--pause', '600'], env=env, now=T0)
        wd.main(['--resume'], env=env, now=T0)
        world.down()
        for m in range(1, 4):
            world.run(m)
        assert len(world.pushes) == 1

    def test_heartbeat_keeps_flowing_during_a_pause(self, world):
        world.down()
        wd.main(['--pause', '30'], env={'WATCHDOG_STATE_DIR': str(world.settings['state_dir'])}, now=T0)
        world.run(1); world.run(2)
        assert world.beats == ['', '']                   # planned maintenance must not page you through the external service


class TestHeartbeat:

    def test_pinged_while_healthy_and_fail_once_when_down_is_confirmed(self, world):
        world.run(0)
        world.down()
        world.run(1); world.run(2)
        assert world.beats == ['', '', '']               # not confirmed yet: still "alive"
        world.run(3)
        assert world.beats[-1] == '/fail'
        world.run(4)
        assert world.beats.count('/fail') == 1 and world.beats[-1] == '/fail'   # no success pings while confirmed down
        world.up()
        world.run(5)
        assert world.beats[-1] == ''                     # success ping marks it up again

    def test_nothing_is_sent_when_no_url_is_configured(self, tmp_path):
        beats = []
        assert wd.ping_heartbeat('', opener=lambda *a, **k: beats.append(1)) is False and beats == []

    def test_ping_builds_the_fail_url(self):
        seen = []

        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False

        assert wd.ping_heartbeat('https://hc.example/ping/abc/', '/fail', opener=lambda url, timeout: seen.append(url) or Resp())
        assert seen == ['https://hc.example/ping/abc/fail']
        assert wd.ping_heartbeat('https://hc.example/x', opener=Mock(side_effect=OSError('down'))) is False


class TestNtfyResolution:

    def _db(self, tmp_path, **rows):
        path = tmp_path / 'app.db'
        conn = sqlite3.connect(path)
        conn.execute('create table configuration (key text primary key, value text)')
        conn.executemany('insert into configuration values (?, ?)', rows.items())
        conn.commit(); conn.close()
        return path

    def test_database_wins_over_env(self, tmp_path):
        db = self._db(tmp_path, ntfy_topic='db-topic', ntfy_server='https://db.example', push_notifications_enabled='true')
        settings = wd.load_settings({'DATABASE_URL': f'sqlite:///{db}', 'NTFY_TOPIC': 'env-topic', 'WATCHDOG_STATE_DIR': str(tmp_path / 's')})
        state = {}
        ntfy = wd.resolve_ntfy(settings, state)
        assert (ntfy['topic'], ntfy['server'], ntfy['enabled']) == ('db-topic', 'https://db.example', True)
        assert state['ntfy']['topic'] == 'db-topic'      # remembered for the day the database is broken

    def test_env_when_the_database_has_no_topic(self, tmp_path):
        db = self._db(tmp_path, push_notifications_enabled='true')
        settings = wd.load_settings({'DATABASE_URL': f'sqlite:///{db}', 'NTFY_TOPIC': 'env-topic', 'NTFY_ENABLED': 'true',
                                     'NTFY_USERNAME': 'u', 'NTFY_PASSWORD': 'p', 'WATCHDOG_STATE_DIR': str(tmp_path / 's')})
        ntfy = wd.resolve_ntfy(settings, {})
        assert (ntfy['topic'], ntfy['server'], ntfy['enabled'], ntfy['username']) == ('env-topic', 'https://ntfy.sh', True, 'u')

    def test_cache_when_the_database_is_unreadable(self, tmp_path):
        settings = wd.load_settings({'DATABASE_URL': 'sqlite:////nonexistent/app.db', 'WATCHDOG_STATE_DIR': str(tmp_path / 's')})
        cached = {'ntfy': {'server': 'https://cached.example', 'topic': 'cached-topic', 'enabled': True}}
        assert wd.resolve_ntfy(settings, cached)['topic'] == 'cached-topic'
        assert wd.resolve_ntfy(settings, {}) is None

    def test_disabled_push_sends_nothing_and_reports_failure(self, tmp_path):
        db = self._db(tmp_path, ntfy_topic='t', push_notifications_enabled='false')
        w = World(tmp_path, {'DATABASE_URL': f'sqlite:///{db}'})
        w.down()
        assert [w.run(m) for m in range(3)] == [0, 0, 1]
        assert w.pushes == []

    def test_the_database_is_opened_read_only(self, tmp_path):
        db = self._db(tmp_path, ntfy_topic='t')
        before = db.stat().st_mtime_ns
        wd.resolve_ntfy(wd.load_settings({'DATABASE_URL': f'sqlite:///{db}', 'WATCHDOG_STATE_DIR': str(tmp_path / 's')}), {})
        assert db.stat().st_mtime_ns == before
        assert wd.database_path({'DATABASE_URL': 'sqlite:///relative.db'}) == ROOT / 'relative.db'
        assert wd.database_path({'DATABASE_URL': 'postgresql://x'}) is None


class TestSendNtfy:

    def test_json_publish_with_basic_auth_and_unicode_title(self):
        seen = {}

        class Resp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def opener(request, timeout):
            seen['url'], seen['body'], seen['headers'] = request.full_url, json.loads(request.data), dict(request.header_items())
            return Resp()

        ntfy = {'server': 'https://ntfy.example/', 'topic': 't', 'username': 'u', 'password': 'p'}
        assert wd.send_ntfy(ntfy, 'Café ☕ down', 'body', 4, ['warning'], 'http://x', opener=opener)
        assert seen['url'] == 'https://ntfy.example/'
        assert seen['body'] == {'topic': 't', 'title': 'Café ☕ down', 'message': 'body', 'priority': 4, 'tags': ['warning'], 'click': 'http://x'}
        assert seen['headers']['Authorization'].startswith('Basic ')

    def test_failure_is_a_false_not_an_exception(self):
        assert wd.send_ntfy({'server': 'https://x', 'topic': 't'}, 'a', 'b', 3, [], opener=Mock(side_effect=OSError('no route'))) is False


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        code = 503 if self.path.endswith('degraded') else 200
        body = json.dumps({'stale_threads': ['WanMonitor']} if code == 503 else {'success': True}).encode()
        self.send_response(code); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


class TestProbe:

    @pytest.fixture
    def server(self):
        srv = HTTPServer(('127.0.0.1', 0), _Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        yield srv.server_address[1]
        srv.shutdown(); srv.server_close()

    def test_real_http_statuses(self, server):
        assert wd.probe(f'http://127.0.0.1:{server}/ok')['status'] == 200
        degraded = wd.probe(f'http://127.0.0.1:{server}/degraded')
        assert degraded['status'] == 503 and degraded['body'] == {'stale_threads': ['WanMonitor']}

    def test_refused_connection_is_reported_not_raised(self):
        import socket
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        result = wd.probe(f'http://127.0.0.1:{port}/x', timeout=2)
        assert result['status'] is None and result['error'] == 'connection refused'

    def test_evaluate_against_a_real_server(self, server):
        settings = wd.load_settings({'PORT': str(server)})
        assert wd.evaluate(settings, get_lan_ip=lambda: None) == (wd.OK, '')


class TestDiagnose:

    def test_crash_loop_shows_state_restarts_and_the_error(self):
        def run(args, timeout=5):
            if args[0] == 'systemctl':
                return 'ActiveState=activating\nSubState=auto-restart\nResult=exit-code\nNRestarts=120\n'
            return "Traceback (most recent call last):\n  File x\nModuleNotFoundError: No module named 'gunicorn'\nstatus=1\n"
        text = wd.diagnose('homenetmon', run)
        assert 'activating (auto-restart), result exit-code, 120 restarts' in text
        assert "ModuleNotFoundError: No module named 'gunicorn'" in text

    def test_clean_stop_says_so(self):
        def run(args, timeout=5):
            return 'ActiveState=inactive\nSubState=dead\nResult=success\nNRestarts=0\n' if args[0] == 'systemctl' else ''
        assert 'stopped (start it with: systemctl --user start homenetmon)' in wd.diagnose('homenetmon', run)

    def test_no_systemd_is_just_empty(self):
        assert wd.diagnose('homenetmon', lambda args, timeout=5: '') == ''


class TestCommandLine:

    def test_test_push_and_status(self, tmp_path, capsys):
        env = {'WATCHDOG_STATE_DIR': str(tmp_path / 's'), 'NTFY_TOPIC': 't', 'NTFY_ENABLED': 'true', 'DATABASE_URL': 'sqlite:////nonexistent/x.db'}
        sent = []
        deps = wd.Deps(send=lambda ntfy, title, message, priority, tags, click='': sent.append(title) or True)
        assert wd.main(['--test'], env=env, now=T0, deps=deps) == 0
        assert sent == ['HomeNetMon watchdog: test'] and 'sent' in capsys.readouterr().out
        assert wd.main(['--status'], env=env, now=T0 + 5, deps=deps) == 0
        out = capsys.readouterr().out
        assert 'last check:  never' in out and 'alerted:     no' in out

    def test_test_push_reports_failure_in_the_exit_code(self, tmp_path):
        env = {'WATCHDOG_STATE_DIR': str(tmp_path / 's'), 'DATABASE_URL': 'sqlite:////nonexistent/x.db'}   # no topic anywhere
        assert wd.main(['--test'], env=env, now=T0, deps=wd.Deps(send=Mock())) == 1

    def test_durations(self):
        assert [wd.human_duration(s) for s in (10, 3 * 60, 65 * 60, 44 * 3600 + 25 * 60)] == ['under a minute', '3 min', '1 h 05 min', '44 h 25 min']


class TestContracts:
    """The properties that stop the watchdog from failing the way the app did."""

    def test_it_imports_only_the_standard_library(self):
        tree = ast.parse(SCRIPT.read_text())
        imported = {n.names[0].name.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.Import)}
        imported |= {n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        assert imported <= set(sys.stdlib_module_names), sorted(imported - set(sys.stdlib_module_names))

    def test_the_unit_runs_system_python_never_the_venv(self):
        unit = (ROOT / 'systemd/homenetmon-watchdog.service').read_text()
        exec_start = re.search(r'^ExecStart=(.*)$', unit, re.M).group(1)
        assert exec_start.startswith('/usr/bin/python3 ') and 'venv' not in exec_start
        assert 'scripts/ops/homenetmon_watchdog.py' in exec_start and 'Type=oneshot' in unit

    def test_port_and_database_match_the_app_unit(self):
        def env_lines(name):
            return [line for line in (ROOT / 'systemd' / name).read_text().splitlines()
                    if re.match(r'(Environment=(PORT|DATABASE_URL)=|EnvironmentFile=)', line)]
        assert env_lines('homenetmon-watchdog.service') == [ln for ln in env_lines('homenetmon.user.service')]
        assert env_lines('homenetmon-watchdog.service')       # and not vacuously

    def test_timer_runs_every_minute_after_boot(self):
        timer = (ROOT / 'systemd/homenetmon-watchdog.timer').read_text()
        assert 'OnBootSec=2min' in timer and 'OnUnitActiveSec=1min' in timer
        assert 'Unit=homenetmon-watchdog.service' in timer and 'WantedBy=timers.target' in timer

    def test_the_app_and_the_script_agree_on_the_state_path(self, monkeypatch, tmp_path):
        from core import watchdog_status
        for env in ({'WATCHDOG_STATE_DIR': str(tmp_path / 'explicit')}, {'XDG_STATE_HOME': str(tmp_path / 'xdg')}, {}):
            for key in ('WATCHDOG_STATE_DIR', 'XDG_STATE_HOME'):
                monkeypatch.delenv(key, raising=False)
            for key, value in env.items():
                monkeypatch.setenv(key, value)
            assert watchdog_status.state_dir() == wd.state_dir(dict(__import__('os').environ))

    def test_installer_installs_the_watchdog(self):
        text = (ROOT / 'install.sh').read_text()
        assert 'homenetmon-watchdog' in text and 'enable --now homenetmon-watchdog.timer' in text


class TestAppSide:

    def _write_state(self, tmp_path, monkeypatch, last_run, **extra):
        monkeypatch.setenv('WATCHDOG_STATE_DIR', str(tmp_path))
        (tmp_path / 'state.json').write_text(json.dumps({'last_run': last_run, **extra}))

    def test_status_reader(self, tmp_path, monkeypatch):
        from core import watchdog_status
        monkeypatch.setenv('WATCHDOG_STATE_DIR', str(tmp_path / 'none'))
        assert watchdog_status.read()['installed'] is False and watchdog_status.stale_age() is None
        self._write_state(tmp_path, monkeypatch, time.time() - 30, kind='degraded')
        status = watchdog_status.read()
        assert status['installed'] and status['state'] == 'degraded' and 25 <= status['last_check_age_s'] <= 40
        assert watchdog_status.stale_age() is None
        self._write_state(tmp_path, monkeypatch, time.time() - 3600)
        assert watchdog_status.stale_age() >= 3600 - 5
        (tmp_path / 'state.json').write_text('garbage')
        assert watchdog_status.read()['installed'] is False          # a corrupt file never raises

    def test_health_endpoint_reports_the_watchdog_without_changing_its_status(self, client, tmp_path, monkeypatch):
        monkeypatch.setenv('WATCHDOG_STATE_DIR', str(tmp_path / 'none'))
        baseline = client.get('/api/system/health')
        assert baseline.get_json()['watchdog'] == {'installed': False, 'last_check_age_s': None, 'state': None, 'paused': False}
        self._write_state(tmp_path, monkeypatch, time.time() - 2000, kind='down')    # a stale, "down" watchdog
        response = client.get('/api/system/health')
        assert response.status_code == baseline.status_code           # the app never judges itself by the watchdog
        assert response.get_json()['watchdog']['state'] == 'down'

    def test_stale_watchdog_pushes_once_per_episode(self, app, tmp_path, monkeypatch):
        from services.resource_monitor import ResourceMonitor
        monitor = ResourceMonitor(app=app)
        monkeypatch.setattr('core.health._process_started', time.time() - 3600)
        self._write_state(tmp_path, monkeypatch, time.time() - 1200)
        with patch('services.push_notifications.push_service.send_notification') as push:
            alerted = monitor._check_outside_watchdog(False)
            assert alerted is True and push.call_count == 1
            assert 'watchdog' in push.call_args.kwargs['title'].lower() and push.call_args.kwargs['priority'] == 'high'
            assert monitor._check_outside_watchdog(True) is True and push.call_count == 1   # same episode: silent
            self._write_state(tmp_path, monkeypatch, time.time() - 20)                      # it recovered
            assert monitor._check_outside_watchdog(True) is False
            self._write_state(tmp_path, monkeypatch, time.time() - 1200)                    # and stopped again
            assert monitor._check_outside_watchdog(False) is True and push.call_count == 2

    def test_no_push_in_the_startup_grace_or_when_never_installed(self, app, tmp_path, monkeypatch):
        from services.resource_monitor import ResourceMonitor
        monitor = ResourceMonitor(app=app)
        with patch('services.push_notifications.push_service.send_notification') as push:
            self._write_state(tmp_path, monkeypatch, time.time() - 1200)
            monkeypatch.setattr('core.health._process_started', time.time() - 60)          # app just booted
            assert monitor._check_outside_watchdog(False) is False
            monkeypatch.setattr('core.health._process_started', time.time() - 3600)
            monkeypatch.setenv('WATCHDOG_STATE_DIR', str(tmp_path / 'none'))                # never installed
            assert monitor._check_outside_watchdog(False) is False
            assert push.call_count == 0
