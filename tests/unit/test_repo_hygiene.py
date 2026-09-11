"""
Guards against the documentation/deployment drift found in the 2026-09 review:
docs naming files that do not exist, the wrong unit name, the removed
ADMIN_PASSWORD, an unparseable compose file, and .env.example keys nothing reads.
"""

import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCS = [p for p in (ROOT / 'docs').glob('*.md')] + [ROOT / 'README.md', ROOT / 'CLAUDE.md']


def _read(p):
    return p.read_text(errors='replace')


class TestDocsNameRealThings:

    @pytest.mark.parametrize('ghost', ['database_performance_fix.py', 'optimize_db_queries.py', 'build_assets.py',
                                       'run_http2.py', 'comprehensive_database_health_assessment.py',
                                       'emergency_database_cleanup.py', 'PHASE_2_AUDIT_REPORT.md',
                                       'backup_production.py', 'deploy_production.py', 'performance_monitor_live.py',
                                       'optimize_database_performance.py', 'database_performance_monitor.py',
                                       'comprehensive_load_stress_test_suite.py', 'resolve_alerts.py',
                                       'reclassify_devices.py', 'production_health_check.sh', 'restart_homenetmon.sh',
                                       'startup_notification.py', 'setup_ssl.sh', 'docker-compose.prod.yml',
                                       '.env.prod.template', 'fix_ping_permissions.sh', 'logs/app.log', 'Config.load_from_file',
                                       'security/configure-firewall.sh', 'security/vulnerability-scanner.py'])
    def test_no_doc_references_deleted_files(self, ghost):
        hits = [p.name for p in DOCS if ghost in _read(p) and f'scripts/db/{ghost}' not in _read(p)
                and f'scripts/ops/{ghost}' not in _read(p) and f'scripts/perf/{ghost}' not in _read(p)]
        assert not hits, f'{ghost} referenced in {hits}'

    def test_no_admin_password_anywhere(self):
        files = DOCS + [ROOT / '.env.example', ROOT / '.env.prod.example', ROOT / 'systemd/homenetmon.service',
                        ROOT / 'systemd/homenetmon.user.service', ROOT / 'install.sh', ROOT / 'docker-compose.yml']
        hits = [str(p.relative_to(ROOT)) for p in files if p.exists() and 'ADMIN_PASSWORD' in _read(p)]
        assert not hits, hits

    def test_no_login_flow_documented(self):
        api_ref = _read(ROOT / 'docs/API_REFERENCE.md')
        assert 'http://localhost/login' not in api_ref and 'username=admin' not in api_ref
        assert 'self.login(' not in api_ref

    def test_unit_name_is_lowercase_everywhere(self):
        hits = []
        for p in DOCS + [ROOT / 'install.sh', ROOT / 'health_check.sh']:
            for m in re.finditer(r'homeNetMon\.service|systemctl [a-z -]*homeNetMon\b|journalctl -u homeNetMon\b', _read(p)):
                hits.append(f'{p.name}: {m.group(0)}')
        assert not hits, hits

    def test_readme_defaults_match_config(self):
        # Compare against the code defaults in config.py, not Config.* (which reflects the local .env).
        src = _read(ROOT / 'config.py')
        ping = re.search(r"PING_INTERVAL = int\(os\.environ\.get\('PING_INTERVAL', '(\d+)'\)\)", src).group(1)
        scan = re.search(r"SCAN_INTERVAL = int\(os\.environ\.get\('SCAN_INTERVAL', '(\d+)'\)\)", src).group(1)
        readme = _read(ROOT / 'README.md')
        assert f'| `PING_INTERVAL` | `{ping}` |' in readme
        assert f'| `SCAN_INTERVAL` | `{scan}` |' in readme


class TestDeploymentArtifacts:

    def test_docker_compose_is_a_single_document(self):
        docs = list(yaml.safe_load_all(_read(ROOT / 'docker-compose.yml')))
        assert len(docs) == 1 and 'services' in docs[0]
        env = docs[0]['services']['homeNetMon']['environment']
        assert 'PING_INTERVAL=600' in env and 'SCAN_INTERVAL=86400' in env

    @pytest.mark.parametrize('unit', ['systemd/homenetmon.service', 'systemd/homenetmon.user.service'])
    def test_systemd_units_have_the_essentials(self, unit):
        text = _read(ROOT / unit)
        assert 'ExecStart=' in text and 'DATABASE_URL=' in text
        assert 'gunicorn' in text and 'wsgi:app' in text and '--workers 1' in text   # one process: Socket.IO + threads
        assert 'MemoryDenyWriteExecute=true' not in text

    def test_shell_scripts_parse(self):
        for script in ['install.sh', 'health_check.sh', 'run_production.sh', 'setup_backup_cron.sh']:
            r = subprocess.run(['bash', '-n', str(ROOT / script)], capture_output=True, text=True)
            assert r.returncode == 0, f'{script}: {r.stderr}'

    def test_removed_surfaces_are_gone(self):
        for gone in ['k8s', 'helm', 'sdk', 'examples', 'docker', 'Dockerfile.prod', 'docker-compose.prod.yml',
                     'build_assets.py', 'run_http2.py', 'templates/noc_view.html', 'static/bundles']:
            assert not (ROOT / gone).exists(), gone


class TestEnvExample:

    def test_every_documented_key_is_read_somewhere(self):
        keys = re.findall(r'^#?\s*([A-Z][A-Z0-9_]+)=', _read(ROOT / '.env.example'), re.M)
        code = ''.join(_read(p) for p in [ROOT / 'config.py', ROOT / 'app.py', ROOT / 'api/config.py',
                                            ROOT / 'services/rate_limiter.py', ROOT / 'services/push_notifications.py',
                                            ROOT / 'core/security_middleware.py', ROOT / 'services/cdn_manager.py'])
        unread = [k for k in set(keys) if k not in code]
        assert not unread, f'.env.example documents keys nothing reads: {sorted(unread)}'

    def test_documented_intervals_are_the_gentle_defaults(self):
        text = _read(ROOT / '.env.example')
        assert 'PING_INTERVAL=600' in text and 'SCAN_INTERVAL=86400' in text and 'BANDWIDTH_INTERVAL=300' in text
