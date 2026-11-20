"""scripts/generate_api_reference.py builds the app to read its routes. create_app() adds a file handler for
logs/<LOG_FILE>, and in the production checkout .env names production's log. The script points LOG_FILE at
os.devnull, so the log stays untouched even with logging enabled (the script also disables logging; this runs it
with that call made a no-op)."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN_WITH_LOGGING = (
    "import logging, runpy, sys; logging.disable = lambda level=None: None; "
    "runpy.run_path(sys.argv[1], run_name='__main__')"
)


def test_the_api_reference_script_writes_nothing_to_the_log_file(tmp_path):
    standin = tmp_path / 'standin.log'                      # where .env's LOG_FILE would point
    env = {'PATH': '/usr/bin:/bin', 'DATABASE_URL': 'sqlite:///:memory:', 'LOG_FILE': str(standin),
           'SECRET_KEY': 'test', 'HOME': str(tmp_path)}
    out = subprocess.run([sys.executable, '-c', RUN_WITH_LOGGING, str(ROOT / 'scripts' / 'generate_api_reference.py')],
                         cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.startswith('# HomeNetMon API Reference')
    assert not standin.exists() or standin.read_text() == ''
