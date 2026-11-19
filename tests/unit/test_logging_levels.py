"""Config.setup_logging keeps LOG_LEVEL for the app, but lets core.gunicorn_compat log at DEBUG to both the
console (the journal under systemd) and the log file: gunicorn exposes nr_conns nowhere else."""

import logging

import pytest

from config import Config


@pytest.fixture
def fresh_logging(tmp_path, monkeypatch):
    """Run setup_logging into a temporary log file, then put the test session's logging back as it was."""
    root = logging.getLogger()
    saved = (root.level, list(root.handlers), logging.getLogger('core.gunicorn_compat').level)
    monkeypatch.setattr(Config, 'BASE_DIR', tmp_path)
    monkeypatch.setattr(Config, 'LOG_FILE', 'app.log')

    def setup(level):
        monkeypatch.setattr(Config, 'LOG_LEVEL', level)
        Config.setup_logging()
        return tmp_path / 'logs' / 'app.log'

    yield setup
    for handler in root.handlers:
        if handler not in saved[1]:
            handler.close()
    root.handlers[:] = saved[1]
    root.setLevel(saved[0])
    logging.getLogger('core.gunicorn_compat').setLevel(saved[2])


def _emit():
    logging.getLogger('core.gunicorn_compat').debug('compat debug line')
    logging.getLogger('core.gunicorn_compat.child').debug('compat child debug line')
    logging.getLogger('monitoring.monitor').debug('other debug line')
    logging.getLogger('monitoring.monitor').info('other info line')
    for handler in logging.getLogger().handlers:
        handler.flush()


def test_gunicorn_compat_logs_debug_while_the_app_stays_at_info(fresh_logging, capsys):
    log_file = fresh_logging('INFO')
    _emit()
    console = capsys.readouterr().err
    written = log_file.read_text()
    for out in (console, written):
        assert 'compat debug line' in out
        assert 'compat child debug line' in out
        assert 'other info line' in out
        assert 'other debug line' not in out


def test_log_level_still_governs_the_rest_of_the_app(fresh_logging, capsys):
    log_file = fresh_logging('WARNING')
    _emit()
    console = capsys.readouterr().err
    written = log_file.read_text()
    for out in (console, written):
        assert 'compat debug line' in out
        assert 'other info line' not in out             # the root logger still drops it at LOG_LEVEL, as before
