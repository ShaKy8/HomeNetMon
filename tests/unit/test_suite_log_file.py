"""The suite never writes to the checkout's logs/ folder. create_app() adds a file handler for logs/<LOG_FILE>; in
the production checkout .env names production's log there, and the default resolves to the same file, so the test
app's lines (devices nas-1, sweep-1 in 192.168.1.x) were appended to the live log. The app fixture points LOG_FILE at
a temporary file instead."""

import logging
from pathlib import Path

from config import Config


def test_no_log_handler_writes_into_the_checkouts_logs_folder(app):
    logs = (Path(Config.BASE_DIR) / 'logs').resolve()
    files = [Path(h.baseFilename).resolve() for h in logging.getLogger().handlers if hasattr(h, 'baseFilename')]
    assert files                                            # the app's file handler is there, just elsewhere
    assert [f for f in files if f.parent == logs] == []
