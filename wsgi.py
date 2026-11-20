"""WSGI entry point for gunicorn (production) and other WSGI servers.

    gunicorn --workers 1 --worker-class gthread --threads 32 --bind 0.0.0.0:5000 wsgi:app

Exactly one worker: Socket.IO state and the background monitoring threads live in
this process (no message queue). gthread with `simple-websocket` carries the
WebSocket transport; each open socket pins a thread, hence --threads 32. Do not
use --preload (the monitoring threads must start inside the worker).
`python app.py` remains the development entry point.
"""

from app import create_app
from core.gunicorn_compat import install_closed_socket_guard
from core.shutdown import close_live_clients_on_sigterm

app, socketio = create_app()
# gunicorn counted each closed WebSocket off twice (core/gunicorn_compat.py). Before the next line: it finds the
# worker through gunicorn's own SIGTERM handler, which close_live_clients_on_sigterm replaces.
install_closed_socket_guard()
# A stop otherwise waits out --graceful-timeout for open Socket.IO pages and idle connections (core/shutdown.py),
# and 5 to 7 s for ping retries and presence checks after SIGTERM kills the running pings (monitoring/monitor.py).
close_live_clients_on_sigterm(socketio, stop_now=[app._monitor.request_stop])
