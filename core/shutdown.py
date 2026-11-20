"""Let a gunicorn stop end in seconds instead of sitting out --graceful-timeout.

On SIGTERM gunicorn's gthread worker stops accepting and waits for every open connection to finish. Two kinds
never finished in time, so with a page open each stop took the full 30 s:
- a Socket.IO WebSocket never ends on its own. Closing the Engine.IO sockets ends those requests; the pages see
  a transport close and reconnect by themselves.
- an idle keep-alive (or not yet used) connection is closed only once its --keep-alive time has run out, and the
  shutdown loop then sleeps on select() for the whole remaining timeout. Marking them due at SIGTERM lets
  gunicorn's own cleanup close them as its loop wakes.
"""

import logging
import signal
import threading

logger = logging.getLogger(__name__)


def close_live_clients_on_sigterm(socketio, stop_now=()):
    """Chain onto the worker's SIGTERM handler: run it, call each of ``stop_now``, mark idle connections due, close
    the Socket.IO clients.

    ``stop_now`` takes callables that must run inside the handler itself, on every signal, such as
    DeviceMonitor.request_stop: systemd's SIGTERM kills the running pings at the same moment, and the monitor has
    to know it is stopping before those pings come back as failures. They must be safe in a signal handler (no
    logging, no locks the main thread may hold); one that raises does not stop the others.

    gunicorn installs its handlers before it imports the app (wsgi.py), so this runs after them. Under
    `python app.py` or pytest SIGTERM is not a callable handler and nothing is installed. Returns True when the
    chain is installed.
    """
    previous = signal.getsignal(signal.SIGTERM)
    if not callable(previous):
        return False
    started = threading.Event()
    stop_now = tuple(stop_now)

    def handler(signum, frame):
        previous(signum, frame)
        for stop in stop_now:
            try:
                stop()
            except Exception:                # nothing may escape a signal handler, and logging is not safe here
                pass
        _mark_idle_connections_due(getattr(previous, '__self__', None))
        if started.is_set():                 # systemd and the master both signal the worker
            return
        started.set()
        threading.Thread(target=_close_all, args=(socketio,), daemon=True, name='CloseLiveClients').start()

    signal.signal(signal.SIGTERM, handler)
    # signal.signal() drops the restart flag gunicorn set so that SIGTERM does not interrupt system calls of
    # requests still running: set it again
    if hasattr(signal, 'siginterrupt'):
        signal.siginterrupt(signal.SIGTERM, False)
    return True


def _mark_idle_connections_due(worker):
    """gunicorn's gthread worker keeps idle connections in these two lists and closes each once its timeout has
    passed. Only the timeouts change here, on the worker's own main thread (signal handlers run there); gunicorn
    closes the connections itself. Anything else is not a gthread worker and is left alone."""
    for name in ('keepalived_conns', 'pending_conns'):
        for conn in list(getattr(worker, name, None) or ()):
            if hasattr(conn, 'timeout'):
                conn.timeout = 0


def _close_all(socketio):
    """Close each client in a thread of its own: a close waits for the client to take its close packet, and a
    polling client whose next request never comes (the worker no longer accepts) would hold up the rest."""
    try:
        eio = socketio.server.eio
        sids = list(eio.sockets)
    except Exception as e:
        logger.warning(f"Could not list Socket.IO clients at shutdown: {e}")
        return
    logger.info(f"Shutting down: closing {len(sids)} Socket.IO client(s)")
    for sid in sids:
        threading.Thread(target=_close_one, args=(eio, sid), daemon=True, name='CloseLiveClient').start()


def _close_one(eio, sid):
    try:
        eio.disconnect(sid)
    except Exception as e:
        logger.warning(f"Could not close Socket.IO client {sid} at shutdown: {e}")
