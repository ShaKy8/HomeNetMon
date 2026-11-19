"""Count each closed WebSocket connection once in gunicorn's gthread worker.

When a Socket.IO WebSocket ends, simple-websocket closes the socket gunicorn handed it (environ['gunicorn.socket'])
itself. gunicorn 26.2 then counts the connection off (nr_conns), calls TConn.close(graceful=True), whose
setblocking() raises EBADF on the closed socket, and its except branch counts it off a second time. Every closed
tab lowered nr_conns by one more, so a stop could stop waiting while a request was still running.

The guard: if the graceful close raises OSError, fall back to the plain close, which is what gunicorn's except
branch does, without the second count. A pre-check of the socket would not do: simple-websocket wakes its handler
before it closes the socket, so the socket can close while gunicorn is closing it.
"""

import logging
import signal

logger = logging.getLogger(__name__)

try:
    from gunicorn import util as _gunicorn_util
    from gunicorn.workers import gthread as _gthread
    _ORIGINAL_CLOSE = _gthread.TConn.close
except ImportError:                          # gunicorn is a production dependency; nothing to guard without it
    _gthread = None
    _ORIGINAL_CLOSE = None


def _guarded(original, worker=None):
    """Wrap TConn.close. With the worker, log its nr_conns after each close at DEBUG: gunicorn exposes the count
    nowhere else (gunicornc's stats leave it out), and the journal then shows whether it drifts below the real
    number of connections. Add this logger to Config.DEBUG_LOGGERS to keep its DEBUG lines at any LOG_LEVEL.
    gunicorn counts a connection off before closing it, so the value logged is the count still open."""
    def close(self, graceful=False):
        already_closed = False
        if not graceful:
            result = original(self, graceful=False)
        else:
            try:
                result = original(self, graceful=True)
            except OSError:
                _gunicorn_util.close(self.sock)    # already closed under us: the plain close never raises
                result, already_closed = None, True
        if worker is not None and logger.isEnabledFor(logging.DEBUG):
            note = ' (socket already closed)' if already_closed else ''
            logger.debug(f"gunicorn: connection closed{note}, nr_conns={getattr(worker, 'nr_conns', '?')}")
        return result
    close._closed_socket_guard = True
    return close


def install_closed_socket_guard():
    """Wrap TConn.close once, only inside a gunicorn gthread worker (found through its SIGTERM handler, which
    gunicorn installs before it imports the app). Returns True when the guard is in place."""
    if _gthread is None:
        return False
    worker = getattr(signal.getsignal(signal.SIGTERM), '__self__', None)
    if not isinstance(worker, _gthread.ThreadWorker):
        return False
    if not getattr(_gthread.TConn.close, '_closed_socket_guard', False):
        _gthread.TConn.close = _guarded(_gthread.TConn.close, worker)
        logger.info("gunicorn: closed WebSocket connections are counted once")
    return True
