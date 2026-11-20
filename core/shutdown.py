"""Let a gunicorn stop end in seconds instead of sitting out --graceful-timeout.

On SIGTERM gunicorn's gthread worker stops accepting and waits for every open connection to finish. Two kinds
never finished in time, so with a page open each stop took the full 30 s:
- a Socket.IO WebSocket never ends on its own. Closing the Engine.IO sockets ends those requests; the pages see
  a transport close and reconnect by themselves.
- an idle keep-alive connection, or a new one that sent nothing for 5 s, is closed only once its --keep-alive
  time has run out, and the shutdown loop then sleeps on select() for the whole remaining timeout. Marking them
  due at SIGTERM lets gunicorn's own cleanup close them as its loop wakes.
A new connection that has not sent its first data yet held a stop up for 5 s more (7 s if the client does not
close when the server does): gunicorn waits for that data in a pool thread, on a selector of its own, before the
connection reaches either list. That wait also watches a pipe the SIGTERM handler writes to (_wake_first_data_waits).
"""

import logging
import os
import selectors
import signal
import socket
import threading

logger = logging.getLogger(__name__)

try:
    from gunicorn.workers import gthread as _gthread
except ImportError:                          # gunicorn is a production dependency; nothing to wake without it
    _gthread = None

_wake_fds = None                             # (read end, write end) once installed in this worker process


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
    wake = _wake_first_data_waits(getattr(previous, '__self__', None))
    if wake is not None:
        stop_now += (wake,)

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


def _wake_first_data_waits(worker):
    """In a gthread worker, make TConn.wait_for_data also watch a pipe and return the signal-safe callable that
    writes to it. The byte is never read, so the pipe stays readable: every wait under way returns at once, and so
    does any later one. A connection woken this way, with no data, gets SHUT_RD, so gunicorn's graceful close finds
    the read side ended instead of lingering 2 s for a client that does not close. One whose data is there is
    served as before. Returns None outside a gthread worker."""
    global _wake_fds
    if _gthread is None or not isinstance(worker, _gthread.ThreadWorker):
        return None
    if _wake_fds is None:
        read_fd, write_fd = os.pipe()
        os.set_blocking(write_fd, False)
        _wake_fds = (read_fd, write_fd)
    if not getattr(_gthread.TConn.wait_for_data, '_wakes_at_stop', False):
        _gthread.TConn.wait_for_data = _waking_wait_for_data(_wake_fds[0])
    write_fd = _wake_fds[1]

    def wake():
        try:
            os.write(write_fd, b'x')
        except OSError:                      # a full pipe is already readable
            pass
    return wake


def _waking_wait_for_data(wake_fd):
    """gunicorn 26.2's TConn.wait_for_data, plus the wake pipe (tests/unit/test_graceful_stop.py pins the original)."""
    def wait_for_data(self, timeout):
        if self.data_ready:
            return True
        sel = selectors.DefaultSelector()
        try:
            sel.register(self.sock, selectors.EVENT_READ)
            sel.register(wake_fd, selectors.EVENT_READ)
            ready = {key.fileobj for key, _ in sel.select(timeout=timeout)}
        except (OSError, ValueError):
            return False                     # socket closed or invalid, as in the original
        finally:
            sel.close()
        if self.sock in ready:
            self.data_ready = True
            return True
        # Only the stop's wake, with no data yet. gunicorn would still have served a request arriving in the rest of
        # the 5 s; it is now closed unanswered, as it would be once the worker has gone (a client retries it).
        if ready:
            try:
                self.sock.shutdown(socket.SHUT_RD)
            except OSError:
                pass
        return False
    wait_for_data._wakes_at_stop = True
    return wait_for_data


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
