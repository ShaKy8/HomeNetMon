"""A gunicorn stop waits for every open connection, and a Socket.IO WebSocket never ends on its own: with a
dashboard open, the worker sat out the whole 30 s --graceful-timeout on every restart. core.shutdown chains onto
the SIGTERM handler gunicorn's worker installed and closes the Socket.IO clients. The real signal module is never
touched here: the tests hand core.shutdown a fake one."""

import os
import signal
import socket
import threading
import time
import types
from pathlib import Path

import pytest
from gunicorn import util as gunicorn_util
from gunicorn.config import Config
from gunicorn.workers import gthread

import core.shutdown as shutdown

ROOT = Path(__file__).resolve().parents[2]


class FakeEio:
    def __init__(self, sids, hang=()):
        self.sockets = {sid: object() for sid in sids}
        self.hang = set(hang)
        self.closed = []
        self.release = threading.Event()

    def disconnect(self, sid=None):
        if sid in self.hang:
            self.release.wait(5)
        self.closed.append(sid)


def _socketio(eio):
    return types.SimpleNamespace(server=types.SimpleNamespace(eio=eio))


def _fake_signal(monkeypatch, previous):
    installed = {}
    fake = types.SimpleNamespace(SIGTERM=signal.SIGTERM, getsignal=lambda signum: previous,
                                 signal=lambda signum, handler: installed.__setitem__(signum, handler),
                                 siginterrupt=lambda signum, flag: installed.__setitem__(('siginterrupt', signum), flag))
    monkeypatch.setattr(shutdown, 'signal', fake)
    return installed


def _wait_for(predicate, seconds=2.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_sigterm_runs_gunicorns_handler_then_closes_every_client_once(monkeypatch):
    calls = []
    installed = _fake_signal(monkeypatch, lambda signum, frame: calls.append(signum))
    eio = FakeEio(['a', 'b'])
    assert shutdown.close_live_clients_on_sigterm(_socketio(eio)) is True
    handler = installed[signal.SIGTERM]
    handler(signal.SIGTERM, None)
    handler(signal.SIGTERM, None)            # systemd and the master both signal the worker
    assert calls == [signal.SIGTERM, signal.SIGTERM]
    assert _wait_for(lambda: len(eio.closed) == 2)
    time.sleep(0.1)
    assert sorted(eio.closed) == ['a', 'b']


def test_a_client_that_never_drains_does_not_hold_the_others(monkeypatch):
    installed = _fake_signal(monkeypatch, lambda signum, frame: None)
    eio = FakeEio(['stuck', 'b', 'c'], hang=['stuck'])
    shutdown.close_live_clients_on_sigterm(_socketio(eio))
    installed[signal.SIGTERM](signal.SIGTERM, None)
    try:
        assert _wait_for(lambda: sorted(eio.closed) == ['b', 'c'])
    finally:
        eio.release.set()


def test_the_handler_returns_at_once(monkeypatch):
    """Closing happens off the signal handler: gunicorn's main loop must keep running to drain connections."""
    installed = _fake_signal(monkeypatch, lambda signum, frame: None)
    eio = FakeEio(['stuck'], hang=['stuck'])
    shutdown.close_live_clients_on_sigterm(_socketio(eio))
    started = time.monotonic()
    installed[signal.SIGTERM](signal.SIGTERM, None)
    eio.release.set()
    assert time.monotonic() - started < 0.5


def test_idle_connections_are_due_at_once(monkeypatch):
    """gunicorn's gthread worker closes an idle keep-alive (or not yet used) connection only once its 2 s have run
    out, and its shutdown loop then sleeps on select() for the whole remaining timeout: one idle browser
    connection held the stop for 30 s. The handler marks them due; gunicorn's own cleanup closes them when the
    loop wakes. Nothing else of the worker is touched."""
    class Conn:
        def __init__(self):
            self.timeout = time.monotonic() + 2

    class Worker:
        def __init__(self):
            self.keepalived_conns = [Conn(), Conn()]
            self.pending_conns = [Conn()]

        def handle_exit(self, signum, frame):
            pass

    worker = Worker()
    installed = _fake_signal(monkeypatch, worker.handle_exit)
    shutdown.close_live_clients_on_sigterm(_socketio(FakeEio([])))
    installed[signal.SIGTERM](signal.SIGTERM, None)
    conns = worker.keepalived_conns + worker.pending_conns
    assert len(conns) == 3 and all(c.timeout <= time.monotonic() for c in conns)


def test_a_plain_function_handler_still_works(monkeypatch):
    """Not a gunicorn worker's bound method: the clients are still closed, nothing else is attempted."""
    installed = _fake_signal(monkeypatch, lambda signum, frame: None)
    eio = FakeEio(['a'])
    shutdown.close_live_clients_on_sigterm(_socketio(eio))
    installed[signal.SIGTERM](signal.SIGTERM, None)
    assert _wait_for(lambda: eio.closed == ['a'])


def test_nothing_is_installed_without_a_callable_handler(monkeypatch):
    """python app.py and pytest leave SIGTERM at its default: only gunicorn's worker gets the chain."""
    for previous in (signal.SIG_DFL, signal.SIG_IGN, None):
        installed = _fake_signal(monkeypatch, previous)
        assert shutdown.close_live_clients_on_sigterm(_socketio(FakeEio(['a']))) is False
        assert installed == {}


def test_sigterm_still_does_not_interrupt_system_calls(monkeypatch):
    """gunicorn sets siginterrupt(SIGTERM, False) so running requests are not disturbed; signal.signal() drops it."""
    installed = _fake_signal(monkeypatch, lambda signum, frame: None)
    shutdown.close_live_clients_on_sigterm(_socketio(FakeEio([])))
    assert installed[('siginterrupt', signal.SIGTERM)] is False


def test_stop_now_runs_in_the_handler_after_gunicorns_on_every_signal(monkeypatch):
    """The monitor's stop flag must be set inside the handler, before the pings systemd just killed come back as
    failures; one callable that raises must not keep the others from running or break the handler."""
    calls = []
    installed = _fake_signal(monkeypatch, lambda signum, frame: calls.append('gunicorn'))

    def broken():
        raise RuntimeError('boom')
    shutdown.close_live_clients_on_sigterm(_socketio(FakeEio([])),
                                          stop_now=[broken, lambda: calls.append('monitor')])
    installed[signal.SIGTERM](signal.SIGTERM, None)
    installed[signal.SIGTERM](signal.SIGTERM, None)
    assert calls == ['gunicorn', 'monitor', 'gunicorn', 'monitor']


# A new connection that has not sent its first data yet: gunicorn waits for that data in a pool thread, on a
# selector of its own, for up to 5 s, and the stop waited with it (7 s for a client that does not close). These use
# real gunicorn connections on a TCP loopback pair; TConn.wait_for_data is patched only under monkeypatch.

class _Worker(gthread.ThreadWorker):
    def __init__(self):                      # only what the SIGTERM chain touches
        self.alive = True
        self.keepalived_conns = []
        self.pending_conns = []

    def handle_exit(self, signum, frame):
        self.alive = False


@pytest.fixture
def first_data(monkeypatch):
    """Restore TConn.wait_for_data and the wake pipe after the test; yield a maker of (TConn, client socket)."""
    monkeypatch.setattr(gthread.TConn, 'wait_for_data', gthread.TConn.wait_for_data)
    monkeypatch.setattr(shutdown, '_wake_fds', None, raising=False)
    listener = socket.create_server(('127.0.0.1', 0))
    opened = []

    def connect():
        client = socket.create_connection(listener.getsockname())
        server_side, addr = listener.accept()
        opened.extend((client, server_side))
        return gthread.TConn(Config(), server_side, addr, listener.getsockname()), client
    yield connect
    for sock in opened:
        sock.close()
    listener.close()
    for fd in getattr(shutdown, '_wake_fds', None) or ():
        os.close(fd)


def _install_on_gthread_worker(monkeypatch):
    worker = _Worker()
    installed = _fake_signal(monkeypatch, worker.handle_exit)
    assert shutdown.close_live_clients_on_sigterm(_socketio(FakeEio([]))) is True
    return worker, installed[signal.SIGTERM]


def _wait_in_thread(conn, timeout=5.0):
    result = {}
    thread = threading.Thread(target=lambda: result.setdefault('ready', conn.wait_for_data(timeout)), daemon=True)
    thread.start()
    return thread, result


def test_sigterm_ends_a_wait_for_first_data(monkeypatch, first_data):
    worker, handler = _install_on_gthread_worker(monkeypatch)
    conn, _client = first_data()             # the client stays open and sends nothing, and never closes
    thread, result = _wait_in_thread(conn)
    time.sleep(0.2)
    assert thread.is_alive()                 # really waiting for first data
    handler(signal.SIGTERM, None)
    thread.join(1.0)
    assert not thread.is_alive() and result == {'ready': False}
    assert worker.alive is False
    # gunicorn now closes it gracefully (finish_request): the read side is already ended, so no 2 s linger
    started = time.monotonic()
    gunicorn_util.close_graceful(conn.sock)
    assert time.monotonic() - started < 0.5


def test_after_sigterm_a_new_wait_returns_at_once(monkeypatch, first_data):
    _worker, handler = _install_on_gthread_worker(monkeypatch)
    handler(signal.SIGTERM, None)
    handler(signal.SIGTERM, None)            # systemd and the master both signal the worker
    conn, _client = first_data()
    started = time.monotonic()
    assert conn.wait_for_data(5.0) is False
    assert time.monotonic() - started < 0.5


def test_data_that_is_there_is_still_served_after_sigterm(monkeypatch, first_data):
    _worker, handler = _install_on_gthread_worker(monkeypatch)
    conn, client = first_data()
    client.sendall(b'GET / HTTP/1.1\r\n')
    time.sleep(0.05)
    handler(signal.SIGTERM, None)
    assert conn.wait_for_data(5.0) is True and conn.data_ready is True


def test_without_a_stop_the_wait_is_unchanged(monkeypatch, first_data):
    _install_on_gthread_worker(monkeypatch)
    conn, client = first_data()
    # data arriving during the wait is served
    thread, result = _wait_in_thread(conn)
    time.sleep(0.1)
    client.sendall(b'GET')
    thread.join(1.0)
    assert result == {'ready': True}
    # a plain timeout returns False and leaves the socket alone: the slow client goes on to pending_conns
    other, other_client = first_data()
    assert other.wait_for_data(0.2) is False
    other_client.sendall(b'late')
    other.sock.setblocking(True)
    other.sock.settimeout(1)
    assert other.sock.recv(10) == b'late'


def test_the_wait_is_patched_only_in_a_gthread_worker(monkeypatch, first_data):
    original = gthread.TConn.wait_for_data
    _fake_signal(monkeypatch, lambda signum, frame: None)
    shutdown.close_live_clients_on_sigterm(_socketio(FakeEio([])))
    assert gthread.TConn.wait_for_data is original and getattr(shutdown, '_wake_fds', None) is None


def test_wsgi_installs_it():
    source = (ROOT / 'wsgi.py').read_text()
    assert 'close_live_clients_on_sigterm(socketio, stop_now=[app._monitor.request_stop, app._scanner.request_stop])' in source


# The fix leans on the installed gunicorn and Engine.IO. A version bump that renames these would quietly bring the
# 30 s stop back while the tests above, built on fakes, stay green: pin the real ones.

def test_gunicorn_installs_its_sigterm_handler_before_it_loads_the_app():
    import inspect

    from gunicorn.workers.base import Worker
    init = inspect.getsource(Worker.init_process)
    assert init.index('self.init_signals()') < init.index('self.load_wsgi()')
    assert 'signal.signal(signal.SIGTERM, self.handle_exit)' in inspect.getsource(Worker.init_signals)


def test_gunicorn_gthread_keeps_idle_connections_in_timed_lists():
    import inspect

    from gunicorn.workers.gthread import ThreadWorker
    init = inspect.getsource(ThreadWorker.__init__)
    assert 'self.keepalived_conns' in init and 'self.pending_conns' in init
    for name, attr in (('murder_keepalived', 'keepalived_conns'), ('murder_pending', 'pending_conns')):
        source = inspect.getsource(getattr(ThreadWorker, name))
        assert f'self.{attr}' in source and 'conn.timeout' in source, name
    assert callable(ThreadWorker.handle_exit)


def test_engineio_server_can_list_and_close_its_clients(app):
    eio = app.socketio.server.eio
    assert isinstance(eio.sockets, dict)
    assert callable(eio.disconnect)


def test_gunicorn_waits_for_first_data_in_the_pool_thread():
    """_waking_wait_for_data copies TConn.wait_for_data and relies on handle() deferring and finish_request()
    closing a deferred connection once the worker is stopping."""
    import inspect
    wait = inspect.getsource(gthread.TConn.wait_for_data)
    for line in ('if self.data_ready:', 'sel = selectors.DefaultSelector()',
                 'sel.register(self.sock, selectors.EVENT_READ)', 'events = sel.select(timeout=timeout)',
                 'self.data_ready = True', 'except (OSError, ValueError):', 'sel.close()'):
        assert line in wait, line
    handle = inspect.getsource(gthread.ThreadWorker.handle)
    assert 'if not conn.wait_for_data(DEFAULT_WORKER_DATA_TIMEOUT):' in handle and 'return _DEFER' in handle
    finish = inspect.getsource(gthread.ThreadWorker.finish_request)
    assert 'if result is _DEFER and self.alive:' in finish and 'conn.close(graceful=True)' in finish
