"""A gunicorn stop waits for every open connection, and a Socket.IO WebSocket never ends on its own: with a
dashboard open, the worker sat out the whole 30 s --graceful-timeout on every restart. core.shutdown chains onto
the SIGTERM handler gunicorn's worker installed and closes the Socket.IO clients. The real signal module is never
touched here: the tests hand core.shutdown a fake one."""

import signal
import threading
import time
import types
from pathlib import Path

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


def test_wsgi_installs_it():
    source = (ROOT / 'wsgi.py').read_text()
    assert 'close_live_clients_on_sigterm(socketio, stop_now=[app._monitor.request_stop])' in source


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
