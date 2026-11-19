"""When a Socket.IO WebSocket ends, simple-websocket closes the socket gunicorn handed it (environ['gunicorn.socket'])
itself. gunicorn 26.2's gthread worker then counts the connection off, calls TConn.close(graceful=True), whose
setblocking() raises EBADF on the closed socket, and its except branch counts the same connection off a second
time: five dashboard tabs opened and closed left nr_conns at -5. core.gunicorn_compat makes that close unable to
raise. The real signal module and gunicorn's class are never changed here except under monkeypatch."""

import errno
import signal
import socket
import types

import pytest
from gunicorn.config import Config
from gunicorn.workers import gthread

import core.gunicorn_compat as compat

ROOT = __import__('pathlib').Path(__file__).resolve().parents[2]


def _closed_conn():
    """A real TConn whose socket was closed after gunicorn took it, as simple-websocket leaves it."""
    a, b = socket.socketpair()
    conn = gthread.TConn(Config(), a, ('127.0.0.1', 1), ('127.0.0.1', 2))
    b.close()
    a.close()
    return conn


def test_unpatched_gunicorn_still_raises_on_a_closed_socket():
    """The bug the patch exists for. When a gunicorn release guards this itself, this test fails: drop the patch."""
    with pytest.raises(OSError):
        compat._ORIGINAL_CLOSE(_closed_conn(), graceful=True)


def test_guarded_close_returns_on_a_closed_socket():
    close = compat._guarded(compat._ORIGINAL_CLOSE)
    assert close(_closed_conn(), graceful=True) is None


def test_guarded_close_returns_when_the_socket_closes_under_it():
    """simple-websocket signals its handler before it closes the socket, so fileno() can still look open when
    gunicorn starts closing: the close itself must not raise, whatever the order."""
    class Sock:
        closed = 0

        def fileno(self):
            return 7

        def setblocking(self, flag):
            raise OSError(errno.EBADF, 'Bad file descriptor')

        def close(self):
            Sock.closed += 1

    conn = types.SimpleNamespace(sock=Sock())
    close = compat._guarded(compat._ORIGINAL_CLOSE)
    assert close(conn, graceful=True) is None
    assert Sock.closed == 1                   # falls back to the plain close, as gunicorn's own except branch does


def test_guarded_close_still_closes_an_open_socket():
    a, b = socket.socketpair()
    conn = gthread.TConn(Config(), a, ('127.0.0.1', 1), ('127.0.0.1', 2))
    b.close()
    compat._guarded(compat._ORIGINAL_CLOSE)(conn, graceful=True)
    assert a.fileno() == -1


def _fake_signal(monkeypatch, handler):
    monkeypatch.setattr(compat, 'signal', types.SimpleNamespace(SIGTERM=signal.SIGTERM,
                                                                 getsignal=lambda signum: handler))


def test_installed_only_in_a_gthread_worker(monkeypatch):
    monkeypatch.setattr(gthread.TConn, 'close', compat._ORIGINAL_CLOSE)
    for handler in (signal.SIG_DFL, None, lambda signum, frame: None):
        _fake_signal(monkeypatch, handler)
        assert compat.install_closed_socket_guard() is False
        assert gthread.TConn.close is compat._ORIGINAL_CLOSE


def test_installed_once_in_a_gthread_worker(monkeypatch):
    monkeypatch.setattr(gthread.TConn, 'close', compat._ORIGINAL_CLOSE)
    worker = object.__new__(gthread.ThreadWorker)       # no __init__: only the type and the bound handler matter
    _fake_signal(monkeypatch, worker.handle_exit)
    assert compat.install_closed_socket_guard() is True
    first = gthread.TConn.close
    assert first is not compat._ORIGINAL_CLOSE
    assert compat.install_closed_socket_guard() is True
    assert gthread.TConn.close is first                 # not wrapped twice


def test_wsgi_installs_it_while_gunicorns_handler_is_still_in_place():
    """core.shutdown replaces the SIGTERM handler; the gate reads gunicorn's, so this must run first."""
    source = (ROOT / 'wsgi.py').read_text()
    assert source.index('install_closed_socket_guard()') < source.index('close_live_clients_on_sigterm(socketio)')
