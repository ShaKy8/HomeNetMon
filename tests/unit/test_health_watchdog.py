"""core/health.py: a thread that is alive but has never heartbeated is only in
start-up grace for one stale budget after process start; after that it is stale.
(Live evidence: SecurityScanner sat inside a multi-minute nmap sweep with no
heartbeat and was reported healthy indefinitely.)"""

import threading
import time

import core.health as health


def _with_live_thread(name, fn):
    stop = threading.Event()
    t = threading.Thread(target=stop.wait, name=name, daemon=True)
    t.start()
    try:
        return fn()
    finally:
        stop.set()
        t.join(timeout=2)


def test_no_heartbeat_is_grace_right_after_start(monkeypatch):
    name = 'SecurityScanner'
    monkeypatch.setattr(health, '_process_started', time.time())
    with health._lock:
        health._heartbeats.pop(name, None)
    result = _with_live_thread(name, health.check)
    assert result['threads'][name]['alive'] is True
    assert result['threads'][name]['stale'] is False


def test_no_heartbeat_becomes_stale_after_one_budget(monkeypatch):
    name = 'SecurityScanner'
    budget = health.EXPECTED_THREADS[name] * health.MAX_AGE_MULTIPLIER
    monkeypatch.setattr(health, '_process_started', time.time() - budget - 5)
    with health._lock:
        health._heartbeats.pop(name, None)
    result = _with_live_thread(name, health.check)
    assert result['threads'][name]['alive'] is True
    assert result['threads'][name]['stale'] is True
    assert name in result['stale']


def test_recent_heartbeat_is_never_stale(monkeypatch):
    name = 'SecurityScanner'
    monkeypatch.setattr(health, '_process_started', time.time() - 10 ** 6)
    health.record_heartbeat(name)
    result = _with_live_thread(name, health.check)
    assert result['threads'][name]['stale'] is False


def test_watchdog_does_not_list_removed_threads():
    for gone in ('ConfigurationService',):
        assert gone not in health.EXPECTED_THREADS
