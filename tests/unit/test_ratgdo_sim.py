"""Tests for scripts/dev/ratgdo_sim.py, the ESPHome ratgdo board simulator.

The simulator is an operational one-shot outside the package tree, so it is
loaded by file path. Each test gets a fresh server on an ephemeral port.
"""

import importlib.util
import threading
import time
from pathlib import Path

import pytest
import requests

SIM_PATH = Path(__file__).resolve().parents[2] / "scripts" / "dev" / "ratgdo_sim.py"
TIMEOUT = 2


def _load_sim():
    spec = importlib.util.spec_from_file_location("ratgdo_sim", SIM_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ratgdo_sim = _load_sim()


@pytest.fixture
def sim_factory():
    """Start simulators on 127.0.0.1:0; returns (base_url, state). All are torn down after the test."""
    started = []

    def _start(travel=0.3, **kwargs):
        server, state = ratgdo_sim.make_server("127.0.0.1", 0, travel=travel, **kwargs)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        thread.start()
        started.append((server, state))
        return f"http://127.0.0.1:{server.server_address[1]}", state

    yield _start
    for server, state in started:
        server.shutdown()
        server.server_close()
        state.stop()


@pytest.fixture
def sim(sim_factory):
    url, _ = sim_factory()
    return url


def get(url, path, **kwargs):
    return requests.get(url + path, timeout=TIMEOUT, **kwargs)


def post(url, path, **kwargs):
    return requests.post(url + path, timeout=TIMEOUT, **kwargs)


def door(url):
    return get(url, "/cover/door").json()


def wait_until(url, predicate, timeout=2.0):
    """Poll GET /cover/door until predicate(json) is true; return the last payload."""
    deadline = time.monotonic() + timeout
    payload = door(url)
    while not predicate(payload):
        if time.monotonic() > deadline:
            pytest.fail(f"door never reached expected state; last={payload}")
        time.sleep(0.05)
        payload = door(url)
    return payload


def test_initial_door_is_closed_and_idle(sim):
    payload = door(sim)
    assert payload == {"id": "cover-door", "state": "CLOSED", "value": 0.0, "current_operation": "IDLE"}


def test_open_completes_travel_and_counts_opening(sim):
    assert get(sim, "/sensor/openings").json()["value"] == 0
    resp = post(sim, "/cover/door/open")
    assert resp.status_code == 200
    assert resp.content == b""

    payload = wait_until(sim, lambda d: d["current_operation"] == "IDLE" and d["value"] == 1.0)
    assert payload["state"] == "OPEN"

    openings = get(sim, "/sensor/openings").json()
    assert openings == {"id": "sensor-openings", "state": "1", "value": 1}


def test_stop_mid_travel_holds_position(sim_factory):
    url, _ = sim_factory(travel=2.0)
    post(url, "/cover/door/open")
    wait_until(url, lambda d: 0 < d["value"] < 1)
    assert post(url, "/cover/door/stop").status_code == 200

    payload = door(url)
    assert payload["current_operation"] == "IDLE"
    assert 0 < payload["value"] < 1
    assert payload["state"] == "OPEN"
    assert get(url, "/binary_sensor/motor").json()["state"] == "OFF"

    time.sleep(0.3)
    assert door(url)["value"] == payload["value"], "a stopped door must not creep"


def test_light_toggle(sim):
    assert get(sim, "/light/light").json() == {"id": "light-light", "state": "OFF", "value": False}
    post(sim, "/light/light/toggle")
    assert get(sim, "/light/light").json() == {"id": "light-light", "state": "ON", "value": True}
    post(sim, "/light/light/turn_off")
    assert get(sim, "/light/light").json()["state"] == "OFF"


def test_lock_and_unlock_remotes(sim):
    assert get(sim, "/lock/lock_remotes").json()["state"] == "UNLOCKED"
    post(sim, "/lock/lock_remotes/lock")
    assert get(sim, "/lock/lock_remotes").json() == {"id": "lock-lock_remotes", "state": "LOCKED", "value": True}
    post(sim, "/lock/lock_remotes/unlock")
    assert get(sim, "/lock/lock_remotes").json()["value"] is False


def test_obstruction_while_closing_reverses(sim_factory):
    url, _ = sim_factory(travel=2.0)
    post(url, "/cover/door/open")
    wait_until(url, lambda d: d["value"] == 1.0 and d["current_operation"] == "IDLE", timeout=3.0)
    post(url, "/cover/door/close")
    wait_until(url, lambda d: d["current_operation"] == "CLOSING")

    resp = post(url, "/_sim/obstruction", json={"state": True})
    assert resp.status_code == 200
    assert door(url)["current_operation"] == "OPENING"
    assert get(url, "/binary_sensor/obstruction").json()["state"] == "ON"
    assert get(url, "/_sim/state").json()["door"] == "opening"


def test_new_id_style_uses_display_names(sim_factory):
    url, _ = sim_factory(id_style="new")
    assert door(url)["id"] == "cover/Door"
    assert get(url, "/lock/lock_remotes").json()["id"] == "lock/Lock remotes"
    assert get(url, "/text_sensor/firmware_version").json()["id"] == "text_sensor/Firmware Version"


def test_basic_auth_required_when_configured(sim_factory):
    url, _ = sim_factory(auth="u:p")
    resp = get(url, "/cover/door")
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == 'Basic realm="ratgdo"'
    assert post(url, "/cover/door/open").status_code == 401

    resp = get(url, "/cover/door", auth=("u", "p"))
    assert resp.status_code == 200
    assert resp.json()["state"] == "CLOSED"
    assert get(url, "/cover/door", auth=("u", "wrong")).status_code == 401


def test_unknown_routes_are_json_404(sim):
    resp = get(sim, "/cover/nope")
    assert resp.status_code == 404
    assert resp.json() == {"error": "not found"}
    assert post(sim, "/cover/door/fly").status_code == 404


def test_root_page_and_detail_query(sim):
    resp = get(sim, "/")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/html")
    assert door(sim) == get(sim, "/cover/door?detail=all").json()


def test_sse_stream_sends_cover_state(sim):
    resp = requests.get(sim + "/events", stream=True, timeout=5)
    try:
        assert resp.status_code == 200
        assert resp.headers["Content-Type"] == "text/event-stream"
        assert resp.headers["Cache-Control"] == "no-cache"
        last_event = None
        found = False
        for line in resp.iter_lines(decode_unicode=True):
            if line.startswith("event:"):
                last_event = line.split(":", 1)[1].strip()
            elif line.startswith("data:") and last_event == "state" and '"cover-door"' in line:
                found = True
                break
        assert found
    finally:
        resp.close()
