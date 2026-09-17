#!/usr/bin/env python3
"""Local simulator of a ratgdo garage-door board running the ESPHome firmware.

A ratgdo (https://github.com/ratgdo/esphome-ratgdo) exposes ESPHome's
``web_server`` component: a REST API (``GET /<domain>/<object_id>`` returns the
entity's JSON, ``POST /<domain>/<object_id>/<action>`` drives it) plus a
Server-Sent-Events stream at ``GET /events`` that pushes every entity on
connect and again whenever one changes.  This script emulates that surface for
the entities a ratgdo v2.5i board publishes:

    cover/door              light/light             lock/lock_remotes
    binary_sensor/obstruction  binary_sensor/motion  binary_sensor/motor
    binary_sensor/button    sensor/openings         sensor/paired_devices
    text_sensor/firmware_version
    button/toggle_door, button/query_status, button/sync, button/restart

The door moves in simulated time: a full open or close takes ``--travel``
seconds, ``stop`` freezes it mid-travel, and an obstruction while closing
reverses it, like a real opener.  Test-only hooks under ``/_sim/`` inject
obstruction, motion and wall-console presses (external commands that do not
come through the REST API).

Nothing here talks to a real board.  Standard library only.

Runbook
-------
    venv/bin/python scripts/dev/ratgdo_sim.py --port 8099 --travel 3

    curl -s localhost:8099/cover/door
    curl -s -X POST localhost:8099/cover/door/open
    curl -s -N localhost:8099/events            # SSE stream
    curl -s -X POST -d '{"state": true}' localhost:8099/_sim/obstruction
    curl -s localhost:8099/_sim/state

Options: ``--host`` (default 127.0.0.1), ``--port`` (8099), ``--travel``
(12.0 s), ``--auth user:pass`` (HTTP Basic on every route, /events included),
``--id-style legacy|new`` (entity ``id`` field: ``cover-door`` vs
``cover/Door``), ``--verbose`` (request log).

Embedding (tests): ``server, state = make_server('127.0.0.1', 0, travel=0.3)``;
run ``server.serve_forever()`` in a thread, read the bound port from
``server.server_address[1]``, and finish with ``server.shutdown()`` and
``state.stop()``.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import json
import queue
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

FIRMWARE = "2025.9.0-sim"
DEVICE_NAME = "ratgdov25i-sim"
PAIRED_DEVICES = 3
TICK_SECONDS = 0.1
SSE_PING_SECONDS = 5

# (domain, object_id) -> ESPHome display name, in the order /events emits them.
DISPLAY_NAMES: dict[tuple[str, str], str] = {
    ("cover", "door"): "Door",
    ("light", "light"): "Light",
    ("lock", "lock_remotes"): "Lock remotes",
    ("binary_sensor", "obstruction"): "Obstruction",
    ("binary_sensor", "motion"): "Motion",
    ("binary_sensor", "motor"): "Motor",
    ("binary_sensor", "button"): "Button",
    ("sensor", "openings"): "Openings",
    ("sensor", "paired_devices"): "Paired Devices",
    ("text_sensor", "firmware_version"): "Firmware Version",
}
ENTITIES = list(DISPLAY_NAMES)

COVER = ("cover", "door")
LIGHT = ("light", "light")
LOCK = ("lock", "lock_remotes")
OBSTRUCTION = ("binary_sensor", "obstruction")
MOTION = ("binary_sensor", "motion")
MOTOR = ("binary_sensor", "motor")
OPENINGS = ("sensor", "openings")

DOOR_STATES = ("closed", "open", "opening", "closing", "stopped")


class SimState:
    """Mutable board state plus the 10 Hz tick thread that moves the door."""

    def __init__(self, travel: float = 12.0, id_style: str = "legacy") -> None:
        if id_style not in ("legacy", "new"):
            raise ValueError(f"id_style must be 'legacy' or 'new', not {id_style!r}")
        self.travel = float(travel)
        self.id_style = id_style
        self.firmware = FIRMWARE
        self.name = DEVICE_NAME

        self.door = "closed"
        self.position = 0.0
        self.light = False
        self.lock = False
        self.obstruction = False
        self.motion = False
        self.motor = False
        self.openings = 0

        self._lock = threading.Lock()
        self._subscribers: list[queue.Queue] = []
        self._sub_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._tick_loop, daemon=True, name="ratgdo-sim-tick")
        self._thread.start()

    # -- lifecycle ---------------------------------------------------------

    def stop(self) -> None:
        """Stop the tick thread (idempotent)."""
        self._stop_event.set()
        if self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._thread.join(timeout=2)

    def _tick_loop(self) -> None:
        last = time.monotonic()
        while not self._stop_event.wait(TICK_SECONDS):
            now = time.monotonic()
            dt, last = now - last, now
            with self._lock:
                if not self.motor:
                    continue
                step = dt / self.travel if self.travel > 0 else 1.0
                if self.door == "opening":
                    self.position = min(1.0, self.position + step)
                    if self.position >= 1.0:
                        self.door, self.motor = "open", False
                elif self.door == "closing":
                    self.position = max(0.0, self.position - step)
                    if self.position <= 0.0:
                        self.door, self.motor = "closed", False
                else:  # defensive: motor on without travel direction
                    self.motor = False
                self._broadcast_locked([COVER, MOTOR])

    # -- entity ids / JSON -------------------------------------------------

    def entity_id(self, domain: str, object_id: str) -> str:
        if self.id_style == "new":
            return f"{domain}/{DISPLAY_NAMES[(domain, object_id)]}"
        return f"{domain}-{object_id}"

    def entity_json(self, domain: str, object_id: str) -> dict | None:
        with self._lock:
            return self._entity_json_locked(domain, object_id)

    def _entity_json_locked(self, domain: str, object_id: str) -> dict | None:
        key = (domain, object_id)
        if key not in DISPLAY_NAMES:
            return None
        ident = self.entity_id(domain, object_id)
        if key == COVER:
            closed = self.door == "closed" and self.position == 0.0
            if self.door == "opening":
                op = "OPENING"
            elif self.door == "closing":
                op = "CLOSING"
            else:
                op = "IDLE"
            return {
                "id": ident,
                "state": "CLOSED" if closed else "OPEN",
                "value": self.position,
                "current_operation": op,
            }
        if key == LIGHT:
            return {"id": ident, "state": "ON" if self.light else "OFF", "value": self.light}
        if key == LOCK:
            return {"id": ident, "state": "LOCKED" if self.lock else "UNLOCKED", "value": self.lock}
        if domain == "binary_sensor":
            value = {
                "obstruction": self.obstruction,
                "motion": self.motion,
                "motor": self.motor,
                "button": False,
            }[object_id]
            return {"id": ident, "state": "ON" if value else "OFF", "value": value}
        if key == OPENINGS:
            return {"id": ident, "state": str(self.openings), "value": self.openings}
        if key == ("sensor", "paired_devices"):
            return {"id": ident, "state": str(PAIRED_DEVICES), "value": PAIRED_DEVICES}
        if key == ("text_sensor", "firmware_version"):
            return {"id": ident, "state": self.firmware, "value": self.firmware}
        return None  # pragma: no cover - every key above is handled

    def snapshot(self) -> dict:
        """Full internal state (the /_sim/state hook)."""
        with self._lock:
            return {
                "name": self.name,
                "firmware": self.firmware,
                "door": self.door,
                "position": self.position,
                "light": self.light,
                "lock": self.lock,
                "obstruction": self.obstruction,
                "motion": self.motion,
                "motor": self.motor,
                "openings": self.openings,
                "travel": self.travel,
                "id_style": self.id_style,
            }

    # -- SSE fan-out -------------------------------------------------------

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue()
        with self._sub_lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._sub_lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _broadcast_locked(self, keys: list[tuple[str, str]]) -> None:
        payloads = [json.dumps(self._entity_json_locked(*key)) for key in keys]
        with self._sub_lock:
            for q in self._subscribers:
                for payload in payloads:
                    q.put(("state", payload))

    # -- door commands -----------------------------------------------------

    def _start_opening_locked(self) -> None:
        if self.door == "closed":
            self.openings += 1
            self._broadcast_locked([OPENINGS])
        self.door, self.motor = "opening", True

    def _start_closing_locked(self) -> None:
        self.door, self.motor = "closing", True

    def open_door(self) -> None:
        with self._lock:
            if self.door in ("open", "opening"):
                return
            self._start_opening_locked()
            self._broadcast_locked([COVER, MOTOR])

    def close_door(self) -> None:
        with self._lock:
            if self.door in ("closed", "closing"):
                return
            self._start_closing_locked()
            self._broadcast_locked([COVER, MOTOR])

    def stop_door(self) -> None:
        with self._lock:
            if self.door not in ("opening", "closing"):
                return
            self.door, self.motor = "stopped", False
            self._broadcast_locked([COVER, MOTOR])

    def toggle_door(self) -> None:
        """closed->open, open->close, opening->stop, closing->stop, stopped->open."""
        with self._lock:
            if self.door in ("closed", "stopped"):
                self._start_opening_locked()
            elif self.door == "open":
                self._start_closing_locked()
            else:  # opening / closing
                self.door, self.motor = "stopped", False
            self._broadcast_locked([COVER, MOTOR])

    # -- other entities ----------------------------------------------------

    def set_light(self, on: bool) -> None:
        with self._lock:
            self.light = bool(on)
            self._broadcast_locked([LIGHT])

    def toggle_light(self) -> None:
        with self._lock:
            self.light = not self.light
            self._broadcast_locked([LIGHT])

    def set_lock(self, locked: bool) -> None:
        with self._lock:
            self.lock = bool(locked)
            self._broadcast_locked([LOCK])

    def set_obstruction(self, present: bool) -> None:
        with self._lock:
            self.obstruction = bool(present)
            changed = [OBSTRUCTION]
            if self.obstruction and self.door == "closing":
                # A real opener stops and reverses when the beam is broken.
                self.door, self.motor = "opening", True
                changed += [COVER, MOTOR]
            self._broadcast_locked(changed)

    def set_motion(self, detected: bool) -> None:
        with self._lock:
            self.motion = bool(detected)
            self._broadcast_locked([MOTION])


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

DOOR_ACTIONS = {
    "open": SimState.open_door,
    "close": SimState.close_door,
    "stop": SimState.stop_door,
    "toggle": SimState.toggle_door,
}
LIGHT_ACTIONS = {
    "turn_on": lambda s: s.set_light(True),
    "turn_off": lambda s: s.set_light(False),
    "toggle": SimState.toggle_light,
}
LOCK_ACTIONS = {
    "lock": lambda s: s.set_lock(True),
    "unlock": lambda s: s.set_lock(False),
}
BUTTON_PRESS = {
    "toggle_door": SimState.toggle_door,
    "query_status": lambda s: None,
    "sync": lambda s: None,
    "restart": lambda s: None,
}


class RatgdoSimServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, state: SimState, auth: str | None, verbose: bool) -> None:
        self.state = state
        self.auth_header = None
        if auth:
            if ":" not in auth:
                raise ValueError("--auth expects user:pass")
            self.auth_header = "Basic " + base64.b64encode(auth.encode()).decode()
        self.verbose = verbose
        super().__init__(address, handler)

    def handle_error(self, request, client_address) -> None:
        # Clients dropping an SSE stream are routine; stay quiet unless asked.
        if self.verbose:
            super().handle_error(request, client_address)


class RatgdoHandler(BaseHTTPRequestHandler):
    server: RatgdoSimServer
    server_version = "ratgdo-sim/1.0"

    # -- plumbing ----------------------------------------------------------

    def log_message(self, fmt, *args) -> None:
        if self.server.verbose:
            super().log_message(fmt, *args)

    def _authorized(self) -> bool:
        expected = self.server.auth_header
        if expected is None:
            return True
        supplied = self.headers.get("Authorization", "")
        if hmac.compare_digest(supplied.encode(), expected.encode()):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="ratgdo"')
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _send_json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_empty(self, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _not_found(self) -> None:
        self._send_json({"error": "not found"}, 404)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    def _parts(self) -> list[str]:
        path = urlsplit(self.path).path
        return [p for p in path.split("/") if p]

    # -- GET ---------------------------------------------------------------

    def do_GET(self) -> None:
        if not self._authorized():
            return
        parts = self._parts()
        if not parts:
            self._send_html()
            return
        if parts == ["events"]:
            self._serve_events()
            return
        if parts == ["_sim", "state"]:
            self._send_json(self.server.state.snapshot())
            return
        if len(parts) == 2:
            payload = self.server.state.entity_json(parts[0], parts[1])
            if payload is not None:
                self._send_json(payload)
                return
        self._not_found()

    def _send_html(self) -> None:
        snap = self.server.state.snapshot()
        rows = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in snap.items())
        body = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>{DEVICE_NAME}</title></head><body>"
            f"<h1>{DEVICE_NAME}</h1><p>ESPHome ratgdo simulator</p>"
            f"<table>{rows}</table>"
            "<p>REST: GET /cover/door, POST /cover/door/open|close|stop|toggle, "
            "GET /events (SSE), GET /_sim/state</p>"
            "</body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse(self, event: str, data: str) -> None:
        self.wfile.write(f"event: {event}\ndata: {data}\n\n".encode())

    def _serve_events(self) -> None:
        state = self.server.state
        q = state.subscribe()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            self._sse("ping", "")
            for domain, object_id in ENTITIES:
                self._sse("state", json.dumps(state.entity_json(domain, object_id)))
            self.wfile.flush()
            while True:
                try:
                    event, data = q.get(timeout=SSE_PING_SECONDS)
                except queue.Empty:
                    event, data = "ping", ""
                self._sse(event, data)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            state.unsubscribe(q)

    # -- POST --------------------------------------------------------------

    def do_POST(self) -> None:
        if not self._authorized():
            return
        parts = self._parts()
        state = self.server.state

        if len(parts) == 2 and parts[0] == "_sim":
            body = self._read_json_body()
            hook = parts[1]
            if hook == "obstruction":
                state.set_obstruction(bool(body.get("state", False)))
            elif hook == "motion":
                state.set_motion(bool(body.get("state", False)))
            elif hook == "wall_button":
                state.toggle_door()
            else:
                self._not_found()
                return
            self._send_empty()
            return

        if len(parts) != 3:
            self._not_found()
            return
        domain, object_id, action = parts
        table = None
        if (domain, object_id) == COVER:
            table = DOOR_ACTIONS
        elif (domain, object_id) == LIGHT:
            table = LIGHT_ACTIONS
        elif (domain, object_id) == LOCK:
            table = LOCK_ACTIONS
        elif domain == "button" and action == "press":
            table = BUTTON_PRESS
            action = object_id
        if table is None or action not in table:
            self._not_found()
            return
        table[action](state)
        self._send_empty()


# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------


def make_server(
    host: str,
    port: int,
    travel: float,
    auth: str | None = None,
    id_style: str = "legacy",
    verbose: bool = False,
) -> tuple[ThreadingHTTPServer, SimState]:
    """Build a bound (not yet serving) server and its state. ``port=0`` picks a free port."""
    state = SimState(travel=travel, id_style=id_style)
    try:
        server = RatgdoSimServer((host, port), RatgdoHandler, state, auth, verbose)
    except Exception:
        state.stop()
        raise
    return server, state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ESPHome ratgdo garage-door simulator")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8099, help="bind port (default 8099)")
    parser.add_argument("--travel", type=float, default=12.0, help="seconds for a full open/close (default 12)")
    parser.add_argument("--auth", default=None, metavar="USER:PASS", help="require HTTP Basic auth on every route")
    parser.add_argument("--id-style", choices=("legacy", "new"), default="legacy", help="entity id format")
    parser.add_argument("--verbose", action="store_true", help="log every request")
    args = parser.parse_args(argv)

    server, state = make_server(args.host, args.port, args.travel, auth=args.auth, id_style=args.id_style, verbose=args.verbose)
    host, port = server.server_address[:2]
    print(f"{DEVICE_NAME} ({FIRMWARE}) listening on http://{host}:{port}  travel={args.travel}s  ids={args.id_style}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        server.server_close()
        state.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
