# Garage Door (myQ opener) through a ratgdo board

HomeNetMon can show and control a Chamberlain / LiftMaster garage door opener, including
the myQ Wi-Fi models, from the **Smart Home** page (`/smart-home`) and a tile on the dashboard.
It does this through a small board called a **ratgdo**, not through myQ.

## Why not myQ directly

myQ has no local API and Chamberlain blocks third-party clients of its cloud API: the Home
Assistant integration was removed in 2023.12, `pymyq` was archived in June 2026 and
`homebridge-myq` is retired. Anything built on the cloud API stops working the next time
Chamberlain changes it.

A [ratgdo](https://paulwieland.github.io/ratgdo/) is an ESP board that wires into the
opener's wall-console terminals and speaks the opener's own Security+ 2.0 protocol. With the
ESPHome firmware it exposes a plain HTTP API on your LAN: door state and position, light,
remote lock-out, obstruction and motion sensors, and an event stream that pushes every change.
The myQ app keeps working next to it.

If the myQ hub sits on a **guest** Wi-Fi it never appears in HomeNetMon: guest networks are
isolated from the main LAN and HomeNetMon only sees `NETWORK_RANGE`. That is fine; the hub is
not needed for anything here.

## What you get

- **Smart Home page**: an animated door that follows the board's position, hold-to-confirm
  Open / Close (and Stop while it moves), opener light and remote lock-out switches,
  obstruction and motion indicators, an "open for" timer, openings per day for two weeks,
  recent activity with who caused it (HomeNetMon or a remote / wall button), and a grid of the
  smart-home devices HomeNetMon monitors.
- **Dashboard tile** next to the Internet tile: closed / open + time / opening / closing /
  offline. Click it to open the Smart Home page.
- **Alerts** through the normal channels (ntfy, email, webhook, Discord):

  | Alert | Raised when | Resolves when |
  |---|---|---|
  | Garage door left open | Open longer than *Left open after* (15 min by default) | The door closes |
  | Garage door open during quiet hours | Open during the configured hours (informational) | The door closes |
  | Garage door obstruction | The safety beam is blocked | The beam clears |
  | Garage controller offline | The board has not answered three polls | The board answers again |

- **History**: every door / light / lock / obstruction / online change is a `garage_events`
  row (kept for a year, `garage_retention_days`).

## Hardware

- **ratgdo32** (ESP32) is recommended: more memory for the live event stream. The older
  **ratgdo v2.5i** (ESP8266) also works.
- Order from the ratgdo site; check the compatibility table there. Every Security+ 2.0 opener
  (yellow learn button, most openers since 2011, all myQ models) is supported; older
  Security+ 1.0 and dry-contact openers are too with the matching firmware option.
- The board needs 2.4 GHz Wi-Fi where the opener is mounted.

## Setup

1. **Wire the board.** Three wires to the opener's wall-console terminals (and two to the
   obstruction sensor terminals if you want the beam sensor). Follow the wiring diagram for
   your opener on the ratgdo site; power the board from its USB supply.
2. **Flash the ESPHome firmware** with the web installer at
   <https://ratgdo.github.io/esphome-ratgdo/> (Chrome or Edge, USB cable). Pick the board and
   the Security+ 2.0 option.
3. **Join the main Wi-Fi.** The installer asks for the network; use the SSID HomeNetMon's host
   is on, not the guest network. Give the board a DHCP reservation in the router (Google Home
   app: Wi-Fi → Network settings → Advanced networking → DHCP IP reservations) so its address
   never changes.
4. **Confirm it answers.** Open `http://<board-ip>/` in a browser: the ESPHome page shows the
   door, light and sensors. Do not leave this page open all day on an ESP8266 board; it shares
   the board's few event-stream slots with HomeNetMon.
5. **Enable it in HomeNetMon.** Settings → **Garage door**:
   - Click **Find ratgdo** (after a network scan has seen the board) or type its address.
   - **Test connection** reports the door state and firmware.
   - Set *Left open after*, the quiet hours (this server's local time; blank disables) and
     the poll interval, tick **Enable**, then **Save garage settings**.
   - Username / password are only needed if you add `web_server: auth:` to the board's YAML.
     They are stored in plain text in the configuration table, like the ntfy topic.
6. Open **Smart Home**. The tile and the page go live within a few seconds.

## How it works

`services/garage_monitor.py` runs the `GarageMonitor` thread (it heartbeats even while the
feature is disabled, so `/api/system/health` always lists it). When enabled it holds one
Server-Sent-Events connection to the board (`GarageEvents` helper thread) so changes arrive
within a second, polls every `garage_poll_interval` seconds as a safety net (every 5 s while
the door moves without a live stream), writes `garage_events` rows for transitions and raises
the alerts above on the board's device row. Commands go straight to the board
(`POST /api/garage/door`, `/light`, `/lock`) and a change within 20 s of a HomeNetMon command
is recorded as *from HomeNetMon*; anything else as *remote or wall button*.

The board's own web page is the fallback: if HomeNetMon is down, the door still works from
`http://<board-ip>/`, remotes and the wall button.

## Trust model

HomeNetMon has no login. Anyone who can reach the dashboard (the LAN, or a Tailscale peer
that reaches it) can open the door. Mitigations: CSRF on every state-changing request, a strict
rate limit on the control routes, the board must be on a private address, and the page
requires a press-and-hold. If that is not acceptable for your household, put an authenticating
reverse proxy in front (see the Security Guide) or leave the integration disabled.

## Troubleshooting

- **Garage controller offline**: the board is off, on the wrong Wi-Fi or its address changed.
  `Test connection` in Settings tells you which; a DHCP reservation prevents the last one.
- **Live badge says "Polling"**: the event stream is not up (an ESP8266 board with another
  browser tab open, or Wi-Fi drops). Control still works; state updates every poll interval.
- **Door shows Unknown**: press **Query status** or **Sync** on the board's own page, then
  reload; on a fresh board the first status arrives after the first door movement.
- **Nothing found by "Find ratgdo"**: it only probes devices a scan has already seen. Run
  **Scan Network** on the dashboard once the board is on the main Wi-Fi, or type the address.

## Developer runbook (simulator)

`scripts/dev/ratgdo_sim.py` emulates a board (REST + SSE, door travel, obstruction,
optional Basic auth) so the whole feature runs without hardware:

```bash
venv/bin/python scripts/dev/ratgdo_sim.py --port 8099 --travel 3
HOST=127.0.0.1 PORT=5001 DATABASE_URL=sqlite:////tmp/hnm-e2e.db SECURITY_SCANNING_ENABLED=false venv/bin/python app.py
BASE_URL=http://127.0.0.1:5001 GARAGE_SIM_URL=http://127.0.0.1:8099 npx playwright test
```

Point the dev instance at `127.0.0.1:8099` from Settings → Garage door (or let `TestGarage.js`
do it). Unit tests: `pytest tests/unit/services/test_ratgdo_client.py
tests/unit/services/test_garage_monitor.py tests/unit/test_garage_api.py
tests/unit/services/test_garage_discovery.py tests/unit/test_ratgdo_sim.py`. Port 5000 is
production on the deployed host; never point the E2E suite at it.
