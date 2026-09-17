# Garage Door from the Ring "Garage Cam"

HomeNetMon shows whether the garage door is **open or closed** by looking at the Ring camera that
points at it. Nothing here can move the door: the camera is the sensor. The reading lives on the
**Smart Home** page (`/smart-home`) and in a Garage tile on the dashboard.

## How it works

1. On a schedule (every 15 minutes by default) the app fetches the camera's most recent stored
   snapshot from Ring. After Ring reports **motion** at the garage it asks the camera for a fresh
   frame about 45 seconds later (once the recording has ended); **Check now** on the page does the
   same.
2. A frame that looks identical to the last one is ignored (a local pixel comparison). Everything
   else goes to **Claude** with a fixed prompt; the answer is *open*, *closed* or *unknown* with a
   confidence and a one-line reason.
3. A confident reading becomes the door state. Every change is recorded with the frame that caused
   it (Recent activity shows the thumbnail), feeds the openings chart and stats, and can raise
   alerts through your usual channels (ntfy, email, webhook, Discord):

   | Alert | Raised when | Resolves when |
   |---|---|---|
   | Garage door left open | Open longer than *Left open after* (15 min by default) | The door is read as closed |
   | Garage door open during quiet hours | Open during the configured hours (informational) | The door is read as closed |
   | Garage camera unavailable | Ring or the model failed three checks in a row | A check succeeds again |

Readings below 60 % confidence, or where the door is not visible, keep the previous state. Night
(infrared) frames are read like any other and flagged on the page.

## Why not myQ

myQ has no local API and Chamberlain blocks third-party use of its cloud API. Ring's own
"Partner API" is only for certified app publishers (with a watermark on every image). So the
integration signs in to Ring the same way Home Assistant's Ring integration does: with the
unofficial `ring-doorbell` library. It is unofficial, so Ring could break it without notice; it
is isolated in `services/ring_client.py`.

## Setup

1. **Claude API key.** Create one at console.anthropic.com and put it in `.env`:
   `ANTHROPIC_API_KEY=sk-ant-...`, then restart the service. Without it frames are fetched but
   never read; the page says so.
2. **Ring app: Snapshot Capture.** For a battery camera, turn on *Snapshot Capture* for the Garage
   Cam (Device settings → Video settings) so Ring always holds a recent frame. Battery cameras
   only take a new picture every few minutes and never while recording; wired cameras answer a
   fresh-frame request in seconds.
3. **Settings → Garage door.**
   - *Ring account*: email + password → **Sign in to Ring** → enter the code Ring sends → sign in
     again. The password is sent to Ring once and never stored; only the sign-in token is kept, in
     `RING_TOKEN_FILE` (`production_data/ring_token.json` by default, mode 0600). **Sign out**
     deletes it.
   - *Camera*: **Refresh**, pick the garage camera. *Check every* (default 900 s; 120 s minimum) and
     *After Ring motion* (check sooner).
   - *Reading the picture*: the Claude model (`claude-opus-5` by default; `claude-sonnet-5` and
     `claude-haiku-4-5` are cheaper), optional *scene notes* ("white sectional door, camera looks
     down from the left") that help the model, and how often an unchanged frame is re-read
     (60 min).
   - *Alerts*: left-open minutes and quiet hours (this server's local time; blank disables).
   - Tick **Enable the garage camera**, **Save**.
4. Open **Smart Home** and press **Check now**.

## What it costs

A 1024-pixel frame is roughly 1,100 input tokens. At Anthropic's list prices one reading is about
$0.01 on `claude-opus-5`, $0.004 on `claude-sonnet-5` and $0.002 on `claude-haiku-4-5`. With a check
every 15 minutes, only changed frames read, and a forced re-read once an hour, a typical day is
20–60 readings: on the order of $0.20–0.60 a day on Opus 5, far less on Haiku. The page shows
today's readings and their estimated cost; the `vision` block of `GET /api/garage` carries the
numbers.

## Privacy and trust

- The Ring token and the saved frames (`production_data/garage_cam/`, the latest frame plus the
  last 100 door-event frames) live next to the database, readable by the service user only, and
  are gitignored.
- HomeNetMon has no login: **anyone who can reach the dashboard can see the latest camera frame**
  (`/api/garage/snapshot.jpg`) and trigger a check. Same trust model as the rest of the app; front
  it with an authenticating proxy if that matters.
- Frames go to Anthropic's API for the reading; nothing else leaves the LAN.

## Troubleshooting

- **"Garage camera unavailable"**: Ring rejected the token (sign in again in Settings), Ring is
  down, or the Claude key is wrong. The alert message names the last error; so does the page.
- **The reading is wrong at night / in glare**: add scene notes; the model reports *night* and the
  confidence floor keeps the last state on doubtful frames. A wired camera or a higher Snapshot
  Capture cadence gives better frames.
- **The frame is old**: the page shows the frame's age. For a battery camera the stored frame is
  only as fresh as Snapshot Capture; press **Check now** or wait for the next motion.
- **Signed out unexpectedly**: Ring rotates tokens; if refresh fails the app forgets the token and
  the page asks for a new sign-in.

## Developer notes

`services/ring_client.py` (RingBridge: one asyncio loop in a daemon thread), `services/door_vision.py`
(frame gate + Claude call), `services/garage_monitor.py` (ticker thread `GarageMonitor`, events,
alerts, `garage_status` push), `api/garage.py`. Tests: `pytest tests/unit/services/test_ring_client.py
tests/unit/services/test_door_vision.py tests/unit/services/test_garage_monitor.py
tests/unit/test_garage_api.py`. Both external services are faked in the tests; no network is needed.
