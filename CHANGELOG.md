# Changelog

All notable changes to HomeNetMon will be documented in this file.

## [2.8.1] - 2026-09-20

Alert noise. Nine days of running produced 232 device-down alerts, 628 recovery alerts and
78 "device online" pushes, almost all for phones, tablets and laptops that were home the whole time.

### Fixed
- The scanner took every entry in the kernel's ARP cache as a device seen just now, STALE entries
  hours old included, so each scan "recovered" every sleeping device and 45 minutes later its
  failing pings raised a fresh down alert. Only neighbours the kernel has confirmed (REACHABLE)
  count now (`monitoring/neighbors.py`); `arp -a` remains the fallback where iproute2 is missing.
- A failed ping is followed by a neighbour-table check: a host that answers ARP within 12 s is
  present. Phones and tablets ignore ICMP while asleep but still answer ARP, so they stay up and
  raise no alert; a host whose probes FAIL is down as before. The response-time history still
  records the missed ping.
- A device-down alert resolves when the device has been seen since the alert was raised, and
  exactly one recovery alert (and push) is created at that moment. The separate recovery checker,
  which fired every cycle the device merely looked recent, is gone.

## [2.8.0] - 2026-09-18

The garage door feature is gone. Neither the ratgdo board (2.6.0) nor the Ring camera reading
(2.7.0) was ever configured; the Ring app on a phone does the job. The code, page, settings,
table, alerts and dependencies are removed rather than left disabled.

### Removed
- The Smart Home page (`/smart-home`), the dashboard Garage tile and the navbar entry.
- `services/garage_monitor.py`, `services/ring_client.py`, `services/door_vision.py`, `api/garage.py`,
  the `garage_*` settings and Settings section, the `GarageEvent` table and its retention rule, the
  `garage_left_open` / `garage_quiet_hours_open` / `garage_offline` alerts, the `GarageMonitor` thread,
  `ANTHROPIC_API_KEY` / `RING_TOKEN_FILE`, `docs/GARAGE_CAM.md`.
- Dependencies `ring-doorbell`, `anthropic` and the `Pillow` pin.
- `scripts/db/v280_garage_removal.py` drops `garage_events` and deletes the `garage_*` settings and
  alerts from an existing database (dry run by default).

### Kept
- `GET /api/config` still withholds any `*_password` key; `myq*` / `liftmaster*` / `chamberlain*`
  hostnames and vendors classify as smart home.

## [2.7.0] - 2026-09-17

The garage door is now *read*, not controlled. The ratgdo board of 2.6.0 was never bought; the
door state comes from the Ring "Garage Cam" instead: each new snapshot is read by Claude vision.
Ring has no personal API (its Partner API is for certified publishers), so the app uses the
unofficial `ring-doorbell` library the way Home Assistant does.

### Added
- `services/ring_client.py`: `RingBridge` runs the async library on one loop in a daemon thread;
  sign-in with the 2FA code, token kept in `RING_TOKEN_FILE` (0600), stored and fresh snapshots,
  motion history. `services/door_vision.py`: Pillow change gate (unchanged frames are never sent)
  and one structured `anthropic` call returning open / closed / unknown with confidence and reason.
- Settings > Garage door: Ring sign-in, camera picker, check cadence (15 min default; sooner after
  Ring motion), Claude model, scene notes, re-read window, left-open minutes, quiet hours.
- Smart Home page: the latest frame, the reading and its confidence, "open for" timer, Check now,
  camera battery / Wi-Fi, today's readings and cost; door events keep the frame that caused them.
- `GET /api/garage/snapshot.jpg`, `POST /api/garage/check`, `POST /api/garage/ring/login|logout`,
  `GET /api/garage/ring/cameras`; `ANTHROPIC_API_KEY` and `RING_TOKEN_FILE` in `.env`;
  `docs/GARAGE_CAM.md`; `scripts/db/v270_garage_cleanup.py`.

### Changed
- `garage_offline` now means "Garage camera unavailable" (three failed checks in a row).
- Dependencies: `ring-doorbell`, `anthropic`, `Pillow` (pinned, pip-audit clean).

### Removed
- The ratgdo control path: `services/ratgdo_client.py`, `services/garage_discovery.py`, the
  simulator, `TestGarage.js`, the door / light / lock / discover / test routes, the board settings
  and the obstruction alert. `docs/GARAGE_DOOR.md`.

## [2.6.0] - 2026-09-17

Garage door control and a Smart Home page. A myQ (Chamberlain) opener joined the household; myQ has
no local or third-party API (the cloud API is blocked, `pymyq` archived, `homebridge-myq` retired),
so the integration targets a ratgdo board running the ESPHome firmware on the main LAN. Everything
was built and verified against a local simulator; the board plugs in through Settings.

### Added
- `/smart-home`: an animated door that follows the board's position, hold-to-confirm Open / Close
  (Stop while moving), opener light and remote lock-out switches, obstruction / motion chips, an
  "open for" timer, openings per day for 14 days, recent activity with attribution (HomeNetMon vs
  remote / wall button) and a grid of the smart-home, IoT and media devices. Garage tile on the
  dashboard hero row (hidden until enabled). "Smart Home" in the navbar.
- `services/garage_monitor.py` (`GarageMonitor` thread, heartbeats while disabled), the
  `GarageEvent` table (retained a year), `services/ratgdo_client.py` (REST + Server-Sent Events,
  both ESPHome entity-id formats) and `services/garage_discovery.py` (finds a board among devices
  the scanner has seen and confirms it with one probe).
- Alerts through the usual channels: `garage_left_open`, `garage_quiet_hours_open`,
  `garage_obstruction`, `garage_offline`; all resolve themselves when the condition clears.
- `GET /api/garage`, `POST /api/garage/{door,light,lock}`, `GET /api/garage/history`,
  `GET /api/garage/discover`, `POST /api/garage/test`, `GET/PUT /api/config/garage`; Settings →
  Garage door (Find ratgdo, Test connection, thresholds, quiet hours).
- `scripts/dev/ratgdo_sim.py` simulator and `TestGarage.js` (Playwright, gated by `GARAGE_SIM_URL`);
  `docs/GARAGE_DOOR.md`.
- `ratgdo*`, `myq*`, `liftmaster*`, `chamberlain*` hostnames and Chamberlain / LiftMaster vendors
  classify as smart home.

### Changed
- `GET /api/config` no longer returns keys ending in `_password`.
- The dashboard's device-card renderer moved to `static/js/device-cards.js`, shared with the Smart
  Home page.

## [2.5.1] - 2026-09-11

Remote access over Tailscale. The documented path (open the dashboard through the tailnet) rendered
every page but the Socket.IO handshake refused the tailnet origin, so nothing ever live-updated.

### Fixed
- The Socket.IO origin check accepts `100.64.0.0/10` explicitly (CPython 3.12.4+ stopped calling that
  range private) and this host's own Tailscale MagicDNS name, read from `tailscale status --json` and
  cached 30 s. Other hostnames still need `ALLOWED_ORIGIN_HOSTS`; public addresses are still refused.
- Behind a reverse proxy on this host (`tailscale serve`, Caddy) every request arrived from loopback,
  a trusted address, so rate limiting was off for all remote clients. The limiter now keys on the
  first `X-Forwarded-For` hop, only when the connection itself comes from loopback.
- `Strict-Transport-Security` was sent over plain HTTP; it is now sent only with `HTTPS_ENABLED=true`.
- Device-control targets are checked with `core.validators.is_lan_address`, which excludes the
  Tailscale range on every Python version instead of depending on `ipaddress.is_private`.

### Added
- `GET /api/system/tailscale` and a *Remote Access (Tailscale)* card on the About page: the tailnet
  URL of this host and each peer's online state (no thread, no table, no alerts).
- `ALLOWED_ORIGIN_HOSTS` setting; Tailscale section in the Deployment Guide (`BASE_URL`, optional
  `tailscale serve`, never Funnel).

## [2.5.0] - 2026-09-11

A second full review of the running system (see git history for the per-phase detail). The API surface
went from ~257 routes to 70, all with a caller; 11 empty tables are gone; every finding was verified live.

### Fixed
- Alert auto-resolution and alert retention had never run (called without an app context); 105 of 139
  open alerts closed on the first pass. `AlertManager.resolve_alerts()` now owns the lifecycle
  (device_down, high_latency, performance, new_device, stale after `alert_max_open_days`).
- The device page called an undefined `initializeCharts()`, leaving every button inert and both charts
  blank; the analytics page shadowed `showToast` with a console stub; dashboard bulk enable/disable
  stopped after one device.
- Read-only GETs the pages poll were on the 1-per-5-minute rate-limit tier (security scan progress
  never updated); the trusted-IP bypass only changed the limiter key.
- Settings > Network / Alerts wrote around the configuration service, so history, rollback and
  hot-reload callbacks never fired. `POST /api/config/reset` seeded 30 s / 300 s intervals.
- Three different device counts (145 / 107 / 60) and two alert counts across endpoints: one
  definition in `services/device_counts.py`, used by the summary API, the health score, the dashboard
  tiles and the Socket.IO push. Devices outside `NETWORK_RANGE` are archived, not pinged.
- Watchdog: a thread that never heartbeated was never reported stale; `SecurityScanner` now heartbeats
  per device and is skipped when scanning is disabled (health returned 503 on default installs).
- Naive local timestamps in the scan-status API (7 h skew), `print()` in model methods, unbounded
  alert queries, the 8.9 s `quick-stats` sweep, stale `v2.0.0` strings, unpinned Chart.js / d3, XSS
  sinks on the security, topology and analytics pages.

### Added
- Alerts page overhaul: server-side severity / status / time / search filters with facets and paging,
  Acknowledge (single, selected, all-filtered), all six severities styled, alert titles, notification log.
- Device identification: mDNS probes, DHCP-lease names, a rule-based classifier that ignores randomized
  MACs, re-classification of unknowns, `POST /api/devices/reclassify`, Add-device form, notes and tags.
- Internet / gateway reachability monitor (`monitoring/wan_monitor.py`, `GET /api/monitoring/wan`) with a
  dashboard tile and `wan_down` / `gateway_down` / `wan_recovery` alerts.
- Per-device Performance card (health score, availability, p50 / p95, 24h / 7d / 30d chart).
- gunicorn (`wsgi.py`) as the production server in the systemd units, Dockerfile and `run_production.sh`.
- `scripts/db/v250_schema_cleanup.py` one-shot; `init_db` adds missing columns idempotently.
- Discord test button, security settings that persist, a Service Health card on /about, a gated
  integration suite (`tests/integration`), a real non-destructive Playwright suite, an OpenAPI spec
  generated from the live route map.

### Removed
- Escalation (3 pages, 13 routes, 3 tables), automation rule engine, anomaly / ML analytics (incl.
  `/api/ai/*` and numpy / scikit-learn), speed test, notification read receipts, the vulnerability /
  compliance / OS-info half of the security scanner, the `/system-info` and `/notifications/analytics`
  pages, four dead blueprints, ~170 uncalled routes, the YAML config loader, 20 dead one-shot scripts,
  and `constants.py` entries nothing read.

## [2.4.0] - 2026-09-04

A full-codebase review of the running system. Highlights (see git history for the per-phase detail):

### Fixed
- Ping collector dropped ~55% of results every cycle (9 s deadline for the whole batch on an 8-worker pool); offline devices never got a monitoring row. Health scores were a constant 63.0 for them and fired false performance alerts.
- Per-device bandwidth was synthesized (`random.uniform`) and made up half of a 1.3 GB database; replaced by real host-interface throughput (`InterfaceBandwidth`).
- A full-table DELETE ran on every monitoring insert; `init_db` could `drop_all()` the database on a failed migration probe; the startup "aggressive cleanup" deleted days 8-30 of history on every restart.
- `/settings` could not save (POST to a GET-only route); `/device/<id>` rendered blank (envelope not unwrapped, wrong field names); live WebSocket updates never reached any page (no room subscription); Wake-on-LAN packets were malformed; the ping parser always reported 100% loss.
- CSRF accepted its own cookie as the token; a request-wide "malicious pattern" filter rejected legitimate input; debug routes and an unauthenticated `update_configuration` Socket.IO handler removed; Socket.IO runs in threading mode (eventlet was auto-selected without monkey-patching).
- Duplicate indexes (10 on `monitoring_data`, 15 on `devices`), dead tables and ~3,200 lines of unreferenced modules removed; SQLAlchemy 2.0.52 incompatibility (`func.case`) fixed.

### Added
- Unified retention service covering every time-series table (ten had none), hourly, with WAL checkpoints.
- Stale-device archiving (`STALE_DEVICE_DAYS`) and DHCP address-reuse handling in the scanner.
- One alert pipeline (dedup, suppression, correlation) for device, performance and security alerts; security alerts auto-resolve when the port closes.
- Settings > Alerts & Notifications: thresholds and ntfy/email/webhook/Discord channels with test buttons.
- Watchdog heartbeats for all 11 background threads; retention status in `/api/system/health`.
- `scripts/db/maintenance_window.py`; WAL-safe `scripts/backup_database.py`.

### Changed
- Dashboards consolidated: `/full-view`, `/performance-dashboard`, `/ai-dashboard` redirect to `/` and `/analytics` tabs. `/network-map` renders the real topology engine.
- `requirements.txt` is runtime-only (dev tools in `requirements-dev.txt`); unused scientific/network packages and eventlet dropped; Python >= 3.11.
- Deployment surface reduced to systemd units (system and per-user), one Dockerfile/compose file and a rewritten `install.sh`; Kubernetes/Helm manifests, the SDK/examples for a removed API and one-shot report docs removed.

## [2.3.2] - 2025-08-22

### New Features
- f5c8927 feat: implement comprehensive version management and accurate device counting

### Other Changes
- ce152f6 Remove GitHub Actions workflows due to permission restrictions
## [2.3.1] - 2025-08-22

### New Features
- Automated version management system with Git integration
- Dynamic version detection from Git tags
- Enhanced system information page with Git repository details
- Automated release workflows via GitHub Actions
- Release management script for semantic versioning

### Improvements  
- Updated about page to show version source (Git tag vs hardcoded)
- Added Git commit information to system info display
- Improved build date detection using Git commit timestamps
- Enhanced version display with branch and status information

### Technical Changes
- Added `get_git_info()` function for repository information
- Added `get_dynamic_version()` for Git-based version detection
- Updated system info API to include Git metadata
- Created automated release script (`release.py`)
- Added GitHub Actions workflows for CI/CD

### Documentation
- Added comprehensive release management documentation
- Updated system architecture notes with version management details

---

*Previous versions were managed manually. This changelog will be automatically maintained going forward.*
