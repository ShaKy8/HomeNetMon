# CLAUDE.md

Instructions for AI coding agents working in this repository. Read all of it before changing anything.

Where this file and the code disagree, the code is right: follow the code and correct this file in the same change. `tests/unit/test_repo_hygiene.py` reads this file, so run the suite after editing it (see "Documentation and process" in section 8).

## 1. What this project is

HomeNetMon is a Flask + SQLAlchemy + Socket.IO web app that monitors the devices on one home or small-office subnet (a single `/24`). It discovers devices (kernel ARP table plus an nmap ping sweep), pings them on an interval, checks the internet link, port-scans on a schedule, raises alerts, sends notifications (ntfy push, email, webhook, Discord) and serves a server-rendered Bootstrap dashboard with live WebSocket updates. It is not meant for corporate networks. Current version: 2.10.1.

Three properties shape every decision:

- **One household, a trusted LAN, no authentication.** Every endpoint is open to the LAN by design. The protections are a Host-header allowlist, CSRF tokens, input validation and rate limiting.
- **One process.** Production is gunicorn with exactly one `gthread` worker (32 threads, no `--preload`). Socket.IO state and up to eight background threads live inside that worker. There is no queue, no second worker and no async runtime.
- **Gentle on purpose.** Devices are pinged every 600 s and the network is swept once a day, because home IoT devices misbehave when probed hard. Tests pin these defaults.

Stack: Python 3.11+ (the venv here is 3.14, CI uses 3.12), Flask, Flask-SQLAlchemy, Flask-SocketIO in `threading` mode, Flask-Limiter, SQLite in WAL mode (PostgreSQL is supported), Jinja templates, Bootstrap 5.3.0, Bootstrap Icons, Chart.js 4.4.1, d3 7.9.0 (network map only), plain JavaScript. There is no frontend build step.

### This machine runs the production instance

Treat this checkout as a live system, not a sandbox.

- The deployed service is the user unit `~/.config/systemd/user/homenetmon.service`. It serves **port 5000** from this directory and keeps its data in `production_data/homeNetMon.db` (gitignored).
- **`.env` in this checkout sets `DATABASE_URL` to that production database and turns security scanning on.** `config.py` loads `.env` at import. Any app instance or script started here without its own `DATABASE_URL` opens the production database and runs a second set of monitoring threads against it.
- **Edits to `templates/` and `static/` are live in production the moment you save them** (templates auto-reload, static files are served from disk). Python changes go live at the next restart, including an automatic one after a crash or reboot. Never leave the tree in a broken state.
- The test suite is safe to run at any time: `tests/conftest.py` points SQLAlchemy at a temporary file before the app is created, and no background thread starts.
- `sudo` is not available. The `sqlite3` command-line tool is not installed; use Python's `sqlite3` module.

## 2. How to work here

1. **Read before you write.** Open the function you are about to change and search for its callers. Many concerns here have exactly one owner (section 6); find the owner before adding code beside it.
2. **Check names before relying on them.** Before you call or mention a function, setting, file or flag, search for it. That includes names in this file.
3. **Make the smallest change that solves the problem.** No drive-by refactors, renames, reformatting or dependency bumps. If you find a bug or dead code outside the task, report it in your summary and leave it alone.
4. **Prove it.** Run the test file for the area while you iterate, the full suite and the linter before you finish, and for UI work look at the page in a dev instance. A change you have not exercised is not done.
5. **Ask before acting on the live system or the outside world.** That covers restarting or stopping the service, running a `scripts/db/` one-shot with `--execute`, deleting backups, calling the `/api/config/test/*` endpoints on production (they send real pushes and emails), committing and pushing. Reading (status, logs, GET requests, dry runs) needs no permission.
6. **Report plainly.** Say what you changed, what you ran and what it printed, and what you could not verify. If a test fails, say so and show the failure.

## 3. Folder map

| Path | Contents |
|---|---|
| `app.py` | Composition root `create_app()`: middleware, Socket.IO, blueprints, singleton services, page routes, thread start-up. Order-sensitive. |
| `wsgi.py` | gunicorn entry point (`wsgi:app`). |
| `config.py` | `Config`: loads `.env`, holds code defaults, sets up logging. |
| `constants.py` | Values shared by more than one module (`DEVICE_DOWN_AFTER_SECONDS`, `ALERT_ON_DOWN_BY_TYPE`, `APP_VERSION`, the status vocabulary). |
| `models.py` | Every SQLAlchemy model, `init_db()`, `_ensure_columns()`, `seed_default_configuration()`. |
| `version.py` | Version and system information. The version shown in the UI comes from the latest git tag when git is available. |
| `api/` | One blueprint per file (ten) plus `rate_limited_endpoints.py`. |
| `core/` | Cross-cutting infrastructure: `security_middleware.py` (Host check, CSRF, headers), `host_policy.py`, `error_handler.py`, `validators.py`, `health.py` (thread heartbeats), `watchdog_status.py`, `websocket_memory_manager.py`. |
| `monitoring/` | `scanner.py`, `monitor.py`, `alerts.py`, `wan_monitor.py`, `bandwidth_monitor.py`, and the helpers `ping.py`, `neighbors.py`, `mdns.py`, `device_classifier.py`, `notification_policy.py`, `iot_device_optimizer.py`. |
| `services/` | Thread owners `security_scanner.py`, `performance_monitor.py`, `resource_monitor.py`; shared logic `retention.py`, `device_counts.py`, `configuration_service.py`, `push_notifications.py`, `alert_correlation.py`, `alert_priority.py`, `query_cache.py`, `performance_cache.py`, `rate_limiter.py`, `pagination.py`, `tailscale.py`, `websocket_throttle.py`, `device_control.py`, `health_score.py`, `network_topology.py`. |
| `performance_middleware.py`, `api_documentation.py` | Response timing and cache headers; OpenAPI, `/api/docs`, `/api/redoc`. |
| `templates/` | `base_beautiful.html` (layout and the shared theme), `components/navbar.html`, one template per page. |
| `static/` | `js/ui-feedback.js`, `js/csrf-handler.js`, `js/dashboard-page.js`, `js/security-page.js`, icons, images, `manifest.json`. There is no CSS file; styles are inline in the templates. |
| `tests/` | `conftest.py`, `fixtures/`, `unit/` (with `unit/models/` and `unit/services/`), `integration/test_api_endpoints.py`. |
| `TestHomeNetmon.js`, `playwright.config.js`, `package.json` | Browser end-to-end suite (Playwright). Node is used for nothing else. |
| `scripts/` | Operational tools, not runtime: `backup_database.py`, `db/` (one-shot schema and data fixes), `ops/homenetmon_watchdog.py`, `generate_api_reference.py`, `migrations/` (historical). |
| `systemd/` | Unit templates: system unit, user unit, watchdog service and timer. |
| `docs/` | Deployment, operations, security, troubleshooting and user guides. `API_REFERENCE.md` is generated. |
| `Dockerfile`, `docker-compose.yml`, `install.sh`, `run_production.sh`, `health_check.sh`, `setup_backup_cron.sh` | Deployment helpers. |
| `.github/workflows/ci.yml` | CI: syntax check, ruff, pip-audit, pytest with a coverage floor. |
| `AGENTS.md` | Short orientation for other agents. It defers to this file; keep the two consistent. |

Gitignored and never committed: `.env` and its variants (only the two `.example` files are tracked), `production_data/`, `backups/`, `logs/`, `venv/`, `node_modules/`, `instance/`, `test-results/`.

The runtime is `app.py`, `wsgi.py`, `api/`, `core/`, `monitoring/`, `services/`, `models.py`, `config.py`, `constants.py`, `version.py`, `performance_middleware.py` and `api_documentation.py`. Everything else is tooling or documentation.

## 4. Commands

### Environment

```bash
source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt   # only after a requirements change
```

There is nothing to build: no bundler, no compiled assets. Do not move or rename `venv/` (its scripts hard-code the path).

### Run a development instance

Never run a bare `python app.py` here (section 1). Use this form:

```bash
mkdir -p /tmp/hnm-dev
DATABASE_URL=sqlite:////tmp/hnm-dev/dev.db SECURITY_SCANNING_ENABLED=false LOG_FILE=dev.log \
  HOST=127.0.0.1 PORT=5001 venv/bin/python app.py
```

- `DATABASE_URL`: without it, `.env` supplies the production database.
- `SECURITY_SCANNING_ENABLED=false`: `.env` enables nmap port scans, and a second scanner on the LAN is what the slow defaults exist to prevent.
- `LOG_FILE`: otherwise the instance appends to production's rotating log in `logs/`.
- `PORT=5001`: port 5000 is production. Use `HOST=0.0.0.0` only when the user wants to open the page from another device.
- The instance starts with an empty database and fills it at the first scan. It is a real monitor: it pings and sweeps the real LAN. Keep it short-lived and stop it by the PID you started.
- `app.py` runs with `use_reloader=False`: restart it after Python changes.

For UI work that needs real data, copy the production database first. Use SQLite's backup API, never `cp` (a copy taken without its `-wal` file is stale or reported as malformed):

```bash
venv/bin/python - <<'PY'
import sqlite3
src = sqlite3.connect('file:production_data/homeNetMon.db?mode=ro', uri=True)
dst = sqlite3.connect('/tmp/hnm-dev/dev.db')
src.backup(dst)
# The copy carries the real notification settings: switch the channels off,
# or the dev instance can send real pushes and emails.
dst.execute("UPDATE configuration SET value='false' WHERE key IN "
            "('push_notifications_enabled','alert_email_enabled','alert_webhook_enabled','alert_discord_enabled')")
dst.commit()
PY
```

### Test and lint

```bash
pytest tests/unit tests/integration -q                 # the CI suite: 798 passed, 0 skipped, about 25 s (2026-11-17)
pytest tests/unit tests/integration --cov=. --cov-fail-under=47   # with the coverage floor CI enforces
pytest tests/unit/test_alerts_api.py -q                # one file
pytest tests/unit/test_route_inventory.py::test_api_surface_is_exactly_the_allowlist   # one test; or -k <substring>
ruff check .                                           # CI gate; add --fix to apply safe fixes
pre-commit run --all-files                             # the hooks a commit runs
BASE_URL=http://127.0.0.1:5001 npx playwright test     # browser suite against YOUR dev instance; refuses to run without BASE_URL
```

- Pytest options live in `pyproject.toml` (`--strict-markers`, a 15 s per-test timeout, declared markers). There is no `pytest.ini`.
- CI (`.github/workflows/ci.yml`) parses every `.py` file, then runs `ruff check .`, `pip-audit -r requirements.txt` and the pytest command with `DATABASE_URL=sqlite:///:memory:`, a `SECRET_KEY` and `NETWORK_RANGE=192.168.1.0/24`. It installs the `nmap` binary because the test fixtures touch the scanner at import.
- Ruff is deliberately narrow (`E9`, `F`, `B`, `S`, `PIE`, `PLE`, `RUF` with many ignores; `scripts/`, `static/`, `templates/` excluded). A clean run is not a style guarantee. Do not widen the ruleset or run `ruff format` over files in a feature change.
- The venv must be active before `git commit`: the commit hook finds `pre-commit` only on the PATH, so run `source venv/bin/activate` in the same shell first. If a commit fails with "`pre-commit` not found", activate the venv and retry. Never pass `--no-verify`.
- The `end-of-file-fixer` hook fixes files and fails the commit: add the fixed files and commit again.
- Run `pip-audit -r requirements.txt` after any dependency change. If it cannot run on this machine, say so and rely on CI.

### Database and generated docs

```bash
venv/bin/python scripts/backup_database.py              # online, WAL-safe backup into backups/; run it before any schema or data work
venv/bin/python scripts/db/maintenance_window.py        # dry run: prints the plan, changes nothing
venv/bin/python scripts/db/v290_cleanup.py --db /tmp/hnm-dev/dev.db --execute   # rehearse a one-shot on a copy
DATABASE_URL=sqlite:///:memory: venv/bin/python scripts/generate_api_reference.py > docs/API_REFERENCE.md   # after any route change
```

Every script under `scripts/db/` is a dry run unless `--execute` is given, targets the production database unless `--db` is given, and expects the service to be stopped. They have already been applied to production; keep them as history and as the pattern for the next one. `--execute` without `--db` needs the user's go-ahead and a fresh backup.

### The production service (this machine)

```bash
systemctl --user status homenetmon                      # read-only checks are always fine
journalctl --user -u homenetmon -n 100 --no-pager
./health_check.sh                                       # exit 0 when /api/system/health reports every thread alive
/usr/bin/python3 scripts/ops/homenetmon_watchdog.py --status
systemctl --user restart homenetmon                     # only when the user asks
```

Deploying, when asked: take a backup, restart, wait about ten seconds, run `./health_check.sh`, read the last journal lines. After changing `systemd/homenetmon.user.service`, regenerate the installed unit:

```bash
sed -e "s#%h/HomeNetMon#$PWD#g" systemd/homenetmon.user.service > ~/.config/systemd/user/homenetmon.service && systemctl --user daemon-reload
```

Other ways to run the app, not used on this machine: `./run_production.sh` (gunicorn in the foreground), `./install.sh --user` (installs the user unit and the watchdog timer), `Dockerfile` with `docker-compose.yml`.

## 5. How it is built

### Start-up: `app.py::create_app()`

The order matters. It returns `(app, socketio)`.

1. Logging, the Flask app, compression, then `init_db(app)`: creates tables, adds late columns, seeds default settings.
2. Middleware: `PerformanceMiddleware` (timing and `Cache-Control`), `SecurityMiddleware`, `global_error_handler`.
3. Socket.IO with `async_mode='threading'`; the origin check is `core.host_policy.origin_allowed`.
4. Ten blueprints. The URL prefix is set at registration, not in the blueprint: `/api/devices`, `/api/monitoring`, `/api/config`, `/api/config-management`, `/api/analytics`, `/api/device-control`, `/api/security`, `/api/notifications`, `/api/system`, `/api/performance`.
5. Singleton services, attached to the app: `app._scanner`, `app._monitor`, `app.alert_manager`, `app.bandwidth_monitor`, `app.security_scanner`, `app.wan_monitor`, `app.performance_monitor`, `app.resource_monitor`, `app.configuration_service`, `app.rate_limiter`, `app.websocket_connection_manager`, `app.socketio`, `app.security_middleware`, `app.emit_alert_update`, `app.emit_alerts_changed`. Other code reaches them through `current_app.<name>`; do not rename them.
6. Unless `Config.TESTING` is set, `start_monitoring_services()` starts one daemon thread per service.

### Every request

`SecurityMiddleware` runs three checks in this order before the view:

1. **Host header** must name this server (`core/host_policy.py`: loopback, private, link-local and Tailscale addresses, addresses inside `NETWORK_RANGE`, bare names and `.local` / `.lan` / `.home.arpa` names, this node's Tailscale name, the `BASE_URL` host, `ALLOWED_ORIGIN_HOSTS`). Otherwise 400. This is the defence against DNS rebinding.
2. **Content type** of POST/PUT/PATCH must be JSON, form, multipart or text. Otherwise 400.
3. **CSRF** on POST/PUT/PATCH/DELETE: a stateless HMAC token, valid for one hour, accepted from the `X-CSRF-Token` header or a `csrf_token` form field, never from the cookie. Otherwise 403. Tokens come from `GET /api/csrf-token` or the `<meta name="csrf-token">` tag every page carries.

Responses get security headers and a CSP that allows scripts only from this origin, `cdn.jsdelivr.net` and `cdn.socket.io`. Inline scripts and inline `onclick` handlers are allowed because the templates rely on them.

### Background threads

| Thread name | Code | Job | Default cadence |
|---|---|---|---|
| `NetworkScanner` | `monitoring/scanner.py` (`start_continuous_scan`) | ARP plus nmap discovery, identity (hostname, vendor, mDNS, DHCP leases), classification, `new_device` alerts | `scan_interval`, 86400 s |
| `DeviceMonitor` | `monitoring/monitor.py` | Pings `device_counts.monitored_devices()`, confirms presence by ARP after a failed ping, writes `MonitoringData`, pushes live status, archives stale devices | `ping_interval`, 600 s |
| `AlertManager` | `monitoring/alerts.py` | Device-down and latency checks, then `resolve_alerts()` | 600 s |
| `WanMonitor` | `monitoring/wan_monitor.py` | Pings the gateway and `wan_check_target`; `WanCheck` rows; internet and gateway alerts | `wan_check_interval`, 60 s |
| `BandwidthMonitor` | `monitoring/bandwidth_monitor.py` | Host interface counters into `InterfaceBandwidth` | `bandwidth_interval`, 300 s |
| `PerformanceMonitor` | `services/performance_monitor.py` | Health scores from ping data into `PerformanceMetrics` | 300 s |
| `ResourceMonitor` | `services/resource_monitor.py` | Runs `services/retention.py` hourly; pushes if the outside watchdog goes silent | 300 s |
| `SecurityScanner` | `services/security_scanner.py` | nmap port scans, `SecurityScan` / `SecurityEvent` rows, port alerts | runs only when the environment has `SECURITY_SCANNING_ENABLED=true` |

Every loop calls `core.health.record_heartbeat('<ThreadName>')`. The names must match `core/health.py::EXPECTED_THREADS`. `GET /api/system/health` returns 503 when a thread is dead or silent, and the outside watchdog then pushes a notification.

### Settings

Precedence: a runtime `Configuration` row (written by the Settings page) beats `.env`, which beats the default in `config.py`. `init_db` seeds missing rows from `Config` and logs a WARNING when a row differs from the environment. Services read settings at use time with `Configuration.get_value(key)` inside an app context; values are strings. Environment keys are documented in `.env.example`.

### Data

Models, all in `models.py`: `Device`, `DeviceIpHistory`, `MonitoringData`, `Alert`, `AlertSuppression`, `Configuration`, `ConfigurationHistory`, `InterfaceBandwidth`, `NotificationHistory`, `SecurityScan`, `SecurityEvent`, `PerformanceMetrics`, `WanCheck`.

- Tables are created by `db.create_all()` at start-up. There is no migration framework.
- Timestamps are naive UTC (`datetime.utcnow()`); serializers append `Z`. The local clock is used on purpose where a person thinks in local time (quiet hours, daily suppression windows).
- `Device.ip_address` is unique and nullable (cleared when another MAC takes the address). `Device.status` is derived from `last_seen` and `constants.DEVICE_DOWN_AFTER_SECONDS`.
- `Device.to_dict()` (one device) and `Device.to_dict_fast()` (lists, fed by `batch_get_device_data()`) must keep the same core keys; a test checks it.

### Device identity

- A different MAC on a known IP is a new device; the old row loses its IP and its monitoring.
- An archived device is re-enabled when its MAC reappears inside the network range.
- Phones rotate their MAC. Before creating a row for an unknown MAC, `NetworkScanner._adopt_rotated_mac()` looks for the row with the same `identity_key(hostname)` and adopts it only under strict rules: never when two rows already have real MACs, a real MAC takes over only MAC-less or randomized rows, a randomized MAC takes a real-MAC row only while that row is absent, and a reverse-DNS name must also match the last IP. Do not loosen these: a wrong merge cannot be undone.
- `DeviceMonitor.ping_device()` returns `SKIPPED`, not `None`, when the IoT optimizer defers a device. `None` records a failed ping; `SKIPPED` must record nothing.

### Alerts

- `AlertManager.create_alert(device_id, alert_type, severity, message, subtype=None, notify=True, resolved=False)` is the pipeline for every alert: dedup against an open alert with the same device, type and subtype, then suppression rules, correlation, priority, commit, notifications, WebSocket emit. It returns `None` when the alert was deduplicated or suppressed, and must run inside an app context.
- `Alert.device_id` is required, so network-level alerts (internet down) attach to the gateway's device row.
- A device-down alert needs all of: `device.alerts_on_down` is true, not seen for the threshold (45 min by default, 15 for `Device.is_critical`), three consecutive failed pings, and 7-day uptime under 90 percent.
- `Device.alerts_on_down` is the explicit `alert_on_down` column, else `is_critical`, else `constants.ALERT_ON_DOWN_BY_TYPE` (phones, Apple devices and unknown devices are silent).
- Auto-resolution: `AlertManager.resolve_alerts()` closes `device_down` (creating exactly one `device_recovery`), `high_latency`, `performance`, `new_device` after a day, and anything open longer than `alert_max_open_days`. The WAN monitor and the security scanner close their own alert types.
- Whether an alert is pushed is decided by `monitoring/notification_policy.py` (the `notify_*` settings and quiet hours; critical always passes) inside `send_alert_notifications`, which records the outcome in `Alert.notification_status`. The channels are switched by the settings `push_notifications_enabled`, `alert_email_enabled`, `alert_webhook_enabled` and `alert_discord_enabled`.
- Presence: a device counts as seen when it answers a ping, or when its ARP entry is REACHABLE within 12 s of a failed ping (`monitoring/neighbors.py`). A STALE ARP entry is not presence.

### Live updates

Pages share one Socket.IO connection and join rooms by emitting `subscribe_to_updates` with `{types: [...]}` (`device_status`, `monitoring_summary`, `alerts`). `device_status_update` goes to the room `updates_device_status`; `monitoring_summary` and `wan_status` go to `updates_monitoring_summary`. `alert_update` and the `scan_*` events are broadcast to every client. A bulk alert change sends `alert_update` with `action: 'bulk'` and no alert.

### Outside watchdog

`scripts/ops/homenetmon_watchdog.py`, run every minute by a systemd user timer, pushes through ntfy when the app is down or degraded, because the app cannot report its own death. It runs on `/usr/bin/python3` with the standard library only, never the venv; it only reads the app database; it never restarts anything. Tests enforce the first two, and that its unit's environment lines equal those of `homenetmon.user.service`. Do not import app code into it or add packages. Its state is read back by `core/watchdog_status.py` for the About page and `/api/system/health`.

### Pages

| URL | Template | Page script |
|---|---|---|
| `/` | `dashboard.html` | `static/js/dashboard-page.js` |
| `/device/<id>` | `device_detail.html` | inline |
| `/alerts` | `alerts.html` | inline |
| `/analytics` | `analytics.html` | inline |
| `/network-map` | `topology.html` | inline, plus d3 |
| `/security` | `security.html` | `static/js/security-page.js` |
| `/settings` | `settings.html` | inline |
| `/about` | `about.html` | inline |

Retired URLs (`/noc`, `/devices`, `/topology`, `/notifications`, `/security-dashboard`, `/ai-dashboard`, `/performance-dashboard` and a few more) redirect; a test pins them.

## 6. Coding rules

### One owner per concern

Before adding logic, check whether it already has an owner. Use the owner; do not write a second implementation.

| Concern | Owner | Never |
|---|---|---|
| Creating an alert | `current_app.alert_manager.create_alert(...)` | construct `Alert(...)` yourself |
| Closing alerts automatically | `AlertManager.resolve_alerts()`, or the producer of that alert type | add a second resolver for a type that has one |
| Deciding who is notified | `monitoring/notification_policy.py` | add per-type senders, or pass `notify=False` to silence a type |
| Writing a setting | `api/config.py::_set()`, which calls `configuration_service.set_configuration()` | call `Configuration.set_value()` from a route |
| Device and alert counts | `services/device_counts.py` | re-derive them in a query |
| The devices to ping | `device_counts.monitored_devices()` | filter on `is_monitored` alone |
| The "down" threshold | `constants.DEVICE_DOWN_AFTER_SECONDS` | write `900` |
| What a critical device is | `Device.is_critical` | add another heuristic |
| ICMP ping | `monitoring/ping.py::ping_host` | shell out to `ping` again |
| Presence | `monitoring/neighbors.py` | treat any ARP entry as "seen" |
| Deleting old rows | a `RetentionRule` in `services/retention.py` | clean up in an insert hook or a new loop |
| The device type list | `monitoring/device_classifier.py::ALL_DEVICE_TYPES` | keep a second list |
| "Is this host, origin or URL allowed" | `core/host_policy.py` | write an ad-hoc check |
| A target address taken from a request | `api/device_control.py::_resolve_target` | pass a client-supplied address to ping or nmap |
| Rate limits | `@create_endpoint_limiter(tier)` | add a second limiter |
| Toasts, escaping, the fetch helper, debounce | `static/js/ui-feedback.js` | re-implement them in a page |
| The CSRF header on requests | `static/js/csrf-handler.js` | set it by hand |
| The Socket.IO connection | `window.liveSocket()` | call `io()` a second time |

The code contains a few older exceptions to this table (fallback paths that build an `Alert` directly when no manager is attached, a cleanup loop inside the performance monitor, a `ping` call in `api/devices.py`). Do not copy them, and do not remove them as a side effect of other work.

### Python

- Match the file you are in: four spaces, `snake_case`, `logger = logging.getLogger(__name__)`, f-string log messages, lines up to 120 characters.
- Service code wraps one unit of work in `try`, logs the error, calls `db.session.rollback()` and returns a neutral value. A background loop must never raise out of its `while`.
- `subprocess`: an argument list, never `shell=True`, always a timeout, and validate addresses with `ipaddress.ip_address()` first. `monitoring/ping.py` is the model.
- nmap and ping run unprivileged. Do not add options that need root or raw sockets (`-O`, `-sS`) or `--script`, and keep the printer and own-host exclusions in the security scanner.
- Keep monitoring slow. Do not lower intervals or add probes. `.env.example`, `docker-compose.yml`, the README and the seeds must keep agreeing with `config.py`.
- Deployment binds `0.0.0.0` because the units and Docker set `HOST`; the code default stays `127.0.0.1`.

### Threads and the database

- Background work is a daemon thread started in `start_monitoring_services()`. Not cron, not a second process, not asyncio.
- Open `with self.app.app_context():` around each unit of work, never for the thread's lifetime: a pinned context holds a SQLite snapshot and blocks WAL checkpoints.
- Wait with a `threading.Event` (`self._stop_event.wait(interval)`) so `stop()` is prompt.
- Do not hand ORM objects to another thread or app context. Pass ids or plain dicts and query again; `DeviceMonitor._ping_device_for_batch` is the model.
- Commit once per batch and roll back in the `except`.
- Reach services through `current_app.<name>`. Never construct a second `AlertManager`, scanner or monitor, and never create a service at import time in a blueprint.

### API endpoints

Copy `api/devices.py::update_device`:

```python
@devices_bp.route('/<int:device_id>', methods=['PUT', 'PATCH'])
@create_endpoint_limiter('strict')                 # directly under the route
@validate_request(allowed_fields=[...])            # unknown fields are dropped
@handle_errors()                                   # turns raised errors into a JSON response
def update_device(device_id): ...
```

- Tiers: `relaxed` (120/min) for GET, `strict` (10/min) for single writes, `bulk` (2/min) for multi-row writes, `critical` (1 per 5 min) for destructive or scan-triggering actions. A misspelled tier silently becomes `moderate`.
- Validate with `core.validators.InputValidator`. Signal failures by raising `ValidationError` or `ResourceNotFoundError` from `core.error_handler`. In new code do not return `str(e)` to the client.
- Use `Model.query.get(id)` and raise `ResourceNotFoundError`; `get_or_404` inside a broad `except` turns a 404 into a 500.
- After a device write: `db.session.commit()`, then `invalidate_device_cache()` inside a `try/except` that ignores failure.
- Response shapes are not uniform, and that is accepted. Older endpoints return `{"success": true, ...}` or a bare payload, and `{"error": "..."}` on failure; `@handle_errors()` endpoints fail with `{error_code, message, status_code, ...}`. Do not migrate one side; handle both where the page calls the API.
- Every route needs a real caller (a page, a script or the health check) and an entry in `ALLOWED` in `tests/unit/test_route_inventory.py`. Regenerate `docs/API_REFERENCE.md` afterwards.

### Schema changes

1. Add the column to the model.
2. Add it to `_ensure_columns()` in `models.init_db` (an idempotent `ALTER TABLE` at start-up), because `create_all()` never alters an existing table.
3. If existing rows must change, write a dry-run-by-default one-shot under `scripts/db/`; copy `v290_cleanup.py`.
4. A new model goes into both delete lists of the `db_session` fixture in `tests/conftest.py`, and a time-series table gets a `RetentionRule`.

SQLite cannot alter constraints in place; `scripts/db/maintenance_window.py` shows the table-rebuild pattern.

### Security

- No authentication, by decision. Do not add logins, users, API keys or `@login_required`, and do not treat proxy or Tailscale identity headers as authentication.
- Never weaken the Host check, CSRF, the CSP or the private-address rule for device control. An outbound URL taken from user input goes through `core.host_policy.outbound_url_problem`.
- Escape every string a LAN device controls (hostnames, vendor strings, service banners, mDNS names) before it reaches `innerHTML`.
- Never commit or print secrets: `.env`, the ntfy topic, SMTP credentials, webhook URLs.

### Tests

- Put tests in `tests/unit/` or extend `tests/integration/test_api_endpoints.py` when a route's shape changes.
- Fixtures in `tests/conftest.py`: the session-scoped `app`, `client`, `db_session` (empties every table before and after each test, `Configuration` included), `sample_device`, `sample_devices`, `sample_alert`, `sample_monitoring_data`, and the mocks `mock_nmap`, `mock_ping`, `mock_smtp`, `mock_requests`, `mock_socketio`. Factories live in `tests/fixtures/`; keep `sqlalchemy_session = db.session` on each.
- CSRF is enforced under test. An unsafe request needs a token:

```python
token = client.get('/api/csrf-token').get_json()['csrf_token']
client.post('/api/devices', json={...}, headers={'X-CSRF-Token': token})
```

- No background thread runs under test. To test a loop, call one iteration yourself inside `app.app_context()`, for example `app._monitor.monitor_all_devices()`.
- Test devices live in `192.168.1.0/24`; the fixture pins `Config.NETWORK_RANGE`.
- No real network, SMTP or ntfy in tests. Do not depend on the hour of day or on values in `.env`.
- No skips. A test that no longer matches the code is fixed or deleted. Markers must be declared in `pyproject.toml`.

### Versions, dependencies, git

- `requirements.txt` is runtime-only and pinned; dev tools are in `requirements-dev.txt`. Do not add a dependency for something the standard library or an existing package does, and stay within current major versions unless asked.
- A release changes the version in `version.py`, `pyproject.toml`, `package.json` and `constants.APP_VERSION` together (a test keeps them equal), adds a `CHANGELOG.md` entry (`## [x.y.z] - YYYY-MM-DD` with `### Added`, `### Changed`, `### Fixed`, `### Removed`) and is tagged `vX.Y.Z`. The version shown in the UI and used for cache-busting comes from the latest tag.
- Commit only when asked: one concern per commit, a short imperative subject with a scope prefix as in `git log` (`fix(alerts):`, `feat(ops):`, `ui:`, `sec:`, `tests:`, `docs:`).

## 7. Design rules

### Adding things

- **A setting**: a `Configuration` key read at use time, a validation rule in `services/configuration_service.py`, a fallback in `config.py` if it also has an environment variable, an entry in `.env.example` (a test fails if that file lists a key nothing reads) and a control on the Settings page.
- **A background job**: a singleton with a loop method, built in `create_app()`, attached to `app`, started as `threading.Thread(daemon=True, name=...)` in `start_monitoring_services()`, heartbeating every iteration and listed in `EXPECTED_THREADS`.
- **An alert type**: produce it with `create_alert`, give it a title in `Alert.ALERT_TITLES` and a style in `AlertManager.PUSH_STYLE`, decide who resolves it and whether the notification policy needs a key for it.
- **A table**: see "Schema changes".
- **An endpoint**: see "API endpoints". If no page will call it, do not add it.
- **A page**: ask first. The page set in section 5 is complete; a new view normally becomes a tab or card on an existing page.
- Prefer removing to adding. This codebase was cut from 257 API routes to about 70 because most had no caller. Do not build for hypothetical users, multi-tenancy, high availability or enterprise scale.

### User interface

- Server-rendered Jinja, Bootstrap 5.3.0, vanilla JavaScript. No framework, no bundler, no CSS file, no npm runtime packages. No new CDN hosts or web fonts: the CSP allows only `cdn.jsdelivr.net` and `cdn.socket.io`. CDN URLs carry an exact version, and a test checks it.
- Every page extends `base_beautiful.html` and fills the blocks `title`, `extra_css`, `content` and `extra_js`. The `extra_css` block holds the page's own `<style>` element.
- The shared theme is the `<style>` block of `base_beautiful.html`. Colours are literals; only the Network Map page defines CSS variables (`--topology-*`), for itself. There are two themes, and the navbar toggle stores the choice in `localStorage`. The base has light rules with dark overrides under `[data-bs-theme="dark"]`. Page-level CSS is the other way round: each rule is written for dark, and a rule whose colours only work on a dark page is followed directly by its light twin, the same selector behind `:where([data-bs-theme="light"])`, holding only the changed colours. `:where()` adds no specificity, so the twin wins and loses exactly where its dark rule does. Take the light values from the pairs in the base: white text becomes `#1e293b`, a white-alpha fill becomes `rgba(255, 255, 255, 0.8)` on a card or input and a black-alpha tint elsewhere, a white-alpha border becomes black-alpha, a pastel such as `#86efac` becomes its dark shade `#15803d`. **Dark is the reference theme**: design there, then check the light theme as well.
- Palette:

| Role | Colour |
|---|---|
| Primary, links, focus | `#3b82f6` |
| Up, success | `#22c55e` |
| Down, danger | `#ef4444` |
| Warning | `#f59e0b` |
| Unknown, secondary | `#6b7280` |
| Page background and text, dark | `#0f0f23`, `#ffffff` |
| Page background and text, light | `#f8fafc`, `#1e293b` |

- Surfaces are translucent "glass": a faint fill, a 1 px translucent border and `backdrop-filter: blur(20px)`. Tinted elements use the role colour at 10 to 30 percent opacity with a 30 percent border, not a solid block. Do not introduce new hues.
- Reuse the existing classes: `.modern-card` with `.card-header` and `.card-body`, `.btn-modern` (plus `.btn-primary`, `.btn-success`, `.btn-warning`, `.btn-danger`), `.badge.bg-*`, `.status-dot` with `.status-up`, `.status-down`, `.status-warning`, `.status-unknown`, `.page-header`, `.page-title`, `.page-subtitle`, `.loading-skeleton`, `.spinning`, `.hidden`. Radii are 16 px for cards, 12 px for buttons and inputs, 8 px for badges.
- Device status is exactly `up`, `down`, `warning` or `unknown` (`constants.py`), shown with text or an icon as well as colour.
- Icons are Bootstrap Icons (`<i class="bi bi-...">`) only.
- Charts use the global `Chart` with `responsive: true, maintainAspectRatio: false` and the palette above (lines at 0.8 opacity, fills at 0.1). A canvas cannot be themed from CSS: label, tick and grid colours set by hand must follow the theme and be redrawn when it switches; `chartColors()` and `chartRedraws` in `analytics.html` are the model. No date adapter is loaded, so use category axes with pre-formatted labels, never `type: 'time'`.
- Layout: the content container is at most 1600 px wide, the base breakpoint is 768 px, and buttons are at least 44 by 44 px. Check new UI at phone width.
- Wording is short, plain and in sentence case ("Device offline", "New open port"), as in `Alert.ALERT_TITLES`.
- Feedback: `showSuccess()`, `showError()` or `showToast()` for results; `showGlobalLoading()` / `hideGlobalLoading()` or `.loading-skeleton` while waiting; an explicit empty state (icon plus muted text) instead of a blank area; `confirm()` before a destructive action.
- Scripts: Bootstrap, Socket.IO and Chart.js load with `defer`, so page code that uses `bootstrap`, `io` or `Chart` must start from `DOMContentLoaded`. Static URLs end with `?v={{ app_version }}`.
- Requests: `apiRequest(url, {method, body, headers})` returns parsed JSON and throws on a non-2xx status (the error has `.status` and `.data`); a 200 with `success: false` does not throw, so check it. Plain `fetch` also works; the CSRF header is added for you either way.
- Live data: take the socket from `window.liveSocket()`, subscribe on `connect` and also at once when it is already connected:

```js
const socket = window.liveSocket();
const subscribe = () => socket.emit('subscribe_to_updates', { types: ['device_status', 'alerts'] });
socket.on('connect', subscribe);
if (socket.connected) subscribe();
```

- Device data reaches the page through `fetch`, so the XSS boundary is `innerHTML`: wrap every API string in `escapeHtml()`. Do not put a device-controlled string inside an inline `onclick="..."` attribute at all; HTML-escaping does not make it a safe JavaScript string. Pass a numeric id, or use a `data-` attribute and `addEventListener`.
- Accessibility: keep the skip link and the `main` landmark, one `<h1>` per page, a label for every control and an `aria-label` on icon-only buttons.
- API timestamps are UTC with a trailing `Z`; show them in the viewer's local time.

## 8. Mistakes to avoid

Each of these has happened here or is one step away. The format is: the mistake, what it causes, what to do instead.

### The live system

1. **Starting the app or a script here without `DATABASE_URL`.** `.env` supplies the production database, so a second monitor writes to it: duplicate pings, duplicate alerts, real notifications. Use the dev command in section 4 every time. This also applies inside a git worktree under this directory, because python-dotenv searches parent directories for `.env`.
2. **Treating port 5000 as a test target.** It is production. A POST or DELETE there changes real data and the `test/*` endpoints send real messages. Read from it with GET if you must; send writes only to your own instance on 5001.
3. **Experimenting in `templates/` or `static/`.** Saved edits are live at once. Make every saved state a working one, or do exploratory work in a worktree outside this directory.
4. **Forgetting how Python changes reach production.** They are not live until a restart, and you do not restart unasked. They do go live on any restart, so never stop work with the suite failing.
5. **Expecting a script change to reach browsers.** Static files are cached for a year and the `?v=` cache-buster is the latest git tag, so browsers keep the old script until the next tagged release while template changes arrive at once. Hard-refresh when checking, and do not make a live template depend on an untagged script change.
6. **Copying the database with `cp`.** Without its `-wal` and `-shm` files the copy is stale or "malformed". Use the snippet in section 4 or `scripts/backup_database.py`.
7. **Running a dev instance on a database copy with notifications still on.** The copy holds the real ntfy topic and SMTP settings. Switch the channels off in the copy first.
8. **Changing `.env` and seeing no effect.** A runtime `Configuration` row overrides it. Look at `GET /api/config` or the Settings page and change the setting there.
9. **Killing processes by pattern** (`pkill -f gunicorn`, `pkill -f app.py`). That kills production or your own shell. Record the PID of what you start and kill only that.
10. **Running a `scripts/db/` script with `--execute` to see what it does.** Without `--db` it changes production. Run the dry run, rehearse with `--db` on a copy, and get a go-ahead and a backup before the real one.

### Backend

11. **Building an `Alert(...)` row directly.** It skips dedup, suppression, the notification policy, `notification_status` and the live update, which is how alert storms start. Call `current_app.alert_manager.create_alert(...)` and handle a `None` return.
12. **Renaming an alert type or subtype.** Dedup, the resolution rules, titles, push styles and the notification policy key on those strings. Add new ones and leave existing ones alone.
13. **Counting a STALE ARP entry as "seen", or setting `last_seen` anywhere new.** `device_down` resolves when `last_seen` passes the alert's creation time, so false presence closes and reopens alerts in a loop. That bug produced hundreds of false alerts in nine days. Presence is a ping reply or a REACHABLE neighbour.
14. **Holding one app context for a thread's lifetime.** It pins a SQLite read snapshot and blocks WAL checkpoints. Open the context per iteration.
15. **Passing ORM objects between threads or app contexts.** They belong to another session and fail or go stale. Pass ids and query again.
16. **Renaming a thread, or adding a loop without a heartbeat.** `/api/system/health` turns 503 and the watchdog pushes "degraded" to the owner's phone. Keep the name identical in `threading.Thread(name=...)`, `record_heartbeat()` and `EXPECTED_THREADS`; a long sweep heartbeats inside its inner loop.
17. **Creating a second service instance** (`AlertManager()` in a route, a scanner at import time). An instance without the app skips suppression rules and cannot emit. Use `current_app.<name>`.
18. **Adding a model column and nothing else.** Tests pass on a fresh database and production fails with "no such column" at the next restart. Add it to `_ensure_columns()`.
19. **Making monitoring faster or deeper** (shorter intervals, more nmap options, scripts, OS detection). It destabilises IoT devices and printers, needs privileges the service does not have, and breaks the tests that pin the defaults.
20. **Cleaning up old rows where they are inserted.** Per-insert deletes held write locks and were removed. Add a `RetentionRule`.
21. **Creating alerts from a request handler.** `create_alert` sends notifications synchronously (SMTP alone can wait 15 s). Alerts come from the background services.

### API

22. **Adding or removing a route without updating the inventory.** `tests/unit/test_route_inventory.py` compares the `/api/*` rule strings with `ALLOWED` in both directions and rejects removed prefixes. Add the full rule string, with converters, and a real caller.
23. **Putting a GET on the `critical` or `intensive` tier, or mistyping a tier.** Pages that load or poll the route get 429s (a test catches `critical`), and a typo silently means `moderate`.
24. **Writing a POST, PUT or DELETE test without a CSRF token.** It returns 403, because CSRF is not disabled under test. Fetch a token first (section 6).
25. **Reaching the app through a new public hostname.** The Host check answers 400. Add the name to `ALLOWED_ORIGIN_HOSTS`; do not loosen `host_policy`.
26. **"Normalising" a response envelope.** Pages and tests depend on each endpoint's current shape. Keep the shape of the endpoint you touch.
27. **Forgetting `invalidate_device_cache()` after a device write.** `GET /api/devices` serves the old data until the cache expires.
28. **Emitting a Socket.IO event nobody listens for, or to a room nobody joins.** Search the templates for the event name first and reuse `device_status_update`, `monitoring_summary` or `alert_update` where possible.

### Tests and tooling

29. **Skipping or weakening a failing test.** The rule here is fix or delete. If the test is right, the code is wrong.
30. **Expecting background behaviour in a test.** No thread runs under `TESTING`: nothing pings, scans or resolves unless the test calls it.
31. **Relying on seeded settings inside a `db_session` test.** The fixture empties `Configuration`. Create the rows the test needs.
32. **Reformatting a file, widening ruff or bumping dependencies inside a feature change.** The diff becomes unreviewable and unrelated things break. Those are separate changes, made on request.

### Frontend

33. **Putting a device-controlled string into `innerHTML` unescaped.** A hostname or service banner is attacker-controlled input, and this app has no login: that is stored XSS. Wrap it in `escapeHtml()`. Never add `|safe` to a template; there is none today.
34. **Re-implementing a toast, fetch wrapper, debounce or CSRF handling in a page.** The contract tests fail and behaviour drifts. Use `ui-feedback.js` and `csrf-handler.js`.
35. **Opening a second socket, or subscribing only inside the `connect` handler.** The navbar usually connects first, so `connect` has already fired and the page silently gets no updates. Use the pattern in section 7.
36. **Using `Chart`, `io` or `bootstrap` at script load.** They are deferred and not defined yet. Start from `DOMContentLoaded`.
37. **Renaming an element id, a function or a pinned line of page script.** `tests/unit/test_frontend_contracts.py` pins literal strings (ids, function names, fragments such as `${esc(name)}`) and `TestHomeNetmon.js` selects by id. Search both files for a name before you change it.
38. **Writing a page's CSS in `extra_css` without its own `<style>` element, or moving that block back inside the base `<style>`.** The block is rendered in the `<head>` after the base `<style>` has closed, so bare rules show up as text at the top of the page. Wrap them in `<style>...</style>`, as every existing page does. The block used to sit inside the base `<style>`; a `<style>` tag nested in another is CSS text, and the browser silently dropped the first rule of every page. A test in `tests/unit/test_frontend_contracts.py` checks for nesting.
39. **Adding a colour, card or button style of your own, or a dark-only page rule without its light twin.** It breaks the look of the page or one of the themes; white text with no twin is invisible on the light page, and a test in `tests/unit/test_frontend_contracts.py` fails. Use the palette and classes in section 7 and write the twin next to the rule.
40. **Regenerating a large block of a template or page script.** The templates run from 500 to 2,500 lines with many inline functions, and a rewrite once deleted unrelated ones. Make targeted edits and re-read the surrounding code.

### Documentation and process

41. **Naming a deleted script, the removed admin-password variable or a mixed-case unit name in this file, the README or `docs/`.** `tests/unit/test_repo_hygiene.py` fails. Read that test before writing about removed things.
42. **Hand-editing `docs/API_REFERENCE.md`.** It is generated. Run the generator.
43. **Bumping the version in one place.** A test compares four files. Change all four, add the changelog entry and tag the release.
44. **Rebuilding something that was removed on purpose** (section 9). Ask first.
45. **Changing a command or convention here without updating `AGENTS.md`,** or the reverse.
46. **Saying "done" on the strength of reading the code.** Run the checklist in section 10.

## 9. Decisions already made

The owner decided these. Do not reopen or rebuild them without being asked.

- No authentication and no multi-user features.
- Removed in 2.5.0: escalation, automation rules, anomaly and ML analytics, speed test, notification read receipts, vulnerability and compliance scanning, the YAML configuration loader, and every API route without a caller.
- Per-device bandwidth does not exist, because it cannot be measured from this host. Only host-interface throughput is recorded.
- Removed in 2.8.0: the garage door feature and the Smart Home page.
- Since 2.9.0: no seeded suppression rules and no per-alert-type push senders; "device back online" and "scan complete" pushes are off by default.
- The presence model of 2.8.1 (a ping reply or a REACHABLE neighbour) stays.
- The app must work when reached over Tailscale. It does not monitor tailnet peers.
- Deployment is the systemd units plus one Dockerfile and compose file. No Kubernetes, Helm or bundled reverse proxy.
- The outside watchdog only notifies. It never restarts the service.
- The page set is complete; retired pages stay redirects.

## 10. Before you say a task is done

- [ ] `git diff` shows only what the task needs: no debug output, no reformatting, no unrelated edits.
- [ ] `ruff check .` passes.
- [ ] `pytest tests/unit tests/integration -q` passes with nothing skipped. New behaviour has a test; a bug fix has a test that failed before the fix.
- [ ] Route added, removed or renamed: `ALLOWED` updated, a real caller exists, `docs/API_REFERENCE.md` regenerated.
- [ ] Model changed: `_ensure_columns()`, a `scripts/db/` one-shot if existing rows must change, the `db_session` delete lists, a `RetentionRule` for a time series.
- [ ] Setting added: validation rule, `config.py` fallback, `.env.example`, Settings page.
- [ ] Thread added or changed: heartbeat, `EXPECTED_THREADS`, an app context per iteration.
- [ ] Alerts or notifications touched: everything goes through `create_alert`; dedup and the notification policy still apply; nothing can push in a loop.
- [ ] UI touched: page loaded on a dev instance in both themes and at phone width, browser console clean, live updates still arrive, device-controlled strings escaped.
- [ ] Docs: this file, `AGENTS.md`, the README and `docs/` updated when a command or convention changed; a `CHANGELOG.md` entry for a user-visible change.
- [ ] Dev instances you started are stopped, scratch files are gone, and `git status` shows no database, log or `.env` file.
- [ ] Production untouched unless asked. If you deployed: backup taken, service restarted, `./health_check.sh` exits 0, the journal is clean.
- [ ] Your final message says what you ran and what it printed, and what you could not verify.

## Further reading

- `README.md`: features and the install walkthrough.
- `docs/README.md`: index of the deployment, operations, security, troubleshooting, user and API guides.
- `CHANGELOG.md`: why things are the way they are; 2.5.0, 2.8.1, 2.9.0 and 2.10.x are the entries worth reading.
- `AGENTS.md`: the short version of this file for other agents.
