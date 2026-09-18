# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HomeNetMon is a Flask + SQLAlchemy + Socket.IO web app for monitoring devices on a single home/small-business subnet (`x.x.x.x/24`). It discovers devices via ARP/nmap, pings them on an interval, checks the internet link, port-scans on a schedule, fires alerts, and serves a Bootstrap 5 + Chart.js dashboard with live WebSocket updates. **Not** intended for corporate/enterprise networks. There is no user authentication — the app assumes a trusted LAN.

## Common Commands

### Run the app
```bash
source venv/bin/activate
HOST=0.0.0.0 DEBUG=true PORT=5001 python app.py   # dev; the deployed service already owns port 5000 on this machine
./run_production.sh                       # gunicorn in the foreground with .env loaded, DB defaults to production_data/
./install.sh --user                       # install as a per-user systemd service (no root)
```
`app.py` runs `socketio.run()` with `use_reloader=False`, so code changes need a restart. Production runs **gunicorn** (`wsgi.py`, one `gthread` worker, 32 threads, no `--preload`): Socket.IO state and the monitoring threads live in the single worker process. Defaults (`config.py`): port 5000, network `192.168.86.0/24`, ping every 600 s, scan every 86400 s, SQLite at `homeNetMon.db` in the checkout. Override via `.env` (see `.env.example`). **Runtime settings saved from the Settings page (the `Configuration` table) win over `.env`** for `network_range`, `ping_interval`, `scan_interval`, `bandwidth_interval`, alert thresholds, notification channels, security scan settings and the WAN check; `init_db` only seeds them on a fresh database and logs a WARNING when they differ from the environment.

The deployment on this machine runs as the **user** unit `~/.config/systemd/user/homenetmon.service` with `DATABASE_URL` pointing at `production_data/homeNetMon.db` (gitignored). Do not commit database files. Regenerate the installed unit from `systemd/homenetmon.user.service` after changing the template (`sed -e "s#%h/HomeNetMon#$PWD#g" … > ~/.config/systemd/user/homenetmon.service && systemctl --user daemon-reload`).

### Tests
```bash
pytest tests/unit tests/integration       # what CI requires (~590 pass / ~90 skip); config in pyproject.toml
pytest tests/unit tests/integration --cov=. --cov-fail-under=47   # coverage floor CI enforces (measured 50% on 2026-09-11)
pytest tests/unit/test_alerts_api.py      # one file
pytest tests/unit/test_alerts_api.py::TestListFilters::test_paging   # one test; or -k <substring>
pytest --no-cov -q                        # quick iteration
BASE_URL=http://127.0.0.1:5001 npx playwright test   # E2E, non-destructive; refuses to run without BASE_URL (or CI)
```
CI (`.github/workflows/ci.yml`) runs the suites with `DATABASE_URL=sqlite:///:memory:`, `SECRET_KEY` and `NETWORK_RANGE=192.168.1.0/24` set, and installs the `nmap` binary because conftest touches the scanner at import time. Skipped unit tests are listed in `tests/conftest.py:STALE_TEST_SKIPS` with a reason each; to revive one, fix it and remove its entry. Pytest options (`--strict-markers`, `timeout=15`, markers) live in `pyproject.toml [tool.pytest.ini_options]` — there is no `pytest.ini`.

The session-scoped `app` fixture pins `Config.NETWORK_RANGE = '192.168.1.0/24'` (test devices live there) and sets `Config.TESTING = True` **before** `create_app()`, which makes `create_app()` skip `start_monitoring_services()` entirely (no background threads under test) and disables CSRF. A test that needs a service loop must drive one iteration directly (e.g. `current_app._monitor.monitor_all_devices()` inside `app.app_context()`). `tests/unit/test_route_inventory.py` pins the exact set of `/api/*` rules: adding a route means adding a caller **and** an `ALLOWED` entry.

Playwright never reuses a running server: on this machine `localhost:5000` is production. Run a dev instance on another port (a copy of the DB is fine) and pass `BASE_URL`.

Fixtures: `tests/fixtures/factories.py` imports `factories_original.py` (factory_boy) and falls back to `simple_factories.py` when factory_boy is unavailable. Every `SQLAlchemyModelFactory` sets `sqlalchemy_session = db.session`; keep that. The `db_session` fixture truncates a fixed list of tables per test — add new models to it.

### Lint and formatting
```bash
ruff check .                # CI gate; config in pyproject.toml; version pinned in requirements-dev.txt and .pre-commit-config.yaml
ruff check --fix .
pre-commit run --all-files  # the end-of-file-fixer hook rejects a commit whose files it had to fix: re-add and commit again
```

### Database
```bash
venv/bin/python scripts/backup_database.py            # online, WAL-safe backup into backups/ (the sqlite3 CLI is not installed here)
venv/bin/python scripts/db/maintenance_window.py      # dry run: duplicate indexes, dead tables, VACUUM plan
venv/bin/python scripts/db/v250_schema_cleanup.py     # dry run of the 2.5.0 one-shot (drop tables of removed models, add device columns, archive out-of-range devices)
venv/bin/python scripts/db/v250_schema_cleanup.py --execute   # only with the service stopped; --db <copy> to rehearse
```
Schema is created by `init_db()`/`create_all()` at startup; there is no migration framework (`scripts/migrations/` holds historical one-shots, not a runner). Adding a column means adding it to `_ensure_columns()` in `models.init_db` (idempotent `ALTER TABLE`) and, for production, to a one-shot under `scripts/db/`. SQLite cannot alter constraints in place — see the `devices` rebuild in `maintenance_window.py` for the pattern.

### Service control (this machine)
```bash
systemctl --user {status,restart} homenetmon
journalctl --user -u homenetmon -f
./health_check.sh                          # exits 0 when /api/system/health reports every thread alive
```

## Architecture

### Composition root: `app.py` `create_app()`
Order-sensitive. It:
1. Loads `Config` (from `config.py`, which reads `.env`) and sets up logging. `Config.validate_host_binding()` only **warns**; `HOST` stays `127.0.0.1` unless the unit/.env sets it.
2. Registers middlewares: `flask_compress`, `services.cdn_manager.CDNManager`, `performance_middleware.PerformanceMiddleware` (timing header + cache policy only), `core.security_middleware.SecurityMiddleware` (CSRF + security headers), `core.error_handler.global_error_handler` (JSON for `/api/*`, HTML pages otherwise).
3. Builds Socket.IO with `async_mode='threading'` and a `cors_allowed_origins_callback` that allows only origins that are this host: private / link-local / `100.64.0.0/10` (Tailscale) IPs, `.local` and bare names, the host's Tailscale MagicDNS name (`services/tailscale.py`, cached `tailscale status --json`) and `ALLOWED_ORIGIN_HOSTS`. Server pushes go to **rooms**; a page must emit `subscribe_to_updates` with `{types: ['device_status', 'monitoring_summary', 'alerts']}` to receive `device_status_update`, `monitoring_summary`, `wan_status` and `alert_update` (bulk changes send `alert_update` with `action: 'bulk'` and no alert).
4. Registers 10 API blueprints from `api/*.py` under `/api/<name>` prefixes (set at registration, not in the blueprint): devices, monitoring, config, config-management, analytics, device-control, security, notifications, system, performance. `api_documentation.py` adds `/api/docs`, `/api/redoc` and `/api/openapi.json` (generated from the route map).
5. Instantiates **singleton services** and attaches them to the app: `app._scanner`, `app._monitor`, `app.alert_manager`, `app.bandwidth_monitor`, `app.security_scanner`, `app.configuration_service`, `app.rate_limiter` (Flask-Limiter wrapper; `api/rate_limited_endpoints.py` reads `.rate_limiter.limiter`), `app.performance_monitor`, `app.resource_monitor`, `app.wan_monitor`, `app.websocket_optimizer`, `app.websocket_connection_manager`, `app.query_cache`, `app.memory_monitor`, `app.socketio`, `app.security_middleware`, `app.emit_alert_update`, `app.emit_alerts_changed`. Other code reaches them via `current_app.<name>` — preserve the names.
6. Spawns one daemon thread per service in `start_monitoring_services()`. Every loop calls `core.health.record_heartbeat('<ThreadName>')`; the names must match `core/health.py:EXPECTED_THREADS` (`NetworkScanner`, `DeviceMonitor`, `AlertManager`, `BandwidthMonitor`, `PerformanceMonitor`, `ResourceMonitor`, `WanMonitor`, `SecurityScanner`), which `/api/system/health` reports (503 when any thread is stale; `SecurityScanner` is skipped when scanning is disabled). A thread that is alive but never heartbeated becomes stale after one grace period.

The security scanner is gated by `SECURITY_SCANNING_ENABLED` and off by default in code (nmap scans can destabilise IoT devices); this deployment enables it.

### Background services (`monitoring/`, `services/`)
- `monitoring/scanner.py` — ARP + nmap discovery on `scan_interval`; ignores addresses outside `NETWORK_RANGE`; handles DHCP address reuse (a different MAC on a known IP is a new device; the stale device loses its IP and monitoring); re-enables archived devices when their MAC reappears (only inside the range); `apply_network_range()` archives/resumes devices when the range changes. Identity: `resolve_hostname`, `get_mac_vendor` (None for randomized MACs), `enrich_identity` (mDNS via `monitoring/mdns.py`, optional `DHCP_LEASES_FILE`, budgeted per scan), classification via `monitoring/device_classifier.py` (ordered regex rules: mDNS services, hostname, vendor); unknown devices are re-classified every scan and `reclassify()` backs `POST /api/devices/reclassify`.
- `monitoring/monitor.py` — `DeviceMonitor`: pings every device from `services.device_counts.monitored_devices()` (monitored, addressed, in range) each `ping_interval` with a `ThreadPoolExecutor` sized by `max_workers`, waits for **all** results, records failures as rows, pushes `monitoring_summary` from `device_counts.summarize()`; archives devices unseen for `stale_device_days`. `ping_device()` returns `SKIPPED` (not `None`) when the IoT optimizer defers a device; the ICMP call itself is `monitoring/ping.py::ping_host`.
- `monitoring/alerts.py` — `AlertManager`. **`create_alert()` is the only way to create an alert** (dedup on device/type/subtype, suppression rules, correlation, priority, notifications, WebSocket emit). The performance monitor, security scanner and WAN monitor call it too. **`resolve_alerts()` is the only auto-resolution path** (device_down, high_latency, performance, new_device, and anything older than `alert_max_open_days`; `dry_run=True` returns counts). Thresholds and channel settings come from the runtime `Configuration` with `.env` fallback. `Alert.title` derives a heading from `alert_type`/`alert_subtype`.
- `monitoring/wan_monitor.py` — pings the default gateway and `wan_check_target` every `wan_check_interval`; `WanCheck` rows; `wan_down` / `gateway_down` / `wan_recovery` alerts on the gateway's `Device` row; `GET /api/monitoring/wan`.
- `monitoring/bandwidth_monitor.py` — samples host interface counters into `InterfaceBandwidth`. Per-device bandwidth is not measurable from the host and does not exist.
- `services/security_scanner.py` — scheduled nmap port scans (`-sV`, no `--script`), `SecurityScan`/`SecurityEvent` rows, `security_new_service` / `security_suspicious_port` alerts that resolve when the port closes; `reload_config()` reads the Settings keys at the start of each sweep; heartbeats per device.
- `services/performance_monitor.py` — health scores from ping data only into `PerformanceMetrics`; read by the device page's Performance card via `api/performance.py`.
- `services/retention.py` — the single retention service (one rule per table); run hourly by `ResourceMonitor`. Never add per-insert cleanup hooks.
- `services/device_counts.py` — the one definition of `total_devices` / `monitored_devices` / `devices_up` / `devices_down` / `devices_unknown` / `active_alerts`, used by `/api/monitoring/summary`, the analytics health score, the dashboard tiles and the Socket.IO summary.
- `services/configuration_service.py` — validation rules, `ConfigurationHistory`, hot-reload callbacks. **Every Settings write goes through `set_configuration()`** (`api/config.py::_set`); never call `Configuration.set_value()` from a route.

Pattern for a new background service: singleton with `start_monitoring()`, instantiate in `create_app()`, attach to `app`, launch via `threading.Thread(daemon=True, name=...)` in `start_monitoring_services()`, heartbeat each loop, add to `EXPECTED_THREADS`, open `with app.app_context():` per iteration (never for the thread's lifetime — it pins a SQLite snapshot and blocks WAL checkpoints), and use a `threading.Event` for the wait so `stop()` is prompt.

### Core infrastructure (`core/`)
`security_middleware.py` (stateless HMAC CSRF tokens accepted from the `X-CSRF-Token` header or a form field only — never the cookie; security headers; CSP still needs `'unsafe-inline'` because templates carry inline scripts), `error_handler.py`, `health.py` (thread heartbeats), `validators.py`, `websocket_memory_manager.py`. Caching: `services/query_cache.py` (`invalidate_device_cache()` after device writes). Rate limiting: `api/rate_limited_endpoints.py::create_endpoint_limiter(tier)` tags each view with `_rate_limit_tier`; read-only GETs must not use `critical`/`intensive` (a test enforces it); localhost and `RATE_LIMIT_TRUSTED_IPS` are exempt.

### Models (`models.py`)
`Device` (incl. `notes`, `tags` csv exposed as a list, `mdns_services`), `DeviceIpHistory`, `MonitoringData`, `Alert`, `AlertSuppression`, `Configuration` + `ConfigurationHistory`, `InterfaceBandwidth`, `NotificationHistory`, `SecurityScan`/`SecurityEvent`, `PerformanceMetrics`, `WanCheck`. `Device.ip_address` is nullable (cleared on DHCP reuse). `Device.to_dict()` and `to_dict_fast()` share a key set (`display_name`, `ip_address`, `is_monitored`, `status`, `active_alerts`, `latest_response_time`, `tags`, ...); the 7-day `uptime_percentage()` is added only by the detail endpoint. `constants.DEVICE_DOWN_AFTER_SECONDS` is the one staleness threshold. `init_db()` runs `_ensure_columns()` for columns added after a table existed.

### API layer (`api/`)
Blueprint → `@create_endpoint_limiter(tier)` → validation (`core.validators`; device-control endpoints accept private addresses only) → response. **The response envelope is not uniform**: older endpoints return `{"success": true, ...}`, newer ones the `core.error_handler` shape. Don't migrate one side alone; normalize at the call site. Every route has a caller (`tests/unit/test_route_inventory.py`); `docs/API_REFERENCE.md` is generated from the route map (`scripts/generate_api_reference.py`). `GET /api/monitoring/alerts` is the filtered/paged alert list (`_alert_params` / `_alert_query`), also used by `acknowledge-all`.

### Frontend (`templates/`, `static/`)
Server-rendered Jinja + Bootstrap 5 + Chart.js (pinned) + vanilla JS; no build step (templates append `?v={{ app_version }}` to static URLs). `static/js/ui-feedback.js` (loaded by the base template) provides `showToast/showSuccess/showError`, `escapeHtml`, `apiRequest`, `debounce`; `csrf-handler.js` adds the CSRF header to every unsafe fetch — pages must not re-implement any of these (a contract test checks). Escape any string that a LAN device controls (hostnames, service banners) before `innerHTML`. Pages: `/` dashboard, `/device/<id>`, `/alerts`, `/analytics` (tabs), `/network-map`, `/security`, `/settings`, `/about`. Retired pages redirect. `default_network_range` and `app_version` are injected into every template.

## Conventions and gotchas

- **No authentication. Period.** Every endpoint is open to the LAN by design. Don't add `@login_required`/`g.current_user`; do add rate limiting and validation. CSRF is enforced on POST/PUT/PATCH/DELETE.
- **Never bind to 127.0.0.1 in deployment.** The units and Docker set `HOST=0.0.0.0`; `Config.HOST` alone does not.
- **Services are singletons attached to `app`.** Reuse `current_app._monitor`, `current_app.alert_manager`, etc. Never instantiate a second engine at import time in a blueprint (that is how `api/analytics.py` used to 500).
- **Monitoring intervals are intentionally slow** (600 s ping, daily scan). `.env.example`, `docker-compose.yml` and the seeds agree; keep them agreeing.
- **`db.session` across threads** needs `with app.app_context():` per iteration.
- **Runtime `Configuration` overrides `.env`** (see above) — when a setting "does not change", check the Settings page / `/api/config`.
- **Dependencies**: `requirements.txt` is runtime-only and pinned; dev tools in `requirements-dev.txt`; Python ≥ 3.11. Run `pip-audit -r requirements.txt` after bumps.
- **Root-level `*.sh`/`*.py` helpers and everything under `scripts/` are operational one-shots**, not runtime. The runtime is `app.py` + `wsgi.py` + `api/` + `core/` + `monitoring/` + `services/` + `models.py` + `config.py` + `constants.py` + `version.py` + `performance_middleware.py` + `api_documentation.py`.
- **Ruff is deliberately narrow** (`E9`, `F`, `B`, `S`, `PIE`, `PLE`, `RUF` with many ignores; `scripts/`, `static/`, `templates/` excluded). A clean `ruff check` is not a style guarantee; don't widen the ruleset in a feature commit.
- **`AGENTS.md`** is the short orientation for other coding agents and defers to this file; keep the two consistent when changing commands or conventions.
- **Version** lives in `version.py`, `pyproject.toml`, `package.json` and `constants.APP_VERSION` (a test keeps them equal) plus a `CHANGELOG.md` entry.
- **Removed on purpose in 2.5.0** (do not reintroduce): escalation, automation rules, anomaly/ML analytics, speed test, notification read receipts, the vulnerability/compliance scanner half, the YAML configuration loader, per-device bandwidth.

## Configuration

Read `config.py` and `.env.example`. Most-edited keys: `NETWORK_RANGE`, `PING_INTERVAL`, `SCAN_INTERVAL`, `DATA_RETENTION_DAYS`, `STALE_DEVICE_DAYS`, `BASE_URL`, `SMTP_*`, `NTFY_*`, `WEBHOOK_URL`, `SECRET_KEY`, `DATABASE_URL` (SQLite default; PostgreSQL supported — `docs/POSTGRESQL_MIGRATION.md`), `SECURITY_SCANNING_ENABLED`, `WAN_CHECK_TARGET`, `DHCP_LEASES_FILE`, `ALLOW_SERVICE_RESTART`.

## Further reading

- `README.md` — features and install walkthrough
- `docs/README.md` — index of the deployment, operations, security, troubleshooting, user and API guides
- `CHANGELOG.md` — 2.5.0 summarises this review; 2.4.0 the previous one
