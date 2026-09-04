# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HomeNetMon is a Flask + SQLAlchemy + Socket.IO web app for monitoring devices on a single home/small-business subnet (`x.x.x.x/24`). It discovers devices via ARP/nmap, pings them on an interval, fires alerts, and serves a Bootstrap 5 + Chart.js dashboard with live WebSocket updates. **Not** intended for corporate/enterprise networks. There is no user authentication — the app assumes a trusted LAN.

## Common Commands

### Run the app
```bash
source venv/bin/activate
HOST=0.0.0.0 DEBUG=true python app.py     # dev
./run_production.sh                       # foreground with .env loaded
./install.sh --user                       # install as a per-user systemd service (no root)
```
Defaults (`config.py`): port 5000, network `192.168.86.0/24`, ping every 600 s, scan every 86400 s, SQLite at `homeNetMon.db` in the checkout. Override via `.env` (see `.env.example`). **Runtime settings saved from the Settings page (the `Configuration` table) win over `.env`** for `network_range`, `ping_interval`, `scan_interval` and `bandwidth_interval`; `init_db` only seeds them on a fresh database and logs a WARNING when they differ from the environment.

The deployment on this machine runs as the **user** unit `~/.config/systemd/user/homenetmon.service` with `DATABASE_URL` pointing at `production_data/homeNetMon.db` (gitignored). Do not commit database files.

### Tests
```bash
pytest tests/unit                         # what CI requires (~390 pass / ~90 skip); config in pyproject.toml
pytest tests/unit --cov=. --cov-fail-under=28   # coverage floor CI enforces (measured 30.5% on 2026-09-04)
pytest tests/unit/test_retention.py       # one file
pytest --no-cov -q                        # quick iteration
pytest tests/api tests/integration        # advisory in CI: 162 of 209 fail (written against endpoints that never existed)
npx playwright test TestHomeNetmon.js     # E2E (auto-starts the app; see playwright.config.js)
```
Skipped unit tests are listed in `tests/conftest.py:STALE_TEST_SKIPS` with a reason each; to revive one, fix it and remove its entry. Pytest options (`--strict-markers`, `timeout=15`, markers) live in `pyproject.toml [tool.pytest.ini_options]` — there is no `pytest.ini`.

Fixtures: `tests/fixtures/factories.py` imports `factories_original.py` (factory_boy) and falls back to `simple_factories.py` when factory_boy is unavailable. Every `SQLAlchemyModelFactory` sets `sqlalchemy_session = db.session`; keep that.

### Lint and formatting
```bash
ruff check .                # CI gate; config in pyproject.toml; version pinned in requirements-dev.txt and .pre-commit-config.yaml
ruff check --fix .
pre-commit run --all-files
```

### Database
```bash
venv/bin/python scripts/backup_database.py            # online, WAL-safe backup into backups/ (the sqlite3 CLI is not installed here)
venv/bin/python scripts/db/maintenance_window.py      # dry run: duplicate indexes, dead tables, VACUUM plan
venv/bin/python scripts/db/maintenance_window.py --execute   # only with the service stopped
```
Schema is created by `init_db()`/`create_all()` at startup; there is no migration framework. Adding a column means an `ALTER TABLE` migration (SQLite cannot alter constraints in place — see the `devices` rebuild in `maintenance_window.py` for the pattern).

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
3. Builds Socket.IO with `async_mode='threading'` and a `cors_allowed_origins_callback` that allows only RFC1918 / `.local` origins. Server pushes go to **rooms**; a page must emit `subscribe_to_updates` with `{types: ['device_status', 'monitoring_summary', 'alerts', ...]}` to receive `device_status_update`, `monitoring_summary` and `alert_update`.
4. Registers 18 API blueprints from `api/*.py` under `/api/<name>` prefixes (set at registration, not in the blueprint).
5. Instantiates **singleton services** and attaches them to the app: `app._scanner`, `app._monitor`, `app.alert_manager`, `app.bandwidth_monitor`, `app.speed_test_service`, `app.anomaly_detection_service`, `app.security_scanner`, `app.rule_engine_service`, `app.configuration_service`, `app.escalation_service`, `app.rate_limiter` (Flask-Limiter wrapper; `api/rate_limited_endpoints.py` reads `.rate_limiter.limiter`), `app.performance_monitor`, `app.resource_monitor`, `app.websocket_optimizer`, `app.websocket_connection_manager`, `app.query_cache`, `app.memory_monitor`, `app.socketio`, `app.security_middleware`, `app.emit_alert_update`. Other code reaches them via `current_app.<name>` — preserve the names.
6. Spawns one daemon thread per service in `start_monitoring_services()`. Every loop calls `core.health.record_heartbeat('<ThreadName>')`; the names must match `core/health.py:EXPECTED_THREADS`, which `/api/system/health` reports (503 when any thread is stale).

The security scanner is gated by `SECURITY_SCANNING_ENABLED` and off by default in code (nmap scans can destabilise IoT devices); this deployment enables it.

### Background services (`monitoring/`, `services/`)
- `monitoring/scanner.py` — ARP + nmap discovery on `scan_interval`; ignores addresses outside `NETWORK_RANGE`; handles DHCP address reuse (a different MAC on a known IP is a new device; the stale device loses its IP and monitoring); re-enables archived devices when their MAC reappears.
- `monitoring/monitor.py` — `DeviceMonitor`: pings every monitored device each `ping_interval` with a `ThreadPoolExecutor` sized by `max_workers`, waits for **all** results, records failures as rows; archives devices unseen for `stale_device_days` (`is_monitored=False`). `ping_device()` returns `SKIPPED` (not `None`) when the IoT optimizer defers a device.
- `monitoring/alerts.py` — `AlertManager`. **`create_alert()` is the only way to create an alert** (dedup on device/type/subtype, suppression rules, correlation, priority, notifications, WebSocket emit). The performance monitor and security scanner call it too. Thresholds and channel settings come from the runtime `Configuration` (Settings page) with `.env` fallback.
- `monitoring/bandwidth_monitor.py` — samples host interface counters into `InterfaceBandwidth`. Per-device bandwidth is not measurable from the host and no longer exists.
- `services/retention.py` — the single retention service (one rule per table); run hourly by `ResourceMonitor`. Never add per-insert cleanup hooks.
- `services/performance_monitor.py` — health scores from ping data only; a device with no samples in the window gets no row.

Pattern for a new background service: singleton with `start_monitoring()`, instantiate in `create_app()`, attach to `app`, launch via `threading.Thread(daemon=True, name=...)` in `start_monitoring_services()`, heartbeat each loop, add to `EXPECTED_THREADS`, open `with app.app_context():` per iteration (never for the thread's lifetime — it pins a SQLite snapshot and blocks WAL checkpoints).

### Core infrastructure (`core/`)
`security_middleware.py` (stateless HMAC CSRF tokens accepted from the `X-CSRF-Token` header or a form field only — never the cookie; security headers; CSP still needs `'unsafe-inline'` because templates carry inline scripts), `error_handler.py`, `health.py` (thread heartbeats), `validators.py`, `websocket_memory_manager.py`. Caching: `services/query_cache.py` (`invalidate_device_cache()` after device writes).

### Models (`models.py`)
`Device`, `DeviceIpHistory`, `MonitoringData`, `Alert`, `AlertSuppression`, `Configuration` + `ConfigurationHistory`, `InterfaceBandwidth`, `NotificationHistory`/`NotificationReceipt`, `AutomationRule`/`RuleExecution`, `EscalationRule`/`EscalationExecution`/`EscalationActionLog`, `SecurityScan`/`SecurityVulnerability`/`SecurityEvent`/`ComplianceResult`/`DeviceOSInfo`, `PerformanceMetrics`. `Device.ip_address` is nullable (cleared on DHCP reuse). `Device.to_dict()` and `to_dict_fast()` share a key set (`display_name`, `ip_address`, `is_monitored`, `status`, `active_alerts`, `latest_response_time`, ...); the 7-day `uptime_percentage()` is added only by the detail endpoint. `constants.DEVICE_DOWN_AFTER_SECONDS` is the one staleness threshold.

### API layer (`api/`)
Blueprint → `@create_endpoint_limiter(tier)` → validation (`core.validators`; device-control endpoints accept private addresses only) → response. **The response envelope is not uniform**: older endpoints return `{"success": true, ...}`, newer ones the `core.error_handler` shape. Don't migrate one side alone; normalize at the call site. Interactive docs at `/api/docs`.

### Frontend (`templates/`, `static/`)
Server-rendered Jinja + Bootstrap 5 + Chart.js + vanilla JS; no build step (templates append `?v={{ app_version }}` to static URLs). `static/js/ui-feedback.js` (loaded by the base template) provides `showToast/showSuccess/showError`, `escapeHtml`, `apiRequest`; `csrf-handler.js` adds the CSRF header to every unsafe fetch. Escape any string that a LAN device controls (hostnames, service banners) before `innerHTML`. Pages: `/` dashboard, `/device/<id>`, `/alerts`, `/analytics` (tabs, incl. performance and anomalies), `/network-map`, `/security`, `/settings`, escalation pages. Retired pages redirect.

## Conventions and gotchas

- **No authentication. Period.** Every endpoint is open to the LAN by design. Don't add `@login_required`/`g.current_user`; do add rate limiting and validation. CSRF is enforced on POST/PUT/PATCH/DELETE.
- **Never bind to 127.0.0.1 in deployment.** The units and Docker set `HOST=0.0.0.0`; `Config.HOST` alone does not.
- **Services are singletons attached to `app`.** Reuse `current_app._monitor`, `current_app.alert_manager`, etc.
- **Monitoring intervals are intentionally slow** (600 s ping, daily scan). `.env.example`, `docker-compose.yml` and the seeds agree; keep them agreeing.
- **`db.session` across threads** needs `with app.app_context():` per iteration.
- **Runtime `Configuration` overrides `.env`** (see above) — when a setting "does not change", check the Settings page / `/api/config`.
- **Dependencies**: `requirements.txt` is runtime-only and pinned; dev tools in `requirements-dev.txt`; Python ≥ 3.11. Run `pip-audit -r requirements.txt` after bumps.
- **Root-level `*.sh`/`*.py` helpers and everything under `scripts/` are operational one-shots**, not runtime. The runtime is `app.py` + `api/` + `core/` + `monitoring/` + `services/` + `models.py` + `config.py` + `constants.py`.
- **Version** lives in `version.py`, `pyproject.toml` and `package.json` (keep them equal) plus a `CHANGELOG.md` entry.

## Configuration

Read `config.py` and `.env.example`. Most-edited keys: `NETWORK_RANGE`, `PING_INTERVAL`, `SCAN_INTERVAL`, `DATA_RETENTION_DAYS`, `STALE_DEVICE_DAYS`, `BASE_URL`, `SMTP_*`, `NTFY_*`, `WEBHOOK_URL`, `SECRET_KEY`, `DATABASE_URL` (SQLite default; PostgreSQL supported — `docs/POSTGRESQL_MIGRATION.md`), `SECURITY_SCANNING_ENABLED`, `ALLOW_SERVICE_RESTART`.

## Further reading

- `README.md` — features and install walkthrough
- `docs/API_REFERENCE.md`, `docs/DEPLOYMENT_GUIDE.md`, `docs/TROUBLESHOOTING_GUIDE.md`, `docs/RESTORE.md`
- `tests/QUICK_START.md` — test commands by area
- `CHANGELOG.md` — 2.4.0 summarises the 2026-09 review
