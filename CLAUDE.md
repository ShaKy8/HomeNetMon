# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HomeNetMon is a Flask + SQLAlchemy + Socket.IO web app for monitoring devices on a single home/small-business subnet (`x.x.x.x/24`). It discovers devices via ARP/nmap, pings them on an interval, fires alerts, and serves a Bootstrap 5 + Chart.js dashboard with live WebSocket updates. **Not** intended for corporate/enterprise networks. There is no user authentication — the app assumes a trusted LAN.

## Common Commands

### Run the app
```bash
source venv/bin/activate
HOST=0.0.0.0 DEBUG=true python app.py     # dev
python run_http2.py                       # HTTP/2 variant
./run_production.sh                       # production launcher
```
Defaults: port 5000, network `192.168.86.0/24`, SQLite at `homeNetMon.db`. Override via `.env` (see `.env.example`). The DB file in this repo is ~1 GB — do not commit changes to it.

### Tests
```bash
pytest                                    # full suite (pytest.ini enforces --cov-fail-under=80)
pytest tests/unit/test_unified_cache.py   # one file
pytest tests/unit/test_unified_cache.py::TestMemoryCache::test_lru_eviction  # one test
pytest -m unit                            # by marker (unit/integration/api/slow/network/performance/alerts/models/services)
pytest --no-cov                           # skip coverage gate when iterating
npx playwright test TestHomeNetmon.js     # E2E (auto-starts the Flask app; see playwright.config.js)
```
Test fixtures live in `tests/fixtures/factories.py` and `tests/conftest.py`.

### Assets
```bash
python build_assets.py                    # bundle + minify CSS/JS, writes manifest for cache busting
```
Run this after any change in `static/css/` or `static/js/`.

### Database
```bash
sqlite3 homeNetMon.db ".backup backup.db" # safe backup
python database_performance_fix.py        # apply perf indexes
python optimize_db_queries.py             # query optimization pass
```

### Production / service control
```bash
sudo systemctl {status,restart} homeNetMon
sudo journalctl -u homeNetMon -f
./install.sh                              # automated Ubuntu/Debian install
```

## Architecture

### Composition root: `app.py` `create_app()`
`create_app()` is large and order-sensitive. It:
1. Loads `Config` (from `config.py`, reads `.env`), sets up logging, calls `Config.validate_host_binding()` (which **forces** binding to non-loopback for LAN access).
2. Registers middlewares: `flask_compress`, `services.http_optimizer.HTTPOptimizer`, `services.cdn_manager.CDNManager`, `core.security_middleware.SecurityMiddleware` (CSRF), `core.error_handler.global_error_handler`, `performance_middleware.PerformanceMiddleware`.
3. Builds Socket.IO with a custom `cors_allowed_origins_callback` that allows only RFC1918 / `.local` origins.
4. Registers ~18 API blueprints from `api/*.py` under `/api/<name>` prefixes.
5. Instantiates **singleton services** and attaches them to the app object as `app._scanner`, `app._monitor`, `app.alert_manager`, `app.bandwidth_monitor`, `app.speed_test_service`, `app.anomaly_detection_service`, `app.security_scanner`, `app.rule_engine_service`, `app.configuration_service`, `app.escalation_service`, `app.rate_limiter`, `app.performance_monitor`, `app.websocket_optimizer`, `app.websocket_connection_manager`, `app.query_cache`, `app.memory_monitor`, `app.socketio`. Other code reaches services via `current_app.<name>` — preserve those attribute names when refactoring.
6. Spawns one daemon thread per long-running service (scanner, monitor, alerts, anomaly, bandwidth, rule engine, configuration, escalation, performance, optional security_scanner gated by `SECURITY_SCANNING_ENABLED=true`).

The security scanner is **disabled by default** because it can destabilize IoT devices on home networks.

### Background services (`monitoring/`, `services/`)
- `monitoring/scanner.py` — `NetworkScanner.start_continuous_scan()` runs ARP + nmap discovery on `SCAN_INTERVAL` (default 24h — deliberately slow to avoid hammering IoT devices).
- `monitoring/monitor.py` — `DeviceMonitor.start_monitoring()` pings all known devices every `PING_INTERVAL` (default 600s) using a thread pool capped at `MAX_WORKERS`, persists `MonitoringData`, and emits `device_status_update` / `monitoring_summary` over Socket.IO.
- `monitoring/alerts.py` — `AlertManager` periodically calls `check_device_down_alerts`, `check_high_latency_alerts`, `check_device_recovery_alerts`; dispatches via SMTP (`SMTP_*` env) and/or webhook (`WEBHOOK_URL`).
- `monitoring/bandwidth_monitor.py` — per-device bandwidth deltas on `BANDWIDTH_INTERVAL`.

If you add a new background service, follow the same pattern: singleton with `start_monitoring()` method, instantiate in `create_app()`, attach to `app`, launch via `threading.Thread(daemon=True)` inside `start_monitoring_services()`.

### Core infrastructure (`core/`)
Cross-cutting concerns: `security_middleware.py` (CSRF), `rate_limiter.py` (Redis-backed with in-memory fallback), `cache_layer.py` + `services/unified_cache.py` (LRU + TTL, used heavily by APIs), `db_optimizer.py` / `database_pool.py` (SQLAlchemy connection pool tuning), `websocket_manager.py` + `websocket_memory_manager.py` (fixes a known Socket.IO leak on long-lived rooms), `error_handler.py` (standardized JSON error envelopes).

### Models (`models.py`)
Single ~110 KB file. Primary entities: `Device`, `DeviceIpHistory`, `MonitoringData` (high-volume time-series), `Alert`, `AlertSuppression`, `Configuration` + `ConfigurationHistory`, `BandwidthData`, `NotificationHistory`/`NotificationReceipt`, `AutomationRule`/`RuleExecution`, `EscalationRule`/`EscalationExecution`/`EscalationActionLog`, `SecurityScan`/`SecurityVulnerability`/`SecurityEvent`/`SecurityIncident`, `PerformanceMetrics`/`PerformanceSnapshot`/`PerformanceAlert`, `OptimizationRecommendation`. `init_db(app)` performs lightweight schema bootstrapping; for structural changes use the scripts in `migrations/` or the ad-hoc `*_migration.py` / `database_schema_fix.py` files at the repo root.

### API layer (`api/`)
Each module exports a Flask `Blueprint` (e.g. `devices_bp`) registered in `app.py`. URL prefix is set at registration, **not** in the blueprint, so a route `@bp.route('/<id>')` inside `api/devices.py` becomes `/api/devices/<id>`. New endpoints should follow the existing pattern: blueprint → caching decorator from `services.query_cache` where appropriate → input validation via `core.validators` / `core.validation_middleware` → standardized response via `core.error_handler` helpers.

### Frontend (`templates/`, `static/`)
Server-rendered Jinja templates, Bootstrap 5, Chart.js, vanilla JS. Socket.IO emits drive live updates — see events `device_status_update` and `monitoring_summary`. After editing CSS/JS, run `python build_assets.py` to refresh the bundles and `static/manifest.json` (the manifest powers cache-busting hashes in templates).

## Conventions and gotchas

- **Never bind to 127.0.0.1 / localhost.** `Config.HOST` defaults to `127.0.0.1` in code but `Config.validate_host_binding()` forces `0.0.0.0` because the app is useless if it can't reach the LAN. Don't undo this.
- **No authentication.** Every endpoint is open on the LAN. Don't add auth-style assumptions; do add rate limiting and input validation. CSRF is enforced for state-changing requests via `core.security_middleware`.
- **Services are singletons attached to `app`.** Don't instantiate `DeviceMonitor`, `AlertManager`, etc. a second time — reuse `current_app._monitor`, `current_app.alert_manager`, etc.
- **Monitoring intervals are intentionally slow.** Defaults are tuned for flaky home IoT (10 min ping, 24 h scan). Don't shorten them in config defaults without a specific reason.
- **`db.session` across threads.** Background services run in daemon threads; they must use `with app.app_context():` for DB work. Existing services already do this — copy the pattern.
- **Coverage gate is 80%** (pytest.ini). Use `pytest --no-cov` for quick iteration, but the gate must pass before merging.
- **`homeNetMon.db` is ~1 GB.** It's in `.gitignore` patterns but check before staging. For schema work, copy to a scratch DB first.
- **Many root-level `*.py` files are one-shot scripts** (audits, migrations, performance reports) generated by past tasks. They are not part of the runtime — don't import from them. The runtime is `app.py` + `api/` + `core/` + `monitoring/` + `services/` + `models.py` + `config.py`.

## Configuration

Read `config.py` and `.env.example` for the full list. Most-edited keys: `NETWORK_RANGE`, `PING_INTERVAL`, `SCAN_INTERVAL`, `MAX_WORKERS`, `DATA_RETENTION_DAYS`, `SMTP_*`, `WEBHOOK_URL`, `SECRET_KEY`, `DATABASE_URL` (SQLite default; PostgreSQL supported — see `migrate_to_postgresql.py` and `POSTGRESQL_MIGRATION.md`). Runtime overrides also available via the `/settings` UI, stored in the `Configuration` table.

## Further reading

- `README.md` — user-facing feature list and install walkthrough
- `docs/API_REFERENCE.md`, `docs/DEPLOYMENT_GUIDE.md`, `docs/TROUBLESHOOTING_GUIDE.md`
- `tests/QUICK_START.md` — curated test commands by feature area
- `PHASE_2_AUDIT_REPORT.md` — recent architectural audit and recommendations
- API docs served at `/api/docs` (Swagger) and `/api/redoc` when the app is running
