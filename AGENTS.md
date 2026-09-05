# Repository Guidelines

Concise orientation for coding agents. `CLAUDE.md` holds the detailed architecture notes, gotchas and the facts about the deployment on this machine; read it before changing runtime code.

## Project Structure & Module Organization

HomeNetMon is a Flask, SQLAlchemy and Socket.IO application for monitoring one home LAN. `app.py` is the composition root; shared models and configuration live in `models.py`, `config.py` and `constants.py`. HTTP blueprints are under `api/`, cross-cutting infrastructure under `core/`, device discovery and polling under `monitoring/`, and background services under `services/`. Jinja pages live in `templates/`; the few JavaScript files, icons and the web manifest live in `static/` (no build step; templates append `?v=<version>` for cache busting). Tests are in `tests/unit/` (required in CI), `tests/api/` and `tests/integration/` (advisory); the browser suite is `TestHomeNetmon.js`. Deployment files are `systemd/`, `Dockerfile`, `docker-compose.yml` and `install.sh`; operational one-shots live under `scripts/`; documentation under `docs/`.

## Build, Test, and Development Commands

- `python3 -m venv venv && source venv/bin/activate`: create and activate a local environment (Python 3.11+).
- `pip install -r requirements.txt -r requirements-dev.txt`: runtime deps plus pytest, ruff and pip-audit.
- `cp .env.example .env && HOST=0.0.0.0 DEBUG=true python app.py`: run the development server on port 5000.
- `pytest tests/unit -q`: the CI unit-test target; `pytest tests/unit --cov=. --cov-fail-under=28` adds the coverage floor CI enforces.
- `npx playwright test TestHomeNetmon.js`: Chromium end-to-end tests; Playwright starts Flask automatically.
- `ruff check .` and `pre-commit run --all-files`: lint and repository sanity checks.
- `venv/bin/python scripts/backup_database.py`: WAL-safe online backup before any database work.

## Coding Style & Naming Conventions

Python 3.11+, four-space indentation, `snake_case` for modules and functions, `PascalCase` for classes. Ruff is configured in `pyproject.toml` (120-character lines, preserved quote style). Keep API routes in blueprints, validate input at the route, and reuse the singleton services attached by `create_app()` instead of constructing duplicates. Create alerts only through `AlertManager.create_alert()`; put table retention in `services/retention.py`, never in insert hooks. Frontend code is vanilla JavaScript; escape any string a LAN device controls (hostnames, service banners) before `innerHTML`, and use the helpers in `static/js/ui-feedback.js`.

## Testing Guidelines

Add focused unit tests for behaviour changes. Use the fixtures in `tests/conftest.py` and `tests/fixtures/`; database work in background threads needs an application context, and `create_app()` does not start background threads while `Config.TESTING` is set. Pytest options and markers live in `pyproject.toml` (`--strict-markers`). Skipped legacy tests are listed with reasons in `tests/conftest.py:STALE_TEST_SKIPS`; revive by fixing the test and removing its entry, and do not add skips without a reason.

## Commit & Pull Request Guidelines

Use concise, imperative subjects with a scope prefix (`feat:`, `fix:`, `test:`, `ci:`, `docs:`, `sec:`). Keep commits scoped. Pull requests should explain the problem and the fix, list the verification commands run, and include screenshots for visible UI changes. Call out configuration, schema or security effects explicitly; schema changes need an idempotent migration step (see `scripts/db/maintenance_window.py` for the SQLite rebuild pattern).

## Security & Configuration Tips

Never commit `.env`, database files, logs or secrets. The application intentionally has no authentication and is for trusted LAN use only; do not expose it to the internet. Preserve CSRF enforcement (`X-CSRF-Token` header), route-level validation, rate limiting and private-address-only device control. Runtime settings saved from the Settings page override `.env` for the network range and intervals; monitoring intervals are deliberately slow for home IoT devices.
