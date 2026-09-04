# Repository Guidelines

## Project Structure & Module Organization

HomeNetMon is a Flask, SQLAlchemy, and Socket.IO application. `app.py` is the composition root; shared models and configuration live in `models.py`, `config.py`, and `constants.py`. HTTP blueprints are under `api/`, cross-cutting infrastructure under `core/`, device discovery and polling under `monitoring/`, and application services under `services/`. Jinja pages live in `templates/`; source CSS, JavaScript, images, and generated bundles live in `static/`. Tests are grouped into `tests/unit/`, `tests/api/`, and `tests/integration/`; the browser suite is `TestHomeNetmon.js`. Deployment manifests are in `docker/`, `k8s/`, and `helm/`, with operational documentation in `docs/`.

## Build, Test, and Development Commands

- `python3 -m venv venv && source venv/bin/activate`: create and activate a local environment.
- `pip install -r requirements.txt`: install runtime and Python test dependencies.
- `cp .env.example .env && HOST=0.0.0.0 DEBUG=true python app.py`: configure and run the development server on port 5000.
- `pytest tests/unit --no-cov --timeout=15 -q --tb=short`: run the CI unit-test target quickly.
- `pytest`: run all configured Python tests with the 80% coverage gate and reports.
- `npx playwright test TestHomeNetmon.js`: run Chromium end-to-end tests; Playwright starts Flask automatically.
- `ruff check .` and `pre-commit run --all-files`: run lint and repository sanity checks.
- `python build_assets.py`: regenerate bundles and the cache-busting manifest after editing `static/css/` or `static/js/`.

## Coding Style & Naming Conventions

Use Python 3.10+ with four-space indentation, `snake_case` for modules/functions, and `PascalCase` for classes. Ruff is configured in `pyproject.toml` with a 120-character target and preserved quote style. Keep API routes in blueprints and reuse singleton services attached by `create_app()` rather than constructing duplicates. Tests use `test_*.py`, `Test*` classes, and `test_*` functions. Keep frontend code vanilla JavaScript and follow nearby formatting.

## Testing Guidelines

Add focused unit tests for behavior changes and API/integration tests for boundaries. Use existing fixtures in `tests/fixtures/`; database work in background threads requires an application context. Mark specialized tests with the registered markers in `pytest.ini`. Do not remove or add stale-test skips without documenting the reason in `tests/conftest.py`.

## Commit & Pull Request Guidelines

Recent history uses concise, imperative subjects with prefixes such as `feat:`, `fix:`, `test:`, `ci:`, and `sec:`. Keep commits scoped and include regenerated assets when applicable. Pull requests should explain the problem and solution, list verification commands, link relevant issues, and include screenshots for visible UI changes. Call out configuration, schema, or security effects explicitly.

## Security & Configuration Tips

Never commit `.env`, database files, logs, or secrets. The application intentionally has no authentication and is for trusted LAN use only; do not expose it directly to the internet. Preserve input validation, CSRF protection, rate limiting, and the non-loopback host binding.
