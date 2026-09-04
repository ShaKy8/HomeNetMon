# Changelog

All notable changes to HomeNetMon will be documented in this file.

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
