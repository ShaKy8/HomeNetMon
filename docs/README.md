# HomeNetMon Documentation

HomeNetMon monitors one home or small-office subnet: it discovers devices, pings them, checks the
internet link, port-scans on a schedule, raises alerts and shows everything on a Bootstrap dashboard
with live updates. There is **no login**: it is meant for a trusted LAN only.

| Guide | Read it when |
|---|---|
| [Deployment Guide](DEPLOYMENT_GUIDE.md) | Installing as a per-user or system `systemd` service, or with Docker; upgrading; configuration |
| [User Guide](USER_GUIDE.md) | Using the dashboard, device pages, alerts, analytics, network map, security page and settings |
| [Operations Guide](OPERATIONS_GUIDE.md) | Day-to-day checks, logs, backups, the maintenance window, retention |
| [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md) | Something is wrong: service, discovery, pings, alerts, database, performance |
| [Security Guide](SECURITY_GUIDE.md) | The trust model, what the app does and does not protect, hardening that actually applies |
| [API Reference](API_REFERENCE.md) | Every route the UI calls, generated from the route map (`/api/docs` is the interactive version) |
| [Restore](RESTORE.md) | Restoring the SQLite database from a backup |
| [PostgreSQL Migration](POSTGRESQL_MIGRATION.md) | Moving off SQLite (optional) |

Developer notes (architecture, conventions, gotchas) live in the repository root: `CLAUDE.md` and `AGENTS.md`.
The release history is in `CHANGELOG.md`.
