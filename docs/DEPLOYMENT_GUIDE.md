# Deployment Guide

HomeNetMon is a single Python process (Flask + Socket.IO + background threads) with a SQLite database.
It needs `nmap` and `ping` on the host and a network interface on the subnet it monitors. It serves
plain HTTP on the LAN and has no authentication: **do not expose it to the internet**.

## Requirements

- Linux with Python 3.11+ (tested on Ubuntu/Debian), `nmap`, `iputils-ping`
- The host must sit on the monitored subnet (`NETWORK_RANGE`, one `/24`-style range per instance)
- `ping` and `nmap` with `cap_net_raw` (Debian/Ubuntu default) so discovery works unprivileged

## Option A: per-user systemd service (recommended for a home server)

Runs from the git checkout as your own user; no root except for installing packages.

```bash
git clone https://github.com/ShaKy8/HomeNetMon.git && cd HomeNetMon
./install.sh --user
```

The installer creates `venv/`, copies `.env.example` to `.env` if needed, writes
`~/.config/systemd/user/homenetmon.service` from `systemd/homenetmon.user.service` with the checkout
path filled in, enables lingering so the service survives logout, and starts it.

```bash
systemctl --user status homenetmon
journalctl --user -u homenetmon -f
./health_check.sh                      # exits 0 when /api/system/health reports every thread alive
```

The database lives at `production_data/homeNetMon.db` (gitignored) and logs at `logs/homenetmon.log`.

## Option B: system-wide systemd service

Installs into `/opt/homenetmon` under a dedicated `homenetmon` user with the hardened unit
`systemd/homenetmon.service` (ProtectSystem, PrivateTmp, …).

```bash
./install.sh                            # asks for sudo where needed
sudo systemctl status homenetmon
sudo journalctl -u homenetmon -f
```

Database: `/opt/homenetmon/data/homeNetMon.db`; configuration: `/opt/homenetmon/.env`.

## Option C: Docker

```bash
cp .env.example .env         # set NETWORK_RANGE at least
docker compose up -d
docker compose logs -f homenetmon
```

The container needs host networking (already set in `docker-compose.yml`) so ARP/nmap discovery and
pings see the LAN. The database is a bind mount under `./data`.

## What actually runs

All three options start gunicorn with one worker and a threaded worker class:

```
gunicorn --workers 1 --worker-class gthread --threads 32 --bind 0.0.0.0:5000 wsgi:app
```

One worker is required: Socket.IO state and the monitoring threads live in the process. For
development use `HOST=0.0.0.0 DEBUG=true PORT=5001 python app.py` (no reloader; restart after edits).

`GET /api/system/health` reports every background thread (scanner, monitor, alerts, bandwidth,
performance, retention, WAN check, security scanner when enabled) and returns 503 if one is stale.

## Configuration

Copy `.env.example` to `.env` and read its comments; the important keys:

| Key | Default | Meaning |
|---|---|---|
| `NETWORK_RANGE` | `192.168.86.0/24` | The subnet to discover and ping. Devices outside it are archived. |
| `PING_INTERVAL` / `SCAN_INTERVAL` | 600 / 86400 s | Deliberately gentle; IoT devices dislike frequent probes. |
| `DATA_RETENTION_DAYS` | 30 | Applies to every time-series table. |
| `STALE_DEVICE_DAYS` | 30 | Unseen devices stop being pinged until they reappear. |
| `SECURITY_SCANNING_ENABLED` | false | Scheduled nmap port scans of every monitored device. |
| `WAN_CHECK_TARGET` / `WAN_CHECK_INTERVAL` | 1.1.1.1 / 60 s | Internet reachability check. |
| `SMTP_*`, `NTFY_*`, `WEBHOOK_URL` | | Notification channels (the Settings page can also set most of these). |
| `SECRET_KEY` | required | Signs CSRF tokens; the installer generates one. |
| `HOST` / `PORT` | 127.0.0.1 / 5000 | The units and Docker set `HOST=0.0.0.0`. |

**Runtime settings win.** Network range, intervals, alert thresholds, notification channels, security
scan settings and the internet check are stored in the database once saved from **Settings**; the
environment only seeds them on a fresh database (the log warns when they differ).

## Upgrading

```bash
git pull
venv/bin/pip install -r requirements.txt
venv/bin/python scripts/backup_database.py
systemctl --user restart homenetmon        # sudo systemctl restart homenetmon for the system unit
./health_check.sh
```

Schema changes ship as idempotent steps in `init_db()` (new columns) or as a one-shot under
`scripts/db/` for anything that needs the service stopped; the changelog says which. For 2.5.0:

```bash
systemctl --user stop homenetmon
venv/bin/python scripts/db/v250_schema_cleanup.py            # dry run
venv/bin/python scripts/db/v250_schema_cleanup.py --execute
systemctl --user start homenetmon
```

If the unit template changed, regenerate the installed unit:

```bash
sed -e "s#%h/HomeNetMon#$PWD#g" systemd/homenetmon.user.service > ~/.config/systemd/user/homenetmon.service
systemctl --user daemon-reload && systemctl --user restart homenetmon
```

## HTTPS and remote access

HomeNetMon serves HTTP only. If you want TLS or access from outside the LAN, put it behind a reverse
proxy that terminates TLS and adds authentication (Caddy, nginx with basic auth, Tailscale, a VPN).
Set `BASE_URL` so notification links use the public address. See the [Security Guide](SECURITY_GUIDE.md).
