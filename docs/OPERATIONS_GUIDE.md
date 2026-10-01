# Operations Guide

Commands assume the per-user service from the checkout; for the system install replace
`systemctl --user` with `sudo systemctl`, `journalctl --user` with `sudo journalctl`, and the paths
with `/opt/homenetmon/...`.

## Daily health

```bash
./health_check.sh                                  # 0 = every thread alive
curl -s localhost:5000/api/system/health | python3 -m json.tool
curl -s localhost:5000/api/monitoring/summary      # devices total/monitored/up/down, active alerts
curl -s localhost:5000/api/monitoring/wan          # internet + gateway state, 24 h availability
```

The **About** page shows the same thread health in the browser. A stale thread means it stopped
heartbeating for 2.5x its interval.

## Watching HomeNetMon itself (the outside watchdog)

HomeNetMon cannot report its own death, so a separate watchdog does. A systemd timer runs
`scripts/ops/homenetmon_watchdog.py` once a minute. It uses the **system Python and the standard
library only**, never the app's venv, so a broken venv or dependency cannot silence it (that is how a
44-hour outage went unnoticed in 2026-09). It reads `/api/system/health` on `127.0.0.1` and on the
machine's LAN address and pushes through the same ntfy topic as your alerts (Settings or `.env`).

| Push | When | Priority |
|---|---|---|
| **DOWN** | Three failed checks in a row (about 3 minutes): refused, timed out, HTTP error, or answering on `127.0.0.1` but not the LAN address. The body says what systemd reports (state, restart count) and the last log error. | high |
| **DEGRADED** | `/api/system/health` returns 503: it names the stale background threads. | high |
| **STILL DOWN / STILL DEGRADED** | Every 6 hours while the problem lasts. | high |
| **BACK** | Healthy again, with the outage length ("44 h 25 min"). | default |
| **checks were interrupted** | The machine was off, suspended or frozen for over 10 minutes (reported after it returns). | low |

A restart or a deploy takes about a minute and does not trigger it. A push that cannot be delivered
(for example the internet is down) is retried every minute until it gets through.

```bash
systemctl --user list-timers homenetmon-watchdog       # next and last run
journalctl --user -u homenetmon-watchdog -n 20
/usr/bin/python3 scripts/ops/homenetmon_watchdog.py --status
/usr/bin/python3 scripts/ops/homenetmon_watchdog.py --test           # sends a test push
/usr/bin/python3 scripts/ops/homenetmon_watchdog.py --pause 30       # planned maintenance longer than a few minutes
/usr/bin/python3 scripts/ops/homenetmon_watchdog.py --resume
```

Install: `./install.sh --user` does it. By hand:
`for u in service timer; do sed -e "s#%h/HomeNetMon#$PWD#g" systemd/homenetmon-watchdog.$u > ~/.config/systemd/user/homenetmon-watchdog.$u; done`
then `systemctl --user daemon-reload && systemctl --user enable --now homenetmon-watchdog.timer`.
Tunables in `.env`: `WATCHDOG_FAIL_THRESHOLD` (3), `WATCHDOG_REMINDER_HOURS` (6),
`WATCHDOG_HEARTBEAT_URL` (below). If push notifications are switched off in Settings the watchdog stays
silent and logs that it has no channel.

**What it cannot see.** The whole machine dying (power cut, freeze) cannot be reported by a program on
that machine, only afterwards by the "interrupted" push. A firewall that blocks the LAN is invisible
too, because traffic to the machine's own address never leaves it. For the first, add the optional
heartbeat below.

**Heartbeat (optional, recommended).** A free dead-man's-switch service such as healthchecks.io expects
a ping every minute and alerts you when the pings stop, which is the only way to hear about a dead
machine in real time. It also gets an immediate `/fail` ping when the watchdog confirms DOWN, a second
path if ntfy.sh itself is unreachable. Create a check with period 1 minute and grace 5 minutes, add the
notification integration you want (ntfy or email), then put its ping URL in `.env` as
`WATCHDOG_HEARTBEAT_URL=...` (it is read on every run, no restart needed). The URL is a secret: `.env`
is gitignored. Pings leave the machine; nothing connects in.

**The app also watches the watchdog.** The About page shows "Outside watchdog: last check N s ago", and if the
watchdog stays silent for 15 minutes while HomeNetMon has been up for ten, HomeNetMon pushes
"watchdog stopped".

## Logs

```bash
journalctl --user -u homenetmon -f                             # live
journalctl --user -u homenetmon --since "-1 day" | grep -E "ERROR|Traceback"
tail -f logs/homenetmon.log                                    # rotating file log (10 MB x 5)
```

Normal noise: `Runtime setting ... overrides ... from the environment` (Settings value wins),
`Large network detected` (a /24 is "large" for the exclusion optimiser), and werkzeug `Bad request`
lines from IoT devices speaking SIP/RTSP at port 5000.

## Backups

```bash
venv/bin/python scripts/backup_database.py                     # WAL-safe online backup into backups/
./setup_backup_cron.sh                                         # nightly cron entry
```

Restore procedure: [RESTORE.md](RESTORE.md). Back up before every upgrade and every maintenance window.

## Retention and database size

`services/retention.py` is the only place rows are deleted: one rule per table, run hourly by the
resource monitor, driven by `DATA_RETENTION_DAYS` (and per-table `*_retention_days` runtime keys).
Resolved alerts are kept 30 days; unresolved alerts are never deleted by retention. The last run is
reported under `retention` in `/api/system/health`.

For a VACUUM or index work use the maintenance window, always with the service stopped:

```bash
venv/bin/python scripts/backup_database.py
systemctl --user stop homenetmon
venv/bin/python scripts/db/maintenance_window.py               # dry run
venv/bin/python scripts/db/maintenance_window.py --execute
systemctl --user start homenetmon
```

The `sqlite3` CLI is not required; both scripts use Python's `sqlite3` module.

## One-shot upgrades (`scripts/db/`)

Each script is a dry run by default, refuses to execute while the service is active, and is
idempotent. Rehearse on a copy with `--db backups/copy.db --execute` first.

| Script | When | What |
|---|---|---|
| `v250_schema_cleanup.py` | upgrading to 2.5.0 | drop tables of removed models, add device columns, archive out-of-range devices |
| `v280_garage_removal.py` | upgrading to 2.8.0 | remove the garage feature's tables, settings and alerts |
| `v290_cleanup.py` | upgrading to 2.9.0 | `devices.alert_on_down`, quiet-hours rule → `notify_quiet_hours_*`, delete the eight seeded suppression rules and the dead `performance_metrics` columns |
| `v290_merge_duplicates.py` | upgrading to 2.9.0, and any time rotated MACs left duplicates | fold duplicate device rows (see the header for the skip rules; `--only`, `--skip`, `--force-pair KEEP DROP`, `--delete-orphans`) |

```bash
venv/bin/python scripts/backup_database.py
systemctl --user stop homenetmon
venv/bin/python scripts/db/v290_cleanup.py && venv/bin/python scripts/db/v290_cleanup.py --execute
venv/bin/python scripts/db/v290_merge_duplicates.py          # read every MERGE / apart / skip line
venv/bin/python scripts/db/v290_merge_duplicates.py --execute
systemctl --user start homenetmon && ./health_check.sh
```

## Alerts

- Alerts auto-resolve: device back online, latency normal, performance recovered (or no data for 24 h),
  informational alerts after a day, and anything open longer than `alert_max_open_days` (30).
- The Alerts page filters server-side (status, severity, time, search) and supports acknowledge /
  resolve / delete per alert, per selection and for every alert matching the current filters.
- **Notification policy** (Settings → Alerts): which types notify (device down, back online, new
  device, security, scan complete) and quiet hours; critical alerts always notify. Every alert is
  recorded; `Alert.notification_status` says whether it was `sent`, `failed`, `none` (no channel
  enabled) or `suppressed` (policy). Nothing is seeded any more; suppression rules under
  **Alerts → Quiet hours & rules** are for per-device / per-type exceptions.
- Per device: **Alert when down** on the device page (or the bell in the dashboard table). Phones,
  Apple devices and unidentified hosts are silent unless switched on; routers and servers always alert.
- Recoveries in the first 15 minutes after a restart are recorded but not pushed.
- Notification deliveries are listed at the bottom of the Alerts page (**Notification log**); a red
  badge counts the week's failed deliveries (ntfy 429s show there).

## Devices

- Discovery runs every `scan_interval`; **Scan Network** on the dashboard runs it now.
- Devices outside `NETWORK_RANGE` are archived when the range changes; widening the range resumes them.
- **Reclassify unknown** (dashboard → Advanced) re-runs type detection for devices still typed
  *unknown*; types set by hand are never overwritten.
- Devices unseen for `STALE_DEVICE_DAYS` are archived and resume automatically when seen again.
- A randomized MAC that reappears with a known hostname is adopted into the existing row
  (`mac_rotation` in the device's address history) instead of creating a duplicate; duplicates from
  before 2.9.0 are folded by `scripts/db/v290_merge_duplicates.py`.
- **Needs attention** (dashboard → Advanced) lists unnamed or untyped devices with inline editors.

## Security scanning

Enable with `SECURITY_SCANNING_ENABLED=true` (restart required). The scan interval, top-port count and
service/version detection are on the **Security** page and apply from the next sweep. Printers are
excluded by default; nmap probes can jam some models. A sweep of ~60 devices takes tens of minutes;
the scanner heartbeats per device so the watchdog stays quiet.

## Internet check

The WAN monitor pings the default gateway and `wan_check_target` every `wan_check_interval` seconds.
After `wan_down_after_checks` failures it raises `wan_down` (or `gateway_down` when the gateway itself
is silent) and resolves it on recovery. All three are under **Settings → Network → Internet check**.

## Configuration history

Every value saved from Settings (and via `PUT /api/config/...`) is validated and recorded;
**Settings → History** shows the log and offers rollback.
