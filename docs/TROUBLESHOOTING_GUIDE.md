# Troubleshooting Guide

Start with the three commands every section assumes:

```bash
systemctl --user status homenetmon
journalctl --user -u homenetmon --since "-30 min" --no-pager | grep -E "ERROR|WARNING|Traceback"
curl -s localhost:5000/api/system/health | python3 -m json.tool
```

## The service will not start

- `journalctl --user -u homenetmon -n 100` shows the traceback. Common causes:
  - **`SECRET_KEY` missing or too short**: set a 32+ character value in `.env`.
  - **Port in use**: another process on 5000 (`ss -ltnp | grep 5000`); change `PORT` in the unit or `.env`.
  - **Database path**: `DATABASE_URL` must be `sqlite:////absolute/path.db` (four slashes). The
    directory must exist and be writable by the service user.
  - **`nmap` missing**: `sudo apt install nmap`.
- The installed unit can drift from the template after an upgrade; regenerate it (Deployment Guide).

## Health reports a stale thread (503)

- The About page or `/api/system/health` names the thread. Restart the service; if it recurs, look for
  the thread's name in the journal. `SecurityScanner` is expected to be absent when scanning is off.
- A thread that never heartbeated is reported stale after one grace period; before that it shows
  `last_heartbeat_ago_s: null`.

## No devices are discovered

- The host must be on the subnet in `NETWORK_RANGE` (check **Settings → Network**, which overrides
  `.env`). Compare with `ip -4 addr` and `nmap -sn <range>` run by hand.
- `getcap $(which nmap) $(which ping)` should show `cap_net_raw`; otherwise `sudo setcap cap_net_raw+ep …`.
- Devices outside the range are archived on purpose; widen the range to bring them back.

## Devices show as down although they are up

- Some IoT devices ignore ICMP or sleep. Compare with `ping -c 1 <ip>` from the host.
- A device is *down* after `DEVICE_DOWN_AFTER_SECONDS` (900 s) without an answer, so with a 600 s ping
  interval one missed cycle is enough. Watch the device page's availability figure before worrying.

## Everything is "unknown" type

- Detection uses mDNS service types, hostnames and MAC vendors. Randomized MACs (phones, laptops) have
  no vendor by design. Run **Reclassify unknown** (dashboard → Advanced) after a scan; set the type by
  hand on the device page for the rest (it is never overwritten).
- Optional: point `DHCP_LEASES_FILE` at a dnsmasq / Pi-hole leases file to get DHCP hostnames.

## No alerts, or too many

- Thresholds and quiet hours: **Settings → Alerts** and **Alerts → Quiet hours & rules**.
- Notification channels each have a **Send test** button on the Settings page; failures are listed in
  the **Notification log** on the Alerts page with the provider's error.
- Old alerts close automatically after `alert_max_open_days` (30). Use **Acknowledge all (filtered)**
  to clear a backlog without deleting it.

## The dashboard does not update live

- Live updates need a Socket.IO connection; the navbar badge turns red when it drops. Reverse proxies
  must forward WebSocket upgrades (`Connection: upgrade`) or Socket.IO falls back to polling, which
  still works but slower.
- Origins other than RFC 1918 / `.local` are refused by design; access the dashboard by its LAN address.

## Settings do not change

Values saved from **Settings** are stored in the database and win over `.env`; the log prints a
`Runtime setting … overrides …` warning at start-up when they differ. Change them in Settings, or via
`PUT /api/config/<key>`, not in `.env`.

## Database problems

- **Locked / slow**: run the maintenance window with the service stopped (Operations Guide).
- **Corrupted**: restore the latest backup ([RESTORE.md](RESTORE.md)); `PRAGMA integrity_check` is
  part of every maintenance run.
- **Growing**: `DATA_RETENTION_DAYS` controls every time-series table; the hourly retention pass is
  reported in `/api/system/health` under `retention`.

## High CPU or memory

- Discovery and security scans are the expensive parts; both intervals are runtime settings. Lower
  `max_workers` if ping cycles saturate a small box.
- `journalctl … | grep "Slow request"` lists API calls over the slow-request threshold.

## Collect this before asking for help

```bash
curl -s localhost:5000/api/system/info | python3 -m json.tool
curl -s localhost:5000/api/system/health | python3 -m json.tool
journalctl --user -u homenetmon --since "-1 hour" --no-pager > /tmp/homenetmon-journal.txt
```
