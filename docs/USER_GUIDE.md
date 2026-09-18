# User Guide

Open `http://<server>:5000` on your LAN. There is no login. Every page updates live where it makes
sense; the navbar badge shows the number of active alerts and turns red if the live connection drops.

## Dashboard (`/`)

- **Hero tiles**: devices online, monitored devices (hover for the full inventory count), average
  response time, active alerts, internet status (gateway and external target, hover for availability)
  and overall network status. The numbers come from one shared definition, so they match the API and
  the analytics page.
- **Device grid / table**: search by name, IP, status, tag or note; filter by status, type and group;
  switch views; sort. Click a card to open the device page; the table view has per-row monitor toggles.
- **Scan Network** runs discovery now. **Add Device** registers a host discovery cannot see (IP, optional
  MAC, name, type, group, tags, notes). **Advanced** opens bulk enable/disable, presets, CSV export and
  **Reclassify unknown**.
- Shortcuts: `/` focuses search, `Ctrl+R` reloads devices, `Ctrl+N` starts a scan, `Esc` clears search.

## Device page (`/device/<id>`)

- Info cards: address, MAC, vendor, type, group / room, priority, last seen, response time, uptime,
  health score, tags, mDNS services, notes and IP-address changes.
- **Response Time** chart with 1H / 6H / 24H / 7D ranges and an **Uptime** ring.
- **Performance** card: latest health score with grade, availability over the window, median and 95th
  percentile response time, and a health / response-time chart for 24H / 7D / 30D.
- Actions: Ping now, Wake-on-LAN, Port scan, Discover info, Traceroute, Edit (name, type, priority,
  group, room, tags, notes, monitoring), Delete, Export CSV. Open ports found by the security scanner
  are listed below the charts.

## Alerts (`/alerts`)

- Filters run on the server: severity (critical, high, warning, medium, low, info), status (active,
  unacknowledged, acknowledged, resolved, all), time range (24 h to all time) and free-text search.
  Facet counts sit above the list; pages of 50.
- Each card shows the title, priority, severity, device link, message and timestamps, with
  **Acknowledge**, **Resolve** and **Delete**. Select several for bulk actions, or **Acknowledge all
  (filtered)** for everything matching the current filters. **Bulk delete** removes by type, status or
  severity; **Delete ALL alerts** asks you to type a confirmation.
- **Quiet hours & rules** suppresses alerts by device, type, severity and daily window.
- **Notification log** lists every delivery attempt (channel, status, error) for the last 7 days.

## Analytics (`/analytics`)

Network health score with recommendations, device insights (most reliable, fastest, least reliable,
slowest), usage patterns by hour and weekday, trends over the chosen range (24 h, 7 d, 30 d) and
host-interface bandwidth. Per-device bandwidth is not available: the host cannot see other devices'
traffic.

## Network map (`/network-map`)

A force-directed map of devices and their relationships (gateway dependency, similar-latency peers,
subnet gateway). Click a node for details, ping groups of devices from the toolbar, use the search box
to highlight matches.

## Security (`/security`)

Summary of open security alerts, risk assessment, per-device open ports and services, scan progress,
and the scanner settings (interval, top ports, service / version detection). **Run scan** and **Stop**
control the sweep; **Acknowledge all** clears open security alerts.

## Settings (`/settings`)

- **Network**: range to monitor, ping and scan intervals, the internet check (target, interval,
  failure threshold, gateway override). Saving validates, records history and reloads the services.
- **Interface**: dashboard title, auto-refresh, show offline devices.
- **Alerts & notifications**: down / latency thresholds; ntfy push, email, webhook and Discord channels,
  each with a **Send test** button.
- **History**: every configuration change with rollback.
- **System**: restart the service (when allowed), reset monitoring data.

## About (`/about`)

Version and build, host statistics, and **Service Health**: every background thread with its last
heartbeat.

## Alert types

| Type | Meaning | Resolves when |
|---|---|---|
| Device offline | No answer for the configured threshold | The device answers again |
| Device back online | Recovery notice | Informational |
| High latency | Response time above threshold | Latency normal for 5 minutes |
| New device discovered | Unknown host joined the network | After 24 hours |
| Performance … | Health score below threshold | Score recovers, or no data for a day |
| New open port / Suspicious port open | Security scanner findings | The port closes |
| Internet down / Gateway unreachable | Internet check failed repeatedly | Connectivity returns (with an "Internet restored" notice) |

Anything still open after `alert_max_open_days` (30 by default) is resolved as stale.
