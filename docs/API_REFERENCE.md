# HomeNetMon API Reference

Generated from the live route map (the same source as `/api/docs` and `/api/openapi.json`); every route
listed here has a caller in the web UI, a script or the health check. Regenerate after changing routes:

```bash
DATABASE_URL=sqlite:///:memory: venv/bin/python scripts/generate_api_reference.py > docs/API_REFERENCE.md
```

## Conventions

- **No authentication.** HomeNetMon is for a trusted LAN; keep it off the internet.
- **CSRF.** Every POST/PUT/PATCH/DELETE must carry `X-CSRF-Token` from `GET /api/csrf-token`
  (the browser helper `static/js/csrf-handler.js` does this automatically).
- **Envelopes are not uniform.** Older routes return `{"success": true, ...}`; newer ones return the
  `core/error_handler.py` shape. Errors are always JSON with an `error` key. Normalise at the call site.
- **Timestamps** are UTC ISO-8601 with a `Z` suffix.
- **Rate limits** per route: `relaxed` 120/min, `moderate` 60/min, `strict` 10/min, `bulk` 2/min,
  `critical` 1 per 5 minutes. Localhost and `RATE_LIMIT_TRUSTED_IPS` are exempt.
- **Counts** (`total_devices`, `monitored_devices`, `devices_up`, `devices_down`, `active_alerts`) share
  one definition, `services/device_counts.py`, everywhere they appear.

## Devices and device control

| Method | Path | What it does |
|---|---|---|
| `POST` | `/api/device-control/discover-info` | Discover additional information about a device Rate limit tier: strict. |
| `POST` | `/api/device-control/port-scan` | Scan ports on a device Rate limit tier: critical. |
| `POST` | `/api/device-control/traceroute` | Perform traceroute to a device Rate limit tier: strict. |
| `POST` | `/api/device-control/wake-on-lan` | Send Wake-on-LAN magic packet to device Rate limit tier: strict. |
| `GET` | `/api/devices` | Get all devices with optional filtering - ULTRA-CACHED VERSION Rate limit tier: relaxed. |
| `POST` | `/api/devices` | Create a new device Rate limit tier: strict. |
| `POST` | `/api/devices/bulk-update` | Bulk update device properties Rate limit tier: bulk. |
| `POST` | `/api/devices/ping-all` | Ping all monitored devices Rate limit tier: intensive. |
| `POST` | `/api/devices/reclassify` | Re-run device type classification. Body {"all": true} redoes every auto-classified device; default is only devices still typed 'unknown'. User-set types on the device page are kept because they are never 'unknown'. Rate limit tier: strict. |
| `POST` | `/api/devices/scan-now` | Trigger a manual network scan with progress updates |
| `GET` | `/api/devices/scan-status` | Get current scan status Rate limit tier: relaxed. |
| `GET` | `/api/devices/types` | Get all device types Rate limit tier: relaxed. |
| `DELETE` | `/api/devices/{device_id}` | Delete a device Rate limit tier: strict. |
| `GET` | `/api/devices/{device_id}` | Get specific device details Rate limit tier: relaxed. |
| `PATCH` | `/api/devices/{device_id}` | Update device details with validation Rate limit tier: strict. |
| `PUT` | `/api/devices/{device_id}` | Update device details with validation Rate limit tier: strict. |
| `GET` | `/api/devices/{device_id}/history.csv` | Export per-device ping history as CSV. |
| `GET` | `/api/devices/{device_id}/ip-history` | Get IP address change history for a device Rate limit tier: relaxed. |
| `POST` | `/api/devices/{device_id}/ping` | Trigger ping for a single device Rate limit tier: strict. |

## Monitoring, summary, bandwidth, internet

| Method | Path | What it does |
|---|---|---|
| `GET` | `/api/monitoring/bandwidth/devices` | Per-interface ranking (kept at this URL for the analytics page). Rate limit tier: relaxed. |
| `GET` | `/api/monitoring/bandwidth/summary` | Aggregate host throughput over the window, plus per-interface totals. Rate limit tier: relaxed. |
| `GET` | `/api/monitoring/bandwidth/timeline` | Interface throughput bucketed for charts (sum across interfaces per bucket). Rate limit tier: relaxed. |
| `GET` | `/api/monitoring/data` | Get monitoring data with optional filtering and pagination Rate limit tier: relaxed. |
| `GET` | `/api/monitoring/summary` | Get comprehensive monitoring summary for high-level dashboard Rate limit tier: relaxed. |
| `GET` | `/api/monitoring/wan` | Internet / gateway reachability: current state plus availability over ?hours= (24). Rate limit tier: relaxed. |

## Alerts, suppression rules, notification log

| Method | Path | What it does |
|---|---|---|
| `GET` | `/api/monitoring/alerts` | List alerts with server-side filtering, facets and paging. |
| `POST` | `/api/monitoring/alerts/acknowledge-all` | Acknowledge every open alert matching the body's filters (same keys as GET /alerts). Rate limit tier: bulk. |
| `POST` | `/api/monitoring/alerts/bulk-acknowledge` | Acknowledge the alerts listed in alert_ids. Rate limit tier: bulk. |
| `DELETE` | `/api/monitoring/alerts/bulk-delete` | Delete alerts by specific criteria (type, status, etc.) Rate limit tier: critical. |
| `POST` | `/api/monitoring/alerts/bulk-resolve` | Resolve the alerts listed in alert_ids. Rate limit tier: bulk. |
| `DELETE` | `/api/monitoring/alerts/delete-all` | Delete all alerts Rate limit tier: critical. |
| `GET` | `/api/monitoring/alerts/suppressions` | Get all alert suppression rules Rate limit tier: relaxed. |
| `POST` | `/api/monitoring/alerts/suppressions` | Create a new alert suppression rule Rate limit tier: strict. |
| `DELETE` | `/api/monitoring/alerts/suppressions/{suppression_id}` | Delete an alert suppression rule Rate limit tier: strict. |
| `PUT` | `/api/monitoring/alerts/suppressions/{suppression_id}` | Update an alert suppression rule Rate limit tier: strict. |
| `DELETE` | `/api/monitoring/alerts/{alert_id}` | Delete a specific alert Rate limit tier: strict. |
| `POST` | `/api/monitoring/alerts/{alert_id}/acknowledge` | Acknowledge an alert Rate limit tier: strict. |
| `POST` | `/api/monitoring/alerts/{alert_id}/resolve` | Resolve an alert Rate limit tier: strict. |
| `GET` | `/api/notifications/history` | Get notification history with optional filtering Rate limit tier: relaxed. |

## Analytics and per-device performance

| Method | Path | What it does |
|---|---|---|
| `GET` | `/api/analytics/device-insights` | Get insights about device patterns and behavior Rate limit tier: relaxed. |
| `GET` | `/api/analytics/network-health-score` | Calculate overall network health score Rate limit tier: relaxed. |
| `GET` | `/api/analytics/network-trends` | Get network performance trends over time Rate limit tier: relaxed. |
| `GET` | `/api/analytics/topology/visualization` | Get network topology data optimized for visualization Rate limit tier: relaxed. |
| `GET` | `/api/analytics/usage-patterns` | Analyze device usage patterns over time Rate limit tier: relaxed. |
| `GET` | `/api/performance/device/{device_id}` | Latest collector scores plus window percentiles for one device. Rate limit tier: relaxed. |
| `GET` | `/api/performance/device/{device_id}/timeline` | Collector rows bucketed by hour (default) or day: health, response time, uptime. Rate limit tier: relaxed. |

## Security scanner

| Method | Path | What it does |
|---|---|---|
| `GET` | `/api/security/alerts` | Get recent security alerts Rate limit tier: relaxed. |
| `GET` | `/api/security/device/{device_id}/ports` | Get open ports and services for a specific device Rate limit tier: relaxed. |
| `POST` | `/api/security/device/{device_id}/scan` | Manually trigger a security scan for a specific device Rate limit tier: critical. |
| `GET` | `/api/security/network-overview` | Get network-wide security overview Rate limit tier: relaxed. |
| `GET` | `/api/security/risk-assessment` | Get network risk assessment Rate limit tier: relaxed. |
| `POST` | `/api/security/run-scan` | Manually trigger a network-wide security scan Rate limit tier: critical. |
| `GET` | `/api/security/scan-progress` | Get current scan progress Rate limit tier: relaxed. |
| `POST` | `/api/security/stop-scan` | Stop the currently running network security scan Rate limit tier: strict. |
| `GET` | `/api/security/summary` | Get security summary statistics Rate limit tier: relaxed. |

## Configuration

| Method | Path | What it does |
|---|---|---|
| `GET` | `/api/config` | Get all configuration settings Rate limit tier: relaxed. |
| `GET` | `/api/config-management/history` | Get configuration change history Rate limit tier: relaxed. |
| `POST` | `/api/config-management/rollback` | Rollback configuration to previous value Rate limit tier: strict. |
| `GET` | `/api/config/alerts` | Get alert-related configuration Rate limit tier: relaxed. |
| `PUT` | `/api/config/alerts` | Update alert configuration Rate limit tier: strict. |
| `GET` | `/api/config/network` | Get network-related configuration Rate limit tier: relaxed. |
| `PUT` | `/api/config/network` | Update network configuration Rate limit tier: strict. |
| `POST` | `/api/config/reset-monitoring-data` | Reset all historical monitoring data Rate limit tier: critical. |
| `POST` | `/api/config/restart-system` | Restart the HomeNetMon application Rate limit tier: strict. |
| `POST` | `/api/config/test/discord` | Post a test embed to a Discord webhook (URL from the body, else the saved one). Rate limit tier: strict. |
| `POST` | `/api/config/test/email` | Test email configuration by sending a test email Rate limit tier: strict. |
| `POST` | `/api/config/test/push` | Test push notification configuration by sending a test notification Rate limit tier: strict. |
| `POST` | `/api/config/test/webhook` | Test webhook configuration by sending a test webhook Rate limit tier: strict. |
| `PUT` | `/api/config/{key}` | Update specific configuration value Rate limit tier: strict. |

## System

| Method | Path | What it does |
|---|---|---|
| `GET` | `/api/csrf-token` | API endpoint to get a fresh CSRF token |
| `GET` | `/api/system/health` | Liveness check including background-thread heartbeat status. |
| `GET` | `/api/system/info` | Get comprehensive system information including version, app details, and system stats Rate limit tier: relaxed. |

## Parameters worth knowing

### `GET /api/monitoring/alerts`

`severity` (csv of critical, high, warning, medium, low, info), `status` (active default, unacknowledged,
acknowledged, resolved, all), `hours` (168 default, `0` = all time), `device_id`, `alert_type`,
`alert_type_prefix`, `q` (substring over message, device name, IP), `sort` (created_at or
priority_score), `page`, `per_page` (50, max 200). Returns `alerts`, `pagination`, `facets`
(`status` and `severity` counts) and the normalised `filters`. `POST /alerts/acknowledge-all` accepts the
same keys in its JSON body.

### `GET /api/monitoring/data`

`device_id`, `hours` (24, max 168), `page`, `per_page` or `limit` (max 2000).

### `GET /api/analytics/network-health-score` and `/device-insights`

`hours` or `days` (max 90 days).

### `GET /api/monitoring/wan`

`hours` (24, max 720): current gateway / internet state, availability, average RTT, downsampled timeline.

### `GET /api/performance/device/{device_id}`

`hours` (24, max 2160): the collector's latest scores plus availability and p50 / p95 / max response time
from raw ping samples. `/timeline` adds `granularity=hour|day`.

### `POST /api/devices`

`ip_address` (required), `mac_address`, `custom_name`, `device_type` (auto-detected when omitted),
`device_group`, `room_location`, `tags` (list or csv), `notes`, `is_monitored`. Hostname and vendor are
filled in automatically when possible.

### `POST /api/devices/reclassify`

Body `{"all": true}` re-runs classification for every auto-classified device; the default only touches
devices still typed `unknown`. Types set by hand are never changed.

### `PUT /api/config/<key>` and `PUT /api/config/network` / `/alerts`

All three go through the configuration service: values are validated, a `configuration_history` row is
written (`GET /api/config-management/history`, `POST /rollback`) and the running services reload.
