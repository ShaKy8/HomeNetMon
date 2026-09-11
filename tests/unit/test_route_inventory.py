"""Every /api route must have a caller. 172 of 257 routes had none in 2.4.0 and
several returned 500; this pins the surviving set so dead endpoints cannot creep
back unnoticed. Update ALLOWED when a page gains a real caller.
"""

REMOVED_PREFIXES = ('/api/escalation', '/api/automation', '/api/anomaly', '/api/speedtest', '/api/ai',
                    '/api/health', '/api/maintenance', '/api/performance-optimization', '/api/rate-limit',
                    '/api/notifications/receipt', '/api/notifications/analytics')

ALLOWED = {
    '/api/analytics/device-insights',
    '/api/analytics/network-health-score',
    '/api/analytics/network-trends',
    '/api/analytics/topology/visualization',
    '/api/analytics/usage-patterns',
    '/api/config',
    '/api/config-management/history',
    '/api/config-management/rollback',
    '/api/config/<string:key>',
    '/api/config/alerts',
    '/api/config/network',
    '/api/config/reset-monitoring-data',
    '/api/config/restart-system',
    '/api/config/test/discord',
    '/api/config/test/email',
    '/api/config/test/push',
    '/api/config/test/webhook',
    '/api/csrf-token',
    '/api/openapi.json',
    '/api/device-control/discover-info',
    '/api/device-control/port-scan',
    '/api/device-control/traceroute',
    '/api/device-control/wake-on-lan',
    '/api/devices',
    '/api/devices/<int:device_id>',
    '/api/devices/<int:device_id>/history.csv',
    '/api/devices/<int:device_id>/ip-history',
    '/api/devices/<int:device_id>/ping',
    '/api/devices/bulk-update',
    '/api/devices/ping-all',
    '/api/devices/reclassify',
    '/api/devices/scan-now',
    '/api/devices/scan-status',
    '/api/devices/types',
    '/api/monitoring/alerts',
    '/api/monitoring/alerts/<int:alert_id>',
    '/api/monitoring/alerts/<int:alert_id>/acknowledge',
    '/api/monitoring/alerts/<int:alert_id>/resolve',
    '/api/monitoring/alerts/acknowledge-all',
    '/api/monitoring/alerts/bulk-acknowledge',
    '/api/monitoring/alerts/bulk-delete',
    '/api/monitoring/alerts/bulk-resolve',
    '/api/monitoring/alerts/delete-all',
    '/api/monitoring/alerts/suppressions',
    '/api/monitoring/alerts/suppressions/<int:suppression_id>',
    '/api/monitoring/bandwidth/devices',
    '/api/monitoring/bandwidth/summary',
    '/api/monitoring/bandwidth/timeline',
    '/api/monitoring/data',
    '/api/monitoring/summary',
    '/api/monitoring/wan',
    '/api/notifications/history',
    '/api/performance/alerts/summary',
    '/api/performance/collect',
    '/api/performance/collect/<int:device_id>',
    '/api/performance/device/<int:device_id>',
    '/api/performance/device/<int:device_id>/timeline',
    '/api/performance/devices',
    '/api/performance/health-scores',
    '/api/performance/summary',
    '/api/performance/top-performers',
    '/api/security/alerts',
    '/api/security/device/<int:device_id>/ports',
    '/api/security/device/<int:device_id>/scan',
    '/api/security/network-overview',
    '/api/security/risk-assessment',
    '/api/security/run-scan',
    '/api/security/scan-progress',
    '/api/security/stop-scan',
    '/api/security/summary',
    '/api/system/health',
    '/api/system/info',
}


def _api_rules(app):
    return {r.rule for r in app.url_map.iter_rules()
            if r.rule.startswith('/api/') and not r.rule.startswith(('/api/docs', '/api/redoc'))}


def test_no_removed_prefix_is_registered(app):
    offenders = sorted(r for r in _api_rules(app) if r.startswith(REMOVED_PREFIXES))
    assert offenders == []


def test_api_surface_is_exactly_the_allowlist(app):
    rules = _api_rules(app)
    assert sorted(rules - ALLOWED) == [], 'new routes need a caller and an ALLOWED entry'
    assert sorted(ALLOWED - rules) == [], 'allowlisted route no longer exists'
