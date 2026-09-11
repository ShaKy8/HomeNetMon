"""The Settings page writes network and alert settings through
PUT /api/config/network and /alerts. Those must go through the configuration
service so validation runs, a ConfigurationHistory row exists (the rollback UI
reads it) and the hot-reload callbacks registered in app.py fire. In production
configuration_history had 0 rows because both routes wrote the table directly."""

from unittest.mock import MagicMock, patch

from models import Configuration, ConfigurationHistory


def _headers(client):
    return {'X-CSRF-Token': client.get('/api/csrf-token').get_json()['csrf_token']}


def test_network_put_records_history_and_fires_callbacks(client, app, db_session):
    fired = []
    app.configuration_service.register_service_callback('write_path_probe', lambda k, o, n: fired.append((k, n)))
    try:
        r = client.put('/api/config/network', json={'ping_interval': 900}, headers=_headers(client))
        assert r.status_code == 200, r.get_json()
        assert 'note' not in r.get_json()
        with app.app_context():
            assert Configuration.get_value('ping_interval') == '900'
            row = ConfigurationHistory.query.filter_by(config_key='ping_interval')\
                .order_by(ConfigurationHistory.id.desc()).first()
            assert row is not None
            assert row.new_value == '900'
            assert row.changed_by == 'settings_ui'
        assert ('ping_interval', '900') in fired
    finally:
        app.configuration_service.unregister_service_callback('write_path_probe')


def test_network_put_rejects_invalid_values_with_a_message(client, db_session):
    r = client.put('/api/config/network', json={'ping_interval': 5}, headers=_headers(client))
    assert r.status_code == 400
    assert 'error' in r.get_json()
    r = client.put('/api/config/network', json={'scan_excluded_ips': '192.168.1.5, not-an-ip'}, headers=_headers(client))
    assert r.status_code == 400


def test_alerts_put_accepts_empty_channels_and_records_history(client, app, db_session):
    body = {'email_enabled': False, 'email_from': '', 'email_to': '', 'webhook_enabled': False,
            'webhook_url': '', 'discord_enabled': True,
            'discord_webhook_url': 'https://discord.com/api/webhooks/1/abc', 'push_enabled': False,
            'ntfy_topic': '', 'device_down_threshold': 5, 'high_latency_threshold': 1500}
    r = client.put('/api/config/alerts', json=body, headers=_headers(client))
    assert r.status_code == 200, r.get_json()
    with app.app_context():
        assert Configuration.get_value('alert_discord_enabled') == 'true'
        assert Configuration.get_value('discord_webhook_url') == 'https://discord.com/api/webhooks/1/abc'
        assert ConfigurationHistory.query.filter_by(config_key='discord_webhook_url').count() == 1


def test_alerts_put_rejects_bad_urls(client, db_session):
    r = client.put('/api/config/alerts', json={'discord_webhook_url': 'http://example.com/hook'}, headers=_headers(client))
    assert r.status_code == 400
    r = client.put('/api/config/alerts', json={'webhook_url': 'not a url'}, headers=_headers(client))
    assert r.status_code == 400


def test_discord_test_route_posts_an_embed(client, db_session):
    resp = MagicMock(status_code=204, text='')
    with patch('monitoring.alerts.requests.post', return_value=resp) as post:
        r = client.post('/api/config/test/discord',
                        json={'discord_webhook_url': 'https://discord.com/api/webhooks/1/abc'},
                        headers=_headers(client))
    assert r.status_code == 200, r.get_json()
    assert post.call_args.args[0] == 'https://discord.com/api/webhooks/1/abc'
    assert 'embeds' in post.call_args.kwargs['json']


def test_discord_test_route_without_url_is_400(client, db_session):
    r = client.post('/api/config/test/discord', json={}, headers=_headers(client))
    assert r.status_code == 400
