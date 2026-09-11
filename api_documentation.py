"""
OpenAPI/Swagger Documentation for HomeNetMon API
Auto-generates interactive API documentation
"""

from flask import Flask, jsonify, send_from_directory
from flask_swagger_ui import get_swaggerui_blueprint
import re

from constants import APP_VERSION


TAG_BY_PREFIX = {
    '/api/devices': 'devices', '/api/device-control': 'devices', '/api/monitoring/alerts': 'alerts',
    '/api/monitoring': 'monitoring', '/api/analytics': 'analytics', '/api/performance': 'analytics',
    '/api/config': 'config', '/api/config-management': 'config', '/api/security': 'security',
    '/api/notifications': 'alerts', '/api/system': 'health', '/api/csrf-token': 'health',
}


def _tag_for(rule):
    for prefix in sorted(TAG_BY_PREFIX, key=len, reverse=True):
        if rule.startswith(prefix):
            return TAG_BY_PREFIX[prefix]
    return 'other'


def generate_openapi_spec(app=None):
    """OpenAPI 3.0 document built from the registered routes, so /api/docs can never
    list an endpoint that does not exist (2.4.0 hand-maintained six paths of ~250).
    Summaries come from each view's docstring."""
    from flask import current_app
    app = app or current_app
    paths = {}
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        if not rule.rule.startswith('/api/') or rule.rule.startswith(('/api/docs', '/api/redoc', '/api/openapi.json')):
            continue
        view = app.view_functions.get(rule.endpoint)
        doc = (view.__doc__ or '').strip().splitlines() if view else []
        summary = doc[0].strip() if doc else rule.endpoint
        description = ' '.join(line.strip() for line in doc[1:]).strip()
        openapi_path = re.sub(r'<(?:[a-z]+:)?([a-z_]+)>', r'{\1}', rule.rule)
        params = [{'name': m.group(1), 'in': 'path', 'required': True,
                   'schema': {'type': 'integer' if m.group(0).startswith('<int:') else 'string'}}
                  for m in re.finditer(r'<(?:(?:int|string):)?([a-z_]+)>', rule.rule)]
        tier = getattr(view, '_rate_limit_tier', None)
        for method in sorted((rule.methods or set()) - {'HEAD', 'OPTIONS'}):
            op = {
                'tags': [_tag_for(rule.rule)],
                'summary': summary,
                'description': (description + (f' Rate limit tier: {tier}.' if tier else '')).strip(),
                'operationId': f"{method.lower()}_{rule.endpoint.replace('.', '_')}",
                'responses': {'200': {'description': 'Success'}, '400': {'description': 'Validation error'},
                              '404': {'description': 'Not found'}, '429': {'description': 'Rate limited'}},
            }
            if params:
                op['parameters'] = params
            if method in ('POST', 'PUT', 'PATCH', 'DELETE'):
                op['responses']['403'] = {'description': 'Missing or invalid X-CSRF-Token'}
                op['requestBody'] = {'required': False, 'content': {'application/json': {'schema': {'type': 'object'}}}}
            paths.setdefault(openapi_path, {})[method.lower()] = op

    return {
        "openapi": "3.0.0",
        "info": {
            "title": "HomeNetMon API",
            "description": ("REST API of the home network monitor. No authentication (trusted LAN); "
                            "state-changing requests need the X-CSRF-Token header from GET /api/csrf-token. "
                            "Response envelopes vary: older routes return {success: true, ...}, newer ones the "
                            "core.error_handler shape."),
            "version": APP_VERSION,
            "contact": {"name": "HomeNetMon Project", "url": "https://github.com/ShaKy8/HomeNetMon"},
            "license": {"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
        },
        "servers": [{"url": "/", "description": "This server"}],
        "tags": [
            {"name": "devices", "description": "Device inventory and control"},
            {"name": "monitoring", "description": "Ping data, summary counts, bandwidth, internet check"},
            {"name": "alerts", "description": "Alerts, suppression rules, notification log"},
            {"name": "analytics", "description": "Health score, trends, topology, per-device performance"},
            {"name": "config", "description": "Runtime configuration and its history"},
            {"name": "security", "description": "Port scans and security alerts"},
            {"name": "health", "description": "System information and thread health"},
        ],
        "paths": paths,
    }


def setup_swagger_ui(app: Flask):
    """
    Setup Swagger UI for interactive API documentation

    Args:
        app: Flask application instance
    """
    # Swagger UI configuration
    SWAGGER_URL = '/api/docs'
    API_SPEC_URL = '/api/openapi.json'

    # Create swagger UI blueprint
    swaggerui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_SPEC_URL,
        config={
            'app_name': "HomeNetMon API",
            'dom_id': '#swagger-ui',
            'deepLinking': True,
            'displayRequestDuration': True,
            'filter': True,
            'showExtensions': True,
            'showCommonExtensions': True
        }
    )

    # Register blueprint
    app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

    # Route to serve OpenAPI spec
    @app.route(API_SPEC_URL)
    def get_openapi_spec():
        """Serve OpenAPI specification as JSON"""
        return jsonify(generate_openapi_spec(app))

    # Route for ReDoc alternative documentation
    @app.route('/api/redoc')
    def get_redoc():
        """Serve ReDoc documentation"""
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>HomeNetMon API Documentation</title>
            <meta charset="utf-8"/>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
            <style>
                body {{
                    margin: 0;
                    padding: 0;
                }}
            </style>
        </head>
        <body>
            <redoc spec-url='{API_SPEC_URL}'></redoc>
            <script src="https://cdn.jsdelivr.net/npm/redoc@2.1.5/bundles/redoc.standalone.js"></script>
        </body>
        </html>
        '''

    return app
