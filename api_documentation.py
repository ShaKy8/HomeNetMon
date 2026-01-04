"""
OpenAPI/Swagger Documentation for HomeNetMon API
Auto-generates interactive API documentation
"""

from flask import Flask, jsonify, send_from_directory
from flask_swagger_ui import get_swaggerui_blueprint
from constants import *
import json
import os


def generate_openapi_spec():
    """Generate OpenAPI 3.0 specification for HomeNetMon API"""

    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "HomeNetMon API",
            "description": "Comprehensive Home Network Monitoring REST API",
            "version": APP_VERSION,
            "contact": {
                "name": "HomeNetMon Project",
                "url": "https://github.com/homenetmon/homenetmon"
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT"
            }
        },
        "servers": [
            {
                "url": "http://localhost:5000",
                "description": "Development server"
            },
            {
                "url": "http://0.0.0.0:5000",
                "description": "Local network server"
            }
        ],
        "tags": [
            {"name": "devices", "description": "Device management operations"},
            {"name": "monitoring", "description": "Network monitoring operations"},
            {"name": "alerts", "description": "Alert management"},
            {"name": "analytics", "description": "Network analytics and statistics"},
            {"name": "config", "description": "Configuration management"},
            {"name": "health", "description": "System health and status"}
        ],
        "paths": {
            "/api/devices": {
                "get": {
                    "tags": ["devices"],
                    "summary": "List all devices",
                    "description": "Get all network devices with optional filtering",
                    "parameters": [
                        {
                            "name": "group",
                            "in": "query",
                            "description": "Filter by device group",
                            "schema": {"type": "string"}
                        },
                        {
                            "name": "type",
                            "in": "query",
                            "description": "Filter by device type",
                            "schema": {"type": "string", "enum": ["router", "switch", "computer", "camera", "iot"]}
                        },
                        {
                            "name": "status",
                            "in": "query",
                            "description": "Filter by status",
                            "schema": {"type": "string", "enum": ["up", "down", "warning", "unknown"]}
                        },
                        {
                            "name": "monitored",
                            "in": "query",
                            "description": "Filter by monitoring status",
                            "schema": {"type": "boolean"}
                        },
                        {
                            "name": "page",
                            "in": "query",
                            "description": "Page number for pagination",
                            "schema": {"type": "integer", "minimum": 1}
                        },
                        {
                            "name": "per_page",
                            "in": "query",
                            "description": "Items per page",
                            "schema": {"type": "integer", "minimum": 10, "maximum": 1000}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/DeviceListResponse"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/devices/{device_id}": {
                "get": {
                    "tags": ["devices"],
                    "summary": "Get device details",
                    "description": "Get detailed information about a specific device",
                    "parameters": [
                        {
                            "name": "device_id",
                            "in": "path",
                            "required": True,
                            "description": "Device ID",
                            "schema": {"type": "integer"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Device"}
                                }
                            }
                        },
                        "404": {"description": "Device not found"}
                    }
                },
                "put": {
                    "tags": ["devices"],
                    "summary": "Update device",
                    "description": "Update device configuration",
                    "parameters": [
                        {
                            "name": "device_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"}
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DeviceUpdate"}
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Device updated successfully"},
                        "400": {"description": "Invalid input"},
                        "404": {"description": "Device not found"}
                    }
                },
                "delete": {
                    "tags": ["devices"],
                    "summary": "Delete device",
                    "description": "Remove a device from monitoring",
                    "parameters": [
                        {
                            "name": "device_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "Device deleted successfully"},
                        "404": {"description": "Device not found"}
                    }
                }
            },
            "/api/devices/scan-now": {
                "post": {
                    "tags": ["devices"],
                    "summary": "Trigger network scan",
                    "description": "Initiate an immediate network scan for device discovery",
                    "responses": {
                        "200": {
                            "description": "Scan initiated successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "success": {"type": "boolean"},
                                            "message": {"type": "string"},
                                            "estimated_duration": {"type": "integer"}
                                        }
                                    }
                                }
                            }
                        },
                        "409": {"description": "Scan already in progress"}
                    }
                }
            },
            "/api/monitoring/summary": {
                "get": {
                    "tags": ["monitoring"],
                    "summary": "Get monitoring summary",
                    "description": "Get real-time network monitoring statistics",
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/MonitoringSummary"}
                                }
                            }
                        }
                    }
                }
            },
            "/api/monitoring/alerts": {
                "get": {
                    "tags": ["alerts"],
                    "summary": "List alerts",
                    "description": "Get all alerts with optional filtering",
                    "parameters": [
                        {
                            "name": "resolved",
                            "in": "query",
                            "description": "Filter by resolved status",
                            "schema": {"type": "boolean"}
                        },
                        {
                            "name": "device_id",
                            "in": "query",
                            "description": "Filter by device",
                            "schema": {"type": "integer"}
                        },
                        {
                            "name": "priority",
                            "in": "query",
                            "description": "Filter by priority",
                            "schema": {"type": "string", "enum": ["critical", "high", "medium", "low"]}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/AlertListResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/api/health": {
                "get": {
                    "tags": ["health"],
                    "summary": "Health check",
                    "description": "Get system health status",
                    "responses": {
                        "200": {
                            "description": "System healthy",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/HealthStatus"}
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Device": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "Unique device identifier"},
                        "ip_address": {"type": "string", "format": "ipv4", "description": "Device IP address"},
                        "mac_address": {"type": "string", "description": "Device MAC address"},
                        "hostname": {"type": "string", "description": "Device hostname"},
                        "display_name": {"type": "string", "description": "User-friendly device name"},
                        "device_type": {"type": "string", "description": "Device type classification"},
                        "device_group": {"type": "string", "description": "Device group/category"},
                        "manufacturer": {"type": "string", "description": "Device manufacturer"},
                        "model": {"type": "string", "description": "Device model"},
                        "status": {"type": "string", "enum": ["up", "down", "warning", "unknown"]},
                        "monitor_enabled": {"type": "boolean", "description": "Monitoring enabled flag"},
                        "last_seen": {"type": "string", "format": "date-time"},
                        "first_discovered": {"type": "string", "format": "date-time"},
                        "latest_response_time": {"type": "number", "description": "Latest ping response in ms"},
                        "active_alerts": {"type": "integer", "description": "Number of active alerts"}
                    }
                },
                "DeviceListResponse": {
                    "type": "object",
                    "properties": {
                        "success": {"type": "boolean"},
                        "devices": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/Device"}
                        },
                        "total": {"type": "integer"},
                        "pagination": {
                            "type": "object",
                            "properties": {
                                "page": {"type": "integer"},
                                "per_page": {"type": "integer"},
                                "total": {"type": "integer"},
                                "pages": {"type": "integer"}
                            }
                        }
                    }
                },
                "DeviceUpdate": {
                    "type": "object",
                    "properties": {
                        "display_name": {"type": "string"},
                        "device_type": {"type": "string"},
                        "device_group": {"type": "string"},
                        "monitor_enabled": {"type": "boolean"},
                        "notes": {"type": "string"}
                    }
                },
                "MonitoringSummary": {
                    "type": "object",
                    "properties": {
                        "total_devices": {"type": "integer"},
                        "devices_up": {"type": "integer"},
                        "devices_down": {"type": "integer"},
                        "devices_warning": {"type": "integer"},
                        "avg_response_time": {"type": "number"},
                        "active_alerts": {"type": "integer"},
                        "network_health": {"type": "number", "description": "Health percentage 0-100"}
                    }
                },
                "Alert": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "device_id": {"type": "integer"},
                        "alert_type": {"type": "string"},
                        "priority": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                        "message": {"type": "string"},
                        "resolved": {"type": "boolean"},
                        "created_at": {"type": "string", "format": "date-time"},
                        "resolved_at": {"type": "string", "format": "date-time"}
                    }
                },
                "AlertListResponse": {
                    "type": "object",
                    "properties": {
                        "success": {"type": "boolean"},
                        "alerts": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/Alert"}
                        },
                        "total": {"type": "integer"}
                    }
                },
                "HealthStatus": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "enum": ["healthy", "degraded", "unhealthy"]},
                        "uptime": {"type": "integer", "description": "System uptime in seconds"},
                        "database": {"type": "string", "enum": ["connected", "disconnected"]},
                        "monitoring": {"type": "string", "enum": ["active", "inactive"]},
                        "version": {"type": "string"}
                    }
                }
            }
        }
    }

    return spec


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
        spec = generate_openapi_spec()
        return jsonify(spec)

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
            <script src="https://cdn.jsdelivr.net/npm/redoc@latest/bundles/redoc.standalone.js"></script>
        </body>
        </html>
        '''

    return app
