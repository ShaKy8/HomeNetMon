"""
OpenAPI documentation system with automatic schema generation.
"""

import logging
from typing import Dict, Any, Optional, List, Type
from flask import Flask, Blueprint, jsonify, render_template_string
from flask_restx import Api, Resource, fields, Namespace
from marshmallow import Schema
import json

logger = logging.getLogger(__name__)

# OpenAPI specification template
OPENAPI_TEMPLATE = {
    "openapi": "3.0.3",
    "info": {
        "title": "HomeNetMon API",
        "description": """
        # HomeNetMon Network Monitoring API
        
        A comprehensive network monitoring solution providing real-time device monitoring, 
        alerting, and performance analytics.
        
        ## Features
        - Real-time device monitoring and status tracking
        - Automated network discovery and device management
        - Alert management and notifications
        - Performance monitoring and analytics
        - WebSocket support for real-time updates
        
        ## Authentication
        This API uses JWT (JSON Web Token) authentication. Include the token in the Authorization header:
        ```
        Authorization: Bearer <your-jwt-token>
        ```
        
        ## Error Handling
        All errors follow a standardized format with error codes and detailed messages.
        
        ## Rate Limiting
        API endpoints are rate limited. Check response headers for current limits.
        """,
        "version": "2.0.0",
        "contact": {
            "name": "HomeNetMon Support",
            "url": "https://github.com/homeNetMon/homeNetMon"
        },
        "license": {
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT"
        }
    },
    "servers": [
        {
            "url": "/api",
            "description": "HomeNetMon API Server"
        }
    ],
    "components": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        },
        "schemas": {},
        "responses": {
            "UnauthorizedError": {
                "description": "Authentication required",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/ErrorResponse"
                        }
                    }
                }
            },
            "ForbiddenError": {
                "description": "Insufficient permissions",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/ErrorResponse"
                        }
                    }
                }
            },
            "NotFoundError": {
                "description": "Resource not found",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/ErrorResponse"
                        }
                    }
                }
            },
            "ValidationError": {
                "description": "Request validation failed",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/ValidationErrorResponse"
                        }
                    }
                }
            },
            "RateLimitError": {
                "description": "Rate limit exceeded",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/ErrorResponse"
                        }
                    }
                }
            }
        }
    },
    "security": [
        {
            "bearerAuth": []
        }
    ]
}

# Common schema definitions
COMMON_SCHEMAS = {
    "ErrorResponse": {
        "type": "object",
        "properties": {
            "error_id": {
                "type": "string",
                "format": "uuid",
                "description": "Unique error identifier"
            },
            "error_code": {
                "type": "string",
                "description": "Application error code"
            },
            "message": {
                "type": "string",
                "description": "Human-readable error message"
            },
            "timestamp": {
                "type": "string",
                "format": "date-time",
                "description": "Error timestamp"
            },
            "status_code": {
                "type": "integer",
                "description": "HTTP status code"
            }
        },
        "required": ["error_id", "error_code", "message", "timestamp", "status_code"]
    },
    "ValidationErrorResponse": {
        "allOf": [
            {"$ref": "#/components/schemas/ErrorResponse"},
            {
                "type": "object",
                "properties": {
                    "details": {
                        "type": "object",
                        "properties": {
                            "field_errors": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "invalid_fields": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        }
                    }
                }
            }
        ]
    },
    "SuccessResponse": {
        "type": "object",
        "properties": {
            "success": {
                "type": "boolean",
                "example": True
            },
            "message": {
                "type": "string",
                "description": "Success message"
            },
            "timestamp": {
                "type": "string",
                "format": "date-time"
            },
            "data": {
                "description": "Response data"
            }
        },
        "required": ["success", "message", "timestamp"]
    },
    "PaginationMeta": {
        "type": "object",
        "properties": {
            "pagination": {
                "type": "object",
                "properties": {
                    "page": {
                        "type": "integer",
                        "minimum": 1
                    },
                    "per_page": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1000
                    },
                    "total": {
                        "type": "integer",
                        "minimum": 0
                    },
                    "total_pages": {
                        "type": "integer",
                        "minimum": 0
                    },
                    "has_next": {
                        "type": "boolean"
                    },
                    "has_prev": {
                        "type": "boolean"
                    }
                },
                "required": ["page", "per_page", "total", "total_pages", "has_next", "has_prev"]
            }
        }
    },
    "Device": {
        "type": "object",
        "properties": {
            "id": {
                "type": "integer",
                "description": "Device ID"
            },
            "ip_address": {
                "type": "string",
                "format": "ipv4",
                "description": "Device IP address"
            },
            "mac_address": {
                "type": "string",
                "pattern": "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$",
                "description": "Device MAC address",
                "nullable": True
            },
            "hostname": {
                "type": "string",
                "maxLength": 255,
                "description": "Device hostname",
                "nullable": True
            },
            "custom_name": {
                "type": "string",
                "maxLength": 255,
                "description": "Custom device name",
                "nullable": True
            },
            "device_type": {
                "type": "string",
                "enum": ["router", "computer", "phone", "iot", "server", "other"],
                "description": "Device type",
                "nullable": True
            },
            "device_group": {
                "type": "string",
                "maxLength": 100,
                "description": "Device group",
                "nullable": True
            },
            "is_monitored": {
                "type": "boolean",
                "description": "Whether device is being monitored"
            },
            "status": {
                "type": "string",
                "enum": ["up", "down", "warning", "unknown"],
                "description": "Current device status"
            },
            "last_seen": {
                "type": "string",
                "format": "date-time",
                "description": "Last seen timestamp",
                "nullable": True
            },
            "created_at": {
                "type": "string",
                "format": "date-time",
                "description": "Device creation timestamp"
            }
        },
        "required": ["id", "ip_address", "is_monitored", "status", "created_at"]
    },
    "Alert": {
        "type": "object",
        "properties": {
            "id": {
                "type": "integer",
                "description": "Alert ID"
            },
            "device_id": {
                "type": "integer",
                "description": "Related device ID"
            },
            "message": {
                "type": "string",
                "maxLength": 500,
                "description": "Alert message"
            },
            "severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
                "description": "Alert severity"
            },
            "alert_type": {
                "type": "string",
                "enum": ["device_down", "slow_response", "custom"],
                "description": "Alert type",
                "nullable": True
            },
            "resolved": {
                "type": "boolean",
                "description": "Whether alert is resolved"
            },
            "created_at": {
                "type": "string",
                "format": "date-time",
                "description": "Alert creation timestamp"
            },
            "resolved_at": {
                "type": "string",
                "format": "date-time",
                "description": "Alert resolution timestamp",
                "nullable": True
            }
        },
        "required": ["id", "device_id", "message", "severity", "resolved", "created_at"]
    },
    "MonitoringData": {
        "type": "object",
        "properties": {
            "id": {
                "type": "integer",
                "description": "Monitoring data ID"
            },
            "device_id": {
                "type": "integer",
                "description": "Related device ID"
            },
            "response_time": {
                "type": "number",
                "format": "float",
                "minimum": 0,
                "description": "Response time in milliseconds",
                "nullable": True
            },
            "timestamp": {
                "type": "string",
                "format": "date-time",
                "description": "Monitoring timestamp"
            }
        },
        "required": ["id", "device_id", "timestamp"]
    }
}

class APIDocumentation:
    """Manages API documentation generation and serving."""
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self.spec = OPENAPI_TEMPLATE.copy()
        self.spec["components"]["schemas"].update(COMMON_SCHEMAS)
        
        if app:
            self.init_app(app)
            
    def init_app(self, app: Flask):
        """Initialize API documentation with Flask app."""
        self.app = app
        
        # Create documentation blueprint
        docs_bp = Blueprint('api_docs', __name__)
        
        @docs_bp.route('/openapi.json')
        def openapi_spec():
            """Serve OpenAPI specification."""
            return jsonify(self.spec)
            
        @docs_bp.route('/docs')
        def swagger_ui():
            """Serve Swagger UI."""
            return render_template_string(SWAGGER_UI_TEMPLATE)
            
        @docs_bp.route('/redoc')
        def redoc_ui():
            """Serve ReDoc UI."""
            return render_template_string(REDOC_UI_TEMPLATE)
            
        app.register_blueprint(docs_bp, url_prefix='/api')
        
        logger.info("API documentation initialized")
        
    def add_path(self, path: str, method: str, operation: Dict[str, Any]):
        """Add a path operation to the OpenAPI spec."""
        if "paths" not in self.spec:
            self.spec["paths"] = {}
            
        if path not in self.spec["paths"]:
            self.spec["paths"][path] = {}
            
        self.spec["paths"][path][method.lower()] = operation
        
    def add_schema(self, name: str, schema: Dict[str, Any]):
        """Add a schema to the OpenAPI spec."""
        self.spec["components"]["schemas"][name] = schema
        
    def generate_schema_from_marshmallow(self, schema_class: Type[Schema]) -> Dict[str, Any]:
        """Generate OpenAPI schema from Marshmallow schema."""
        # This is a simplified conversion - in practice you'd use a library like marshmallow-dataclass
        schema_instance = schema_class()
        properties = {}
        required = []
        
        for field_name, field in schema_instance.fields.items():
            field_type = self._marshmallow_to_openapi_type(field)
            properties[field_name] = field_type
            
            if field.required:
                required.append(field_name)
                
        result = {
            "type": "object",
            "properties": properties
        }
        
        if required:
            result["required"] = required
            
        return result
        
    def _marshmallow_to_openapi_type(self, field) -> Dict[str, Any]:
        """Convert Marshmallow field to OpenAPI type."""
        from marshmallow import fields
        
        if isinstance(field, fields.String):
            return {"type": "string"}
        elif isinstance(field, fields.Integer):
            return {"type": "integer"}
        elif isinstance(field, fields.Float):
            return {"type": "number", "format": "float"}
        elif isinstance(field, fields.Boolean):
            return {"type": "boolean"}
        elif isinstance(field, fields.DateTime):
            return {"type": "string", "format": "date-time"}
        elif isinstance(field, fields.List):
            return {
                "type": "array",
                "items": self._marshmallow_to_openapi_type(field.inner)
            }
        else:
            return {"type": "string"}

# Auto-documentation decorator
def document_endpoint(summary: str, description: str = None, 
                     responses: Dict[int, Dict[str, Any]] = None,
                     parameters: List[Dict[str, Any]] = None,
                     request_body: Dict[str, Any] = None,
                     tags: List[str] = None):
    """Decorator to document API endpoints."""
    def decorator(func):
        # Store documentation metadata on the function
        func._api_doc = {
            'summary': summary,
            'description': description or summary,
            'responses': responses or {},
            'parameters': parameters or [],
            'requestBody': request_body,
            'tags': tags or []
        }
        return func
    return decorator

# Swagger UI HTML template
SWAGGER_UI_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>HomeNetMon API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin:0; background: #fafafa; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
    <script>
    window.onload = function() {
        const ui = SwaggerUIBundle({
            url: '/api/openapi.json',
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIStandalonePreset
            ],
            plugins: [
                SwaggerUIBundle.plugins.DownloadUrl
            ],
            layout: "StandaloneLayout"
        });
    };
    </script>
</body>
</html>
"""

# ReDoc HTML template
REDOC_UI_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>HomeNetMon API Documentation</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
    <style>
        body { margin: 0; padding: 0; }
    </style>
</head>
<body>
    <redoc spec-url='/api/openapi.json'></redoc>
    <script src="https://cdn.jsdelivr.net/npm/redoc@2.0.0/bundles/redoc.standalone.js"></script>
</body>
</html>
"""

# API path documentation examples
DEVICE_API_PATHS = {
    "/devices": {
        "get": {
            "tags": ["Devices"],
            "summary": "List all devices",
            "description": "Retrieve a paginated list of all monitored devices.",
            "parameters": [
                {
                    "name": "page",
                    "in": "query",
                    "description": "Page number",
                    "required": False,
                    "schema": {"type": "integer", "minimum": 1, "default": 1}
                },
                {
                    "name": "per_page", 
                    "in": "query",
                    "description": "Items per page",
                    "required": False,
                    "schema": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50}
                }
            ],
            "responses": {
                "200": {
                    "description": "Success",
                    "content": {
                        "application/json": {
                            "schema": {
                                "allOf": [
                                    {"$ref": "#/components/schemas/SuccessResponse"},
                                    {
                                        "type": "object",
                                        "properties": {
                                            "data": {
                                                "type": "array",
                                                "items": {"$ref": "#/components/schemas/Device"}
                                            },
                                            "meta": {"$ref": "#/components/schemas/PaginationMeta"}
                                        }
                                    }
                                ]
                            }
                        }
                    }
                },
                "401": {"$ref": "#/components/responses/UnauthorizedError"}
            }
        },
        "post": {
            "tags": ["Devices"],
            "summary": "Create a new device",
            "description": "Add a new device to the monitoring system.",
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "ip_address": {"type": "string", "format": "ipv4"},
                                "mac_address": {"type": "string", "nullable": True},
                                "hostname": {"type": "string", "nullable": True},
                                "custom_name": {"type": "string", "nullable": True},
                                "device_type": {
                                    "type": "string", 
                                    "enum": ["router", "computer", "phone", "iot", "server", "other"],
                                    "nullable": True
                                }
                            },
                            "required": ["ip_address"]
                        }
                    }
                }
            },
            "responses": {
                "201": {
                    "description": "Device created successfully",
                    "content": {
                        "application/json": {
                            "schema": {
                                "allOf": [
                                    {"$ref": "#/components/schemas/SuccessResponse"},
                                    {
                                        "type": "object",
                                        "properties": {
                                            "data": {"$ref": "#/components/schemas/Device"}
                                        }
                                    }
                                ]
                            }
                        }
                    }
                },
                "400": {"$ref": "#/components/responses/ValidationError"},
                "401": {"$ref": "#/components/responses/UnauthorizedError"}
            }
        }
    }
}

# Global API documentation instance
api_documentation = APIDocumentation()