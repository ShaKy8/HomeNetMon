"""
Request/response validation middleware with comprehensive schema validation.
"""

import logging
import json
import re
from typing import Dict, Any, Optional, List, Union, Type, Callable
from functools import wraps
from datetime import datetime
from flask import Flask, request, jsonify, current_app
from marshmallow import Schema, fields, validate, ValidationError as MarshmallowValidationError
from marshmallow.fields import Field
from core.error_handler import ValidationError, AppError

logger = logging.getLogger(__name__)

class ValidationMiddleware:
    """Middleware for request/response validation."""
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self.schemas = {}
        self.validation_stats = {
            'total_validations': 0,
            'failed_validations': 0,
            'validations_by_endpoint': {},
            'last_reset': datetime.utcnow()
        }
        
        if app:
            self.init_app(app)
            
    def init_app(self, app: Flask):
        """Initialize validation middleware with Flask app."""
        self.app = app
        logger.info("Validation middleware initialized")
        
    def register_schema(self, endpoint: str, schema: Schema, 
                       method: str = 'POST', validate_response: bool = False):
        """Register a validation schema for an endpoint."""
        key = f"{method}:{endpoint}"
        self.schemas[key] = {
            'schema': schema,
            'validate_response': validate_response
        }
        logger.debug(f"Registered validation schema for {key}")
        
    def validate_request(self, schema: Schema, data: Optional[Dict] = None) -> Dict[str, Any]:
        """Validate request data against schema."""
        if data is None:
            data = request.get_json() or {}
            
        try:
            self.validation_stats['total_validations'] += 1
            endpoint = request.endpoint or 'unknown'
            self.validation_stats['validations_by_endpoint'][endpoint] = \
                self.validation_stats['validations_by_endpoint'].get(endpoint, 0) + 1
                
            validated_data = schema.load(data)
            return validated_data
            
        except MarshmallowValidationError as e:
            self.validation_stats['failed_validations'] += 1
            
            # Extract field-specific errors
            field_errors = []
            for field, messages in e.messages.items():
                if isinstance(messages, list):
                    field_errors.extend([f"{field}: {msg}" for msg in messages])
                else:
                    field_errors.append(f"{field}: {messages}")
                    
            raise ValidationError(
                message="Request validation failed",
                details={
                    'field_errors': field_errors,
                    'invalid_fields': list(e.messages.keys())
                }
            ) from e
            
    def validate_response(self, schema: Schema, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate response data against schema."""
        try:
            validated_data = schema.dump(data)
            return validated_data
        except Exception as e:
            logger.error(f"Response validation failed: {e}")
            # Don't raise for response validation to avoid breaking API
            return data
            
    def get_validation_stats(self) -> Dict[str, Any]:
        """Get validation statistics."""
        return self.validation_stats.copy()

# Custom validation fields
class IPAddressField(Field):
    """Field for validating IP addresses."""
    
    def _deserialize(self, value, attr, data, **kwargs):
        if not value:
            return None
            
        # IPv4 pattern
        ipv4_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        
        if ipv4_pattern.match(str(value)):
            return str(value)
            
        raise ValidationError(f"Invalid IP address: {value}")

class MACAddressField(Field):
    """Field for validating MAC addresses."""
    
    def _deserialize(self, value, attr, data, **kwargs):
        if not value:
            return None
            
        # MAC address pattern (supports : and - separators)
        mac_pattern = re.compile(
            r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        )
        
        if mac_pattern.match(str(value)):
            return str(value).upper().replace('-', ':')
            
        raise ValidationError(f"Invalid MAC address: {value}")

class NetworkRangeField(Field):
    """Field for validating network ranges in CIDR notation."""
    
    def _deserialize(self, value, attr, data, **kwargs):
        if not value:
            return None
            
        # CIDR pattern
        cidr_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
            r'\/(?:[0-9]|[1-2][0-9]|3[0-2])$'
        )
        
        if cidr_pattern.match(str(value)):
            return str(value)
            
        raise ValidationError(f"Invalid network range: {value}")

# Common validation schemas
class DeviceCreateSchema(Schema):
    """Schema for creating a new device."""
    ip_address = IPAddressField(required=True)
    mac_address = MACAddressField(allow_none=True)
    hostname = fields.Str(validate=validate.Length(max=255), allow_none=True)
    custom_name = fields.Str(validate=validate.Length(max=255), allow_none=True)
    device_type = fields.Str(
        validate=validate.OneOf(['router', 'computer', 'phone', 'iot', 'server', 'other']),
        allow_none=True
    )
    device_group = fields.Str(validate=validate.Length(max=100), allow_none=True)
    is_monitored = fields.Bool(load_default=True)

class DeviceUpdateSchema(Schema):
    """Schema for updating a device."""
    mac_address = MACAddressField(allow_none=True)
    hostname = fields.Str(validate=validate.Length(max=255), allow_none=True)
    custom_name = fields.Str(validate=validate.Length(max=255), allow_none=True)
    device_type = fields.Str(
        validate=validate.OneOf(['router', 'computer', 'phone', 'iot', 'server', 'other']),
        allow_none=True
    )
    device_group = fields.Str(validate=validate.Length(max=100), allow_none=True)
    is_monitored = fields.Bool(allow_none=True)

class AlertCreateSchema(Schema):
    """Schema for creating alerts."""
    device_id = fields.Int(required=True, validate=validate.Range(min=1))
    message = fields.Str(required=True, validate=validate.Length(min=1, max=500))
    severity = fields.Str(
        required=True,
        validate=validate.OneOf(['low', 'medium', 'high', 'critical'])
    )
    alert_type = fields.Str(
        validate=validate.OneOf(['device_down', 'slow_response', 'custom']),
        allow_none=True
    )

class ConfigurationSchema(Schema):
    """Schema for configuration updates."""
    ping_interval = fields.Int(validate=validate.Range(min=5, max=3600), allow_none=True)
    ping_timeout = fields.Int(validate=validate.Range(min=1, max=60), allow_none=True)
    network_range = NetworkRangeField(allow_none=True)
    email_notifications = fields.Bool(allow_none=True)
    webhook_url = fields.Url(allow_none=True)
    data_retention_days = fields.Int(validate=validate.Range(min=1, max=365), allow_none=True)

class PaginationSchema(Schema):
    """Schema for pagination parameters."""
    page = fields.Int(validate=validate.Range(min=1), load_default=1)
    per_page = fields.Int(validate=validate.Range(min=1, max=1000), load_default=50)
    sort_by = fields.Str(allow_none=True)
    sort_order = fields.Str(
        validate=validate.OneOf(['asc', 'desc']), 
        load_default='asc'
    )

class NetworkScanSchema(Schema):
    """Schema for network scan requests."""
    network_range = NetworkRangeField(required=True)
    scan_type = fields.Str(
        validate=validate.OneOf(['ping', 'arp', 'full']),
        load_default='ping'
    )
    timeout = fields.Int(validate=validate.Range(min=1, max=60), load_default=5)

class BulkActionSchema(Schema):
    """Schema for bulk actions on devices."""
    device_ids = fields.List(
        fields.Int(validate=validate.Range(min=1)),
        required=True,
        validate=validate.Length(min=1, max=1000)
    )
    action = fields.Str(
        required=True,
        validate=validate.OneOf(['enable_monitoring', 'disable_monitoring', 'delete'])
    )
    confirm = fields.Bool(load_default=False)

# Validation decorators
def validate_json(schema: Type[Schema], **schema_kwargs):
    """Decorator to validate JSON request data."""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not request.is_json:
                raise ValidationError("Request must contain JSON data")
                
            try:
                schema_instance = schema(**schema_kwargs)
                validated_data = current_app.extensions['validation_middleware'].validate_request(
                    schema_instance
                )
                # Store validated data in Flask's g for access in view
                from flask import g
                g.validated_data = validated_data
                
                return func(*args, **kwargs)
                
            except ValidationError:
                raise
            except Exception as e:
                raise ValidationError(f"Validation error: {str(e)}") from e
                
        return wrapper
    return decorator

def validate_query_params(schema: Type[Schema], **schema_kwargs):
    """Decorator to validate query parameters."""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                schema_instance = schema(**schema_kwargs)
                validated_data = current_app.extensions['validation_middleware'].validate_request(
                    schema_instance, data=request.args.to_dict()
                )
                from flask import g
                g.validated_params = validated_data
                
                return func(*args, **kwargs)
                
            except ValidationError:
                raise
            except Exception as e:
                raise ValidationError(f"Query parameter validation error: {str(e)}") from e
                
        return wrapper
    return decorator

def sanitize_input(data: Any) -> Any:
    """Sanitize input data to prevent XSS and injection attacks."""
    if isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    elif isinstance(data, str):
        # Remove potentially dangerous characters
        sanitized = data.strip()
        
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        # Limit length
        if len(sanitized) > 10000:
            sanitized = sanitized[:10000]
            
        return sanitized
    else:
        return data

def validate_content_type(allowed_types: List[str]):
    """Decorator to validate request content type."""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            content_type = request.content_type
            if content_type and not any(ct in content_type for ct in allowed_types):
                raise ValidationError(
                    f"Unsupported content type: {content_type}",
                    details={'allowed_types': allowed_types}
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Response formatting helpers
class ResponseFormatter:
    """Helper class for formatting API responses."""
    
    @staticmethod
    def success(data: Any = None, message: str = "Success", 
                meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Format successful response."""
        response = {
            'success': True,
            'message': message,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if data is not None:
            response['data'] = data
            
        if meta:
            response['meta'] = meta
            
        return response
        
    @staticmethod
    def paginated(data: List[Any], page: int, per_page: int, 
                 total: int, **kwargs) -> Dict[str, Any]:
        """Format paginated response."""
        total_pages = (total + per_page - 1) // per_page
        
        meta = {
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'total_pages': total_pages,
                'has_next': page < total_pages,
                'has_prev': page > 1
            }
        }
        meta.update(kwargs)
        
        return ResponseFormatter.success(
            data=data,
            message=f"Retrieved {len(data)} of {total} items",
            meta=meta
        )

# Global validation middleware instance
global_validation_middleware = ValidationMiddleware()