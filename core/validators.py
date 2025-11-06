"""
Input validation and sanitization module for HomeNetMon.
Provides comprehensive validation for all user inputs.
"""

import re
import ipaddress
import logging
from typing import Any, Optional, Union, List, Dict
from werkzeug.exceptions import BadRequest
import html
import urllib.parse

logger = logging.getLogger(__name__)


class InputValidator:
    """Comprehensive input validation and sanitization."""
    
    # Regular expressions for validation
    HOSTNAME_REGEX = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9]$')
    MAC_ADDRESS_REGEX = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_\-]{3,32}$')
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    SAFE_STRING_REGEX = re.compile(r'^[a-zA-Z0-9\s\-_.,!?@#$%&*()+=\[\]{}|;:\'"<>/\\]+$')
    
    # Maximum lengths for various fields
    MAX_LENGTHS = {
        'username': 32,
        'password': 128,
        'email': 254,
        'hostname': 255,
        'device_name': 100,
        'device_type': 50,
        'device_group': 100,
        'alert_message': 500,
        'description': 1000,
        'url': 2000,
        'search_query': 200
    }
    
    @classmethod
    def validate_ip_address(cls, ip_str: str) -> str:
        """Validate and return a clean IP address string."""
        if not ip_str:
            raise ValueError("IP address cannot be empty")
            
        try:
            # This will validate and normalize the IP address
            ip_obj = ipaddress.ip_address(ip_str.strip())
            return str(ip_obj)
        except ValueError as e:
            logger.warning(f"Invalid IP address: {ip_str}")
            raise ValueError(f"Invalid IP address format: {ip_str}")
    
    @classmethod
    def validate_network_range(cls, network_str: str) -> str:
        """Validate and return a clean network range string."""
        if not network_str:
            raise ValueError("Network range cannot be empty")
            
        try:
            # This will validate the network range
            network = ipaddress.ip_network(network_str.strip(), strict=False)
            return str(network)
        except ValueError as e:
            logger.warning(f"Invalid network range: {network_str}")
            raise ValueError(f"Invalid network range format: {network_str}")
    
    @classmethod
    def validate_mac_address(cls, mac_str: str) -> str:
        """Validate and normalize MAC address."""
        if not mac_str:
            return None
            
        mac_str = mac_str.strip().upper()
        
        # Try to normalize different MAC formats
        mac_str = mac_str.replace('-', ':')
        
        if not cls.MAC_ADDRESS_REGEX.match(mac_str):
            logger.warning(f"Invalid MAC address: {mac_str}")
            raise ValueError(f"Invalid MAC address format: {mac_str}")
            
        return mac_str
    
    @classmethod
    def validate_hostname(cls, hostname: str) -> str:
        """Validate hostname format."""
        if not hostname:
            return None
            
        hostname = hostname.strip().lower()
        
        if len(hostname) > cls.MAX_LENGTHS['hostname']:
            raise ValueError(f"Hostname too long (max {cls.MAX_LENGTHS['hostname']} chars)")
            
        if not cls.HOSTNAME_REGEX.match(hostname):
            raise ValueError(f"Invalid hostname format: {hostname}")
            
        return hostname
    
    @classmethod
    def validate_username(cls, username: str) -> str:
        """Validate username format."""
        if not username:
            raise ValueError("Username cannot be empty")
            
        username = username.strip()
        
        if len(username) > cls.MAX_LENGTHS['username']:
            raise ValueError(f"Username too long (max {cls.MAX_LENGTHS['username']} chars)")
            
        if not cls.USERNAME_REGEX.match(username):
            raise ValueError("Username can only contain letters, numbers, underscore and hyphen")
            
        return username
    
    @classmethod
    def validate_email(cls, email: str) -> str:
        """Validate email address format."""
        if not email:
            raise ValueError("Email cannot be empty")
            
        email = email.strip().lower()
        
        if len(email) > cls.MAX_LENGTHS['email']:
            raise ValueError(f"Email too long (max {cls.MAX_LENGTHS['email']} chars)")
            
        if not cls.EMAIL_REGEX.match(email):
            raise ValueError(f"Invalid email format: {email}")
            
        return email
    
    @classmethod
    def validate_password(cls, password: str) -> str:
        """Validate password strength."""
        if not password:
            raise ValueError("Password cannot be empty")
            
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
            
        if len(password) > cls.MAX_LENGTHS['password']:
            raise ValueError(f"Password too long (max {cls.MAX_LENGTHS['password']} chars)")
            
        # Check for password complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
        
        complexity_score = sum([has_upper, has_lower, has_digit, has_special])
        
        if complexity_score < 3:
            raise ValueError("Password must contain at least 3 of: uppercase, lowercase, digit, special character")
            
        return password
    
    @classmethod
    def sanitize_string(cls, input_str: str, max_length: int = 255, 
                       allow_html: bool = False) -> str:
        """Sanitize string input for safe storage and display."""
        if not input_str:
            return ""
            
        # Trim whitespace
        input_str = input_str.strip()
        
        # Limit length
        if len(input_str) > max_length:
            input_str = input_str[:max_length]
        
        # Remove null bytes
        input_str = input_str.replace('\x00', '')
        
        # HTML escape if needed
        if not allow_html:
            input_str = html.escape(input_str)
        
        return input_str
    
    @classmethod
    def validate_integer(cls, value: Any, min_val: Optional[int] = None, 
                        max_val: Optional[int] = None) -> int:
        """Validate integer input within bounds."""
        try:
            int_val = int(value)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid integer value: {value}")
        
        if min_val is not None and int_val < min_val:
            raise ValueError(f"Value must be at least {min_val}")
            
        if max_val is not None and int_val > max_val:
            raise ValueError(f"Value must be at most {max_val}")
            
        return int_val
    
    @classmethod
    def validate_float(cls, value: Any, min_val: Optional[float] = None,
                      max_val: Optional[float] = None) -> float:
        """Validate float input within bounds."""
        try:
            float_val = float(value)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid float value: {value}")
        
        if min_val is not None and float_val < min_val:
            raise ValueError(f"Value must be at least {min_val}")
            
        if max_val is not None and float_val > max_val:
            raise ValueError(f"Value must be at most {max_val}")
            
        return float_val
    
    @classmethod
    def validate_boolean(cls, value: Any) -> bool:
        """Validate and convert boolean input."""
        if isinstance(value, bool):
            return value
            
        if isinstance(value, str):
            value = value.lower().strip()
            if value in ('true', '1', 'yes', 'on'):
                return True
            elif value in ('false', '0', 'no', 'off'):
                return False
                
        raise ValueError(f"Invalid boolean value: {value}")
    
    @classmethod
    def validate_device_type(cls, device_type: str) -> str:
        """Validate device type against allowed values."""
        if not device_type:
            return ''  # Return empty string when no type specified (don't filter)

        device_type = device_type.strip().lower()
        
        allowed_types = [
            'router', 'switch', 'computer', 'laptop', 'phone', 'tablet',
            'printer', 'camera', 'smart_home', 'iot', 'server', 'nas',
            'media', 'gaming', 'unknown'
        ]
        
        if device_type not in allowed_types:
            logger.warning(f"Unknown device type: {device_type}, defaulting to 'unknown'")
            return 'unknown'
            
        return device_type
    
    @classmethod
    def validate_url(cls, url: str, allowed_schemes: List[str] = None) -> str:
        """Validate URL format and scheme."""
        if not url:
            raise ValueError("URL cannot be empty")
            
        url = url.strip()
        
        if len(url) > cls.MAX_LENGTHS['url']:
            raise ValueError(f"URL too long (max {cls.MAX_LENGTHS['url']} chars)")
        
        # Parse URL
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            raise ValueError(f"Invalid URL format: {url}")
        
        # Check scheme
        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']
            
        if parsed.scheme not in allowed_schemes:
            raise ValueError(f"URL scheme must be one of: {', '.join(allowed_schemes)}")
        
        # Check for basic URL structure
        if not parsed.netloc:
            raise ValueError(f"Invalid URL: missing domain")
        
        return url
    
    @classmethod
    def validate_port(cls, port: Any) -> int:
        """Validate network port number."""
        port = cls.validate_integer(port, min_val=1, max_val=65535)
        return port
    
    @classmethod
    def validate_pagination(cls, page: Any = 1, per_page: Any = 50) -> tuple:
        """Validate pagination parameters."""
        page = cls.validate_integer(page, min_val=1, max_val=10000)
        per_page = cls.validate_integer(per_page, min_val=1, max_val=500)
        return page, per_page
    
    @classmethod
    def validate_search_query(cls, query: str) -> str:
        """Validate and sanitize search query."""
        if not query:
            return ""
            
        query = cls.sanitize_string(query, max_length=cls.MAX_LENGTHS['search_query'])
        
        # Remove SQL-like keywords
        dangerous_keywords = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER', 'CREATE', 'EXEC', 'EXECUTE']
        for keyword in dangerous_keywords:
            query = re.sub(rf'\b{keyword}\b', '', query, flags=re.IGNORECASE)
        
        return query.strip()
    
    @classmethod
    def validate_json_input(cls, data: Dict[str, Any], required_fields: List[str] = None,
                           allowed_fields: List[str] = None) -> Dict[str, Any]:
        """Validate JSON input structure."""
        if not isinstance(data, dict):
            raise ValueError("Input must be a JSON object")
        
        # Check required fields
        if required_fields:
            missing = set(required_fields) - set(data.keys())
            if missing:
                raise ValueError(f"Missing required fields: {', '.join(missing)}")
        
        # Check allowed fields
        if allowed_fields:
            extra = set(data.keys()) - set(allowed_fields)
            if extra:
                logger.warning(f"Removing unexpected fields: {extra}")
                for field in extra:
                    del data[field]
        
        return data


def validate_request(required_fields: List[str] = None, allowed_fields: List[str] = None):
    """Decorator to validate request data."""
    from functools import wraps
    from flask import request, jsonify
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get request data
                if request.is_json:
                    data = request.get_json()
                    if data:
                        InputValidator.validate_json_input(
                            data, 
                            required_fields=required_fields,
                            allowed_fields=allowed_fields
                        )
                
                # Validate query parameters
                for key, value in request.args.items():
                    # Basic sanitization of query parameters
                    if len(value) > 1000:
                        return jsonify({'error': f'Query parameter {key} too long'}), 400
                        
                return f(*args, **kwargs)
                
            except ValueError as e:
                logger.warning(f"Validation error: {e}")
                return jsonify({'error': str(e)}), 400
            except Exception as e:
                logger.error(f"Unexpected validation error: {e}")
                return jsonify({'error': 'Invalid request data'}), 400
                
        return decorated_function
    return decorator