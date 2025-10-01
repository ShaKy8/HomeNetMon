# HomeNetMon API Reference

## Overview

HomeNetMon provides a comprehensive REST API for programmatic access to all monitoring functionality. This reference covers all available endpoints, authentication, and usage examples.

## Table of Contents

1. [Authentication](#authentication)
2. [Base URLs and Versioning](#base-urls-and-versioning)
3. [Response Formats](#response-formats)
4. [Error Handling](#error-handling)
5. [Rate Limiting](#rate-limiting)
6. [Device Management API](#device-management-api)
7. [Monitoring API](#monitoring-api)
8. [Performance API](#performance-api)
9. [System API](#system-api)
10. [Security API](#security-api)
11. [WebSocket Events](#websocket-events)

## Authentication

### Session-Based Authentication

Most API endpoints require authentication. Use the web login to establish a session, then include session cookies with API requests.

```bash
# Login to establish session
curl -X POST -c cookies.txt \
  -d "username=admin&password=yourpassword" \
  -d "csrf_token=$(curl -b cookies.txt http://localhost/api/csrf-token | jq -r '.csrf_token')" \
  http://localhost/login

# Use session cookies for API calls
curl -b cookies.txt http://localhost/api/devices
```

### CSRF Protection

All POST/PUT/DELETE requests require CSRF tokens:

```bash
# Get CSRF token
CSRF_TOKEN=$(curl -s http://localhost/api/csrf-token | jq -r '.csrf_token')

# Include in requests
curl -X POST -H "X-CSRF-Token: $CSRF_TOKEN" \
  -d '{"name": "New Device"}' \
  http://localhost/api/devices
```

## Base URLs and Versioning

- **Base URL**: `http://your-server/api/`
- **Current Version**: v1 (implicit)
- **Content Type**: `application/json`

## Response Formats

### Success Response

```json
{
  "success": true,
  "data": {
    // Response data
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Error Response

```json
{
  "success": false,
  "error": "Error description",
  "code": "ERROR_CODE",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Error Handling

### HTTP Status Codes

| Code | Description | Usage |
|------|-------------|-------|
| 200 | OK | Successful request |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid request data |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 422 | Unprocessable Entity | Validation errors |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |

### Error Codes

| Code | Description |
|------|-------------|
| `AUTHENTICATION_REQUIRED` | Login required |
| `CSRF_TOKEN_MISSING` | CSRF token required |
| `VALIDATION_ERROR` | Input validation failed |
| `DEVICE_NOT_FOUND` | Device does not exist |
| `NETWORK_ERROR` | Network operation failed |
| `DATABASE_ERROR` | Database operation failed |

## Rate Limiting

API endpoints are rate limited to prevent abuse:

- **Default Limit**: 100 requests per minute per IP
- **API Endpoints**: 60 requests per minute per IP
- **Authentication**: 10 attempts per minute per IP

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## Device Management API

### List All Devices

```http
GET /api/devices
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "ip": "192.168.1.100",
      "name": "Router",
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "vendor": "Cisco",
      "status": "online",
      "last_seen": "2024-01-01T12:00:00Z",
      "response_time": 15.5,
      "device_type": "router"
    }
  ]
}
```

### Get Device Details

```http
GET /api/devices/{device_id}
```

**Parameters:**
- `device_id` (integer): Device ID

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "ip": "192.168.1.100",
    "name": "Router",
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "vendor": "Cisco",
    "status": "online",
    "last_seen": "2024-01-01T12:00:00Z",
    "response_time": 15.5,
    "device_type": "router",
    "monitoring_enabled": true,
    "alert_enabled": true
  }
}
```

### Update Device

```http
PUT /api/devices/{device_id}
```

**Request Body:**
```json
{
  "name": "Updated Device Name",
  "device_type": "computer",
  "monitoring_enabled": true,
  "alert_enabled": true
}
```

### Delete Device

```http
DELETE /api/devices/{device_id}
```

### Scan for New Devices

```http
POST /api/devices/scan-now
```

**Request Headers:**
```
X-CSRF-Token: your-csrf-token
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scan_id": "scan-123",
    "status": "started",
    "message": "Network scan initiated"
  }
}
```

## Monitoring API

### Get Monitoring Summary

```http
GET /api/monitoring/summary
```

**Query Parameters:**
- `hours` (integer, optional): Time period in hours (default: 24)

**Response:**
```json
{
  "success": true,
  "data": {
    "total_devices": 25,
    "online_devices": 23,
    "offline_devices": 2,
    "average_response_time": 18.5,
    "uptime_percentage": 92.5,
    "alerts": {
      "active": 3,
      "resolved": 15
    }
  }
}
```

### Get Device Monitoring Data

```http
GET /api/monitoring/device/{device_id}
```

**Query Parameters:**
- `hours` (integer, optional): Time period in hours (default: 24)
- `limit` (integer, optional): Maximum number of records (default: 100)

**Response:**
```json
{
  "success": true,
  "data": {
    "device_id": 1,
    "monitoring_data": [
      {
        "timestamp": "2024-01-01T12:00:00Z",
        "status": "online",
        "response_time": 15.5,
        "packet_loss": 0
      }
    ]
  }
}
```

### Get Alerts

```http
GET /api/monitoring/alerts
```

**Query Parameters:**
- `status` (string, optional): Filter by status (`active`, `resolved`)
- `device_id` (integer, optional): Filter by device
- `limit` (integer, optional): Maximum number of alerts

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "device_id": 5,
      "alert_type": "device_offline",
      "message": "Device Router has been offline for 5 minutes",
      "severity": "high",
      "status": "active",
      "created_at": "2024-01-01T12:00:00Z",
      "resolved_at": null
    }
  ]
}
```

### Resolve Alert

```http
PUT /api/monitoring/alerts/{alert_id}/resolve
```

**Request Headers:**
```
X-CSRF-Token: your-csrf-token
```

### Bulk Resolve Alerts

```http
POST /api/monitoring/alerts/resolve-all
```

**Request Headers:**
```
X-CSRF-Token: your-csrf-token
```

**Request Body:**
```json
{
  "alert_ids": [1, 2, 3],
  "reason": "Maintenance window"
}
```

## Performance API

### Get Performance Summary

```http
GET /api/performance/summary
```

**Query Parameters:**
- `hours` (integer, optional): Time period in hours (default: 24)

**Response:**
```json
{
  "success": true,
  "data": {
    "network_health_score": 95.5,
    "average_response_time": 18.5,
    "packet_loss_percentage": 0.1,
    "uptime_percentage": 99.2,
    "device_count": 25,
    "performance_trends": {
      "response_time_trend": "stable",
      "availability_trend": "improving"
    }
  }
}
```

### Get Device Performance

```http
GET /api/performance/device/{device_id}
```

**Query Parameters:**
- `hours` (integer, optional): Time period in hours (default: 24)
- `metrics` (string, optional): Comma-separated metrics list

**Response:**
```json
{
  "success": true,
  "data": {
    "device_id": 1,
    "health_score": 98.5,
    "metrics": {
      "average_response_time": 12.3,
      "packet_loss": 0.0,
      "uptime_percentage": 99.8,
      "availability_score": 100.0
    },
    "trends": {
      "response_time": "improving",
      "availability": "stable"
    }
  }
}
```

### Get Network Health Score

```http
GET /api/performance/network-health
```

**Response:**
```json
{
  "success": true,
  "data": {
    "overall_health_score": 95.5,
    "components": {
      "device_availability": 98.0,
      "response_times": 92.5,
      "network_stability": 96.0
    },
    "recommendations": [
      "Monitor device 192.168.1.50 for high response times",
      "Consider upgrading router firmware"
    ]
  }
}
```

## System API

### Get System Information

```http
GET /api/system/info
```

**Response:**
```json
{
  "success": true,
  "data": {
    "version": "1.0.0",
    "uptime": 86400,
    "system": {
      "cpu_usage": 15.5,
      "memory_usage": 45.2,
      "disk_usage": 25.8
    },
    "database": {
      "size_mb": 125.5,
      "record_count": 50000
    },
    "monitoring": {
      "devices_monitored": 25,
      "active_scans": 1,
      "last_scan": "2024-01-01T12:00:00Z"
    }
  }
}
```

### Health Check

```http
GET /api/system/health
```

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "checks": {
      "database": "ok",
      "network": "ok",
      "disk_space": "ok",
      "memory": "ok"
    },
    "timestamp": "2024-01-01T12:00:00Z"
  }
}
```

### Get Configuration

```http
GET /api/system/config
```

**Response:**
```json
{
  "success": true,
  "data": {
    "network_range": "192.168.1.0/24",
    "ping_interval": 30,
    "scan_interval": 300,
    "alert_enabled": true,
    "monitoring_enabled": true
  }
}
```

### Update Configuration

```http
PUT /api/system/config
```

**Request Headers:**
```
X-CSRF-Token: your-csrf-token
```

**Request Body:**
```json
{
  "ping_interval": 60,
  "scan_interval": 600,
  "alert_enabled": true
}
```

## Security API

### Get CSRF Token

```http
GET /api/csrf-token
```

**Response:**
```json
{
  "csrf_token": "your-csrf-token-here"
}
```

### Security Status

```http
GET /api/security/status
```

**Response:**
```json
{
  "success": true,
  "data": {
    "ssl_enabled": true,
    "firewall_enabled": true,
    "rate_limiting_enabled": true,
    "csrf_protection_enabled": true,
    "security_headers_enabled": true,
    "last_security_scan": "2024-01-01T12:00:00Z"
  }
}
```

## WebSocket Events

HomeNetMon provides real-time updates via WebSocket connections.

### Connection

```javascript
const socket = io('http://your-server');
```

### Device Status Updates

```javascript
socket.on('device_status_update', function(data) {
  console.log('Device update:', data);
  // data: { device_id, status, response_time, timestamp }
});
```

### Network Summary Updates

```javascript
socket.on('monitoring_summary', function(data) {
  console.log('Network summary:', data);
  // data: { total_devices, online_devices, offline_devices, timestamp }
});
```

### Alert Notifications

```javascript
socket.on('new_alert', function(data) {
  console.log('New alert:', data);
  // data: { alert_id, device_id, message, severity, timestamp }
});
```

### Scan Progress

```javascript
socket.on('scan_progress', function(data) {
  console.log('Scan progress:', data);
  // data: { scan_id, progress_percentage, devices_found, timestamp }
});
```

## Usage Examples

### Python Example

```python
import requests
import json

class HomeNetMonAPI:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.session = requests.Session()
        self.login(username, password)

    def login(self, username, password):
        # Get CSRF token
        csrf_response = self.session.get(f"{self.base_url}/api/csrf-token")
        csrf_token = csrf_response.json()['csrf_token']

        # Login
        login_data = {
            'username': username,
            'password': password,
            'csrf_token': csrf_token
        }
        self.session.post(f"{self.base_url}/login", data=login_data)

    def get_devices(self):
        response = self.session.get(f"{self.base_url}/api/devices")
        return response.json()

    def scan_network(self):
        csrf_response = self.session.get(f"{self.base_url}/api/csrf-token")
        csrf_token = csrf_response.json()['csrf_token']

        headers = {'X-CSRF-Token': csrf_token}
        response = self.session.post(
            f"{self.base_url}/api/devices/scan-now",
            headers=headers
        )
        return response.json()

# Usage
api = HomeNetMonAPI('http://localhost', 'admin', 'password')
devices = api.get_devices()
scan_result = api.scan_network()
```

### JavaScript Example

```javascript
class HomeNetMonAPI {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }

    async getCSRFToken() {
        const response = await fetch(`${this.baseUrl}/api/csrf-token`);
        const data = await response.json();
        return data.csrf_token;
    }

    async getDevices() {
        const response = await fetch(`${this.baseUrl}/api/devices`);
        return await response.json();
    }

    async scanNetwork() {
        const csrfToken = await this.getCSRFToken();

        const response = await fetch(`${this.baseUrl}/api/devices/scan-now`, {
            method: 'POST',
            headers: {
                'X-CSRF-Token': csrfToken
            }
        });
        return await response.json();
    }
}

// Usage
const api = new HomeNetMonAPI('http://localhost');
api.getDevices().then(devices => console.log(devices));
api.scanNetwork().then(result => console.log(result));
```

### cURL Examples

```bash
# Get devices
curl -b cookies.txt http://localhost/api/devices

# Get monitoring summary
curl -b cookies.txt "http://localhost/api/monitoring/summary?hours=48"

# Scan network
CSRF_TOKEN=$(curl -b cookies.txt -s http://localhost/api/csrf-token | jq -r '.csrf_token')
curl -b cookies.txt -X POST -H "X-CSRF-Token: $CSRF_TOKEN" \
  http://localhost/api/devices/scan-now

# Update device
curl -b cookies.txt -X PUT -H "X-CSRF-Token: $CSRF_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Updated Device Name"}' \
  http://localhost/api/devices/1
```

## Best Practices

### Authentication
- Always use HTTPS in production
- Include CSRF tokens for state-changing operations
- Handle session expiration gracefully
- Store credentials securely

### Rate Limiting
- Implement client-side rate limiting
- Handle 429 responses with exponential backoff
- Cache responses when appropriate
- Use WebSocket for real-time updates instead of polling

### Error Handling
- Always check response status codes
- Handle network errors gracefully
- Implement retry logic for transient failures
- Log errors for debugging

### Performance
- Use appropriate query parameters to limit data
- Implement pagination for large datasets
- Cache frequently accessed data
- Use WebSocket for real-time updates

---

For additional API questions or feature requests, please refer to the [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md) or contact support.
