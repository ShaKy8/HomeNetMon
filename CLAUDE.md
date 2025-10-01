# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HomeNetMon is a comprehensive home network monitoring solution built with Flask, SQLAlchemy, and modern web technologies. It provides real-time device monitoring, alerting, network visualization, performance analytics, and advanced security features through a responsive web dashboard.
The project is for home or small business use on small single-subnet networks (x.x.x.x/24).  It is not intended for corporate or enterprise use.

### Key Features
- Automatic network device discovery using ARP/nmap scanning
- Real-time ping monitoring with configurable intervals
- Web dashboard with real-time updates via WebSockets
- Email and webhook alert notifications
- Device management with custom naming and grouping
- Historical data tracking and performance charts
- Advanced analytics and anomaly detection
- Performance optimization and resource monitoring
- Security features including authentication, rate limiting, and CSRF protection
- Usage analytics and SaaS administration capabilities
- REST API for external integrations with comprehensive security
- Docker deployment support
- Asset bundling and optimization for production
- Database performance optimization and query caching

## Development Setup

### Prerequisites
- Python 3.8+
- nmap (for network scanning)
- SQLite (for database)

### Quick Start
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export NETWORK_RANGE="192.168.86.0/24"
export DEBUG=true

# Run development server
python app.py
```

### Docker Development
```bash
# Build and run with Docker
docker-compose up --build

# View logs
docker-compose logs -f
```

## Common Commands

### Development
- `python app.py` - Start development server
- `ADMIN_PASSWORD=admin123 HOST=0.0.0.0 DEBUG=true python app.py` - Start with auth enabled
- `python build_assets.py` - Bundle and minify CSS/JS assets
- `python -m pytest` - Run tests
- `python test_auth.py` - Test authentication system
- `python optimize_performance.py` - Run performance optimizations
- `python database_performance_fix.py` - Optimize database performance
- `docker-compose up -d` - Start services in background
- `docker-compose logs -f` - Follow logs

### Production Deployment
- `./install.sh` - Automated installation on Ubuntu/Debian
- `sudo systemctl status homeNetMon` - Check service status
- `sudo systemctl restart homeNetMon` - Restart service
- `sudo journalctl -u homeNetMon -f` - View service logs

### Database Management
- Database is SQLite-based and managed automatically
- Data retention is configurable (default: 30 days)
- Backup: `sqlite3 homeNetMon.db ".backup backup.db"`

## Architecture

### Backend Architecture
```
app.py (Flask Application)
├── models.py (SQLAlchemy Models)
├── config.py (Configuration Management)
├── core/ (Core Services)
│   ├── auth.py, auth_db.py (Authentication System)
│   ├── security_middleware.py (CSRF & Security)
│   ├── rate_limiter.py (Rate Limiting)
│   ├── cache_layer.py (Caching System)
│   ├── db_optimizer.py (Database Optimization)
│   └── websocket_manager.py (WebSocket Management)
├── monitoring/ (Background Services)
│   ├── scanner.py (Network Discovery)
│   ├── monitor.py (Device Monitoring)
│   └── alerts.py (Alert Management)
├── services/ (Business Logic)
│   ├── query_optimizer.py (Query Optimization)
│   ├── cdn_manager.py (CDN & Static Assets)
│   ├── http_optimizer.py (HTTP/2 & Performance)
│   └── resource_optimizer.py (Resource Management)
└── api/ (Extensive REST API)
    ├── devices.py, devices_optimized.py
    ├── monitoring.py, performance.py
    ├── auth.py, security.py
    ├── analytics.py, usage_analytics_api.py
    ├── saas_admin.py, rate_limiting.py
    └── [25+ specialized API modules]
```

### Frontend Architecture
- Bootstrap 5 for responsive UI
- Chart.js for data visualization
- Socket.IO for real-time updates
- Vanilla JavaScript (no framework dependencies)

### Database Schema
- **Device**: Store device information and metadata
- **MonitoringData**: Historical ping/response data
- **Alert**: Alert records and acknowledgments
- **Configuration**: Runtime configuration storage

### Key Components

1. **Network Scanner** (`monitoring/scanner.py`)
   - ARP table parsing for device discovery
   - nmap integration for detailed scanning
   - MAC vendor lookup and device classification

2. **Device Monitor** (`monitoring/monitor.py`) 
   - Multi-threaded ping monitoring
   - Response time tracking and statistics
   - Real-time WebSocket updates

3. **Alert Manager** (`monitoring/alerts.py`)
   - Rule-based alert generation
   - Email and webhook notifications
   - Alert lifecycle management

4. **Web Dashboard** (`templates/`)
   - Real-time device status grid
   - Individual device detail pages
   - Configuration interface
   - Alert management interface

## Configuration

### Environment Variables
Key configuration options (see `.env.example`):
- `NETWORK_RANGE`: CIDR network to monitor
- `PING_INTERVAL`: Monitoring frequency (seconds)
- `SMTP_*`: Email configuration for alerts
- `WEBHOOK_URL`: Webhook endpoint for notifications

### Runtime Configuration
- Web-based settings interface at `/settings`
- YAML configuration file support
- Database-stored configuration with web UI

## API Documentation

RESTful API available at `/api/`:
- `/api/devices` - Device management
- `/api/monitoring` - Monitoring data and statistics  
- `/api/config` - Configuration management

WebSocket events for real-time updates:
- `device_status_update` - Individual device status
- `monitoring_summary` - Network-wide statistics

## Security Considerations

### Network Permissions
- Requires `CAP_NET_RAW` for ping operations
- Needs network access for scanning
- Docker containers run as non-root user

### Application Security
- Database-backed authentication system with admin controls
- CSRF protection via security middleware
- Comprehensive rate limiting with Redis support
- Input validation and sanitization on all endpoints
- SQL injection protection via SQLAlchemy ORM
- XSS prevention through template escaping
- Secure session management
- API security with authentication tokens
- Security headers and middleware

## Deployment Options

1. **Docker (Recommended)**
   - Complete containerized deployment
   - Host network mode for full scanning capability
   - Automatic service management

2. **Native Installation**
   - Systemd service integration
   - Nginx reverse proxy configuration
   - Full system integration

3. **Development**
   - Direct Python execution
   - Debug mode with hot reloading
   - SQLite database in project directory

## Testing and Quality

### Code Organization
- Modular design with clear separation of concerns
- REST API follows OpenAPI patterns
- Database models use SQLAlchemy best practices
- Frontend follows responsive design principles

### Error Handling
- Comprehensive exception handling in all modules
- Graceful degradation for network issues
- User-friendly error messages in UI
- Structured logging throughout application

## Performance & Optimization

### Asset Management
- Frontend assets are bundled and minified via `build_assets.py`
- Gzip and Brotli compression for static files
- CDN integration for optimized delivery
- Cache busting with content hashes

### Database Optimization
- Query optimization and performance profiling
- Database indexing for common queries
- Connection pooling and resource management
- Query caching layer for frequently accessed data

### Real-time Features
- WebSocket connection optimization
- Memory-efficient real-time updates
- Connection throttling and resource management

## Authentication & Security

### Development Authentication
- Use `ADMIN_PASSWORD=admin123` environment variable for development
- Authentication system stores users in database
- Run `python migrate_to_db_auth.py` to set up database authentication
- Test with `python test_auth.py`

### Rate Limiting
- Redis-backed rate limiting (falls back to in-memory)
- Per-endpoint and per-IP limits
- Admin interface for rate limit management
- Configurable limits via environment variables

## Important Development Notes

### Network Binding
- **NEVER** bind to 127.0.0.1 or localhost
- Always use 0.0.0.0 for proper network access
- Application designed for local network access

### Asset Building
- Run `python build_assets.py` after CSS/JS changes
- Assets are automatically compressed and optimized
- Manifest file tracks asset versions for cache busting

### Database Management
- SQLite with extensive performance optimizations
- Run database optimization scripts after schema changes
- Automatic indexing and query performance monitoring

### Testing and Quality
- Comprehensive test suite with authentication tests
- Performance monitoring and profiling tools
- Database performance validation
- Asset optimization verification

### Authentication & Route Issues
- If @login_required decorators cause 500 errors, check for missing 'login' route
- The login_required decorator in core/auth.py redirects to url_for('login')
- For admin pages (/security, /settings, /analytics), consider removing @login_required if no login route exists
- Authentication models (User, Session) must be properly defined in models.py

## Architecture Highlights

- **Modular Design**: Core services, API modules, and monitoring separated
- **Performance-First**: Extensive caching, optimization, and profiling
- **Security-Aware**: Authentication, CSRF protection, rate limiting
- **Production-Ready**: Asset bundling, database optimization, monitoring
- **Scalable**: Resource management, connection optimization, caching layers
- Do not add an authentication system