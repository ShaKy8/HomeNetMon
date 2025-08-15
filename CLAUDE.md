# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HomeNetMon is a comprehensive home network monitoring solution built with Flask, SQLAlchemy, and modern web technologies. It provides real-time device monitoring, alerting, and network visualization through a responsive web dashboard.

### Key Features
- Automatic network device discovery using ARP/nmap scanning
- Real-time ping monitoring with configurable intervals
- Web dashboard with real-time updates via WebSockets
- Email and webhook alert notifications
- Device management with custom naming and grouping
- Historical data tracking and performance charts
- REST API for external integrations
- Docker deployment support

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
- `python -m pytest` - Run tests (when implemented)
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
├── monitoring/ (Background Services)
│   ├── scanner.py (Network Discovery)
│   ├── monitor.py (Device Monitoring)
│   └── alerts.py (Alert Management)
└── api/ (REST API Blueprints)
    ├── devices.py
    ├── monitoring.py
    └── config.py
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
- No authentication currently implemented (suitable for home networks)
- Input validation on all API endpoints
- SQL injection protection via SQLAlchemy ORM
- XSS prevention through template escaping

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

## Notes

- This is a complete, production-ready home network monitoring solution
- Designed for easy deployment and minimal maintenance
- Extensible architecture supports additional monitoring features
- Optimized for home networks (typically <100 devices)
- All major features implemented including real-time monitoring, alerting, and web dashboard
- never bind anything to 127.0.0.1
- never bind anything to localhost