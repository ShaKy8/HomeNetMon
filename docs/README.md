# HomeNetMon Documentation

## Overview

Welcome to the comprehensive documentation for HomeNetMon, a powerful network monitoring solution for home and small business environments. This documentation covers everything from quick deployment to advanced administration.

## Quick Navigation

### 🚀 Getting Started
- [**Quick Start Guide**](QUICK_START.md) - 5-minute deployment
- [**Deployment Guide**](DEPLOYMENT_GUIDE.md) - Complete installation procedures
- [**User Guide**](USER_GUIDE.md) - User interface and features

### 🔧 Operations & Maintenance
- [**Operations Guide**](OPERATIONS_GUIDE.md) - Day-to-day operations
- [**Administration Guide**](ADMINISTRATION_GUIDE.md) - Advanced administration
- [**Troubleshooting Guide**](TROUBLESHOOTING_GUIDE.md) - Problem resolution

### 🔌 Technical Reference
- [**API Reference**](API_REFERENCE.md) - Complete API documentation
- [**Security Guide**](../SECURITY_GUIDE.md) - Security hardening
- [**Production Deployment**](../PRODUCTION_DEPLOYMENT.md) - Production setup

## Documentation Structure

### For New Users
1. Start with [Quick Start Guide](QUICK_START.md) for immediate deployment
2. Read [User Guide](USER_GUIDE.md) to understand features
3. Configure using [Deployment Guide](DEPLOYMENT_GUIDE.md) for production

### For Administrators
1. Review [Administration Guide](ADMINISTRATION_GUIDE.md) for management tasks
2. Implement [Security Guide](../SECURITY_GUIDE.md) for hardening
3. Use [Operations Guide](OPERATIONS_GUIDE.md) for daily operations

### For Developers
1. Study [API Reference](API_REFERENCE.md) for integration
2. Review codebase structure and patterns
3. Use [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md) for diagnostics

## Key Features Covered

### Network Monitoring
- Automatic device discovery
- Real-time status monitoring
- Performance analytics
- Historical data tracking

### Alerting & Notifications
- Configurable alert thresholds
- Email and webhook notifications
- Alert management and resolution
- Escalation procedures

### Performance Management
- Network health scoring
- Response time monitoring
- Availability tracking
- Performance optimization

### Security Features
- Authentication and authorization
- SSL/TLS encryption
- Rate limiting and protection
- Security monitoring

### Administration
- User management
- Configuration management
- Backup and recovery
- System maintenance

## Common Use Cases

### Home Network Monitoring
- Monitor family devices and IoT equipment
- Track internet connectivity issues
- Identify unauthorized devices
- Optimize WiFi performance

### Small Business Networks
- Monitor critical business devices
- Ensure network reliability
- Track performance trends
- Manage network security

### IT Professional Tools
- Network diagnostic capabilities
- Performance baseline establishment
- Proactive issue identification
- Documentation and reporting

## Support Resources

### Documentation Hierarchy
```
docs/
├── README.md                    # This file - main index
├── QUICK_START.md              # 5-minute deployment
├── DEPLOYMENT_GUIDE.md         # Complete installation
├── USER_GUIDE.md               # End-user documentation
├── OPERATIONS_GUIDE.md         # Daily operations
├── ADMINISTRATION_GUIDE.md     # Advanced administration
├── TROUBLESHOOTING_GUIDE.md    # Problem resolution
└── API_REFERENCE.md            # Complete API documentation
```

### External Documentation
- [Security Guide](../SECURITY_GUIDE.md) - Security implementation
- [Production Deployment](../PRODUCTION_DEPLOYMENT.md) - Production setup
- [Performance Optimization](../PERFORMANCE_OPTIMIZATION_GUIDE.md) - Optimization

### Getting Help

#### Self-Service Resources
1. **Search Documentation** - Use browser search (Ctrl+F) within guides
2. **Check Troubleshooting** - Review [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md)
3. **Review Logs** - Check application and system logs
4. **Test Configuration** - Verify settings and connectivity

#### Common Solutions
| Issue | Quick Solution | Documentation |
|-------|----------------|---------------|
| Service won't start | Check logs and configuration | [Troubleshooting](TROUBLESHOOTING_GUIDE.md#service-issues) |
| Devices not appearing | Verify network range | [User Guide](USER_GUIDE.md#network-discovery) |
| Poor performance | Run optimization scripts | [Operations](OPERATIONS_GUIDE.md#performance-management) |
| Security concerns | Review security checklist | [Security Guide](../SECURITY_GUIDE.md) |
| API integration | Check API documentation | [API Reference](API_REFERENCE.md) |

#### Support Channels
1. **Documentation** - Comprehensive guides for all topics
2. **Troubleshooting** - Step-by-step problem resolution
3. **Community** - Forums and discussion groups
4. **Professional Support** - Technical assistance (if available)

## Version Information

- **Documentation Version**: 1.0
- **Last Updated**: 2024-01-01
- **Compatible With**: HomeNetMon v1.0+

## Contributing to Documentation

### Improvement Suggestions
- Report unclear sections
- Suggest additional examples
- Request new topics
- Provide feedback on accuracy

### Documentation Standards
- Clear, concise language
- Step-by-step procedures
- Working examples
- Regular updates

## Quick Reference Cards

### Essential Commands
```bash
# Service management
sudo systemctl status homenetmon
sudo systemctl restart homenetmon

# Health checks
curl http://localhost/health
./health_check.sh

# Backup and restore
python3 backup_production.py
python3 optimize_database_performance.py

# Security
sudo ./security/configure-firewall.sh
sudo certbot renew
```

### Important File Locations
```
/opt/homenetmon/                # Application directory
/opt/homenetmon/.env           # Configuration file
/opt/homenetmon/logs/          # Log files
/opt/homenetmon/backups/       # Database backups
/etc/systemd/system/homenetmon.service  # Systemd service
```

### Default URLs and Ports
- **Web Interface**: http://localhost or http://your-server-ip
- **API Base**: http://localhost/api/
- **Health Check**: http://localhost/health
- **Default Port**: 5000 (application), 80/443 (web)

## Quick Start Summary

For immediate deployment:

1. **Download and Configure**
   ```bash
   git clone https://github.com/your-org/homenetmon.git
   cd homenetmon
   cp .env.prod.template .env.prod
   # Edit .env.prod with your settings
   ```

2. **Deploy**
   ```bash
   # Docker (recommended)
   docker-compose -f docker-compose.prod.yml up -d

   # Or native
   sudo ./deploy.sh
   ```

3. **Access and Configure**
   - Open http://your-server-ip
   - Login with admin credentials
   - Configure network range
   - Start monitoring

For detailed instructions, see the [Quick Start Guide](QUICK_START.md).

---

**Next Steps:**
- Choose your deployment method from the guides above
- Configure your specific environment needs
- Set up monitoring and alerting
- Implement security best practices
- Establish maintenance procedures

Happy monitoring! 🚀
