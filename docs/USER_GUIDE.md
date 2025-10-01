# HomeNetMon User Guide

## Overview

HomeNetMon is a comprehensive network monitoring solution that helps you monitor, manage, and analyze your home or small business network. This guide covers all user-facing features and functionality.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Device Management](#device-management)
4. [Network Monitoring](#network-monitoring)
5. [Alerts and Notifications](#alerts-and-notifications)
6. [Performance Analytics](#performance-analytics)
7. [Network Topology](#network-topology)
8. [Settings and Configuration](#settings-and-configuration)
9. [Troubleshooting](#troubleshooting)

## Getting Started

### First Login

1. **Access the Application**
   - Open your web browser
   - Navigate to `http://your-server-ip` or your configured domain
   - You should see the HomeNetMon login screen

2. **Login**
   - Username: `admin`
   - Password: Your configured admin password
   - Click "Login"

3. **Initial Setup**
   - Upon first login, the system will automatically start scanning your network
   - Wait for the initial scan to complete (usually 1-2 minutes)
   - You'll see discovered devices appear on the dashboard

### Dashboard Overview

The main dashboard provides a real-time overview of your network:

#### Top Statistics Bar
- **Total Devices**: Number of discovered devices
- **Online Devices**: Currently responsive devices
- **Offline Devices**: Non-responsive devices
- **Network Health**: Overall network health score

#### Device Status Grid
- **Green**: Device is online and responsive
- **Red**: Device is offline or not responding
- **Yellow**: Device has connectivity issues
- **Gray**: Device monitoring is disabled

#### Quick Actions
- **Scan Network**: Manually trigger a network scan
- **Refresh**: Update current status
- **Settings**: Access configuration options

## Device Management

### Viewing Devices

#### Device List
- All discovered devices are shown in a grid layout
- Each device card shows:
  - Device name (or IP address)
  - Current status (online/offline)
  - Last seen timestamp
  - Response time (for online devices)
  - Device type icon

#### Device Details
- Click on any device card to view detailed information:
  - IP address and MAC address
  - Vendor information (if available)
  - Connection history
  - Performance statistics
  - Alert history

### Managing Devices

#### Renaming Devices
1. Click on a device to open its details
2. Click the "Edit" button
3. Enter a friendly name (e.g., "Living Room TV")
4. Click "Save"

#### Setting Device Types
1. Open device details
2. Click "Edit"
3. Select the appropriate device type:
   - Computer
   - Router
   - Switch
   - Printer
   - Phone
   - Tablet
   - Smart TV
   - IoT Device
   - Gaming Console
   - Other
4. Click "Save"

#### Enabling/Disabling Monitoring
1. Open device details
2. Toggle "Monitoring Enabled"
3. Disabled devices will not be pinged or generate alerts

#### Removing Devices
1. Open device details
2. Click "Remove Device"
3. Confirm the action
   - Note: Devices may be rediscovered during network scans

### Network Discovery

#### Automatic Scanning
- HomeNetMon automatically scans your network every 5 minutes
- New devices are automatically added
- Existing devices are updated with current information

#### Manual Scanning
- Click "Scan Network" on the dashboard
- Useful after adding new devices to your network
- Takes 30-60 seconds depending on network size

#### Scan Settings
- Network range is configured during setup
- Default: Scans your primary network subnet
- Can be adjusted in Settings if needed

## Network Monitoring

### Real-Time Status
- Device status updates every 30 seconds
- Dashboard shows current network state
- WebSocket connections provide instant updates

### Historical Data
- Performance data is stored for analysis
- Default retention: 30 days
- Includes response times, availability, and connectivity

### Performance Metrics

#### Response Time
- Time for ping response from each device
- Measured in milliseconds
- Lower is better (typically <50ms for local devices)

#### Availability
- Percentage of time device responds to pings
- Calculated over selected time period
- 100% = always responsive

#### Packet Loss
- Percentage of ping packets that don't receive responses
- 0% = perfect connectivity
- >5% may indicate network issues

### Monitoring Views

#### Live Dashboard
- Real-time device status
- Current response times
- Active alerts
- Quick network overview

#### Device History
- Click device → "History" tab
- Shows response time trends
- Availability statistics
- Connection events

#### Network Overview
- View all devices simultaneously
- Filter by status (online/offline)
- Sort by response time or last seen

## Alerts and Notifications

### Alert Types

#### Device Offline
- Triggered when device stops responding
- Default threshold: 3 consecutive failed pings
- Resolution: Device comes back online

#### High Response Time
- Triggered when response time exceeds threshold
- Default threshold: 1000ms (1 second)
- May indicate network congestion

#### Device Discovered
- Triggered when new device joins network
- Helps identify unauthorized devices
- Automatically cleared after review

#### Device Missing
- Triggered when previously seen device disappears
- May indicate device powered off or disconnected
- Cleared when device reappears

### Alert Management

#### Viewing Alerts
1. Click "Alerts" in navigation menu
2. See all current and historical alerts
3. Filter by status, device, or type

#### Alert Details
- Click on any alert to see details:
  - Device information
  - Alert trigger time
  - Current status
  - Resolution time (if resolved)

#### Resolving Alerts
1. Open alert details
2. Click "Resolve" button
3. Add optional resolution notes
4. Alert is marked as resolved

#### Bulk Operations
- Select multiple alerts using checkboxes
- Use "Resolve Selected" for bulk resolution
- Useful for maintenance periods

### Notification Setup

#### Email Notifications
1. Go to Settings → Notifications
2. Configure SMTP settings:
   - SMTP server (e.g., smtp.gmail.com)
   - Port (usually 587 for TLS)
   - Username and password
   - From email address
3. Test email configuration
4. Enable email alerts

#### Webhook Notifications
1. Go to Settings → Notifications
2. Enter webhook URL (e.g., Slack, Discord, Teams)
3. Test webhook connection
4. Enable webhook alerts

## Performance Analytics

### Network Health Score
- Overall network performance rating (0-100)
- Based on device availability and response times
- Green (90-100): Excellent
- Yellow (70-89): Good
- Red (<70): Needs attention

### Performance Trends
- Access via "Analytics" menu
- Shows network performance over time
- Identifies patterns and issues

#### Response Time Trends
- Average response times over time
- Identifies network slowdowns
- Helps plan network upgrades

#### Availability Trends
- Network uptime statistics
- Device reliability analysis
- Outage pattern identification

#### Device Performance Comparison
- Compare device performance
- Identify problematic devices
- Network topology optimization

### Analytics Features

#### Time Range Selection
- Last 24 hours
- Last 7 days
- Last 30 days
- Custom date ranges

#### Device Filtering
- View specific devices
- Group by device type
- Filter by performance criteria

#### Export Options
- Download charts as images
- Export data as CSV
- Generate PDF reports

## Network Topology

### Topology View
- Visual representation of your network
- Shows device relationships
- Interactive network map

### Features

#### Device Visualization
- Devices shown as nodes
- Connections represented as lines
- Status indicated by color coding

#### Interactive Elements
- Click devices for quick info
- Drag to reorganize layout
- Zoom and pan for large networks

#### Layout Options
- Automatic layout algorithms
- Manual positioning
- Save custom layouts

### Topology Information

#### Device Relationships
- Router/gateway identification
- Switch connections
- Wireless access points
- Client device connections

#### Network Structure
- Subnet visualization
- VLAN identification (if supported)
- Physical vs. logical connections

## Settings and Configuration

### Network Settings

#### Network Range
- Define which IP range to monitor
- Usually your local subnet (e.g., 192.168.1.0/24)
- Can monitor multiple ranges

#### Scan Intervals
- Network scan frequency (default: 5 minutes)
- Ping interval (default: 30 seconds)
- Balance between accuracy and network load

#### Monitoring Thresholds
- Offline detection threshold
- High response time threshold
- Alert trigger sensitivity

### User Preferences

#### Dashboard Layout
- Device grid size
- Information display options
- Refresh intervals

#### Notifications
- Email alert settings
- Webhook configurations
- Alert severity filters

#### Data Retention
- Historical data storage period
- Database cleanup settings
- Backup configurations

### System Settings

#### Performance Tuning
- Worker process count
- Database optimization
- Cache settings

#### Security Configuration
- Password requirements
- Session timeouts
- SSL/TLS settings

#### Backup Settings
- Automatic backup scheduling
- Backup retention policy
- Restore procedures

## Advanced Features

### API Access
- RESTful API for automation
- WebSocket for real-time data
- Authentication and rate limiting

### Custom Integrations
- Webhook support for external systems
- SNMP monitoring (if supported)
- Integration with network management tools

### Automation
- Automated network discovery
- Self-healing capabilities
- Intelligent alerting

## Tips and Best Practices

### Network Optimization
1. **Place router centrally** for best coverage
2. **Use wired connections** for critical devices
3. **Update device firmware** regularly
4. **Monitor bandwidth usage** to identify bottlenecks

### Monitoring Best Practices
1. **Set meaningful device names** for easy identification
2. **Configure appropriate alert thresholds** to avoid noise
3. **Review alerts regularly** to identify patterns
4. **Use analytics** to plan network improvements

### Security Considerations
1. **Change default passwords** immediately
2. **Enable HTTPS** for secure access
3. **Limit network access** to monitoring system
4. **Monitor for unauthorized devices**

### Maintenance
1. **Check system health** regularly
2. **Update HomeNetMon** when new versions are available
3. **Backup configurations** before changes
4. **Review and clean old data** periodically

## Troubleshooting

### Common Issues

#### Devices Not Appearing
- Check network range configuration
- Verify device is on same network
- Manually trigger network scan
- Check device firewall settings

#### Offline Devices Showing as Online
- Check ping thresholds
- Verify device responds to ping manually
- Review monitoring settings
- Check network connectivity

#### Slow Dashboard Loading
- Clear browser cache
- Check server performance
- Optimize database
- Review system resources

#### Alerts Not Working
- Verify notification settings
- Test email/webhook configuration
- Check alert thresholds
- Review device monitoring status

### Getting Help
1. Check this user guide for solutions
2. Review the troubleshooting section
3. Check application logs for errors
4. Contact support with specific details

### Performance Tips
- **Use modern browser** for best experience
- **Enable JavaScript** for full functionality
- **Close unused browser tabs** to save memory
- **Use wired connection** for monitoring system

---

## Next Steps

After reading this guide:
1. Set up your network monitoring preferences
2. Configure notifications for important alerts
3. Customize device names and types
4. Explore the analytics features
5. Set up regular maintenance routines

For technical questions, see the [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md) or [API Reference](API_REFERENCE.md).
