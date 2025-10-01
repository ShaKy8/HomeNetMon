# HomeNetMon Quick Start Guide

## 5-Minute Deployment

### Prerequisites
- Ubuntu/Debian server with 2GB+ RAM
- Domain name (optional, for SSL)
- Network access to monitor

### Docker Deployment (Recommended)

1. **Clone and Configure**
   ```bash
   git clone https://github.com/your-org/homenetmon.git
   cd homenetmon
   cp .env.prod.template .env.prod
   ```

2. **Set Required Variables**
   ```bash
   # Edit .env.prod
   SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
   ADMIN_PASSWORD=your-secure-password-here
   NETWORK_RANGE=192.168.1.0/24  # Your network
   ```

3. **Deploy**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

4. **Access Application**
   - Open: http://your-server-ip
   - Login with admin password
   - Begin monitoring your network

### Native Deployment

1. **One-Command Deployment**
   ```bash
   sudo ./deploy.sh
   ```

2. **Configure**
   ```bash
   sudo cp .env.prod.template /opt/homenetmon/.env
   sudo nano /opt/homenetmon/.env  # Set your configuration
   sudo systemctl restart homenetmon
   ```

### SSL Setup (Optional)

```bash
sudo ./setup_ssl.sh your-domain.com
```

### Security Setup (Recommended)

```bash
sudo ./security/configure-firewall.sh
```

## Verification

```bash
# Check service status
curl http://localhost/health

# Access web interface
open http://your-server-ip
```

## Next Steps

1. Review the [Full Deployment Guide](DEPLOYMENT_GUIDE.md)
2. Configure [Security Settings](../SECURITY_GUIDE.md)
3. Set up [Monitoring and Alerts](OPERATIONS_GUIDE.md)
4. Read the [User Guide](USER_GUIDE.md)

## Troubleshooting

**Service won't start:**
```bash
journalctl -u homenetmon -f
```

**Network scanning issues:**
```bash
sudo apt install nmap
```

**Need help?** Check the [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md)
