# HomeNetMon Production Deployment Guide

This guide covers deploying HomeNetMon in a production environment.

## Quick Start

### Option 1: Docker Deployment (Recommended)

1. **Prepare environment:**
   ```bash
   cp .env.prod.template .env.prod
   # Edit .env.prod with your configuration
   ```

2. **Deploy with Docker:**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

3. **Access application:**
   - HTTP: http://your-server
   - HTTPS: https://your-server (after SSL setup)

### Option 2: Native Deployment

1. **Run deployment script:**
   ```bash
   sudo ./deploy.sh
   ```

2. **Configure environment:**
   ```bash
   sudo cp .env.prod.template /opt/homenetmon/.env
   sudo nano /opt/homenetmon/.env
   ```

3. **Restart service:**
   ```bash
   sudo systemctl restart homenetmon
   ```

## SSL/TLS Setup

Enable HTTPS with Let's Encrypt:

```bash
sudo ./setup_ssl.sh your-domain.com your-email@domain.com
```

## Configuration

### Environment Variables

Key production settings in `.env.prod`:

- `SECRET_KEY`: Strong secret key for sessions
- `ADMIN_PASSWORD`: Admin login password
- `NETWORK_RANGE`: Your network CIDR (e.g., 192.168.1.0/24)
- `SMTP_*`: Email configuration for alerts
- `REDIS_URL`: Redis connection for caching

### Security Settings

- Change default admin password
- Configure firewall (ports 80, 443)
- Enable HTTPS in production
- Set strong SECRET_KEY
- Configure SMTP for alerts

## Monitoring

### Health Checks

```bash
./health_check.sh
curl http://localhost/health
```

### Service Management

```bash
# Check status
systemctl status homenetmon

# View logs
journalctl -u homenetmon -f

# Restart service
systemctl restart homenetmon
```

### Database Backups

Backups run automatically via cron. Manual backup:

```bash
python3 backup_production.py
```

## Updates

Update to latest version:

```bash
sudo ./update.sh
```

## Performance Tuning

### Database Optimization

- Automatic cleanup runs daily
- WAL mode enabled for performance
- Indexes optimized for queries

### Nginx Configuration

- Gzip compression enabled
- Static file caching
- Rate limiting configured
- Security headers applied

### Application Settings

- Redis caching enabled
- Connection pooling
- Performance monitoring
- Resource optimization

## Troubleshooting

### Common Issues

1. **Service won't start:**
   ```bash
   journalctl -u homenetmon --no-pager -l
   ```

2. **Network scanning issues:**
   - Check nmap installation
   - Verify network permissions
   - Review NETWORK_RANGE setting

3. **Database problems:**
   ```bash
   sqlite3 /opt/homenetmon/data/homeNetMon.db ".schema"
   ```

4. **Performance issues:**
   ```bash
   python3 optimize_database_performance.py
   ```

### Log Locations

- Application: `/opt/homenetmon/logs/`
- Nginx: `/var/log/nginx/`
- System: `journalctl -u homenetmon`

## Security Checklist

- [ ] Strong admin password set
- [ ] HTTPS enabled with valid certificate
- [ ] Firewall configured (UFW/iptables)
- [ ] Regular security updates
- [ ] Database backups verified
- [ ] Rate limiting enabled
- [ ] Security headers configured
- [ ] Non-root user running application

## Scaling

For high-traffic deployments:

1. **Database:** Consider PostgreSQL migration
2. **Caching:** Redis cluster setup
3. **Load Balancing:** Multiple app instances
4. **Monitoring:** External monitoring tools

## Support

- Configuration issues: Check logs and environment
- Performance problems: Run optimization scripts
- Security concerns: Review security checklist
- Updates: Use provided update script

## Architecture

```
Internet → Nginx → HomeNetMon App → SQLite/Redis
                ↓
         Static Files, WebSockets
```

Production deployment provides:
- High availability
- Security hardening
- Performance optimization
- Automated backups
- Monitoring capabilities
