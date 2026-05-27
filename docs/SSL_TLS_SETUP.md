# 🔒 SSL/TLS Configuration Guide for HomeNetMon

This guide provides comprehensive instructions for setting up SSL/TLS encryption for HomeNetMon in production environments. SSL/TLS is **essential** for production deployments to protect data in transit.

## Table of Contents

1. [Why SSL/TLS is Critical](#why-ssltls-is-critical)
2. [Certificate Options](#certificate-options)
3. [Nginx Reverse Proxy Setup](#nginx-reverse-proxy-setup)
4. [Apache Reverse Proxy Setup](#apache-reverse-proxy-setup)
5. [Direct Flask SSL Setup](#direct-flask-ssl-setup)
6. [Let's Encrypt Automation](#lets-encrypt-automation)
7. [Docker with SSL](#docker-with-ssl)
8. [SSL Testing and Validation](#ssl-testing-and-validation)
9. [Troubleshooting](#troubleshooting)

## Why SSL/TLS is Critical

Without SSL/TLS, HomeNetMon transmits:
- ❌ **Login credentials in plain text**
- ❌ **Session cookies unencrypted**
- ❌ **Network monitoring data unprotected**
- ❌ **API calls without encryption**
- ❌ **Real-time WebSocket data exposed**

With SSL/TLS enabled:
- ✅ **All data encrypted in transit**
- ✅ **Authentication credentials protected**
- ✅ **Session hijacking prevention**
- ✅ **Man-in-the-middle attack protection**
- ✅ **Browser security warnings eliminated**

## Certificate Options

### 1. Let's Encrypt (Free, Recommended)
```bash
# Automatic, free, and trusted certificates
# Valid for 90 days with auto-renewal
# Supported by all major browsers
```

### 2. Commercial Certificate Authority
```bash
# Paid certificates from providers like:
# - DigiCert, Comodo, GlobalSign
# - Extended validation options available
# - Longer validity periods (1-2 years)
```

### 3. Self-Signed Certificate (Development Only)
```bash
# Free but not trusted by browsers
# Causes security warnings
# Only suitable for development/testing
```

## Nginx Reverse Proxy Setup (Recommended)

### Step 1: Install Nginx

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nginx

# CentOS/RHEL
sudo yum install nginx
# or
sudo dnf install nginx

# Start and enable Nginx
sudo systemctl start nginx
sudo systemctl enable nginx
```

### Step 2: Install Certbot (Let's Encrypt)

```bash
# Ubuntu/Debian
sudo apt install certbot python3-certbot-nginx

# CentOS/RHEL
sudo yum install certbot python3-certbot-nginx
# or
sudo dnf install certbot python3-certbot-nginx
```

### Step 3: Obtain SSL Certificate

```bash
# Replace your-domain.com with your actual domain
sudo certbot --nginx -d your-domain.com

# For multiple domains/subdomains
sudo certbot --nginx -d your-domain.com -d homeNetMon.your-domain.com
```

### Step 4: Configure Nginx

Create `/etc/nginx/sites-available/homeNetMon`:

```nginx
# HomeNetMon Nginx Configuration with SSL
server {
    listen 80;
    server_name your-domain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    
    # Modern SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    
    # HSTS (HTTP Strict Transport Security)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    # CSP Header (adjust as needed for your setup)
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; font-src 'self'";
    
    # Gzip Compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    
    # Client body size (for file uploads)
    client_max_body_size 16M;
    
    # Proxy to HomeNetMon application
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Static file serving (optional optimization)
    location /static/ {
        alias /path/to/homeNetMon/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Health check endpoint (no authentication needed)
    location /health {
        proxy_pass http://127.0.0.1:5000/health;
        access_log off;
    }
    
    # Rate limiting for API endpoints
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://127.0.0.1:5000;
        # ... other proxy headers ...
    }
}

# Rate limiting configuration
http {
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
}
```

### Step 5: Enable Site and Restart Nginx

```bash
# Enable the site
sudo ln -s /etc/nginx/sites-available/homeNetMon /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

### Step 6: Set Up Auto-Renewal

```bash
# Test renewal process
sudo certbot renew --dry-run

# Set up automatic renewal (usually done automatically by certbot)
sudo crontab -e

# Add this line if not already present:
0 12 * * * /usr/bin/certbot renew --quiet
```

## Apache Reverse Proxy Setup

### Step 1: Install Apache and SSL Module

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install apache2
sudo a2enmod ssl
sudo a2enmod proxy
sudo a2enmod proxy_http
sudo a2enmod proxy_wstunnel

# CentOS/RHEL
sudo yum install httpd mod_ssl
```

### Step 2: Configure Apache Virtual Host

Create `/etc/apache2/sites-available/homeNetMon-ssl.conf`:

```apache
# HTTP to HTTPS Redirect
<VirtualHost *:80>
    ServerName your-domain.com
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
</VirtualHost>

# HTTPS Configuration
<VirtualHost *:443>
    ServerName your-domain.com
    
    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/your-domain.com/cert.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/your-domain.com/privkey.pem
    SSLCertificateChainFile /etc/letsencrypt/live/your-domain.com/chain.pem
    
    # Modern SSL Configuration
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder off
    
    # Security Headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    
    # Proxy Configuration
    ProxyPreserveHost On
    ProxyPass /ws/ ws://127.0.0.1:5000/ws/
    ProxyPassReverse /ws/ ws://127.0.0.1:5000/ws/
    ProxyPass / http://127.0.0.1:5000/
    ProxyPassReverse / http://127.0.0.1:5000/
    
    # Set headers for the backend
    ProxyPassReverse / http://127.0.0.1:5000/
    ProxyPassReverseMatch ^/(.*) http://127.0.0.1:5000/$1
    
    # Logging
    ErrorLog ${APACHE_LOG_DIR}/homeNetMon_error.log
    CustomLog ${APACHE_LOG_DIR}/homeNetMon_access.log combined
</VirtualHost>
```

### Step 3: Enable Site and Restart Apache

```bash
# Enable the site
sudo a2ensite homeNetMon-ssl
sudo a2enmod rewrite

# Test configuration
sudo apache2ctl configtest

# Restart Apache
sudo systemctl restart apache2
```

## Direct Flask SSL Setup

For smaller deployments, you can enable SSL directly in Flask:

### Step 1: Generate or Obtain Certificates

```bash
# For Let's Encrypt certificates, use certbot standalone
sudo certbot certonly --standalone -d your-domain.com

# Or generate self-signed certificates (development only)
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

### Step 2: Modify HomeNetMon Configuration

Create `ssl_config.py`:

```python
import os
from config import Config

class SSLConfig(Config):
    # SSL Configuration
    SSL_CERT = os.environ.get('SSL_CERT', '/etc/letsencrypt/live/your-domain.com/fullchain.pem')
    SSL_KEY = os.environ.get('SSL_KEY', '/etc/letsencrypt/live/your-domain.com/privkey.pem')
    SSL_ENABLED = os.environ.get('SSL_ENABLED', 'true').lower() == 'true'
    
    # Force HTTPS
    PREFERRED_URL_SCHEME = 'https'
    
    # Secure session cookies
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # CSRF protection
    WTF_CSRF_SSL_STRICT = True
```

### Step 3: Update app.py

```python
from ssl_config import SSLConfig

def create_app():
    app = Flask(__name__)
    app.config.from_object(SSLConfig)
    
    # ... existing configuration ...
    
    return app

if __name__ == '__main__':
    app = create_app()
    
    if app.config.get('SSL_ENABLED'):
        context = (
            app.config['SSL_CERT'],
            app.config['SSL_KEY']
        )
        app.run(
            host=app.config.get('HOST', '0.0.0.0'),
            port=app.config.get('PORT', 443),
            ssl_context=context,
            debug=False
        )
    else:
        app.run(
            host=app.config.get('HOST', '0.0.0.0'),
            port=app.config.get('PORT', 5000),
            debug=False
        )
```

## Let's Encrypt Automation

### Automated Setup Script

Create `setup_ssl.sh`:

```bash
#!/bin/bash
# Automated SSL/TLS setup for HomeNetMon

set -e

DOMAIN=""
EMAIL=""
WEBSERVER="nginx"  # or "apache"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -e|--email)
            EMAIL="$2"
            shift 2
            ;;
        -w|--webserver)
            WEBSERVER="$2"
            shift 2
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
done

if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
    echo "Usage: $0 -d your-domain.com -e your-email@example.com [-w nginx|apache]"
    exit 1
fi

echo "🔒 Setting up SSL/TLS for HomeNetMon"
echo "Domain: $DOMAIN"
echo "Email: $EMAIL"
echo "Webserver: $WEBSERVER"

# Install certbot
if ! command -v certbot &> /dev/null; then
    echo "Installing certbot..."
    if [ -f /etc/debian_version ]; then
        sudo apt update
        sudo apt install -y certbot python3-certbot-$WEBSERVER
    elif [ -f /etc/redhat-release ]; then
        sudo yum install -y certbot python3-certbot-$WEBSERVER
    else
        echo "Unsupported OS. Please install certbot manually."
        exit 1
    fi
fi

# Obtain SSL certificate
echo "Obtaining SSL certificate..."
sudo certbot --$WEBSERVER -d $DOMAIN --email $EMAIL --agree-tos --non-interactive

# Configure auto-renewal
echo "Setting up auto-renewal..."
echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -

# Test renewal
echo "Testing renewal..."
sudo certbot renew --dry-run

echo "✅ SSL/TLS setup completed!"
echo "Your HomeNetMon instance should now be accessible at https://$DOMAIN"
```

Make it executable:

```bash
chmod +x setup_ssl.sh

# Run the setup
./setup_ssl.sh -d your-domain.com -e your-email@example.com -w nginx
```

## Docker with SSL

### Docker Compose with Nginx and SSL

Create `docker-compose.ssl.yml`:

```yaml
version: '3.8'

services:
  homeNetMon:
    build: .
    restart: unless-stopped
    environment:
      - HOST=0.0.0.0
      - PORT=5000
      - PREFERRED_URL_SCHEME=https
    volumes:
      - ./homeNetMon.db:/app/homeNetMon.db
    networks:
      - homeNetMon_network

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
    depends_on:
      - homeNetMon
    networks:
      - homeNetMon_network

  certbot:
    image: certbot/certbot:latest
    volumes:
      - /etc/letsencrypt:/etc/letsencrypt
      - /var/www/certbot:/var/www/certbot
    command: certonly --webroot --webroot-path=/var/www/certbot --email your-email@example.com --agree-tos --no-eff-email -d your-domain.com

networks:
  homeNetMon_network:
    driver: bridge
```

### Nginx Configuration for Docker

Create `nginx.conf`:

```nginx
events {
    worker_connections 1024;
}

http {
    upstream homeNetMon {
        server homeNetMon:5000;
    }

    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name your-domain.com;
        
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }
        
        location / {
            return 301 https://$host$request_uri;
        }
    }

    # HTTPS Configuration
    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
        ssl_prefer_server_ciphers off;

        location / {
            proxy_pass http://homeNetMon;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # WebSocket support
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
```

## SSL Testing and Validation

### 1. SSL Labs Test

```bash
# Test your SSL configuration
curl -s "https://api.ssllabs.com/api/v3/analyze?host=your-domain.com&publish=off&startNew=on&all=done&ignoreMismatch=on"
```

### 2. Certificate Information

```bash
# Check certificate details
openssl s_client -connect your-domain.com:443 -servername your-domain.com 2>/dev/null | openssl x509 -noout -text

# Check certificate expiration
echo | openssl s_client -servername your-domain.com -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -dates
```

### 3. Security Headers Test

```bash
# Check security headers
curl -I https://your-domain.com

# Test with security headers analyzer
curl -s https://securityheaders.com/?q=your-domain.com\&followRedirects=on
```

### 4. WebSocket SSL Test

```javascript
// Test WebSocket over SSL
const ws = new WebSocket('wss://your-domain.com/socket.io/?transport=websocket');
ws.onopen = () => console.log('WebSocket SSL connection successful');
ws.onerror = (error) => console.error('WebSocket SSL error:', error);
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Certificate Chain Issues

```bash
# Check certificate chain
openssl verify -verbose -CAfile /etc/ssl/certs/ca-certificates.crt /etc/letsencrypt/live/your-domain.com/fullchain.pem

# Fix incomplete certificate chain
# Ensure you're using fullchain.pem, not cert.pem
```

#### 2. Nginx/Apache Not Starting

```bash
# Check configuration syntax
sudo nginx -t
sudo apache2ctl configtest

# Check logs
sudo journalctl -u nginx -f
sudo journalctl -u apache2 -f
```

#### 3. Certificate Renewal Fails

```bash
# Check certbot logs
sudo journalctl -u certbot -f

# Manual renewal test
sudo certbot renew --dry-run --verbose

# Force renewal
sudo certbot renew --force-renewal
```

#### 4. Mixed Content Warnings

```python
# Ensure Flask is configured for HTTPS
app.config['PREFERRED_URL_SCHEME'] = 'https'

# Update all internal URLs to use HTTPS
# Check for hardcoded HTTP URLs in templates and JavaScript
```

#### 5. WebSocket Connection Issues

```nginx
# Ensure proper WebSocket proxy configuration
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_set_header Host $host;
```

### Debugging Commands

```bash
# Test SSL connection
openssl s_client -connect your-domain.com:443 -servername your-domain.com

# Check certificate validity
curl -vvI https://your-domain.com 2>&1 | grep -A 10 -B 10 certificate

# Test specific cipher
openssl s_client -connect your-domain.com:443 -cipher 'ECDHE-RSA-AES128-GCM-SHA256'

# Check SSL configuration
nmap --script ssl-enum-ciphers -p 443 your-domain.com
```

## Security Best Practices

### 1. Certificate Management
- ✅ Use Let's Encrypt for free, trusted certificates
- ✅ Set up automated renewal (certbot cron job)
- ✅ Monitor certificate expiration dates
- ✅ Use fullchain.pem (includes intermediate certificates)

### 2. SSL/TLS Configuration
- ✅ Disable old protocols (SSLv3, TLSv1.0, TLSv1.1)
- ✅ Use strong cipher suites
- ✅ Enable Perfect Forward Secrecy
- ✅ Implement HSTS (HTTP Strict Transport Security)

### 3. Security Headers
- ✅ Set Content-Security-Policy
- ✅ Enable X-Frame-Options: DENY
- ✅ Set X-Content-Type-Options: nosniff
- ✅ Configure Referrer-Policy

### 4. Monitoring and Maintenance
- ✅ Regular SSL Labs scans
- ✅ Monitor certificate expiration
- ✅ Test renewal process monthly
- ✅ Keep web server and SSL libraries updated

## Quick Setup Checklist

- [ ] Domain pointing to your server
- [ ] Firewall configured (ports 80, 443 open)
- [ ] Web server installed (Nginx/Apache)
- [ ] Certbot installed
- [ ] SSL certificate obtained
- [ ] Web server configured with SSL
- [ ] HTTP to HTTPS redirect enabled
- [ ] Security headers configured
- [ ] Auto-renewal set up
- [ ] SSL configuration tested
- [ ] WebSocket over SSL tested
- [ ] Certificate monitoring configured

## Support Resources

- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [Security Headers](https://securityheaders.com/)
- [HSTS Preload List](https://hstspreload.org/)

---

🔒 **Remember**: SSL/TLS is not optional for production deployments. It's a fundamental security requirement that protects your users' data and maintains trust in your monitoring system.