#!/bin/bash
# SSL/TLS Setup for HomeNetMon
# This script helps set up SSL certificates using Let's Encrypt

set -e

echo "🔒 SSL/TLS Setup for HomeNetMon"
echo "==============================="

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain-name>"
    echo "Example: $0 homenetmon.yourdomain.com"
    exit 1
fi

DOMAIN=$1
EMAIL=${2:-admin@${DOMAIN}}

# Install certbot
apt-get update
apt-get install -y certbot python3-certbot-nginx

# Get certificate
certbot --nginx -d $DOMAIN --email $EMAIL --agree-tos --non-interactive

# Setup auto-renewal
systemctl enable certbot.timer
systemctl start certbot.timer

echo "✅ SSL certificate installed for $DOMAIN"
echo "Auto-renewal is configured"
echo "Check renewal status: certbot renew --dry-run"
