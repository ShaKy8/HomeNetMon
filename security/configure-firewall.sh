#!/bin/bash
# UFW Firewall Configuration for HomeNetMon Production

echo "🔥 Configuring UFW Firewall for HomeNetMon"

# Reset UFW to defaults
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (adjust port if non-standard)
ufw allow ssh
ufw allow 22

# Allow HTTP and HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Allow local network access for network monitoring
# Adjusted for current network range
ufw allow from 192.168.86.0/24 to any port 80
ufw allow from 192.168.86.0/24 to any port 443

# Rate limiting for SSH
ufw limit ssh

# Enable logging
ufw logging on

# Enable firewall
ufw --force enable

echo "✅ UFW Firewall configured successfully"
echo "📊 UFW Status:"
ufw status verbose
