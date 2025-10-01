#!/bin/bash
# Generate DH parameters for perfect forward secrecy

echo "🔐 Generating DH parameters for SSL/TLS security"
echo "This may take several minutes..."

openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

echo "✅ DH parameters generated successfully"
