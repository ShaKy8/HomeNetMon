#!/bin/bash
# External health check for HomeNetMon (exit 0 = healthy, 2 = unhealthy).
# Usage: ./health_check.sh [base_url]   default http://127.0.0.1:5000
APP_URL="${1:-http://127.0.0.1:5000}"
SERVICE_NAME="homenetmon"

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$APP_URL/api/system/health" || echo "000")

# The service may be a user unit or a system unit.
if systemctl --user is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    SERVICE_STATUS="active (user)"
elif systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    SERVICE_STATUS="active (system)"
else
    SERVICE_STATUS="inactive"
fi

# /api/system/health returns 200 when every background thread is heartbeating, 503 otherwise.
if [ "$HTTP_STATUS" == "200" ]; then
    echo "OK - HomeNetMon is healthy ($SERVICE_STATUS)"
    exit 0
fi
echo "CRITICAL - HomeNetMon is unhealthy"
echo "HTTP Status: $HTTP_STATUS ($APP_URL/api/system/health)"
echo "Service Status: $SERVICE_STATUS"
exit 2
