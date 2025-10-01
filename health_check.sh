#!/bin/bash
# Health check script for HomeNetMon
# Can be used with external monitoring systems

APP_URL="http://localhost"
SERVICE_NAME="homenetmon"

# Check HTTP response
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" $APP_URL/health || echo "000")

# Check service status
SERVICE_STATUS=$(systemctl is-active $SERVICE_NAME)

# Check database
DB_CHECK=$(systemctl --user is-active $SERVICE_NAME && echo "OK" || echo "FAIL")

if [ "$HTTP_STATUS" == "200" ] && [ "$SERVICE_STATUS" == "active" ]; then
    echo "OK - HomeNetMon is healthy"
    exit 0
else
    echo "CRITICAL - HomeNetMon is unhealthy"
    echo "HTTP Status: $HTTP_STATUS"
    echo "Service Status: $SERVICE_STATUS"
    exit 2
fi
