#!/bin/bash
# Production Health Check for HomeNetMon

echo "🏥 HomeNetMon Production Health Check"
echo "====================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_pass() {
    echo -e "${GREEN}✅${NC} $1"
}

check_fail() {
    echo -e "${RED}❌${NC} $1"
}

check_warn() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

# Check if service is running
echo -e "\n📊 Service Status:"
if pgrep -f "python.*app.py" > /dev/null; then
    check_pass "HomeNetMon service is running"
    PID=$(pgrep -f "python.*app.py" | head -1)
    echo "   PID: $PID"
else
    check_fail "HomeNetMon service is not running"
fi

# Check port availability
echo -e "\n🌐 Network Status:"
if netstat -tlnp 2>/dev/null | grep -q ":5000"; then
    check_pass "Application listening on port 5000"
else
    check_fail "Port 5000 not active"
fi

# Check homepage response
echo -e "\n🏠 Application Response:"
HTTP_CODE=$(wget --spider -S "http://localhost:5000/" 2>&1 | grep "HTTP/" | awk '{print $2}' | tail -1)
if [ "$HTTP_CODE" = "200" ]; then
    check_pass "Homepage responding (HTTP $HTTP_CODE)"
else
    check_warn "Homepage status: HTTP $HTTP_CODE"
fi

# Check database
echo -e "\n💾 Database Status:"
if [ -f "production_data/homeNetMon.db" ]; then
    check_pass "Production database exists"
    DB_SIZE=$(du -h production_data/homeNetMon.db | awk '{print $1}')
    echo "   Size: $DB_SIZE"
else
    check_warn "Production database not found"
fi

# Check logs
echo -e "\n📝 Logging Status:"
if [ -d "logs" ]; then
    check_pass "Log directory exists"
    LOG_COUNT=$(ls -1 logs/*.log 2>/dev/null | wc -l)
    echo "   Log files: $LOG_COUNT"
else
    check_warn "Log directory not found"
fi

# Check memory usage
echo -e "\n💻 Resource Usage:"
if [ -n "$PID" ]; then
    MEM_USAGE=$(ps -o %mem= -p $PID | tr -d ' ')
    CPU_USAGE=$(ps -o %cpu= -p $PID | tr -d ' ')
    echo "   Memory: ${MEM_USAGE}%"
    echo "   CPU: ${CPU_USAGE}%"
fi

# Check critical endpoints
echo -e "\n🔌 API Endpoints:"
ENDPOINTS=("/api/devices" "/api/monitoring/summary" "/api/alerts/summary")
for endpoint in "${ENDPOINTS[@]}"; do
    if wget -q --spider "http://localhost:5000$endpoint"; then
        check_pass "$endpoint - Available"
    else
        check_warn "$endpoint - Not responding"
    fi
done

# Check environment
echo -e "\n⚙️ Environment:"
if [ -f ".env" ]; then
    check_pass "Production environment configured"
    FLASK_ENV=$(grep "FLASK_ENV" .env | cut -d'=' -f2)
    echo "   Mode: $FLASK_ENV"
else
    check_warn "Environment file not found"
fi

# Network monitoring status
echo -e "\n🔍 Network Monitoring:"
NETWORK_RANGE=$(grep "NETWORK_RANGE" .env 2>/dev/null | cut -d'=' -f2)
if [ -n "$NETWORK_RANGE" ]; then
    check_pass "Network range configured: $NETWORK_RANGE"
else
    check_warn "Network range not configured"
fi

echo -e "\n✨ Health check complete!"
echo "====================================="
echo "🌐 Access HomeNetMon at: http://localhost:5000"
echo "🔐 Admin credentials are in .env.prod file"