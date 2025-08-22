#!/bin/bash
# Cloud-native startup script for HomeNetMon

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Environment setup
export PYTHONPATH=/app:$PYTHONPATH
export PATH=/root/.local/bin:$PATH

log "Starting HomeNetMon Cloud-Native Application"

# Check required environment variables
required_vars=(
    "FLASK_ENV"
    "DATABASE_URL"
    "REDIS_URL"
)

for var in "${required_vars[@]}"; do
    if [[ -z "${!var}" ]]; then
        warn "Environment variable $var is not set"
    fi
done

# Set default values
export FLASK_ENV=${FLASK_ENV:-production}
export DEBUG=${DEBUG:-false}
export LOG_LEVEL=${LOG_LEVEL:-INFO}
export WORKER_PROCESSES=${WORKER_PROCESSES:-4}
export WORKER_CONNECTIONS=${WORKER_CONNECTIONS:-1000}
export MAX_REQUESTS=${MAX_REQUESTS:-1000}
export MAX_REQUESTS_JITTER=${MAX_REQUESTS_JITTER:-100}
export BIND_ADDRESS=${BIND_ADDRESS:-0.0.0.0:5000}

# Cloud-specific configuration
export OTEL_SERVICE_NAME=${OTEL_SERVICE_NAME:-homenetmon}
export OTEL_SERVICE_VERSION=${OTEL_SERVICE_VERSION:-1.0.0}
export OTEL_RESOURCE_ATTRIBUTES=${OTEL_RESOURCE_ATTRIBUTES:-"service.name=homenetmon,service.version=1.0.0"}

# Kubernetes-specific environment
if [[ -n "$KUBERNETES_SERVICE_HOST" ]]; then
    log "Running in Kubernetes cluster"
    export ENVIRONMENT=kubernetes
    export POD_NAME=${POD_NAME:-unknown}
    export POD_NAMESPACE=${POD_NAMESPACE:-default}
    export NODE_NAME=${NODE_NAME:-unknown}
    
    # Add Kubernetes metadata to OpenTelemetry
    export OTEL_RESOURCE_ATTRIBUTES="${OTEL_RESOURCE_ATTRIBUTES},k8s.pod.name=${POD_NAME},k8s.namespace.name=${POD_NAMESPACE},k8s.node.name=${NODE_NAME}"
fi

# Wait for dependencies
wait_for_service() {
    local host=$1
    local port=$2
    local service_name=$3
    local max_attempts=30
    local attempt=1
    
    log "Waiting for $service_name at $host:$port..."
    
    while ! nc -z "$host" "$port" 2>/dev/null; do
        if [[ $attempt -ge $max_attempts ]]; then
            error "Failed to connect to $service_name after $max_attempts attempts"
            return 1
        fi
        
        log "Attempt $attempt/$max_attempts: Waiting for $service_name..."
        sleep 2
        ((attempt++))
    done
    
    log "$service_name is available"
    return 0
}

# Parse and wait for dependencies
if [[ -n "$REDIS_URL" ]]; then
    redis_host=$(echo "$REDIS_URL" | sed -n 's|.*://[^@]*@\?\([^:]*\):.*|\1|p')
    redis_port=$(echo "$REDIS_URL" | sed -n 's|.*://[^@]*@\?[^:]*:\([0-9]*\).*|\1|p')
    
    if [[ -n "$redis_host" && -n "$redis_port" ]]; then
        wait_for_service "$redis_host" "$redis_port" "Redis"
    fi
fi

if [[ -n "$DATABASE_URL" && "$DATABASE_URL" != *"sqlite"* ]]; then
    db_host=$(echo "$DATABASE_URL" | sed -n 's|.*://[^@]*@\?\([^:]*\):.*|\1|p')
    db_port=$(echo "$DATABASE_URL" | sed -n 's|.*://[^@]*@\?[^:]*:\([0-9]*\).*|\1|p')
    
    if [[ -n "$db_host" && -n "$db_port" ]]; then
        wait_for_service "$db_host" "$db_port" "Database"
    fi
fi

# Initialize application
log "Initializing application..."

# Database migrations
if [[ "$FLASK_ENV" != "development" ]]; then
    log "Running database migrations..."
    python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('Database initialized successfully')
" || {
        error "Database initialization failed"
        exit 1
    }
fi

# Set up OpenTelemetry instrumentation
if [[ "$ENABLE_TRACING" == "true" ]]; then
    log "Enabling OpenTelemetry instrumentation..."
    export OTEL_PYTHON_LOGGING_AUTO_INSTRUMENTATION_ENABLED=true
    
    # Auto-instrument the application
    opentelemetry-bootstrap --action=install 2>/dev/null || true
fi

# Set up Prometheus metrics
if [[ "$ENABLE_METRICS" == "true" ]]; then
    log "Enabling Prometheus metrics..."
    mkdir -p "$PROMETHEUS_MULTIPROC_DIR"
fi

# Health check function
health_check() {
    curl -f -s "http://localhost:$(echo "$BIND_ADDRESS" | cut -d: -f2)/health" > /dev/null
}

# Pre-flight checks
log "Running pre-flight checks..."

# Check disk space
available_space=$(df /app | tail -1 | awk '{print $4}')
if [[ $available_space -lt 1048576 ]]; then # Less than 1GB
    warn "Low disk space: ${available_space}KB available"
fi

# Check memory
available_memory=$(free -m | awk 'NR==2{print $7}')
if [[ $available_memory -lt 512 ]]; then # Less than 512MB
    warn "Low memory: ${available_memory}MB available"
fi

# Check network connectivity
if ! ping -c 1 8.8.8.8 &> /dev/null; then
    warn "No external network connectivity detected"
fi

log "Pre-flight checks completed"

# Signal handlers for graceful shutdown
shutdown_handler() {
    log "Received shutdown signal, gracefully stopping..."
    
    # Stop background processes
    if [[ -n "$MONITOR_PID" ]]; then
        kill -TERM "$MONITOR_PID" 2>/dev/null || true
    fi
    
    # Stop main application
    if [[ -n "$APP_PID" ]]; then
        kill -TERM "$APP_PID" 2>/dev/null || true
        wait "$APP_PID"
    fi
    
    log "Application stopped gracefully"
    exit 0
}

trap shutdown_handler SIGTERM SIGINT

# Start background monitoring (if enabled)
if [[ "$ENABLE_BACKGROUND_MONITORING" == "true" ]]; then
    log "Starting background monitoring..."
    python -m monitoring.monitor &
    MONITOR_PID=$!
fi

# Start the application
log "Starting HomeNetMon application..."
log "Environment: $FLASK_ENV"
log "Debug mode: $DEBUG"
log "Workers: $WORKER_PROCESSES"
log "Bind address: $BIND_ADDRESS"

if [[ "$FLASK_ENV" == "development" ]]; then
    # Development mode
    log "Starting in development mode with Flask dev server"
    exec python -m flask run --host=0.0.0.0 --port=$(echo "$BIND_ADDRESS" | cut -d: -f2)
else
    # Production mode with Gunicorn
    log "Starting in production mode with Gunicorn"
    
    # Build Gunicorn command
    gunicorn_cmd=(
        "gunicorn"
        "--bind" "$BIND_ADDRESS"
        "--workers" "$WORKER_PROCESSES"
        "--worker-class" "gevent"
        "--worker-connections" "$WORKER_CONNECTIONS"
        "--max-requests" "$MAX_REQUESTS"
        "--max-requests-jitter" "$MAX_REQUESTS_JITTER"
        "--timeout" "30"
        "--keepalive" "5"
        "--preload"
        "--access-logfile" "-"
        "--error-logfile" "-"
        "--log-level" "$(echo "$LOG_LEVEL" | tr '[:upper:]' '[:lower:]')"
        "--capture-output"
        "--enable-stdio-inheritance"
    )
    
    # Add graceful timeout
    gunicorn_cmd+=("--graceful-timeout" "30")
    
    # Add worker management
    gunicorn_cmd+=("--worker-tmp-dir" "/dev/shm")
    
    # Production optimizations
    if [[ "$FLASK_ENV" == "production" ]]; then
        gunicorn_cmd+=("--max-requests-jitter" "100")
        gunicorn_cmd+=("--worker-class" "gevent")
    fi
    
    # OpenTelemetry instrumentation
    if [[ "$ENABLE_TRACING" == "true" ]]; then
        gunicorn_cmd=("opentelemetry-instrument" "${gunicorn_cmd[@]}")
    fi
    
    # Add the application module
    gunicorn_cmd+=("app:app")
    
    log "Starting with command: ${gunicorn_cmd[*]}"
    
    # Start Gunicorn
    exec "${gunicorn_cmd[@]}" &
    APP_PID=$!
    
    # Wait for application to start
    sleep 5
    
    # Verify application is healthy
    if health_check; then
        log "Application started successfully and is healthy"
    else
        error "Application failed health check"
        exit 1
    fi
    
    # Keep the script running
    wait "$APP_PID"
fi