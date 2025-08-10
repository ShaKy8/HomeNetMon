# Multi-stage Docker build for HomeNetMon

# Build stage
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    python3-dev \
    libpcap-dev \
    nmap \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    iputils-ping \
    net-tools \
    arp-scan \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd -r homeNetMon && useradd -r -g homeNetMon homeNetMon

# Set working directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application files
COPY . .

# Create data directory for SQLite database
RUN mkdir -p /app/data && chown -R homeNetMon:homeNetMon /app/data

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DATABASE_URL=sqlite:///app/data/homeNetMon.db
ENV HOST=0.0.0.0
ENV PORT=5000

# Create health check script
RUN echo '#!/bin/bash\ncurl -f http://localhost:5000/health || exit 1' > /app/healthcheck.sh && \
    chmod +x /app/healthcheck.sh

# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Set proper permissions
RUN chown -R homeNetMon:homeNetMon /app

# Switch to non-root user
USER homeNetMon

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD /app/healthcheck.sh

# Default command
CMD ["python", "app.py"]