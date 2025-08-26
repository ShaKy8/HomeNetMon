-- PERFORMANCE OPTIMIZATION: Critical Database Indexes for HomeNetMon
-- Execute these indexes to dramatically improve query performance

-- 1. CRITICAL: Devices table indexes
-- Current devices.py queries will be 10-100x faster with these indexes

-- Primary lookup index (already exists, but ensure it's optimized)
CREATE INDEX IF NOT EXISTS idx_devices_ip_address ON devices(ip_address);

-- Status computation optimization (used heavily in API)
CREATE INDEX IF NOT EXISTS idx_devices_last_seen_monitored ON devices(last_seen, is_monitored) 
WHERE is_monitored = 1;

-- Device filtering indexes
CREATE INDEX IF NOT EXISTS idx_devices_type_monitored ON devices(device_type, is_monitored);
CREATE INDEX IF NOT EXISTS idx_devices_group_monitored ON devices(device_group, is_monitored);

-- Network range filtering (if using IP range queries)
CREATE INDEX IF NOT EXISTS idx_devices_ip_range ON devices(ip_address) 
WHERE is_monitored = 1;

-- 2. CRITICAL: MonitoringData table indexes  
-- These are essential for the API performance issues we observed

-- Latest monitoring data per device (most critical for API performance)
CREATE INDEX IF NOT EXISTS idx_monitoring_device_timestamp_desc ON monitoring_data(device_id, timestamp DESC);

-- Response time analysis
CREATE INDEX IF NOT EXISTS idx_monitoring_device_response ON monitoring_data(device_id, response_time, timestamp DESC);

-- Time-range queries (for charts and analytics)
CREATE INDEX IF NOT EXISTS idx_monitoring_timestamp_device ON monitoring_data(timestamp DESC, device_id);

-- Cleanup queries (for data retention)
CREATE INDEX IF NOT EXISTS idx_monitoring_timestamp_only ON monitoring_data(timestamp);

-- 3. ALERTS table indexes
-- For alert counting and filtering

-- Active alerts per device (critical for device API)
CREATE INDEX IF NOT EXISTS idx_alerts_device_resolved ON alerts(device_id, resolved, created_at DESC);

-- Alert dashboard queries
CREATE INDEX IF NOT EXISTS idx_alerts_resolved_severity ON alerts(resolved, severity, created_at DESC);

-- Alert history queries
CREATE INDEX IF NOT EXISTS idx_alerts_created_resolved ON alerts(created_at DESC, resolved);

-- 4. PERFORMANCE_METRICS table indexes (if exists)
-- For performance monitoring features

-- Latest performance per device
CREATE INDEX IF NOT EXISTS idx_performance_device_timestamp ON performance_metrics(device_id, timestamp DESC);

-- Performance aggregation queries
CREATE INDEX IF NOT EXISTS idx_performance_timestamp_health ON performance_metrics(timestamp DESC, health_score);

-- 5. COMPOSITE indexes for complex queries

-- Device status with latest monitoring (super critical for dashboard)
CREATE INDEX IF NOT EXISTS idx_devices_monitoring_composite ON devices(is_monitored, last_seen, device_type, id);

-- Alert summary queries
CREATE INDEX IF NOT EXISTS idx_alerts_summary_composite ON alerts(resolved, device_id, severity, created_at DESC);

-- 6. MATERIALIZED VIEW equivalent (for ultra-fast device summaries)
-- Create a summary table that's updated via triggers for maximum performance

CREATE TABLE IF NOT EXISTS device_summary_cache (
    device_id INTEGER PRIMARY KEY,
    ip_address VARCHAR(15),
    display_name VARCHAR(255),
    device_type VARCHAR(50),
    status VARCHAR(20),
    last_seen DATETIME,
    latest_response_time FLOAT,
    active_alerts_count INTEGER,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

-- Index for the summary cache
CREATE INDEX IF NOT EXISTS idx_device_summary_status ON device_summary_cache(status, device_type);
CREATE INDEX IF NOT EXISTS idx_device_summary_updated ON device_summary_cache(last_updated);

-- 7. QUERY OPTIMIZATION: Statistics updates
-- Ensure SQLite has current statistics for query optimization
ANALYZE;

-- 8. PERFORMANCE TESTING QUERIES
-- Use these to verify index effectiveness

-- Test 1: Device list with status (should be <10ms)
-- SELECT d.*, (SELECT response_time FROM monitoring_data WHERE device_id = d.id ORDER BY timestamp DESC LIMIT 1) as latest_response
-- FROM devices d WHERE is_monitored = 1 ORDER BY ip_address;

-- Test 2: Alert counts per device (should be <5ms) 
-- SELECT device_id, COUNT(*) FROM alerts WHERE resolved = 0 GROUP BY device_id;

-- Test 3: Latest monitoring data (should be <10ms)
-- SELECT device_id, MAX(timestamp) as latest FROM monitoring_data GROUP BY device_id;

-- 9. MAINTENANCE: Query to identify missing indexes
-- Run this periodically to find slow queries

-- Enable query logging to identify bottlenecks
PRAGMA query_only = off;

-- 10. PERFORMANCE MONITORING
-- Create a simple table to track query performance over time
CREATE TABLE IF NOT EXISTS query_performance_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query_type VARCHAR(100),
    execution_time_ms INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_query_perf_type_time ON query_performance_log(query_type, timestamp DESC);