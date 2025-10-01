/**
 * HomeNetMon Core Application JavaScript
 * Core functionality for the network monitoring dashboard
 */

// Global app state
window.HomeNetMon = {
    config: {
        apiBase: '/api',
        socketConnected: false,
        autoRefresh: true,
        refreshInterval: 30000
    },
    data: {
        devices: [],
        alerts: [],
        lastUpdate: null
    },
    socket: null
};

// Initialize application when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('HomeNetMon application initializing...');
    
    // Initialize Socket.IO connection
    initializeSocket();
    
    // Initialize global event handlers
    initializeGlobalHandlers();
    
    // Start auto-refresh if enabled
    if (HomeNetMon.config.autoRefresh) {
        startAutoRefresh();
    }
    
    console.log('HomeNetMon application initialized');
});

/**
 * Initialize Socket.IO connection for real-time updates
 */
function initializeSocket() {
    try {
        HomeNetMon.socket = io({
            transports: ['websocket', 'polling'],
            timeout: 20000
        });
        
        HomeNetMon.socket.on('connect', function() {
            console.log('Socket.IO connected');
            HomeNetMon.config.socketConnected = true;
            updateConnectionStatus(true);
        });
        
        HomeNetMon.socket.on('disconnect', function() {
            console.log('Socket.IO disconnected');
            HomeNetMon.config.socketConnected = false;
            updateConnectionStatus(false);
        });
        
        // Listen for device updates
        HomeNetMon.socket.on('device_status_update', function(data) {
            updateDeviceStatus(data);
        });
        
        // Listen for monitoring summaries
        HomeNetMon.socket.on('monitoring_summary', function(data) {
            updateMonitoringSummary(data);
        });
        
    } catch (error) {
        console.error('Socket.IO initialization failed:', error);
    }
}

/**
 * Initialize global event handlers
 */
function initializeGlobalHandlers() {
    // Handle navigation
    document.addEventListener('click', function(e) {
        const link = e.target.closest('[data-nav]');
        if (link) {
            e.preventDefault();
            const url = link.getAttribute('href') || link.getAttribute('data-url');
            if (url) {
                window.location.href = url;
            }
        }
    });
    
    // Handle refresh buttons
    document.addEventListener('click', function(e) {
        if (e.target.matches('[data-refresh]')) {
            e.preventDefault();
            refreshData();
        }
    });
}

/**
 * Update connection status indicator
 */
function updateConnectionStatus(connected) {
    const indicators = document.querySelectorAll('[data-connection-status]');
    indicators.forEach(indicator => {
        indicator.className = connected ? 'text-success' : 'text-danger';
        indicator.textContent = connected ? 'Connected' : 'Disconnected';
    });
}

/**
 * Update device status from real-time data
 */
function updateDeviceStatus(data) {
    if (!data || !data.device_id) return;
    
    const deviceRows = document.querySelectorAll(`[data-device-id="${data.device_id}"]`);
    deviceRows.forEach(row => {
        // Update status badge
        const statusBadge = row.querySelector('[data-status]');
        if (statusBadge) {
            statusBadge.className = `badge bg-${getStatusColor(data.status)}`;
            statusBadge.textContent = data.status.toUpperCase();
        }
        
        // Update response time
        const responseTime = row.querySelector('[data-response-time]');
        if (responseTime) {
            responseTime.textContent = data.response_time ? `${data.response_time}ms` : 'N/A';
        }
        
        // Update last seen
        const lastSeen = row.querySelector('[data-last-seen]');
        if (lastSeen && data.timestamp) {
            lastSeen.textContent = formatTimestamp(data.timestamp);
        }
    });
}

/**
 * Update monitoring summary
 */
function updateMonitoringSummary(data) {
    if (!data) return;
    
    // Update quick stats
    const stats = [
        { key: 'total_devices', selector: '[data-stat-total-devices]' },
        { key: 'devices_up', selector: '[data-stat-devices-up]' },
        { key: 'devices_down', selector: '[data-stat-devices-down]' },
        { key: 'active_alerts', selector: '[data-stat-active-alerts]' }
    ];
    
    stats.forEach(stat => {
        const elements = document.querySelectorAll(stat.selector);
        elements.forEach(el => {
            el.textContent = data[stat.key] || '0';
        });
    });
    
    // Update success rate if available
    if (data.success_rate !== undefined) {
        const successElements = document.querySelectorAll('[data-stat-success-rate]');
        successElements.forEach(el => {
            el.textContent = `${data.success_rate.toFixed(1)}%`;
        });
    }
}

/**
 * Get status color for badges
 */
function getStatusColor(status) {
    const statusColors = {
        'up': 'success',
        'down': 'danger',
        'warning': 'warning',
        'unknown': 'secondary'
    };
    return statusColors[status] || 'secondary';
}

/**
 * Format timestamp for display
 */
function formatTimestamp(timestamp) {
    try {
        const date = new Date(timestamp);
        return date.toLocaleString();
    } catch (error) {
        return 'Unknown';
    }
}

/**
 * Start auto-refresh timer
 */
function startAutoRefresh() {
    setInterval(function() {
        if (!HomeNetMon.config.socketConnected) {
            refreshData();
        }
    }, HomeNetMon.config.refreshInterval);
}

/**
 * Refresh data manually
 */
function refreshData() {
    console.log('Refreshing data...');
    // Trigger page refresh or data reload
    window.location.reload();
}

/**
 * Utility function to make API calls
 */
function apiCall(endpoint, options = {}) {
    const url = HomeNetMon.config.apiBase + endpoint;
    
    return fetch(url, {
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        },
        ...options
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
    })
    .catch(error => {
        console.error('API call failed:', error);
        throw error;
    });
}

// Export for other modules
window.HomeNetMon.apiCall = apiCall;
window.HomeNetMon.updateDeviceStatus = updateDeviceStatus;