/**
 * HomeNetMon Real-time Updates JavaScript
 * Handles WebSocket connections and real-time data updates
 */

// Real-time updates state
window.RealTimeUpdates = {
    socket: null,
    connected: false,
    reconnectAttempts: 0,
    maxReconnectAttempts: 5,
    subscriptions: new Set(),
    handlers: {}
};

/**
 * Initialize real-time updates system
 */
function initializeRealTimeUpdates() {
    console.log('Initializing real-time updates...');
    
    if (typeof io === 'undefined') {
        console.warn('Socket.IO not available, real-time updates disabled');
        return;
    }
    
    connectWebSocket();
}

/**
 * Connect to WebSocket server
 */
function connectWebSocket() {
    try {
        RealTimeUpdates.socket = io({
            transports: ['websocket', 'polling'],
            timeout: 20000,
            forceNew: true
        });
        
        setupSocketHandlers();
        
    } catch (error) {
        console.error('WebSocket connection failed:', error);
        scheduleReconnect();
    }
}

/**
 * Set up socket event handlers
 */
function setupSocketHandlers() {
    const socket = RealTimeUpdates.socket;
    
    socket.on('connect', function() {
        console.log('Real-time updates connected');
        RealTimeUpdates.connected = true;
        RealTimeUpdates.reconnectAttempts = 0;
        
        // Update connection status
        updateConnectionIndicator(true);
        
        // Re-subscribe to rooms
        resubscribeToRooms();
        
        // Emit connection established event
        emitCustomEvent('realtime:connected');
    });
    
    socket.on('disconnect', function(reason) {
        console.log('Real-time updates disconnected:', reason);
        RealTimeUpdates.connected = false;
        updateConnectionIndicator(false);
        
        // Emit disconnection event
        emitCustomEvent('realtime:disconnected', { reason });
        
        // Schedule reconnect if not intentional
        if (reason !== 'io client disconnect') {
            scheduleReconnect();
        }
    });
    
    socket.on('connect_error', function(error) {
        console.error('Real-time connection error:', error);
        scheduleReconnect();
    });
    
    // Device status updates
    socket.on('device_status_update', function(data) {
        handleDeviceUpdate(data);
    });
    
    // Monitoring summaries
    socket.on('monitoring_summary', function(data) {
        handleMonitoringSummary(data);
    });
    
    // Chart data updates
    socket.on('chart_data_update', function(data) {
        handleChartUpdate(data);
    });
    
    // Alert updates
    socket.on('alert_update', function(data) {
        handleAlertUpdate(data);
    });
    
    // Performance metrics updates
    socket.on('performance_metrics_update', function(data) {
        handlePerformanceUpdate(data);
    });
}

/**
 * Handle device status updates
 */
function handleDeviceUpdate(data) {
    if (!data || !data.device_id) return;
    
    console.debug('Device update received:', data);
    
    // Update device displays
    updateDeviceDisplays(data);
    
    // Update charts if device affects network status
    if (data.status_changed) {
        requestChartUpdate();
    }
    
    // Emit custom event for other components
    emitCustomEvent('device:updated', data);
}

/**
 * Handle monitoring summary updates
 */
function handleMonitoringSummary(data) {
    if (!data) return;
    
    console.debug('Monitoring summary received:', data);
    
    // Update summary displays
    updateSummaryDisplays(data);
    
    // Update network status indicators
    updateNetworkStatus(data);
    
    // Emit custom event
    emitCustomEvent('monitoring:summary', data);
}

/**
 * Handle chart data updates
 */
function handleChartUpdate(data) {
    if (!data) return;
    
    console.debug('Chart update received:', data);
    
    // Update charts based on type
    switch (data.type) {
        case 'network_overview':
            updateNetworkChart(data);
            break;
        case 'response_time':
            updateResponseTimeChart(data);
            break;
        case 'bandwidth':
            updateBandwidthChart(data);
            break;
    }
    
    // Emit custom event
    emitCustomEvent('chart:updated', data);
}

/**
 * Handle alert updates
 */
function handleAlertUpdate(data) {
    if (!data) return;
    
    console.debug('Alert update received:', data);
    
    // Update alert displays
    updateAlertDisplays(data);
    
    // Show notification if new alert
    if (data.type === 'new_alert') {
        showAlertNotification(data);
    }
    
    // Emit custom event
    emitCustomEvent('alert:updated', data);
}

/**
 * Handle performance metrics updates
 */
function handlePerformanceUpdate(data) {
    if (!data) return;
    
    console.debug('Performance update received:', data);
    
    // Update performance displays
    updatePerformanceDisplays(data);
    
    // Emit custom event
    emitCustomEvent('performance:updated', data);
}

/**
 * Update device displays across the page
 */
function updateDeviceDisplays(data) {
    const deviceElements = document.querySelectorAll(`[data-device-id="${data.device_id}"]`);
    
    deviceElements.forEach(element => {
        // Update status badges
        const statusBadge = element.querySelector('[data-device-status]');
        if (statusBadge) {
            statusBadge.className = `badge bg-${getStatusColor(data.status)}`;
            statusBadge.textContent = data.status.toUpperCase();
        }
        
        // Update response times
        const responseTime = element.querySelector('[data-device-response-time]');
        if (responseTime) {
            responseTime.textContent = data.response_time ? `${data.response_time}ms` : 'N/A';
        }
        
        // Update timestamps
        const lastSeen = element.querySelector('[data-device-last-seen]');
        if (lastSeen && data.timestamp) {
            lastSeen.textContent = formatRelativeTime(data.timestamp);
        }
        
        // Update device names if provided
        if (data.display_name) {
            const nameElement = element.querySelector('[data-device-name]');
            if (nameElement) {
                nameElement.textContent = data.display_name;
            }
        }
    });
}

/**
 * Update summary displays
 */
function updateSummaryDisplays(data) {
    const summaryElements = [
        { key: 'total_devices', selector: '[data-summary-total]' },
        { key: 'devices_up', selector: '[data-summary-up]' },
        { key: 'devices_down', selector: '[data-summary-down]' },
        { key: 'active_alerts', selector: '[data-summary-alerts]' },
        { key: 'success_rate', selector: '[data-summary-success-rate]' }
    ];
    
    summaryElements.forEach(item => {
        const elements = document.querySelectorAll(item.selector);
        elements.forEach(element => {
            let value = data[item.key];
            if (item.key === 'success_rate' && value !== undefined) {
                value = `${value.toFixed(1)}%`;
            }
            element.textContent = value || '0';
        });
    });
}

/**
 * Subscribe to real-time updates for a specific room
 */
function subscribeToUpdates(room) {
    if (!RealTimeUpdates.socket || RealTimeUpdates.subscriptions.has(room)) {
        return;
    }
    
    console.log('Subscribing to updates:', room);
    RealTimeUpdates.socket.emit('join', room);
    RealTimeUpdates.subscriptions.add(room);
}

/**
 * Unsubscribe from real-time updates for a specific room
 */
function unsubscribeFromUpdates(room) {
    if (!RealTimeUpdates.socket || !RealTimeUpdates.subscriptions.has(room)) {
        return;
    }
    
    console.log('Unsubscribing from updates:', room);
    RealTimeUpdates.socket.emit('leave', room);
    RealTimeUpdates.subscriptions.delete(room);
}

/**
 * Re-subscribe to all rooms after reconnection
 */
function resubscribeToRooms() {
    RealTimeUpdates.subscriptions.forEach(room => {
        RealTimeUpdates.socket.emit('join', room);
    });
}

/**
 * Update connection status indicator
 */
function updateConnectionIndicator(connected) {
    const indicators = document.querySelectorAll('[data-connection-status]');
    indicators.forEach(indicator => {
        indicator.className = connected ? 'text-success' : 'text-warning';
        indicator.textContent = connected ? 'Live' : 'Connecting...';
        indicator.title = connected ? 'Real-time updates active' : 'Attempting to reconnect...';
    });
}

/**
 * Schedule reconnection attempt
 */
function scheduleReconnect() {
    if (RealTimeUpdates.reconnectAttempts >= RealTimeUpdates.maxReconnectAttempts) {
        console.error('Max reconnection attempts reached');
        updateConnectionIndicator(false);
        return;
    }
    
    RealTimeUpdates.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, RealTimeUpdates.reconnectAttempts), 30000);
    
    console.log(`Scheduling reconnect attempt ${RealTimeUpdates.reconnectAttempts} in ${delay}ms`);
    
    setTimeout(() => {
        if (!RealTimeUpdates.connected) {
            connectWebSocket();
        }
    }, delay);
}

/**
 * Emit custom DOM event
 */
function emitCustomEvent(eventName, data = null) {
    const event = new CustomEvent(eventName, { detail: data });
    document.dispatchEvent(event);
}

/**
 * Show alert notification
 */
function showAlertNotification(alertData) {
    // Simple notification implementation
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(`HomeNetMon Alert: ${alertData.device_name}`, {
            body: alertData.message,
            icon: '/static/favicon.ico'
        });
    }
}

/**
 * Format relative time
 */
function formatRelativeTime(timestamp) {
    try {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
        if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
        return `${Math.floor(diff / 86400000)}d ago`;
    } catch (error) {
        return 'Unknown';
    }
}

/**
 * Request chart update
 */
function requestChartUpdate() {
    // Throttle chart update requests
    if (!requestChartUpdate.lastRequest || Date.now() - requestChartUpdate.lastRequest > 5000) {
        requestChartUpdate.lastRequest = Date.now();
        emitCustomEvent('chart:refresh');
    }
}

// Utility functions (shared)
function getStatusColor(status) {
    const colors = {
        'up': 'success',
        'down': 'danger', 
        'warning': 'warning',
        'unknown': 'secondary'
    };
    return colors[status] || 'secondary';
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initializeRealTimeUpdates();
    
    // Auto-subscribe to common update streams
    setTimeout(() => {
        subscribeToUpdates('updates_device_status');
        subscribeToUpdates('updates_monitoring_summary');
    }, 1000);
});

// Export functions for external use
window.RealTimeUpdates.subscribe = subscribeToUpdates;
window.RealTimeUpdates.unsubscribe = unsubscribeFromUpdates;
window.RealTimeUpdates.isConnected = () => RealTimeUpdates.connected;