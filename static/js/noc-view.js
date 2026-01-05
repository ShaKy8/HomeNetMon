// NOC Dashboard JavaScript
let socket;
let deviceModal = null;
let actionResultsModal = null;
let currentDeviceId = null;
let nocData = {
    healthScore: 0,
    devicesOnline: 0,
    devicesOffline: 0,
    avgResponseTime: 0,
    activeAlerts: 0,
    devices: [],
    alerts: []
};

// Global cleanup tracking
window.nocTimers = {
    clockInterval: null,
    dataRefreshInterval: null,
    healthCheckInterval: null
};

// Request management for API call deduplication
window.nocRequests = {
    controllers: {},
    inProgress: new Set()
};

// Enhanced fetch with deduplication and cancellation
async function nocFetch(url, options = {}) {
    const requestKey = `${options.method || 'GET'}:${url}`;

    // Cancel existing request if in progress
    if (window.nocRequests.controllers[requestKey]) {
        window.nocRequests.controllers[requestKey].abort();
        window.nocRequests.inProgress.delete(requestKey);
    }

    // Skip if same request already in progress (unless forced)
    if (window.nocRequests.inProgress.has(requestKey) && !options.force) {
        return { deduped: true };
    }

    // Create new AbortController for this request
    const controller = new AbortController();
    window.nocRequests.controllers[requestKey] = controller;
    window.nocRequests.inProgress.add(requestKey);

    try {
        // Remove timeout from options since fetch doesn't support it
        const { timeout, ...fetchOptions } = options;

        const response = await fetch(url, {
            ...fetchOptions,
            signal: controller.signal
        });

        return response;
    } catch (error) {
        if (error.name === 'AbortError') {
            return { cancelled: true };
        }
        throw error;
    } finally {
        // Cleanup
        delete window.nocRequests.controllers[requestKey];
        window.nocRequests.inProgress.delete(requestKey);
    }
}

// Enhanced Loading State Management
window.nocLoading = {
    activeOperations: new Set(),
    globalIndicator: null
};

function showGlobalLoading(message = 'Loading...') {
    if (!window.nocLoading.globalIndicator) {
        const indicator = document.createElement('div');
        indicator.className = 'global-loading';
        indicator.innerHTML = `<span>${message}</span>`;
        document.body.appendChild(indicator);
        window.nocLoading.globalIndicator = indicator;
    } else {
        window.nocLoading.globalIndicator.querySelector('span').textContent = message;
    }
}

function hideGlobalLoading() {
    if (window.nocLoading.globalIndicator) {
        window.nocLoading.globalIndicator.remove();
        window.nocLoading.globalIndicator = null;
    }
}

function showButtonLoading(button, originalText) {
    if (button) {
        button.disabled = true;
        button.classList.add('btn-loading');
        button.dataset.originalText = originalText || button.textContent;
        button.textContent = '';
    }
}

function hideButtonLoading(button) {
    if (button) {
        button.disabled = false;
        button.classList.remove('btn-loading');
        if (button.dataset.originalText) {
            button.textContent = button.dataset.originalText;
            delete button.dataset.originalText;
        }
    }
}

function showModalLoading(modal, message = 'Loading device details...') {
    const modalBody = modal.querySelector('.modal-body');
    if (modalBody) {
        const existingOverlay = modalBody.querySelector('.modal-loading-overlay');
        if (!existingOverlay) {
            const overlay = document.createElement('div');
            overlay.className = 'modal-loading-overlay';
            overlay.innerHTML = `
                <div class="modal-loading-spinner"></div>
                <div class="modal-loading-text">${message}</div>
            `;
            modalBody.appendChild(overlay);
        }
    }
}

function hideModalLoading(modal) {
    const modalBody = modal.querySelector('.modal-body');
    if (modalBody) {
        const overlay = modalBody.querySelector('.modal-loading-overlay');
        if (overlay) {
            overlay.remove();
        }
    }
}

function addLoadingToElement(element, size = 'normal') {
    if (element && !element.classList.contains('loading-overlay')) {
        element.classList.add('loading-overlay');
        element.dataset.loadingSize = size;
    }
}

function removeLoadingFromElement(element) {
    if (element) {
        element.classList.remove('loading-overlay');
        delete element.dataset.loadingSize;
    }
}

// Enhanced Error Handling System
window.nocErrors = {
    retryAttempts: new Map(),
    maxRetries: 3,
    retryDelay: 2000
};

// Enhanced error classification and user-friendly messages
function getErrorContext(error, operation = 'operation') {
    const message = error.message || error.toString();

    // Network errors
    if (error.name === 'TypeError' && message.includes('fetch')) {
        return {
            type: 'network',
            title: 'Connection Error',
            message: `Unable to connect to the server. Please check your network connection.`,
            userFriendly: true,
            retryable: true,
            icon: '🌐'
        };
    }

    // Timeout errors
    if (message.includes('timeout') || message.includes('Timeout')) {
        return {
            type: 'timeout',
            title: 'Request Timeout',
            message: `The ${operation} took too long to complete. The server might be busy.`,
            userFriendly: true,
            retryable: true,
            icon: '⏱️'
        };
    }

    // Server errors (5xx)
    if (message.includes('HTTP 5')) {
        return {
            type: 'server',
            title: 'Server Error',
            message: `The server encountered an error while processing your request.`,
            userFriendly: true,
            retryable: true,
            icon: '🔧'
        };
    }

    // Client errors (4xx)
    if (message.includes('HTTP 4')) {
        return {
            type: 'client',
            title: 'Request Error',
            message: `The request couldn't be processed. Please try again.`,
            userFriendly: true,
            retryable: false,
            icon: '❌'
        };
    }

    // Permission/Auth errors
    if (message.includes('Unauthorized') || message.includes('Forbidden')) {
        return {
            type: 'auth',
            title: 'Access Denied',
            message: `You don't have permission to perform this action.`,
            userFriendly: true,
            retryable: false,
            icon: '🔒'
        };
    }

    // Device-specific errors
    if (message.includes('device') || message.includes('Device')) {
        return {
            type: 'device',
            title: 'Device Error',
            message: `Unable to communicate with the device. It might be offline or unreachable.`,
            userFriendly: true,
            retryable: true,
            icon: '📱'
        };
    }

    // Generic fallback
    return {
        type: 'generic',
        title: 'Unexpected Error',
        message: `An unexpected error occurred: ${message}`,
        userFriendly: false,
        retryable: true,
        icon: '⚠️'
    };
}

// Enhanced error display with retry options
function showEnhancedError(error, operation = 'operation', context = {}) {
    const errorInfo = getErrorContext(error, operation);
    const canRetry = errorInfo.retryable && context.onRetry;

    const toastType = errorInfo.type === 'network' ? 'warning' : 'error';
    const retryText = canRetry ? ' Click to retry.' : '';

    showToast(`${errorInfo.icon} ${errorInfo.title}: ${errorInfo.message}${retryText}`, toastType);

    // Add retry click handler if applicable
    if (canRetry) {
        const toasts = document.querySelectorAll('.toast:last-child');
        if (toasts.length > 0) {
            const lastToast = toasts[toasts.length - 1];
            lastToast.style.cursor = 'pointer';
            lastToast.onclick = async () => {
                lastToast.onclick = null; // Prevent multiple clicks
                await attemptRetry(operation, context.onRetry, error);
            };
        }
    }

    return errorInfo;
}

// Retry mechanism with exponential backoff
async function attemptRetry(operation, retryFunction, originalError) {
    const retryKey = `${operation}-${Date.now()}`;
    const currentAttempts = window.nocErrors.retryAttempts.get(operation) || 0;

    if (currentAttempts >= window.nocErrors.maxRetries) {
        showToast(`❌ Maximum retry attempts reached for ${operation}`, 'error');
        window.nocErrors.retryAttempts.delete(operation);
        return false;
    }

    const delay = window.nocErrors.retryDelay * Math.pow(2, currentAttempts);
    showToast(`🔄 Retrying ${operation} in ${delay/1000} seconds...`, 'info');

    setTimeout(async () => {
        try {
            window.nocErrors.retryAttempts.set(operation, currentAttempts + 1);
            await retryFunction();
            window.nocErrors.retryAttempts.delete(operation);
            showToast(`✅ ${operation} succeeded after retry`, 'success');
        } catch (retryError) {
            showEnhancedError(retryError, operation, { onRetry: retryFunction });
        }
    }, delay);

    return true;
}

// Enhanced modal error display
function showEnhancedModalError(error, operation = 'operation') {
    const errorInfo = getErrorContext(error, operation);

    // Update modal title
    const modalTitle = document.querySelector('#nocDeviceModal .modal-title');
    if (modalTitle) {
        modalTitle.innerHTML = `${errorInfo.icon} ${errorInfo.title}`;
    }

    // Show error in modal body
    const modalBody = document.querySelector('#nocDeviceModal .modal-body');
    if (modalBody) {
        modalBody.innerHTML = `
            <div class="alert alert-danger d-flex align-items-center" role="alert">
                <div class="me-3" style="font-size: 2rem;">${errorInfo.icon}</div>
                <div>
                    <h6 class="alert-heading mb-1">${errorInfo.title}</h6>
                    <p class="mb-0">${errorInfo.message}</p>
                    ${errorInfo.retryable ?
                        '<small class="text-muted">You can close this dialog and try again.</small>' :
                        ''}
                </div>
            </div>
        `;
    }
}

// Network status error display
function showNetworkError(error) {
    const healthScore = getElement('healthScore');
    const networkStatus = getElement('networkStatus');

    if (healthScore) {
        healthScore.innerHTML = `<div class="text-danger">⚠️</div>`;
        healthScore.className = 'health-score-number health-score-poor';
        healthScore.title = 'Network monitoring unavailable';
    }

    if (networkStatus) {
        networkStatus.textContent = 'CONNECTION ERROR';
        networkStatus.className = 'status-indicator status-critical';
        networkStatus.title = error.message;
    }
}

// DOM Element Caching System for Performance Optimization
window.nocElements = {
    cache: {},
    selectors: {
        // Core UI elements
        healthScore: '#health-score',
        networkStatus: '#network-status .status-indicator',
        deviceGrid: '#device-grid',
        alertsFeed: '#alerts-feed',
        nocClock: '#noc-clock',

        // Modal elements
        nocDeviceModal: '#nocDeviceModal',
        actionResultsModal: '#actionResultsModal',

        // Search and filter elements
        deviceSearch: '#device-search',
        searchSort: '#search-sort',
        advancedSearchPanel: '#advanced-search-panel',

        // Control elements
        showCriticalOnly: '#show-critical-only',
        showAllDevices: '#show-all-devices',
        toggleSearch: '#toggle-search',

        // Statistics elements
        deviceCount: '#device-count',
        nocAvgResponseTime: '#noc-avg-response-time',
        nocLastUpdate: '#noc-last-update',
        criticalAlertCount: '#critical-alert-count',
        warningAlertCount: '#warning-alert-count'
    }
};

// Cached DOM element getter with automatic fallback
function getElement(key, forceRefresh = false) {
    // Return cached element if available and not forcing refresh
    if (!forceRefresh && window.nocElements.cache[key]) {
        // Verify element is still in DOM
        if (document.contains(window.nocElements.cache[key])) {
            return window.nocElements.cache[key];
        } else {
            // Element was removed from DOM, clear cache
            delete window.nocElements.cache[key];
        }
    }

    // Look up selector and find element
    const selector = window.nocElements.selectors[key];
    if (!selector) {
        console.warn(`DOM cache: Unknown element key '${key}'`);
        return null;
    }

    const element = document.querySelector(selector);
    if (element) {
        window.nocElements.cache[key] = element;
    }

    return element;
}

// Get multiple elements at once
function getElements(keys, forceRefresh = false) {
    const elements = {};
    keys.forEach(key => {
        elements[key] = getElement(key, forceRefresh);
    });
    return elements;
}

// Clear element cache (call after major DOM changes)
function clearElementCache() {
    window.nocElements.cache = {};
}

// Touch feedback system for mobile devices
window.nocTouch = {
    activeElements: new Set(),
    swipeIndicator: null
};

// Touch feedback functions
function addTouchFeedback(element) {
    if (element && !window.nocTouch.activeElements.has(element)) {
        element.style.transform = 'scale(0.95)';
        element.style.transition = 'transform 0.1s ease';
        window.nocTouch.activeElements.add(element);
    }
}

function clearTouchFeedback() {
    window.nocTouch.activeElements.forEach(element => {
        if (element) {
            element.style.transform = '';
            element.style.transition = '';
        }
    });
    window.nocTouch.activeElements.clear();
}

// Swipe indicator for mobile navigation
function showSwipeIndicator(direction) {
    if (!window.nocTouch.swipeIndicator) {
        const indicator = document.createElement('div');
        indicator.className = 'swipe-indicator';
        indicator.innerHTML = `<span>Swipe ${direction}</span>`;
        indicator.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: rgba(0, 255, 255, 0.9);
            color: var(--noc-bg-primary);
            padding: 12px 20px;
            border-radius: 6px;
            z-index: 10000;
            font-weight: bold;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
            pointer-events: none;
        `;
        document.body.appendChild(indicator);
        window.nocTouch.swipeIndicator = indicator;

        // Auto-hide after 2 seconds
        setTimeout(() => {
            hideSwipeIndicator();
        }, 2000);
    }
}

function hideSwipeIndicator() {
    if (window.nocTouch.swipeIndicator) {
        window.nocTouch.swipeIndicator.remove();
        window.nocTouch.swipeIndicator = null;
    }
}

// Enhanced touch feedback for different interaction types
function provideTouchFeedback(type) {
    // Haptic feedback
    if (navigator.vibrate) {
        const patterns = {
            tap: [10],
            longPress: [50, 50, 50],
            error: [100, 50, 100],
            success: [25, 25, 25]
        };
        navigator.vibrate(patterns[type] || patterns.tap);
    }

    // Audio feedback (optional, very subtle)
    if (window.nocAudioFeedback && window.nocAudioFeedback.enabled) {
        // Could add subtle audio cues here
    }
}

// Initialize NOC dashboard system
function initializeNOCSystem() {
    try {
        console.log('NOC: Initializing dashboard system...');

        // Initialize modals
        const modalElements = document.querySelectorAll('.modal');
        modalElements.forEach(modalEl => {
            if (modalEl.id === 'nocDeviceModal') {
                deviceModal = new bootstrap.Modal(modalEl);
            } else if (modalEl.id === 'actionResultsModal') {
                actionResultsModal = new bootstrap.Modal(modalEl);
            }
        });

        // Clear any existing timers
        Object.keys(window.nocTimers).forEach(timer => {
            if (window.nocTimers[timer]) {
                clearInterval(window.nocTimers[timer]);
                window.nocTimers[timer] = null;
            }
        });

        // Clear caches
        clearElementCache();

        // Clear touch feedback
        clearTouchFeedback();
        hideSwipeIndicator();

        console.log('NOC: System initialization completed successfully');
        return true;

    } catch (error) {
        console.error('NOC: Failed to initialize system:', error);
        return false;
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('NOC: DOM loaded, starting initialization...');

    // Initialize system
    if (!initializeNOCSystem()) {
        console.error('NOC: System initialization failed, stopping startup sequence');
        return;
    }

    // Start the clock immediately
    updateClock();
    window.nocTimers.clockInterval = setInterval(updateClock, 1000);

    // Load initial data
    loadHealthOverview();
    loadDevices();
    loadAlerts();

    // Set up data refresh intervals
    window.nocTimers.dataRefreshInterval = setInterval(() => {
        loadHealthOverview();
        loadDevices();
        loadAlerts();
    }, 30000); // Refresh every 30 seconds

    // Health check interval (more frequent)
    window.nocTimers.healthCheckInterval = setInterval(loadHealthOverview, 10000); // Every 10 seconds

    // Initialize WebSocket connection
    initializeWebSocket();

    // Set up event listeners
    setupEventListeners();

    console.log('NOC: Dashboard fully initialized and running');
});

// Update clock display
function updateClock() {
    try {
        const now = new Date();
        const timeString = now.toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
        const dateString = now.toLocaleDateString('en-US', {
            weekday: 'short',
            month: 'short',
            day: 'numeric',
            year: 'numeric'
        });

        const clockElement = getElement('nocClock');
        if (!clockElement) {
            return;
        }

        clockElement.innerHTML = `
            ${timeString}
            <small class="noc-date">${dateString}</small>
        `;
    } catch (error) {
        console.error('NOC: Error updating clock:', error);
    }
}

// Load health overview data
async function loadHealthOverview() {
    try {
        const response = await nocFetch('/api/health/overview');
        if (response.deduped || response.cancelled) return;

        const data = await response.json();
        updateHealthDisplay(data);
        updateNetworkSummary(data);
        updateNetworkStatus(data);

    } catch (error) {
        console.error('NOC: Error loading health overview:', error);
        showNetworkError(error);
    }
}

// Update health score display
function updateHealthDisplay(data) {
    try {
        const score = data.health_score || 0;
        const scoreElement = getElement('healthScore');

        if (!scoreElement) {
            console.warn('NOC: Health score element not found');
            return;
        }

        // Update score number
        scoreElement.textContent = Math.round(score);

        // Update score color based on value
        scoreElement.className = 'health-score-number-enhanced';
        if (score >= 90) {
            scoreElement.classList.add('health-score-excellent');
        } else if (score >= 75) {
            scoreElement.classList.add('health-score-good');
        } else if (score >= 50) {
            scoreElement.classList.add('health-score-fair');
        } else {
            scoreElement.classList.add('health-score-poor');
        }

        // Update health summary text
        const summaryElement = document.getElementById('health-summary');
        if (summaryElement) {
            let summaryText = 'Network operational status';
            if (data.devices) {
                try {
                    const devicesTotal = data.devices.length || 0;
                    const devicesOnline = data.devices.filter(d => d.status === 'online').length || 0;
                    summaryText = `${devicesOnline}/${devicesTotal} devices online`;
                } catch (deviceCountError) {
                    console.error('NOC: Error calculating device counts:', deviceCountError);
                    // Use fallback values
                    devicesTotal = 0;
                    devicesOnline = 0;
                    summaryText = 'Device status unavailable';
                }
            }
            summaryElement.textContent = summaryText;
        }

        // Update trend indicator
        updateHealthTrend(score);

        // Update accessibility description
        const descElement = document.getElementById('health-score-description');
        if (descElement) {
            let status = 'unknown';
            if (score >= 90) status = 'excellent';
            else if (score >= 75) status = 'good';
            else if (score >= 50) status = 'fair';
            else status = 'poor';

            descElement.textContent = `Network health score is ${score} out of 100, indicating ${status} performance`;
        }

    } catch (error) {
        console.error('NOC: Error updating health display:', error);
        console.error('NOC: Error data:', data);
        console.error('NOC: Error stack:', error.stack);

        // Fallback: At least show the score even if other updates fail
        const scoreElement = document.getElementById('health-score');
        if (scoreElement && typeof score === 'number') {
            scoreElement.textContent = Math.round(score);
        }
    }
}

// Update health trend indicator
function updateHealthTrend(currentScore) {
    const trendArrow = document.getElementById('trend-arrow');
    if (!trendArrow) return;

    // Add current score to history
    if (!window.nocData.healthHistory) {
        window.nocData.healthHistory = [];
    }

    window.nocData.healthHistory.push(currentScore);

    // Keep only last 10 readings
    if (window.nocData.healthHistory.length > 10) {
        window.nocData.healthHistory.shift();
    }

    // Calculate trend if we have enough data
    if (window.nocData.healthHistory.length >= 3) {
        const recent = window.nocData.healthHistory.slice(-3);
        const avg = recent.reduce((a, b) => a + b, 0) / recent.length;
        const previousAvg = window.nocData.healthHistory.slice(-6, -3);

        if (previousAvg.length >= 3) {
            const prevAvg = previousAvg.reduce((a, b) => a + b, 0) / previousAvg.length;
            const trendDiff = avg - prevAvg;

            if (Math.abs(trendDiff) > 2) { // Only show trend if significant
                trendArrow.style.display = 'block';
                if (trendDiff > 0) {
                    trendArrow.className = 'bi bi-arrow-up text-success trend-arrow';
                    trendArrow.title = 'Health score trending up';
                } else {
                    trendArrow.className = 'bi bi-arrow-down text-danger trend-arrow';
                    trendArrow.title = 'Health score trending down';
                }
            } else {
                trendArrow.style.display = 'none';
            }
        }
    }
}

// Update network summary
function updateNetworkSummary(data) {
    try {
        const avgResponseElement = getElement('nocAvgResponseTime');
        const lastUpdateElement = getElement('nocLastUpdate');

        if (avgResponseElement) {
            const avgResponse = data.average_response_time || 0;
            avgResponseElement.textContent = avgResponse > 0 ? `${avgResponse.toFixed(1)}ms` : '--';
        }

        if (lastUpdateElement) {
            const lastUpdate = data.last_update ? new Date(data.last_update) : new Date();
            const timeAgo = getTimeAgo(lastUpdate);
            lastUpdateElement.textContent = timeAgo;
        }

    } catch (error) {
        console.error('NOC: Error updating network summary:', error);
    }
}

// Update network status indicator
function updateNetworkStatus(data) {
    try {
        const networkStatusElement = getElement('networkStatus');
        if (!networkStatusElement) return;

        const score = data.health_score || 0;
        let status = 'UNKNOWN';
        let statusClass = 'status-critical';

        if (score >= 90) {
            status = 'OPTIMAL';
            statusClass = 'status-online';
        } else if (score >= 75) {
            status = 'NORMAL';
            statusClass = 'status-online';
        } else if (score >= 50) {
            status = 'DEGRADED';
            statusClass = 'status-degraded';
        } else {
            status = 'CRITICAL';
            statusClass = 'status-critical';
        }

        networkStatusElement.textContent = status;
        networkStatusElement.className = `status-indicator ${statusClass}`;

        // Update accessibility description
        const descElement = document.getElementById('network-status-description');
        if (descElement) {
            descElement.textContent = `Network status is ${status.toLowerCase()}`;
        }

    } catch (error) {
        console.error('NOC: Error updating network status:', error);
    }
}

// Load devices data
async function loadDevices() {
    try {
        const response = await nocFetch('/api/devices/status');
        if (response.deduped || response.cancelled) return;

        const devices = await response.json();
        updateDeviceGrid(devices);
        updateDeviceCount(devices);
        updateNetworkMap(devices);

    } catch (error) {
        console.error('NOC: Error loading devices:', error);
        showEnhancedError(error, 'device loading', {
            onRetry: loadDevices
        });
    }
}

// Update device grid
function updateDeviceGrid(devices) {
    try {
        const deviceGrid = getElement('deviceGrid');
        if (!deviceGrid) {
            console.error('NOC: Critical element deviceGrid not found in DOM!');
            showSystemError('Device grid element not found. Page may not be fully loaded.');
            return false;
        }

        const showCriticalOnly = getElement('showCriticalOnly');
        const showAllDevices = getElement('showAllDevices');

        let filteredDevices = devices;

        // Apply filters
        if (showCriticalOnly && showCriticalOnly.checked) {
            filteredDevices = devices.filter(device =>
                device.status !== 'online' || device.alerts_count > 0
            );
        }

        if (!showAllDevices || !showAllDevices.checked) {
            filteredDevices = filteredDevices.slice(0, 20); // Limit to 20 for NOC view
        }

        // Clear existing content
        deviceGrid.innerHTML = '';

        if (filteredDevices.length === 0) {
            deviceGrid.innerHTML = `
                <div class="col-12">
                    <div class="text-center py-4 text-muted">
                        <i class="bi bi-search mb-2" style="font-size: 2rem;"></i>
                        <p>No devices found matching current filters</p>
                    </div>
                </div>
            `;
            return;
        }

        // Create device tiles
        filteredDevices.forEach(device => {
            const deviceTile = createDeviceTile(device);
            deviceGrid.appendChild(deviceTile);
        });

        // Update show more button
        const showMoreContainer = document.getElementById('show-more-container');
        if (showMoreContainer) {
            if (devices.length > filteredDevices.length) {
                showMoreContainer.style.display = 'block';
            } else {
                showMoreContainer.style.display = 'none';
            }
        }

    } catch (error) {
        console.error('NOC: Error updating device grid:', error);
        const deviceGrid = getElement('deviceGrid');
        if (deviceGrid) {
            deviceGrid.innerHTML = `
                <div class="col-12">
                    <div class="alert alert-danger" role="alert">
                        <i class="bi bi-exclamation-triangle me-2"></i>
                        Error loading device data. Please refresh the page.
                    </div>
                </div>
            `;
        }
    }
}

// Create individual device tile
function createDeviceTile(device) {
    const col = document.createElement('div');
    col.className = 'col-lg-6 col-xl-4 mb-3';

    const statusClass = device.status === 'online' ? 'device-online' :
                       device.status === 'offline' ? 'device-offline' : 'device-warning';

    const priorityClass = device.alerts_count > 0 ? 'critical' :
                         device.status === 'online' ? 'normal' : 'monitoring';

    const responseTime = device.avg_response_time > 0 ?
                        `${device.avg_response_time.toFixed(1)}ms` : '--';

    const deviceType = device.device_type || 'unknown';
    const deviceIcon = getDeviceIcon(deviceType);

    col.innerHTML = `
        <div class="device-tile ${statusClass}"
             data-device-id="${device.id}"
             onclick="showDeviceModal(${device.id})"
             role="button"
             tabindex="0"
             aria-label="Device ${device.name || device.ip}, status ${device.status}">

            <div class="device-priority-indicator ${priorityClass}"
                 aria-label="Priority: ${priorityClass}"></div>

            <div class="d-flex align-items-start">
                <div class="me-2">
                    <i class="bi ${deviceIcon} text-info" style="font-size: 1.2rem;"></i>
                </div>
                <div class="flex-grow-1">
                    <div class="device-name">${device.name || device.ip}</div>
                    <div class="device-ip">${device.ip}</div>
                    <div class="device-status text-${device.status === 'online' ? 'success' : 'danger'}">
                        ${device.status.toUpperCase()}
                    </div>
                    <div class="device-response-time">
                        Response: ${responseTime}
                    </div>

                    ${device.alerts_count > 0 ? `
                        <div class="mt-2">
                            <span class="noc-badge">${device.alerts_count} alert${device.alerts_count !== 1 ? 's' : ''}</span>
                        </div>
                    ` : ''}
                </div>
            </div>

            <div class="quick-actions mt-2">
                <a href="/device/${device.id}" class="quick-action-btn" onclick="event.stopPropagation();">
                    <i class="bi bi-info-circle"></i> Details
                </a>
                ${device.status === 'offline' ? `
                    <button class="quick-action-btn" onclick="event.stopPropagation(); pingDevice(${device.id});">
                        <i class="bi bi-wifi"></i> Ping
                    </button>
                ` : ''}
            </div>
        </div>
    `;

    return col;
}

// Get device icon based on type
function getDeviceIcon(deviceType) {
    const icons = {
        'router': 'bi-router',
        'switch': 'bi-diagram-3',
        'computer': 'bi-pc-display',
        'laptop': 'bi-laptop',
        'phone': 'bi-phone',
        'tablet': 'bi-tablet',
        'server': 'bi-server',
        'printer': 'bi-printer',
        'camera': 'bi-camera-video',
        'smart_tv': 'bi-tv',
        'game_console': 'bi-controller',
        'iot': 'bi-cpu',
        'unknown': 'bi-question-circle'
    };

    return icons[deviceType] || icons.unknown;
}

// Update device count
function updateDeviceCount(devices) {
    try {
        const deviceCountElement = getElement('deviceCount');
        if (deviceCountElement) {
            const onlineCount = devices.filter(d => d.status === 'online').length;
            deviceCountElement.textContent = `${onlineCount}/${devices.length}`;
            deviceCountElement.className = onlineCount === devices.length ?
                'badge bg-success ms-2' : 'badge bg-warning ms-2';
        }
    } catch (error) {
        console.error('NOC: Error updating device count:', error);
    }
}

// Update network map
function updateNetworkMap(devices) {
    try {
        const networkMap = document.getElementById('network-map');
        if (!networkMap) return;

        // Clear existing nodes
        networkMap.innerHTML = '';

        if (devices.length === 0) {
            networkMap.innerHTML = '<div class="text-center text-muted">No devices to display</div>';
            return;
        }

        // Create a simple grid layout for devices
        const maxNodes = 20; // Limit for performance
        const displayDevices = devices.slice(0, maxNodes);

        displayDevices.forEach((device, index) => {
            const node = document.createElement('div');
            node.className = `map-node ${device.status}`;

            // Position nodes in a grid pattern
            const cols = Math.ceil(Math.sqrt(displayDevices.length));
            const row = Math.floor(index / cols);
            const col = index % cols;

            const x = (col + 1) * (100 / (cols + 1));
            const y = (row + 1) * (100 / (Math.ceil(displayDevices.length / cols) + 1));

            node.style.left = `${x}%`;
            node.style.top = `${y}%`;
            node.title = `${device.name || device.ip} (${device.status})`;

            node.onclick = () => showDeviceModal(device.id);

            networkMap.appendChild(node);
        });

        if (devices.length > maxNodes) {
            const moreIndicator = document.createElement('div');
            moreIndicator.className = 'text-center text-muted mt-2';
            moreIndicator.style.position = 'absolute';
            moreIndicator.style.bottom = '10px';
            moreIndicator.style.left = '50%';
            moreIndicator.style.transform = 'translateX(-50%)';
            moreIndicator.innerHTML = `<small>+${devices.length - maxNodes} more devices</small>`;
            networkMap.appendChild(moreIndicator);
        }

    } catch (error) {
        console.error('NOC: Error updating network map:', error);
    }
}

// Load alerts data
async function loadAlerts() {
    try {
        const response = await nocFetch('/api/alerts/active');
        if (response.deduped || response.cancelled) return;

        const alerts = await response.json();
        updateAlertsDisplay(alerts);
        updateAlertCounts(alerts);
        updateCriticalBanner(alerts);

    } catch (error) {
        console.error('NOC: Error loading alerts:', error);
        showEnhancedError(error, 'alert loading', {
            onRetry: loadAlerts
        });
    }
}

// Update alerts display
function updateAlertsDisplay(alerts) {
    try {
        const alertsFeed = getElement('alertsFeed');
        if (!alertsFeed) return;

        alertsFeed.innerHTML = '';

        if (alerts.length === 0) {
            alertsFeed.innerHTML = `
                <div class="text-center text-muted py-3">
                    <i class="bi bi-check-circle mb-2" style="font-size: 2rem; color: var(--noc-accent-green);"></i>
                    <p class="mb-0">No active alerts</p>
                </div>
            `;
            return;
        }

        // Group alerts by severity
        const groupedAlerts = {
            critical: alerts.filter(a => a.severity === 'critical'),
            warning: alerts.filter(a => a.severity === 'warning'),
            info: alerts.filter(a => a.severity === 'info')
        };

        // Display each group
        Object.entries(groupedAlerts).forEach(([severity, severityAlerts]) => {
            if (severityAlerts.length === 0) return;

            // Add severity header
            const header = document.createElement('div');
            header.className = `alert-severity-header ${severity}`;
            header.innerHTML = `
                <span>${severity.toUpperCase()}</span>
                <span class="badge">${severityAlerts.length}</span>
            `;
            alertsFeed.appendChild(header);

            // Add alerts for this severity
            severityAlerts.slice(0, 10).forEach(alert => { // Limit to 10 per severity
                const alertElement = createAlertElement(alert);
                alertsFeed.appendChild(alertElement);
            });
        });

    } catch (error) {
        console.error('NOC: Error updating alerts display:', error);
    }
}

// Create individual alert element
function createAlertElement(alert) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert-item alert-${alert.severity}`;
    alertDiv.dataset.alertId = alert.id;

    const timeAgo = getTimeAgo(new Date(alert.created_at));

    alertDiv.innerHTML = `
        <div class="d-flex justify-content-between align-items-start">
            <div class="flex-grow-1">
                <strong>${alert.device_name || 'System'}</strong>
                <br>
                <span class="alert-message">${alert.message}</span>
            </div>
            <div class="alert-timestamp">${timeAgo}</div>
        </div>
        ${alert.acknowledged ? '<div class="text-muted small mt-1">Acknowledged</div>' : ''}
    `;

    // Add click handler for acknowledgment
    if (!alert.acknowledged) {
        alertDiv.onclick = () => acknowledgeAlert(alert.id);
        alertDiv.style.cursor = 'pointer';
        alertDiv.title = 'Click to acknowledge';
    }

    return alertDiv;
}

// Update alert counts
function updateAlertCounts(alerts) {
    try {
        const criticalCount = alerts.filter(a => a.severity === 'critical').length;
        const warningCount = alerts.filter(a => a.severity === 'warning').length;

        const criticalBadge = getElement('criticalAlertCount');
        const warningBadge = getElement('warningAlertCount');

        if (criticalBadge) {
            if (criticalCount > 0) {
                criticalBadge.textContent = criticalCount;
                criticalBadge.style.display = 'inline';
            } else {
                criticalBadge.style.display = 'none';
            }
        }

        if (warningBadge) {
            if (warningCount > 0) {
                warningBadge.textContent = warningCount;
                warningBadge.style.display = 'inline';
            } else {
                warningBadge.style.display = 'none';
            }
        }

    } catch (error) {
        console.error('NOC: Error updating alert counts:', error);
    }
}

// Update critical alert banner
function updateCriticalBanner(alerts) {
    try {
        const criticalAlerts = alerts.filter(a => a.severity === 'critical');
        const banner = document.getElementById('critical-alert-banner');

        if (!banner) return;

        if (criticalAlerts.length > 0) {
            const alertText = document.getElementById('critical-alert-text');
            if (alertText) {
                if (criticalAlerts.length === 1) {
                    alertText.textContent = criticalAlerts[0].message;
                } else {
                    alertText.textContent = `${criticalAlerts.length} critical issues detected`;
                }
            }
            banner.style.display = 'block';
        } else {
            banner.style.display = 'none';
        }

    } catch (error) {
        console.error('NOC: Error updating critical banner:', error);
    }
}

// Show device modal
async function showDeviceModal(deviceId) {
    if (!deviceModal) return;

    currentDeviceId = deviceId;

    try {
        showModalLoading(deviceModal._element);
        deviceModal.show();

        const response = await nocFetch(`/api/devices/${deviceId}`);
        if (response.deduped || response.cancelled) return;

        const device = await response.json();
        updateDeviceModal(device);

    } catch (error) {
        console.error('NOC: Error loading device details:', error);
        showEnhancedModalError(error, 'device detail loading');
    } finally {
        hideModalLoading(deviceModal._element);
    }
}

// Update device modal with data
function updateDeviceModal(device) {
    try {
        // Update modal title
        const modalTitle = document.getElementById('nocDeviceModalLabel');
        if (modalTitle) {
            modalTitle.innerHTML = `
                <i class="bi bi-hdd-network me-2"></i>
                ${device.name || device.ip}
            `;
        }

        // Update device information
        const updates = {
            'modal-device-name': device.name || device.ip,
            'modal-device-ip': device.ip,
            'modal-device-mac': device.mac_address || '--',
            'modal-device-vendor': device.vendor || '--',
            'modal-device-type': device.device_type || '--'
        };

        Object.entries(updates).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        });

        // Update status badge
        const statusElement = document.getElementById('modal-device-status');
        if (statusElement) {
            statusElement.textContent = device.status.toUpperCase();
            statusElement.className = `badge bg-${device.status === 'online' ? 'success' : 'danger'}`;
        }

        // Update monitoring toggle
        const monitoringToggle = document.getElementById('modal-monitoring-toggle');
        if (monitoringToggle) {
            monitoringToggle.checked = device.monitoring_enabled;
        }

        // Update performance metrics
        const perfUpdates = {
            'modal-response-time': device.avg_response_time > 0 ? `${device.avg_response_time.toFixed(1)}ms` : '--',
            'modal-uptime': device.uptime_percentage ? `${device.uptime_percentage.toFixed(1)}%` : '--',
            'modal-last-seen': device.last_seen ? getTimeAgo(new Date(device.last_seen)) : '--',
            'modal-alerts-count': device.alerts_count || '0'
        };

        Object.entries(perfUpdates).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        });

    } catch (error) {
        console.error('NOC: Error updating device modal:', error);
    }
}

// Initialize WebSocket connection
function initializeWebSocket() {
    try {
        socket = io();

        socket.on('connect', () => {
            console.log('NOC: WebSocket connected');
            showToast('🔗 Real-time connection established', 'success');
        });

        socket.on('disconnect', () => {
            console.log('NOC: WebSocket disconnected');
            showToast('🔌 Real-time connection lost', 'warning');
        });

        socket.on('device_status_update', (data) => {
            updateDeviceInGrid(data);
        });

        socket.on('alert_update', (data) => {
            if (data.type === 'new_alert') {
                showToast(`🚨 ${data.alert.severity.toUpperCase()}: ${data.alert.message}`, 'error');
                loadAlerts(); // Refresh alerts display
            }
        });

        socket.on('health_update', (data) => {
            updateHealthDisplay(data);
        });

    } catch (error) {
        console.error('NOC: Error initializing WebSocket:', error);
    }
}

// Update single device in grid
function updateDeviceInGrid(deviceData) {
    try {
        const deviceTile = document.querySelector(`[data-device-id="${deviceData.id}"]`);
        if (!deviceTile) return;

        // Update status class
        deviceTile.className = deviceTile.className.replace(
            /device-(online|offline|warning)/g,
            `device-${deviceData.status}`
        );

        // Update status text
        const statusElement = deviceTile.querySelector('.device-status');
        if (statusElement) {
            statusElement.textContent = deviceData.status.toUpperCase();
            statusElement.className = `device-status text-${deviceData.status === 'online' ? 'success' : 'danger'}`;
        }

        // Update response time
        const responseElement = deviceTile.querySelector('.device-response-time');
        if (responseElement && deviceData.response_time) {
            responseElement.textContent = `Response: ${deviceData.response_time.toFixed(1)}ms`;
        }

    } catch (error) {
        console.error('NOC: Error updating device in grid:', error);
    }
}

// Setup event listeners
function setupEventListeners() {
    try {
        // Search toggle
        const toggleSearch = getElement('toggleSearch');
        if (toggleSearch) {
            toggleSearch.addEventListener('click', () => {
                const searchPanel = getElement('advancedSearchPanel');
                if (searchPanel) {
                    const isVisible = searchPanel.style.display !== 'none';
                    searchPanel.style.display = isVisible ? 'none' : 'block';
                    toggleSearch.classList.toggle('active', !isVisible);
                }
            });
        }

        // Device search
        const deviceSearch = getElement('deviceSearch');
        if (deviceSearch) {
            deviceSearch.addEventListener('input', debounce(handleDeviceSearch, 300));
        }

        // Filter toggles
        const showCriticalOnly = getElement('showCriticalOnly');
        const showAllDevices = getElement('showAllDevices');

        if (showCriticalOnly) {
            showCriticalOnly.addEventListener('change', () => {
                if (showAllDevices) showAllDevices.checked = false;
                loadDevices();
            });
        }

        if (showAllDevices) {
            showAllDevices.addEventListener('change', () => {
                if (showCriticalOnly) showCriticalOnly.checked = false;
                loadDevices();
            });
        }

        // Full screen button
        const fullscreenBtn = document.querySelector('.fullscreen-btn');
        if (fullscreenBtn) {
            fullscreenBtn.addEventListener('click', toggleFullscreen);
        }

        // Modal action buttons
        setupModalActionListeners();

        // Keyboard shortcuts
        document.addEventListener('keydown', handleKeyboardShortcuts);

        // Touch events for mobile
        setupTouchEventListeners();

    } catch (error) {
        console.error('NOC: Error setting up event listeners:', error);
    }
}

// Setup modal action listeners
function setupModalActionListeners() {
    const modalPingBtn = document.getElementById('modal-ping-btn');
    const modalWakeBtn = document.getElementById('modal-wake-btn');
    const modalScanBtn = document.getElementById('modal-scan-btn');
    const modalViewDetailsBtn = document.getElementById('modal-view-details-btn');

    if (modalPingBtn) {
        modalPingBtn.addEventListener('click', () => {
            if (currentDeviceId) pingDevice(currentDeviceId);
        });
    }

    if (modalWakeBtn) {
        modalWakeBtn.addEventListener('click', () => {
            if (currentDeviceId) wakeDevice(currentDeviceId);
        });
    }

    if (modalScanBtn) {
        modalScanBtn.addEventListener('click', () => {
            if (currentDeviceId) scanDevice(currentDeviceId);
        });
    }

    if (modalViewDetailsBtn) {
        modalViewDetailsBtn.addEventListener('click', () => {
            if (currentDeviceId) {
                window.open(`/device/${currentDeviceId}`, '_blank');
            }
        });
    }
}

// Setup touch event listeners for mobile
function setupTouchEventListeners() {
    // Add touch feedback to device tiles
    document.addEventListener('touchstart', (e) => {
        const deviceTile = e.target.closest('.device-tile');
        if (deviceTile) {
            addTouchFeedback(deviceTile);
        }
    });

    document.addEventListener('touchend', () => {
        clearTouchFeedback();
    });

    // Swipe gestures for navigation
    let touchStartX = 0;
    let touchStartY = 0;

    document.addEventListener('touchstart', (e) => {
        touchStartX = e.touches[0].clientX;
        touchStartY = e.touches[0].clientY;
    });

    document.addEventListener('touchmove', (e) => {
        if (!touchStartX || !touchStartY) return;

        const touchEndX = e.touches[0].clientX;
        const touchEndY = e.touches[0].clientY;

        const diffX = touchStartX - touchEndX;
        const diffY = touchStartY - touchEndY;

        // Only handle horizontal swipes
        if (Math.abs(diffX) > Math.abs(diffY) && Math.abs(diffX) > 50) {
            if (diffX > 0) {
                // Swipe left - could trigger filter change
                showSwipeIndicator('left for filters');
            } else {
                // Swipe right - could trigger menu
                showSwipeIndicator('right for menu');
            }
        }
    });
}

// Handle device search
function handleDeviceSearch() {
    const searchTerm = getElement('deviceSearch')?.value?.toLowerCase();
    if (!searchTerm) {
        loadDevices();
        return;
    }

    // Filter devices based on search term
    // This would normally filter the device grid
    console.log('NOC: Searching for:', searchTerm);
}

// Handle keyboard shortcuts
function handleKeyboardShortcuts(e) {
    switch(e.key) {
        case 'F11':
            e.preventDefault();
            toggleFullscreen();
            break;
        case 'Escape':
            if (deviceModal && deviceModal._isShown) {
                deviceModal.hide();
            }
            break;
        case '?':
            if (e.shiftKey) {
                showKeyboardShortcuts();
            }
            break;
    }
}

// Device action functions
async function pingDevice(deviceId) {
    try {
        showToast('🔄 Pinging device...', 'info');
        const response = await nocFetch(`/api/devices/${deviceId}/ping`, { method: 'POST' });
        const result = await response.json();

        if (result.success) {
            showToast(`✅ Ping successful: ${result.response_time}ms`, 'success');
        } else {
            showToast(`❌ Ping failed: ${result.error}`, 'error');
        }

    } catch (error) {
        showEnhancedError(error, 'device ping');
    }
}

async function wakeDevice(deviceId) {
    try {
        showToast('🔄 Sending Wake-on-LAN packet...', 'info');
        const response = await nocFetch(`/api/devices/${deviceId}/wake`, { method: 'POST' });
        const result = await response.json();

        if (result.success) {
            showToast('✅ Wake packet sent successfully', 'success');
        } else {
            showToast(`❌ Wake failed: ${result.error}`, 'error');
        }

    } catch (error) {
        showEnhancedError(error, 'device wake');
    }
}

async function scanDevice(deviceId) {
    try {
        showToast('🔄 Starting port scan...', 'info');
        const response = await nocFetch(`/api/devices/${deviceId}/scan`, { method: 'POST' });
        const result = await response.json();

        if (result.success) {
            showActionResults('Port Scan', result);
        } else {
            showToast(`❌ Scan failed: ${result.error}`, 'error');
        }

    } catch (error) {
        showEnhancedError(error, 'device scan');
    }
}

// Show action results in modal
function showActionResults(actionType, result) {
    if (!actionResultsModal) return;

    document.getElementById('results-action-type').textContent = actionType;
    document.getElementById('results-device-name').textContent = result.device_name || 'Unknown';
    document.getElementById('results-timestamp').textContent = new Date().toLocaleString();
    document.getElementById('results-content').textContent = result.output || 'No output available';

    actionResultsModal.show();
}

// Acknowledge alert
async function acknowledgeAlert(alertId) {
    try {
        const response = await nocFetch(`/api/alerts/${alertId}/acknowledge`, { method: 'POST' });
        if (response.ok) {
            showToast('✅ Alert acknowledged', 'success');
            loadAlerts(); // Refresh alerts
        }
    } catch (error) {
        showEnhancedError(error, 'alert acknowledgment');
    }
}

// Toggle fullscreen mode
function toggleFullscreen() {
    if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen().catch(err => {
            console.error('NOC: Error attempting to enable fullscreen:', err);
        });
    } else {
        document.exitFullscreen();
    }
}

// Utility functions
function getTimeAgo(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `noc-toast toast-${type}`;
    toast.textContent = message;

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 5000);
}

function showSystemError(message) {
    showToast(`⚠️ System Error: ${message}`, 'error');
}

// Cleanup function for page unload
window.addEventListener('beforeunload', () => {
    // Clear timers
    Object.keys(window.nocTimers).forEach(timer => {
        if (window.nocTimers[timer]) {
            clearInterval(window.nocTimers[timer]);
        }
    });

    // Disconnect WebSocket
    if (socket) {
        socket.disconnect();
    }

    // Cancel pending requests
    Object.values(window.nocRequests.controllers).forEach(controller => {
        controller.abort();
    });
});

// Handle visibility change (tab switching)
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        // Page is hidden, reduce update frequency
        if (window.nocTimers.dataRefreshInterval) {
            clearInterval(window.nocTimers.dataRefreshInterval);
            window.nocTimers.dataRefreshInterval = setInterval(() => {
                loadHealthOverview();
                loadDevices();
                loadAlerts();
            }, 60000); // Slower refresh when hidden
        }
    } else {
        // Page is visible, restore normal frequency
        if (window.nocTimers.dataRefreshInterval) {
            clearInterval(window.nocTimers.dataRefreshInterval);
            window.nocTimers.dataRefreshInterval = setInterval(() => {
                loadHealthOverview();
                loadDevices();
                loadAlerts();
            }, 30000); // Normal refresh rate
        }

        // Immediate refresh when page becomes visible
        loadHealthOverview();
        loadDevices();
        loadAlerts();
    }
});

// Performance monitoring
if (window.performance && window.performance.mark) {
    window.performance.mark('noc-script-end');
    console.log('NOC: Script initialization completed');
}

// Keyboard shortcuts help
document.addEventListener('keydown', (e) => {
    if (e.key === '?' && e.shiftKey) {
        showKeyboardShortcuts();
    }
});

function showKeyboardShortcuts() {
    alert('Keyboard Shortcuts:\n\nArrow Keys - Navigate devices\nEnter/Space - Open device details\nF11 - Toggle fullscreen\nESC - Close modals');
}
