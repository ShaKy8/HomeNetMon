/**
 * HomeNetMon Dashboard JavaScript
 * Enhanced dashboard functionality and real-time updates
 */

// Dashboard-specific state
window.Dashboard = {
    charts: {},
    refreshInterval: null,
    initialized: false
};

// User Preferences Management
class UserPreferences {
    constructor() {
        this.storageKey = 'homenetmon-dashboard-prefs';
        this.defaults = {
            showPerformanceMetrics: false,
            filterType: '',
            filterGroup: '',
            filterStatus: '',
            viewMode: 'grid',
            sortField: 'display_name',
            sortDirection: 'asc'
        };
        this.preferences = this.load();
    }
    
    load() {
        try {
            const stored = localStorage.getItem(this.storageKey);
            if (stored) {
                const parsed = JSON.parse(stored);
                return { ...this.defaults, ...parsed };
            }
        } catch (error) {
            console.warn('Error loading user preferences:', error);
        }
        return { ...this.defaults };
    }
    
    save() {
        try {
            localStorage.setItem(this.storageKey, JSON.stringify(this.preferences));
        } catch (error) {
            console.warn('Error saving user preferences:', error);
        }
    }
    
    get(key) {
        return this.preferences[key] ?? this.defaults[key];
    }
    
    set(key, value) {
        this.preferences[key] = value;
        this.save();
    }
    
    reset() {
        this.preferences = { ...this.defaults };
        this.save();
    }
}

// Global preferences instance
window.userPrefs = new UserPreferences();

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    if (document.querySelector('[data-dashboard]')) {
        console.log('Initializing dashboard...');
        initializeDashboard();
    }
});

/**
 * Initialize dashboard functionality
 */
function initializeDashboard() {
    if (Dashboard.initialized) return;
    
    // Initialize charts if Chart.js is available
    if (typeof Chart !== 'undefined') {
        initializeCharts();
    }
    
    // Initialize device grid handlers
    initializeDeviceGrid();
    
    // Initialize filter handlers
    initializeFilters();
    
    // Set up dashboard-specific socket handlers
    setupDashboardSocket();
    
    // Initialize performance metrics toggle
    initializePerformanceToggle();
    
    // Apply saved user preferences
    applyUserPreferences();
    
    // Initialize preference saving for filters
    initializeFilterPreferences();
    
    // Show initial loading state
    setTimeout(() => {
        if (window.skeletonManager) {
            window.skeletonManager.showLoadingState(800);
        }
    }, 100);
    
    Dashboard.initialized = true;
    console.log('Dashboard initialized');
}

/**
 * Initialize charts
 */
function initializeCharts() {
    // Network Overview Chart
    const networkChartCanvas = document.getElementById('networkOverviewChart');
    if (networkChartCanvas) {
        Dashboard.charts.network = new Chart(networkChartCanvas, {
            type: 'doughnut',
            data: {
                labels: ['Up', 'Down', 'Warning'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: [
                        '#28a745',
                        '#dc3545',
                        '#ffc107'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }
    
    // Response Time Chart
    const responseTimeCanvas = document.getElementById('responseTimeChart');
    if (responseTimeCanvas) {
        Dashboard.charts.responseTime = new Chart(responseTimeCanvas, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Response Time (ms)',
                    data: [],
                    borderColor: '#007bff',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
}

/**
 * Initialize device grid functionality
 */
function initializeDeviceGrid() {
    const deviceGrid = document.querySelector('[data-device-grid]');
    if (!deviceGrid) return;
    
    // Device card click handlers
    deviceGrid.addEventListener('click', function(e) {
        const deviceCard = e.target.closest('[data-device-card]');
        if (deviceCard) {
            const deviceId = deviceCard.getAttribute('data-device-id');
            if (deviceId) {
                window.location.href = `/device/${deviceId}`;
            }
        }
    });
    
    // Quick action handlers
    deviceGrid.addEventListener('click', function(e) {
        const quickAction = e.target.closest('[data-quick-action]');
        if (quickAction) {
            e.stopPropagation();
            const action = quickAction.getAttribute('data-quick-action');
            const deviceId = quickAction.closest('[data-device-card]')?.getAttribute('data-device-id');
            
            if (action && deviceId) {
                handleQuickAction(action, deviceId);
            }
        }
    });
}

/**
 * Initialize filter functionality
 */
function initializeFilters() {
    const filters = document.querySelectorAll('[data-filter]');
    
    filters.forEach(filter => {
        filter.addEventListener('change', function() {
            applyFilters();
        });
    });
}

/**
 * Set up dashboard-specific socket handlers
 */
function setupDashboardSocket() {
    if (!HomeNetMon.socket) return;
    
    // Listen for device updates
    HomeNetMon.socket.on('device_status_update', function(data) {
        updateDeviceCard(data);
        updateCharts();
    });
    
    // Listen for monitoring summaries
    HomeNetMon.socket.on('monitoring_summary', function(data) {
        updateNetworkChart(data);
        updateQuickStats(data);
    });
    
    // Join dashboard updates room
    HomeNetMon.socket.emit('join', 'updates_device_status');
    HomeNetMon.socket.emit('join', 'updates_monitoring_summary');
}

/**
 * Update device card with real-time data
 */
function updateDeviceCard(data) {
    if (!data || !data.device_id) return;
    
    const deviceCard = document.querySelector(`[data-device-card][data-device-id="${data.device_id}"]`);
    if (!deviceCard) return;
    
    // Update status badge
    const statusBadge = deviceCard.querySelector('[data-device-status]');
    if (statusBadge) {
        statusBadge.className = `badge badge-${getStatusColor(data.status)}`;
        statusBadge.textContent = data.status.toUpperCase();
    }
    
    // Update response time
    const responseTimeEl = deviceCard.querySelector('[data-device-response-time]');
    if (responseTimeEl) {
        responseTimeEl.textContent = data.response_time ? `${data.response_time}ms` : 'N/A';
    }
    
    // Update last seen
    const lastSeenEl = deviceCard.querySelector('[data-device-last-seen]');
    if (lastSeenEl && data.timestamp) {
        lastSeenEl.textContent = formatTimestamp(data.timestamp);
    }
    
    // Update card background based on status
    deviceCard.className = deviceCard.className.replace(/border-\w+/, `border-${getStatusColor(data.status)}`);
}

/**
 * Update network overview chart
 */
function updateNetworkChart(data) {
    if (!Dashboard.charts.network || !data) return;
    
    const chart = Dashboard.charts.network;
    chart.data.datasets[0].data = [
        data.devices_up || 0,
        data.devices_down || 0,
        data.devices_warning || 0
    ];
    chart.update('none');
}

/**
 * Update quick stats
 */
function updateQuickStats(data) {
    if (!data) return;
    
    const statElements = [
        { key: 'total_devices', selector: '[data-quick-stat="total_devices"]' },
        { key: 'devices_up', selector: '[data-quick-stat="devices_up"]' },
        { key: 'devices_down', selector: '[data-quick-stat="devices_down"]' },
        { key: 'active_alerts', selector: '[data-quick-stat="active_alerts"]' }
    ];
    
    statElements.forEach(stat => {
        const element = document.querySelector(stat.selector);
        if (element) {
            element.textContent = data[stat.key] || '0';
        }
    });
}

/**
 * Handle quick actions on device cards
 */
function handleQuickAction(action, deviceId) {
    switch (action) {
        case 'ping':
            performDevicePing(deviceId);
            break;
        case 'details':
            window.location.href = `/device/${deviceId}`;
            break;
        case 'toggle-monitoring':
            toggleDeviceMonitoring(deviceId);
            break;
        default:
            console.warn('Unknown quick action:', action);
    }
}

/**
 * Perform device ping
 */
function performDevicePing(deviceId) {
    if (!HomeNetMon.apiCall) return;
    
    HomeNetMon.apiCall(`/devices/${deviceId}/ping`, { method: 'POST' })
        .then(response => {
            console.log('Ping result:', response);
            showToast('Ping initiated', 'success');
        })
        .catch(error => {
            console.error('Ping failed:', error);
            showToast('Ping failed', 'error');
        });
}

/**
 * Toggle device monitoring
 */
function toggleDeviceMonitoring(deviceId) {
    if (!HomeNetMon.apiCall) return;
    
    HomeNetMon.apiCall(`/devices/${deviceId}/toggle-monitoring`, { method: 'POST' })
        .then(response => {
            console.log('Monitoring toggled:', response);
            showToast('Monitoring setting updated', 'success');
        })
        .catch(error => {
            console.error('Toggle monitoring failed:', error);
            showToast('Failed to update monitoring', 'error');
        });
}

/**
 * Apply filters to device grid
 */
function applyFilters() {
    const statusFilter = document.querySelector('[data-filter="status"]')?.value;
    const typeFilter = document.querySelector('[data-filter="type"]')?.value;
    const groupFilter = document.querySelector('[data-filter="group"]')?.value;
    
    const deviceCards = document.querySelectorAll('[data-device-card]');
    
    deviceCards.forEach(card => {
        let visible = true;
        
        // Apply status filter
        if (statusFilter && statusFilter !== 'all') {
            const deviceStatus = card.getAttribute('data-device-status');
            if (deviceStatus !== statusFilter) {
                visible = false;
            }
        }
        
        // Apply type filter
        if (typeFilter && typeFilter !== 'all') {
            const deviceType = card.getAttribute('data-device-type');
            if (deviceType !== typeFilter) {
                visible = false;
            }
        }
        
        // Apply group filter
        if (groupFilter && groupFilter !== 'all') {
            const deviceGroup = card.getAttribute('data-device-group');
            if (deviceGroup !== groupFilter) {
                visible = false;
            }
        }
        
        card.style.display = visible ? '' : 'none';
    });
}

/**
 * Update charts with latest data
 */
function updateCharts() {
    // This would be called periodically to update charts
    // Implementation depends on specific chart data needs
}

/**
 * Enhanced loading state management with skeletons
 */
function showLoadingWithSkeletons(duration = 1500) {
    if (window.skeletonManager) {
        window.skeletonManager.showLoadingState(duration);
    }
}

/**
 * Show toast notification using enhanced ToastManager
 */
function showToast(message, type = 'info', duration = 4000, options = {}) {
    if (window.toastManager) {
        return window.toastManager.show(message, type, duration, options);
    } else {
        // Fallback to simple implementation if ToastManager not available
        console.warn('ToastManager not available, using fallback');
        const toast = document.createElement('div');
        toast.className = `alert alert-${type === 'success' ? 'success' : type === 'error' ? 'danger' : 'info'} toast-notification`;
        toast.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        toast.textContent = message;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.remove();
        }, duration || 3000);
    }
}

/**
 * Get status color helper (shared with app.js)
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
 * Format timestamp helper (shared with app.js)
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
 * Initialize performance metrics toggle functionality
 */
function initializePerformanceToggle() {
    const toggleBtn = document.getElementById('toggle-metrics-btn');
    const sidebar = document.getElementById('performance-metrics-sidebar');
    
    if (!toggleBtn || !sidebar) return;
    
    // Load saved preference
    const showMetrics = window.userPrefs.get('showPerformanceMetrics');
    
    // Set initial state
    updateMetricsVisibility(showMetrics);
    
    // Add click handler
    toggleBtn.addEventListener('click', function() {
        const isVisible = sidebar.style.display !== 'none';
        const newState = !isVisible;
        
        updateMetricsVisibility(newState);
        
        // Save preference
        window.userPrefs.set('showPerformanceMetrics', newState);
        
        // Show feedback
        showToast(`Performance metrics ${newState ? 'shown' : 'hidden'}`, 'info');
    });
}

/**
 * Update performance metrics visibility
 */
function updateMetricsVisibility(show) {
    const toggleBtn = document.getElementById('toggle-metrics-btn');
    const sidebar = document.getElementById('performance-metrics-sidebar');
    const parentRow = sidebar.parentElement;
    
    if (show) {
        sidebar.style.display = 'block';
        toggleBtn.querySelector('span').textContent = 'Hide Metrics';
        toggleBtn.querySelector('i').className = 'bi bi-eye-slash me-2';
        
        // Adjust main content column width - find the network topology div
        const mainContent = parentRow.querySelector('.col-lg-8');
        if (mainContent) {
            mainContent.className = 'col-lg-8 mb-4';
        }
    } else {
        sidebar.style.display = 'none';
        toggleBtn.querySelector('span').textContent = 'Show Metrics';
        toggleBtn.querySelector('i').className = 'bi bi-bar-chart me-2';
        
        // Expand main content to full width
        const mainContent = parentRow.querySelector('.col-lg-8');
        if (mainContent) {
            mainContent.className = 'col-lg-12 mb-4';
        }
    }
}

/**
 * Apply saved user preferences on page load
 */
function applyUserPreferences() {
    // Apply filter preferences
    const filterType = document.getElementById('filter-type');
    const filterGroup = document.getElementById('filter-group');
    const filterStatus = document.getElementById('filter-status');
    
    if (filterType) filterType.value = window.userPrefs.get('filterType');
    if (filterGroup) filterGroup.value = window.userPrefs.get('filterGroup');
    if (filterStatus) filterStatus.value = window.userPrefs.get('filterStatus');
    
    // Apply view mode preference if available
    const viewMode = window.userPrefs.get('viewMode');
    if (viewMode && window.currentView !== undefined) {
        window.currentView = viewMode;
    }
}

/**
 * Initialize preference saving for filter changes
 */
function initializeFilterPreferences() {
    const filterType = document.getElementById('filter-type');
    const filterGroup = document.getElementById('filter-group');
    const filterStatus = document.getElementById('filter-status');
    
    if (filterType) {
        filterType.addEventListener('change', function() {
            window.userPrefs.set('filterType', this.value);
        });
    }
    
    if (filterGroup) {
        filterGroup.addEventListener('change', function() {
            window.userPrefs.set('filterGroup', this.value);
        });
    }
    
    if (filterStatus) {
        filterStatus.addEventListener('change', function() {
            window.userPrefs.set('filterStatus', this.value);
        });
    }
}

/**
 * Skeleton Loading Management
 */
class SkeletonManager {
    constructor() {
        this.skeletonContainer = document.getElementById('dashboard-skeleton');
        this.performanceSkeleton = document.getElementById('performance-skeleton');
        this.dataVisualizationsContainer = document.getElementById('data-visualizations');
        this.statusSummaryContainer = document.getElementById('status-summary');
    }
    
    showSkeletons(options = {}) {
        const { showPerformance = true } = options;
        
        if (this.skeletonContainer) {
            this.skeletonContainer.style.display = 'block';
        }
        
        // Show/hide performance skeleton based on preference
        if (this.performanceSkeleton) {
            this.performanceSkeleton.style.display = showPerformance ? 'block' : 'none';
        }
        
        // Hide real content
        if (this.dataVisualizationsContainer) {
            this.dataVisualizationsContainer.style.display = 'none';
        }
        if (this.statusSummaryContainer) {
            this.statusSummaryContainer.style.display = 'none';
        }
    }
    
    hideSkeletons() {
        if (this.skeletonContainer) {
            this.skeletonContainer.style.display = 'none';
        }
        
        // Show real content with animation
        if (this.dataVisualizationsContainer) {
            this.dataVisualizationsContainer.style.display = 'block';
            this.dataVisualizationsContainer.classList.add('fade-in');
        }
        if (this.statusSummaryContainer) {
            this.statusSummaryContainer.style.display = 'block';
            this.statusSummaryContainer.classList.add('fade-in');
        }
    }
    
    showLoadingState(duration = 1500) {
        const showPerformance = window.userPrefs.get('showPerformanceMetrics');
        this.showSkeletons({ showPerformance });
        
        setTimeout(() => {
            this.hideSkeletons();
        }, duration);
    }
}

// Global skeleton manager
window.skeletonManager = new SkeletonManager();

/**
 * Toast Manager for Enhanced Notifications
 */
class ToastManager {
    constructor() {
        this.toasts = [];
        this.maxToasts = 3;
        this.container = this.createContainer();
        this.toastId = 0;
    }
    
    createContainer() {
        let container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.className = 'position-fixed top-0 end-0 p-3';
            container.style.cssText = 'z-index: 1060; max-width: 350px;';
            document.body.appendChild(container);
        }
        return container;
    }
    
    show(message, type = 'info', duration = 4000, options = {}) {
        const { persistent = false, actions = [] } = options;
        
        // Remove oldest toast if we've reached the limit
        if (this.toasts.length >= this.maxToasts) {
            const oldestToast = this.toasts.shift();
            this.removeToast(oldestToast, false);
        }
        
        const toast = this.createToast(message, type, duration, persistent, actions);
        this.toasts.push(toast);
        this.container.appendChild(toast.element);
        
        // Animate in
        setTimeout(() => {
            toast.element.classList.add('show');
        }, 10);
        
        // Auto-dismiss if not persistent
        if (!persistent && duration > 0) {
            toast.timeoutId = setTimeout(() => {
                this.removeToast(toast);
            }, duration);
        }
        
        return toast;
    }
    
    createToast(message, type, duration, persistent, actions) {
        const toastId = `toast-${++this.toastId}`;
        const iconMap = {
            'success': 'check-circle-fill',
            'error': 'exclamation-circle-fill',
            'warning': 'exclamation-triangle-fill',
            'info': 'info-circle-fill',
            'danger': 'x-circle-fill'
        };
        
        const colorMap = {
            'success': 'success',
            'error': 'danger',
            'warning': 'warning',
            'info': 'primary',
            'danger': 'danger'
        };
        
        const icon = iconMap[type] || iconMap.info;
        const color = colorMap[type] || colorMap.info;
        
        const element = document.createElement('div');
        element.id = toastId;
        element.className = `toast fade`;
        element.setAttribute('role', 'alert');
        element.setAttribute('aria-live', 'assertive');
        element.setAttribute('aria-atomic', 'true');
        
        let actionsHtml = '';
        if (actions.length > 0) {
            actionsHtml = actions.map(action => 
                `<button type="button" class="btn btn-sm btn-outline-${color} me-2" onclick="${action.onClick}">${action.text}</button>`
            ).join('');
        }
        
        element.innerHTML = `
            <div class="toast-header bg-${color} text-white">
                <i class="bi bi-${icon} me-2"></i>
                <strong class="me-auto">${this.getTypeTitle(type)}</strong>
                <small class="text-white-50">${new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</small>
                <button type="button" class="btn-close btn-close-white" onclick="window.toastManager.dismissToast('${toastId}')" aria-label="Close"></button>
            </div>
            <div class="toast-body">
                <div class="mb-2">${message}</div>
                ${actionsHtml ? `<div class="toast-actions">${actionsHtml}</div>` : ''}
            </div>
        `;
        
        const toast = {
            id: toastId,
            element: element,
            type: type,
            persistent: persistent,
            timeoutId: null
        };
        
        return toast;
    }
    
    getTypeTitle(type) {
        const titles = {
            'success': 'Success',
            'error': 'Error',
            'warning': 'Warning',
            'info': 'Info',
            'danger': 'Error'
        };
        return titles[type] || 'Notification';
    }
    
    removeToast(toast, animate = true) {
        if (!toast || !toast.element) return;
        
        // Clear timeout if exists
        if (toast.timeoutId) {
            clearTimeout(toast.timeoutId);
        }
        
        // Remove from array
        const index = this.toasts.findIndex(t => t.id === toast.id);
        if (index > -1) {
            this.toasts.splice(index, 1);
        }
        
        // Animate out and remove
        if (animate) {
            toast.element.classList.remove('show');
            setTimeout(() => {
                if (toast.element && toast.element.parentNode) {
                    toast.element.remove();
                }
            }, 300);
        } else {
            toast.element.remove();
        }
    }
    
    dismissToast(toastId) {
        const toast = this.toasts.find(t => t.id === toastId);
        if (toast) {
            this.removeToast(toast);
        }
    }
    
    clear() {
        this.toasts.forEach(toast => this.removeToast(toast, false));
        this.toasts = [];
    }
}

// Global toast manager
window.toastManager = new ToastManager();

/**
 * Keyboard Shortcuts Manager
 */
class KeyboardShortcuts {
    constructor() {
        this.shortcuts = {
            'r': {
                action: 'refresh',
                description: 'Refresh dashboard',
                handler: () => this.refreshDashboard()
            },
            'f': {
                action: 'filters',
                description: 'Toggle filter panel',
                handler: () => this.toggleFilters()
            },
            'v': {
                action: 'view',
                description: 'Toggle performance metrics',
                handler: () => this.toggleView()
            },
            's': {
                action: 'scan',
                description: 'Start network scan',
                handler: () => this.startScan()
            },
            'p': {
                action: 'performance',
                description: 'Open performance dashboard',
                handler: () => this.openPerformanceDashboard()
            },
            'h': {
                action: 'help',
                description: 'Show keyboard shortcuts',
                handler: () => this.showHelp()
            },
            'escape': {
                action: 'escape',
                description: 'Close modals/panels',
                handler: () => this.handleEscape()
            }
        };
        
        this.isEnabled = true;
        this.helpVisible = false;
        this.init();
    }
    
    init() {
        document.addEventListener('keydown', (event) => {
            this.handleKeydown(event);
        });
        
        // Add visual indicators to buttons
        this.addShortcutIndicators();
    }
    
    handleKeydown(event) {
        // Don't trigger shortcuts when typing in form fields
        if (this.shouldIgnoreShortcut(event)) {
            return;
        }
        
        const key = event.key.toLowerCase();
        const shortcut = this.shortcuts[key];
        
        if (shortcut && this.isEnabled) {
            event.preventDefault();
            shortcut.handler();
            this.showShortcutFeedback(shortcut.description);
        }
    }
    
    shouldIgnoreShortcut(event) {
        // Ignore if modifier keys are pressed (except for specific combinations)
        if (event.ctrlKey || event.altKey || event.metaKey) {
            return true;
        }
        
        // Ignore if focus is on form elements
        const activeElement = document.activeElement;
        if (activeElement) {
            const tagName = activeElement.tagName.toLowerCase();
            const inputTypes = ['input', 'textarea', 'select', 'button'];
            if (inputTypes.includes(tagName) || activeElement.contentEditable === 'true') {
                return true;
            }
        }
        
        return false;
    }
    
    refreshDashboard() {
        const refreshBtn = document.getElementById('refresh-btn');
        if (refreshBtn) {
            refreshBtn.click();
        } else {
            // Fallback: trigger refresh functionality directly
            if (window.skeletonManager) {
                window.skeletonManager.showLoadingState();
            }
            window.toastManager.show('Dashboard refreshed', 'info', 2000);
        }
    }
    
    toggleFilters() {
        // Look for filter panels or buttons to toggle
        const filterSection = document.querySelector('.search-filter-section');
        const filterToggleBtn = document.querySelector('[data-bs-toggle="collapse"][data-bs-target*="filter"]');
        
        if (filterToggleBtn) {
            filterToggleBtn.click();
        } else if (filterSection) {
            const isVisible = filterSection.style.display !== 'none';
            filterSection.style.display = isVisible ? 'none' : 'block';
            window.toastManager.show(`Filters ${isVisible ? 'hidden' : 'shown'}`, 'info', 1500);
        } else {
            window.toastManager.show('Filter panel not found', 'warning', 2000);
        }
    }
    
    toggleView() {
        const toggleBtn = document.getElementById('toggle-metrics-btn');
        if (toggleBtn) {
            toggleBtn.click();
        } else {
            window.toastManager.show('View toggle not available', 'warning', 2000);
        }
    }
    
    startScan() {
        const scanBtn = document.getElementById('scan-btn');
        if (scanBtn) {
            scanBtn.click();
        } else {
            window.toastManager.show('Network scan not available', 'warning', 2000);
        }
    }
    
    openPerformanceDashboard() {
        window.location.href = '/performance-dashboard';
    }
    
    handleEscape() {
        // Close any open modals
        const modals = document.querySelectorAll('.modal.show');
        modals.forEach(modal => {
            const bootstrapModal = bootstrap.Modal.getInstance(modal);
            if (bootstrapModal) {
                bootstrapModal.hide();
            }
        });
        
        // Hide help if visible
        if (this.helpVisible) {
            this.hideHelp();
        }
        
        // Close any dropdowns
        const dropdowns = document.querySelectorAll('.dropdown-menu.show');
        dropdowns.forEach(dropdown => {
            dropdown.classList.remove('show');
        });
    }
    
    showHelp() {
        if (this.helpVisible) {
            this.hideHelp();
            return;
        }
        
        const helpContent = Object.entries(this.shortcuts)
            .filter(([key]) => key !== 'escape') // Don't show escape in help
            .map(([key, shortcut]) => 
                `<div class="d-flex justify-content-between align-items-center mb-2">
                    <span>${shortcut.description}</span>
                    <kbd class="kbd-shortcut">${key.toUpperCase()}</kbd>
                </div>`
            ).join('');
            
        const helpToast = window.toastManager.show(
            `<div class="keyboard-shortcuts-help">
                <h6 class="mb-3">Keyboard Shortcuts</h6>
                ${helpContent}
                <small class="text-muted mt-2 d-block">Press H again or ESC to close</small>
            </div>`,
            'info',
            0, // Don't auto-dismiss
            { persistent: true }
        );
        
        this.helpVisible = true;
        this.currentHelpToast = helpToast;
    }
    
    hideHelp() {
        if (this.currentHelpToast) {
            window.toastManager.removeToast(this.currentHelpToast);
            this.helpVisible = false;
            this.currentHelpToast = null;
        }
    }
    
    addShortcutIndicators() {
        // Add keyboard shortcut hints to buttons
        const buttonMappings = {
            'refresh-btn': 'R',
            'scan-btn': 'S',
            'toggle-metrics-btn': 'V'
        };
        
        Object.entries(buttonMappings).forEach(([buttonId, key]) => {
            const button = document.getElementById(buttonId);
            if (button) {
                const currentTitle = button.getAttribute('title') || '';
                button.setAttribute('title', `${currentTitle} (${key})`.trim());
                
                // Add visual keyboard indicator
                const keyIndicator = document.createElement('small');
                keyIndicator.className = 'keyboard-hint ms-1';
                keyIndicator.textContent = key;
                keyIndicator.style.cssText = 'opacity: 0.7; font-size: 0.75rem;';
                
                // Only add if not already present
                if (!button.querySelector('.keyboard-hint')) {
                    button.appendChild(keyIndicator);
                }
            }
        });
    }
    
    showShortcutFeedback(description) {
        // Brief visual feedback when shortcut is used
        const feedback = document.createElement('div');
        feedback.className = 'shortcut-feedback position-fixed';
        feedback.style.cssText = `
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(0, 0, 0, 0.8);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 0.375rem;
            font-size: 0.875rem;
            z-index: 9999;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.2s ease;
        `;
        feedback.textContent = description;
        
        document.body.appendChild(feedback);
        
        // Animate in
        setTimeout(() => {
            feedback.style.opacity = '1';
        }, 10);
        
        // Remove after delay
        setTimeout(() => {
            feedback.style.opacity = '0';
            setTimeout(() => {
                feedback.remove();
            }, 200);
        }, 1500);
    }
    
    enable() {
        this.isEnabled = true;
    }
    
    disable() {
        this.isEnabled = false;
    }
}

// Global keyboard shortcuts manager
window.keyboardShortcuts = new KeyboardShortcuts();

/**
 * Device Grid Management Functions
 */

/**
 * Render devices in the dashboard grid
 */
function renderDeviceGrid(devices) {
    const devicesGrid = document.getElementById('devices-grid');
    const noDevicesState = document.getElementById('no-devices-state');
    const loadingIndicator = document.getElementById('loading-indicator');
    const deviceCountSummary = document.getElementById('device-count-summary');
    
    if (!devicesGrid) return;
    
    // Hide loading indicator
    if (loadingIndicator) {
        loadingIndicator.style.display = 'none';
    }
    
    // Update device count summary
    if (deviceCountSummary) {
        const totalDevices = devices.length;
        const onlineDevices = devices.filter(d => d.status === 'up').length;
        const offlineDevices = devices.filter(d => d.status === 'down').length;
        deviceCountSummary.textContent = `${totalDevices} devices total • ${onlineDevices} online • ${offlineDevices} offline`;
    }
    
    if (!devices || devices.length === 0) {
        devicesGrid.style.display = 'none';
        if (noDevicesState) {
            noDevicesState.style.display = 'block';
        }
        return;
    }
    
    // Show grid and hide empty state
    devicesGrid.style.display = 'block';
    if (noDevicesState) {
        noDevicesState.style.display = 'none';
    }
    
    // Clear existing content
    devicesGrid.innerHTML = '';
    
    // Create device cards
    devices.forEach((device, index) => {
        const deviceCard = createDeviceCard(device);
        deviceCard.style.animationDelay = `${index * 0.05}s`;
        devicesGrid.appendChild(deviceCard);
    });
}

/**
 * Create a device card element
 */
function createDeviceCard(device) {
    const colDiv = document.createElement('div');
    colDiv.className = 'col-sm-6 col-md-4 col-lg-3 col-xl-2';
    
    const cardDiv = document.createElement('div');
    cardDiv.className = `card device-card status-${device.status || 'unknown'} fade-in`;
    cardDiv.setAttribute('data-device-id', device.id);
    cardDiv.setAttribute('data-device-status', device.status || 'unknown');
    cardDiv.style.cursor = 'pointer';
    
    // Status colors for the stripe
    const statusColors = {
        'up': '#28a745',
        'down': '#dc3545', 
        'warning': '#ffc107',
        'unknown': '#6c757d'
    };
    cardDiv.style.setProperty('--status-color', statusColors[device.status] || statusColors.unknown);
    
    const cardBody = document.createElement('div');
    cardBody.className = 'card-body';
    
    // Device name and IP
    const deviceName = document.createElement('div');
    deviceName.className = 'device-name';
    deviceName.textContent = device.display_name || device.hostname || 'Unknown Device';
    
    const deviceIp = document.createElement('div');
    deviceIp.className = 'device-ip';
    deviceIp.textContent = device.ip_address || 'No IP';
    
    // Device stats
    const deviceStats = document.createElement('div');
    deviceStats.className = 'device-stats';
    
    const responseTime = document.createElement('div');
    responseTime.className = 'response-time';
    if (device.avg_response_time && device.avg_response_time > 0) {
        responseTime.innerHTML = `<i class="bi bi-speedometer2"></i> ${Math.round(device.avg_response_time)}ms`;
    } else {
        responseTime.innerHTML = `<i class="bi bi-question-circle"></i> No data`;
    }
    
    const lastSeen = document.createElement('div');
    lastSeen.className = 'last-seen';
    if (device.last_seen) {
        const lastSeenDate = new Date(device.last_seen);
        const now = new Date();
        const diffMinutes = Math.floor((now - lastSeenDate) / (1000 * 60));
        
        if (diffMinutes < 1) {
            lastSeen.textContent = 'Just now';
        } else if (diffMinutes < 60) {
            lastSeen.textContent = `${diffMinutes}m ago`;
        } else if (diffMinutes < 1440) {
            lastSeen.textContent = `${Math.floor(diffMinutes / 60)}h ago`;
        } else {
            lastSeen.textContent = `${Math.floor(diffMinutes / 1440)}d ago`;
        }
    } else {
        lastSeen.textContent = 'Never';
    }
    
    deviceStats.appendChild(responseTime);
    deviceStats.appendChild(lastSeen);
    
    cardBody.appendChild(deviceName);
    cardBody.appendChild(deviceIp);
    cardBody.appendChild(deviceStats);
    cardDiv.appendChild(cardBody);
    
    // Add click handler for navigation to device details
    cardDiv.addEventListener('click', function() {
        window.location.href = `/device/${device.id}`;
    });
    
    colDiv.appendChild(cardDiv);
    return colDiv;
}

/**
 * Filter devices based on search and status
 */
function filterDevices() {
    const searchTerm = document.getElementById('search-input')?.value?.toLowerCase() || '';
    const statusFilter = document.getElementById('status-filter')?.value || '';
    
    const deviceCards = document.querySelectorAll('[data-device-id]');
    let visibleCount = 0;
    
    deviceCards.forEach(card => {
        const deviceName = card.querySelector('.device-name')?.textContent?.toLowerCase() || '';
        const deviceIp = card.querySelector('.device-ip')?.textContent?.toLowerCase() || '';
        const deviceStatus = card.getAttribute('data-device-status') || '';
        
        const matchesSearch = !searchTerm || 
            deviceName.includes(searchTerm) || 
            deviceIp.includes(searchTerm);
        
        const matchesStatus = !statusFilter || deviceStatus === statusFilter;
        
        const shouldShow = matchesSearch && matchesStatus;
        
        const colDiv = card.parentElement;
        if (shouldShow) {
            colDiv.style.display = 'block';
            visibleCount++;
        } else {
            colDiv.style.display = 'none';
        }
    });
    
    // Update summary
    const deviceCountSummary = document.getElementById('device-count-summary');
    if (deviceCountSummary) {
        const totalCards = deviceCards.length;
        if (searchTerm || statusFilter) {
            deviceCountSummary.textContent = `Showing ${visibleCount} of ${totalCards} devices`;
        }
    }
    
    // Show/hide empty state
    const devicesGrid = document.getElementById('devices-grid');
    const noDevicesState = document.getElementById('no-devices-state');
    if (visibleCount === 0 && (searchTerm || statusFilter)) {
        if (devicesGrid) devicesGrid.style.display = 'none';
        if (noDevicesState) {
            noDevicesState.style.display = 'block';
            noDevicesState.querySelector('h4').textContent = 'No Matching Devices';
            noDevicesState.querySelector('p').textContent = 'No devices match your search criteria. Try adjusting your filters.';
        }
    } else if (visibleCount > 0) {
        if (devicesGrid) devicesGrid.style.display = 'block';
        if (noDevicesState) noDevicesState.style.display = 'none';
    }
}

/**
 * Load devices from API
 */
async function loadDevices() {
    try {
        const loadingIndicator = document.getElementById('loading-indicator');
        if (loadingIndicator) {
            loadingIndicator.style.display = 'block';
        }
        
        const response = await fetch('/api/devices');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const devices = await response.json();
        renderDeviceGrid(devices);
        
        // Initialize filter handlers after devices are loaded
        const searchInput = document.getElementById('search-input');
        const statusFilter = document.getElementById('status-filter');
        const searchClear = document.getElementById('search-clear');
        
        if (searchInput) {
            searchInput.addEventListener('input', filterDevices);
            searchInput.addEventListener('input', function() {
                if (searchClear) {
                    searchClear.style.display = this.value ? 'block' : 'none';
                }
            });
        }
        
        if (statusFilter) {
            statusFilter.addEventListener('change', filterDevices);
        }
        
        if (searchClear) {
            searchClear.addEventListener('click', function() {
                if (searchInput) {
                    searchInput.value = '';
                    searchInput.dispatchEvent(new Event('input'));
                }
            });
        }
        
    } catch (error) {
        console.error('Error loading devices:', error);
        
        const loadingIndicator = document.getElementById('loading-indicator');
        if (loadingIndicator) {
            loadingIndicator.innerHTML = `
                <div class="text-center py-5">
                    <i class="bi bi-exclamation-triangle text-warning mb-3" style="font-size: 3rem;"></i>
                    <h5 class="text-muted">Failed to Load Devices</h5>
                    <p class="text-muted mb-3">Unable to fetch device information.</p>
                    <button class="btn btn-primary" onclick="loadDevices()">
                        <i class="bi bi-arrow-clockwise me-2"></i>Try Again
                    </button>
                </div>
            `;
        }
    }
}

// Export dashboard functions
window.Dashboard.updateDeviceCard = updateDeviceCard;
window.Dashboard.applyFilters = applyFilters;
window.Dashboard.togglePerformanceMetrics = updateMetricsVisibility;
window.Dashboard.renderDeviceGrid = renderDeviceGrid;
window.Dashboard.loadDevices = loadDevices;
window.Dashboard.userPrefs = window.userPrefs;
window.Dashboard.skeletonManager = window.skeletonManager;
window.Dashboard.toastManager = window.toastManager;
window.Dashboard.keyboardShortcuts = window.keyboardShortcuts;
window.Dashboard.showToast = showToast;

// Load devices when dashboard is initialized
document.addEventListener('DOMContentLoaded', function() {
    if (document.querySelector('[data-dashboard]')) {
        // Load devices after a short delay to allow UI to render
        setTimeout(loadDevices, 500);
    }
});