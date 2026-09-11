/**
 * Dashboard Page Controller
 * Handles device display, filtering, scanning, and real-time updates
 */

// State Management
let socket;
let devicesData = [];
let currentView = 'grid';
let advancedMode = false;
let filters = {
    search: '',
    status: '',
    type: '',
    sortBy: 'name',
    group: '',
    showArchived: false   // devices unmonitored for staleness are hidden by default
};
const esc = (v) => (window.escapeHtml ? window.escapeHtml(v) : String(v == null ? '' : v));

// Utility: Debounce function for performance
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

// Page Visibility API state
let pollingInterval = null;
let isPageVisible = true;

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    initializeSocket();
    loadDevices();
    setupEventListeners();
    checkScanStatus();

    // Check for saved preferences
    const savedView = localStorage.getItem('deviceView') || 'grid';
    if (savedView === 'table') {
        switchToTableView();
    }

    const savedAdvanced = localStorage.getItem('advancedMode') === 'true';
    if (savedAdvanced) {
        toggleAdvancedPanel();
    }

    // Set up polling with Page Visibility API
    startPolling();
    setupPageVisibilityHandling();
});

// Start polling interval
function startPolling() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
    }
    // Fallback refresh; live changes arrive over the WebSocket room subscribed below.
    pollingInterval = setInterval(loadDevices, 120000);
}

// Stop polling interval
function stopPolling() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
    }
}

// Handle page visibility changes
function setupPageVisibilityHandling() {
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            // Page is hidden - pause polling
            isPageVisible = false;
            stopPolling();
        } else {
            // Page is visible - resume polling and refresh immediately
            isPageVisible = true;
            loadDevices(); // Refresh data immediately when tab becomes visible
            startPolling();
        }
    });
}

// Socket.IO initialization
function initializeSocket() {
    socket = io();

    socket.on('connect', function() {
        updateNetworkStatus(true);
        // Server pushes go to rooms; nothing arrives until the page joins them.
        socket.emit('subscribe_to_updates', { types: ['device_status', 'monitoring_summary', 'alerts'] });
    });

    socket.on('disconnect', function() {
        updateNetworkStatus(false);
    });

    // Scan progress events
    socket.on('scan_started', function(data) {
        showScanProgress();
        showNotification('Network scan started', 'info');
    });

    socket.on('scan_progress', function(data) {

        // Update real progress if available
        if (data.progress !== undefined && window.updateRealScanProgress) {
            window.updateRealScanProgress(data.progress);

            // Immediately update UI with real progress
            scanProgressValue = data.progress;
            document.getElementById('scan-progress-bar').style.width = data.progress + '%';
            document.getElementById('scan-progress-percentage').textContent = Math.floor(data.progress) + '%';

            // If we hit 100%, complete the scan
            if (data.progress >= 100) {
                completeScanProgress(data.devices_found || 0, data.new_devices || 0);
            }
        }

        if (data.phase) {
            document.getElementById('scan-phase-text').textContent = data.phase;
        }
        if (data.stage) {  // Also support 'stage' as an alias
            document.getElementById('scan-phase-text').textContent = data.stage;
        }

        if (data.devices_found !== undefined) {
            document.getElementById('devices-found').textContent = data.devices_found.toString();
        }
        if (data.new_devices !== undefined) {
            document.getElementById('new-devices').textContent = data.new_devices.toString();
        }
    });

    socket.on('scan_completed', function(data) {
        const devicesFound = data.devices_found || 0;
        completeScanProgress(devicesFound, 0);
        showNotification(`Scan completed: ${devicesFound} devices found`, 'success');
    });

    socket.on('scan_error', function(data) {
        closeScanProgress();
        hideScanStatus();
        const btn = document.getElementById('scan-network');
        btn.innerHTML = '<i class="bi bi-radar"></i> Scan Network';
        btn.disabled = false;
        showNotification(`Scan error: ${data.error || 'Unknown error'}`, 'error');
    });

    socket.on('device_status_update', handleDeviceStatusUpdate);
    socket.on('monitoring_summary', handleMonitoringSummary);
    socket.on('alert_update', debounce(loadDevices, 1500));
}

// Translate the monitor's per-ping event into a partial device record.
function handleDeviceStatusUpdate(data) {
    if (!data || data.device_id === undefined) return;
    const patch = { id: data.device_id, status: data.status, latest_response_time: data.response_time };
    if (data.response_time !== null && data.response_time !== undefined) patch.last_seen = data.timestamp;
    if (data.is_monitored !== undefined) patch.is_monitored = data.is_monitored;
    handleDeviceUpdate(patch);
}

// Event Listeners Setup
function setupEventListeners() {
    // Search with debounce for performance (300ms delay)
    const debouncedSearch = debounce(function(searchValue) {
        filters.search = searchValue.toLowerCase();
        filterAndDisplayDevices();
    }, 300);
    document.getElementById('device-search').addEventListener('input', function(e) {
        debouncedSearch(e.target.value);
    });

    // View Toggle
    document.getElementById('grid-view').addEventListener('click', switchToGridView);
    document.getElementById('table-view').addEventListener('click', switchToTableView);

    // Action Buttons
    document.getElementById('refresh-all').addEventListener('click', refreshAllDevices);
    document.getElementById('scan-network').addEventListener('click', scanNetwork);
    document.getElementById('toggle-advanced').addEventListener('click', toggleAdvancedPanel);

    // Advanced Filters
    document.getElementById('status-filter').addEventListener('change', function(e) {
        filters.status = e.target.value;
        filterAndDisplayDevices();
    });

    document.getElementById('type-filter').addEventListener('change', function(e) {
        filters.type = e.target.value;
        filterAndDisplayDevices();
    });

    document.getElementById('sort-by').addEventListener('change', function(e) {
        filters.sortBy = e.target.value;
        filterAndDisplayDevices();
    });
    const groupFilter = document.getElementById('group-filter');
    if (groupFilter) {
        groupFilter.addEventListener('change', function(e) {
            filters.group = e.target.value;
            filterAndDisplayDevices();
        });
    }
    const archivedToggle = document.getElementById('show-archived');
    if (archivedToggle) {
        archivedToggle.addEventListener('change', function(e) {
            filters.showArchived = e.target.checked;
            updateStats();
            filterAndDisplayDevices();
        });
    }
    // The navbar search navigates here with ?search=<term>
    const initialSearch = new URLSearchParams(window.location.search).get('search');
    if (initialSearch) {
        document.getElementById('device-search').value = initialSearch;
        filters.search = initialSearch.toLowerCase();
    }

    // Bulk Actions
    document.getElementById('bulk-enable').addEventListener('click', bulkEnableMonitoring);
    document.getElementById('bulk-disable').addEventListener('click', bulkDisableMonitoring);

    // Export
    document.getElementById('export-csv').addEventListener('click', exportToCSV);

    // Presets
    document.getElementById('monitor-preset-security').addEventListener('click', () => applyMonitoringPreset('security'));
    document.getElementById('monitor-preset-essential').addEventListener('click', () => applyMonitoringPreset('essential'));
}

// Load devices from API
async function loadDevices() {
    try {
        const response = await fetch('/api/devices');

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const text = await response.text();

        let data;
        try {
            data = JSON.parse(text);
        } catch (parseError) {
            throw parseError;
        }

        devicesData = data.devices || [];
        refreshGroupOptions();
        updateStats();
        filterAndDisplayDevices();
        document.getElementById('loading-devices').classList.add('hidden');
        loadSummary();
    } catch (error) {
        const loading = document.getElementById('loading-devices');
        loading.textContent = 'Error loading devices: ' + error.message;
        loading.classList.add('text-danger');
    }
}

// Hero statistics: counts come from /api/monitoring/summary (one definition shared with
// the API and the analytics page); the average response time is computed from the grid.
let latestSummary = null;

async function loadSummary() {
    try {
        const response = await fetch('/api/monitoring/summary');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        applySummary(await response.json());
    } catch (error) {
        console.error('Summary unavailable:', error);
    }
}

function applySummary(summary) {
    if (!summary) return;
    latestSummary = summary;
    const set = (id, value) => { const el = document.getElementById(id); if (el && value !== undefined) el.textContent = value; };
    set('hero-devices-online', summary.devices_up);
    set('hero-total-devices', summary.monitored_devices);
    set('hero-alerts', summary.active_alerts);
    const totalEl = document.getElementById('hero-total-devices');
    if (totalEl && summary.total_devices !== undefined) {
        totalEl.title = `${summary.total_devices} in inventory (incl. archived / out of range)`;
    }
    const statusElement = document.getElementById('hero-network-status');
    if (statusElement && summary.monitored_devices !== undefined) {
        const pct = summary.monitored_devices ? (summary.devices_up / summary.monitored_devices) * 100 : 0;
        if (!summary.monitored_devices) {
            statusElement.innerHTML = '<span class="status-dot status-warning"></span>No devices';
        } else if (pct >= 90) {
            statusElement.innerHTML = '<span class="status-dot status-up"></span>Healthy';
        } else if (pct >= 70) {
            statusElement.innerHTML = '<span class="status-dot status-warning"></span>Degraded';
        } else {
            statusElement.innerHTML = '<span class="status-dot status-down"></span>Critical';
        }
    }
}

function updateStats() {
    const visible = filters.showArchived ? devicesData : devicesData.filter(d => d.is_monitored);
    const avgResponse = visible
        .filter(d => d.latest_response_time > 0)
        .reduce((acc, d, _, arr) => acc + d.latest_response_time / arr.length, 0);
    document.getElementById('hero-response-time').textContent =
        avgResponse ? Math.round(avgResponse) + ' ms' : '-- ms';
    if (!latestSummary) {
        // Until the summary arrives, show what the grid knows
        document.getElementById('hero-devices-online').textContent = visible.filter(d => d.status === 'up').length;
        document.getElementById('hero-total-devices').textContent = visible.length;
    }
}

// Filter and display devices
function filterAndDisplayDevices() {
    let filtered = filters.showArchived ? [...devicesData] : devicesData.filter(d => d.is_monitored);

    // Apply search filter
    if (filters.search) {
        filtered = filtered.filter(device => {
            const name = (device.display_name || device.hostname || '').toLowerCase();
            const ip = device.ip_address.toLowerCase();
            const status = device.status.toLowerCase();
            return name.includes(filters.search) ||
                   ip.includes(filters.search) ||
                   status.includes(filters.search);
        });
    }

    // Apply group filter (device_group is free text set in the device editor)
    if (filters.group) {
        filtered = filtered.filter(device => (device.device_group || '') === filters.group);
    }

    // Apply status filter
    if (filters.status) {
        filtered = filtered.filter(device => device.status === filters.status);
    }

    // Apply type filter on the classified device_type (the API also has /api/devices/types)
    if (filters.type) {
        const groups = {
            network: ['router', 'switch', 'gateway', 'access_point', 'network'],
            cameras: ['camera'],
            smart: ['smart_home', 'iot', 'speaker', 'tv', 'media', 'thermostat', 'sensor'],
            personal: ['computer', 'laptop', 'phone', 'tablet', 'apple', 'gaming']
        };
        const wanted = groups[filters.type] || [];
        filtered = filtered.filter(device => wanted.includes((device.device_type || 'unknown').toLowerCase()));
    }

    // Sort devices
    filtered.sort((a, b) => {
        switch(filters.sortBy) {
            case 'status':
                return a.status.localeCompare(b.status);
            case 'response':
                return (b.latest_response_time || 0) - (a.latest_response_time || 0);
            case 'lastseen':
                return new Date(b.last_seen || 0) - new Date(a.last_seen || 0);
            default: // name
                const nameA = a.display_name || a.hostname || a.ip_address;
                const nameB = b.display_name || b.hostname || b.ip_address;
                return nameA.localeCompare(nameB);
        }
    });

    // Update device count
    document.getElementById('device-count').textContent = filtered.length;

    // Display based on current view
    if (currentView === 'grid') {
        displayGridView(filtered);
    } else {
        displayTableView(filtered);
    }

    // Show/hide no devices message
    const noDevicesElement = document.getElementById('no-devices');
    if (filtered.length === 0) {
        noDevicesElement.classList.remove('hidden');
    } else {
        noDevicesElement.classList.add('hidden');
    }
}

// Keep the group <select> in sync with the groups that exist
function refreshGroupOptions() {
    const select = document.getElementById('group-filter');
    if (!select) return;
    const groups = [...new Set(devicesData.map(d => d.device_group).filter(Boolean))].sort((a, b) => a.localeCompare(b));
    const current = select.value;
    select.innerHTML = '<option value="">All groups</option>' +
        groups.map(g => `<option value="${esc(g)}">${esc(g)}</option>`).join('');
    if (groups.includes(current)) select.value = current; else filters.group = '';
}

function groupBadge(device) {
    const bits = [device.device_group, device.room_location].filter(Boolean);
    return bits.length ? `<span class="badge bg-secondary ms-1" title="Group / room">${esc(bits.join(' · '))}</span>` : '';
}

// Display devices in grid view
function displayGridView(devices) {
    const container = document.getElementById('devices-grid-view');
    container.innerHTML = devices.map(device => createDeviceCard(device)).join('');
}

// Create device card HTML
function createDeviceCard(device) {
    const statusClass = device.status || 'unknown';
    const name = device.display_name || device.hostname || 'Unknown Device';
    const lastSeen = formatLastSeen(device.last_seen);
    const responseTime = device.latest_response_time
        ? `${Math.round(device.latest_response_time)}ms`
        : '--';

    return `
        <div class="device-card" data-device-id="${device.id}" onclick="openDeviceDetails(${device.id})">
            <div class="device-name">
                <span class="status-dot status-${statusClass}"></span>
                ${esc(name)}${groupBadge(device)}
            </div>
            <div class="device-ip">${esc(device.ip_address)}</div>
            <div class="device-stats">
                <span><i class="bi bi-lightning"></i> ${responseTime}</span>
                <span><i class="bi bi-clock"></i> ${lastSeen}</span>
            </div>
        </div>
    `;
}

// Display devices in table view
function displayTableView(devices) {
    const tbody = document.getElementById('devices-table-body');
    tbody.innerHTML = devices.map(device => createDeviceRow(device)).join('');
}

// Create device table row HTML
function createDeviceRow(device) {
    const statusClass = device.status || 'unknown';
    const name = device.display_name || device.hostname || 'Unknown Device';
    const lastSeen = formatLastSeen(device.last_seen);
    const responseTime = device.latest_response_time
        ? `${Math.round(device.latest_response_time)}ms`
        : '--';
    const monitoringStatus = device.is_monitored ? 'Enabled' : 'Disabled';

    return `
        <tr data-device-id="${device.id}">
            <td><span class="status-dot status-${statusClass}"></span></td>
            <td>${esc(name)}${groupBadge(device)}</td>
            <td style="font-family: monospace;">${esc(device.ip_address)}</td>
            <td>${responseTime}</td>
            <td>${lastSeen}</td>
            <td>
                <span class="badge ${device.is_monitored ? 'bg-success' : 'bg-secondary'}">
                    ${monitoringStatus}
                </span>
            </td>
            <td>
                <button class="btn btn-sm btn-outline-light" onclick="openDeviceDetails(${device.id})">
                    <i class="bi bi-eye"></i>
                </button>
                <button class="btn btn-sm btn-outline-light" onclick="toggleMonitoring(${device.id}, event)">
                    <i class="bi bi-power"></i>
                </button>
            </td>
        </tr>
    `;
}

// Format last seen timestamp
function formatLastSeen(timestamp) {
    if (!timestamp) return 'Never';
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
    return `${Math.floor(diffMins / 1440)}d ago`;
}

// View switching functions
function switchToGridView() {
    currentView = 'grid';
    document.getElementById('grid-view').classList.add('active');
    document.getElementById('table-view').classList.remove('active');
    document.getElementById('devices-grid-view').style.display = 'grid';
    document.getElementById('devices-grid-view').classList.remove('hidden');
    document.getElementById('devices-table-view').classList.add('hidden');
    document.getElementById('view-info').textContent = 'Grid View';
    localStorage.setItem('deviceView', 'grid');
    filterAndDisplayDevices();
}

function switchToTableView() {
    currentView = 'table';
    document.getElementById('table-view').classList.add('active');
    document.getElementById('grid-view').classList.remove('active');
    document.getElementById('devices-table-view').style.display = 'block';
    document.getElementById('devices-table-view').classList.remove('hidden');
    document.getElementById('devices-grid-view').classList.add('hidden');
    document.getElementById('view-info').textContent = 'Table View';
    localStorage.setItem('deviceView', 'table');
    filterAndDisplayDevices();
}

// Toggle advanced panel
function toggleAdvancedPanel() {
    advancedMode = !advancedMode;
    const panel = document.getElementById('advanced-panel');
    const button = document.getElementById('toggle-advanced');

    if (advancedMode) {
        panel.classList.add('show');
        button.innerHTML = '<i class="bi bi-sliders"></i> Hide Advanced';
    } else {
        panel.classList.remove('show');
        button.innerHTML = '<i class="bi bi-sliders"></i> Advanced';
    }

    localStorage.setItem('advancedMode', advancedMode);
}

// Action functions
async function refreshAllDevices() {
    const btn = document.getElementById('refresh-all');
    btn.innerHTML = '<i class="bi bi-arrow-clockwise spinning"></i> Refreshing...';
    btn.disabled = true;

    try {
        await fetch('/api/devices/ping-all', {
            method: 'POST'
        });
        setTimeout(loadDevices, 2000);
    } catch (error) {
    } finally {
        btn.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Refresh';
        btn.disabled = false;
    }
}

// Scan progress management
let scanStartTime = null;
let scanTimer = null;
let scanProgressValue = 0;

async function scanNetwork() {
    const btn = document.getElementById('scan-network');

    // Prevent multiple simultaneous scans
    if (btn.disabled || window.scanProgressInterval) {
        return;
    }

    try {
        // Get CSRF token from multiple sources
        let csrfToken = null;

        // Try meta tag first
        const metaTag = document.querySelector('meta[name="csrf-token"]');
        if (metaTag) {
            csrfToken = metaTag.getAttribute('content');
        }

        // If not found, try cookie
        if (!csrfToken) {
            const cookies = document.cookie.split(';');
            for (let cookie of cookies) {
                const [name, value] = cookie.trim().split('=');
                if (name === 'csrf_token') {
                    csrfToken = value;
                    break;
                }
            }
        }


        const headers = {};

        // Add CSRF token if available
        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }


        const response = await fetch('/api/devices/scan-now', {
            method: 'POST',
            headers: headers
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Show scan status indicator
            showScanStatus();

            // Start progress indicator
            showScanProgress();

            // Update button state
            btn.innerHTML = '<i class="bi bi-radar spinning"></i> Scanning...';
            btn.disabled = true;

            // Start progress simulation
            startProgressSimulation(data.estimated_duration || 120);

            // Show notification
            showNotification('Network scan initiated', 'info');
        } else if (response.status === 409) {
            // Show scan status indicator since scan is already running
            showScanStatus();
            showNotification('Scan already in progress', 'warning');
        } else {
            throw new Error(data.error || 'Failed to start scan');
        }
    } catch (error) {
        showNotification(`Scan failed: ${error.message}`, 'error');
        hideScanStatus();
        btn.innerHTML = '<i class="bi bi-radar"></i> Scan Network';
        btn.disabled = false;
    }
}

function showScanProgress() {
    const container = document.getElementById('scan-progress-container');
    container.classList.remove('hidden');

    // Reset progress
    scanProgressValue = 0;
    scanStartTime = Date.now();
    document.getElementById('scan-progress-bar').style.width = '0%';
    document.getElementById('scan-progress-percentage').textContent = '0%';
    document.getElementById('scan-phase-text').textContent = 'Initializing scan...';
    document.getElementById('devices-found').textContent = '0';
    document.getElementById('new-devices').textContent = '0';
    document.getElementById('scan-duration').textContent = '0:00';
    document.getElementById('eta-time').textContent = 'Calculating...';

    // Start duration timer
    if (scanTimer) clearInterval(scanTimer);
    scanTimer = setInterval(updateScanDuration, 1000);
}

function startProgressSimulation(estimatedDuration) {
    const phases = [
        { at: 10, text: 'Checking network configuration...' },
        { at: 20, text: 'Scanning ARP table...' },
        { at: 40, text: 'Running network discovery (nmap)...' },
        { at: 70, text: 'Processing discovered devices...' },
        { at: 90, text: 'Updating database...' },
        { at: 95, text: 'Finalizing results...' }
    ];

    let currentPhase = 0;
    let lastRealProgress = 0;  // Track actual progress from WebSocket

    // Timeout protection - fail after 3 minutes
    const scanTimeout = setTimeout(() => {
        closeScanProgress();
        hideScanStatus();
        const btn = document.getElementById('scan-network');
        btn.innerHTML = '<i class="bi bi-radar"></i> Scan Network';
        btn.disabled = false;
        showNotification('Network scan timed out. Please try again.', 'error');
    }, 180000); // 3 minutes

    // Store timeout for cleanup
    window.scanTimeout = scanTimeout;

    const progressInterval = setInterval(() => {
        // If we have real progress from WebSocket, use it
        if (lastRealProgress > scanProgressValue) {
            scanProgressValue = lastRealProgress;
        }
        // Otherwise simulate progress, but slower and don't cap at 95%
        else if (scanProgressValue < 90) {
            scanProgressValue += Math.random() * 2 + 0.5;
            scanProgressValue = Math.min(scanProgressValue, 90);
        }

        // Update progress bar
        document.getElementById('scan-progress-bar').style.width = scanProgressValue + '%';
        document.getElementById('scan-progress-percentage').textContent = Math.floor(scanProgressValue) + '%';

        // Update phase text
        while (currentPhase < phases.length && scanProgressValue >= phases[currentPhase].at) {
            document.getElementById('scan-phase-text').textContent = phases[currentPhase].text;
            currentPhase++;
        }

        // Update ETA
        const elapsed = (Date.now() - scanStartTime) / 1000;
        const estimatedTotal = elapsed / (scanProgressValue / 100);
        const remaining = Math.max(0, estimatedTotal - elapsed);
        document.getElementById('eta-time').textContent = formatTime(remaining);
    }, 500);

    // Store interval for cleanup
    window.scanProgressInterval = progressInterval;

    // Store function to update from real progress
    window.updateRealScanProgress = (progress) => {
        lastRealProgress = progress;
        scanProgressValue = progress;
    };
}

function updateScanDuration() {
    if (!scanStartTime) return;
    const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
    document.getElementById('scan-duration').textContent = formatTime(elapsed);
}

function formatTime(seconds) {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, '0')}`;
}

function closeScanProgress() {
    const container = document.getElementById('scan-progress-container');
    container.classList.add('hidden');

    // Clear timers
    if (scanTimer) {
        clearInterval(scanTimer);
        scanTimer = null;
    }
    if (window.scanProgressInterval) {
        clearInterval(window.scanProgressInterval);
        window.scanProgressInterval = null;
    }
    if (window.scanTimeout) {
        clearTimeout(window.scanTimeout);
        window.scanTimeout = null;
    }
}

function completeScanProgress(devicesFound = 0, newDevices = 0) {
    // Update to 100%
    scanProgressValue = 100;
    document.getElementById('scan-progress-bar').style.width = '100%';
    document.getElementById('scan-progress-percentage').textContent = '100%';
    document.getElementById('scan-phase-text').textContent = 'Scan completed successfully!';
    document.getElementById('devices-found').textContent = devicesFound.toString();
    document.getElementById('new-devices').textContent = newDevices.toString();
    document.getElementById('eta-time').textContent = 'Complete';

    // Hide scan status indicator
    hideScanStatus();

    // Re-enable scan button
    const btn = document.getElementById('scan-network');
    btn.innerHTML = '<i class="bi bi-radar"></i> Scan Network';
    btn.disabled = false;

    // Clear progress interval
    if (window.scanProgressInterval) {
        clearInterval(window.scanProgressInterval);
        window.scanProgressInterval = null;
    }

    // Auto-hide after 5 seconds
    setTimeout(() => {
        closeScanProgress();
    }, 5000);

    // Reload devices
    loadDevices();
}

function showNotification(message, type = 'info') {
    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        toastContainer.style.zIndex = '1055';
        document.body.appendChild(toastContainer);
    }

    // Map type to Bootstrap color class
    const typeMap = {
        'success': 'success',
        'error': 'danger',
        'warning': 'warning',
        'info': 'primary'
    };
    const bgClass = typeMap[type] || 'primary';

    // Create toast element with escaped message
    const toastEl = document.createElement('div');
    toastEl.className = `toast align-items-center text-bg-${bgClass} border-0`;
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');

    const toastBody = document.createElement('div');
    toastBody.className = 'd-flex';
    toastBody.innerHTML = `
        <div class="toast-body"></div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
    `;
    // Set message text safely (prevents XSS)
    toastBody.querySelector('.toast-body').textContent = message;
    toastEl.appendChild(toastBody);

    toastContainer.appendChild(toastEl);

    // Initialize and show toast using Bootstrap
    const toast = new bootstrap.Toast(toastEl, { delay: 5000 });
    toast.show();

    // Remove toast element after it's hidden
    toastEl.addEventListener('hidden.bs.toast', function() {
        toastEl.remove();
    });
}

// Scan status indicator functions
function showScanStatus() {
    const statusElement = document.getElementById('scan-status');
    if (statusElement) {
        statusElement.classList.remove('hidden');
        statusElement.style.display = 'flex';
    }
}

function hideScanStatus() {
    const statusElement = document.getElementById('scan-status');
    if (statusElement) {
        statusElement.classList.add('hidden');
    }
}

// Check if a scan is currently in progress
async function checkScanStatus() {
    try {
        const response = await fetch('/api/devices/scan-status');
        if (response.ok) {
            const data = await response.json();
            if (data.scan_in_progress) {
                showScanStatus();
            }
        }
    } catch (error) {
    }
}

// Device actions
function openDeviceDetails(deviceId) {
    window.location.href = `/device/${deviceId}`;
}

async function toggleMonitoring(deviceId, ev) {
    if (ev && typeof ev.stopPropagation === 'function') ev.stopPropagation();
    const device = devicesData.find(d => d.id === deviceId);
    if (!device) return;

    try {
        const response = await fetch(`/api/devices/${deviceId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ is_monitored: !device.is_monitored })
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        await loadDevices();
    } catch (error) {
        showError(`Could not update monitoring: ${error.message}`);
    }
}

// Bulk operations: one request for all devices, one reload
async function setMonitoring(deviceIds, isMonitored) {
    if (!deviceIds.length) return;
    try {
        const response = await fetch('/api/devices/bulk-update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ device_ids: deviceIds, is_monitored: isMonitored })
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        showSuccess(`${isMonitored ? 'Enabled' : 'Disabled'} monitoring for ${deviceIds.length} device(s)`);
    } catch (error) {
        showError(`Bulk update failed: ${error.message}`);
    }
    await loadDevices();
}

async function bulkEnableMonitoring() {
    await setMonitoring(devicesData.filter(d => !d.is_monitored).map(d => d.id), true);
}

async function bulkDisableMonitoring() {
    await setMonitoring(devicesData.filter(d => d.is_monitored).map(d => d.id), false);
}

// Apply monitoring preset
async function applyMonitoringPreset(preset) {
    let devicesToEnable = [];

    switch(preset) {
        case 'security':
            devicesToEnable = devicesData.filter(d => {
                const name = (d.display_name || d.hostname || '').toLowerCase();
                return name.includes('camera') || name.includes('ring') ||
                       name.includes('cam') || name.includes('security');
            });
            break;
        case 'essential':
            devicesToEnable = devicesData.filter(d => {
                const name = (d.display_name || d.hostname || '').toLowerCase();
                return name.includes('router') || name.includes('gateway') ||
                       d.device_type === 'router';
            });
            break;
    }

    const keep = new Set(devicesToEnable.map(d => d.id));
    await setMonitoring(devicesData.filter(d => d.is_monitored && !keep.has(d.id)).map(d => d.id), false);
    await setMonitoring(devicesData.filter(d => keep.has(d.id) && !d.is_monitored).map(d => d.id), true);
}

// Export to CSV
function exportToCSV() {
    const csv = [
        ['Name', 'IP Address', 'Status', 'Response Time', 'Last Seen', 'Monitoring'],
        ...devicesData.map(d => [
            d.display_name || d.hostname || 'Unknown',
            d.ip_address,
            d.status,
            d.latest_response_time || '',
            d.last_seen || '',
            d.is_monitored ? 'Enabled' : 'Disabled'
        ])
    ].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `network-devices-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
}

// Socket.IO handlers
function handleDeviceUpdate(data) {
    const index = devicesData.findIndex(d => d.id === data.id);
    if (index === -1) return;

    const prev = devicesData[index];
    const next = { ...prev, ...data };
    devicesData[index] = next;
    updateStats();

    // A full re-render is only needed when list membership or sort order could change.
    const statusChanged = prev.status !== next.status;
    const responseChanged = prev.latest_response_time !== next.latest_response_time;
    const lastSeenChanged = prev.last_seen !== next.last_seen;
    const needsResort =
        (filters.sortBy === 'status' && statusChanged) ||
        (filters.sortBy === 'response' && responseChanged) ||
        (filters.sortBy === 'lastseen' && lastSeenChanged);
    const filterMembershipChanged = statusChanged && !!filters.status;

    if (needsResort || filterMembershipChanged) {
        filterAndDisplayDevices();
        return;
    }

    updateDeviceCardInPlace(next);
}

// Patch a single card/row in place without rebuilding the grid.
function updateDeviceCardInPlace(device) {
    const statusClass = device.status || 'unknown';
    const responseTime = device.latest_response_time != null
        ? `${Math.round(device.latest_response_time)}ms`
        : '--';
    const lastSeen = formatLastSeen(device.last_seen);

    const card = document.querySelector(`.device-card[data-device-id="${device.id}"]`);
    if (card) {
        const dot = card.querySelector('.status-dot');
        if (dot) dot.className = `status-dot status-${statusClass}`;
        const stats = card.querySelectorAll('.device-stats span');
        if (stats[0]) stats[0].innerHTML = `<i class="bi bi-lightning"></i> ${responseTime}`;
        if (stats[1]) stats[1].innerHTML = `<i class="bi bi-clock"></i> ${lastSeen}`;
    }

    const row = document.querySelector(`tr[data-device-id="${device.id}"]`);
    if (row) {
        const cells = row.querySelectorAll('td');
        const dot = cells[0] && cells[0].querySelector('.status-dot');
        if (dot) dot.className = `status-dot status-${statusClass}`;
        if (cells[3]) cells[3].textContent = responseTime;
        if (cells[4]) cells[4].textContent = lastSeen;
    }
}

function handleMonitoringSummary(data) {
    // Server push carries the same keys as /api/monitoring/summary
    applySummary(data);
}

function updateNetworkStatus(connected) {
    // Socket connectivity belongs to the navbar badge, not the network-health tile
    if (typeof updateConnectionStatus === 'function') updateConnectionStatus(connected);
}
