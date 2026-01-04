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
    sortBy: 'name'
};

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

    // Auto-refresh every 30 seconds
    setInterval(loadDevices, 30000);
});

// Socket.IO initialization
function initializeSocket() {
    socket = io();

    socket.on('connect', function() {
        updateNetworkStatus(true);
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

    socket.on('device_update', handleDeviceUpdate);
    socket.on('monitoring_summary', handleMonitoringSummary);
}

// Event Listeners Setup
function setupEventListeners() {
    // Search
    document.getElementById('device-search').addEventListener('input', function(e) {
        filters.search = e.target.value.toLowerCase();
        filterAndDisplayDevices();
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
        updateStats();
        filterAndDisplayDevices();
        document.getElementById('loading-devices').style.display = 'none';
    } catch (error) {
        document.getElementById('loading-devices').innerHTML =
            '<p class="text-danger">Error loading devices: ' + error.message + '</p>';
    }
}

// Update hero statistics
function updateStats() {
    const online = devicesData.filter(d => d.status === 'up').length;
    const total = devicesData.length;
    const alerts = devicesData.filter(d => d.has_alerts).length;
    const avgResponse = devicesData
        .filter(d => d.latest_response_time > 0)
        .reduce((acc, d, _, arr) => acc + d.latest_response_time / arr.length, 0);

    document.getElementById('hero-devices-online').textContent = online;
    document.getElementById('hero-total-devices').textContent = total;
    document.getElementById('hero-response-time').textContent =
        avgResponse ? Math.round(avgResponse) + ' ms' : '-- ms';
    document.getElementById('hero-alerts').textContent = alerts;

    // Update network status
    const healthPercentage = total ? (online / total) * 100 : 0;
    const statusElement = document.getElementById('hero-network-status');
    if (healthPercentage >= 90) {
        statusElement.innerHTML = '<span class="status-dot status-up"></span>Healthy';
    } else if (healthPercentage >= 70) {
        statusElement.innerHTML = '<span class="status-dot status-warning"></span>Degraded';
    } else {
        statusElement.innerHTML = '<span class="status-dot status-down"></span>Critical';
    }
}

// Filter and display devices
function filterAndDisplayDevices() {
    let filtered = [...devicesData];

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

    // Apply status filter
    if (filters.status) {
        filtered = filtered.filter(device => device.status === filters.status);
    }

    // Apply type filter (simplified for now)
    if (filters.type) {
        filtered = filtered.filter(device => {
            const name = (device.display_name || device.hostname || '').toLowerCase();
            switch(filters.type) {
                case 'cameras':
                    return name.includes('camera') || name.includes('ring') || name.includes('cam');
                case 'network':
                    return name.includes('router') || name.includes('switch') || name.includes('gateway');
                case 'smart':
                    return name.includes('google') || name.includes('alexa') || name.includes('nest');
                default:
                    return true;
            }
        });
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
    document.getElementById('no-devices').style.display =
        filtered.length === 0 ? 'block' : 'none';
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
        <div class="device-card" onclick="openDeviceDetails(${device.id})">
            <div class="device-name">
                <span class="status-dot status-${statusClass}"></span>
                ${name}
            </div>
            <div class="device-ip">${device.ip_address}</div>
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
    const monitoringStatus = device.monitor_enabled ? 'Enabled' : 'Disabled';

    return `
        <tr>
            <td><span class="status-dot status-${statusClass}"></span></td>
            <td>${name}</td>
            <td style="font-family: monospace;">${device.ip_address}</td>
            <td>${responseTime}</td>
            <td>${lastSeen}</td>
            <td>
                <span class="badge ${device.monitor_enabled ? 'bg-success' : 'bg-secondary'}">
                    ${monitoringStatus}
                </span>
            </td>
            <td>
                <button class="btn btn-sm btn-outline-light" onclick="openDeviceDetails(${device.id})">
                    <i class="bi bi-eye"></i>
                </button>
                <button class="btn btn-sm btn-outline-light" onclick="toggleMonitoring(${device.id})">
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
    document.getElementById('devices-table-view').style.display = 'none';
    document.getElementById('view-info').textContent = 'Grid View';
    localStorage.setItem('deviceView', 'grid');
    filterAndDisplayDevices();
}

function switchToTableView() {
    currentView = 'table';
    document.getElementById('table-view').classList.add('active');
    document.getElementById('grid-view').classList.remove('active');
    document.getElementById('devices-table-view').style.display = 'block';
    document.getElementById('devices-grid-view').style.display = 'none';
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
        await fetch('/api/devices/ping_all', {
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
    container.style.display = 'block';

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
    container.style.display = 'none';

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
    // You can implement a toast notification system here
}

// Scan status indicator functions
function showScanStatus() {
    const statusElement = document.getElementById('scan-status');
    if (statusElement) {
        statusElement.style.display = 'flex';
    }
}

function hideScanStatus() {
    const statusElement = document.getElementById('scan-status');
    if (statusElement) {
        statusElement.style.display = 'none';
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

async function toggleMonitoring(deviceId) {
    event.stopPropagation();
    const device = devicesData.find(d => d.id === deviceId);
    if (!device) return;

    try {
        await fetch(`/api/devices/${deviceId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ monitor_enabled: !device.monitor_enabled })
        });
        loadDevices();
    } catch (error) {
    }
}

// Bulk operations
async function bulkEnableMonitoring() {
    const devices = devicesData.filter(d => !d.monitor_enabled);
    for (const device of devices) {
        await toggleMonitoring(device.id);
    }
}

async function bulkDisableMonitoring() {
    const devices = devicesData.filter(d => d.monitor_enabled);
    for (const device of devices) {
        await toggleMonitoring(device.id);
    }
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
                       d.ip_address === '192.168.86.1';
            });
            break;
    }

    // Disable all first
    await bulkDisableMonitoring();

    // Enable selected devices
    for (const device of devicesToEnable) {
        if (!device.monitor_enabled) {
            await toggleMonitoring(device.id);
        }
    }
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
            d.monitor_enabled ? 'Enabled' : 'Disabled'
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
    if (index !== -1) {
        devicesData[index] = { ...devicesData[index], ...data };
        updateStats();
        filterAndDisplayDevices();
    }
}

function handleMonitoringSummary(data) {
    // Update hero stats with real-time data
    if (data.devices_up !== undefined) {
        document.getElementById('hero-devices-online').textContent = data.devices_up;
    }
    if (data.total_devices !== undefined) {
        document.getElementById('hero-total-devices').textContent = data.total_devices;
    }
}

function updateNetworkStatus(connected) {
    const statusElement = document.getElementById('hero-network-status');
    if (connected) {
        statusElement.innerHTML = '<span class="status-dot status-up"></span>Connected';
    } else {
        statusElement.innerHTML = '<span class="status-dot status-down"></span>Disconnected';
    }
}
