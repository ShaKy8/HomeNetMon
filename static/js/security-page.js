    let securityCharts = {};
    let currentTimeFilter = 24; // Default 24 hours
    
    // Toast notification function
    function showToast(message, type = 'info') {
        // Create toast container if it doesn't exist
        let toastContainer = document.getElementById('toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.id = 'toast-container';
            toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
            toastContainer.style.zIndex = '1055';
            document.body.appendChild(toastContainer);
        }
        
        // Create toast element
        const toastEl = document.createElement('div');
        toastEl.className = `toast align-items-center text-bg-${type === 'error' ? 'danger' : type === 'success' ? 'success' : 'primary'} border-0`;
        toastEl.setAttribute('role', 'alert');
        toastEl.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;
        
        toastContainer.appendChild(toastEl);
        
        // Initialize and show toast
        const toast = new bootstrap.Toast(toastEl, { delay: 5000 });
        toast.show();
        
        // Remove toast element after it's hidden
        toastEl.addEventListener('hidden.bs.toast', function () {
            toastEl.remove();
        });
    }

    // CSRF Token Helper Functions
    function getCSRFToken() {
        // Try meta tag first
        const metaToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        if (metaToken) return metaToken;
        
        // Fallback to cookie
        return document.cookie
            .split('; ')
            .find(row => row.startsWith('csrf_token='))
            ?.split('=')[1];
    }
    
    function getHeaders(additionalHeaders = {}) {
        const headers = {
            'Content-Type': 'application/json',
            ...additionalHeaders
        };
        
        const csrfToken = getCSRFToken();
        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }
        
        return headers;
    }

    document.addEventListener('DOMContentLoaded', function() {
        // Debug CSRF token
        console.log('CSRF Token from meta:', document.querySelector('meta[name="csrf-token"]')?.getAttribute('content'));
        console.log('CSRF Token from cookie:', document.cookie.split('; ').find(row => row.startsWith('csrf_token=')));
        console.log('Final CSRF Token:', getCSRFToken());
        
        // Initialize Bootstrap tooltips
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl, {
                trigger: 'hover focus',
                delay: { "show": 500, "hide": 100 }
            });
        });
        
        loadSecurityData();
        checkScanStatus(); // Check if scan is already running on page load
        
        // Event listeners
        document.getElementById('refresh-security-data').addEventListener('click', loadSecurityData);
        document.getElementById('run-security-scan').addEventListener('click', runNetworkScan);
        document.getElementById('stop-security-scan').addEventListener('click', stopNetworkScan);
        document.getElementById('security-settings-form').addEventListener('submit', updateSecuritySettings);
        
        // Time filter buttons
        document.querySelectorAll('.time-filter').forEach(btn => {
            btn.addEventListener('click', (e) => {
                // Update active button
                document.querySelectorAll('.time-filter').forEach(b => b.classList.remove('btn-secondary'));
                document.querySelectorAll('.time-filter').forEach(b => b.classList.add('btn-outline-secondary'));
                e.target.classList.remove('btn-outline-secondary');
                e.target.classList.add('btn-secondary');
                
                currentTimeFilter = parseInt(e.target.dataset.hours);
                loadSecurityData();
            });
        });
        
        // Set default active button
        document.querySelector('.time-filter[data-hours="24"]').click();
        
        // Auto-refresh every 60 seconds
        setInterval(loadSecurityData, 60000);
        
        // Re-initialize tooltips after dynamic content updates
        document.addEventListener('DOMContentLoaded', function() {
            const observer = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    if (mutation.addedNodes.length > 0) {
                        // Re-initialize tooltips for new elements
                        const newTooltips = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]:not([data-bs-original-title])'));
                        newTooltips.forEach(function (tooltipTriggerEl) {
                            new bootstrap.Tooltip(tooltipTriggerEl, {
                                trigger: 'hover focus',
                                delay: { "show": 500, "hide": 100 }
                            });
                        });
                    }
                });
            });
            observer.observe(document.body, { childList: true, subtree: true });
        });
    });
    
    async function checkScanStatus() {
        try {
            const response = await fetch('/api/security/scan-progress');
            const data = await response.json();
            
            if (data.success && data.progress.active) {
                const button = document.getElementById('run-security-scan');
                const progress = data.progress;
                
                // Update button to show scan is running
                button.disabled = true;
                button.innerHTML = '<i class="bi bi-hourglass-split"></i> Scan Running...';
                button.setAttribute('data-bs-title', `Security scan in progress (${progress.progress}% complete). Started ${progress.duration_formatted} ago.`);
                
                // Show progress container if scan is running
                const progressContainer = document.getElementById('scan-progress-container');
                if (progressContainer) {
                    progressContainer.style.display = 'block';
                    
                    // Start monitoring the existing scan
                    monitorExistingScan();
                }
            }
        } catch (error) {
            console.error('Error checking scan status:', error);
        }
    }
    
    function monitorExistingScan() {
        const progressBar = document.getElementById('scan-progress-bar');
        const statusText = document.getElementById('scan-status-text');
        const detailsText = document.getElementById('scan-details');
        const scanStage = document.getElementById('scan-stage');
        const deviceInfo = document.getElementById('current-device-info');
        
        // Null checks to prevent errors
        if (!progressBar || !statusText || !detailsText || !scanStage || !deviceInfo) {
            console.error('Missing required DOM elements for monitoring scan');
            return;
        }
        
        let progressInterval = setInterval(async () => {
            try {
                const progressResponse = await fetch('/api/security/scan-progress');
                const progressData = await progressResponse.json();
                
                if (progressData.success) {
                    const progress = progressData.progress;
                    
                    if (!progress.active) {
                        // Scan completed, reset UI
                        clearInterval(progressInterval);
                        const button = document.getElementById('run-security-scan');
                        button.disabled = false;
                        button.innerHTML = '<i class="bi bi-search"></i> Run Network Scan';
                        button.setAttribute('data-bs-title', 'Start a comprehensive network scan to check all devices for open ports, services, and potential security risks');
                        
                        document.getElementById('scan-progress-container').style.display = 'none';
                        loadSecurityData(); // Refresh data after scan completion
                        return;
                    }
                    
                    // Update progress UI
                    progressBar.style.width = progress.progress + '%';
                    
                    if (progress.status === 'running') {
                        scanStage.textContent = 'Scanning';
                        scanStage.className = 'ms-3 badge bg-warning';
                        
                        if (progress.current_device) {
                            deviceInfo.style.display = 'block';
                            const deviceNameEl = document.getElementById('current-device-name');
                            const deviceProgressEl = document.getElementById('current-device-progress');
                            if (deviceNameEl) deviceNameEl.textContent = progress.current_device;
                            if (deviceProgressEl) deviceProgressEl.style.width = progress.current_device_progress + '%';
                            statusText.textContent = `Scanning ${progress.current_device}`;
                        }
                        
                        // Update statistics with null checks
                        const devicesProgressEl = document.getElementById('devices-progress');
                        const portsScannedEl = document.getElementById('ports-scanned');
                        const openPortsEl = document.getElementById('open-ports-found');
                        const alertsEl = document.getElementById('alerts-generated');
                        const percentageEl = document.getElementById('scan-percentage');
                        
                        if (devicesProgressEl) devicesProgressEl.textContent = `${progress.devices_completed}/${progress.total_devices}`;
                        if (portsScannedEl) portsScannedEl.textContent = progress.total_ports_scanned || 0;
                        if (openPortsEl) openPortsEl.textContent = progress.open_ports_found || 0;
                        if (alertsEl) alertsEl.textContent = progress.alerts_generated || 0;
                        if (percentageEl) percentageEl.textContent = progress.progress + '%';
                        
                        detailsText.textContent = `Scanned ${progress.devices_completed} of ${progress.total_devices} devices | Found ${progress.open_ports_found} open ports | Generated ${progress.alerts_generated} security alerts`;
                    }
                    
                    // Update button tooltip with progress
                    const button = document.getElementById('run-security-scan');
                    button.setAttribute('data-bs-title', `Security scan in progress (${progress.progress}% complete). Started ${progress.duration_formatted} ago.`);
                }
            } catch (error) {
                console.error('Error monitoring scan progress:', error);
            }
        }, 2000);
    }
    
    async function loadSecurityData() {
        try {
            await Promise.all([
                loadSecuritySummary(),
                loadNetworkOverview(),
                loadSecurityAlerts(),
                loadRiskAssessment()
            ]);
        } catch (error) {
            console.error('Error loading security data:', error);
            showToast('Error loading security dashboard data', 'error');
            
            // Show fallback UI for offline/error state
            document.getElementById('security-status').innerHTML = `
                Error
                <small class="d-block" style="font-size: 0.75rem; opacity: 0.9; font-weight: normal;">
                    Unable to load data
                </small>
            `;
            document.getElementById('security-status').closest('.card').className = 'card bg-secondary text-white';
        }
    }
    
    async function loadSecuritySummary() {
        try {
            const response = await fetch(`/api/security/summary?hours=${currentTimeFilter}`);
            const data = await response.json();
            
            if (data.success) {
                const summary = data.summary;
                
                // Update summary cards with enhanced display and visual indicators
                const devicesScanned = summary.devices_scanned || 0;
                const totalAlerts = summary.total_alerts || 0;
                const highRiskDevices = (summary.by_severity.high || 0) + (summary.by_severity.critical || 0);
                
                // Calculate overall network risk level
                const networkRiskScore = calculateNetworkRiskScore(summary);
                const networkRiskLevel = getRiskLevelFromScore(networkRiskScore);
                
                document.getElementById('devices-scanned').innerHTML = `
                    <div class="d-flex align-items-center">
                        <span class="h4 mb-0 me-2">${devicesScanned}</span>
                        <div class="risk-indicator risk-${networkRiskLevel}" style="font-size: 0.6rem;">
                            ${getRiskIcon(networkRiskScore)} ${networkRiskLevel}
                        </div>
                    </div>
                    <small class="d-block" style="font-size: 0.75rem; opacity: 0.9; font-weight: normal;">
                        ${devicesScanned === 1 ? 'device' : 'devices'} scanned
                    </small>
                `;
                
                // Build the risk indicator HTML separately to avoid syntax issues
                let riskIndicatorHTML = '';
                if (totalAlerts > 0) {
                    const riskClass = totalAlerts >= 5 ? 'risk-critical' : totalAlerts >= 3 ? 'risk-high' : 'risk-medium';
                    const riskIcon = totalAlerts >= 5 ? '!' : totalAlerts >= 3 ? '!' : '*';
                    riskIndicatorHTML = `<div class="risk-indicator ${riskClass}" style="font-size: 0.6rem;">${riskIcon}</div>`;
                } else {
                    riskIndicatorHTML = '<div class="risk-indicator risk-low" style="font-size: 0.6rem;">+</div>';
                }

                document.getElementById('total-open-ports').innerHTML = `
                    <div class="d-flex align-items-center">
                        <span class="h4 mb-0 me-2">${totalAlerts}</span>
                        ${riskIndicatorHTML}
                    </div>
                    <small class="d-block" style="font-size: 0.75rem; opacity: 0.9; font-weight: normal;">
                        security alert${totalAlerts === 1 ? '' : 's'}
                    </small>
                `;
                
                document.getElementById('high-risk-devices').innerHTML = `
                    <div class="d-flex align-items-center">
                        <span class="h4 mb-0 me-2">${highRiskDevices}</span>
                        <div class="risk-indicator ${highRiskDevices > 0 ? 'risk-critical' : 'risk-low'}" style="font-size: 0.6rem;">
                            ${highRiskDevices > 0 ? '!' : '+'}
                        </div>
                    </div>
                    <small class="d-block" style="font-size: 0.75rem; opacity: 0.9; font-weight: normal;">
                        ${highRiskDevices === 0 ? 'all devices secure' : (highRiskDevices === 1 ? 'device needs attention' : 'devices need attention')}
                    </small>
                `;
                
                // Update security status
                updateSecurityStatus(summary);
                
                // Update charts
                updateSecurityAlertsChart(summary.by_type);
                updateRiskDistributionChart(summary.by_severity);
            }
        } catch (error) {
            console.error('Error loading security summary:', error);
        }
    }
    
    async function loadNetworkOverview() {
        try {
            const response = await fetch(`/api/security/network-overview?hours=${currentTimeFilter}`);
            const data = await response.json();
            
            if (data.success) {
                updateNetworkOverviewTable(data.network_overview);
            }
        } catch (error) {
            console.error('Error loading network overview:', error);
        }
    }
    
    async function loadSecurityAlerts() {
        try {
            const response = await fetch(`/api/security/alerts?hours=${currentTimeFilter}&limit=20`);
            const data = await response.json();
            
            if (data.success) {
                updateSecurityAlertsTable(data.alerts);
            }
        } catch (error) {
            console.error('Error loading security alerts:', error);
        }
    }
    
    async function loadRiskAssessment() {
        try {
            const response = await fetch(`/api/security/risk-assessment?hours=${currentTimeFilter}`);
            const data = await response.json();
            
            if (data.success) {
                updateSecurityRecommendations(data.risk_assessment);
            }
        } catch (error) {
            console.error('Error loading risk assessment:', error);
        }
    }
    
    async function runNetworkScan() {
        try {
            const button = document.getElementById('run-security-scan');
            const originalText = button ? button.innerHTML : '';
            const progressContainer = document.getElementById('scan-progress-container');
            const progressBar = document.getElementById('scan-progress-bar');
            const statusText = document.getElementById('scan-status-text');
            const detailsText = document.getElementById('scan-details');
            
            // Null checks for required elements
            if (!button || !progressContainer || !progressBar || !statusText || !detailsText) {
                console.error('Missing required DOM elements for scan');
                showToast('Error: Missing UI elements', 'error');
                return;
            }
            
            // Show progress UI
            button.disabled = true;
            button.innerHTML = '<i class="bi bi-hourglass-split"></i> Starting...';
            progressContainer.style.display = 'block';
            progressBar.style.width = '0%';
            statusText.textContent = 'Starting scan...';
            detailsText.textContent = 'Initializing network security scan...';
            
            // Show enhanced progress UI immediately
            const statsDiv = document.getElementById('scan-stats');
            const deviceInfo = document.getElementById('current-device-info');
            const explanationDiv = document.getElementById('scan-explanation');
            const scanStage = document.getElementById('scan-stage');
            
            if (statsDiv) statsDiv.style.display = 'flex';
            if (explanationDiv) explanationDiv.style.display = 'block';
            if (scanStage) {
                scanStage.textContent = 'Starting';
                scanStage.className = 'ms-3 badge bg-primary';
            }
            
            // Start scan timer
            let scanStartTime = Date.now();
            const timerInterval = setInterval(() => {
                const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
                const minutes = Math.floor(elapsed / 60);
                const seconds = elapsed % 60;
                const timerEl = document.getElementById('scan-timer');
                if (timerEl) {
                    timerEl.textContent = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
                }
            }, 1000);
            
            // Start the scan
            const response = await fetch('/api/security/run-scan', {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify({})
            });
            
            const data = await response.json();
            
            if (!data.success) {
                if (data.error && data.error.includes('already in progress')) {
                    // Handle scan already in progress
                    button.innerHTML = '<i class="bi bi-hourglass-split"></i> Scan Running...';
                    statusText.textContent = 'Scan already in progress';
                    detailsText.textContent = 'A security scan is currently running. Please wait for it to complete.';
                    
                    // Start monitoring the existing scan
                    monitorExistingScan();
                    return;
                }
                throw new Error(data.error || 'Failed to start scan');
            }
            
            // Start polling for progress
            button.innerHTML = '<i class="bi bi-hourglass-split"></i> Scanning...';
            statusText.textContent = 'Scan started';
            detailsText.textContent = 'Scanning network devices for open ports and services...';
            
            let progressInterval = setInterval(async () => {
                try {
                    const progressResponse = await fetch('/api/security/scan-progress');
                    const progressData = await progressResponse.json();
                    
                    if (progressData.success) {
                        const progress = progressData.progress;
                        
                        // Update progress bar
                        progressBar.style.width = progress.progress + '%';
                        
                        // Update enhanced status display
                        if (progress.status === 'running') {
                            scanStage.textContent = 'Scanning';
                            scanStage.className = 'ms-3 badge bg-warning';

                            // Enable stop button and disable run button during scan
                            const runBtn = document.getElementById('run-security-scan');
                            const stopBtn = document.getElementById('stop-security-scan');
                            if (runBtn && stopBtn) {
                                runBtn.disabled = true;
                                runBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Scanning...';
                                stopBtn.disabled = false;
                                stopBtn.setAttribute('data-bs-title', 'Stop the currently running security scan');
                            }
                            
                            // Update current device info
                            if (progress.current_device) {
                                if (deviceInfo) deviceInfo.style.display = 'block';
                                const deviceNameEl = document.getElementById('current-device-name');
                                const deviceProgressEl = document.getElementById('current-device-progress');
                                if (deviceNameEl) deviceNameEl.textContent = progress.current_device;
                                if (deviceProgressEl) deviceProgressEl.style.width = progress.current_device_progress + '%';
                                
                                statusText.textContent = `Scanning ${progress.current_device}`;
                                
                                // Update explanation based on scan phase
                                const explanationText = document.getElementById('scan-explanation-text');
                                if (explanationText) {
                                    explanationText.textContent = `Currently checking ${progress.current_device} for open network ports. The scanner tests the most common ports to identify running services and potential security risks.`;
                                }
                            } else {
                                statusText.textContent = 'Scanning network devices...';
                                if (deviceInfo) deviceInfo.style.display = 'none';
                            }
                            
                            // Update statistics with null checks
                            const devicesProgressEl2 = document.getElementById('devices-progress');
                            const portsScannedEl2 = document.getElementById('ports-scanned');
                            const openPortsEl2 = document.getElementById('open-ports-found');
                            const alertsEl2 = document.getElementById('alerts-generated');
                            const percentageEl2 = document.getElementById('scan-percentage');
                            
                            if (devicesProgressEl2) devicesProgressEl2.textContent = `${progress.devices_completed}/${progress.total_devices}`;
                            if (portsScannedEl2) portsScannedEl2.textContent = progress.total_ports_scanned || 0;
                            if (openPortsEl2) openPortsEl2.textContent = progress.open_ports_found || 0;
                            if (alertsEl2) alertsEl2.textContent = progress.alerts_generated || 0;
                            if (percentageEl2) percentageEl2.textContent = progress.progress + '%';
                            
                            // Enhanced details
                            detailsText.textContent = `Scanned ${progress.devices_completed} of ${progress.total_devices} devices | Found ${progress.open_ports_found} open ports | Generated ${progress.alerts_generated} security alerts`;
                            
                        } else if (progress.status === 'completed') {
                            clearInterval(progressInterval);
                            clearInterval(timerInterval);

                            // Reset buttons for completion
                            const runBtn = document.getElementById('run-security-scan');
                            const stopBtn = document.getElementById('stop-security-scan');
                            if (runBtn && stopBtn) {
                                runBtn.disabled = false;
                                runBtn.innerHTML = '<i class="bi bi-search"></i> Run Network Scan';
                                stopBtn.disabled = true;
                                stopBtn.setAttribute('data-bs-title', 'Stop the currently running security scan (available when scan is active)');
                            }

                            // Update UI for completion
                            scanStage.textContent = 'Completed';
                            scanStage.className = 'ms-3 badge bg-success';
                            
                            progressBar.style.width = '100%';
                            progressBar.className = 'progress-bar bg-success';
                            document.getElementById('scan-spinner').style.display = 'none';
                            
                            statusText.textContent = 'Security scan completed successfully!';
                            deviceInfo.style.display = 'none';
                            
                            // Final statistics update
                            document.getElementById('devices-progress').textContent = `${progress.total_devices}/${progress.total_devices}`;
                            document.getElementById('ports-scanned').textContent = progress.total_ports_scanned || 0;
                            document.getElementById('open-ports-found').textContent = progress.open_ports_found || 0;
                            document.getElementById('alerts-generated').textContent = progress.alerts_generated || 0;
                            document.getElementById('scan-percentage').textContent = '100%';
                            
                            // Summary message
                            const scanSummary = `
                                <div class="d-flex align-items-center">
                                    <i class="bi bi-check-circle text-success me-2"></i>
                                    <div>
                                        <div class="fw-medium text-success">Scan completed successfully!</div>
                                        <div class="small text-muted">
                                            Analyzed ${progress.total_devices} devices, checked ${progress.total_ports_scanned} ports, 
                                            found ${progress.open_ports_found} open services, and identified ${progress.alerts_generated} security concerns.
                                            ${progress.duration_formatted ? ` Completed in ${progress.duration_formatted}.` : ''}
                                        </div>
                                    </div>
                                </div>
                            `;
                            
                            detailsText.innerHTML = scanSummary;
                            
                            // Update explanation for completion
                            document.getElementById('scan-explanation-text').textContent = 
                                'The security scan has analyzed your entire network and identified any potential security issues. Review the alerts above to understand and address any risks found.';
                            
                            showToast('Network security scan completed successfully', 'success');
                            
                            // Hide progress after a delay and refresh data
                            setTimeout(() => {
                                progressContainer.style.display = 'none';
                                loadSecurityData();
                            }, 3000);
                            
                        } else if (progress.status === 'stopped') {
                            clearInterval(progressInterval);
                            clearInterval(timerInterval);

                            // Reset buttons for stopped scan
                            const runBtn = document.getElementById('run-security-scan');
                            const stopBtn = document.getElementById('stop-security-scan');
                            if (runBtn && stopBtn) {
                                runBtn.disabled = false;
                                runBtn.innerHTML = '<i class="bi bi-search"></i> Run Network Scan';
                                stopBtn.disabled = true;
                                stopBtn.setAttribute('data-bs-title', 'Stop the currently running security scan (available when scan is active)');
                            }

                            // Update UI for stopped scan
                            if (scanStage) {
                                scanStage.textContent = 'Stopped';
                                scanStage.className = 'ms-3 badge bg-warning';
                            }

                            statusText.textContent = 'Security scan stopped by user';
                            if (deviceInfo) deviceInfo.style.display = 'none';

                        } else if (progress.status === 'failed') {
                            clearInterval(progressInterval);
                            clearInterval(timerInterval);

                            // Reset buttons for failure
                            const runBtn = document.getElementById('run-security-scan');
                            const stopBtn = document.getElementById('stop-security-scan');
                            if (runBtn && stopBtn) {
                                runBtn.disabled = false;
                                runBtn.innerHTML = '<i class="bi bi-search"></i> Run Network Scan';
                                stopBtn.disabled = true;
                                stopBtn.setAttribute('data-bs-title', 'Stop the currently running security scan (available when scan is active)');
                            }

                            // Update UI for failure
                            if (scanStage) {
                                scanStage.textContent = 'Failed';
                                scanStage.className = 'ms-3 badge bg-danger';
                            }
                            
                            if (progressBar) {
                                progressBar.classList.add('bg-danger');
                                progressBar.classList.remove('progress-bar-animated');
                            }
                            const spinnerEl = document.getElementById('scan-spinner');
                            if (spinnerEl) spinnerEl.style.display = 'none';
                            
                            statusText.textContent = 'X Security scan failed';
                            if (deviceInfo) deviceInfo.style.display = 'none';
                            
                            // Error details
                            const errorMessage = progress.error_message || 'An unexpected error occurred during the security scan.';
                            detailsText.innerHTML = `
                                <div class="d-flex align-items-start">
                                    <i class="bi bi-exclamation-triangle text-danger me-2 mt-1"></i>
                                    <div>
                                        <div class="fw-medium text-danger">Scan Failed</div>
                                        <div class="small text-muted">${errorMessage}</div>
                                        <div class="small text-muted mt-1">
                                            Try running the scan again. If the problem persists, check your network connectivity and scanner permissions.
                                        </div>
                                    </div>
                                </div>
                            `;
                            
                            // Update explanation for failure
                            const explanationTextEl = document.getElementById('scan-explanation-text');
                            if (explanationTextEl) {
                                explanationTextEl.textContent = 'The security scan encountered an error and could not complete. This may be due to network connectivity issues or scanner configuration problems.';
                            }
                            
                            showToast(`Scan failed: ${errorMessage}`, 'error');
                            
                            setTimeout(() => {
                                progressContainer.style.display = 'none';
                                progressBar.classList.remove('bg-danger');
                            }, 8000);
                        }
                    }
                } catch (error) {
                    console.error('Error polling scan progress:', error);
                }
            }, 2000); // Poll every 2 seconds
            
            // Set a timeout to stop polling after 30 minutes (just in case)
            setTimeout(() => {
                if (progressInterval) {
                    clearInterval(progressInterval);
                }
                if (timerInterval) {
                    clearInterval(timerInterval);
                }
            }, 30 * 60 * 1000);
            
        } catch (error) {
            console.error('Error running security scan:', error);
            
            const progressBar = document.getElementById('scan-progress-bar');
            const statusText = document.getElementById('scan-status-text');
            const detailsText = document.getElementById('scan-details');
            const button = document.getElementById('run-security-scan');
            
            if (progressBar) {
                progressBar.style.width = '100%';
                progressBar.classList.add('bg-danger');
            }
            if (statusText) statusText.textContent = 'X Scan failed to start';
            if (detailsText) detailsText.textContent = 'Failed to start security scan: ' + error.message;
            if (button) {
                button.disabled = false;
                button.innerHTML = '<i class="bi bi-search"></i> Run Network Scan';
            }
            
            showToast('Error running security scan: ' + (error.message || 'Unknown error'), 'error');
            
            setTimeout(() => {
                const progressContainer = document.getElementById('scan-progress-container');
                if (progressContainer) progressContainer.style.display = 'none';
                if (progressBar) progressBar.classList.remove('bg-danger');
            }, 5000);
            
        } finally {
            // Re-enable button
            setTimeout(() => {
                const button = document.getElementById('run-security-scan');
                button.disabled = false;
                button.innerHTML = '<i class="bi bi-search"></i> Run Network Scan';
            }, 1000);
        }
    }

    async function stopNetworkScan() {
        try {
            const runButton = document.getElementById('run-security-scan');
            const stopButton = document.getElementById('stop-security-scan');
            const progressContainer = document.getElementById('scan-progress-container');
            const progressBar = document.getElementById('scan-progress-bar');
            const statusText = document.getElementById('scan-status-text');
            const detailsText = document.getElementById('scan-details');

            // Disable stop button during request
            if (stopButton) {
                stopButton.disabled = true;
                stopButton.innerHTML = '<i class="bi bi-hourglass-split"></i> Stopping...';
            }

            // Call stop scan API
            const response = await fetch('/api/security/stop-scan', {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify({})
            });

            const data = await response.json();

            if (data.success) {
                // Update UI to show scan stopped
                if (progressBar) {
                    progressBar.style.width = '100%';
                    progressBar.classList.remove('progress-bar-animated');
                    progressBar.classList.add('bg-warning');
                }

                if (statusText) statusText.textContent = 'Security scan stopped by user';
                if (detailsText) {
                    detailsText.innerHTML = `
                        <div class="d-flex align-items-center">
                            <i class="bi bi-exclamation-triangle text-warning me-2"></i>
                            <div>
                                <div class="fw-medium text-warning">Scan stopped</div>
                                <div class="small text-muted">The security scan was stopped before completion.</div>
                            </div>
                        </div>
                    `;
                }

                // Update scan stage if exists
                const scanStage = document.getElementById('scan-stage');
                if (scanStage) {
                    scanStage.textContent = 'Stopped';
                    scanStage.className = 'ms-3 badge bg-warning';
                }

                // Hide scan progress after a delay
                setTimeout(() => {
                    if (progressContainer) progressContainer.style.display = 'none';

                    // Reset buttons
                    if (runButton) {
                        runButton.disabled = false;
                        runButton.innerHTML = '<i class="bi bi-search"></i> Run Network Scan';
                    }
                    if (stopButton) {
                        stopButton.disabled = true;
                        stopButton.innerHTML = '<i class="bi bi-stop-circle"></i> Stop Scan';
                        stopButton.setAttribute('data-bs-title', 'Stop the currently running security scan (available when scan is active)');
                    }
                }, 2000);

                showToast('Security scan stopped successfully', 'warning');
            } else {
                throw new Error(data.error || 'Failed to stop scan');
            }

        } catch (error) {
            console.error('Error stopping scan:', error);
            showToast('Error stopping scan: ' + error.message, 'error');

            // Reset stop button on error
            const stopButton = document.getElementById('stop-security-scan');
            if (stopButton) {
                stopButton.disabled = false;
                stopButton.innerHTML = '<i class="bi bi-stop-circle"></i> Stop Scan';
            }
        }
    }

    function updateSecurityStatus(summary) {
        const statusElement = document.getElementById('security-status');
        const statusCard = statusElement.closest('.card');
        
        const criticalIssues = summary.by_severity?.critical || 0;
        const highIssues = summary.by_severity?.high || 0;
        const mediumIssues = summary.by_severity?.medium || 0;
        const totalIssues = criticalIssues + highIssues + mediumIssues;
        
        let statusText, explanation, cardClass;
        
        if (criticalIssues > 0) {
            statusText = 'Critical Risk';
            explanation = `${criticalIssues} critical security issue${criticalIssues > 1 ? 's' : ''} need immediate attention`;
            cardClass = 'card bg-danger text-white';
        } else if (highIssues > 0) {
            statusText = 'High Risk';
            explanation = `${highIssues} high-risk issue${highIssues > 1 ? 's' : ''} should be reviewed soon`;
            cardClass = 'card bg-warning text-white';
        } else if (mediumIssues > 0) {
            statusText = 'Moderate Risk';
            explanation = `${mediumIssues} medium-risk issue${mediumIssues > 1 ? 's' : ''} to monitor`;
            cardClass = 'card bg-info text-white';
        } else {
            statusText = 'Secure';
            explanation = 'No significant security issues detected';
            cardClass = 'card bg-success text-white';
        }
        
        statusElement.innerHTML = `
            ${statusText}
            <small class="d-block" style="font-size: 0.75rem; opacity: 0.9; font-weight: normal;">
                ${explanation}
            </small>
        `;
        statusCard.className = cardClass;
        
        // Update tooltip with more detailed information
        const helpIcon = statusCard.querySelector('[data-bs-toggle="tooltip"]');
        if (helpIcon && window.bootstrap) {
            const tooltip = bootstrap.Tooltip.getInstance(helpIcon);
            if (tooltip) {
                tooltip.dispose();
            }
            new bootstrap.Tooltip(helpIcon, {
                title: `Security Status: ${statusText}. ${explanation}. ${totalIssues > 0 ? 'Review the alerts below for details.' : 'Keep monitoring to maintain security.'}`
            });
        }
    }
    
    function updateSecurityAlertsChart(byType) {
        const ctx = document.getElementById('security-alerts-chart').getContext('2d');
        
        if (securityCharts.alerts) {
            securityCharts.alerts.destroy();
        }
        
        const labels = Object.keys(byType || {});
        const data = Object.values(byType || {});
        
        securityCharts.alerts = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels.map(label => label.replace('_', ' ').toUpperCase()),
                datasets: [{
                    label: 'Count',
                    data: data,
                    backgroundColor: [
                        '#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#feca57'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }
    
    function updateRiskDistributionChart(bySeverity) {
        const ctx = document.getElementById('risk-distribution-chart').getContext('2d');
        
        if (securityCharts.risk) {
            securityCharts.risk.destroy();
        }
        
        securityCharts.risk = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Low', 'Medium', 'High', 'Critical'],
                datasets: [{
                    data: [
                        bySeverity?.low || 0,
                        bySeverity?.medium || 0,
                        bySeverity?.high || 0,
                        bySeverity?.critical || 0
                    ],
                    backgroundColor: [
                        '#28a745', '#ffc107', '#fd7e14', '#dc3545'
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
    
    function updateNetworkOverviewTable(overview) {
        const container = document.getElementById('network-overview-table');
        
        if (!overview || !overview.devices || overview.devices.length === 0) {
            container.innerHTML = `
                <div class="text-center py-4">
                    <div class="text-info mb-2">
                        <i class="bi bi-search" style="font-size: 2rem;"></i>
                    </div>
                    <div class="text-muted">
                        <strong>No scan data available</strong><br>
                        <small>Run a network scan to see security information for your devices.</small>
                    </div>
                    <button class="btn btn-outline-primary btn-sm mt-2" onclick="document.getElementById('run-security-scan').click()">
                        <i class="bi bi-search"></i> Start Network Scan
                    </button>
                </div>
            `;
            return;
        }
        
        const table = `
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Device</th>
                            <th>IP Address</th>
                            <th>Open Ports</th>
                            <th>Risk Score</th>
                            <th>Security Status</th>
                            <th>Services</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${overview.devices.map(device => `
                            <tr>
                                <td>
                                    <span class="fw-bold">${device.name}</span>
                                </td>
                                <td>
                                    <code>${device.ip_address}</code>
                                </td>
                                <td>
                                    <span class="badge bg-info">${device.open_ports}</span>
                                </td>
                                <td>
                                    <div class="risk-score-display">
                                        <div class="risk-score-bar">
                                            <div class="risk-score-fill bg-${getRiskColor(device.avg_risk_score)}" 
                                                 style="width: ${(device.avg_risk_score / 10) * 100}%"></div>
                                        </div>
                                        <span class="small fw-medium">${device.avg_risk_score.toFixed(1)}</span>
                                    </div>
                                    <div class="mt-1">
                                        <span class="risk-indicator risk-${device.security_status.replace(' ', '-')}">
                                            ${getRiskIcon(device.avg_risk_score)} ${device.security_status}
                                        </span>
                                    </div>
                                </td>
                                <td>
                                    <div class="device-security-badge ${getSecurityBadgeClass(device.security_status)}">
                                        ${device.security_status.replace('-', ' ')}
                                    </div>
                                    <div class="mt-1">
                                        <small class="text-muted">
                                            ${device.open_ports} port${device.open_ports === 1 ? '' : 's'} open
                                        </small>
                                    </div>
                                </td>
                                <td>
                                    <small>${device.services.slice(0, 3).join(', ')}${device.services.length > 3 ? '...' : ''}</small>
                                </td>
                                <td>
                                    <button class="btn btn-sm btn-outline-primary" onclick="scanDevice(${device.id})"
                                            data-bs-toggle="tooltip" data-bs-placement="left" 
                                            data-bs-title="Run a detailed security scan on this specific device">
                                        <i class="bi bi-search"></i> Scan
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
        
        container.innerHTML = table;
    }
    
    function updateSecurityAlertsTable(alerts) {
        const container = document.getElementById('security-alerts-table');
        
        if (!alerts || alerts.length === 0) {
            container.innerHTML = `
                <div class="text-center py-4">
                    <div class="text-success mb-2">
                        <i class="bi bi-shield-check" style="font-size: 2rem;"></i>
                    </div>
                    <div class="text-muted">
                        <strong>No security alerts found</strong><br>
                        <small>Your network appears secure for the selected time period. Keep monitoring with regular scans.</small>
                    </div>
                </div>
            `;
            return;
        }
        
        const table = `
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th class="text-center" style="width: 40px;">
                                <input type="checkbox" class="form-check-input" id="select-all-alerts" 
                                       data-bs-toggle="tooltip" data-bs-placement="right" 
                                       data-bs-title="Select all visible alerts">
                            </th>
                            <th class="text-nowrap">Priority</th>
                            <th>Device</th>
                            <th>Threat Type</th>
                            <th>Impact</th>
                            <th>Details</th>
                            <th>Detected</th>
                            <th class="text-center">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${alerts.map(alert => {
                            const alertInfo = getAlertTypeInfo(alert.alert_type, alert.severity);
                            const impactInfo = getAlertImpactInfo(alert);
                            const timeAgo = getTimeAgo(new Date(alert.created_at));
                            
                            return `
                            <tr class="${alert.severity === 'critical' ? 'table-danger' : alert.severity === 'high' ? 'table-warning' : ''}">
                                <td class="text-center">
                                    <div class="d-flex flex-column align-items-center">
                                        <div class="priority-indicator priority-${alert.severity} mb-1" 
                                             data-bs-toggle="tooltip" data-bs-placement="right"
                                             data-bs-title="${alertInfo.priorityExplanation}">
                                            <i class="bi bi-${alertInfo.priorityIcon}"></i>
                                        </div>
                                        <small class="text-muted">${alert.severity.toUpperCase()}</small>
                                    </div>
                                </td>
                                <td>
                                    <div class="fw-medium">${alert.device_name}</div>
                                    <small class="text-muted">Device</small>
                                </td>
                                <td>
                                    <div class="d-flex align-items-center mb-1">
                                        <i class="bi bi-${alertInfo.icon} me-2 ${alertInfo.iconColor}"></i>
                                        <span class="fw-medium">${alertInfo.displayName}</span>
                                    </div>
                                    <small class="text-muted">${alertInfo.description}</small>
                                </td>
                                <td>
                                    <div class="impact-assessment">
                                        <div class="fw-medium text-${impactInfo.color}">${impactInfo.level}</div>
                                        <small class="text-muted">${impactInfo.description}</small>
                                        ${alert.risk_score ? `<div class="mt-1"><small class="text-muted">Risk: ${alert.risk_score}/10</small></div>` : ''}
                                    </div>
                                </td>
                                <td>
                                    <div class="alert-details">
                                        <div class="mb-1">${alert.message.replace('[SECURITY] ', '')}</div>
                                        ${alert.port ? `<div><code class="bg-light px-1 rounded">Port ${alert.port}</code></div>` : ''}
                                        ${alert.service ? `<div class="mt-1"><small class="text-muted">Service: ${alert.service}</small></div>` : ''}
                                        ${alert.version ? `<div><small class="text-muted">Version: ${alert.version}</small></div>` : ''}
                                    </div>
                                </td>
                                <td>
                                    <div class="time-info">
                                        <div class="fw-medium">${timeAgo}</div>
                                        <small class="text-muted">${new Date(alert.created_at).toLocaleDateString()}</small>
                                    </div>
                                </td>
                                <td class="text-center">
                                    <div class="btn-group-vertical btn-group-sm">
                                        ${alert.acknowledged ? 
                                            '<span class="badge bg-success mb-1"><i class="bi bi-check-circle"></i> Reviewed</span>' : 
                                            `<button class="btn btn-outline-success btn-sm mb-1" onclick="acknowledgeAlert(${alert.id})" 
                                                     data-bs-toggle="tooltip" data-bs-placement="left" 
                                                     data-bs-title="Mark this alert as reviewed and understood">
                                                <i class="bi bi-check"></i> Review
                                             </button>`
                                        }
                                        ${alertInfo.hasRemediation ? 
                                            `<button class="btn btn-outline-primary btn-sm" onclick="showRemediationInfo('${alert.alert_type}', '${alert.severity}')"
                                                     data-bs-toggle="tooltip" data-bs-placement="left" 
                                                     data-bs-title="Get guidance on how to address this security issue">
                                                <i class="bi bi-question-circle"></i> Help
                                             </button>` : ''
                                        }
                                    </div>
                                </td>
                            </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        `;
        
        container.innerHTML = table;
    }
    
    function updateSecurityRecommendations(riskAssessment) {
        const container = document.getElementById('security-recommendations');
        if (!container) return;
        
        if (!riskAssessment || !riskAssessment.recommendations) {
            container.innerHTML = `
                <div class="text-center py-3">
                    <div class="text-info mb-2">
                        <i class="bi bi-lightbulb" style="font-size: 1.5rem;"></i>
                    </div>
                    <div class="text-muted">
                        <strong>Analysis in progress</strong><br>
                        <small>Security recommendations will appear after scanning your network.</small>
                    </div>
                </div>
            `;
            return;
        }
        
        const riskLevel = riskAssessment.overall_risk_level || 'low';
        const riskScore = riskAssessment.risk_score || 0;
        
        // Enhanced risk level explanations
        const riskLevelInfo = {
            'low': {
                title: 'Low Risk - Good Security Posture',
                explanation: 'Your network shows good security practices with minimal risks detected.',
                color: 'success',
                icon: 'shield-check'
            },
            'medium': {
                title: 'Medium Risk - Some Attention Needed',
                explanation: 'Minor security issues detected that should be addressed when convenient.',
                color: 'warning',
                icon: 'shield-exclamation'
            },
            'high': {
                title: 'High Risk - Review Required',
                explanation: 'Security concerns found that should be reviewed and addressed soon.',
                color: 'danger',
                icon: 'shield-exclamation'
            },
            'critical': {
                title: 'Critical Risk - Immediate Action Required',
                explanation: 'Serious security vulnerabilities detected that need immediate attention.',
                color: 'danger',
                icon: 'shield-x'
            }
        };
        
        const riskInfo = riskLevelInfo[riskLevel] || riskLevelInfo['low'];
        
        // Prioritize recommendations by importance
        const prioritizedRecommendations = riskAssessment.recommendations.map((rec, index) => {
            let priority = 'medium';
            let icon = 'check-circle';
            
            if (rec.toLowerCase().includes('immediate') || rec.toLowerCase().includes('critical')) {
                priority = 'high';
                icon = 'exclamation-triangle';
            } else if (rec.toLowerCase().includes('enable') || rec.toLowerCase().includes('update')) {
                priority = 'medium';
                icon = 'gear';
            } else {
                priority = 'low';
                icon = 'info-circle';
            }
            
            return { text: rec, priority, icon, order: priority === 'high' ? 0 : (priority === 'medium' ? 1 : 2) };
        }).sort((a, b) => a.order - b.order);
        
        const recommendations = prioritizedRecommendations.map(rec => {
            const priorityColors = {
                'high': 'text-danger',
                'medium': 'text-warning', 
                'low': 'text-info'
            };
            
            return `
                <div class="d-flex align-items-start mb-3 p-2 rounded" style="background-color: rgba(var(--bs-primary-rgb), 0.05);">
                    <i class="bi bi-${rec.icon} ${priorityColors[rec.priority]} me-3 mt-1" style="font-size: 1.1rem;"></i>
                    <div class="flex-grow-1">
                        <div class="fw-medium mb-1">${rec.text}</div>
                        <small class="text-muted">
                            ${rec.priority === 'high' ? 'High Priority - Address soon' : 
                              rec.priority === 'medium' ? 'Medium Priority - Plan to address' : 
                              'Low Priority - Consider when convenient'}
                        </small>
                    </div>
                </div>
            `;
        }).join('');
        
        container.innerHTML = `
            <div class="alert alert-${riskInfo.color} mb-4" style="border: 2px solid; border-radius: 8px;">
                <div class="d-flex align-items-center mb-2">
                    <i class="bi bi-${riskInfo.icon} me-2" style="font-size: 1.2rem;"></i>
                    <strong>${riskInfo.title}</strong>
                </div>
                <div class="mb-2">${riskInfo.explanation}</div>
                <div class="d-flex align-items-center">
                    <span class="me-3">Risk Score: <strong>${riskScore}/100</strong></span>
                    <div class="progress flex-grow-1" style="height: 8px;">
                        <div class="progress-bar bg-${getRiskColor(riskScore)}" style="width: ${riskScore}%"></div>
                    </div>
                </div>
            </div>
            
            <h6 class="mb-3 d-flex align-items-center">
                <i class="bi bi-lightbulb me-2"></i>
                Recommended Actions
                ${prioritizedRecommendations.length > 0 ? `<span class="badge bg-primary ms-2">${prioritizedRecommendations.length}</span>` : ''}
            </h6>
            ${recommendations || '<div class="text-muted">No specific recommendations at this time. Keep monitoring your network regularly.</div>'}
        `;
    }
    
    function getRiskColor(score) {
        if (score >= 8) return 'danger';
        if (score >= 6) return 'warning';
        if (score >= 4) return 'info';
        return 'success';
    }
    
    function getRiskIcon(score) {
        if (score >= 8) return '!';
        if (score >= 6) return '*';
        if (score >= 4) return 'o';
        return '+';
    }
    
    function getSecurityBadgeClass(status) {
        const statusMap = {
            'low': 'secure',
            'medium': 'medium-risk',
            'high': 'high-risk',
            'critical': 'critical-risk'
        };
        return statusMap[status] || 'secure';
    }
    
    function getRiskLevelFromScore(score) {
        if (score >= 8) return 'critical';
        if (score >= 6) return 'high';
        if (score >= 4) return 'medium';
        return 'low';
    }
    
    function getSecurityStatusColor(status) {
        const colors = {
            'low': 'success',
            'medium': 'warning', 
            'high': 'danger',
            'critical': 'dark'
        };
        return colors[status] || 'secondary';
    }
    
    function getSeverityColor(severity) {
        const colors = {
            'low': 'success',
            'medium': 'warning',
            'high': 'danger',
            'critical': 'dark'
        };
        return colors[severity] || 'secondary';
    }
    
    // Alert type information and categorization
    function getAlertTypeInfo(alertType, severity) {
        const alertTypes = {
            'new_service': {
                displayName: 'New Service Detected',
                description: 'A previously unknown service has been discovered',
                icon: 'plus-circle',
                iconColor: 'text-info',
                hasRemediation: true,
                priorityExplanation: 'New services may indicate changes in your network or potential security risks'
            },
            'suspicious_port': {
                displayName: 'Suspicious Port Open',
                description: 'A port associated with security risks is open',
                icon: 'door-open',
                iconColor: 'text-warning',
                hasRemediation: true,
                priorityExplanation: 'Suspicious ports can provide entry points for attackers'
            },
            'vulnerability': {
                displayName: 'Security Vulnerability',
                description: 'A known security weakness has been identified',
                icon: 'shield-exclamation',
                iconColor: 'text-danger',
                hasRemediation: true,
                priorityExplanation: 'Vulnerabilities can be exploited by attackers to gain access'
            },
            'config_change': {
                displayName: 'Configuration Change',
                description: 'A security-related configuration has changed',
                icon: 'gear',
                iconColor: 'text-warning',
                hasRemediation: true,
                priorityExplanation: 'Unexpected configuration changes may indicate security issues'
            }
        };
        
        const info = alertTypes[alertType] || {
            displayName: alertType.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase()),
            description: 'Security alert requiring attention',
            icon: 'exclamation-triangle',
            iconColor: 'text-warning',
            hasRemediation: false,
            priorityExplanation: 'This alert indicates a potential security concern'
        };
        
        // Set priority icon based on severity
        info.priorityIcon = {
            'critical': 'exclamation-triangle-fill',
            'high': 'exclamation-circle',
            'medium': 'info-circle',
            'low': 'circle'
        }[severity] || 'circle';
        
        return info;
    }
    
    // Impact assessment for alerts
    function getAlertImpactInfo(alert) {
        const severity = alert.severity;
        const alertType = alert.alert_type;
        const riskScore = alert.risk_score || 0;
        
        let impact = {
            level: 'Unknown',
            description: 'Impact assessment unavailable',
            color: 'muted'
        };
        
        if (severity === 'critical') {
            impact = {
                level: 'Critical Impact',
                description: 'Immediate security risk to network',
                color: 'danger'
            };
        } else if (severity === 'high' || riskScore >= 7) {
            impact = {
                level: 'High Impact',
                description: 'Significant security concern',
                color: 'warning'
            };
        } else if (severity === 'medium' || riskScore >= 4) {
            impact = {
                level: 'Medium Impact',
                description: 'Moderate security risk',
                color: 'info'
            };
        } else {
            impact = {
                level: 'Low Impact',
                description: 'Minor security concern',
                color: 'success'
            };
        }
        
        return impact;
    }
    
    // Time ago helper function
    function getTimeAgo(date) {
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        if (diffDays < 30) return `${diffDays}d ago`;
        return date.toLocaleDateString();
    }
    
    // Show remediation information
    function showRemediationInfo(alertType, severity) {
        const remediationInfo = {
            'new_service': {
                title: 'New Service Detected - What to do',
                content: `
                    <div class="mb-3">
                        <h6>Immediate Steps:</h6>
                        <ol class="small">
                            <li>Verify if this service was intentionally installed</li>
                            <li>Check if the service is necessary for your operations</li>
                            <li>Ensure the service is properly configured and secured</li>
                            <li>Consider disabling the service if it's not needed</li>
                        </ol>
                    </div>
                    <div class="alert alert-info small">
                        <strong>Why this matters:</strong> New services can introduce vulnerabilities or provide unauthorized access points.
                    </div>
                `
            },
            'suspicious_port': {
                title: 'Suspicious Port Open - What to do',
                content: `
                    <div class="mb-3">
                        <h6>Immediate Steps:</h6>
                        <ol class="small">
                            <li>Identify what service is running on this port</li>
                            <li>Check if the service is legitimate and necessary</li>
                            <li>Review security settings for the service</li>
                            <li>Consider blocking the port if the service is not needed</li>
                            <li>Update the service to the latest version</li>
                        </ol>
                    </div>
                    <div class="alert alert-warning small">
                        <strong>Why this matters:</strong> Suspicious ports often run services that are commonly targeted by attackers.
                    </div>
                `
            },
            'vulnerability': {
                title: 'Security Vulnerability - What to do',
                content: `
                    <div class="mb-3">
                        <h6>Immediate Steps:</h6>
                        <ol class="small">
                            <li><strong>Update immediately:</strong> Install the latest software updates</li>
                            <li>Review security patches for the affected service</li>
                            <li>Consider temporarily disabling the service if updates aren't available</li>
                            <li>Monitor for any suspicious activity</li>
                            <li>Check vendor security advisories</li>
                        </ol>
                    </div>
                    <div class="alert alert-danger small">
                        <strong>Why this matters:</strong> Vulnerabilities can be exploited by attackers to gain unauthorized access to your network.
                    </div>
                `
            }
        };
        
        const info = remediationInfo[alertType] || {
            title: 'Security Alert - General Guidance',
            content: `
                <div class="mb-3">
                    <h6>General Security Steps:</h6>
                    <ol class="small">
                        <li>Review the alert details carefully</li>
                        <li>Investigate the affected device or service</li>
                        <li>Apply security updates if available</li>
                        <li>Consider consulting security documentation</li>
                        <li>Monitor for related security issues</li>
                    </ol>
                </div>
                <div class="alert alert-info small">
                    <strong>When in doubt:</strong> Consult with a security professional or your IT support team.
                </div>
            `
        };
        
        // Create and show modal with remediation information
        const modalHtml = `
            <div class="modal fade" id="remediationModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">${info.title}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            ${info.content}
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Remove existing modal if any
        const existingModal = document.getElementById('remediationModal');
        if (existingModal) {
            existingModal.remove();
        }
        
        // Add modal to page and show it
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        const modal = new bootstrap.Modal(document.getElementById('remediationModal'));
        modal.show();
        
        // Clean up modal after it's hidden
        document.getElementById('remediationModal').addEventListener('hidden.bs.modal', function() {
            this.remove();
        });
    }
    
    async function scanDevice(deviceId) {
        try {
            showToast('Starting device security scan...', 'info');
            
            const response = await fetch(`/api/security/device/${deviceId}/scan`, {
                method: 'POST',
                headers: getHeaders()
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast(`Device scan completed. Found ${data.open_ports} open ports, ${data.security_alerts} security alerts.`, 'success');
                loadSecurityData(); // Refresh data
            } else {
                showToast(`Device scan failed: ${data.error}`, 'error');
            }
        } catch (error) {
            console.error('Error scanning device:', error);
            showToast('Error scanning device', 'error');
        }
    }
    
    async function acknowledgeAlert(alertId) {
        try {
            const response = await fetch(`/api/monitoring/alerts/${alertId}/acknowledge`, {
                method: 'POST',
                headers: getHeaders()
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast('Alert acknowledged', 'success');
                loadSecurityAlerts(); // Refresh alerts
            } else {
                showToast(`Failed to acknowledge alert: ${data.error}`, 'error');
            }
        } catch (error) {
            console.error('Error acknowledging alert:', error);
            showToast('Error acknowledging alert', 'error');
        }
    }
    
    async function updateSecuritySettings(event) {
        event.preventDefault();
        
        try {
            const settings = {
                scan_interval: parseInt(document.getElementById('scan-interval').value) * 3600, // Convert to seconds
                top_ports: parseInt(document.getElementById('top-ports').value),
                service_detection: document.getElementById('service-detection').checked,
                version_detection: document.getElementById('version-detection').checked
            };
            
            // For now, just show a success message
            // In production, this would update the scanner configuration
            showToast('Security settings updated successfully', 'success');
            
        } catch (error) {
            console.error('Error updating settings:', error);
            showToast('Error updating security settings', 'error');
        }
    }
    
    // Network risk calculation
    function calculateNetworkRiskScore(summary) {
        const critical = summary.by_severity?.critical || 0;
        const high = summary.by_severity?.high || 0;
        const medium = summary.by_severity?.medium || 0;
        const low = summary.by_severity?.low || 0;
        
        // Weighted risk calculation
        const riskScore = (critical * 10) + (high * 7) + (medium * 4) + (low * 1);
        const totalAlerts = critical + high + medium + low;
        
        if (totalAlerts === 0) return 0;
        
        const averageRisk = riskScore / totalAlerts;
        return Math.min(10, averageRisk);
    }
    
    // Alert Management Functions
    function toggleAlertFilters() {
        const filtersDiv = document.getElementById('alert-filters');
        const button = document.getElementById('filter-alerts-btn');
        
        if (filtersDiv.style.display === 'none') {
            filtersDiv.style.display = 'block';
            button.classList.add('btn-primary');
            button.classList.remove('btn-outline-primary');
        } else {
            filtersDiv.style.display = 'none';
            button.classList.remove('btn-primary');
            button.classList.add('btn-outline-primary');
        }
    }
    
    function clearAlertFilters() {
        document.getElementById('severity-filter').value = '';
        document.getElementById('type-filter').value = '';
        document.getElementById('status-filter').value = '';
        applyAlertFilters();
    }
    
    function handleAlertSelection(event) {
        const alertId = parseInt(event.target.value);
        
        if (event.target.checked) {
            selectedAlerts.add(alertId);
        } else {
            selectedAlerts.delete(alertId);
        }
        
        updateBulkActionsBar();
        updateSelectAllCheckbox();
    }
    
    function toggleSelectAllAlerts(event) {
        const checkboxes = document.querySelectorAll('.alert-checkbox');
        
        checkboxes.forEach(checkbox => {
            checkbox.checked = event.target.checked;
            const alertId = parseInt(checkbox.value);
            
            if (event.target.checked) {
                selectedAlerts.add(alertId);
            } else {
                selectedAlerts.delete(alertId);
            }
        });
        
        updateBulkActionsBar();
    }
    
    function updateSelectAllCheckbox() {
        const selectAllCheckbox = document.getElementById('select-all-alerts');
        const checkboxes = document.querySelectorAll('.alert-checkbox');
        
        if (checkboxes.length === 0) {
            selectAllCheckbox.checked = false;
            selectAllCheckbox.indeterminate = false;
        } else if (selectedAlerts.size === checkboxes.length) {
            selectAllCheckbox.checked = true;
            selectAllCheckbox.indeterminate = false;
        } else if (selectedAlerts.size > 0) {
            selectAllCheckbox.checked = false;
            selectAllCheckbox.indeterminate = true;
        } else {
            selectAllCheckbox.checked = false;
            selectAllCheckbox.indeterminate = false;
        }
    }
    
    function updateBulkActionsBar() {
        const bulkActionsBar = document.getElementById('bulk-actions-bar');
        const selectedCount = document.getElementById('selected-count');
        
        if (selectedAlerts.size > 0) {
            bulkActionsBar.style.display = 'block';
            selectedCount.textContent = selectedAlerts.size;
        } else {
            bulkActionsBar.style.display = 'none';
        }
    }
    
    function clearAlertSelection() {
        selectedAlerts.clear();
        document.querySelectorAll('.alert-checkbox').forEach(checkbox => {
            checkbox.checked = false;
        });
        updateBulkActionsBar();
        updateSelectAllCheckbox();
    }
    
    async function bulkAcknowledgeAlerts() {
        if (selectedAlerts.size === 0) return;
        
        try {
            const promises = Array.from(selectedAlerts).map(alertId => 
                fetch(`/api/monitoring/alerts/${alertId}/acknowledge`, {
                    method: 'POST',
                    headers: getHeaders()
                })
            );
            
            await Promise.all(promises);
            
            showToast(`Successfully acknowledged ${selectedAlerts.size} alert${selectedAlerts.size > 1 ? 's' : ''}`, 'success');
            
            // Refresh alerts and clear selection
            clearAlertSelection();
            loadSecurityAlerts();
            
        } catch (error) {
            console.error('Error acknowledging alerts:', error);
            showToast('Error acknowledging selected alerts', 'error');
        }
    }
    
    async function acknowledgeAllVisibleAlerts() {
        const unacknowledgedAlerts = filteredAlerts.filter(alert => !alert.acknowledged);
        
        if (unacknowledgedAlerts.length === 0) {
            showToast('No unacknowledged alerts to process', 'info');
            return;
        }
        
        if (!confirm(`Are you sure you want to acknowledge all ${unacknowledgedAlerts.length} visible alert${unacknowledgedAlerts.length > 1 ? 's' : ''}?`)) {
            return;
        }
        
        try {
            const promises = unacknowledgedAlerts.map(alert => 
                fetch(`/api/monitoring/alerts/${alert.id}/acknowledge`, {
                    method: 'POST',
                    headers: getHeaders()
                })
            );
            
            await Promise.all(promises);
            
            showToast(`Successfully acknowledged ${unacknowledgedAlerts.length} alert${unacknowledgedAlerts.length > 1 ? 's' : ''}`, 'success');
            
            // Refresh alerts
            loadSecurityAlerts();
            
        } catch (error) {
            console.error('Error acknowledging all alerts:', error);
            showToast('Error acknowledging alerts', 'error');
        }
    }
    
    // Security Education Modal
    function showSecurityGuideModal() {
        const modalHtml = `
            <div class="modal fade" id="securityGuideModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header bg-primary text-white">
                            <h5 class="modal-title"><i class="bi bi-question-circle me-2"></i>Quick Security Guide</h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <h6 class="text-success"><i class="bi bi-shield-check"></i> Understanding Security Levels</h6>
                            <div class="mb-3">
                                <div class="mb-2"><span class="badge bg-success">SECURE</span> No significant issues found</div>
                                <div class="mb-2"><span class="badge bg-warning">MODERATE</span> Minor security concerns to monitor</div>
                                <div class="mb-2"><span class="badge bg-danger">AT RISK</span> Security issues need attention</div>
                                <div class="mb-2"><span class="badge bg-dark">CRITICAL</span> Immediate action required</div>
                            </div>
                            
                            <h6 class="text-info"><i class="bi bi-lightbulb"></i> What to Do About Alerts</h6>
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="card border-primary mb-3">
                                        <div class="card-header bg-primary text-white">
                                            <strong>New Service Detected:</strong>
                                        </div>
                                        <div class="card-body">
                                            <ol class="small mb-0">
                                                <li>Check if you recognize the service</li>
                                                <li>Verify it's needed for your operations</li>
                                                <li>Update if legitimate but outdated</li>
                                                <li>Disable if unnecessary</li>
                                            </ol>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="card border-warning mb-3">
                                        <div class="card-header bg-warning text-dark">
                                            <strong>Suspicious Port Open:</strong>
                                        </div>
                                        <div class="card-body">
                                            <ol class="small mb-0">
                                                <li>Research what uses that port</li>
                                                <li>Check if the service is legitimate</li>
                                                <li>Consider blocking if unneeded</li>
                                                <li>Get help if you're unsure</li>
                                            </ol>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="alert alert-info">
                                <strong><i class="bi bi-info-circle"></i> Remember:</strong> When in doubt, it's safer to ask for help or disable services you don't recognize.
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Remove existing modal if any
        const existingModal = document.getElementById('securityGuideModal');
        if (existingModal) existingModal.remove();
        
        // Add modal to page and show it
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        const modal = new bootstrap.Modal(document.getElementById('securityGuideModal'));
        modal.show();
        
        // Clean up modal after it's hidden
        document.getElementById('securityGuideModal').addEventListener('hidden.bs.modal', function() {
            this.remove();
        });
    }
    
    // Debounce utility function
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
