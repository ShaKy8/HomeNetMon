/**
 * HomeNetMon JavaScript/TypeScript SDK
 * Optimized for mobile applications, React Native, and web apps
 * 
 * @version 1.0.0
 * @author HomeNetMon Team
 */

class HomeNetMonSDK {
    constructor(config = {}) {
        this.baseUrl = config.baseUrl || 'http://localhost:5000';
        this.apiVersion = config.apiVersion || 'v1';
        this.apiKey = config.apiKey || null;
        this.sessionToken = config.sessionToken || null;
        
        // Configuration
        this.config = {
            timeout: config.timeout || 30000,
            retryAttempts: config.retryAttempts || 3,
            retryDelay: config.retryDelay || 1000,
            enableCompression: config.enableCompression !== false,
            enableOffline: config.enableOffline !== false,
            syncInterval: config.syncInterval || 30000,
            debugMode: config.debugMode || false,
            ...config
        };
        
        // State management
        this.isOnline = navigator.onLine || true;
        this.lastSyncTime = null;
        this.syncInProgress = false;
        this.offlineQueue = [];
        this.eventListeners = {};
        this.cache = new Map();
        
        // Setup event listeners
        this.setupNetworkListeners();
        this.setupAutoSync();
        
        // Load offline data if available
        this.loadOfflineData();
    }
    
    // ========================================================================
    // Authentication Methods
    // ========================================================================
    
    /**
     * Authenticate with username and password
     */
    async login(username, password, mfaToken = null, rememberMe = false) {
        try {
            const response = await this.request('/api/remote/auth/login', {
                method: 'POST',
                body: {
                    username,
                    password,
                    mfa_token: mfaToken,
                    remember_me: rememberMe
                }
            });
            
            if (response.session_token) {
                this.sessionToken = response.session_token;
                this.storeCredentials();
                this.emit('authenticated', response.user);
            }
            
            return response;
        } catch (error) {
            this.emit('authenticationError', error);
            throw error;
        }
    }
    
    /**
     * Logout and clear credentials
     */
    async logout() {
        try {
            if (this.sessionToken) {
                await this.request('/api/remote/auth/logout', {
                    method: 'POST'
                });
            }
        } catch (error) {
            console.warn('Logout request failed:', error);
        } finally {
            this.sessionToken = null;
            this.clearCredentials();
            this.emit('logout');
        }
    }
    
    /**
     * Set API key for authentication
     */
    setApiKey(apiKey) {
        this.apiKey = apiKey;
        this.storeCredentials();
    }
    
    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return !!(this.sessionToken || this.apiKey);
    }
    
    // ========================================================================
    // Device Management
    // ========================================================================
    
    /**
     * Get devices with filtering and pagination
     */
    async getDevices(options = {}) {
        const params = new URLSearchParams();
        
        if (options.page) params.append('page', options.page);
        if (options.perPage) params.append('per_page', options.perPage);
        if (options.status) params.append('status', options.status);
        if (options.deviceType) params.append('device_type', options.deviceType);
        if (options.search) params.append('search', options.search);
        if (options.includeMetrics) params.append('include_metrics', 'true');
        if (this.config.enableCompression) params.append('compress', 'true');
        
        const url = `/api/mobile/v1/devices?${params.toString()}`;
        const response = await this.request(url);
        
        // Cache device data
        if (response.devices) {
            this.cacheDevices(response.devices);
        }
        
        return response;
    }
    
    /**
     * Get detailed device information
     */
    async getDevice(deviceId, options = {}) {
        const params = new URLSearchParams();
        if (options.hours) params.append('hours', options.hours);
        
        const url = `/api/mobile/v1/devices/${deviceId}?${params.toString()}`;
        const response = await this.request(url);
        
        // Cache device details
        if (response.device) {
            this.cache.set(`device_${deviceId}`, {
                data: response.device,
                timestamp: Date.now()
            });
        }
        
        return response;
    }
    
    /**
     * Ping a device
     */
    async pingDevice(deviceId) {
        if (!this.isOnline) {
            return this.queueOfflineAction('ping_device', { device_id: deviceId });
        }
        
        return await this.request(`/api/mobile/v1/ping/${deviceId}`, {
            method: 'POST'
        });
    }
    
    /**
     * Update device information
     */
    async updateDevice(deviceId, updates) {
        if (!this.isOnline) {
            return this.queueOfflineAction('update_device', {
                device_id: deviceId,
                updates
            });
        }
        
        const response = await this.request(`/api/devices/${deviceId}`, {
            method: 'PUT',
            body: updates
        });
        
        // Update cache
        this.invalidateDeviceCache(deviceId);
        
        return response;
    }
    
    // ========================================================================
    // Alert Management
    // ========================================================================
    
    /**
     * Get alerts with filtering
     */
    async getAlerts(options = {}) {
        const params = new URLSearchParams();
        
        if (options.page) params.append('page', options.page);
        if (options.perPage) params.append('per_page', options.perPage);
        if (options.severity) params.append('severity', options.severity);
        if (options.acknowledged) params.append('acknowledged', options.acknowledged);
        if (options.deviceId) params.append('device_id', options.deviceId);
        if (options.since) params.append('since', options.since);
        
        const url = `/api/alerts?${params.toString()}`;
        return await this.request(url);
    }
    
    /**
     * Acknowledge an alert
     */
    async acknowledgeAlert(alertId) {
        if (!this.isOnline) {
            return this.queueOfflineAction('acknowledge_alert', { alert_id: alertId });
        }
        
        return await this.request(`/api/mobile/v1/alerts/${alertId}/acknowledge`, {
            method: 'POST'
        });
    }
    
    // ========================================================================
    // Real-time Data Sync
    // ========================================================================
    
    /**
     * Get incremental updates since last sync
     */
    async getDeltaSync(options = {}) {
        const params = new URLSearchParams();
        
        if (this.lastSyncTime) {
            params.append('last_sync', this.lastSyncTime);
        }
        
        params.append('include_devices', options.includeDevices !== false);
        params.append('include_alerts', options.includeAlerts !== false);
        params.append('include_monitoring', options.includeMonitoring || false);
        
        const url = `/api/mobile/v1/sync/delta?${params.toString()}`;
        const response = await this.request(url);
        
        if (response.success) {
            this.lastSyncTime = response.sync_timestamp;
            this.processDeltaUpdates(response.delta);
            this.storeLastSyncTime();
        }
        
        return response;
    }
    
    /**
     * Process offline queue with batch sync
     */
    async syncOfflineQueue() {
        if (this.offlineQueue.length === 0) {
            return { success: true, processed: 0 };
        }
        
        try {
            const response = await this.request('/api/mobile/v1/sync/batch', {
                method: 'POST',
                body: {
                    operations: this.offlineQueue
                }
            });
            
            if (response.success) {
                // Remove successfully processed operations
                this.offlineQueue = this.offlineQueue.filter((_, index) => {
                    const result = response.results.find(r => r.index === index);
                    return result && !result.success;
                });
                
                this.storeOfflineQueue();
                this.emit('offlineSyncComplete', response);
            }
            
            return response;
        } catch (error) {
            console.error('Failed to sync offline queue:', error);
            throw error;
        }
    }
    
    /**
     * Get network summary
     */
    async getNetworkSummary(cacheMinutes = 5) {
        const cacheKey = 'network_summary';
        const cached = this.cache.get(cacheKey);
        
        if (cached && (Date.now() - cached.timestamp) < (cacheMinutes * 60 * 1000)) {
            return cached.data;
        }
        
        const params = new URLSearchParams();
        params.append('cache', cacheMinutes);
        
        const url = `/api/mobile/v1/network/summary?${params.toString()}`;
        const response = await this.request(url);
        
        if (response.success) {
            this.cache.set(cacheKey, {
                data: response,
                timestamp: Date.now()
            });
        }
        
        return response;
    }
    
    // ========================================================================
    // Configuration and Setup
    // ========================================================================
    
    /**
     * Get mobile app configuration
     */
    async getMobileConfig() {
        return await this.request('/api/mobile/v1/config/mobile');
    }
    
    /**
     * Update SDK configuration
     */
    updateConfig(newConfig) {
        this.config = { ...this.config, ...newConfig };
        
        // Restart auto-sync if interval changed
        if (newConfig.syncInterval) {
            this.setupAutoSync();
        }
    }
    
    // ========================================================================
    // Offline Support
    // ========================================================================
    
    /**
     * Queue action for offline processing
     */
    queueOfflineAction(type, data) {
        const action = {
            type,
            ...data,
            timestamp: new Date().toISOString(),
            id: this.generateId()
        };
        
        this.offlineQueue.push(action);
        this.storeOfflineQueue();
        
        this.emit('offlineAction', action);
        
        return {
            success: true,
            queued: true,
            actionId: action.id
        };
    }
    
    /**
     * Get cached device data for offline use
     */
    getCachedDevices() {
        const cached = this.getFromStorage('cached_devices');
        return cached ? JSON.parse(cached) : [];
    }
    
    /**
     * Check if data is available offline
     */
    isDataAvailableOffline(type, id = null) {
        if (type === 'devices') {
            return this.getCachedDevices().length > 0;
        }
        
        if (type === 'device' && id) {
            return this.cache.has(`device_${id}`);
        }
        
        return false;
    }
    
    // ========================================================================
    // Event Management
    // ========================================================================
    
    /**
     * Add event listener
     */
    on(event, callback) {
        if (!this.eventListeners[event]) {
            this.eventListeners[event] = [];
        }
        this.eventListeners[event].push(callback);
    }
    
    /**
     * Remove event listener
     */
    off(event, callback) {
        if (this.eventListeners[event]) {
            this.eventListeners[event] = this.eventListeners[event].filter(cb => cb !== callback);
        }
    }
    
    /**
     * Emit event
     */
    emit(event, data) {
        if (this.eventListeners[event]) {
            this.eventListeners[event].forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error(`Error in event listener for ${event}:`, error);
                }
            });
        }
    }
    
    // ========================================================================
    // Private Methods
    // ========================================================================
    
    /**
     * Make HTTP request with error handling and retries
     */
    async request(url, options = {}) {
        const fullUrl = url.startsWith('http') ? url : `${this.baseUrl}${url}`;
        
        const requestOptions = {
            method: options.method || 'GET',
            headers: {
                'Content-Type': 'application/json',
                ...this.getAuthHeaders(),
                ...options.headers
            },
            signal: AbortSignal.timeout(this.config.timeout)
        };
        
        if (options.body) {
            requestOptions.body = JSON.stringify(options.body);
        }
        
        let lastError;
        
        for (let attempt = 0; attempt < this.config.retryAttempts; attempt++) {
            try {
                if (this.config.debugMode) {
                    console.log(`SDK Request [${attempt + 1}/${this.config.retryAttempts}]:`, {
                        url: fullUrl,
                        method: requestOptions.method,
                        headers: requestOptions.headers
                    });
                }
                
                const response = await fetch(fullUrl, requestOptions);
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const data = await response.json();
                
                // Handle compressed responses
                if (data.compressed) {
                    const decompressed = await this.decompressData(data.data);
                    return JSON.parse(decompressed);
                }
                
                return data;
                
            } catch (error) {
                lastError = error;
                
                if (attempt < this.config.retryAttempts - 1) {
                    const delay = this.config.retryDelay * Math.pow(2, attempt);
                    await this.sleep(delay);
                }
            }
        }
        
        throw lastError;
    }
    
    /**
     * Get authentication headers
     */
    getAuthHeaders() {
        const headers = {};
        
        if (this.sessionToken) {
            headers['Authorization'] = `Bearer ${this.sessionToken}`;
        } else if (this.apiKey) {
            headers['X-API-Key'] = this.apiKey;
        }
        
        return headers;
    }
    
    /**
     * Setup network status listeners
     */
    setupNetworkListeners() {
        if (typeof window !== 'undefined') {
            window.addEventListener('online', () => {
                this.isOnline = true;
                this.emit('online');
                this.syncOfflineQueue();
            });
            
            window.addEventListener('offline', () => {
                this.isOnline = false;
                this.emit('offline');
            });
        }
    }
    
    /**
     * Setup automatic synchronization
     */
    setupAutoSync() {
        if (this.syncTimer) {
            clearInterval(this.syncTimer);
        }
        
        if (this.config.syncInterval > 0) {
            this.syncTimer = setInterval(() => {
                if (this.isOnline && !this.syncInProgress && this.isAuthenticated()) {
                    this.performAutoSync();
                }
            }, this.config.syncInterval);
        }
    }
    
    /**
     * Perform automatic synchronization
     */
    async performAutoSync() {
        try {
            this.syncInProgress = true;
            
            // Sync offline queue first
            if (this.offlineQueue.length > 0) {
                await this.syncOfflineQueue();
            }
            
            // Get delta updates
            await this.getDeltaSync();
            
            this.emit('autoSyncComplete');
            
        } catch (error) {
            console.error('Auto sync failed:', error);
            this.emit('autoSyncError', error);
        } finally {
            this.syncInProgress = false;
        }
    }
    
    /**
     * Process delta updates
     */
    processDeltaUpdates(delta) {
        if (delta.devices) {
            this.emit('devicesUpdated', delta.devices);
        }
        
        if (delta.alerts) {
            this.emit('alertsUpdated', delta.alerts);
        }
        
        if (delta.monitoring) {
            this.emit('monitoringUpdated', delta.monitoring);
        }
    }
    
    /**
     * Cache device data
     */
    cacheDevices(devices) {
        this.storeInStorage('cached_devices', JSON.stringify(devices));
        
        devices.forEach(device => {
            this.cache.set(`device_${device.id}`, {
                data: device,
                timestamp: Date.now()
            });
        });
    }
    
    /**
     * Invalidate device cache
     */
    invalidateDeviceCache(deviceId = null) {
        if (deviceId) {
            this.cache.delete(`device_${deviceId}`);
        } else {
            // Clear all device cache
            for (const key of this.cache.keys()) {
                if (key.startsWith('device_')) {
                    this.cache.delete(key);
                }
            }
        }
    }
    
    /**
     * Storage methods
     */
    storeInStorage(key, value) {
        try {
            if (typeof localStorage !== 'undefined') {
                localStorage.setItem(`homenetmon_${key}`, value);
            }
        } catch (error) {
            console.warn('Failed to store data:', error);
        }
    }
    
    getFromStorage(key) {
        try {
            if (typeof localStorage !== 'undefined') {
                return localStorage.getItem(`homenetmon_${key}`);
            }
        } catch (error) {
            console.warn('Failed to get data from storage:', error);
        }
        return null;
    }
    
    removeFromStorage(key) {
        try {
            if (typeof localStorage !== 'undefined') {
                localStorage.removeItem(`homenetmon_${key}`);
            }
        } catch (error) {
            console.warn('Failed to remove data from storage:', error);
        }
    }
    
    /**
     * Store credentials
     */
    storeCredentials() {
        if (this.sessionToken) {
            this.storeInStorage('session_token', this.sessionToken);
        }
        if (this.apiKey) {
            this.storeInStorage('api_key', this.apiKey);
        }
    }
    
    /**
     * Load credentials
     */
    loadCredentials() {
        const sessionToken = this.getFromStorage('session_token');
        const apiKey = this.getFromStorage('api_key');
        
        if (sessionToken) this.sessionToken = sessionToken;
        if (apiKey) this.apiKey = apiKey;
    }
    
    /**
     * Clear credentials
     */
    clearCredentials() {
        this.removeFromStorage('session_token');
        this.removeFromStorage('api_key');
    }
    
    /**
     * Store offline queue
     */
    storeOfflineQueue() {
        this.storeInStorage('offline_queue', JSON.stringify(this.offlineQueue));
    }
    
    /**
     * Load offline data
     */
    loadOfflineData() {
        // Load credentials
        this.loadCredentials();
        
        // Load offline queue
        const queue = this.getFromStorage('offline_queue');
        if (queue) {
            try {
                this.offlineQueue = JSON.parse(queue);
            } catch (error) {
                console.warn('Failed to parse offline queue:', error);
                this.offlineQueue = [];
            }
        }
        
        // Load last sync time
        const lastSync = this.getFromStorage('last_sync_time');
        if (lastSync) {
            this.lastSyncTime = lastSync;
        }
    }
    
    /**
     * Store last sync time
     */
    storeLastSyncTime() {
        if (this.lastSyncTime) {
            this.storeInStorage('last_sync_time', this.lastSyncTime);
        }
    }
    
    /**
     * Decompress data (placeholder for actual implementation)
     */
    async decompressData(compressedData) {
        // In a real implementation, this would use pako or similar library
        // For now, return as-is
        return atob(compressedData);
    }
    
    /**
     * Utility methods
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    
    generateId() {
        return Math.random().toString(36).substr(2, 9);
    }
    
    /**
     * Cleanup resources
     */
    destroy() {
        if (this.syncTimer) {
            clearInterval(this.syncTimer);
        }
        
        this.eventListeners = {};
        this.cache.clear();
    }
}

// Export for different module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = HomeNetMonSDK;
} else if (typeof define === 'function' && define.amd) {
    define([], () => HomeNetMonSDK);
} else if (typeof window !== 'undefined') {
    window.HomeNetMonSDK = HomeNetMonSDK;
}

// TypeScript type definitions
if (typeof module !== 'undefined') {
    module.exports.HomeNetMonSDK = HomeNetMonSDK;
}

/**
 * Usage Examples:
 * 
 * // Initialize SDK
 * const sdk = new HomeNetMonSDK({
 *     baseUrl: 'https://your-homenetmon-instance.com',
 *     apiKey: 'your-api-key',
 *     enableOffline: true,
 *     syncInterval: 30000
 * });
 * 
 * // Login with credentials
 * await sdk.login('username', 'password');
 * 
 * // Get devices
 * const devices = await sdk.getDevices({ status: 'up', includeMetrics: true });
 * 
 * // Listen for real-time updates
 * sdk.on('devicesUpdated', (devices) => {
 *     console.log('Devices updated:', devices);
 * });
 * 
 * // Handle offline scenarios
 * sdk.on('offline', () => {
 *     console.log('App is offline, queueing actions');
 * });
 * 
 * sdk.on('online', () => {
 *     console.log('App is back online, syncing data');
 * });
 */