// HomeNetMon PWA Manager - Enhanced mobile and offline capabilities
class PWAManager {
    constructor() {
        this.isOnline = navigator.onLine;
        this.serviceWorker = null;
        this.db = null;
        this.syncInProgress = false;
        
        // Configuration
        this.config = {
            dbName: 'HomeNetMonDB',
            dbVersion: 1,
            maxOfflineNotifications: 100,
            syncRetryDelay: 30000, // 30 seconds
            offlineDataRetentionDays: 7
        };
        
        // Initialize PWA functionality
        this.init();
    }
    
    async init() {
        console.log('[PWAManager] Initializing PWA functionality');
        
        try {
            // Register service worker
            await this.registerServiceWorker();
            
            // Initialize IndexedDB
            await this.initIndexedDB();
            
            // Set up event listeners
            this.setupEventListeners();
            
            // Check for app updates
            this.checkForUpdates();
            
            // Initialize push notifications if supported
            if ('Notification' in window && 'serviceWorker' in navigator) {
                await this.initPushNotifications();
            }
            
            console.log('[PWAManager] PWA initialization complete');
        } catch (error) {
            console.error('[PWAManager] Failed to initialize PWA:', error);
        }
    }
    
    // Service Worker Registration
    async registerServiceWorker() {
        if ('serviceWorker' in navigator) {
            try {
                const registration = await navigator.serviceWorker.register('/static/service-worker.js', {
                    scope: '/'
                });
                
                this.serviceWorker = registration;
                console.log('[PWAManager] Service Worker registered successfully');
                
                // Handle service worker updates
                registration.addEventListener('updatefound', () => {
                    console.log('[PWAManager] New service worker version available');
                    this.handleServiceWorkerUpdate(registration.installing);
                });
                
                // Check for waiting service worker
                if (registration.waiting) {
                    this.showUpdateAvailable();
                }
                
                return registration;
            } catch (error) {
                console.error('[PWAManager] Service Worker registration failed:', error);
                throw error;
            }
        } else {
            throw new Error('Service Workers not supported');
        }
    }
    
    // IndexedDB Initialization
    async initIndexedDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.config.dbName, this.config.dbVersion);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                this.db = request.result;
                console.log('[PWAManager] IndexedDB initialized');
                resolve(this.db);
            };
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                this.setupIndexedDBStores(db);
            };
        });
    }
    
    setupIndexedDBStores(db) {
        // Create object stores if they don't exist
        const stores = ['devices', 'monitoring_data', 'alerts', 'offline_queue', 'user_preferences'];
        
        stores.forEach(storeName => {
            if (!db.objectStoreNames.contains(storeName)) {
                let store;
                
                switch (storeName) {
                    case 'devices':
                        store = db.createObjectStore(storeName, { keyPath: 'id' });
                        store.createIndex('ip_address', 'ip_address', { unique: false });
                        store.createIndex('last_seen', 'last_seen', { unique: false });
                        break;
                        
                    case 'monitoring_data':
                        store = db.createObjectStore(storeName, { keyPath: 'id', autoIncrement: true });
                        store.createIndex('device_id', 'device_id', { unique: false });
                        store.createIndex('timestamp', 'timestamp', { unique: false });
                        break;
                        
                    case 'alerts':
                        store = db.createObjectStore(storeName, { keyPath: 'id' });
                        store.createIndex('device_id', 'device_id', { unique: false });
                        store.createIndex('severity', 'severity', { unique: false });
                        store.createIndex('created_at', 'created_at', { unique: false });
                        break;
                        
                    case 'offline_queue':
                        store = db.createObjectStore(storeName, { keyPath: 'id', autoIncrement: true });
                        store.createIndex('sync_tag', 'sync_tag', { unique: false });
                        store.createIndex('created_at', 'created_at', { unique: false });
                        break;
                        
                    case 'user_preferences':
                        store = db.createObjectStore(storeName, { keyPath: 'key' });
                        break;
                }
            }
        });
    }
    
    // Event Listeners Setup
    setupEventListeners() {
        // Online/offline status
        window.addEventListener('online', () => {
            console.log('[PWAManager] Back online');
            this.isOnline = true;
            this.handleOnlineStatusChange(true);
        });
        
        window.addEventListener('offline', () => {
            console.log('[PWAManager] Gone offline');
            this.isOnline = false;
            this.handleOnlineStatusChange(false);
        });
        
        // Service worker messages
        navigator.serviceWorker.addEventListener('message', (event) => {
            this.handleServiceWorkerMessage(event.data);
        });
        
        // Before install prompt (for PWA installation)
        window.addEventListener('beforeinstallprompt', (event) => {
            event.preventDefault();
            this.showInstallPrompt(event);
        });
        
        // App installed
        window.addEventListener('appinstalled', () => {
            console.log('[PWAManager] PWA installed successfully');
            this.trackEvent('pwa_installed');
        });
    }
    
    // Handle online/offline status changes
    handleOnlineStatusChange(isOnline) {
        const statusIndicator = document.getElementById('connection-status');
        if (statusIndicator) {
            statusIndicator.className = isOnline ? 'online' : 'offline';
            statusIndicator.textContent = isOnline ? 'Online' : 'Offline';
        }
        
        // Show notification
        this.showNotification(
            isOnline ? 'Back Online' : 'Offline Mode',
            isOnline ? 'Connection restored' : 'Working offline with cached data',
            isOnline ? 'success' : 'warning'
        );
        
        // Sync data when back online
        if (isOnline && !this.syncInProgress) {
            this.syncOfflineData();
        }
        
        // Update UI state
        document.body.classList.toggle('offline', !isOnline);
    }
    
    // Service Worker Message Handler
    handleServiceWorkerMessage(data) {
        console.log('[PWAManager] Message from Service Worker:', data);
        
        switch (data.type) {
            case 'SERVER_RECONNECTED':
                this.handleServerReconnection();
                break;
                
            case 'UPDATE_AVAILABLE':
                this.showUpdateAvailable();
                break;
                
            case 'CACHE_UPDATED':
                this.handleCacheUpdate(data.url);
                break;
                
            case 'SYNC_COMPLETE':
                this.handleSyncComplete(data.syncTag);
                break;
        }
    }
    
    // Push Notifications Setup
    async initPushNotifications() {
        try {
            // Request permission
            const permission = await Notification.requestPermission();
            
            if (permission === 'granted') {
                console.log('[PWAManager] Push notifications enabled');
                
                // Subscribe to push notifications
                const subscription = await this.subscribeToNotifications();
                if (subscription) {
                    await this.sendSubscriptionToServer(subscription);
                }
            } else {
                console.log('[PWAManager] Push notifications denied');
            }
        } catch (error) {
            console.error('[PWAManager] Failed to initialize push notifications:', error);
        }
    }
    
    async subscribeToNotifications() {
        if (!this.serviceWorker) return null;
        
        try {
            const subscription = await this.serviceWorker.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: await this.getVapidKey()
            });
            
            console.log('[PWAManager] Push subscription created');
            return subscription;
        } catch (error) {
            console.error('[PWAManager] Failed to create push subscription:', error);
            return null;
        }
    }
    
    async getVapidKey() {
        try {
            const response = await fetch('/api/push/vapid-key');
            const data = await response.json();
            return this.urlBase64ToUint8Array(data.publicKey);
        } catch (error) {
            console.error('[PWAManager] Failed to get VAPID key:', error);
            // Return a default key or handle gracefully
            return null;
        }
    }
    
    urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - base64String.length % 4) % 4);
        const base64 = (base64String + padding)
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        
        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);
        
        for (let i = 0; i < rawData.length; ++i) {
            outputArray[i] = rawData.charCodeAt(i);
        }
        
        return outputArray;
    }
    
    async sendSubscriptionToServer(subscription) {
        try {
            const response = await fetch('/api/push/subscribe', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(subscription)
            });
            
            if (response.ok) {
                console.log('[PWAManager] Push subscription registered with server');
            }
        } catch (error) {
            console.error('[PWAManager] Failed to register push subscription:', error);
        }
    }
    
    // Offline Data Management
    async storeOfflineData(storeName, data) {
        if (!this.db) return false;
        
        try {
            const transaction = this.db.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            
            if (Array.isArray(data)) {
                for (const item of data) {
                    await store.put(item);
                }
            } else {
                await store.put(data);
            }
            
            console.log(`[PWAManager] Data stored offline in ${storeName}`);
            return true;
        } catch (error) {
            console.error(`[PWAManager] Failed to store offline data in ${storeName}:`, error);
            return false;
        }
    }
    
    async getOfflineData(storeName, key = null) {
        if (!this.db) return null;
        
        try {
            const transaction = this.db.transaction([storeName], 'readonly');
            const store = transaction.objectStore(storeName);
            
            let request;
            if (key) {
                request = store.get(key);
            } else {
                request = store.getAll();
            }
            
            return new Promise((resolve, reject) => {
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(request.error);
            });
        } catch (error) {
            console.error(`[PWAManager] Failed to get offline data from ${storeName}:`, error);
            return null;
        }
    }
    
    // Sync offline data when back online
    async syncOfflineData() {
        if (this.syncInProgress || !this.isOnline) return;
        
        this.syncInProgress = true;
        console.log('[PWAManager] Starting offline data sync');
        
        try {
            // Get queued actions from offline queue
            const queuedActions = await this.getOfflineData('offline_queue');
            
            if (queuedActions && queuedActions.length > 0) {
                for (const action of queuedActions) {
                    await this.processQueuedAction(action);
                }
            }
            
            // Refresh cached data
            await this.refreshCachedData();
            
            console.log('[PWAManager] Offline data sync complete');
        } catch (error) {
            console.error('[PWAManager] Failed to sync offline data:', error);
        } finally {
            this.syncInProgress = false;
        }
    }
    
    async processQueuedAction(action) {
        try {
            // Process based on sync tag
            switch (action.sync_tag) {
                case 'device-ping':
                    await this.processPingAction(action);
                    break;
                case 'alert-acknowledge':
                    await this.processAlertAction(action);
                    break;
                case 'config-update':
                    await this.processConfigAction(action);
                    break;
                default:
                    console.warn(`[PWAManager] Unknown sync tag: ${action.sync_tag}`);
            }
            
            // Remove from queue on success
            await this.removeFromQueue(action.id);
        } catch (error) {
            console.error(`[PWAManager] Failed to process queued action:`, error);
            
            // Increment retry count
            action.retry_count = (action.retry_count || 0) + 1;
            
            if (action.retry_count >= 3) {
                // Max retries reached, remove from queue
                await this.removeFromQueue(action.id);
            } else {
                // Update retry count
                await this.storeOfflineData('offline_queue', action);
            }
        }
    }
    
    async processPingAction(action) {
        const response = await fetch(`/api/devices/${action.data.deviceId}/ping`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (!response.ok) {
            throw new Error(`Ping failed: ${response.status}`);
        }
    }
    
    async processAlertAction(action) {
        const response = await fetch(`/api/alerts/${action.data.alertId}/acknowledge`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                acknowledged_by: 'mobile_offline_sync',
                timestamp: action.data.timestamp
            })
        });
        
        if (!response.ok) {
            throw new Error(`Alert acknowledgment failed: ${response.status}`);
        }
    }
    
    async processConfigAction(action) {
        const response = await fetch('/api/config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(action.data.config)
        });
        
        if (!response.ok) {
            throw new Error(`Config update failed: ${response.status}`);
        }
    }
    
    async removeFromQueue(actionId) {
        if (!this.db) return;
        
        try {
            const transaction = this.db.transaction(['offline_queue'], 'readwrite');
            const store = transaction.objectStore('offline_queue');
            await store.delete(actionId);
        } catch (error) {
            console.error('[PWAManager] Failed to remove action from queue:', error);
        }
    }
    
    // Refresh cached data
    async refreshCachedData() {
        const endpoints = [
            '/api/devices',
            '/api/monitoring/status',
            '/api/alerts',
            '/api/performance/summary'
        ];
        
        for (const endpoint of endpoints) {
            try {
                const response = await fetch(endpoint);
                if (response.ok) {
                    const data = await response.json();
                    
                    // Store in appropriate IndexedDB store
                    if (endpoint.includes('devices')) {
                        await this.storeOfflineData('devices', data);
                    } else if (endpoint.includes('alerts')) {
                        await this.storeOfflineData('alerts', data);
                    } else if (endpoint.includes('monitoring') || endpoint.includes('performance')) {
                        await this.storeOfflineData('monitoring_data', {
                            endpoint: endpoint,
                            data: data,
                            timestamp: Date.now()
                        });
                    }
                    
                    // Also send to service worker for caching
                    if (navigator.serviceWorker.controller) {
                        navigator.serviceWorker.controller.postMessage({
                            type: 'CACHE_API_DATA',
                            endpoint: endpoint,
                            data: data
                        });
                    }
                }
            } catch (error) {
                console.error(`[PWAManager] Failed to refresh data for ${endpoint}:`, error);
            }
        }
    }
    
    // UI Notifications
    showNotification(title, message, type = 'info') {
        // Create or update notification element
        let notification = document.getElementById('pwa-notification');
        
        if (!notification) {
            notification = document.createElement('div');
            notification.id = 'pwa-notification';
            notification.className = 'pwa-notification';
            document.body.appendChild(notification);
        }
        
        notification.className = `pwa-notification ${type} show`;
        notification.innerHTML = `
            <div class="notification-content">
                <strong>${title}</strong>
                <span>${message}</span>
            </div>
            <button class="notification-close" onclick="this.parentElement.classList.remove('show')">&times;</button>
        `;
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            notification.classList.remove('show');
        }, 5000);
    }
    
    showInstallPrompt(event) {
        // Show custom install prompt
        const installPrompt = document.createElement('div');
        installPrompt.className = 'install-prompt';
        installPrompt.innerHTML = `
            <div class="install-prompt-content">
                <h3>Install HomeNetMon</h3>
                <p>Install HomeNetMon for quick access and offline functionality</p>
                <div class="install-prompt-actions">
                    <button id="install-app" class="btn btn-primary">Install</button>
                    <button id="dismiss-install" class="btn btn-secondary">Not now</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(installPrompt);
        
        document.getElementById('install-app').onclick = () => {
            event.prompt();
            event.userChoice.then((choiceResult) => {
                if (choiceResult.outcome === 'accepted') {
                    console.log('[PWAManager] User accepted install prompt');
                    this.trackEvent('pwa_install_accepted');
                } else {
                    console.log('[PWAManager] User dismissed install prompt');
                    this.trackEvent('pwa_install_dismissed');
                }
                document.body.removeChild(installPrompt);
            });
        };
        
        document.getElementById('dismiss-install').onclick = () => {
            document.body.removeChild(installPrompt);
            this.trackEvent('pwa_install_dismissed');
        };
    }
    
    showUpdateAvailable() {
        this.showNotification(
            'Update Available',
            'A new version of HomeNetMon is available. Refresh to update.',
            'info'
        );
        
        // Add refresh button
        const notification = document.getElementById('pwa-notification');
        if (notification) {
            const refreshBtn = document.createElement('button');
            refreshBtn.textContent = 'Refresh';
            refreshBtn.className = 'btn btn-sm btn-primary ms-2';
            refreshBtn.onclick = () => window.location.reload();
            notification.querySelector('.notification-content').appendChild(refreshBtn);
        }
    }
    
    handleServiceWorkerUpdate(installingWorker) {
        installingWorker.addEventListener('statechange', () => {
            if (installingWorker.state === 'installed' && navigator.serviceWorker.controller) {
                this.showUpdateAvailable();
            }
        });
    }
    
    handleServerReconnection() {
        this.showNotification(
            'Server Connected',
            'Successfully reconnected to HomeNetMon server',
            'success'
        );
        
        // Refresh page data
        if (window.updateDashboard) {
            window.updateDashboard();
        }
    }
    
    handleCacheUpdate(url) {
        console.log(`[PWAManager] Cache updated for: ${url}`);
    }
    
    handleSyncComplete(syncTag) {
        console.log(`[PWAManager] Background sync complete: ${syncTag}`);
    }
    
    // Check for app updates
    async checkForUpdates() {
        if (this.serviceWorker) {
            try {
                const registration = await this.serviceWorker.update();
                console.log('[PWAManager] Checked for updates');
            } catch (error) {
                console.error('[PWAManager] Failed to check for updates:', error);
            }
        }
    }
    
    // Analytics/tracking
    trackEvent(eventName, properties = {}) {
        console.log(`[PWAManager] Event tracked: ${eventName}`, properties);
        
        // Send to analytics if available
        if (window.gtag) {
            window.gtag('event', eventName, properties);
        }
    }
    
    // Public API methods
    async queueOfflineAction(syncTag, data) {
        if (!this.db) return false;
        
        try {
            const action = {
                sync_tag: syncTag,
                data: data,
                created_at: Date.now(),
                retry_count: 0
            };
            
            await this.storeOfflineData('offline_queue', action);
            
            // Register background sync if available
            if (this.serviceWorker && 'sync' in window.ServiceWorkerRegistration.prototype) {
                await this.serviceWorker.sync.register(syncTag);
            }
            
            return true;
        } catch (error) {
            console.error('[PWAManager] Failed to queue offline action:', error);
            return false;
        }
    }
    
    // Get app info
    getAppInfo() {
        return {
            isOnline: this.isOnline,
            isInstalled: window.matchMedia('(display-mode: standalone)').matches,
            serviceWorkerReady: !!this.serviceWorker,
            dbReady: !!this.db,
            notificationsEnabled: Notification.permission === 'granted'
        };
    }
}

// Initialize PWA Manager when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.pwaManager = new PWAManager();
    });
} else {
    window.pwaManager = new PWAManager();
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PWAManager;
}