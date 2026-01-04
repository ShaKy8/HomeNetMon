// HomeNetMon PWA Manager - Enhanced mobile and offline capabilities
class PWAManager {
    constructor() {
        this.isOnline = navigator.onLine;
        this.serviceWorker = null;
        this.db = null;
        this.syncInProgress = false;
        
        // Connection stability tracking
        this.connectionState = {
            lastOnlineTime: Date.now(),
            lastOfflineTime: null,
            consecutiveOfflineEvents: 0,
            isStable: true,
            transitionTimeout: null
        };
        
        // Configuration
        this.config = {
            dbName: 'HomeNetMonDB',
            dbVersion: 1,
            maxOfflineNotifications: 100,
            syncRetryDelay: 30000, // 30 seconds
            offlineDataRetentionDays: 7,
            // Stability thresholds
            minOfflineDuration: 3000, // Must be offline for 3 seconds before showing notification
            transitionGracePeriod: 1000, // Grace period for rapid online/offline events
            maxConsecutiveOfflineEvents: 3 // Threshold for considering connection unstable
        };
        
        // Initialize PWA functionality
        this.init();
    }
    
    async init() {
        
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
            
        } catch (error) {
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
                
                // Handle service worker updates
                registration.addEventListener('updatefound', () => {
                    this.handleServiceWorkerUpdate(registration.installing);
                });
                
                // Check for waiting service worker
                if (registration.waiting) {
                    this.showUpdateAvailable();
                }
                
                return registration;
            } catch (error) {
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
        // Enhanced online/offline status with stability checking
        window.addEventListener('online', () => {
            this.handleConnectionEvent('online');
        });
        
        window.addEventListener('offline', () => {
            this.handleConnectionEvent('offline');
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
            this.trackEvent('pwa_installed');
        });
        
        // Page visibility changes (to avoid false offline detection during page transitions)
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
                // Page became visible, verify connection
                setTimeout(() => this.verifyConnection(), 500);
            }
        });
        
        // Window focus events
        window.addEventListener('focus', () => {
            // Window gained focus, verify connection
            setTimeout(() => this.verifyConnection(), 200);
        });
        
        // Page navigation events - suppress offline detection during navigation
        window.addEventListener('beforeunload', () => {
            this.isNavigating = true;
        });
        
        // Page load complete
        window.addEventListener('load', () => {
            // Reset navigation flag after page loads
            setTimeout(() => {
                this.isNavigating = false;
                // Verify connection after page navigation
                this.verifyConnection();
            }, 1000);
        });
    }
    
    // Enhanced connection event handling with stability checking
    handleConnectionEvent(eventType) {
        // Skip connection events during page navigation
        if (this.isNavigating) {
            return;
        }
        
        const now = Date.now();
        
        // Clear any pending transition timeout
        if (this.connectionState.transitionTimeout) {
            clearTimeout(this.connectionState.transitionTimeout);
            this.connectionState.transitionTimeout = null;
        }
        
        if (eventType === 'online') {
            this.connectionState.lastOnlineTime = now;
            this.connectionState.consecutiveOfflineEvents = 0;
            
            // If we were previously offline, verify the connection before showing online status
            if (!this.isOnline) {
                this.verifyConnection(true);
            } else {
                // Already online, just update without notification
                this.isOnline = true;
                this.updateConnectionIndicator(true);
            }
            
        } else if (eventType === 'offline') {
            this.connectionState.lastOfflineTime = now;
            this.connectionState.consecutiveOfflineEvents++;
            
            // Check if this might be a transient offline event during page navigation
            const timeSinceLastOnline = now - this.connectionState.lastOnlineTime;
            
            if (timeSinceLastOnline < this.config.transitionGracePeriod) {
                return;
            }
            
            // Set a timeout to only show offline status if we stay offline
            this.connectionState.transitionTimeout = setTimeout(() => {
                if (!navigator.onLine) {
                    this.isOnline = false;
                    this.handleOnlineStatusChange(false);
                }
            }, this.config.minOfflineDuration);
        }
    }
    
    // Verify connection by making an actual network request
    async verifyConnection(fromOnlineEvent = false) {
        try {
            // Make a lightweight request to check actual connectivity
            const response = await fetch('/health', { 
                method: 'HEAD',
                cache: 'no-cache',
                timeout: 5000
            });
            
            const isActuallyOnline = response.ok;
            
            if (isActuallyOnline !== this.isOnline) {
                this.isOnline = isActuallyOnline;
                
                // Only show notifications for verified status changes
                if (fromOnlineEvent && isActuallyOnline) {
                    this.handleOnlineStatusChange(true);
                } else {
                    this.updateConnectionIndicator(isActuallyOnline);
                }
            }
            
        } catch (error) {
            // Network request failed, likely actually offline
            if (this.isOnline) {
                this.isOnline = false;
                this.handleOnlineStatusChange(false);
            }
        }
    }
    
    // Update connection indicator without notifications
    updateConnectionIndicator(isOnline) {
        const statusIndicator = document.getElementById('connection-status');
        if (statusIndicator) {
            statusIndicator.className = isOnline ? 'online' : 'offline';
            statusIndicator.textContent = isOnline ? 'Online' : 'Offline';
        }
        
        // Update UI state
        document.body.classList.toggle('offline', !isOnline);
    }
    
    // Handle online/offline status changes (with notifications)
    handleOnlineStatusChange(isOnline) {
        // Update UI indicators
        this.updateConnectionIndicator(isOnline);
        
        // Only show notifications for significant offline periods or confirmed online restoration
        const now = Date.now();
        const shouldShowNotification = isOnline ? 
            (this.connectionState.lastOfflineTime && (now - this.connectionState.lastOfflineTime) > this.config.minOfflineDuration) :
            (this.connectionState.consecutiveOfflineEvents >= this.config.maxConsecutiveOfflineEvents);
        
        if (shouldShowNotification) {
            // Show notification for genuine status changes only
            this.showNotification(
                isOnline ? 'Connection Restored' : 'Working Offline',
                isOnline ? 'Successfully reconnected to HomeNetMon' : 'Using cached data while offline',
                isOnline ? 'success' : 'warning'
            );
        }
        
        // Sync data when back online
        if (isOnline && !this.syncInProgress) {
            this.syncOfflineData();
        }
        
        // Reset consecutive offline events when back online
        if (isOnline) {
            this.connectionState.consecutiveOfflineEvents = 0;
            this.connectionState.lastOfflineTime = null;
        }
    }
    
    // Service Worker Message Handler
    handleServiceWorkerMessage(data) {
        
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
                
                // Subscribe to push notifications
                const subscription = await this.subscribeToNotifications();
                if (subscription) {
                    await this.sendSubscriptionToServer(subscription);
                }
            } else {
            }
        } catch (error) {
        }
    }
    
    async subscribeToNotifications() {
        if (!this.serviceWorker) return null;
        
        try {
            const subscription = await this.serviceWorker.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: await this.getVapidKey()
            });
            
            return subscription;
        } catch (error) {
            return null;
        }
    }
    
    async getVapidKey() {
        try {
            const response = await fetch('/api/push/vapid-key');
            const data = await response.json();
            return this.urlBase64ToUint8Array(data.publicKey);
        } catch (error) {
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
            }
        } catch (error) {
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
            
            return true;
        } catch (error) {
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
            return null;
        }
    }
    
    // Sync offline data when back online
    async syncOfflineData() {
        if (this.syncInProgress || !this.isOnline) return;
        
        this.syncInProgress = true;
        
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
            
        } catch (error) {
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
            }
            
            // Remove from queue on success
            await this.removeFromQueue(action.id);
        } catch (error) {
            
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
            }
        }
    }
    
    // UI Notifications with spam prevention
    showNotification(title, message, type = 'info', duration = 4000) {
        // Prevent notification spam by checking if same notification was recently shown
        const notificationKey = `${title}:${type}`;
        const now = Date.now();
        
        if (!this.lastNotifications) {
            this.lastNotifications = new Map();
        }
        
        const lastShown = this.lastNotifications.get(notificationKey);
        if (lastShown && (now - lastShown) < 10000) { // 10 second cooldown
            return;
        }
        
        this.lastNotifications.set(notificationKey, now);
        
        // Create or update notification element
        let notification = document.getElementById('pwa-notification');
        
        if (!notification) {
            notification = document.createElement('div');
            notification.id = 'pwa-notification';
            notification.className = 'pwa-notification';
            document.body.appendChild(notification);
            
            // Add CSS styles if not already present
            if (!document.getElementById('pwa-notification-styles')) {
                const style = document.createElement('style');
                style.id = 'pwa-notification-styles';
                style.textContent = `
                    .pwa-notification {
                        position: fixed;
                        top: 20px;
                        right: 20px;
                        z-index: 10000;
                        background: var(--bs-dark);
                        color: white;
                        padding: 12px 16px;
                        border-radius: 8px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                        transform: translateX(100%);
                        opacity: 0;
                        transition: all 0.3s ease;
                        max-width: 320px;
                    }
                    .pwa-notification.show {
                        transform: translateX(0);
                        opacity: 1;
                    }
                    .pwa-notification.success { background: var(--bs-success); }
                    .pwa-notification.warning { background: var(--bs-warning); color: var(--bs-dark); }
                    .pwa-notification.info { background: var(--bs-info); }
                    .pwa-notification .notification-content { display: flex; flex-direction: column; gap: 4px; }
                    .pwa-notification .notification-close {
                        position: absolute;
                        top: 8px;
                        right: 8px;
                        background: none;
                        border: none;
                        color: inherit;
                        font-size: 18px;
                        cursor: pointer;
                        opacity: 0.7;
                    }
                    .pwa-notification .notification-close:hover { opacity: 1; }
                `;
                document.head.appendChild(style);
            }
        }
        
        notification.className = `pwa-notification ${type} show`;
        // Build notification content safely
        const content = document.createElement('div');
        content.className = 'notification-content';
        
        const titleElement = document.createElement('strong');
        if (window.htmlSanitizer) {
            window.htmlSanitizer.setText(titleElement, title);
        } else {
            titleElement.textContent = title;
        }
        
        const messageElement = document.createElement('span');
        if (window.htmlSanitizer) {
            window.htmlSanitizer.setText(messageElement, message);
        } else {
            messageElement.textContent = message;
        }
        
        const closeBtn = document.createElement('button');
        closeBtn.className = 'notification-close';
        closeBtn.textContent = '×';
        closeBtn.onclick = () => notification.classList.remove('show');
        
        content.appendChild(titleElement);
        content.appendChild(messageElement);
        notification.appendChild(content);
        notification.appendChild(closeBtn);
        
        // Auto-hide after specified duration
        setTimeout(() => {
            notification.classList.remove('show');
        }, duration);
    }
    
    showInstallPrompt(event) {
        // Show custom install prompt
        const installPrompt = document.createElement('div');
        installPrompt.className = 'install-prompt';
        // Build install prompt content safely
        const promptContent = document.createElement('div');
        promptContent.className = 'install-prompt-content';
        
        const title = document.createElement('h3');
        title.textContent = 'Install HomeNetMon';
        
        const description = document.createElement('p');
        description.textContent = 'Install HomeNetMon for quick access and offline functionality';
        
        const actions = document.createElement('div');
        actions.className = 'install-prompt-actions';
        
        const installBtn = document.createElement('button');
        installBtn.id = 'install-app';
        installBtn.className = 'btn btn-primary';
        installBtn.textContent = 'Install';
        
        const dismissBtn = document.createElement('button');
        dismissBtn.id = 'dismiss-install';
        dismissBtn.className = 'btn btn-secondary';
        dismissBtn.textContent = 'Not now';
        
        actions.appendChild(installBtn);
        actions.appendChild(dismissBtn);
        
        promptContent.appendChild(title);
        promptContent.appendChild(description);
        promptContent.appendChild(actions);
        
        installPrompt.appendChild(promptContent);
        
        document.body.appendChild(installPrompt);
        
        document.getElementById('install-app').onclick = () => {
            event.prompt();
            event.userChoice.then((choiceResult) => {
                if (choiceResult.outcome === 'accepted') {
                    this.trackEvent('pwa_install_accepted');
                } else {
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
    }
    
    handleSyncComplete(syncTag) {
    }
    
    // Check for app updates
    async checkForUpdates() {
        if (this.serviceWorker) {
            try {
                const registration = await this.serviceWorker.update();
            } catch (error) {
            }
        }
    }
    
    // Analytics/tracking
    trackEvent(eventName, properties = {}) {
        
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