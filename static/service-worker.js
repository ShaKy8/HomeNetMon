// HomeNetMon Enhanced Service Worker for Mobile & PWA
const CACHE_NAME = 'homenetmon-v2.0.0';
const STATIC_CACHE = 'homenetmon-static-v2.0.0';
const DYNAMIC_CACHE = 'homenetmon-dynamic-v2.0.0';
const OFFLINE_CACHE = 'homenetmon-offline-v2.0.0';
const DATA_CACHE = 'homenetmon-data-v2.0.0';

// Assets to cache on install
const STATIC_ASSETS = [
  '/',
  '/static/css/app.css',
  '/static/manifest.json',
  '/static/icons/icon-192x192.png',
  '/static/icons/icon-512x512.png',
  // Bootstrap CSS and JS
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js',
  // Bootstrap Icons
  'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css',
  // Chart.js
  'https://cdn.jsdelivr.net/npm/chart.js',
  // Socket.IO
  'https://cdn.socket.io/4.7.2/socket.io.min.js',
  // D3.js
  'https://cdn.jsdelivr.net/npm/d3@7'
];

// Critical API routes for offline functionality
const CRITICAL_API_ROUTES = [
  '/api/devices',
  '/api/monitoring/status',
  '/api/monitoring/background-activity',
  '/api/alerts',
  '/api/performance/summary',
  '/api/security/summary',
  '/api/health'
];

// Background sync tags
const SYNC_TAGS = {
  DEVICE_PING: 'device-ping',
  ALERT_ACK: 'alert-acknowledge',
  CONFIG_UPDATE: 'config-update',
  PERFORMANCE_DATA: 'performance-data',
  SECURITY_EVENT: 'security-event'
};

// IndexedDB for offline data storage
const DB_NAME = 'HomeNetMonDB';
const DB_VERSION = 1;
const STORES = {
  DEVICES: 'devices',
  MONITORING_DATA: 'monitoring_data',
  ALERTS: 'alerts',
  OFFLINE_QUEUE: 'offline_queue',
  USER_PREFERENCES: 'user_preferences'
};

// IndexedDB initialization
let db;

// Initialize IndexedDB
function initDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      db = request.result;
      resolve(db);
    };
    
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      
      // Create object stores
      if (!db.objectStoreNames.contains(STORES.DEVICES)) {
        const deviceStore = db.createObjectStore(STORES.DEVICES, { keyPath: 'id' });
        deviceStore.createIndex('ip_address', 'ip_address', { unique: false });
        deviceStore.createIndex('last_seen', 'last_seen', { unique: false });
      }
      
      if (!db.objectStoreNames.contains(STORES.MONITORING_DATA)) {
        const monitoringStore = db.createObjectStore(STORES.MONITORING_DATA, { keyPath: 'id', autoIncrement: true });
        monitoringStore.createIndex('device_id', 'device_id', { unique: false });
        monitoringStore.createIndex('timestamp', 'timestamp', { unique: false });
      }
      
      if (!db.objectStoreNames.contains(STORES.ALERTS)) {
        const alertStore = db.createObjectStore(STORES.ALERTS, { keyPath: 'id' });
        alertStore.createIndex('device_id', 'device_id', { unique: false });
        alertStore.createIndex('severity', 'severity', { unique: false });
        alertStore.createIndex('created_at', 'created_at', { unique: false });
      }
      
      if (!db.objectStoreNames.contains(STORES.OFFLINE_QUEUE)) {
        const queueStore = db.createObjectStore(STORES.OFFLINE_QUEUE, { keyPath: 'id', autoIncrement: true });
        queueStore.createIndex('sync_tag', 'sync_tag', { unique: false });
        queueStore.createIndex('created_at', 'created_at', { unique: false });
      }
      
      if (!db.objectStoreNames.contains(STORES.USER_PREFERENCES)) {
        db.createObjectStore(STORES.USER_PREFERENCES, { keyPath: 'key' });
      }
    };
  });
}

// Install event - cache static assets and initialize DB
self.addEventListener('install', (event) => {
  console.log('[ServiceWorker] Install event');
  
  event.waitUntil(
    Promise.all([
      // Cache static assets
      caches.open(STATIC_CACHE)
        .then((cache) => {
          console.log('[ServiceWorker] Caching static assets');
          return cache.addAll(STATIC_ASSETS.map(url => new Request(url, { cache: 'reload' })));
        }),
      // Initialize IndexedDB
      initDB()
        .then(() => console.log('[ServiceWorker] IndexedDB initialized'))
        .catch((error) => console.error('[ServiceWorker] IndexedDB initialization failed:', error)),
      // Pre-cache critical API data
      cacheCriticalAPIData()
    ])
    .catch((error) => {
      console.error('[ServiceWorker] Installation failed:', error);
    })
  );
  
  // Skip waiting to activate immediately
  self.skipWaiting();
});

// Pre-cache critical API data
async function cacheCriticalAPIData() {
  try {
    const cache = await caches.open(DATA_CACHE);
    
    for (const route of CRITICAL_API_ROUTES) {
      try {
        const response = await fetch(route);
        if (response.ok) {
          await cache.put(route, response.clone());
          
          // Also store in IndexedDB for offline access
          const data = await response.json();
          await storeOfflineData(route, data);
        }
      } catch (error) {
        console.warn(`[ServiceWorker] Failed to pre-cache ${route}:`, error);
      }
    }
  } catch (error) {
    console.error('[ServiceWorker] Failed to cache critical API data:', error);
  }
}

// Store data in IndexedDB
async function storeOfflineData(endpoint, data) {
  if (!db) await initDB();
  
  const transaction = db.transaction([STORES.MONITORING_DATA], 'readwrite');
  const store = transaction.objectStore(STORES.MONITORING_DATA);
  
  try {
    await store.put({
      endpoint: endpoint,
      data: data,
      timestamp: Date.now(),
      lastUpdated: new Date().toISOString()
    });
  } catch (error) {
    console.error('[ServiceWorker] Failed to store offline data:', error);
  }
}

// Activate event - clean up old caches and data
self.addEventListener('activate', (event) => {
  console.log('[ServiceWorker] Activate event');
  
  event.waitUntil(
    Promise.all([
      // Clean up old caches
      caches.keys().then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            if (!cacheName.includes('v2.0.0')) {
              console.log('[ServiceWorker] Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      }),
      // Clean up old offline data
      cleanupOldOfflineData(),
      // Initialize DB if not already done
      !db ? initDB() : Promise.resolve()
    ])
  );
  
  // Take control of all pages immediately
  self.clients.claim();
});

// Fetch event - implement caching strategies
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);
  
  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }
  
  // Handle API requests with network-first strategy
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirstStrategy(request));
    return;
  }
  
  // Handle Socket.IO requests
  if (url.pathname.startsWith('/socket.io/')) {
    event.respondWith(fetch(request));
    return;
  }
  
  // Handle static assets and pages with cache-first strategy
  event.respondWith(cacheFirstStrategy(request));
});

// Network-first strategy for API calls
async function networkFirstStrategy(request) {
  try {
    const networkResponse = await fetch(request);
    
    if (networkResponse.ok) {
      // Cache successful API responses for offline access
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, networkResponse.clone());
    }
    
    return networkResponse;
  } catch (error) {
    console.log('[ServiceWorker] Network request failed, trying cache:', request.url);
    
    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
      return cachedResponse;
    }
    
    // Return offline response for API calls
    return new Response(
      JSON.stringify({
        error: 'Network unavailable',
        offline: true,
        message: 'This data is not available offline'
      }),
      {
        status: 503,
        statusText: 'Service Unavailable',
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

// Cache-first strategy for static assets
async function cacheFirstStrategy(request) {
  const cachedResponse = await caches.match(request);
  
  if (cachedResponse) {
    return cachedResponse;
  }
  
  try {
    const networkResponse = await fetch(request);
    
    if (networkResponse.ok) {
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, networkResponse.clone());
    }
    
    return networkResponse;
  } catch (error) {
    console.log('[ServiceWorker] Failed to fetch from network:', request.url);
    
    // Return offline page for navigation requests
    if (request.mode === 'navigate') {
      const offlineResponse = await caches.match('/');
      if (offlineResponse) {
        return offlineResponse;
      }
    }
    
    throw error;
  }
}

// Clean up old offline data
async function cleanupOldOfflineData() {
  if (!db) return;
  
  try {
    const cutoffTime = Date.now() - (7 * 24 * 60 * 60 * 1000); // 7 days ago
    
    const transaction = db.transaction([STORES.MONITORING_DATA, STORES.OFFLINE_QUEUE], 'readwrite');
    
    // Clean monitoring data
    const monitoringStore = transaction.objectStore(STORES.MONITORING_DATA);
    const monitoringIndex = monitoringStore.index('timestamp');
    const monitoringRange = IDBKeyRange.upperBound(cutoffTime);
    await monitoringIndex.openCursor(monitoringRange)?.delete();
    
    // Clean offline queue (failed requests older than 24 hours)
    const queueStore = transaction.objectStore(STORES.OFFLINE_QUEUE);
    const queueIndex = queueStore.index('created_at');
    const queueCutoff = Date.now() - (24 * 60 * 60 * 1000);
    const queueRange = IDBKeyRange.upperBound(queueCutoff);
    await queueIndex.openCursor(queueRange)?.delete();
    
  } catch (error) {
    console.error('[ServiceWorker] Failed to cleanup old data:', error);
  }
}

// Enhanced background sync for failed requests and data synchronization
self.addEventListener('sync', (event) => {
  console.log('[ServiceWorker] Background sync event:', event.tag);
  
  switch (event.tag) {
    case SYNC_TAGS.DEVICE_PING:
      event.waitUntil(retryFailedPings());
      break;
      
    case SYNC_TAGS.ALERT_ACK:
      event.waitUntil(syncAlertAcknowledgments());
      break;
      
    case SYNC_TAGS.CONFIG_UPDATE:
      event.waitUntil(syncConfigurationUpdates());
      break;
      
    case SYNC_TAGS.PERFORMANCE_DATA:
      event.waitUntil(syncPerformanceData());
      break;
      
    case SYNC_TAGS.SECURITY_EVENT:
      event.waitUntil(syncSecurityEvents());
      break;
      
    default:
      console.log('[ServiceWorker] Unknown sync tag:', event.tag);
  }
});

// Enhanced push notification support with intelligent handling
self.addEventListener('push', (event) => {
  console.log('[ServiceWorker] Push notification received:', event);
  
  if (!event.data) {
    return;
  }
  
  const data = event.data.json();
  
  // Intelligent notification prioritization
  const priority = data.priority || determinePriority(data);
  const shouldShow = shouldShowNotification(data, priority);
  
  if (!shouldShow) {
    console.log('[ServiceWorker] Notification suppressed due to priority/settings');
    return;
  }
  
  const options = {
    body: data.body || 'HomeNetMon notification',
    icon: getNotificationIcon(data.type),
    badge: '/static/icons/icon-72x72.png',
    vibrate: getVibrationPattern(priority),
    data: {
      dateOfArrival: Date.now(),
      primaryKey: data.primaryKey || '1',
      url: data.url || '/',
      type: data.type || 'general',
      priority: priority
    },
    actions: getNotificationActions(data),
    requireInteraction: priority === 'critical' || data.requireInteraction,
    silent: data.silent || false,
    tag: data.tag || `homenetmon-${data.type || 'general'}`,
    renotify: priority === 'critical',
    timestamp: Date.now()
  };
  
  // Add custom styling based on notification type
  if (data.image) {
    options.image = data.image;
  }
  
  event.waitUntil(
    Promise.all([
      self.registration.showNotification(data.title || 'HomeNetMon', options),
      storeNotificationForOffline(data)
    ])
  );
});

// Determine notification priority
function determinePriority(data) {
  if (data.type === 'security' || data.severity === 'critical') return 'critical';
  if (data.type === 'alert' || data.severity === 'high') return 'high';
  if (data.type === 'performance' || data.severity === 'medium') return 'medium';
  return 'low';
}

// Check if notification should be shown based on user preferences and context
function shouldShowNotification(data, priority) {
  // Always show critical notifications
  if (priority === 'critical') return true;
  
  // Check user's quiet hours (would be stored in IndexedDB)
  const now = new Date();
  const hour = now.getHours();
  
  // Simple quiet hours check (can be customized)
  if (hour >= 22 || hour <= 7) {
    return priority === 'critical' || priority === 'high';
  }
  
  return true;
}

// Get appropriate icon for notification type
function getNotificationIcon(type) {
  const icons = {
    'security': '/static/icons/security-notification.png',
    'alert': '/static/icons/alert-notification.png',
    'performance': '/static/icons/performance-notification.png',
    'device': '/static/icons/device-notification.png',
    'system': '/static/icons/system-notification.png'
  };
  
  return icons[type] || '/static/icons/icon-192x192.png';
}

// Get vibration pattern based on priority
function getVibrationPattern(priority) {
  const patterns = {
    'critical': [200, 100, 200, 100, 200],
    'high': [100, 50, 100],
    'medium': [100],
    'low': []
  };
  
  return patterns[priority] || [100];
}

// Get appropriate actions for notification type
function getNotificationActions(data) {
  const commonActions = [
    {
      action: 'view',
      title: 'View',
      icon: '/static/icons/view-action.png'
    },
    {
      action: 'dismiss',
      title: 'Dismiss',
      icon: '/static/icons/dismiss-action.png'
    }
  ];
  
  // Add type-specific actions
  if (data.type === 'alert') {
    return [
      {
        action: 'acknowledge',
        title: 'Acknowledge',
        icon: '/static/icons/ack-action.png'
      },
      ...commonActions
    ];
  }
  
  if (data.type === 'device') {
    return [
      {
        action: 'ping',
        title: 'Ping Device',
        icon: '/static/icons/ping-action.png'
      },
      ...commonActions
    ];
  }
  
  return commonActions;
}

// Store notification for offline viewing
async function storeNotificationForOffline(data) {
  if (!db) await initDB();
  
  try {
    const transaction = db.transaction([STORES.USER_PREFERENCES], 'readwrite');
    const store = transaction.objectStore(STORES.USER_PREFERENCES);
    
    // Get existing notifications
    const existing = await store.get('recent_notifications');
    const notifications = existing?.value || [];
    
    // Add new notification
    notifications.unshift({
      ...data,
      receivedAt: Date.now(),
      read: false
    });
    
    // Keep only last 50 notifications
    if (notifications.length > 50) {
      notifications.splice(50);
    }
    
    await store.put({
      key: 'recent_notifications',
      value: notifications,
      lastUpdated: Date.now()
    });
    
  } catch (error) {
    console.error('[ServiceWorker] Failed to store notification:', error);
  }
}

// Handle notification clicks with enhanced action support
self.addEventListener('notificationclick', (event) => {
  console.log('[ServiceWorker] Notification clicked:', event);
  
  event.notification.close();
  
  const { action } = event;
  const notificationData = event.notification.data || {};
  
  // Handle specific actions
  if (action === 'dismiss') {
    return;
  }
  
  if (action === 'acknowledge') {
    event.waitUntil(acknowledgeAlert(notificationData));
    return;
  }
  
  if (action === 'ping') {
    event.waitUntil(pingDevice(notificationData));
    return;
  }
  
  // Default action - open the app
  const urlToOpen = notificationData.url || '/';
  
  event.waitUntil(
    self.clients.matchAll({ type: 'window' })
      .then((clients) => {
        // Check if there's already a window/tab open with the target URL
        const existingClient = clients.find(client => 
          client.url === urlToOpen && 'focus' in client
        );
        
        if (existingClient) {
          return existingClient.focus();
        }
        
        // Open new window/tab
        if (self.clients.openWindow) {
          return self.clients.openWindow(urlToOpen);
        }
      })
  );
});

// Handle alert acknowledgment from notification
async function acknowledgeAlert(notificationData) {
  try {
    const response = await fetch(`/api/alerts/${notificationData.primaryKey}/acknowledge`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        acknowledged_by: 'mobile_notification',
        timestamp: Date.now()
      })
    });
    
    if (!response.ok) {
      // Queue for later if offline
      await queueOfflineAction(SYNC_TAGS.ALERT_ACK, {
        alertId: notificationData.primaryKey,
        action: 'acknowledge',
        timestamp: Date.now()
      });
    }
  } catch (error) {
    console.error('[ServiceWorker] Failed to acknowledge alert:', error);
    // Queue for background sync
    await queueOfflineAction(SYNC_TAGS.ALERT_ACK, {
      alertId: notificationData.primaryKey,
      action: 'acknowledge',
      timestamp: Date.now()
    });
  }
}

// Handle device ping from notification
async function pingDevice(notificationData) {
  try {
    const response = await fetch(`/api/devices/${notificationData.primaryKey}/ping`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      // Queue for later if offline
      await queueOfflineAction(SYNC_TAGS.DEVICE_PING, {
        deviceId: notificationData.primaryKey,
        action: 'ping',
        timestamp: Date.now()
      });
    }
  } catch (error) {
    console.error('[ServiceWorker] Failed to ping device:', error);
    // Queue for background sync
    await queueOfflineAction(SYNC_TAGS.DEVICE_PING, {
      deviceId: notificationData.primaryKey,
      action: 'ping',
      timestamp: Date.now()
    });
  }
}

// Queue actions for offline processing
async function queueOfflineAction(syncTag, actionData) {
  if (!db) await initDB();
  
  try {
    const transaction = db.transaction([STORES.OFFLINE_QUEUE], 'readwrite');
    const store = transaction.objectStore(STORES.OFFLINE_QUEUE);
    
    await store.add({
      sync_tag: syncTag,
      data: actionData,
      created_at: Date.now(),
      retry_count: 0
    });
    
    // Register background sync
    if ('serviceWorker' in self && 'sync' in self.ServiceWorkerRegistration.prototype) {
      await self.registration.sync.register(syncTag);
    }
  } catch (error) {
    console.error('[ServiceWorker] Failed to queue offline action:', error);
  }
}

// Retry failed ping requests and process queued device ping actions
async function retryFailedPings() {
  console.log('[ServiceWorker] Retrying failed ping requests');
  
  try {
    // First, check if we're back online
    const response = await fetch('/api/monitoring/status');
    if (response.ok) {
      console.log('[ServiceWorker] Successfully reconnected to server');
      
      // Process queued device ping actions
      if (db) {
        const transaction = db.transaction([STORES.OFFLINE_QUEUE], 'readwrite');
        const store = transaction.objectStore(STORES.OFFLINE_QUEUE);
        const index = store.index('sync_tag');
        const request = index.getAll(SYNC_TAGS.DEVICE_PING);
        
        request.onsuccess = async () => {
          const queuedPings = request.result;
          
          for (const ping of queuedPings) {
            try {
              const pingResponse = await fetch(`/api/devices/${ping.data.deviceId}/ping`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json'
                }
              });
              
              if (pingResponse.ok) {
                await store.delete(ping.id);
                console.log(`[ServiceWorker] Successfully executed queued ping for device: ${ping.data.deviceId}`);
              } else if (ping.retry_count < 3) {
                ping.retry_count++;
                await store.put(ping);
              } else {
                await store.delete(ping.id);
                console.warn(`[ServiceWorker] Max retries reached for device ping: ${ping.data.deviceId}`);
              }
            } catch (error) {
              console.error('[ServiceWorker] Failed to execute queued ping:', error);
              if (ping.retry_count < 3) {
                ping.retry_count++;
                await store.put(ping);
              }
            }
          }
        };
      }
      
      // Notify all clients about reconnection
      const clients = await self.clients.matchAll();
      clients.forEach(client => {
        client.postMessage({
          type: 'SERVER_RECONNECTED',
          timestamp: Date.now()
        });
      });
      
      // Refresh cached API data
      await cacheCriticalAPIData();
    }
  } catch (error) {
    console.log('[ServiceWorker] Still offline, will retry later');
  }
}

// Utility function to get offline data from IndexedDB
async function getOfflineData(endpoint) {
  if (!db) await initDB();
  
  try {
    const transaction = db.transaction([STORES.MONITORING_DATA], 'readonly');
    const store = transaction.objectStore(STORES.MONITORING_DATA);
    const request = store.get(endpoint);
    
    return new Promise((resolve, reject) => {
      request.onsuccess = () => {
        if (request.result) {
          resolve(request.result.data);
        } else {
          resolve(null);
        }
      };
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    console.error('[ServiceWorker] Failed to get offline data:', error);
    return null;
  }
}

// Utility function to check online status
function isOnline() {
  return navigator.onLine;
}

// Enhanced error handling for failed requests
function handleFailedRequest(request, error) {
  console.log('[ServiceWorker] Request failed:', request.url, error);
  
  // Return appropriate offline response based on request type
  if (request.url.includes('/api/')) {
    return new Response(
      JSON.stringify({
        error: 'Network unavailable',
        offline: true,
        message: 'This request failed and will be retried when connection is restored',
        timestamp: Date.now()
      }),
      {
        status: 503,
        statusText: 'Service Unavailable',
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
  
  // For other requests, try to serve from cache
  return caches.match(request).then(response => {
    if (response) {
      return response;
    }
    
    // Return generic offline response
    return new Response('Offline - Content not available', {
      status: 503,
      statusText: 'Service Unavailable'
    });
  });
}

// Sync alert acknowledgments when back online
async function syncAlertAcknowledgments() {
  console.log('[ServiceWorker] Syncing alert acknowledgments');
  
  if (!db) return;
  
  try {
    const transaction = db.transaction([STORES.OFFLINE_QUEUE], 'readwrite');
    const store = transaction.objectStore(STORES.OFFLINE_QUEUE);
    const index = store.index('sync_tag');
    const request = index.getAll(SYNC_TAGS.ALERT_ACK);
    
    request.onsuccess = async () => {
      const queuedItems = request.result;
      
      for (const item of queuedItems) {
        try {
          const response = await fetch(`/api/alerts/${item.data.alertId}/acknowledge`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              acknowledged_by: 'mobile_notification_sync',
              timestamp: item.data.timestamp
            })
          });
          
          if (response.ok) {
            // Remove from queue on success
            await store.delete(item.id);
            console.log(`[ServiceWorker] Successfully synced alert acknowledgment: ${item.data.alertId}`);
          } else if (item.retry_count < 3) {
            // Increment retry count
            item.retry_count++;
            await store.put(item);
          } else {
            // Max retries reached, remove from queue
            await store.delete(item.id);
            console.warn(`[ServiceWorker] Max retries reached for alert acknowledgment: ${item.data.alertId}`);
          }
        } catch (error) {
          console.error('[ServiceWorker] Failed to sync alert acknowledgment:', error);
          if (item.retry_count < 3) {
            item.retry_count++;
            await store.put(item);
          }
        }
      }
    };
  } catch (error) {
    console.error('[ServiceWorker] Failed to sync alert acknowledgments:', error);
  }
}

// Sync configuration updates when back online
async function syncConfigurationUpdates() {
  console.log('[ServiceWorker] Syncing configuration updates');
  
  if (!db) return;
  
  try {
    const transaction = db.transaction([STORES.OFFLINE_QUEUE], 'readwrite');
    const store = transaction.objectStore(STORES.OFFLINE_QUEUE);
    const index = store.index('sync_tag');
    const request = index.getAll(SYNC_TAGS.CONFIG_UPDATE);
    
    request.onsuccess = async () => {
      const queuedItems = request.result;
      
      for (const item of queuedItems) {
        try {
          const response = await fetch('/api/config', {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(item.data.config)
          });
          
          if (response.ok) {
            await store.delete(item.id);
            console.log('[ServiceWorker] Successfully synced configuration update');
          } else if (item.retry_count < 3) {
            item.retry_count++;
            await store.put(item);
          } else {
            await store.delete(item.id);
            console.warn('[ServiceWorker] Max retries reached for configuration update');
          }
        } catch (error) {
          console.error('[ServiceWorker] Failed to sync configuration update:', error);
          if (item.retry_count < 3) {
            item.retry_count++;
            await store.put(item);
          }
        }
      }
    };
  } catch (error) {
    console.error('[ServiceWorker] Failed to sync configuration updates:', error);
  }
}

// Sync performance data when back online
async function syncPerformanceData() {
  console.log('[ServiceWorker] Syncing performance data');
  
  if (!db) return;
  
  try {
    const transaction = db.transaction([STORES.OFFLINE_QUEUE], 'readwrite');
    const store = transaction.objectStore(STORES.OFFLINE_QUEUE);
    const index = store.index('sync_tag');
    const request = index.getAll(SYNC_TAGS.PERFORMANCE_DATA);
    
    request.onsuccess = async () => {
      const queuedItems = request.result;
      
      for (const item of queuedItems) {
        try {
          const response = await fetch('/api/monitoring/performance', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(item.data.performanceData)
          });
          
          if (response.ok) {
            await store.delete(item.id);
            console.log('[ServiceWorker] Successfully synced performance data');
          } else if (item.retry_count < 3) {
            item.retry_count++;
            await store.put(item);
          } else {
            await store.delete(item.id);
            console.warn('[ServiceWorker] Max retries reached for performance data sync');
          }
        } catch (error) {
          console.error('[ServiceWorker] Failed to sync performance data:', error);
          if (item.retry_count < 3) {
            item.retry_count++;
            await store.put(item);
          }
        }
      }
    };
  } catch (error) {
    console.error('[ServiceWorker] Failed to sync performance data:', error);
  }
}

// Sync security events when back online
async function syncSecurityEvents() {
  console.log('[ServiceWorker] Syncing security events');
  
  if (!db) return;
  
  try {
    const transaction = db.transaction([STORES.OFFLINE_QUEUE], 'readwrite');
    const store = transaction.objectStore(STORES.OFFLINE_QUEUE);
    const index = store.index('sync_tag');
    const request = index.getAll(SYNC_TAGS.SECURITY_EVENT);
    
    request.onsuccess = async () => {
      const queuedItems = request.result;
      
      for (const item of queuedItems) {
        try {
          const response = await fetch('/api/security/events', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(item.data.securityEvent)
          });
          
          if (response.ok) {
            await store.delete(item.id);
            console.log('[ServiceWorker] Successfully synced security event');
          } else if (item.retry_count < 3) {
            item.retry_count++;
            await store.put(item);
          } else {
            await store.delete(item.id);
            console.warn('[ServiceWorker] Max retries reached for security event sync');
          }
        } catch (error) {
          console.error('[ServiceWorker] Failed to sync security event:', error);
          if (item.retry_count < 3) {
            item.retry_count++;
            await store.put(item);
          }
        }
      }
    };
  } catch (error) {
    console.error('[ServiceWorker] Failed to sync security events:', error);
  }
}

// Message handling from main thread
self.addEventListener('message', (event) => {
  console.log('[ServiceWorker] Message received:', event.data);
  
  if (event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data.type === 'CACHE_DEVICE_DATA') {
    // Cache important device data for offline access
    caches.open(DYNAMIC_CACHE).then(cache => {
      cache.put('/api/devices', new Response(JSON.stringify(event.data.devices)));
    });
  }
  
  if (event.data.type === 'QUEUE_CONFIG_UPDATE') {
    // Queue configuration update for sync
    queueOfflineAction(SYNC_TAGS.CONFIG_UPDATE, {
      config: event.data.config,
      timestamp: Date.now()
    });
  }
  
  if (event.data.type === 'QUEUE_PERFORMANCE_DATA') {
    // Queue performance data for sync
    queueOfflineAction(SYNC_TAGS.PERFORMANCE_DATA, {
      performanceData: event.data.data,
      timestamp: Date.now()
    });
  }
  
  if (event.data.type === 'QUEUE_SECURITY_EVENT') {
    // Queue security event for sync
    queueOfflineAction(SYNC_TAGS.SECURITY_EVENT, {
      securityEvent: event.data.event,
      timestamp: Date.now()
    });
  }
});