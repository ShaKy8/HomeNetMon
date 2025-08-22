/**
 * Read Receipt Tracker
 * 
 * Client-side JavaScript library for tracking notification read receipts
 * and user engagement with privacy-compliant analytics.
 */

class ReadReceiptTracker {
    constructor(options = {}) {
        this.baseUrl = options.baseUrl || '';
        this.apiEndpoint = options.apiEndpoint || '/api/notifications/receipt';
        this.trackingEnabled = options.trackingEnabled !== false;
        this.debugMode = options.debugMode || false;
        this.retryAttempts = options.retryAttempts || 3;
        this.retryDelay = options.retryDelay || 1000;
        
        // Privacy settings
        this.respectDoNotTrack = options.respectDoNotTrack !== false;
        this.requireConsent = options.requireConsent || false;
        this.consentKey = options.consentKey || 'readReceiptConsent';
        
        // Check if tracking should be disabled
        if (this.respectDoNotTrack && navigator.doNotTrack === '1') {
            this.trackingEnabled = false;
            this.log('Tracking disabled due to Do Not Track setting');
        }
        
        if (this.requireConsent && !this.hasConsent()) {
            this.trackingEnabled = false;
            this.log('Tracking disabled - consent required but not given');
        }
        
        this.log('ReadReceiptTracker initialized', { trackingEnabled: this.trackingEnabled });
    }
    
    /**
     * Generate a tracking token for a notification
     */
    async generateTrackingToken(notificationId, metadata = {}) {
        if (!this.trackingEnabled) {
            return null;
        }
        
        try {
            const response = await this.makeRequest(`${this.apiEndpoint}/generate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    notification_id: notificationId,
                    metadata: {
                        ...metadata,
                        user_agent: navigator.userAgent,
                        screen_resolution: `${screen.width}x${screen.height}`,
                        timestamp: new Date().toISOString()
                    }
                })
            });
            
            if (response.ok) {
                const data = await response.json();
                this.log('Generated tracking token', { notificationId, token: data.tracking_token.substring(0, 8) + '...' });
                return data;
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
        } catch (error) {
            this.log('Error generating tracking token', { error: error.message });
            throw error;
        }
    }
    
    /**
     * Track a user interaction
     */
    async trackInteraction(trackingToken, interactionType, metadata = {}) {
        if (!this.trackingEnabled || !trackingToken) {
            return false;
        }
        
        try {
            const response = await this.makeRequest(`${this.apiEndpoint}/track`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    tracking_token: trackingToken,
                    interaction_type: interactionType,
                    metadata: {
                        ...metadata,
                        page_url: window.location.href,
                        referrer: document.referrer,
                        timestamp: new Date().toISOString(),
                        viewport: `${window.innerWidth}x${window.innerHeight}`
                    }
                })
            });
            
            if (response.ok) {
                const data = await response.json();
                this.log('Tracked interaction', { interactionType, success: data.success });
                return data.success;
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
        } catch (error) {
            this.log('Error tracking interaction', { error: error.message });
            return false;
        }
    }
    
    /**
     * Track when a notification is opened/viewed
     */
    async trackOpened(trackingToken, metadata = {}) {
        return this.trackInteraction(trackingToken, 'opened', {
            ...metadata,
            view_time: new Date().getTime()
        });
    }
    
    /**
     * Track when a notification link is clicked
     */
    async trackClicked(trackingToken, linkUrl = null, metadata = {}) {
        return this.trackInteraction(trackingToken, 'clicked', {
            ...metadata,
            link_url: linkUrl,
            click_time: new Date().getTime()
        });
    }
    
    /**
     * Track when a notification is dismissed
     */
    async trackDismissed(trackingToken, metadata = {}) {
        return this.trackInteraction(trackingToken, 'dismissed', {
            ...metadata,
            dismiss_time: new Date().getTime()
        });
    }
    
    /**
     * Track delivery confirmation
     */
    async trackDelivered(trackingToken, metadata = {}) {
        return this.trackInteraction(trackingToken, 'delivered', {
            ...metadata,
            delivery_time: new Date().getTime()
        });
    }
    
    /**
     * Auto-track page visibility for read time calculation
     */
    setupReadTimeTracking(trackingToken, options = {}) {
        if (!this.trackingEnabled || !trackingToken) {
            return;
        }
        
        const startTime = Date.now();
        let totalReadTime = 0;
        let isVisible = !document.hidden;
        let lastVisibilityChange = startTime;
        
        const updateReadTime = () => {
            if (isVisible) {
                totalReadTime += Date.now() - lastVisibilityChange;
            }
            lastVisibilityChange = Date.now();
        };
        
        const handleVisibilityChange = () => {
            updateReadTime();
            isVisible = !document.hidden;
            
            if (isVisible) {
                this.trackOpened(trackingToken, {
                    read_time_seconds: Math.round(totalReadTime / 1000),
                    visibility_event: 'page_visible'
                });
            }
        };
        
        const handleBeforeUnload = () => {
            updateReadTime();
            
            // Send final read time using beacon API for reliability
            if (navigator.sendBeacon && totalReadTime > 1000) { // Only if read for more than 1 second
                const data = JSON.stringify({
                    tracking_token: trackingToken,
                    interaction_type: 'opened',
                    metadata: {
                        total_read_time_seconds: Math.round(totalReadTime / 1000),
                        final_tracking: true
                    }
                });
                
                navigator.sendBeacon(
                    `${this.baseUrl}${this.apiEndpoint}/track`,
                    new Blob([data], { type: 'application/json' })
                );
            }
        };
        
        // Set up event listeners
        document.addEventListener('visibilitychange', handleVisibilityChange);
        window.addEventListener('beforeunload', handleBeforeUnload);
        
        // Initial tracking
        this.trackOpened(trackingToken, { initial_view: true });
        
        // Return cleanup function
        return () => {
            document.removeEventListener('visibilitychange', handleVisibilityChange);
            window.removeEventListener('beforeunload', handleBeforeUnload);
            updateReadTime();
        };
    }
    
    /**
     * Auto-track clicks on notification elements
     */
    setupClickTracking(trackingToken, selector = '[data-notification-link]') {
        if (!this.trackingEnabled || !trackingToken) {
            return;
        }
        
        const handleClick = (event) => {
            const element = event.target.closest(selector);
            if (element) {
                const linkUrl = element.href || element.dataset.href;
                this.trackClicked(trackingToken, linkUrl, {
                    element_type: element.tagName.toLowerCase(),
                    element_text: element.textContent?.trim().substring(0, 100),
                    click_coordinates: `${event.clientX},${event.clientY}`
                });
            }
        };
        
        document.addEventListener('click', handleClick);
        
        // Return cleanup function
        return () => {
            document.removeEventListener('click', handleClick);
        };
    }
    
    /**
     * Create and inject tracking pixel for email notifications
     */
    createTrackingPixel(trackingToken) {
        if (!this.trackingEnabled || !trackingToken) {
            return null;
        }
        
        const pixelUrl = `${this.baseUrl}${this.apiEndpoint}/pixel/${trackingToken}`;
        const img = document.createElement('img');
        img.src = pixelUrl;
        img.style.cssText = 'width:1px;height:1px;border:0;position:absolute;top:-1000px;left:-1000px;';
        img.alt = '';
        img.setAttribute('aria-hidden', 'true');
        
        // Add to DOM
        document.body.appendChild(img);
        
        this.log('Created tracking pixel', { url: pixelUrl });
        return img;
    }
    
    /**
     * Get tracking analytics for current user
     */
    async getAnalytics(hours = 24) {
        try {
            const response = await this.makeRequest(`${this.apiEndpoint}/analytics?hours=${hours}`);
            
            if (response.ok) {
                return await response.json();
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
        } catch (error) {
            this.log('Error getting analytics', { error: error.message });
            throw error;
        }
    }
    
    /**
     * Request user consent for tracking
     */
    async requestConsent(message = 'This notification includes read receipt tracking. Do you consent to engagement analytics?') {
        if (!this.requireConsent) {
            return true;
        }
        
        // Check if consent already given
        if (this.hasConsent()) {
            return true;
        }
        
        // Request consent
        const consent = confirm(message);
        
        if (consent) {
            localStorage.setItem(this.consentKey, 'true');
            this.trackingEnabled = true;
            this.log('User consent granted for tracking');
        } else {
            localStorage.setItem(this.consentKey, 'false');
            this.log('User consent denied for tracking');
        }
        
        return consent;
    }
    
    /**
     * Check if user has given consent
     */
    hasConsent() {
        if (!this.requireConsent) {
            return true;
        }
        
        return localStorage.getItem(this.consentKey) === 'true';
    }
    
    /**
     * Revoke user consent
     */
    revokeConsent() {
        localStorage.setItem(this.consentKey, 'false');
        this.trackingEnabled = false;
        this.log('User consent revoked for tracking');
    }
    
    /**
     * Make HTTP request with retry logic
     */
    async makeRequest(url, options) {
        let lastError;
        
        for (let attempt = 1; attempt <= this.retryAttempts; attempt++) {
            try {
                const response = await fetch(url, options);
                return response;
                
            } catch (error) {
                lastError = error;
                
                if (attempt < this.retryAttempts) {
                    this.log(`Request attempt ${attempt} failed, retrying...`, { error: error.message });
                    await this.delay(this.retryDelay * attempt);
                } else {
                    this.log(`All ${this.retryAttempts} request attempts failed`, { error: error.message });
                }
            }
        }
        
        throw lastError;
    }
    
    /**
     * Utility: delay execution
     */
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    
    /**
     * Debug logging
     */
    log(message, data = {}) {
        if (this.debugMode) {
            console.log(`[ReadReceiptTracker] ${message}`, data);
        }
    }
}

// Utility functions for easy integration
const ReadReceiptUtils = {
    /**
     * Initialize tracker with default settings
     */
    createTracker(options = {}) {
        return new ReadReceiptTracker(options);
    },
    
    /**
     * Quick setup for notification page tracking
     */
    async setupNotificationTracking(notificationId, options = {}) {
        const tracker = new ReadReceiptTracker(options);
        
        try {
            // Generate tracking token
            const tokenData = await tracker.generateTrackingToken(notificationId);
            
            if (tokenData && tokenData.tracking_token) {
                // Set up read time tracking
                const cleanupReadTime = tracker.setupReadTimeTracking(tokenData.tracking_token);
                
                // Set up click tracking
                const cleanupClicks = tracker.setupClickTracking(tokenData.tracking_token);
                
                // Create tracking pixel if needed
                if (options.useTrackingPixel) {
                    tracker.createTrackingPixel(tokenData.tracking_token);
                }
                
                return {
                    tracker,
                    trackingToken: tokenData.tracking_token,
                    cleanup: () => {
                        if (cleanupReadTime) cleanupReadTime();
                        if (cleanupClicks) cleanupClicks();
                    }
                };
            }
            
        } catch (error) {
            console.warn('Failed to setup notification tracking:', error);
        }
        
        return { tracker, trackingToken: null, cleanup: () => {} };
    }
};

// Export for both ES6 modules and script tags
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ReadReceiptTracker, ReadReceiptUtils };
} else if (typeof window !== 'undefined') {
    window.ReadReceiptTracker = ReadReceiptTracker;
    window.ReadReceiptUtils = ReadReceiptUtils;
}