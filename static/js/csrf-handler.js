/**
 * CSRF Token Handler for HomeNetMon
 * Automatically handles CSRF tokens for API requests
 */

class CSRFHandler {
    constructor() {
        this.token = null;
        this.tokenName = 'csrf_token';
        this.headerName = 'X-CSRF-Token';
        this.init();
    }

    init() {
        // Get initial token from meta tag first, then fall back to cookies
        this.token = this.getTokenFromMeta() || this.getCookie(this.tokenName);

        // Set up automatic token inclusion in requests
        this.setupFetchInterceptor();
        this.setupXHRInterceptor();

        console.log('🔒 CSRF Handler initialized with token:', this.token ? 'PRESENT' : 'MISSING');
    }

    getTokenFromMeta() {
        const metaToken = document.querySelector('meta[name="csrf-token"]');
        return metaToken ? metaToken.getAttribute('content') : null;
    }

    getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) {
            return parts.pop().split(';').shift();
        }
        return null;
    }

    getToken() {
        // Refresh token from meta tag or cookies if not available
        if (!this.token) {
            this.token = this.getTokenFromMeta() || this.getCookie(this.tokenName);
        }
        return this.token;
    }

    async refreshTokenFromAPI() {
        try {
            console.log('🔒 Refreshing CSRF token from API...');
            const response = await fetch('/api/csrf-token', {
                method: 'GET',
                credentials: 'same-origin'
            });

            if (!response.ok) {
                throw new Error(`Token refresh failed: ${response.status}`);
            }

            const data = await response.json();
            this.token = data.csrf_token;

            // Update meta tag for other scripts
            let metaTag = document.querySelector('meta[name="csrf-token"]');
            if (metaTag) {
                metaTag.setAttribute('content', this.token);
            }

            console.log('🔒 CSRF token refreshed successfully');
            return this.token;
        } catch (error) {
            console.error('🔒 CSRF token refresh failed:', error);
            throw error;
        }
    }

    setToken(token) {
        this.token = token;
    }

    // Intercept fetch requests to automatically add CSRF token
    setupFetchInterceptor() {
        const originalFetch = window.fetch;
        
        window.fetch = (url, options = {}) => {
            // Debug logging for alerts endpoint
            if (url.includes('/api/monitoring/alerts')) {
                console.log('🔍 CSRF Handler - Alerts request:', {
                    url,
                    method: options.method || 'GET',
                    headers: options.headers,
                    requiresToken: this.requiresCSRFToken(options.method || 'GET', url)
                });
            }

            // Only add CSRF token for same-origin requests
            if (this.isSameOrigin(url)) {
                const token = this.getToken();
                if (token && this.requiresCSRFToken(options.method || 'GET', url)) {
                    options.headers = {
                        ...options.headers,
                        [this.headerName]: token
                    };

                    if (url.includes('/api/monitoring/alerts')) {
                        console.log('🔒 CSRF Handler - Added token to alerts request');
                    }
                }
            }

            // Debug the exact request being made for alerts
            if (url.includes('/api/monitoring/alerts')) {
                console.log('🚀 Making alerts request with options:', {
                    url: url,
                    options: JSON.stringify(options, null, 2)
                });
            }

            return originalFetch(url, options).catch(error => {
                if (url.includes('/api/monitoring/alerts')) {
                    console.error('🚨 Alerts request failed:', error);
                    console.log('🚨 Failed request details:', { url, options });
                }
                throw error;
            });
        };
    }

    // Intercept XMLHttpRequest to automatically add CSRF token
    setupXHRInterceptor() {
        const originalOpen = XMLHttpRequest.prototype.open;
        const originalSend = XMLHttpRequest.prototype.send;

        XMLHttpRequest.prototype.open = function(method, url, ...args) {
            this._method = method;
            this._url = url;
            return originalOpen.apply(this, [method, url, ...args]);
        };

        XMLHttpRequest.prototype.send = function(data) {
            if (window.csrfHandler && window.csrfHandler.isSameOrigin(this._url)) {
                const token = window.csrfHandler.getToken();
                if (token && window.csrfHandler.requiresCSRFToken(this._method, this._url)) {
                    this.setRequestHeader(window.csrfHandler.headerName, token);
                }
            }
            return originalSend.apply(this, arguments);
        };
    }

    isSameOrigin(url) {
        // Check if URL is same-origin
        if (!url) return true;
        
        // Relative URLs are same-origin
        if (url.startsWith('/') || !url.includes('://')) {
            return true;
        }
        
        // Check if absolute URL matches current origin
        try {
            const urlObj = new URL(url);
            return urlObj.origin === window.location.origin;
        } catch (e) {
            return false;
        }
    }

    requiresCSRFToken(method, url = '') {
        const upperMethod = (method || 'GET').toUpperCase();

        // URL-based exemptions for specific endpoints (read-only or token endpoints only)
        const exemptPaths = [
            '/api/health',      // Read-only health check
            '/api/csrf-token'   // Token refresh endpoint
        ];

        // Check if URL matches any exempt path
        if (exemptPaths.some(path => url.includes(path))) {
            return false;
        }

        // CSRF token required for all state-changing methods
        return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(upperMethod);
    }

    // Add CSRF token to form data
    addTokenToFormData(formData) {
        const token = this.getToken();
        if (token && formData instanceof FormData) {
            formData.append(this.tokenName, token);
        }
        return formData;
    }

    // Add CSRF token to form element
    addTokenToForm(form) {
        const token = this.getToken();
        if (token && form instanceof HTMLFormElement) {
            // Remove existing CSRF token fields
            const existingTokens = form.querySelectorAll(`input[name="${this.tokenName}"]`);
            existingTokens.forEach(input => input.remove());
            
            // Add new CSRF token field
            const tokenInput = document.createElement('input');
            tokenInput.type = 'hidden';
            tokenInput.name = this.tokenName;
            tokenInput.value = token;
            form.appendChild(tokenInput);
        }
    }

    // Setup forms to automatically include CSRF tokens
    setupForms() {
        document.addEventListener('submit', (event) => {
            const form = event.target;
            if (form instanceof HTMLFormElement) {
                this.addTokenToForm(form);
            }
        });

        // Also setup existing forms
        document.querySelectorAll('form').forEach(form => {
            this.addTokenToForm(form);
        });
    }

    // Utility method for manual API calls
    getHeaders(additionalHeaders = {}) {
        const token = this.getToken();
        const headers = { ...additionalHeaders };
        
        if (token) {
            headers[this.headerName] = token;
        }
        
        return headers;
    }

    // Refresh token (typically called after receiving new token in response)
    refreshToken() {
        this.token = this.getTokenFromMeta() || this.getCookie(this.tokenName);
        return this.token;
    }

    // Handle CSRF errors with automatic retry
    async handleCSRFError(response) {
        if (response && (response.status === 403 || response.status === 422)) {
            try {
                console.log('🔒 CSRF error detected, attempting automatic token refresh...');
                await this.refreshTokenFromAPI();
                return true; // Indicates error was handled and retry should be attempted
            } catch (error) {
                console.error('🔒 Automatic token refresh failed:', error);

                // Show user-friendly error
                if (window.modernNotifications) {
                    window.modernNotifications.warning('Security token expired. Please refresh the page.', {
                        duration: 5000,
                        actions: [{
                            label: 'Refresh',
                            primary: true,
                            callback: () => window.location.reload()
                        }]
                    });
                } else {
                    console.warn('CSRF token validation failed. Page refresh may be required.');
                }

                return false; // Could not handle error
            }
        }

        return false; // Not a CSRF error
    }
}

// Initialize global CSRF handler
if (typeof window !== 'undefined') {
    window.csrfHandler = new CSRFHandler();
    
    // Setup forms when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            window.csrfHandler.setupForms();
        });
    } else {
        window.csrfHandler.setupForms();
    }
    
    // Expose utility functions globally
    window.getCSRFToken = () => window.csrfHandler.getToken();
    window.getCSRFHeaders = (headers) => window.csrfHandler.getHeaders(headers);
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CSRFHandler;
}