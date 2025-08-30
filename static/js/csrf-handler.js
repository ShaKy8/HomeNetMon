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
        // Get initial token from cookies
        this.token = this.getCookie(this.tokenName);
        
        // Set up automatic token inclusion in requests
        this.setupFetchInterceptor();
        this.setupXHRInterceptor();
        
        console.log('🔒 CSRF Handler initialized');
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
        // Refresh token from cookies if not available
        if (!this.token) {
            this.token = this.getCookie(this.tokenName);
        }
        return this.token;
    }

    setToken(token) {
        this.token = token;
    }

    // Intercept fetch requests to automatically add CSRF token
    setupFetchInterceptor() {
        const originalFetch = window.fetch;
        
        window.fetch = (url, options = {}) => {
            // Only add CSRF token for same-origin requests
            if (this.isSameOrigin(url)) {
                const token = this.getToken();
                if (token && this.requiresCSRFToken(options.method || 'GET')) {
                    options.headers = {
                        ...options.headers,
                        [this.headerName]: token
                    };
                }
            }
            
            return originalFetch(url, options);
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
                if (token && window.csrfHandler.requiresCSRFToken(this._method)) {
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

    requiresCSRFToken(method) {
        const upperMethod = (method || 'GET').toUpperCase();
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
        this.token = this.getCookie(this.tokenName);
        return this.token;
    }

    // Handle CSRF errors
    handleCSRFError(response) {
        if (response && response.status === 403) {
            // Try to refresh token
            this.refreshToken();
            
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
            
            return true; // Indicates error was handled
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