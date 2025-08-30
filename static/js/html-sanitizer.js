/**
 * HTML Sanitizer for HomeNetMon
 * Prevents XSS attacks by safely handling dynamic content insertion
 */

class HTMLSanitizer {
    constructor() {
        // Define allowed HTML tags and their attributes
        this.allowedTags = {
            'div': ['class', 'id', 'style', 'data-*'],
            'span': ['class', 'id', 'style', 'data-*'],
            'p': ['class', 'id', 'style'],
            'a': ['href', 'class', 'id', 'target', 'rel'],
            'img': ['src', 'alt', 'class', 'id', 'width', 'height'],
            'i': ['class', 'id'],
            'b': ['class', 'id'],
            'strong': ['class', 'id'],
            'em': ['class', 'id'],
            'small': ['class', 'id'],
            'h1': ['class', 'id'],
            'h2': ['class', 'id'],
            'h3': ['class', 'id'],
            'h4': ['class', 'id'],
            'h5': ['class', 'id'],
            'h6': ['class', 'id'],
            'ul': ['class', 'id'],
            'ol': ['class', 'id'],
            'li': ['class', 'id'],
            'table': ['class', 'id'],
            'thead': ['class', 'id'],
            'tbody': ['class', 'id'],
            'tr': ['class', 'id'],
            'th': ['class', 'id'],
            'td': ['class', 'id'],
            'button': ['class', 'id', 'type', 'disabled'],
        };

        // Dangerous attributes that should never be allowed
        this.dangerousAttributes = [
            'onclick', 'onload', 'onerror', 'onmouseover', 'onmouseout',
            'onfocus', 'onblur', 'onchange', 'onsubmit', 'onkeydown',
            'onkeyup', 'onkeypress', 'javascript:', 'vbscript:', 'data:',
            'formaction', 'srcdoc'
        ];

        this.init();
    }

    init() {
        console.log('🛡️ HTML Sanitizer initialized');
    }

    /**
     * Sanitize HTML content to prevent XSS
     * @param {string} html - HTML string to sanitize
     * @param {boolean} allowTags - Whether to allow HTML tags (default: true)
     * @returns {string} - Sanitized HTML
     */
    sanitize(html, allowTags = true) {
        if (typeof html !== 'string') {
            return '';
        }

        if (!allowTags) {
            // Strip all HTML tags and return plain text
            return this.escapeHtml(html);
        }

        // Create a temporary DOM element to parse HTML
        const temp = document.createElement('div');
        temp.innerHTML = html;

        // Recursively sanitize all elements
        this.sanitizeElement(temp);

        return temp.innerHTML;
    }

    /**
     * Escape HTML special characters
     * @param {string} text - Text to escape
     * @returns {string} - Escaped text
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Sanitize a DOM element and its children
     * @param {Element} element - Element to sanitize
     */
    sanitizeElement(element) {
        const children = Array.from(element.children);
        
        for (const child of children) {
            const tagName = child.tagName.toLowerCase();
            
            // Remove disallowed tags
            if (!this.allowedTags[tagName]) {
                child.remove();
                continue;
            }

            // Sanitize attributes
            this.sanitizeAttributes(child);

            // Recursively sanitize children
            this.sanitizeElement(child);
        }
    }

    /**
     * Sanitize element attributes
     * @param {Element} element - Element to sanitize
     */
    sanitizeAttributes(element) {
        const tagName = element.tagName.toLowerCase();
        const allowedAttrs = this.allowedTags[tagName] || [];
        const attributes = Array.from(element.attributes);

        for (const attr of attributes) {
            const attrName = attr.name.toLowerCase();
            const attrValue = attr.value.toLowerCase();

            // Remove dangerous attributes
            if (this.dangerousAttributes.some(dangerous => 
                attrName.includes(dangerous) || attrValue.includes(dangerous))) {
                element.removeAttribute(attr.name);
                continue;
            }

            // Check if attribute is allowed for this tag
            const isAllowed = allowedAttrs.some(allowed => {
                if (allowed.endsWith('*')) {
                    // Wildcard attribute (e.g., data-*)
                    return attrName.startsWith(allowed.slice(0, -1));
                }
                return attrName === allowed;
            });

            if (!isAllowed) {
                element.removeAttribute(attr.name);
            }
        }
    }

    /**
     * Safe innerHTML replacement
     * @param {Element} element - Target element
     * @param {string} html - HTML content to set
     */
    setHTML(element, html) {
        if (!element || !(element instanceof Element)) {
            console.warn('Invalid element provided to setHTML');
            return;
        }

        element.innerHTML = this.sanitize(html);
    }

    /**
     * Safe text content replacement
     * @param {Element} element - Target element
     * @param {string} text - Text content to set
     */
    setText(element, text) {
        if (!element || !(element instanceof Element)) {
            console.warn('Invalid element provided to setText');
            return;
        }

        element.textContent = String(text || '');
    }

    /**
     * Create a text node with escaped content
     * @param {string} text - Text content
     * @returns {Text} - Text node
     */
    createTextNode(text) {
        return document.createTextNode(String(text || ''));
    }

    /**
     * Validate and sanitize URLs
     * @param {string} url - URL to validate
     * @returns {string|null} - Sanitized URL or null if invalid
     */
    sanitizeUrl(url) {
        if (typeof url !== 'string') {
            return null;
        }

        // Remove dangerous protocols
        const dangerousProtocols = ['javascript:', 'vbscript:', 'data:', 'file:'];
        const lowerUrl = url.toLowerCase().trim();
        
        if (dangerousProtocols.some(protocol => lowerUrl.startsWith(protocol))) {
            return null;
        }

        // Allow relative URLs, HTTP, HTTPS
        if (url.startsWith('/') || url.startsWith('./') || url.startsWith('../') ||
            lowerUrl.startsWith('http://') || lowerUrl.startsWith('https://') ||
            lowerUrl.startsWith('mailto:') || lowerUrl.startsWith('tel:')) {
            return url;
        }

        return null;
    }

    /**
     * Template literal tag for safe HTML
     * Usage: html`<div>${userContent}</div>`
     */
    html(strings, ...values) {
        let result = '';
        for (let i = 0; i < strings.length; i++) {
            result += strings[i];
            if (i < values.length) {
                result += this.escapeHtml(String(values[i]));
            }
        }
        return this.sanitize(result);
    }

    /**
     * Create a safe HTML builder
     * @returns {Object} - HTML builder with safe methods
     */
    createBuilder() {
        return {
            div: (content, className = '') => 
                `<div class="${this.escapeHtml(className)}">${this.sanitize(content)}</div>`,
            span: (content, className = '') => 
                `<span class="${this.escapeHtml(className)}">${this.sanitize(content)}</span>`,
            p: (content, className = '') => 
                `<p class="${this.escapeHtml(className)}">${this.sanitize(content)}</p>`,
            button: (content, className = '', type = 'button') => 
                `<button type="${this.escapeHtml(type)}" class="${this.escapeHtml(className)}">${this.sanitize(content)}</button>`,
            link: (text, href, className = '') => {
                const safeHref = this.sanitizeUrl(href);
                if (!safeHref) return this.escapeHtml(text);
                return `<a href="${this.escapeHtml(safeHref)}" class="${this.escapeHtml(className)}">${this.escapeHtml(text)}</a>`;
            },
            icon: (iconClass, className = '') =>
                `<i class="${this.escapeHtml(iconClass)} ${this.escapeHtml(className)}"></i>`
        };
    }
}

// Create global instance
if (typeof window !== 'undefined') {
    window.htmlSanitizer = new HTMLSanitizer();
    
    // Create convenient global functions
    window.safeHTML = (element, html) => window.htmlSanitizer.setHTML(element, html);
    window.safeText = (element, text) => window.htmlSanitizer.setText(element, text);
    window.escapeHTML = (text) => window.htmlSanitizer.escapeHtml(text);
    window.sanitizeHTML = (html) => window.htmlSanitizer.sanitize(html);
    
    // Template literal for safe HTML
    window.html = (strings, ...values) => window.htmlSanitizer.html(strings, ...values);
    
    // Override console functions to warn about unsafe innerHTML usage
    if (window.location.hostname !== 'localhost' && !window.location.hostname.startsWith('192.168.')) {
        const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(value) {
                if (typeof value === 'string' && value.includes('<') && !this.dataset.allowUnsafeHTML) {
                    console.warn(
                        'Potentially unsafe innerHTML usage detected. Consider using safeHTML() instead.',
                        this, value
                    );
                }
                return originalInnerHTML.set.call(this, value);
            },
            get: function() {
                return originalInnerHTML.get.call(this);
            }
        });
    }
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = HTMLSanitizer;
}