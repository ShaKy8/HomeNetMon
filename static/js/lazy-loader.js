/**
 * Lazy JavaScript Library Loader
 * Only loads libraries when they're actually needed
 */

class LazyLoader {
    constructor() {
        this.loadedLibraries = new Set();
        this.loadingPromises = new Map();
    }

    /**
     * Load a JavaScript library if not already loaded
     * @param {string} name - Library name
     * @param {string} url - Library URL
     * @returns {Promise} - Resolves when library is loaded
     */
    async loadScript(name, url) {
        if (this.loadedLibraries.has(name)) {
            return Promise.resolve();
        }

        if (this.loadingPromises.has(name)) {
            return this.loadingPromises.get(name);
        }

        const promise = new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = url;
            script.async = true;
            
            script.onload = () => {
                this.loadedLibraries.add(name);
                this.loadingPromises.delete(name);
                resolve();
            };
            
            script.onerror = () => {
                this.loadingPromises.delete(name);
                reject(new Error(`Failed to load ${name}`));
            };
            
            document.head.appendChild(script);
        });

        this.loadingPromises.set(name, promise);
        return promise;
    }

    /**
     * Load Chart.js when needed
     */
    async loadChartJS() {
        if (window.Chart) return;
        
        return this.loadScript(
            'chartjs', 
            'https://cdn.jsdelivr.net/npm/chart.js'
        );
    }

    /**
     * Load D3.js when needed
     */
    async loadD3() {
        if (window.d3) return;
        
        return this.loadScript(
            'd3', 
            'https://cdn.jsdelivr.net/npm/d3@7'
        );
    }

    /**
     * Load a library and execute callback when ready
     * @param {string} library - Library name ('chartjs', 'd3')
     * @param {Function} callback - Function to execute when loaded
     */
    async when(library, callback) {
        try {
            switch (library) {
                case 'chartjs':
                    await this.loadChartJS();
                    break;
                case 'd3':
                    await this.loadD3();
                    break;
                default:
                    throw new Error(`Unknown library: ${library}`);
            }
            
            if (typeof callback === 'function') {
                callback();
            }
        } catch (error) {
        }
    }

    /**
     * Preload libraries that are likely to be needed soon
     */
    preload() {
        // Preload Chart.js with low priority if we're likely to need it
        if (document.querySelector('[data-needs-charts]') || 
            window.location.pathname.includes('dashboard') ||
            window.location.pathname.includes('analytics')) {
            
            requestIdleCallback(() => {
                this.loadChartJS().catch(() => {
                    // Silently fail preloading
                });
            });
        }

        // Preload D3.js if we're on topology page
        if (document.querySelector('[data-needs-d3]') || 
            window.location.pathname.includes('topology')) {
            
            requestIdleCallback(() => {
                this.loadD3().catch(() => {
                    // Silently fail preloading
                });
            });
        }
    }
}

// Global lazy loader instance
window.lazyLoader = new LazyLoader();

// Auto-preload on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.lazyLoader.preload();
    });
} else {
    window.lazyLoader.preload();
}

// Convenience functions
window.loadCharts = () => window.lazyLoader.loadChartJS();
window.loadD3 = () => window.lazyLoader.loadD3();
window.whenCharts = (callback) => window.lazyLoader.when('chartjs', callback);
window.whenD3 = (callback) => window.lazyLoader.when('d3', callback);