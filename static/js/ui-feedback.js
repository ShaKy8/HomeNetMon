/**
 * HomeNetMon shared UI helpers, loaded on every page before page scripts.
 *
 *   escapeHtml(text)                 -> HTML-safe string for innerHTML templates
 *   showToast(message, type, delay)  -> Bootstrap toast (falls back to a plain banner)
 *   showSuccess(message) / showError(message)
 *   showGlobalLoading(message) / hideGlobalLoading()
 *   apiRequest(url, {method, body})  -> fetch + JSON; throws Error(message) on !ok
 *   debounce(fn, wait)               -> trailing-edge debounce
 *
 * A page may define its own function with one of these names; a function
 * declaration in a page script wins over these assignments, which is the
 * intended override path. (The previous base template *re-assigned* console-only
 * stubs on DOMContentLoaded, after page scripts, so every page toast was lost.)
 */
(function () {
    'use strict';

    function escapeHtml(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function toastContainer() {
        let el = document.getElementById('hnm-toast-container');
        if (!el) {
            el = document.createElement('div');
            el.id = 'hnm-toast-container';
            el.className = 'toast-container position-fixed top-0 end-0 p-3';
            el.style.zIndex = '1080';
            el.setAttribute('aria-live', 'polite');
            (document.body || document.documentElement).appendChild(el);
        }
        return el;
    }

    const TYPE_CLASS = { success: 'text-bg-success', error: 'text-bg-danger', danger: 'text-bg-danger',
                         warning: 'text-bg-warning', info: 'text-bg-primary' };

    function showToast(message, type, delay) {
        type = type || 'info';
        delay = typeof delay === 'number' ? delay : 4000;
        const container = toastContainer();
        const toastEl = document.createElement('div');
        toastEl.className = 'toast align-items-center border-0 ' + (TYPE_CLASS[type] || TYPE_CLASS.info);
        toastEl.setAttribute('role', type === 'error' || type === 'danger' ? 'alert' : 'status');
        toastEl.setAttribute('aria-atomic', 'true');
        const row = document.createElement('div');
        row.className = 'd-flex';
        const body = document.createElement('div');
        body.className = 'toast-body';
        body.textContent = String(message);
        const close = document.createElement('button');
        close.type = 'button';
        close.className = 'btn-close btn-close-white me-2 m-auto';
        close.setAttribute('aria-label', 'Close');
        row.appendChild(body); row.appendChild(close); toastEl.appendChild(row);
        container.appendChild(toastEl);

        const remove = () => { if (toastEl.parentNode) toastEl.parentNode.removeChild(toastEl); };
        close.addEventListener('click', remove);
        if (window.bootstrap && window.bootstrap.Toast) {
            const t = new window.bootstrap.Toast(toastEl, { delay: delay, autohide: delay > 0 });
            toastEl.addEventListener('hidden.bs.toast', remove);
            t.show();
        } else {
            toastEl.classList.add('show');
            if (delay > 0) setTimeout(remove, delay);
        }
        return toastEl;
    }

    function showSuccess(message) { return showToast(message, 'success'); }
    function showError(message) { return showToast(message, 'error', 6000); }

    function showGlobalLoading(message) {
        let overlay = document.getElementById('hnm-loading-overlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'hnm-loading-overlay';
            overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.35);z-index:1090;' +
                                    'display:flex;align-items:center;justify-content:center';
            const box = document.createElement('div');
            box.className = 'bg-body text-body rounded shadow p-3 d-flex align-items-center gap-2';
            box.innerHTML = '<div class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></div>' +
                            '<span id="hnm-loading-text"></span>';
            overlay.appendChild(box);
            (document.body || document.documentElement).appendChild(overlay);
        }
        overlay.querySelector('#hnm-loading-text').textContent = message || 'Loading...';
        overlay.hidden = false;
    }
    function hideGlobalLoading() {
        const overlay = document.getElementById('hnm-loading-overlay');
        if (overlay) overlay.hidden = true;
    }

    async function apiRequest(url, options) {
        options = options || {};
        const init = { method: options.method || 'GET', headers: Object.assign({}, options.headers || {}) };
        if (options.body !== undefined) {
            init.headers['Content-Type'] = 'application/json';
            init.body = JSON.stringify(options.body);
        }
        const response = await fetch(url, init);   // csrf-handler.js adds X-CSRF-Token for unsafe methods
        let data = null;
        try { data = await response.json(); } catch (e) { /* no body */ }
        if (!response.ok) {
            const err = new Error((data && (data.error || data.message)) || ('HTTP ' + response.status));
            err.status = response.status; err.data = data;
            throw err;
        }
        return data;
    }

    function debounce(func, wait) {
        let timeout;
        return function debounced(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    window.HNM = { escapeHtml, showToast, showSuccess, showError, showGlobalLoading, hideGlobalLoading, apiRequest, debounce };
    window.debounce = debounce;
    window.escapeHtml = escapeHtml;
    window.showToast = showToast;
    window.showSuccess = showSuccess;
    window.showError = showError;
    window.showGlobalLoading = showGlobalLoading;
    window.hideGlobalLoading = hideGlobalLoading;
    window.apiRequest = apiRequest;
})();
