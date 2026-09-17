/* Smart Home page controller.
 *   garage door : GET /api/garage, POST /api/garage/{door,light,lock}, GET /api/garage/history
 *   live updates: Socket.IO room updates_monitoring_summary -> garage_status; updates_device_status -> device_status_update
 *   devices     : GET /api/devices filtered to the smart-home types, rendered with createDeviceCard (device-cards.js)
 * Shared helpers (apiRequest, showSuccess, showError, escapeHtml, debounce) come from ui-feedback.js;
 * csrf-handler.js adds the CSRF header to every POST. Every string from the board or the LAN is escaped.
 */
(function () {
    'use strict';

    const esc = (v) => (window.escapeHtml ? window.escapeHtml(v) : String(v == null ? '' : v));
    const SMART_TYPES = ['smart_home', 'iot', 'media', 'speaker', 'tv', 'thermostat', 'sensor'];
    const MOVING = ['opening', 'closing'];
    const OPEN_STATES = ['open', 'opening', 'closing', 'stopped'];
    const HOLD_MS = 800;
    const DOOR_TRAVEL = 116;            // SVG units the door panel rises when fully open

    let socket = null;
    let garage = null;                  // last /api/garage document
    let chart = null;
    let devices = [];
    let optimisticUntil = 0;            // ignore stale pushes for a moment after a command
    const reloadHistory = debounce(loadHistory, 1200);

    const $ = (id) => document.getElementById(id);

    // ------------------------------------------------------------------ garage state
    async function loadGarage() {
        try {
            applyGarage(await apiRequest('/api/garage'));
        } catch (error) {
            console.error('Garage status unavailable:', error);
            setLive('Unavailable', '');
        }
    }

    function effectiveDoor(d) {
        if (!d.enabled || !d.configured) return 'unconfigured';
        if (d.online === false) return 'offline';
        return d.door || 'unknown';
    }

    function applyGarage(data) {
        if (!data) return;
        if (Date.now() < optimisticUntil && garage && MOVING.includes(garage.door) && data.door === garage.door_before_command) {
            return;                      // the board has not caught up with our command yet
        }
        garage = data;
        const card = $('garage-card');
        const state = effectiveDoor(data);
        card.dataset.state = state;
        card.classList.toggle('light-on', data.light === true);
        card.classList.toggle('obstructed', data.obstruction === true);

        $('garage-hero-body').hidden = state === 'unconfigured';
        $('garage-empty').hidden = state !== 'unconfigured';
        $('garage-overlay').hidden = state !== 'offline';

        const note = $('garage-offline-note');
        if (state === 'offline') {
            note.textContent = `The ratgdo at ${data.host || '?'} is not answering (${data.consecutive_failures || 0} failed polls). ` +
                'Check that the board is powered and on the main Wi-Fi; the door itself still works from remotes and the wall button.';
            note.hidden = false;
        } else {
            note.hidden = true;
        }

        // Door panel position (0 closed .. 1 open); while moving without a position, animate towards the target.
        let position = typeof data.position === 'number' ? data.position : null;
        if (position === null) position = state === 'open' ? 1 : state === 'closed' ? 0 : 0.5;
        if (state === 'opening' && position < 0.99) position = 1;
        if (state === 'closing' && position > 0.01) position = 0;
        $('garage-door-panel').style.transform = `translateY(${-(DOOR_TRAVEL * position).toFixed(1)}px)`;

        const stateEl = $('garage-door-state');
        const labels = { closed: 'Closed', open: 'Open', opening: 'Opening', closing: 'Closing', stopped: 'Stopped part way',
                         offline: 'Controller offline', unknown: 'Unknown', unconfigured: 'Not configured' };
        stateEl.textContent = labels[state] || state;
        stateEl.className = 'garage-state ' + (
            state === 'closed' ? 'garage-state-closed' :
            MOVING.includes(state) ? 'garage-state-moving' :
            OPEN_STATES.includes(state) ? 'garage-state-open' :
            'garage-state-offline');
        tickOpenFor();

        // Primary action: open when closed, close when open/stopped, nothing while moving (Stop shows instead).
        const primary = $('garage-primary-action');
        const label = $('garage-primary-label');
        const stop = $('garage-stop-action');
        const usable = state !== 'unconfigured' && state !== 'offline' && state !== 'unknown';
        const moving = MOVING.includes(state);
        primary.disabled = !usable || moving;
        stop.hidden = !(usable && moving);
        $('garage-hold-hint').hidden = !usable || moving;
        if (state === 'closed' || state === 'unknown' || !usable) {
            primary.classList.remove('close-action');
            primary.dataset.action = 'open';
            label.innerHTML = '<i class="bi bi-arrow-up-square"></i> Hold to open';
            primary.setAttribute('aria-label', 'Hold to open the garage door');
        } else if (moving) {
            primary.dataset.action = '';
            label.innerHTML = state === 'opening' ? '<i class="bi bi-arrow-up-square"></i> Opening...' : '<i class="bi bi-arrow-down-square"></i> Closing...';
        } else {
            primary.classList.add('close-action');
            primary.dataset.action = 'close';
            label.innerHTML = '<i class="bi bi-arrow-down-square"></i> Hold to close';
            primary.setAttribute('aria-label', 'Hold to close the garage door');
        }

        const light = $('garage-light-toggle');
        const lock = $('garage-lock-toggle');
        light.disabled = lock.disabled = !usable;
        light.checked = data.light === true;
        lock.checked = data.lock === true;

        $('garage-obstruction').hidden = data.obstruction !== true;
        $('garage-motion').hidden = data.motion !== true;
        if (state === 'unconfigured') setLive('Not configured', '');
        else if (state === 'offline') setLive('Offline', 'warn');
        else if (data.sse_connected) setLive('Live', 'live');
        else setLive(`Polling every ${data.poll_interval || 60} s`, '');

        $('garage-last-event').textContent = data.last_event ? `Last: ${describeEvent(data.last_event)} at ${fmtTime(data.last_event.timestamp, true)}` : '';
        const board = data.board || {};
        const bits = [board.host ? `ratgdo at ${board.host}` : null, board.name, board.firmware ? `firmware ${board.firmware}` : null,
                      data.openings != null ? `${data.openings} openings in the board's lifetime` : null].filter(Boolean);
        $('garage-board').textContent = bits.join(' · ');
    }

    function setLive(text, kind) {
        $('garage-live-text').textContent = text;
        $('garage-live').className = 'badge-chip' + (kind ? ' ' + kind : '');
    }

    function openForSeconds() {
        if (!garage || !garage.open_since || !OPEN_STATES.includes(garage.door)) return null;
        return Math.max(0, (Date.now() - Date.parse(garage.open_since)) / 1000);
    }

    function tickOpenFor() {
        const el = $('garage-open-for');
        const seconds = openForSeconds();
        if (seconds === null || !garage || garage.online === false) { el.textContent = ''; return; }
        el.textContent = `Open for ${formatDuration(seconds)}` +
            (garage.left_open_minutes && seconds >= garage.left_open_minutes * 60 ? ' · longer than your alert threshold' : '');
    }

    // ------------------------------------------------------------------ commands
    async function doorAction(action) {
        if (!action) return;
        const before = garage ? garage.door : null;
        try {
            const result = await apiRequest('/api/garage/door', { method: 'POST', body: { action } });
            if (garage && action !== 'stop') {
                // Optimistic: show the motion right away; the board's own state follows within a second.
                garage.door_before_command = before;
                optimisticUntil = Date.now() + 4000;
                applyGarage(Object.assign({}, result.state || garage, { door: action === 'open' ? 'opening' : 'closing' }));
            } else if (result.state) {
                applyGarage(result.state);
            }
            showSuccess(action === 'stop' ? 'Stop sent to the opener' : `${action === 'open' ? 'Opening' : 'Closing'} the garage door`);
        } catch (error) {
            showError(`Garage door ${action} failed: ${error.message}`);
            loadGarage();
        }
    }

    async function lightAction(on) {
        try {
            const result = await apiRequest('/api/garage/light', { method: 'POST', body: { action: on ? 'on' : 'off' } });
            if (result.state) applyGarage(result.state);
            showSuccess(`Opener light ${on ? 'on' : 'off'}`);
        } catch (error) {
            showError(`Light ${on ? 'on' : 'off'} failed: ${error.message}`);
            $('garage-light-toggle').checked = !on;
        }
    }

    async function lockAction(lock) {
        try {
            const result = await apiRequest('/api/garage/lock', { method: 'POST', body: { action: lock ? 'lock' : 'unlock' } });
            if (result.state) applyGarage(result.state);
            showSuccess(lock ? 'Wireless remotes locked out' : 'Wireless remotes enabled');
        } catch (error) {
            showError(`${lock ? 'Lock' : 'Unlock'} failed: ${error.message}`);
            $('garage-lock-toggle').checked = !lock;
        }
    }

    // Press-and-hold confirmation: the ring fills over HOLD_MS; releasing early cancels.
    function bindHold(button, onConfirm) {
        let start = null, frame = null, fired = false;
        const reset = () => {
            if (frame) cancelAnimationFrame(frame);
            frame = null; start = null; fired = false;
            button.style.setProperty('--hold', 0);
            button.classList.remove('holding');
        };
        const step = (now) => {
            if (start === null) return;
            const progress = Math.min(1, (now - start) / HOLD_MS);
            button.style.setProperty('--hold', progress.toFixed(3));
            if (progress >= 1 && !fired) {
                fired = true;
                const action = button.dataset.action;
                reset();
                onConfirm(action);
                return;
            }
            frame = requestAnimationFrame(step);
        };
        const begin = () => {
            if (button.disabled || start !== null) return;
            start = performance.now();
            button.classList.add('holding');
            frame = requestAnimationFrame(step);
        };
        button.addEventListener('pointerdown', (e) => { if (e.button === 0 || e.pointerType !== 'mouse') { e.preventDefault(); begin(); } });
        ['pointerup', 'pointerleave', 'pointercancel'].forEach((ev) => button.addEventListener(ev, reset));
        button.addEventListener('keydown', (e) => { if ((e.key === 'Enter' || e.key === ' ') && !e.repeat) { e.preventDefault(); begin(); } });
        button.addEventListener('keyup', (e) => { if (e.key === 'Enter' || e.key === ' ') reset(); });
        button.addEventListener('blur', reset);
        button.addEventListener('click', (e) => e.preventDefault());
    }

    // ------------------------------------------------------------------ history
    async function loadHistory() {
        try {
            const data = await apiRequest('/api/garage/history?hours=336');
            renderStats(data.stats || {});
            renderChart(data.daily || []);
            renderEvents(data.events || []);
        } catch (error) {
            console.error('Garage history unavailable:', error);
            $('garage-events').innerHTML = '<li class="event-empty">History unavailable</li>';
        }
    }

    function renderStats(s) {
        $('stat-openings-today').textContent = s.openings_today != null ? s.openings_today : '--';
        $('stat-openings-week').textContent = s.openings_week != null ? s.openings_week : '--';
        $('stat-avg-open').textContent = s.avg_open_seconds != null ? formatDuration(s.avg_open_seconds) : '--';
        $('stat-longest-today').textContent = s.longest_open_today_seconds != null ? formatDuration(s.longest_open_today_seconds) : '--';
    }

    function chartColors() {
        const dark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
        return {
            bar: dark ? 'rgba(96, 165, 250, 0.75)' : 'rgba(37, 99, 235, 0.7)',
            barToday: dark ? 'rgba(251, 191, 36, 0.85)' : 'rgba(217, 119, 6, 0.8)',
            grid: dark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.08)',
            text: dark ? 'rgba(255, 255, 255, 0.7)' : 'rgba(30, 41, 59, 0.75)'
        };
    }

    let lastDaily = [];
    function renderChart(daily) {
        lastDaily = daily;
        const canvas = $('garage-chart');
        if (!canvas || typeof Chart === 'undefined') return;
        const c = chartColors();
        const labels = daily.map((d, i) => {
            const date = new Date(d.date + 'T12:00:00');
            return i === daily.length - 1 ? 'Today' : date.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric' });
        });
        const openings = daily.map((d) => d.openings || 0);
        const minutes = daily.map((d) => Math.round((d.open_seconds || 0) / 60));
        if (chart) chart.destroy();
        chart = new Chart(canvas.getContext('2d'), {
            type: 'bar',
            data: {
                labels,
                datasets: [{
                    label: 'Openings',
                    data: openings,
                    backgroundColor: openings.map((_, i) => i === openings.length - 1 ? c.barToday : c.bar),
                    borderRadius: 6,
                    maxBarThickness: 36
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: (ctx) => `${ctx.parsed.y} opening${ctx.parsed.y === 1 ? '' : 's'}`,
                            afterLabel: (ctx) => minutes[ctx.dataIndex] ? `open ${minutes[ctx.dataIndex]} min in total` : ''
                        }
                    }
                },
                scales: {
                    x: { grid: { display: false }, ticks: { color: c.text, maxRotation: 0, autoSkip: true } },
                    y: { beginAtZero: true, grid: { color: c.grid }, ticks: { color: c.text, precision: 0 } }
                }
            }
        });
    }

    const EVENT_ICONS = { door: 'bi-door-open', light: 'bi-lightbulb', lock: 'bi-lock', obstruction: 'bi-exclamation-triangle', online: 'bi-broadcast' };

    function describeEvent(e) {
        const by = e.source === 'dashboard' ? 'from HomeNetMon' : e.source === 'external' ? 'by remote or wall button' : '';
        if (e.kind === 'door') {
            const words = { opening: 'Opening', open: 'Opened', closing: 'Closing', closed: 'Closed', stopped: 'Stopped part way', unknown: 'State unknown' };
            let text = words[e.value] || e.value;
            if (e.value === 'closed' && e.duration_s != null) text += ` after ${formatDuration(e.duration_s)} open`;
            return by && e.value !== 'unknown' ? `${text} ${by}` : text;
        }
        const fromUs = e.source === 'dashboard' ? ' from HomeNetMon' : '';
        if (e.kind === 'light') return `Light ${e.value}${fromUs}`;
        if (e.kind === 'lock') return `Remotes ${e.value}${fromUs}`;
        if (e.kind === 'obstruction') return e.value === 'detected' ? 'Obstruction detected' : 'Obstruction cleared';
        if (e.kind === 'online') return e.value === 'online' ? 'Controller back online' : 'Controller went offline';
        return `${e.kind} ${e.value}`;
    }

    function fmtTime(iso, withDate) {
        const d = new Date(iso);
        if (Number.isNaN(d.getTime())) return '';
        const today = new Date();
        const sameDay = d.toDateString() === today.toDateString();
        const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
        if (sameDay || !withDate) return sameDay ? time : `${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} ${time}`;
        return `${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} ${time}`;
    }

    function renderEvents(events) {
        const list = $('garage-events');
        if (!events.length) {
            list.innerHTML = '<li class="event-empty">No door activity recorded yet</li>';
            return;
        }
        list.innerHTML = events.slice(0, 25).map((e) => `
            <li>
                <span class="event-time">${esc(fmtTime(e.timestamp, true))}</span>
                <span class="event-icon"><i class="bi ${EVENT_ICONS[e.kind] || 'bi-dot'}"></i></span>
                <span class="event-text">${esc(describeEvent(e))}</span>
            </li>`).join('');
    }

    // ------------------------------------------------------------------ smart-home devices
    async function loadSmartDevices() {
        try {
            const data = await apiRequest('/api/devices');
            devices = (data.devices || []).filter((d) => SMART_TYPES.includes(d.device_type) && d.is_monitored !== false);
            devices.sort((a, b) => (a.status === 'down') - (b.status === 'down') || String(a.display_name || a.hostname || '').localeCompare(String(b.display_name || b.hostname || '')));
            renderSmartDevices();
        } catch (error) {
            $('smart-devices-empty').textContent = `Could not load devices: ${error.message}`;
            $('smart-devices-empty').hidden = false;
        }
    }

    function renderSmartDevices() {
        const grid = $('smart-devices-grid');
        grid.innerHTML = devices.map((d) => createDeviceCard(d)).join('');
        $('smart-devices-count').textContent = devices.length;
        $('smart-devices-empty').hidden = devices.length > 0;
    }

    function handleDeviceStatusUpdate(data) {
        if (!data || data.device_id === undefined) return;
        const device = devices.find((d) => d.id === data.device_id);
        if (!device) return;
        device.status = data.status;
        device.latest_response_time = data.response_time;
        if (data.response_time !== null && data.response_time !== undefined) device.last_seen = data.timestamp;
        const card = $('smart-devices-grid').querySelector(`.device-card[data-device-id="${device.id}"]`);
        if (card) card.outerHTML = createDeviceCard(device);
    }

    // ------------------------------------------------------------------ socket
    function initSocket() {
        if (typeof io === 'undefined') return;
        socket = io();
        socket.on('connect', function () {
            // Server pushes go to rooms; nothing arrives until the page joins them.
            socket.emit('subscribe_to_updates', { types: ['device_status', 'monitoring_summary', 'alerts'] });
            if (typeof updateConnectionStatus === 'function') updateConnectionStatus(true);
        });
        socket.on('disconnect', function () {
            if (typeof updateConnectionStatus === 'function') updateConnectionStatus(false);
        });
        socket.on('garage_status', function (data) {
            const previous = garage && garage.last_event ? garage.last_event.id : null;
            applyGarage(data);
            if (data && data.last_event && data.last_event.id !== previous) reloadHistory();
        });
        socket.on('device_status_update', handleDeviceStatusUpdate);
        socket.on('alert_update', reloadHistory);
    }

    // ------------------------------------------------------------------ init
    document.addEventListener('DOMContentLoaded', function () {
        bindHold($('garage-primary-action'), doorAction);
        $('garage-stop-action').addEventListener('click', () => doorAction('stop'));
        $('garage-light-toggle').addEventListener('change', (e) => lightAction(e.target.checked));
        $('garage-lock-toggle').addEventListener('change', (e) => lockAction(e.target.checked));

        loadGarage();
        loadHistory();
        loadSmartDevices();
        initSocket();

        setInterval(tickOpenFor, 1000);
        setInterval(loadGarage, 60000);                 // fallback when the socket is quiet
        setInterval(loadSmartDevices, 120000);
        new MutationObserver(() => { if (lastDaily.length) renderChart(lastDaily); })
            .observe(document.documentElement, { attributes: true, attributeFilter: ['data-bs-theme'] });
    });
})();
