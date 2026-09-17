/* Smart Home page controller.
 *   garage door : GET /api/garage (state read from the Ring camera), POST /api/garage/check, GET /api/garage/history,
 *                 GET /api/garage/snapshot.jpg (latest frame; ?event=<id> for a door event's frame)
 *   live updates: Socket.IO room updates_monitoring_summary -> garage_status; updates_device_status -> device_status_update
 *   devices     : GET /api/devices filtered to the smart-home types, rendered with createDeviceCard (device-cards.js)
 * Shared helpers (apiRequest, showSuccess, showError, escapeHtml, debounce) come from ui-feedback.js;
 * csrf-handler.js adds the CSRF header to every POST. Every string from the camera, the model or the LAN is escaped.
 */
(function () {
    'use strict';

    const esc = (v) => (window.escapeHtml ? window.escapeHtml(v) : String(v == null ? '' : v));
    const SMART_TYPES = ['smart_home', 'iot', 'media', 'speaker', 'tv', 'thermostat', 'sensor'];
    const OPEN_STATES = ['open'];

    let socket = null;
    let garage = null;                  // last /api/garage document
    let chart = null;
    let devices = [];
    let shownSnapshot = null;           // taken_at of the frame currently displayed
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

    function effectiveState(d) {
        if (!d.enabled || !d.camera || !d.camera.id) return 'unconfigured';
        if (!d.ring || !d.ring.signed_in) return 'signed_out';
        if (d.online === false) return 'offline';
        return d.door || 'unknown';
    }

    function applyGarage(data) {
        if (!data) return;
        garage = data;
        const card = $('garage-card');
        const state = effectiveState(data);
        card.dataset.state = state;

        const setup = state === 'unconfigured' || state === 'signed_out';
        $('garage-hero-body').hidden = setup;
        $('garage-empty').hidden = !setup;
        if (setup) {
            $('garage-empty-title').textContent = state === 'signed_out' ? 'Sign in to Ring to see the garage' : 'No garage camera configured';
            $('garage-empty-text').textContent = state === 'signed_out'
                ? 'The garage camera is set up but Ring needs a sign-in (the token expired or was cleared). Sign in again in Settings.'
                : 'HomeNetMon reads the door state from your Ring garage camera: sign in to Ring in Settings, pick the camera, and Claude reads each new frame.';
        }

        const note = $('garage-offline-note');
        if (state === 'offline') {
            note.textContent = `The garage camera is not answering (${data.consecutive_failures || 0} checks in a row failed` +
                (data.last_error ? `: ${data.last_error}` : '') + '). The door state shown is the last one read.';
            note.hidden = false;
        } else if (data.enabled && data.vision && data.vision.api_key_set === false) {
            note.textContent = 'ANTHROPIC_API_KEY is not set in .env, so frames are fetched but never read. Add the key and restart the service.';
            note.hidden = false;
        } else {
            note.hidden = true;
        }

        const stateEl = $('garage-door-state');
        const labels = { closed: 'Closed', open: 'Open', unknown: 'Not read yet', offline: 'Camera unavailable' };
        stateEl.textContent = labels[state] || state;
        stateEl.className = 'garage-state ' + (
            state === 'closed' ? 'garage-state-closed' :
            OPEN_STATES.includes(state) ? 'garage-state-open' :
            'garage-state-offline');
        tickOpenFor();

        const reading = data.reading || null;
        const confidence = $('garage-confidence');
        if (reading && reading.state !== 'unknown') {
            confidence.textContent = `${Math.round((reading.confidence || 0) * 100)}% sure`;
            confidence.className = 'badge-chip ' + (reading.confidence >= 0.85 ? 'good' : reading.confidence >= 0.6 ? 'info' : 'warn');
            confidence.hidden = false;
        } else {
            confidence.hidden = true;
        }
        $('garage-reason').textContent = reading && reading.reason ? reading.reason : '';
        $('garage-night').hidden = !(reading && reading.night);

        refreshSnapshot(data.snapshot || {}, state);

        const usable = !setup;
        $('garage-check-now').disabled = !usable;
        if (setup) setLive('Not configured', '');
        else if (state === 'offline') setLive('Offline', 'warn');
        else setLive(liveText(data), data.snapshot && data.snapshot.has_frame ? 'live' : '');

        const cam = data.camera || {};
        const camBits = [cam.name ? `Ring camera ${cam.name}` : null, cam.model,
                         cam.battery_life != null ? `battery ${cam.battery_life}%` : (cam.is_battery ? 'battery' : null),
                         cam.wifi != null ? `Wi-Fi ${cam.wifi} dBm` : null].filter(Boolean);
        $('garage-camera-line').textContent = camBits.join(' · ');
        const v = data.vision || {};
        const visionBits = [v.model, `${v.checks_today || 0} reading${v.checks_today === 1 ? '' : 's'} today`,
                            v.est_cost_today_usd != null ? `~$${Number(v.est_cost_today_usd).toFixed(2)}` : null,
                            data.check_interval ? `checks every ${Math.round(data.check_interval / 60)} min${data.motion_checks ? ' and after motion' : ''}` : null]
            .filter(Boolean);
        $('garage-vision-line').textContent = visionBits.join(' · ');
        $('garage-last-event').textContent = data.last_event
            ? `Last: ${describeEvent(data.last_event)} at ${fmtTime(data.last_event.timestamp, true)}` : '';
    }

    function liveText(d) {
        const s = d.snapshot || {};
        const bits = [];
        if (s.age_seconds != null) bits.push(`frame ${humanAge(s.age_seconds)} old`);
        if (d.next_check_at) {
            const secs = Math.max(0, (Date.parse(d.next_check_at) - Date.now()) / 1000);
            bits.push(secs < 90 ? 'next check in under 2 min' : `next check in ${Math.round(secs / 60)} min`);
        }
        return bits.length ? bits.join(' · ') : 'Waiting for the first frame';
    }

    function humanAge(seconds) {
        const s = Math.max(0, Math.round(seconds));
        if (s < 60) return `${s}s`;
        if (s < 3600) return `${Math.round(s / 60)} min`;
        return `${(s / 3600).toFixed(1)} h`;
    }

    function refreshSnapshot(snapshot, state) {
        const img = $('garage-snapshot');
        const empty = $('garage-snapshot-empty');
        const frame = $('garage-frame');
        if (!snapshot.has_frame) {
            img.hidden = true;
            empty.hidden = false;
            $('garage-snapshot-age').textContent = '';
            return;
        }
        if (snapshot.taken_at !== shownSnapshot) {
            shownSnapshot = snapshot.taken_at;
            img.src = '/api/garage/snapshot.jpg?t=' + encodeURIComponent(snapshot.taken_at || Date.now());
        }
        img.hidden = false;
        empty.hidden = true;
        frame.classList.toggle('stale', snapshot.age_seconds != null && snapshot.age_seconds > 3600);
        const when = snapshot.taken_at ? `Frame taken ${fmtTime(snapshot.taken_at, true)}` : 'Frame';
        const age = snapshot.age_seconds != null ? ` (${humanAge(snapshot.age_seconds)} ago)` : '';
        const read = snapshot.classified_at ? ` · read ${fmtTime(snapshot.classified_at, true)}` : ' · not read yet';
        $('garage-snapshot-age').textContent = `${when}${age}${state === 'offline' ? '' : read}`;
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

    // ------------------------------------------------------------------ check now
    async function checkNow() {
        const button = $('garage-check-now');
        const icon = $('garage-check-icon');
        button.classList.add('checking');
        icon.classList.add('spin');
        try {
            const result = await apiRequest('/api/garage/check', { method: 'POST', body: {} });
            if (result.state) applyGarage(result.state);
            const r = result.state && result.state.reading;
            showSuccess(r && r.state !== 'unknown' ? `Door read as ${r.state} (${Math.round((r.confidence || 0) * 100)}% sure)` : 'Checked; no new frame from the camera yet');
            reloadHistory();
        } catch (error) {
            showError(`Check failed: ${error.message}`);
            loadGarage();
        } finally {
            button.classList.remove('checking');
            icon.classList.remove('spin');
        }
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

    const EVENT_ICONS = { door: 'bi-door-open', online: 'bi-camera-video' };

    function describeEvent(e) {
        if (e.kind === 'door') {
            const words = { open: 'Opened', closed: 'Closed', unknown: 'State unknown' };
            let text = words[e.value] || e.value;
            if (e.value === 'closed' && e.duration_s != null) text += ` after ${formatDuration(e.duration_s)} open`;
            return e.source === 'camera' && e.value !== 'unknown' ? `${text} (seen by camera)` : text;
        }
        if (e.kind === 'online') return e.value === 'online' ? 'Camera reachable again' : 'Camera unavailable';
        return `${e.kind} ${e.value}`;
    }

    function fmtTime(iso, withDate) {
        const d = new Date(iso);
        if (Number.isNaN(d.getTime())) return '';
        const today = new Date();
        const sameDay = d.toDateString() === today.toDateString();
        const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
        if (sameDay || !withDate) return time;
        return `${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} ${time}`;
    }

    function renderEvents(events) {
        const list = $('garage-events');
        if (!events.length) {
            list.innerHTML = '<li class="event-empty">No door activity recorded yet</li>';
            return;
        }
        list.innerHTML = events.slice(0, 25).map((e) => {
            const thumb = e.kind === 'door' && /^event-\d+\.jpg$/.test(e.detail || '') && Number.isInteger(e.id)
                ? `<span class="event-thumb"><img src="/api/garage/snapshot.jpg?event=${e.id}" alt="" loading="lazy"></span>` : '';
            return `
            <li>
                <span class="event-time">${esc(fmtTime(e.timestamp, true))}</span>
                <span class="event-icon"><i class="bi ${EVENT_ICONS[e.kind] || 'bi-dot'}"></i></span>
                <span class="event-text">${esc(describeEvent(e))}</span>
                ${thumb}
            </li>`;
        }).join('');
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
        $('garage-check-now').addEventListener('click', checkNow);

        loadGarage();
        loadHistory();
        loadSmartDevices();
        initSocket();

        setInterval(tickOpenFor, 1000);
        setInterval(function () { if (garage) setLive(liveText(garage), garage.snapshot && garage.snapshot.has_frame ? 'live' : ''); }, 30000);
        setInterval(loadGarage, 60000);                 // fallback when the socket is quiet
        setInterval(loadSmartDevices, 120000);
        new MutationObserver(() => { if (lastDaily.length) renderChart(lastDaily); })
            .observe(document.documentElement, { attributes: true, attributeFilter: ['data-bs-theme'] });
    });
})();
