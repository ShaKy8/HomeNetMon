/* Device card rendering shared by the dashboard (/) and the Smart Home page.
 * Loaded before the page script; exposes the helpers as globals because the
 * page scripts are classic (non-module) scripts. Every LAN-controlled string
 * (names, IPs, tags, groups) goes through escapeHtml from ui-feedback.js. */
(function () {
    const esc = (v) => (window.escapeHtml ? window.escapeHtml(v) : String(v == null ? '' : v));

    function tagChips(device) {
        const tags = Array.isArray(device.tags) ? device.tags : [];
        if (!tags.length) return '';
        return `<div class="device-tags">${tags.map(t => `<span class="badge bg-secondary me-1">${esc(t)}</span>`).join('')}</div>`;
    }

    function groupBadge(device) {
        const bits = [device.device_group, device.room_location].filter(Boolean);
        return bits.length ? `<span class="badge bg-secondary ms-1" title="Group / room">${esc(bits.join(' · '))}</span>` : '';
    }

    // Format last seen timestamp
    function formatLastSeen(timestamp) {
        if (!timestamp) return 'Never';
        const date = new Date(timestamp);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);

        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
        return `${Math.floor(diffMins / 1440)}d ago`;
    }

    // Device actions
    function openDeviceDetails(deviceId) {
        window.location.href = `/device/${deviceId}`;
    }

    // Create device card HTML
    function createDeviceCard(device) {
        const statusClass = device.status || 'unknown';
        const name = device.display_name || device.hostname || 'Unknown Device';
        const lastSeen = formatLastSeen(device.last_seen);
        const responseTime = device.latest_response_time
            ? `${Math.round(device.latest_response_time)}ms`
            : '--';

        return `
            <div class="device-card" data-device-id="${device.id}" onclick="openDeviceDetails(${device.id})">
                <div class="device-name">
                    <span class="status-dot status-${statusClass}"></span>
                    ${esc(name)}${groupBadge(device)}
                </div>
                <div class="device-ip">${esc(device.ip_address)}</div>
                ${tagChips(device)}
                <div class="device-stats">
                    <span><i class="bi bi-lightning"></i> ${responseTime}</span>
                    <span><i class="bi bi-clock"></i> ${lastSeen}</span>
                </div>
            </div>
        `;
    }

    // "mm:ss" under an hour, "h:mm:ss" above, for open-for timers.
    function formatDuration(seconds) {
        const s = Math.max(0, Math.round(Number(seconds) || 0));
        const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), r = s % 60;
        const pad = (n) => String(n).padStart(2, '0');
        return h ? `${h}:${pad(m)}:${pad(r)}` : `${m}:${pad(r)}`;
    }

    window.tagChips = tagChips;
    window.groupBadge = groupBadge;
    window.createDeviceCard = createDeviceCard;
    window.formatLastSeen = formatLastSeen;
    window.openDeviceDetails = openDeviceDetails;
    window.formatDuration = formatDuration;
})();
