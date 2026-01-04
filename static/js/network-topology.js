/**
 * HomeNetMon Network Topology Visualization
 * Uses D3.js to create interactive network topology diagrams
 */

// Network topology state
window.NetworkTopology = {
    svg: null,
    simulation: null,
    nodes: [],
    links: [],
    width: 800,
    height: 600,
    initialized: false
};

/**
 * Initialize network topology visualization
 */
function initializeNetworkTopology() {
    const container = document.getElementById('network-topology');
    if (!container || NetworkTopology.initialized) return;
    
    
    if (typeof d3 === 'undefined') {
        container.innerHTML = '<div class="alert alert-warning">Network topology visualization requires D3.js</div>';
        return;
    }
    
    setupTopologyContainer(container);
    loadNetworkData();
    
    NetworkTopology.initialized = true;
}

/**
 * Set up the topology container and SVG
 */
function setupTopologyContainer(container) {
    // Get container dimensions
    const rect = container.getBoundingClientRect();
    NetworkTopology.width = rect.width || 800;
    NetworkTopology.height = rect.height || 600;
    
    // Create SVG
    NetworkTopology.svg = d3.select(container)
        .append('svg')
        .attr('width', NetworkTopology.width)
        .attr('height', NetworkTopology.height)
        .attr('viewBox', [0, 0, NetworkTopology.width, NetworkTopology.height]);
    
    // Add zoom behavior
    const zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on('zoom', function(event) {
            NetworkTopology.svg.select('g').attr('transform', event.transform);
        });
    
    NetworkTopology.svg.call(zoom);
    
    // Create main group for all elements
    const g = NetworkTopology.svg.append('g');
    
    // Add arrow markers for directed links
    NetworkTopology.svg.append('defs')
        .selectAll('marker')
        .data(['end'])
        .enter()
        .append('marker')
        .attr('id', 'arrow')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 20)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('class', 'arrow-marker');
}

/**
 * Load network data from API
 */
function loadNetworkData() {
    if (!window.HomeNetMon || !window.HomeNetMon.apiCall) {
        return;
    }
    
    // Load devices and create topology
    window.HomeNetMon.apiCall('/devices')
        .then(response => {
            if (response.success) {
                createTopologyFromDevices(response.devices);
            }
        })
        .catch(error => {
            showTopologyError('Failed to load network data');
        });
}

/**
 * Create topology visualization from device data
 */
function createTopologyFromDevices(devices) {
    if (!devices || devices.length === 0) {
        showTopologyError('No devices found');
        return;
    }
    
    // Prepare nodes and links
    const nodes = prepareNodes(devices);
    const links = prepareLinks(devices);
    
    // Create force simulation
    createForceSimulation(nodes, links);
    
    // Store data
    NetworkTopology.nodes = nodes;
    NetworkTopology.links = links;
}

/**
 * Prepare nodes from device data
 */
function prepareNodes(devices) {
    return devices.map(device => ({
        id: device.id,
        name: device.display_name || device.hostname || device.ip_address,
        ip: device.ip_address,
        status: device.status,
        device_type: device.device_type,
        response_time: device.latest_response_time,
        isGateway: device.ip_address.endsWith('.1'),
        isServer: device.device_type === 'server' || device.ip_address.endsWith('.100'),
        x: Math.random() * NetworkTopology.width,
        y: Math.random() * NetworkTopology.height
    }));
}

/**
 * Prepare links between devices
 */
function prepareLinks(devices) {
    const links = [];
    const gateway = devices.find(d => d.ip_address.endsWith('.1'));
    
    if (gateway) {
        // Connect all devices to gateway
        devices.forEach(device => {
            if (device.id !== gateway.id) {
                links.push({
                    source: gateway.id,
                    target: device.id,
                    type: 'network'
                });
            }
        });
    }
    
    // Add additional logical connections
    const servers = devices.filter(d => d.device_type === 'server' || d.ip_address.endsWith('.100'));
    const clients = devices.filter(d => !d.ip_address.endsWith('.1') && d.device_type !== 'server');
    
    // Connect servers to some clients (simplified topology)
    servers.forEach(server => {
        const connectedClients = clients.slice(0, Math.min(5, clients.length));
        connectedClients.forEach(client => {
            if (!links.some(l => (l.source === server.id && l.target === client.id) || 
                                 (l.source === client.id && l.target === server.id))) {
                links.push({
                    source: server.id,
                    target: client.id,
                    type: 'service'
                });
            }
        });
    });
    
    return links;
}

/**
 * Create D3 force simulation
 */
function createForceSimulation(nodes, links) {
    // Clear existing elements
    NetworkTopology.svg.select('g').selectAll('*').remove();
    
    const g = NetworkTopology.svg.select('g');
    
    // Create simulation
    NetworkTopology.simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(NetworkTopology.width / 2, NetworkTopology.height / 2))
        .force('collision', d3.forceCollide().radius(30));
    
    // Create links
    const link = g.append('g')
        .attr('class', 'links')
        .selectAll('line')
        .data(links)
        .enter()
        .append('line')
        .attr('class', d => `link link-${d.type}`)
        .attr('marker-end', 'url(#arrow)');
    
    // Create nodes
    const node = g.append('g')
        .attr('class', 'nodes')
        .selectAll('g')
        .data(nodes)
        .enter()
        .append('g')
        .attr('class', 'node')
        .call(d3.drag()
            .on('start', dragStarted)
            .on('drag', dragged)
            .on('end', dragEnded));
    
    // Add circles for nodes
    node.append('circle')
        .attr('r', d => getNodeRadius(d))
        .attr('class', d => `node-circle status-${d.status}`)
        .attr('fill', d => getNodeColor(d));
    
    // Add labels
    node.append('text')
        .attr('dx', 12)
        .attr('dy', '.35em')
        .attr('class', 'node-label')
        .text(d => d.name);
    
    // Add tooltips
    node.append('title')
        .text(d => `${d.name}\n${d.ip}\nStatus: ${d.status}\nResponse: ${d.response_time || 'N/A'}ms`);
    
    // Update positions on simulation tick
    NetworkTopology.simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);
        
        node
            .attr('transform', d => `translate(${d.x},${d.y})`);
    });
    
    // Node click handler
    node.on('click', function(event, d) {
        window.location.href = `/device/${d.id}`;
    });
}

/**
 * Get node radius based on device type
 */
function getNodeRadius(node) {
    if (node.isGateway) return 15;
    if (node.isServer) return 12;
    return 8;
}

/**
 * Get node color based on status
 */
function getNodeColor(node) {
    const colors = {
        'up': '#28a745',
        'down': '#dc3545',
        'warning': '#ffc107',
        'unknown': '#6c757d'
    };
    return colors[node.status] || colors.unknown;
}

/**
 * Drag event handlers
 */
function dragStarted(event, d) {
    if (!event.active) NetworkTopology.simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragEnded(event, d) {
    if (!event.active) NetworkTopology.simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

/**
 * Update topology with new data
 */
function updateTopology(devices) {
    if (!NetworkTopology.initialized || !devices) return;
    
    // Update node statuses
    NetworkTopology.nodes.forEach(node => {
        const device = devices.find(d => d.id === node.id);
        if (device) {
            node.status = device.status;
            node.response_time = device.latest_response_time;
        }
    });
    
    // Update visual elements
    NetworkTopology.svg.selectAll('.node-circle')
        .attr('fill', d => getNodeColor(d))
        .attr('class', d => `node-circle status-${d.status}`);
    
    NetworkTopology.svg.selectAll('.node title')
        .text(d => `${d.name}\n${d.ip}\nStatus: ${d.status}\nResponse: ${d.response_time || 'N/A'}ms`);
}

/**
 * Show topology error message
 */
function showTopologyError(message) {
    const container = document.getElementById('network-topology');
    if (container) {
        container.innerHTML = `<div class="alert alert-danger">${message}</div>`;
    }
}

/**
 * Refresh topology data
 */
function refreshTopology() {
    if (NetworkTopology.initialized) {
        loadNetworkData();
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('network-topology')) {
        initializeNetworkTopology();
    }
});

// Listen for device updates
document.addEventListener('device:updated', function(event) {
    if (event.detail && NetworkTopology.initialized) {
        // Update the specific node
        const node = NetworkTopology.nodes.find(n => n.id === event.detail.device_id);
        if (node) {
            node.status = event.detail.status;
            node.response_time = event.detail.response_time;
            
            // Update visual
            NetworkTopology.svg.select(`.node-circle[data-id="${event.detail.device_id}"]`)
                .attr('fill', getNodeColor(node))
                .attr('class', `node-circle status-${node.status}`);
        }
    }
});

// Export functions
window.NetworkTopology.refresh = refreshTopology;
window.NetworkTopology.update = updateTopology;