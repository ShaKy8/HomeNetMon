# Interactive Charts System Documentation

## Overview

The HomeNetMon interactive charts system provides advanced chart interactivity including click-to-drill-down navigation, cross-chart filtering, and real-time WebSocket-driven updates. This system enhances user experience by enabling seamless navigation between different data views and maintaining synchronized state across all charts.

## Architecture

### Core Components

1. **GlobalFilters** - Centralized state management for cross-chart filtering
2. **ChartNavigation** - Device navigation and drill-down functionality
3. **ChartInteractionHandlers** - Chart-specific interaction logic
4. **ChartUpdateManager** - Real-time chart updates via WebSocket
5. **ChartConfigFactory** - Enhanced chart configuration with interaction support

## Implementation Guide

### 1. GlobalFilters System

The GlobalFilters object manages filter state across all charts and dashboards:

```javascript
const GlobalFilters = {
    deviceType: null,
    timeRange: '24h',
    severity: null,
    location: null,
    deviceId: null,
    
    updateFilter: function(key, value) {
        this[key] = value;
        this.notifyChartFilters();
        this.updateURL();
    },
    
    notifyChartFilters: function() {
        const event = new CustomEvent('globalFiltersChanged', {
            detail: { filters: { ...this } }
        });
        document.dispatchEvent(event);
    }
};
```

**Key Features:**
- Automatic URL synchronization
- Event-driven filter updates
- Browser history support
- Cross-dashboard persistence

### 2. Chart Navigation

Enable device navigation and drill-down functionality:

```javascript
const ChartNavigation = {
    navigateToDevice: function(deviceId, options = {}) {
        const url = `/device/${deviceId}`;
        const params = new URLSearchParams();
        
        if (options.timeRange) params.set('timeRange', options.timeRange);
        if (options.metric) params.set('metric', options.metric);
        
        const fullUrl = params.toString() ? `${url}?${params}` : url;
        
        if (options.newTab) {
            window.open(fullUrl, '_blank');
        } else {
            window.location.href = fullUrl;
        }
    }
};
```

### 3. Interactive Chart Configuration

Create interactive charts using the enhanced ChartConfigFactory:

```javascript
// Response Time Chart with Navigation
const chartConfig = ChartConfigFactory.createLineConfig({
    interactionType: 'navigation',
    data: {
        labels: timestamps,
        datasets: [{
            label: 'Response Time (ms)',
            data: responseTimeData,
            borderColor: CHART_COLORS.primary,
            backgroundColor: CHART_COLORS.primary + '20',
            timestamps: timestamps,
            deviceId: deviceId
        }]
    }
});

// Device Types Chart with Filtering
const pieConfig = ChartConfigFactory.createPieConfig({
    interactionType: 'filter',
    data: {
        labels: deviceTypes,
        datasets: [{
            data: deviceCounts,
            backgroundColor: colors,
            deviceTypes: deviceTypes
        }]
    }
});
```

### 4. Real-time Updates

Register charts for real-time updates:

```javascript
// Register chart for updates
ChartUpdateManager.registerChart('responseTimeChart', {
    chart: chartInstance,
    type: 'device_response_time',
    deviceId: deviceId,
    updateHandler: function(data) {
        // Update chart with new data
        this.chart.data.labels = data.labels;
        this.chart.data.datasets[0].data = data.values;
        this.chart.update('none');
    }
});

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    ChartUpdateManager.unregisterChart('responseTimeChart');
});
```

## Chart Interaction Types

### Navigation Interactions
- **Purpose**: Navigate to device detail pages
- **Trigger**: Click on chart data points
- **Behavior**: Opens device detail page with context
- **Visual Feedback**: Cursor changes to pointer, hover highlights

```javascript
// Example: Response time chart click handler
onClick: function(event, elements) {
    if (elements.length > 0) {
        const element = elements[0];
        const dataset = this.data.datasets[element.datasetIndex];
        const deviceId = dataset.deviceId;
        
        ChartNavigation.navigateToDevice(deviceId, {
            timeRange: GlobalFilters.timeRange,
            metric: 'response_time'
        });
    }
}
```

### Filter Interactions
- **Purpose**: Apply filters across all charts
- **Trigger**: Click on chart segments/data points
- **Behavior**: Updates global filters and refreshes all charts
- **Visual Feedback**: Active filter badges, chart highlighting

```javascript
// Example: Device types pie chart click handler
onClick: function(event, elements) {
    if (elements.length > 0) {
        const element = elements[0];
        const deviceType = this.data.labels[element.index];
        
        GlobalFilters.updateFilter('deviceType', deviceType);
        showFilterMessage(`Filtered by device type: ${deviceType}`);
    }
}
```

### Performance Interactions
- **Purpose**: Display detailed performance metrics
- **Trigger**: Click on performance chart elements
- **Behavior**: Shows modal with detailed metrics
- **Visual Feedback**: Modal overlay, detailed statistics

## WebSocket Events

### Outgoing Events (Client → Server)

```javascript
// Request specific chart data
socket.emit('request_chart_data', {
    type: 'device_response_time',
    device_id: deviceId,
    time_range: '24h'
});
```

### Incoming Events (Server → Client)

```javascript
// Automatic chart data updates
socket.on('chart_data_update', function(data) {
    if (data.type === 'device_types') {
        ChartUpdateManager.updateChartsByType('device_types', data.data);
    }
});

// Requested chart data response
socket.on('chart_data_response', function(data) {
    ChartUpdateManager.handleChartDataResponse(data);
});
```

## CSS Visual Feedback

### Interactive Chart Containers

```css
.chart-container.interactive {
    position: relative;
    transition: all 0.2s ease;
}

.chart-container.interactive:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,123,255,0.15);
}

.chart-interaction-hint {
    position: absolute;
    top: 10px;
    right: 10px;
    background: rgba(0,123,255,0.9);
    color: white;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
    opacity: 0;
    transition: opacity 0.2s;
}

.chart-container.interactive:hover .chart-interaction-hint {
    opacity: 1;
}
```

### Update Indicators

```css
.chart-update-indicator {
    position: absolute;
    top: 5px;
    left: 5px;
    width: 8px;
    height: 8px;
    background: #28a745;
    border-radius: 50%;
    opacity: 0;
    animation: pulse 1s ease-in-out;
}

@keyframes pulse {
    0%, 100% { opacity: 0; transform: scale(1); }
    50% { opacity: 1; transform: scale(1.2); }
}
```

## Best Practices

### 1. Chart Registration
- Always register charts that need real-time updates
- Unregister charts when components are destroyed
- Use unique chart IDs across the application

### 2. Error Handling
- Implement fallback behavior for WebSocket disconnections
- Gracefully handle malformed chart data
- Provide user feedback for interaction failures

### 3. Performance Optimization
- Limit real-time update frequency (throttling)
- Use sliding window data for continuous charts
- Implement chart pause/resume for inactive tabs

### 4. Accessibility
- Provide keyboard navigation for chart interactions
- Add ARIA labels for screen readers
- Ensure sufficient color contrast for chart elements

## Example Implementation

### Complete Interactive Device Response Time Chart

```javascript
function createInteractiveResponseTimeChart(deviceId, containerId) {
    const ctx = document.getElementById(containerId).getContext('2d');
    
    // Mark container as interactive
    ctx.canvas.parentElement.classList.add('interactive');
    
    // Add interaction hint
    const hint = document.createElement('div');
    hint.className = 'chart-interaction-hint';
    hint.textContent = 'Click to navigate';
    ctx.canvas.parentElement.appendChild(hint);
    
    // Create chart configuration
    const config = ChartConfigFactory.createLineConfig({
        interactionType: 'navigation',
        data: await loadDeviceData(deviceId),
        options: {
            responsive: true,
            scales: {
                y: { beginAtZero: true, title: { display: true, text: 'Response Time (ms)' }}
            }
        }
    });
    
    // Create chart instance
    const chart = new Chart(ctx, config);
    
    // Register for real-time updates
    ChartUpdateManager.registerChart(`responseTime_${deviceId}`, {
        chart: chart,
        type: 'device_response_time',
        deviceId: deviceId,
        updateHandler: function(data) {
            // Sliding window update
            const maxPoints = 50;
            this.chart.data.labels = data.labels.slice(-maxPoints);
            this.chart.data.datasets[0].data = data.values.slice(-maxPoints);
            this.chart.update('none');
            
            // Show update indicator
            showUpdateIndicator(ctx.canvas.parentElement);
        }
    });
    
    // Listen for global filter changes
    document.addEventListener('globalFiltersChanged', function(event) {
        const filters = event.detail.filters;
        if (filters.timeRange !== chart.currentTimeRange) {
            chart.currentTimeRange = filters.timeRange;
            refreshChartData(chart, deviceId, filters.timeRange);
        }
    });
    
    return chart;
}
```

## Troubleshooting

### Common Issues

1. **Charts not updating in real-time**
   - Check WebSocket connection status
   - Verify chart registration with correct type
   - Ensure update handler is properly implemented

2. **Filter changes not propagating**
   - Verify GlobalFilters event listeners are attached
   - Check for JavaScript errors preventing event dispatch
   - Ensure filter keys match expected values

3. **Navigation not working**
   - Check device ID is properly passed to click handlers
   - Verify URL construction in ChartNavigation methods
   - Ensure route exists for target pages

### Debug Mode

Enable debug logging for the interactive chart system:

```javascript
// Enable debug mode
ChartUpdateManager.debugMode = true;
GlobalFilters.debugMode = true;

// Check chart registrations
console.log('Registered charts:', ChartUpdateManager.getRegisteredCharts());

// Monitor filter changes
GlobalFilters.on('filterChanged', (key, value) => {
    console.log(`Filter changed: ${key} = ${value}`);
});
```

This comprehensive interactive charts system provides a modern, responsive, and feature-rich charting experience that enhances the HomeNetMon dashboard's usability and user engagement.