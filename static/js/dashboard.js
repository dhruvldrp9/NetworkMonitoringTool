// Initialize Socket.IO connection
const socket = io();

// Charts and data storage
let protocolChart = null;
let packetRateChart = null;
let connectionHeatmap = null;
let attackPatternChart = null;
let recentThreats = [];

// Socket event handlers
socket.on('connect', () => {
    document.getElementById('status').className = 'active';
    document.getElementById('status').textContent = 'Connected';
});

socket.on('disconnect', () => {
    document.getElementById('status').className = 'inactive';
    document.getElementById('status').textContent = 'Disconnected';
});

socket.on('stats_update', (data) => {
    updateTrafficStats(data);
    updateProtocolChart(data.protocols);
    updatePacketRateChart(data.packet_rates);
    updateTopIPs(data.top_ips);
    updateConnectionHeatmap(data.connections);
    updateAttackPatterns(data.attacks);
});

socket.on('threat_detected', (threat) => {
    addThreat(threat);
    addActivityLog(`Threat detected: ${threat.type} from ${threat.source}`);
    updateThreatCounter(threat.category, threat.severity);
    playAlertSound(threat.severity);
});

socket.on('packet_processed', (packet) => {
    addActivityLog(`Processed ${packet.protocol} packet: ${packet.src_ip} -> ${packet.dst_ip}`);
    updateRealTimeMetrics(packet);
});

// Update functions
function updateTrafficStats(stats) {
    document.getElementById('total-packets').textContent = stats.general.total_packets;
    document.getElementById('packets-per-second').textContent = 
        stats.general.packets_per_second.toFixed(2);
    document.getElementById('total-bytes').textContent = formatBytes(stats.general.total_bytes);

    // Update additional metrics
    document.getElementById('unique-ips').textContent = stats.general.unique_ips || 0;
    document.getElementById('avg-packet-size').textContent = 
        formatBytes(stats.general.avg_packet_size || 0);
}

function updateProtocolChart(protocols) {
    const data = [{
        values: Object.values(protocols),
        labels: Object.keys(protocols),
        type: 'pie',
        hole: 0.4,
        marker: {
            colors: [
                '#2ecc71', '#3498db', '#9b59b6', 
                '#e74c3c', '#f1c40f', '#1abc9c'
            ]
        }
    }];

    const layout = {
        height: 300,
        margin: { t: 0, b: 0, l: 0, r: 0 },
        showlegend: true,
        legend: {
            orientation: 'h',
            y: -0.2
        }
    };

    Plotly.newPlot('protocol-chart', data, layout);
}

function updateConnectionHeatmap(connections) {
    if (!connections) return;

    const data = [{
        x: connections.dst_ips,
        y: connections.src_ips,
        z: connections.counts,
        type: 'heatmap',
        colorscale: 'Viridis'
    }];

    const layout = {
        height: 400,
        margin: { t: 30, b: 40, l: 100, r: 20 },
        title: 'Connection Heatmap',
        xaxis: { title: 'Destination IPs' },
        yaxis: { title: 'Source IPs' }
    };

    Plotly.newPlot('connection-heatmap', data, layout);
}

function updateAttackPatterns(attacks) {
    if (!attacks) return;

    const data = [{
        type: 'scatter',
        mode: 'lines+markers',
        x: attacks.timestamps,
        y: attacks.counts,
        line: { color: '#e74c3c' },
        name: 'Attack Events'
    }];

    const layout = {
        height: 300,
        margin: { t: 30, b: 40, l: 50, r: 20 },
        title: 'Attack Pattern Timeline',
        xaxis: { title: 'Time' },
        yaxis: { title: 'Attack Count' }
    };

    Plotly.newPlot('attack-pattern-chart', data, layout);
}

function updatePacketRateChart(rates) {
    const data = [{
        y: rates,
        type: 'line',
        name: 'Packets/s',
        line: { color: '#2ecc71' }
    }];

    const layout = {
        height: 300,
        margin: { t: 0, b: 30, l: 30, r: 10 },
        yaxis: { title: 'Packets/s' },
        xaxis: { title: 'Time (last 60 seconds)' }
    };

    Plotly.newPlot('packet-rate-chart', data, layout);
}

function updateTopIPs(ips) {
    const container = document.getElementById('top-ips');
    container.innerHTML = Object.entries(ips)
        .map(([ip, count]) => `
            <div class="ip-entry">
                <span class="ip-address">${ip}</span>
                <span class="packet-count">${count} packets</span>
                <div class="progress-bar" style="width: ${(count / Math.max(...Object.values(ips)) * 100)}%"></div>
            </div>
        `)
        .join('');
}

function addThreat(threat) {
    const container = document.getElementById('threats-list');
    const threatElement = document.createElement('div');
    threatElement.className = `threat-item ${threat.severity} ${threat.category}`;
    threatElement.innerHTML = `
        <div class="threat-header">
            <span class="threat-type">${threat.type}</span>
            <span class="threat-severity ${threat.severity}">${threat.severity}</span>
        </div>
        <div class="threat-details">
            <div>Source: ${threat.source}</div>
            <div>Category: ${threat.category}</div>
            <div>Details: ${threat.details}</div>
            <div class="threat-time">${new Date().toLocaleTimeString()}</div>
        </div>
    `;
    container.insertBefore(threatElement, container.firstChild);

    // Keep only last 100 threats
    if (container.children.length > 100) {
        container.removeChild(container.lastChild);
    }

    // Update threat counter and trigger alert
    updateThreatCounter(threat.category, threat.severity);
}

function updateThreatCounter(category, severity) {
    const counterElement = document.getElementById('threat-counter');
    if (!counterElement.dataset.threats) {
        counterElement.dataset.threats = JSON.stringify({
            total: 0,
            categories: {},
            severities: {}
        });
    }

    const counts = JSON.parse(counterElement.dataset.threats);
    counts.total++;
    counts.categories[category] = (counts.categories[category] || 0) + 1;
    counts.severities[severity] = (counts.severities[severity] || 0) + 1;

    counterElement.dataset.threats = JSON.stringify(counts);

    // Update the display with animated counters
    counterElement.innerHTML = `
        <div class="total-threats">Total Threats: ${counts.total}</div>
        <div class="threat-breakdown">
            ${Object.entries(counts.severities).map(([sev, count]) => 
                `<div class="severity-count ${sev}">
                    ${sev}: <span class="count">${count}</span>
                </div>`
            ).join('')}
        </div>
        <div class="category-breakdown">
            ${Object.entries(counts.categories).map(([cat, count]) =>
                `<div class="category-count ${cat}">
                    ${cat}: <span class="count">${count}</span>
                </div>`
            ).join('')}
        </div>
    `;
}

function addActivityLog(message) {
    const container = document.getElementById('activity-log');
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    logEntry.innerHTML = `
        <span class="log-time">${new Date().toLocaleTimeString()}</span>
        <span class="log-message">${message}</span>
    `;
    container.insertBefore(logEntry, container.firstChild);

    // Keep only last 100 log entries
    if (container.children.length > 100) {
        container.removeChild(container.lastChild);
    }
}

function formatBytes(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex++;
    }
    return `${size.toFixed(2)} ${units[unitIndex]}`;
}

function playAlertSound(severity) {
    const audio = new Audio(`/static/sounds/${severity}-alert.mp3`);
    audio.play().catch(e => console.log('Audio playback failed:', e));
}

// Initialize tooltips and other UI elements
document.addEventListener('DOMContentLoaded', () => {
    // Initialize threshold controls
    const thresholdControls = document.querySelectorAll('.threshold-control');
    thresholdControls.forEach(control => {
        control.addEventListener('change', (e) => {
            const type = e.target.dataset.type;
            const value = e.target.value;
            socket.emit('update_threshold', { type, value });
        });
    });
});

function updateRealTimeMetrics(packet) {
    // Placeholder for updating real-time metrics based on individual packets
    //  This might involve updating counters or other elements on the dashboard.
}