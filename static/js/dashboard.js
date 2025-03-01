// Initialize Socket.IO connection
const socket = io();

// Charts and data storage
let protocolChart = null;
let packetRateChart = null;
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
});

socket.on('threat_detected', (threat) => {
    addThreat(threat);
    addActivityLog(`Threat detected: ${threat.type} from ${threat.source}`);
});

socket.on('packet_processed', (packet) => {
    addActivityLog(`Processed ${packet.protocol} packet: ${packet.src_ip} -> ${packet.dst_ip}`);
});

// Update functions
function updateTrafficStats(stats) {
    document.getElementById('total-packets').textContent = stats.general.total_packets;
    document.getElementById('packets-per-second').textContent = 
        stats.general.packets_per_second.toFixed(2);
    document.getElementById('total-bytes').textContent = formatBytes(stats.general.total_bytes);
}

function updateProtocolChart(protocols) {
    const data = [{
        values: Object.values(protocols),
        labels: Object.keys(protocols),
        type: 'pie'
    }];
    
    const layout = {
        height: 300,
        margin: { t: 0, b: 0, l: 0, r: 0 }
    };

    Plotly.newPlot('protocol-chart', data, layout);
}

function updatePacketRateChart(rates) {
    const data = [{
        y: rates,
        type: 'line',
        name: 'Packets/s'
    }];
    
    const layout = {
        height: 300,
        margin: { t: 0, b: 30, l: 30, r: 10 },
        yaxis: { title: 'Packets/s' }
    };

    Plotly.newPlot('packet-rate-chart', data, layout);
}

function updateTopIPs(ips) {
    const container = document.getElementById('top-ips');
    container.innerHTML = Object.entries(ips)
        .map(([ip, count]) => `<div>${ip}: ${count} packets</div>`)
        .join('');
}

function addThreat(threat) {
    const container = document.getElementById('threats-list');
    const threatElement = document.createElement('div');
    threatElement.className = 'threat-item';
    threatElement.innerHTML = `
        <strong>${threat.type}</strong><br>
        Source: ${threat.source}<br>
        Details: ${threat.details}
    `;
    container.insertBefore(threatElement, container.firstChild);

    // Keep only last 100 threats
    if (container.children.length > 100) {
        container.removeChild(container.lastChild);
    }
}

function addActivityLog(message) {
    const container = document.getElementById('activity-log');
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    logEntry.textContent = `${new Date().toLocaleTimeString()} - ${message}`;
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
