// Initialize Socket.IO connection
const socket = io();

// Charts and data storage
let protocolChart = null;
let packetRateChart = null;
let connectionHeatmap = null;
let attackPatternChart = null;
let recentThreats = [];

// Initialize dashboard with loading states
document.addEventListener('DOMContentLoaded', () => {
    // Show loading states
    document.querySelectorAll('.chart-container').forEach(container => {
        container.innerHTML = '<div class="loading">Loading data...</div>';
    });

    // Fetch initial data
    fetch('/api/initial-stats')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            // Initialize all charts with initial data
            updateTrafficStats(data);
            updateProtocolChart(data.protocols);
            updatePacketRateChart(data.packet_rates);
            updateTopIPs(data.top_ips);
            updateConnectionHeatmap(data.connections);
            updateAttackPatterns(data.attacks);
        })
        .catch(error => {
            console.error('Error loading initial data:', error);
            document.querySelectorAll('.chart-container').forEach(container => {
                container.innerHTML = '<div class="error">Failed to load data. Retrying...</div>';
            });
        });

    // Initialize threshold controls
    initializeControls();

    // Handle window resize for charts
    window.addEventListener('resize', debounce(handleResize, 250));
});

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
    if (!stats.general) return;

    const elements = {
        'total-packets': stats.general.total_packets,
        'packets-per-second': stats.general.packets_per_second.toFixed(2),
        'total-bytes': formatBytes(stats.general.total_bytes),
        'unique-ips': stats.general.unique_ips || 0,
        'avg-packet-size': formatBytes(stats.general.avg_packet_size || 0)
    };

    Object.entries(elements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element && element.textContent !== value.toString()) {
            element.classList.add('updating');
            element.textContent = value;
            setTimeout(() => element.classList.remove('updating'), 500);
        }
    });
}

function updateProtocolChart(protocols) {
    if (!protocols) return;

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
        },
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: {
            color: '#ffffff'
        }
    };

    const config = {
        responsive: true,
        displayModeBar: false
    };

    const container = document.getElementById('protocol-chart');
    if (container) {
        layout.height = container.clientHeight;
        Plotly.newPlot('protocol-chart', data, layout, config);
    }
}

function updateConnectionHeatmap(connections) {
    if (!connections || !connections.counts || !connections.counts.length) return;

    const data = [{
        x: connections.dst_ips,
        y: connections.src_ips,
        z: connections.counts,
        type: 'heatmap',
        colorscale: 'Viridis'
    }];

    const layout = {
        title: 'Connection Heatmap',
        margin: { t: 30, b: 40, l: 100, r: 20 },
        xaxis: { title: 'Destination IPs', color: '#ffffff' },
        yaxis: { title: 'Source IPs', color: '#ffffff' },
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: { color: '#ffffff' }
    };

    const config = {
        responsive: true,
        displayModeBar: false
    };

    const container = document.getElementById('connection-heatmap');
    if (container) {
        layout.height = container.clientHeight;
        Plotly.newPlot('connection-heatmap', data, layout, config);
    }
}

function updateAttackPatterns(attacks) {
    const container = document.getElementById('attack-pattern-chart');
    if (!container) return;

    if (!attacks || !attacks.timestamps || !attacks.counts ||
        attacks.timestamps.length === 0 || attacks.counts.length === 0) {
        container.innerHTML = '<div class="no-data">No attack pattern data available</div>';
        return;
    }

    const formattedTimes = attacks.timestamps.map(ts => {
        const date = new Date(ts * 1000);
        return date.toLocaleTimeString();
    });

    const data = [{
        type: 'scatter',
        mode: 'lines+markers',
        x: formattedTimes,
        y: attacks.counts,
        line: { color: '#e74c3c', width: 2 },
        marker: {
            color: '#e74c3c',
            size: 6
        },
        name: 'Attack Events'
    }];

    const layout = {
        title: 'Attack Pattern Timeline',
        margin: { t: 30, b: 40, l: 50, r: 20 },
        height: container.clientHeight,
        xaxis: {
            title: 'Time',
            color: '#ffffff',
            showgrid: true,
            gridcolor: 'rgba(255, 255, 255, 0.1)'
        },
        yaxis: {
            title: 'Attack Count',
            color: '#ffffff',
            showgrid: true,
            gridcolor: 'rgba(255, 255, 255, 0.1)'
        },
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: { color: '#ffffff' }
    };

    const config = {
        responsive: true,
        displayModeBar: false
    };

    Plotly.newPlot('attack-pattern-chart', data, layout, config);
}

function updatePacketRateChart(rates) {
    if (!rates) return;

    const data = [{
        y: rates,
        type: 'line',
        name: 'Packets/s',
        line: { color: '#2ecc71' }
    }];

    const layout = {
        margin: { t: 0, b: 30, l: 30, r: 10 },
        yaxis: { title: 'Packets/s', color: '#ffffff' },
        xaxis: { title: 'Time (last 60 seconds)', color: '#ffffff' },
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: { color: '#ffffff' }
    };

    const config = {
        responsive: true,
        displayModeBar: false
    };

    const container = document.getElementById('packet-rate-chart');
    if (container) {
        layout.height = container.clientHeight;
        Plotly.newPlot('packet-rate-chart', data, layout, config);
    }
}

function updateTopIPs(ips) {
    const container = document.getElementById('top-ips');
    if (!container || !ips) return;

    const maxCount = Math.max(...Object.values(ips));
    container.innerHTML = Object.entries(ips)
        .map(([ip, count]) => `
            <div class="ip-entry">
                <div class="progress-bar" style="width: ${(count / maxCount * 100)}%"></div>
                <span class="ip-address">${ip}</span>
                <span class="packet-count">${count} packets</span>
            </div>
        `)
        .join('');
}

async function generatePDFReport() {
    const spinner = document.getElementById('loadingSpinner');
    spinner.style.display = 'block';

    try {
        const response = await fetch('/generate_report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                timestamp: new Date().toISOString()
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security_report_${new Date().toISOString().split('T')[0]}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } catch (error) {
        console.error('Error generating PDF report:', error);
        alert('Failed to generate PDF report. Please try again.');
    } finally {
        spinner.style.display = 'none';
    }
}

// Helper functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function handleResize() {
    const charts = [
        { id: 'connection-heatmap', data: connectionHeatmap?.data },
        { id: 'attack-pattern-chart', data: attackPatternChart?.data },
        { id: 'packet-rate-chart', data: packetRateChart?.data },
        { id: 'protocol-chart', data: protocolChart?.data }
    ];

    charts.forEach(({ id, data }) => {
        const container = document.getElementById(id);
        if (container && data) {
            const layout = { height: container.clientHeight };
            Plotly.relayout(id, layout);
        }
    });
}

function initializeControls() {
    // Initialize PDF report download
    const downloadButton = document.getElementById('downloadReport');
    if (downloadButton) {
        downloadButton.addEventListener('click', generatePDFReport);
    }

    // Initialize threat filters
    initializeFilters();
}

function initializeFilters() {
    const filterControls = document.querySelectorAll('.filter-control');
    filterControls.forEach(control => {
        control.addEventListener('change', applyFilters);
    });
}

function applyFilters() {
    const severityFilter = document.querySelector('#severity-filter')?.value;
    const categoryFilter = document.querySelector('#category-filter')?.value;
    const sourceFilter = document.querySelector('#source-filter')?.value;
    const timeFilter = document.querySelector('#time-filter')?.value;

    const threats = document.querySelectorAll('.threat-item');
    threats.forEach(threat => {
        let show = true;

        if (severityFilter && !threat.classList.contains(severityFilter)) {
            show = false;
        }
        if (categoryFilter && !threat.classList.contains(categoryFilter)) {
            show = false;
        }
        if (sourceFilter) {
            const sourceText = threat.querySelector('.threat-details')?.textContent;
            if (!sourceText?.includes(sourceFilter)) {
                show = false;
            }
        }
        if (timeFilter) {
            const threatTime = new Date(threat.querySelector('.threat-time')?.textContent);
            const filterTime = new Date();
            filterTime.setHours(filterTime.getHours() - parseInt(timeFilter));
            if (threatTime < filterTime) {
                show = false;
            }
        }

        threat.style.display = show ? 'block' : 'none';
    });
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

function updateRealTimeMetrics(packet) {
    // Update performance metrics
    const lossElement = document.getElementById('packet-loss');
    const latencyElement = document.getElementById('network-latency');
    const bandwidthElement = document.getElementById('bandwidth-usage');

    if (lossElement && packet.performance) {
        lossElement.textContent = `${packet.performance.loss.toFixed(2)}%`;
        latencyElement.textContent = `${packet.performance.latency.toFixed(2)}ms`;
        bandwidthElement.textContent = `${packet.performance.bandwidth.toFixed(2)} Mbps`;
    }
}

function playAlertSound(severity) {
    const audio = new Audio(`/static/sounds/${severity}-alert.mp3`);
    audio.play().catch(e => console.log('Audio playback failed:', e));
}