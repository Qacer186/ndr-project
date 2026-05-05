// NDR Dashboard - Real-time Statistics

let charts = {};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    console.log('[*] Dashboard initialized');
    loadStats();
    loadAlerts();
    loadBans();
    
    // Refresh every 5 seconds
    setInterval(loadStats, 5000);
    setInterval(loadAlerts, 5000);
    setInterval(loadBans, 10000); // Refresh bans less frequently
});

// Load and display statistics
function loadStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            // Update counters
            document.getElementById('total-alerts').textContent = data.total_alerts;
            document.getElementById('active-bans').textContent = data.active_bans;
            document.getElementById('critical-alerts').textContent = 
                (data.severity_stats && data.severity_stats['CRITICAL']) || 0;
            
            // Top attacker
            if (data.top_ips.length > 0) {
                document.getElementById('top-attacker').textContent = 
                    data.top_ips[0].src_ip + 
                    ' (' + data.top_ips[0].count + ')';
            }
            
            // Update charts
            updateSeverityChart(data.severity_stats);
            updateTypeChart(data.alert_types);
            updateTopIPs(data.top_ips);
        })
        .catch(error => console.error('[ERROR] Failed to load stats:', error));
}

// Load and display recent alerts
function loadAlerts(page = 1) {
    fetch(`/api/alerts?page=${page}&limit=20`)
        .then(response => response.json())
        .then(data => {
            const tbody = document.getElementById('alerts-table');
            tbody.innerHTML = '';
            
            if (data.alerts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No alerts</td></tr>';
                return;
            }
            
            data.alerts.forEach(alert => {
                const row = document.createElement('tr');
                row.className = getSeverityClass(alert.severity_name);
                
                row.innerHTML = `
                    <td><small>${formatTime(alert.timestamp)}</small></td>
                    <td><strong>${alert.alert_type}</strong></td>
                    <td>
                        <span class="badge bg-${getSeverityColor(alert.severity)}">
                            ${alert.severity}
                        </span>
                    </td>
                    <td><code>${alert.src_ip}</code></td>
                    <td>${alert.dest_port || '-'}</td>
                    <td><small>${alert.signature}</small></td>
                `;
                tbody.appendChild(row);
            });
        })
        .catch(error => console.error('[ERROR] Failed to load alerts:', error));
}

// Refresh alerts manually
function refreshAlerts() {
    loadAlerts();
}

// Load and display active bans
function loadBans() {
    fetch('/api/bans')
        .then(response => response.json())
        .then(data => {
            const tbody = document.getElementById('bans-table');
            tbody.innerHTML = '';
            
            if (data.bans.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No active bans</td></tr>';
                return;
            }
            
            data.bans.forEach(ban => {
                const row = document.createElement('tr');
                
                row.innerHTML = `
                    <td><code>${ban.src_ip}</code></td>
                    <td><small>${ban.ban_reason}</small></td>
                    <td><small>${formatTime(ban.ban_start)}</small></td>
                    <td><small>${formatTime(ban.ban_end)}</small></td>
                    <td><span class="badge bg-warning">${ban.alert_count}</span></td>
                    <td>
                        <button class="btn btn-sm btn-outline-danger" 
                                onclick="unbanIP('${ban.src_ip}')">
                            <i class="bi bi-shield-check"></i> Unban
                        </button>
                    </td>
                `;
                tbody.appendChild(row);
            });
        })
        .catch(error => console.error('[ERROR] Failed to load bans:', error));
}

// Unban an IP address
function unbanIP(ip) {
    if (!confirm(`Are you sure you want to unban ${ip}?`)) {
        return;
    }
    
    fetch(`/api/unban/${ip}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert(`Successfully unbanned ${ip}`);
            loadBans(); // Refresh bans list
            loadStats(); // Refresh stats
        } else {
            alert(`Failed to unban ${ip}: ${data.error}`);
        }
    })
    .catch(error => {
        console.error('[ERROR] Failed to unban IP:', error);
        alert(`Error unbanning ${ip}`);
    });
}

// Refresh bans manually
function refreshBans() {
    loadBans();
}

// Update severity chart
function updateSeverityChart(data) {
    const ctx = document.getElementById('severity-chart');
    if (!ctx) return;
    
    const labels = Object.keys(data);
    const values = Object.values(data);
    
    const colors = {
        'INFO': 'rgba(13, 110, 253, 0.8)',      // Blue
        'WARNING': 'rgba(255, 193, 7, 0.8)',    // Yellow
        'CRITICAL': 'rgba(220, 53, 69, 0.8)'    // Red
    };
    
    if (charts.severity) {
        charts.severity.data.labels = labels;
        charts.severity.data.datasets[0].data = values;
        charts.severity.update();
    } else {
        charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: labels.map(l => colors[l])
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { labels: { color: '#fff' } }
                }
            }
        });
    }
}

// Update alert type chart
function updateTypeChart(data) {
    const ctx = document.getElementById('type-chart');
    if (!ctx) return;
    
    const labels = Object.keys(data);
    const values = Object.values(data);
    
    if (charts.types) {
        charts.types.data.labels = labels;
        charts.types.data.datasets[0].data = values;
        charts.types.update();
    } else {
        charts.types = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Count',
                    data: values,
                    backgroundColor: 'rgba(54, 162, 235, 0.8)'
                }]
            },
            options: {
                responsive: true,
                indexAxis: 'y',
                plugins: {
                    legend: { labels: { color: '#fff' } }
                },
                scales: {
                    x: { ticks: { color: '#fff' }, grid: { color: 'rgba(255,255,255,0.1)' } },
                    y: { ticks: { color: '#fff' }, grid: { color: 'rgba(255,255,255,0.1)' } }
                }
            }
        });
    }
}

// Update top IPs table
function updateTopIPs(ips) {
    const tbody = document.getElementById('top-ips-table');
    tbody.innerHTML = '';
    
    if (ips.length === 0) {
        tbody.innerHTML = '<tr><td colspan="2" class="text-center text-muted">No data</td></tr>';
        return;
    }
    
    ips.forEach((ip, index) => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>
                <span class="badge bg-danger">${index + 1}</span>
                <code>${ip.src_ip}</code>
            </td>
            <td><strong>${ip.count}</strong> alerts</td>
        `;
        tbody.appendChild(row);
    });
}

// Refresh alerts manually
function refreshAlerts() {
    loadAlerts();
    loadStats();
}

// Utility functions

function formatTime(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function getSeverityClass(severity) {
    if (severity === 'CRITICAL') return 'table-danger';
    if (severity === 'WARNING') return 'table-warning';
    return '';
}

function getSeverityColor(severity) {
    if (severity === 'CRITICAL') return 'danger';
    if (severity === 'WARNING') return 'warning';
    return 'info';
}
