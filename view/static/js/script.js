function formatDate(timestamp) {
    return new Date(timestamp * 1000).toLocaleString();
}

function updateDNSTable() {
    if (window.location.pathname !== '/dns_table') return;
    fetch('/api/get_dns_table')
        .then(response => {
            if (!response.ok) throw new Error(`DNS Table fetch failed: ${response.status}`);
            return response.json();
        })
        .then(data => {
            const tbody = document.querySelector('#dns-table tbody');
            if (tbody) {
                tbody.innerHTML = '';
                for (const [key, expiry] of Object.entries(data)) {
                    const row = `<tr><td>${key}</td><td>${formatDate(expiry)}</td></tr>`;
                    tbody.innerHTML += row;
                }
            }
        })
        .catch(error => console.error('Error updating DNS table:', error));
}

function updateBlockedIPs() {
    if (window.location.pathname !== '/') return;
    fetch('/api/get_blocked_ips')
        .then(response => {
            if (!response.ok) throw new Error(`Blocked IPs fetch failed: ${response.status}`);
            return response.json();
        })
        .then(data => {
            const tbody = document.querySelector('#blocked-ips tbody');
            if (tbody) {
                tbody.innerHTML = '';
                for (const [ip, expiry] of Object.entries(data)) {
                    const row = `<tr><td >${ip}</td><td style="padding-left: 200px;">${formatDate(expiry)}</td></tr>`;
                    tbody.innerHTML += row;
                }
            }
        })
        .catch(error => console.error('Error updating blocked IPs:', error));
}

function updateAllowlistedDomains() {
    if (window.location.pathname !== '/') return;
    fetch('/api/get_allowlisted_domains')
        .then(response => {
            if (!response.ok) throw new Error(`Allowlisted domains fetch failed: ${response.status}`);
            return response.json();
        })
        .then(data => {
            const ul = document.querySelector('#allowlisted-domains');
            if (ul) {
                ul.innerHTML = '';
                data.forEach(domain => {
                    ul.innerHTML += `<li>${domain}</li>`;
                });
            }
        })
        .catch(error => console.error('Error updating allowlisted domains:', error));
}

function updateAllowlistedUsers() {
    if (window.location.pathname !== '/') return;
    fetch('/api/get_allowlisted_users')
        .then(response => {
            if (!response.ok) throw new Error(`Allowlisted users fetch failed: ${response.status}`);
            return response.json();
        })
        .then(data => {
            const ul = document.querySelector('#allowlisted-users');
            if (ul) {
                ul.innerHTML = '';
                data.forEach(ip => {
                    ul.innerHTML += `<li>${ip}</li>`;
                });
            }
        })
        .catch(error => console.error('Error updating allowlisted users:', error));
}

function updateMetrics() {
    if (window.location.pathname !== '/') return;
    fetch('/api/get_metrics')
        .then(response => {
            if (!response.ok) throw new Error(`Metrics fetch failed: ${response.status}`);
            return response.json();
        })
        .then(data => {
            const packetCount = document.querySelector('#packet-count');
            const avgLatency = document.querySelector('#avg-latency');
            const avgCpu = document.querySelector('#avg-cpu');
            const avgMemory = document.querySelector('#avg-memory');
            if (packetCount) packetCount.textContent = data.packet_count;
            if (avgLatency) avgLatency.textContent = data.avg_latency.toFixed(6);
            if (avgCpu) avgCpu.textContent = data.avg_cpu.toFixed(2);
            if (avgMemory) avgMemory.textContent = data.avg_memory.toFixed(2);
        })
        .catch(error => console.error('Error updating metrics:', error));
}

function updateLogs() {
    if (window.location.pathname !== '/logs') return;
    fetch('/api/get_logs')
        .then(response => {
            if (!response.ok) throw new Error(`Logs fetch failed: ${response.status}`);
            return response.json();
        })
        .then(data => {
            const tbody = document.querySelector('#logs-table tbody');
            if (tbody) {
                tbody.innerHTML = '';
                data.forEach(log => {
                    const row = `<tr><td>${formatDate(log.timestamp)}</td><td>${log.message}</td></tr>`;
                    tbody.innerHTML += row;
                });
                // Scroll to bottom
                const container = document.querySelector('.table-container');
                if (container) container.scrollTop = container.scrollHeight;
            }
        })
        .catch(error => console.error('Error updating logs:', error));
}

function updateDetectedIPs() {
    if (window.location.pathname !== '/') return;
    fetch('/api/get_topology')
        .then(response => {
            if (!response.ok) throw new Error(`Topology fetch failed: ${response.status}`);
            return response.json();
        })
        .then(data => {
            console.log('Detected IPs:', data);
            const ul = document.querySelector('#detected-ips');
            if (ul) {
                ul.innerHTML = '';
                data.forEach(device => {
                    const status = device.is_gateway ? 'Gateway' : device.is_attacker ? 'Attacker' : 'Safe';
                    const statusClass = device.is_attacker ? 'attacker-alert' : '';
                    const boxClass = device.is_attacker ? 'attacker-box' : '';
                    ul.innerHTML += `<li class="${boxClass}">${device.ip} (MAC: ${device.mac}, Status: <span class="${statusClass}">${status}</span>)</li>`;
                });
                if (data.length === 0) {
                    ul.innerHTML = '<li>No devices detected</li>';
                }
            }
        })
        .catch(error => console.error('Error updating detected IPs:', error));
    // Poll every 5 seconds for updates
    setTimeout(updateDetectedIPs, 5000);
}

function updateAttackHistory() {
    if (window.location.pathname !== '/attacks') return;
    fetch('/api/get_attack_history')
        .then(response => {
            if (!response.ok) throw new Error(`Attack history fetch failed: ${response.status}`);
            return response.json();
        })
        .then(data => {
            const tbody = document.querySelector('#attacks-table tbody');
            if (tbody) {
                tbody.innerHTML = '';
                data.forEach(attack => {
                    const row = `<tr>
                        <td>${formatDate(attack.timestamp)}</td>
                        <td class="attacker-alert">${attack.attacker_ip}</td>
                        <td>${attack.target_ip}</td>
                        <td>${attack.reason}</td>
                        <td>${formatDate(attack.expires_at)}</td>
                    </tr>`;
                    tbody.innerHTML += row;
                });
            }
        })
        .catch(error => console.error('Error updating attack history:', error));
}


function executeCommand() {
    if (window.location.pathname !== '/') return;
    const command = document.querySelector('#command-select').value;
    const target = document.querySelector('#command-target').value.trim();
    const output = document.querySelector('#command-output');

    if (!target) {
        if (output) output.textContent = 'Please enter a target IP or Domain';
        return;
    }

    if (command === 'block_ip') {
        fetch('/api/block_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: target })
        })
            .then(response => {
                if (!response.ok) throw new Error(`Block IP failed: ${response.status}`);
                return response.json();
            })
            .then(data => {
                if (output) output.textContent = data.message;
                updateBlockedIPs();
            })
            .catch(error => {
                if (output) output.textContent = `Error: ${error.message}`;
                console.error('Error blocking IP:', error);
            });
    } else if (command === 'unblock_ip') {
        fetch('/api/unblock_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: target })
        })
            .then(response => {
                if (!response.ok) throw new Error(`Unblock IP failed: ${response.status}`);
                return response.json();
            })
            .then(data => {
                if (output) output.textContent = data.message;
                updateBlockedIPs();
            })
            .catch(error => {
                if (output) output.textContent = `Error: ${error.message}`;
                console.error('Error unblocking IP:', error);
            });
    } else if (command === 'add_allowlisted_user') {
        fetch('/api/add_allowlisted_user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: target })
        })
            .then(response => {
                if (!response.ok) throw new Error(`Add allowlisted user failed: ${response.status}`);
                return response.json();
            })
            .then(data => {
                if (output) output.textContent = data.message;
                updateAllowlistedUsers();
            })
            .catch(error => {
                if (output) output.textContent = `Error: ${error.message}`;
                console.error('Error adding allowlisted user:', error);
            });
    } else if (command === 'remove_allowlisted_user') {
    fetch('/api/remove_allowlisted_user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: target })
    })
        .then(response => {
            if (!response.ok) throw new Error(`Remove allowlisted user failed: ${response.status}`);
            return response.json();
        })
        .then(data => {
            if (output) output.textContent = data.message;
            updateAllowlistedUsers();
        })
        .catch(error => {
            if (output) output.textContent = `Error: ${error.message}`;
            console.error('Error removing allowlisted user:', error);
        });
    } else if (command === 'add_allowlisted_domain') {
        fetch('/api/add_allowlisted_domain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: target })
        })
            .then(response => {
                if (!response.ok) throw new Error(`Add allowlisted domain failed: ${response.status}`);
                return response.json();
            })
            .then(data => {
                if (output) output.textContent = data.message;
                updateAllowlistedDomains();
            })
            .catch(error => {
                if (output) output.textContent = `Error: ${error.message}`;
                console.error('Error adding allowlisted domain:', error);
            });
    } else if (command === 'remove_allowlisted_domain') {
        fetch('/api/remove_allowlisted_domain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: target })
        })
            .then(response => {
                if (!response.ok) throw new Error(`Remove allowlisted domain failed: ${response.status}`);
                return response.json();
            })
            .then(data => {
                if (output) output.textContent = data.message;
                updateAllowlistedDomains();
            })
            .catch(error => {
                if (output) output.textContent = `Error: ${error.message}`;
                console.error('Error removing allowlisted domain:', error);
            });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('Page loaded:', window.location.pathname);
    const canvas = document.getElementById('network-canvas');

    // Initial updates
    updateAllowlistedDomains();
    updateDetectedIPs();
    updateDNSTable();
    updateBlockedIPs();
    updateAllowlistedUsers();
    updateMetrics();
    updateLogs();
    updateAttackHistory();

    // Periodic updates
    setInterval(() => {
    updateAllowlistedDomains
    updateDetectedIPs();
        updateDNSTable();
        updateBlockedIPs();
        updateAllowlistedUsers();
        updateMetrics();
        updateLogs();
        updateAttackHistory();
    }, 5000);
});