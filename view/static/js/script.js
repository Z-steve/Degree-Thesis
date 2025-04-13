function formatDate(timestamp) {
    return new Date(timestamp * 1000).toLocaleString();
}

function updateDNSTable() {
    fetch('/api/get_dns_table')
        .then(response => response.json())
        .then(data => {
            const tbody = document.querySelector('#dns-table tbody');
            tbody.innerHTML = '';
            for (const [key, expiry] of Object.entries(data)) {
                const row = `<tr><td>${key}</td><td>${formatDate(expiry)}</td></tr>`;
                tbody.innerHTML += row;
            }
        });
}

function updateBlockedIPs() {
    fetch('/api/get_blocked_ips')
        .then(response => response.json())
        .then(data => {
            const tbody = document.querySelector('#blocked-ips tbody');
            tbody.innerHTML = '';
            for (const [ip, expiry] of Object.entries(data)) {
                const row = `<tr><td>${ip}</td><td>${formatDate(expiry)}</td></tr>`;
                tbody.innerHTML += row;
            }
        });
}

function updateAllowlistedUsers() {
    fetch('/api/get_allowlisted_users')
        .then(response => response.json())
        .then(data => {
            const ul = document.querySelector('#allowlisted-users');
            ul.innerHTML = '';
            data.forEach(ip => {
                ul.innerHTML += `<li>${ip}</li>`;
            });
        });
}

function updateMetrics() {
    fetch('/api/get_metrics')
        .then(response => response.json())
        .then(data => {
            document.querySelector('#packet-count').textContent = data.packet_count;
            document.querySelector('#avg-latency').textContent = data.avg_latency.toFixed(6);
            document.querySelector('#avg-cpu').textContent = data.avg_cpu.toFixed(2);
            document.querySelector('#avg-memory').textContent = data.avg_memory.toFixed(2);
        });
}

function executeCommand() {
    const input = document.querySelector('#command-input').value.trim();
    const output = document.querySelector('#command-output');
    if (!input) {
        output.textContent = 'Please enter a command';
        return;
    }

    const [command, ...args] = input.split(' ');
    if (command === 'block_ip' && args.length === 1) {
        fetch('/api/block_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: args[0] })
        })
            .then(response => response.json())
            .then(data => {
                output.textContent = data.message;
                updateBlockedIPs();
            });
    } else if (command === 'unblock_ip' && args.length === 1) {
        fetch('/api/unblock_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: args[0] })
        })
            .then(response => response.json())
            .then(data => {
                output.textContent = data.message;
                updateBlockedIPs();
            });
    } else if (command === 'add_allowlisted_user' && args.length === 1) {
        fetch('/api/add_allowlisted_user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: args[0] })
        })
            .then(response => response.json())
            .then(data => {
                output.textContent = data.message;
                updateAllowlistedUsers();
            });
    } else {
        output.textContent = 'Invalid command';
    }
}

// Update dashboard every 5 seconds
setInterval(() => {
    updateDNSTable();
    updateBlockedIPs();
    updateAllowlistedUsers();
    updateMetrics();
}, 5000);

// Initial update
updateDNSTable();
updateBlockedIPs();
updateAllowlistedUsers();
updateMetrics();