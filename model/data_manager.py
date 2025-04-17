import pickle
import os
import time

class DataManager:
    def __init__(self, dns_expiration_file="dns_expiration_table.pkl"):
        self.dns_expiration_table = {}
        self.allowlisted_users = [
            '192.168.100.1', '192.168.100.2', '8.8.8.8', '8.8.4.4',
            '2001:4860:4860::8888', '2001:4860:4860::8844',
            '90.147.160.73', '45.135.106.143'
        ]
        self.allowlisted_domains = [
            '91.189.91.49', '91.189.91.96', '185.125.190.17', '185.125.190.49',
            '185.125.190.97', '91.189.91.98', '185.125.190.18', '185.125.190.98',
            '91.189.91.97', '185.125.190.48', '185.125.190.96', '91.189.91.48',
            '90.147.160.73', '45.135.106.143'
        ]
        self.allowlisted_protocols = ['ICMP', 'SSH']
        self.blocked_ips = {}
        self.suspicious_count = {}
        self.logs = []
        self.dns_expiration_file = dns_expiration_file
        self.load_dns_expiration_table()

    def save_dns_expiration_table(self):
        with open(self.dns_expiration_file, 'wb') as f:
            pickle.dump(self.dns_expiration_table, f)

    def load_dns_expiration_table(self):
        if os.path.exists(self.dns_expiration_file):
            with open(self.dns_expiration_file, 'rb') as f:
                self.dns_expiration_table = pickle.load(f)

    def empty_dns_expiration_table(self):
        self.dns_expiration_table = {}
        with open(self.dns_expiration_file, 'wb') as f:
            pickle.dump(self.dns_expiration_table, f)

    def add_blocked_ip(self, ip, block_duration=1000):
        from controller.app import scanner  # Import here to avoid circular import
        self.blocked_ips[ip] = time.time() + block_duration
        self.add_log(f"Blocked IP {ip} until {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.blocked_ips[ip]))}")
        if scanner:
            scanner.update_attacker_status(ip)

    def remove_blocked_ip(self, ip):
        from controller.app import scanner  # Import here to avoid circular import
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            self.add_log(f"Unblocked IP {ip}")
            if scanner:
                scanner.update_attacker_status(ip)

    def add_allowlisted_user(self, ip):
        if ip not in self.allowlisted_users:
            self.allowlisted_users.append(ip)
            self.add_log(f"Added allowlisted user: {ip}")

    def remove_allowlisted_user(self, ip):
        if ip in self.allowlisted_users:
            self.allowlisted_users.remove(ip)
            self.add_log(f"Removed allowlisted user: {ip}")

    def add_allowlisted_domain(self, domain):
        if domain not in self.allowlisted_domains:
            self.allowlisted_domains.append(domain)
            self.add_log(f"Added allowlisted domain: {domain}")

    def remove_allowlisted_domain(self, domain):
        if domain in self.allowlisted_domains:
            self.allowlisted_domains.remove(domain)
            self.add_log(f"Removed allowlisted domain: {domain}")

    def add_log(self, message):
        self.logs.append({
            "timestamp": time.time(),
            "message": message
        })
        self.logs = self.logs[-1000:]