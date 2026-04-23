import pickle
import os
import time
import json

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
        self.attack_history = []
        self.dns_expiration_file = dns_expiration_file
        self.logs_file = "system_logs.json"
        self.attack_history_file = "attack_history.json"
        self.load_dns_expiration_table()
        self.load_logs_and_history()

    def load_logs_and_history(self):
        if os.path.exists(self.logs_file):
            try:
                with open(self.logs_file, 'r') as f:
                    self.logs = json.load(f)
            except Exception:
                self.logs = []
        if os.path.exists(self.attack_history_file):
            try:
                with open(self.attack_history_file, 'r') as f:
                    self.attack_history = json.load(f)
            except Exception:
                self.attack_history = []

    def save_logs_and_history(self):
        try:
            with open(self.logs_file, 'w') as f:
                json.dump(self.logs, f)
            with open(self.attack_history_file, 'w') as f:
                json.dump(self.attack_history, f)
            print("Saved logs and attack history to disk.")
        except Exception as e:
            print(f"Failed to save logs to disk: {e}")
    def save_dns_expiration_table(self):
        try:
            with open(self.dns_expiration_file, 'wb') as f:
                pickle.dump(self.dns_expiration_table, f)
            print(f"Saved DNS expiration table to {self.dns_expiration_file}")
        except Exception as e:
            print(f"Failed to save DNS expiration table to {self.dns_expiration_file}: {e}")
            raise

    def load_dns_expiration_table(self):
        if os.path.exists(self.dns_expiration_file):
            with open(self.dns_expiration_file, 'rb') as f:
                self.dns_expiration_table = pickle.load(f)

    def empty_dns_expiration_table(self):
        self.dns_expiration_table = {}
        with open(self.dns_expiration_file, 'wb') as f:
            pickle.dump(self.dns_expiration_table, f)

    def add_blocked_ip(self, ip, block_duration=1000, target_ip="Unknown", reason="Manual block"):
        from controller.app import scanner  # Import here to avoid circular import
        self.blocked_ips[ip] = time.time() + block_duration
        self.add_log(f"Blocked IP {ip} until {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.blocked_ips[ip]))}", category="SYSTEM", details={"action": "blocked", "ip": ip, "reason": reason})
        
        self.attack_history.insert(0, {
            "timestamp": time.time(),
            "attacker_ip": ip,
            "target_ip": target_ip,
            "reason": reason,
            "expires_at": self.blocked_ips[ip]
        })
        self.attack_history = self.attack_history[:1000] # Keep last 1000
        
        if scanner:
            scanner.update_attacker_status(ip)

    def remove_blocked_ip(self, ip):
        from controller.app import scanner  # Import here to avoid circular import
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            
            # CRITICAL FIX: Reset the suspicious count so the user doesn't get instantly re-banned!
            if ip in self.suspicious_count:
                self.suspicious_count[ip] = 0
                
            self.add_log(f"Unblocked IP {ip}", category="SYSTEM", details={"action": "unblocked", "ip": ip})
            if scanner:
                scanner.update_attacker_status(ip)

    def add_allowlisted_user(self, ip):
        if ip not in self.allowlisted_users:
            self.allowlisted_users.append(ip)
            self.add_log(f"Added allowlisted user: {ip}", category="SYSTEM")

    def remove_allowlisted_user(self, ip):
        if ip in self.allowlisted_users:
            self.allowlisted_users.remove(ip)
            self.add_log(f"Removed allowlisted user: {ip}", category="SYSTEM")

    def add_allowlisted_domain(self, domain):
        if domain not in self.allowlisted_domains:
            self.allowlisted_domains.append(domain)
            self.add_log(f"Added allowlisted domain: {domain}", category="SYSTEM")

    def remove_allowlisted_domain(self, domain):
        if domain in self.allowlisted_domains:
            self.allowlisted_domains.remove(domain)
            self.add_log(f"Removed allowlisted domain: {domain}", category="SYSTEM")

    def add_log(self, message, category="INFO", details=None):
        self.logs.append({
            "timestamp": time.time(),
            "category": category,
            "message": message,
            "details": details or {}
        })
        self.logs = self.logs[-1000:]