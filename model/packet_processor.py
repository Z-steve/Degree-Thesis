import netfilterqueue
import scapy.all as scapy
import subprocess
import threading
import psutil
import socket
import time
import ipaddress

class PacketProcessor:
    def __init__(self, data_manager, block_threshold=100, block_duration=1000, ttl=300):
        self.data_manager = data_manager
        self.block_threshold = block_threshold
        self.block_duration = block_duration
        self.ttl = ttl
        self.packet_count = 0
        self.latencies = []
        self.cpu_usages = []
        self.memory_usages = []
        self.start_time = time.time()
        self.queue = netfilterqueue.NetfilterQueue()
        self.running = False
        self.lock = threading.Lock()
        
        self.vpn_networks = []
        try:
            with open('ipv4VPNs.txt', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self.vpn_networks.append(ipaddress.IPv4Network(line))
            print(f"Loaded {len(self.vpn_networks)} VPN subnets.")
        except FileNotFoundError:
            print("ipv4VPNs.txt not found. VPN blocking disabled.")

    def set_iptables_rule(self):
        try:
            # Clear existing general rule if any
            subprocess.run(['iptables', '-D', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '0'], stderr=subprocess.DEVNULL, check=False)
            
            # Send all DNS traffic to NFQUEUE
            subprocess.run(['iptables', '-I', 'FORWARD', '1', '-p', 'udp', '--sport', '53', '-j', 'NFQUEUE', '--queue-num', '0'], check=True)
            subprocess.run(['iptables', '-I', 'FORWARD', '2', '-p', 'tcp', '--sport', '53', '-j', 'NFQUEUE', '--queue-num', '0'], check=True)
            subprocess.run(['iptables', '-I', 'FORWARD', '3', '-p', 'udp', '--dport', '53', '-j', 'NFQUEUE', '--queue-num', '0'], check=True)
            subprocess.run(['iptables', '-I', 'FORWARD', '4', '-p', 'tcp', '--dport', '53', '-j', 'NFQUEUE', '--queue-num', '0'], check=True)
            
            # Send all NEW connections to NFQUEUE
            subprocess.run(['iptables', '-I', 'FORWARD', '5', '-m', 'conntrack', '--ctstate', 'NEW', '-j', 'NFQUEUE', '--queue-num', '0'], check=True)
            
            print("iptables state-tracking rules added successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to add iptables rule: {e}")

    def get_source_ip(self, packet):
        if scapy.IPv6 in packet:
            return packet[scapy.IPv6].src
        elif scapy.IP in packet:
            return packet[scapy.IP].src
        return None

    def get_destination_ip(self, packet):
        if scapy.IPv6 in packet:
            return packet[scapy.IPv6].dst
        elif scapy.IP in packet:
            return packet[scapy.IP].dst
        return None

    def get_rdata_records(self, packet):
        rdata_records = []
        if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 1:
            for i in range(packet[scapy.DNS].ancount):
                rr = packet[scapy.DNS].an[i]
                if rr.type in [1, 28]:  # A (IPv4), AAAA (IPv6)
                    rdata_records.append(rr.rdata)
        return rdata_records

    def modify_dns_response(self, packet):
        current_time = time.time()
        src_ip = self.get_destination_ip(packet)
        for i in range(packet[scapy.DNS].ancount):
            if packet[scapy.DNS].an[i].type in [1, 28]:
                rdata = packet[scapy.DNS].an[i].rdata
                key = f"{src_ip}||{rdata}"
                self.data_manager.dns_expiration_table[key] = current_time + self.ttl
                packet[scapy.DNS].an[i].ttl = self.ttl
        if scapy.IP in packet:
            del packet[scapy.IP].len
            del packet[scapy.IP].chksum
        elif scapy.IPv6 in packet:
            del packet[scapy.IPv6].plen
            del packet[scapy.IPv6].chksum
        if scapy.UDP in packet:
            del packet[scapy.UDP].len
            del packet[scapy.UDP].chksum
        return packet

    def is_reverse_dns_query(self, packet):
        if packet.haslayer(scapy.DNSQR):
            for i in range(packet[scapy.DNS].qdcount):
                if packet[scapy.DNS].qd[i].qtype == 12:  # PTR
                    return True
        return False

    def is_allowlisted_reverse_dns(self, packet):
        src_ip = self.get_source_ip(packet)
        if src_ip in self.data_manager.allowlisted_users:
            return True
        if packet.haslayer(scapy.DNSQR):
            for i in range(packet[scapy.DNS].qdcount):
                qname = packet[scapy.DNS].qd[i].qname.decode()
                for domain in self.data_manager.allowlisted_domains:
                    if domain in qname:
                        return True
        return False

    def check_reverse_dns_query(self, packet):
        query_name = packet[scapy.DNS].qd[0].qname.decode()
        if query_name.endswith('.in-addr.arpa.'):
            reversed_ip = query_name[:-14].split('.')[::-1]
            if all(part.isdigit() for part in reversed_ip):
                actual_ip = '.'.join(reversed_ip)
            else:
                try:
                    actual_ip = socket.gethostbyname('.'.join(reversed_ip))
                except socket.gaierror:
                    return False
            src_ip = self.get_source_ip(packet)
            key = f"{src_ip}||{actual_ip}"
            if key in self.data_manager.dns_expiration_table:
                current_time = time.time()
                expiration_time = self.data_manager.dns_expiration_table[key]
                if current_time <= expiration_time:
                    print(f"Reverse-DNS query accepted: {src_ip} to {actual_ip}")
                    return True
                else:
                    print(f"Reverse-DNS query rejected: {src_ip} to {actual_ip} expired")
                    return False
        return False

    def calculate_metrics(self, start_time):
        with self.lock:
            end = time.time()
            latency = end - start_time
            self.latencies.append(latency)
            self.cpu_usages.append(psutil.cpu_percent())
            self.memory_usages.append(psutil.virtual_memory().percent)
            if self.packet_count % 10000 == 0:
                avg_latency = sum(self.latencies) / len(self.latencies) if self.latencies else 0
                avg_cpu = sum(self.cpu_usages) / len(self.cpu_usages) if self.cpu_usages else 0
                avg_memory = sum(self.memory_usages) / len(self.memory_usages) if self.memory_usages else 0
                print(f"Processed {self.packet_count} packets.")
                print(f"Average latency: {avg_latency:.6f}s, CPU: {avg_cpu:.2f}%, Memory: {avg_memory:.2f}%")
                self.latencies.clear()
                self.cpu_usages.clear()
                self.memory_usages.clear()

    def process_packet(self, packet):
        with self.lock:
            self.packet_count += 1
        start = time.time()
        scapy_packet = scapy.IP(packet.get_payload())
        current_time = time.time()

        # Clean expired blocked IPs
        self.data_manager.blocked_ips = {
            ip: exp_time for ip, exp_time in self.data_manager.blocked_ips.items()
            if exp_time > current_time
        }

        if scapy.IPv6 in scapy_packet:
            scapy_packet = scapy.IPv6(packet.get_payload())

        verdict_given = False

        if scapy_packet.haslayer(scapy.DNSRR) and (scapy.IP in scapy_packet or scapy.IPv6 in scapy_packet):
            rdata_records = self.get_rdata_records(scapy_packet)
            if rdata_records:
                modified_packet = self.modify_dns_response(scapy_packet)
                packet.set_payload(bytes(modified_packet))
                packet.accept()
                verdict_given = True

        elif self.is_reverse_dns_query(scapy_packet):
            if self.check_reverse_dns_query(scapy_packet) or self.is_allowlisted_reverse_dns(scapy_packet):
                print("Reverse-DNS query accepted")
                packet.accept()
            else:
                src_ip = self.get_source_ip(scapy_packet)
                dst_ip = self.get_destination_ip(scapy_packet)
                print(f"Reverse-DNS query from {src_ip} blocked")
                self.data_manager.add_log(f"Reverse-DNS query from {src_ip} blocked", category="REVERSE DNS", details={"src_ip": src_ip, "dst_ip": dst_ip, "action": "blocked"})
                packet.drop()
            verdict_given = True

        elif scapy_packet.haslayer(scapy.DNSQR):
            packet.accept()
            verdict_given = True

        if not verdict_given and (scapy.IP in scapy_packet or scapy.IPv6 in scapy_packet):
            src_ip = self.get_source_ip(scapy_packet)
            dst_ip = self.get_destination_ip(scapy_packet)
            key = f"{src_ip}||{dst_ip}"
            key2 = f"{dst_ip}||{src_ip}"

            if src_ip in self.data_manager.blocked_ips:
                print(f"Blocked IP {src_ip} to {dst_ip}")
                self.data_manager.add_log(f"Blocked IP {src_ip} to {dst_ip}", category="BLOCKED", details={"src_ip": src_ip, "dst_ip": dst_ip, "reason": "Already blocked"})
                packet.drop()
                verdict_given = True

            elif (key in self.data_manager.dns_expiration_table and
                  self.data_manager.dns_expiration_table[key] > current_time) or (
                  key2 in self.data_manager.dns_expiration_table and
                  self.data_manager.dns_expiration_table[key2] > current_time):
                packet.accept()
                verdict_given = True

            elif scapy_packet.haslayer(scapy.ICMP) or (
                  scapy_packet.haslayer(scapy.TCP) and (
                  scapy_packet[scapy.TCP].dport == 22 or scapy_packet[scapy.TCP].sport == 22)):
                packet.accept()
                verdict_given = True

            elif src_ip in self.data_manager.allowlisted_users or dst_ip in self.data_manager.allowlisted_users:
                packet.accept()
                verdict_given = True

            if not verdict_given:
                is_vpn = False
                try:
                    dst_addr = ipaddress.IPv4Address(dst_ip)
                    for net in self.vpn_networks:
                        if dst_addr in net:
                            is_vpn = True
                            break
                except Exception:
                    pass

                if is_vpn:
                    print(f"VPN Connection Blocked: {src_ip} -> {dst_ip}")
                    self.data_manager.add_log(f"VPN Blocked: {src_ip} -> {dst_ip}", category="VPN", details={"src_ip": src_ip, "dst_ip": dst_ip, "reason": "VPN subnet matched"})
                    self.data_manager.add_blocked_ip(src_ip, self.block_duration, target_ip=dst_ip, reason="VPN Usage Detected")
                    packet.drop()
                    verdict_given = True

            # Allow HTTP/HTTPS for all IPs
            if not verdict_given and scapy_packet.haslayer(scapy.TCP) and (
                  scapy_packet[scapy.TCP].dport in [80, 443] or scapy_packet[scapy.TCP].sport in [80, 443]):
                print(f"Allowed HTTP/HTTPS from {src_ip} to {dst_ip}")
                self.data_manager.add_log(f"Allowed HTTP/HTTPS from {src_ip} to {dst_ip}", category="ALLOWED", details={"src_ip": src_ip, "dst_ip": dst_ip, "protocol": "HTTP/HTTPS"})
                packet.accept()
                verdict_given = True

            if not verdict_given:
                # Quick Reverse DNS Lookup for False Positives
                is_false_positive = False
                try:
                    hostname, _, _ = socket.gethostbyaddr(dst_ip)
                    trusted_domains = ['.1e100.net', '.google.com', '.microsoft.com', '.apple.com', '.amazonaws.com', '.cloudflare.com', '.ubuntu.com']
                    if any(hostname.endswith(domain) for domain in trusted_domains):
                        is_false_positive = True
                        print(f"False Positive Ignored ({hostname}): {src_ip} -> {dst_ip}")
                except Exception:
                    pass

                if is_false_positive:
                    packet.accept()
                    verdict_given = True
                else:
                    if src_ip not in self.data_manager.suspicious_count:
                        self.data_manager.suspicious_count[src_ip] = 0
                    self.data_manager.suspicious_count[src_ip] += 1

                    if self.data_manager.suspicious_count[src_ip] >= self.block_threshold:
                        print(f"Blocking IP {src_ip} after {self.data_manager.suspicious_count[src_ip]} suspicious connections")
                        self.data_manager.add_log(f"Blocking IP {src_ip} after {self.data_manager.suspicious_count[src_ip]} suspicious connections", category="BLOCKED", details={"src_ip": src_ip, "dst_ip": dst_ip, "count": self.data_manager.suspicious_count[src_ip]})
                        self.data_manager.add_blocked_ip(src_ip, self.block_duration, target_ip=dst_ip, reason="Suspicious connection threshold exceeded")
                        packet.drop()
                    else:
                        print(f"Suspicious connection from {src_ip} to {dst_ip}, count: {self.data_manager.suspicious_count[src_ip]}")
                        self.data_manager.add_log(f"Suspicious connection from {src_ip} to {dst_ip}, count: {self.data_manager.suspicious_count[src_ip]}", category="SUSPICIOUS", details={"src_ip": src_ip, "dst_ip": dst_ip, "count": self.data_manager.suspicious_count[src_ip]})
                        packet.accept()
                    verdict_given = True

        self.calculate_metrics(start)

    def start(self):
        self.running = True
        self.set_iptables_rule()
        self.queue.bind(0, self.process_packet)
        try:
            self.queue.run()
        except KeyboardInterrupt:
            self.data_manager.save_dns_expiration_table()
            self.data_manager.save_logs_and_history()
            print("DNS expiration table and logs saved.")
            self.running = False