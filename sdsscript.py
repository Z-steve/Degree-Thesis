import netfilterqueue
import scapy.all as scapy
from scapy.layers import dns
from scapy.layers.inet6 import IPv6
import time
import pickle
import os
import psutil
import socket
import subprocess
import threading
import queue as queue_module

# hash table to save source ip, dns response's provided ip and new TTL associated
dns_expiration_table = {}

allowlisted_users = [
    '192.168.100.1',
    '192.168.100.2',
    '8.8.8.8',  # Google DNS
    '8.8.4.4',  # Google DNS
    '2001:4860:4860::8888',  # Google DNS IPv6
    '2001:4860:4860::8844',  # Google DNS IPv6
    '90.147.160.73',
    '45.135.106.143'

]  # Example allowlisted users

allowlisted_domains = [
    '91.189.91.49', '91.189.91.96',
    '185.125.190.17', '185.125.190.49',
    '185.125.190.97', '91.189.91.98',
    '185.125.190.18', '185.125.190.98',
    '91.189.91.97', '185.125.190.48',
    '185.125.190.96', '91.189.91.48',
    '90.147.160.73', '45.135.106.143'
]  # Example allowlisted domains

allowlisted_protocols = ['ICMP', 'SSH']  # Example allowlisted protocols

blocked_ips = {}  # Dictionary to store blocked IP addresses and their expiration times
block_duration = 1000  # Duration in seconds for which a machine should be blocked

suspicious_count = {}  # Global dictionary to track the number of suspicious connections per IP
block_threshold = 100  # Set the threshold for blocking an IP after 100 suspicious connections

# Global variables for performance metrics
latencies = []
cpu_usages = []
memory_usages = []
packet_count = 0
start_time = time.time()

# File to store the DNS expiration table
dns_expiration_file = "dns_expiration_table.pkl"

def set_iptables_rule():
    try:
        subprocess.run(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '0'], check=True)
        print("iptables rule added successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to add iptables rule: {e}")

def empty_dns_expiration_table():
    with open('dns_expiration_table.pkl', 'wb') as f:
        pickle.dump({}, f)

def save_dns_expiration_table():
    with open(dns_expiration_file, 'wb') as f:
        pickle.dump(dns_expiration_table, f)

def load_dns_expiration_table():
    global dns_expiration_table
    if os.path.exists(dns_expiration_file):
        with open(dns_expiration_file, 'rb') as f:
            dns_expiration_table = pickle.load(f)

def get_source_ip(packet):
    if scapy.IPv6 in packet:
        return packet[scapy.IPv6].src
    elif scapy.IP in packet:
        return packet[scapy.IP].src
    else:
        return None

def get_destination_ip(packet):
    if scapy.IPv6 in packet:
        return packet[scapy.IPv6].dst
    elif scapy.IP in packet:
        return packet[scapy.IP].dst
    else:
        return None


def get_rdata_records(packet):
    rdata_records = []
    if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 1:
        for i in range(packet[scapy.DNS].ancount):
            rr = packet[scapy.DNS].an[i]
            if rr.type in [1, 28]:  # 1 is A (IPv4), 28 is AAAA (IPv6)
                rdata_records.append(rr.rdata)
    return rdata_records


def modify_dns_response(packet):
    global dns_expiration_table
    current_time = time.time()
    tau = 300
    src_ip = get_destination_ip(packet)
    for i in range(packet[scapy.DNS].ancount):
        if packet[scapy.DNS].an[i].type in [1, 28]:  # 1 is A (IPv4), 28 is AAAA (IPv6)
            rdata = packet[scapy.DNS].an[i].rdata
            key = f"{src_ip}||{rdata}"
            dns_expiration_table[key] = current_time + tau
            packet[scapy.DNS].an[i].ttl = tau
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

def is_reverse_dns_query(packet):
    if packet.haslayer(scapy.DNSQR):
        for i in range(packet[scapy.DNS].qdcount):
            if packet[scapy.DNS].qd[i].qtype == 12:  # 12 is the type code for PTR records
                return True
    return False

def is_allowlisted_reverse_dns(packet):
    src_ip = get_source_ip(packet)
    if src_ip in allowlisted_users:
        return True
    if packet.haslayer(scapy.DNSQR):
        for i in range(packet[scapy.DNS].qdcount):
            qname = packet[scapy.DNS].qd[i].qname.decode()
            for domain in allowlisted_domains:
                if domain in qname:
                    return True
    return False


def check_reverse_dns_query(packet):  # Function to check if IP from reverse DNS query is in the hash table
    query_name = packet[scapy.DNS].qd[0].qname.decode()

    if query_name.endswith('.in-addr.arpa.'):
        reversed_ip = query_name[:-14].split('.')[::-1]  # Adjusted to remove the extra period

        # If it's an IP address in the reverse DNS query
        if all(part.isdigit() for part in reversed_ip):
            actual_ip = '.'.join(reversed_ip)
        else:
            # If it's a domain name in the reverse DNS query
            actual_ip = '.'.join(reversed_ip)
            try:
                resolved_ip = socket.gethostbyname(actual_ip)
                actual_ip = resolved_ip
            except socket.gaierror:
                return False

        src_ip = get_source_ip(packet)
        key = f"{src_ip}||{actual_ip}"

        # Check if the key is in the DNS expiration table
        if key in dns_expiration_table:
            current_time = time.time()  # Get the current time
            expiration_time = dns_expiration_table[key]  # Get the stored expiration time

            # print(f"{key}: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expiration_time))}")
            # print(f"{key}: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time))}")

            # Compare current time with expiration time
            if current_time <= expiration_time:
                print("========================\n")
                print(
                    f"Reverse-DNS query accepted since a connection from {src_ip} to {actual_ip} was previously established (so it is considered as legit)\n")
                print("========================\n")
                return True
            else:
                # The entry has expired, so it's no longer valid
                print("========================\n")
                print(f"Reverse-DNS query rejected since the connection from {src_ip} to {actual_ip} has expired\n")
                print("========================\n")
                return False

    return False

def calculate_metrics(start_time):

    # Measure performance
    end = time.time()
    latency = end - start_time
    latencies.append(latency)

    # Record CPU and memory usage
    cpu_usages.append(psutil.cpu_percent())
    memory_usages.append(psutil.virtual_memory().percent)

    # Print metrics periodically (every 10000 packets)
    if packet_count % 10000 == 0:
        avg_latency = sum(latencies) / len(latencies)
        avg_cpu = sum(cpu_usages) / len(cpu_usages)
        avg_memory = sum(memory_usages) / len(memory_usages)
        print("===============================\n")
        print(f"Processed {packet_count} packets.")
        print(f"Average latency per packet: {avg_latency:.6f} seconds.")
        print(f"Average CPU usage: {avg_cpu:.2f}%")
        print(f"Average memory usage: {avg_memory:.2f}%")
        print("===============================\n")

        # Clear the metrics after printing to start fresh for the next 10000 packets
        latencies.clear()
        cpu_usages.clear()
        memory_usages.clear()


def process_commands():
    while True:
        command = input("\nEnter a command: ")
        if command == "print_hash_table":
            print("\nDNS Expiration Table:")
            for key, value in dns_expiration_table.items():
                print(f"{key}: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(value))}")

        elif command == "block_ip":
            ip = input("Enter IP to block: ")
            blocked_ips[ip] = time.time() + block_duration
            print(f"Blocked IP: {ip}")

        elif command == "unblock_ip":
            ip = input("Enter IP to unblock: ")
            if ip in blocked_ips:
                del blocked_ips[ip]
                print(f"Unblocked IP: {ip}")
            else:
                print(f"IP {ip} not found in blocked list.")

        elif command == "add_allowlisted_user":
            ip = input("Enter IP to add to allowlist: ")
            allowlisted_users.append(ip)
            print(f"Added allowlisted user with IP: {ip}")

        elif command == "remove_allowlisted_user":
            ip = input("Enter IP to remove from allowlist: ")
            if ip in allowlisted_users:
                allowlisted_users.remove(ip)
                print(f"Removed allowlisted user with IP: {ip}")
            else:
                print(f"User with IP {ip} not found in allowlist.")

        elif command == "add_allowlisted_domain":
            domain = input("Enter domain to add to allowlist: ")
            allowlisted_domains.append(domain)
            print(f"Added allowlisted domain: {domain}")

        elif command == "remove_allowlisted_domain":
            domain = input("Enter domain to remove from allowlist: ")
            if domain in allowlisted_domains:
                allowlisted_domains.remove(domain)
                print(f"Removed allowlisted domain: {domain}")
            else:
                print(f"Domain {domain} not found in allowlist.")

        elif command == "print_blocked_ips":
            print("\nBlocked IPs:")
            for ip, exp_time in blocked_ips.items():
                print(f"{ip}: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(exp_time))}")

        elif command == "print_allowlisted_users":
            print("\nAllowlisted users:")
            for ip in allowlisted_users:
                print(ip)

        elif command == "print_allowlisted_domains":
            print("\nAllowlisted Domains:")
            for domain in allowlisted_domains:
                print(domain)

        elif command == "exit":
            print("Exiting command interface.")
            break

        elif command == "help":
            show_help()

        else:
            print("Unknown command. Please try again.")

def show_help():
    # Display a list of all available commands and their descriptions
    print("\nAvailable commands:")
    print("1. print_hash_table: Display the current DNS expiration table.")
    print("2. block_ip: Block an IP address for a specified duration.")
    print("3. unblock_ip: Unblock an IP address.")
    print("4. add_allowlisted_user: Add a user to the allowlist.")
    print("5. remove_allowlisted_user: Remove a user from the allowlist.")
    print("6. add_allowlisted_domain: Add a domain to the allowlist.")
    print("7. remove_allowlisted_domain: Remove a domain from the allowlist.")
    print("8. print_blocked_ips: Display the list of currently blocked IPs.")
    print("9. print_allowlisted_users: Display the list of currently allowlisted users.")
    print("10. print_allowlisted_domains: Display the list of currently allowlisted domains.")
    print("11. help: Display this help message with all available commands.")
    print("12. exit: Exit the command interface.")


def process_packet(packet):
    global latencies, cpu_usages, memory_usages, packet_count, blocked_ips
    packet_count += 1
    # Measure latency
    start = time.time()
    scapy_packet = scapy.IP(packet.get_payload())
    current_time = time.time()

    # Remove expired blocked entries
    blocked_ips = {ip: exp_time for ip, exp_time in blocked_ips.items() if exp_time > current_time}

    if scapy.IPv6 in scapy_packet:
        scapy_packet = scapy.IPv6(packet.get_payload())

    # Flag to indicate if a verdict has been given
    verdict_given = False

    if scapy_packet.haslayer(scapy.DNSRR) and (scapy.IP in scapy_packet or scapy.IPv6 in scapy_packet):
        # Process DNS response
        rdata_records = get_rdata_records(scapy_packet)  # check if there are any rdata records
        if rdata_records:
            modified_answers = modify_dns_response(scapy_packet)
            packet.set_payload(bytes(modified_answers))
            packet.accept()
            verdict_given = True

    elif is_reverse_dns_query(scapy_packet):

        if check_reverse_dns_query(scapy_packet) or is_allowlisted_reverse_dns(
                scapy_packet):  # accept reverse dns queries only if allowed
            packet.accept()
            print("\n========================\n")
            print("Reverse-DNS query accepted")
            print("\n========================\n")
        else:
            src_ip = get_source_ip(scapy_packet)  # log and drop not expected reverse dns queries
            print("\n========================================================\n")
            print(f"Reverse-DNS query from {src_ip} detected. Blocking this dns reverse query.")
            print("\n========================================================\n")
            packet.drop()

        verdict_given = True


    elif scapy_packet.haslayer(scapy.DNSQR):
        # Accept all DNS query packets
        packet.accept()
        verdict_given = True

    if not verdict_given and (scapy.IP in scapy_packet or scapy.IPv6 in scapy_packet):
        # Process communication attempt
        src_ip = get_source_ip(scapy_packet)
        dst_ip = get_destination_ip(scapy_packet)
        key = f"{src_ip}||{dst_ip}"
        key2 = f"{dst_ip}||{src_ip}"

        if src_ip in blocked_ips:
            print("\n**********************************************************************\n")
            print(f"Connection attempt from blocked IP {src_ip} to {dst_ip} blocked.")
            print("\n**********************************************************************\n")
            packet.drop()
            verdict_given = True

        if not verdict_given and (key in dns_expiration_table and dns_expiration_table[key] > current_time) or (
                key2 in dns_expiration_table and dns_expiration_table[key2] > current_time):
            packet.accept()  # Allow the connection
            verdict_given = True

        # Allowlist specific protocols and applications
        if not verdict_given:
            if scapy_packet.haslayer(scapy.ICMP) or scapy_packet.haslayer(scapy.TCP) and (
                    scapy_packet[scapy.TCP].dport == 22 or scapy_packet[scapy.TCP].sport == 22):  # ICMP or SSH (port 22)
                packet.accept()
                verdict_given = True

        if not verdict_given:

            # Initialize the count for the src_ip if it's not already in the dictionary
            if src_ip not in suspicious_count:
                suspicious_count[src_ip] = 0

            # Check if the connection involves allowlisted IPs
            if src_ip in allowlisted_users or dst_ip in allowlisted_users:
                packet.accept()  # Allowlisted users are not considered malicious
                verdict_given = True

            else:
                # Increment the suspicious count for the source IP
                suspicious_count[src_ip] += 1

                if suspicious_count[src_ip] >= block_threshold:
                    # Block the IP if it exceeds the threshold
                    print("\n\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-\n\n")
                    print(f"Blocking IP {src_ip} after {suspicious_count[src_ip]} suspicious connections.")
                    blocked_ips[src_ip] = current_time + block_duration
                    packet.drop()  # Drop the connection
                    print("\n\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-\n\n")
                    verdict_given = True
                else:
                    # Log the suspicious connection but do not block it (just log it)
                    print("\n***********************************************************************************\n")
                    print(
                        f"Suspicious connection from {src_ip} to {dst_ip} detected. Count: {suspicious_count[src_ip]}")
                    print("\n***********************************************************************************\n")
                    packet.accept()
                    verdict_given = True

    calculate_metrics(start)


queue = netfilterqueue.NetfilterQueue()
load_dns_expiration_table()  # loading the locally saved hash table
set_iptables_rule()  # run iptables rules on the startup of the script
# Clear the file at the start
# empty_dns_expiration_table()
queue.bind(0, process_packet)

# Define a thread-safe queue for inter-thread communication
command_queue = queue_module.Queue()
# Start the command processing thread
command_thread = threading.Thread(target=process_commands)
command_thread.daemon = True
command_thread.start()

try:
    queue.run()

except KeyboardInterrupt:
    save_dns_expiration_table()  # saving hash table before exiting
    print("DNS expiration table saved.")

