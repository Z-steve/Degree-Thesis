from controller.app import app, set_data_manager, set_packet_processor, set_scanner, data_manager
from model.packet_processor import PacketProcessor
from model.data_manager import DataManager
from model.network_scanner import NetworkScanner
from config.config import Config
import threading
import signal
import subprocess
import sys

def clear_nfqueue_rules():
    try:
        subprocess.run(['sudo', 'iptables', '-F', 'FORWARD'], check=True)
        print("Cleared existing NFQUEUE rules")
    except subprocess.CalledProcessError as e:
        print(f"Error clearing NFQUEUE rules: {e}")

def restore_iptables():
    try:
        subprocess.run('sudo iptables-restore < /etc/iptables/rules.v4', shell=True, check=True)
        print("Restored iptables from /etc/iptables/rules.v4")
    except subprocess.CalledProcessError as e:
        print(f"Error restoring iptables: {e}")

def signal_handler(sig, frame):
    print("\nCaught Ctrl+C, saving DNS expiration table and restoring iptables...")
    try:
        if data_manager:
            data_manager.save_dns_expiration_table()
            print("DNS expiration table saved.")
    except Exception as e:
        print(f"Error saving DNS expiration table: {e}")
    restore_iptables()
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    clear_nfqueue_rules()
    data_manager_instance = DataManager(dns_expiration_file=Config.DNS_EXPIRATION_FILE)
    packet_processor = PacketProcessor(
        data_manager_instance,
        block_threshold=Config.BLOCK_THRESHOLD,
        block_duration=Config.BLOCK_DURATION,
        ttl=Config.TTL
    )
    scanner = NetworkScanner()
    scanner.start_scan()
    set_data_manager(data_manager_instance)
    set_packet_processor(packet_processor)
    set_scanner(scanner)
    processor_thread = threading.Thread(target=packet_processor.start)
    processor_thread.daemon = True
    processor_thread.start()
    app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()