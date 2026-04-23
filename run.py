from controller.app import app, set_data_manager, set_packet_processor, set_scanner
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

def create_signal_handler(data_manager_instance):
    def signal_handler(sig, frame):
        print("\nCaught Ctrl+C, saving DNS expiration table and restoring iptables...")
        if not data_manager_instance:
            print("Error: data_manager_instance is None, cannot save DNS expiration table.")
        else:
            try:
                print(f"Attempting to save DNS expiration table to {data_manager_instance.dns_expiration_file}")
                print(f"DNS expiration table contents: {data_manager_instance.dns_expiration_table}")
                data_manager_instance.save_dns_expiration_table()
                data_manager_instance.save_logs_and_history()
                print("DNS expiration table and logs saved.")
            except Exception as e:
                print(f"Error saving data: {e}")
        restore_iptables()
        sys.exit(0)
    return signal_handler

def main():
    data_manager_instance = DataManager(dns_expiration_file=Config.DNS_EXPIRATION_FILE)
    signal.signal(signal.SIGINT, create_signal_handler(data_manager_instance))
    clear_nfqueue_rules()
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
    app.run(host='127.0.0.1', port=5000)

if __name__ == '__main__':
    main()