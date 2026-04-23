from controller.app import app, set_data_manager, set_packet_processor, set_scanner
from model.packet_processor import PacketProcessor
from model.data_manager import DataManager
from model.network_scanner import NetworkScanner
from config.config import Config
import threading
import signal
import subprocess
import sys
import argparse
import time
import builtins

try:
    import readline
except ImportError:
    readline = None


class StickyConsole:
    def __init__(self, prompt="sds> "):
        self.prompt = prompt
        self._orig_print = builtins.print
        self._lock = threading.Lock()

    def install(self):
        builtins.print = self._print_hook

    def uninstall(self):
        builtins.print = self._orig_print

    def _print_hook(self, *args, **kwargs):
        """Redraw prompt after any background print so command line stays visible."""
        sep = kwargs.get("sep", " ")
        end = kwargs.get("end", "\n")
        message = sep.join(str(a) for a in args)
        with self._lock:
            buf = ""
            if readline is not None:
                try:
                    buf = readline.get_line_buffer()
                except Exception:
                    buf = ""

            sys.stdout.write("\r\033[K")
            sys.stdout.write(message + end)
            sys.stdout.write(self.prompt + buf)
            sys.stdout.flush()

            if readline is not None:
                try:
                    readline.redisplay()
                except Exception:
                    pass

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


def run_cli_console(data_manager_instance, packet_processor):
    print("CLI mode enabled. Commands: help, status, blocked, suspicious, dns, logs [N], attacks [N], block <ip>, unblock <ip>, allow <ip>, unallow <ip>, quit")
    while True:
        try:
            raw = input("sds> ").strip()
        except EOFError:
            time.sleep(1)
            continue

        if not raw:
            continue

        parts = raw.split()
        cmd = parts[0].lower()

        if cmd in ["quit", "exit"]:
            print("Stopping SDS...")
            return

        if cmd == "help":
            print("Commands:")
            print("  status               Show packet/log counters")
            print("  blocked              Show currently blocked IPs")
            print("  suspicious           Show suspicious counters")
            print("  dns                  Show DNS table size")
            print("  logs [N]             Show last N logs (default 10)")
            print("  attacks [N]          Show last N blocked attacks (default 10)")
            print("  block <ip>           Manually block IP")
            print("  unblock <ip>         Manually unblock IP")
            print("  allow <ip>           Add allowlisted user IP")
            print("  unallow <ip>         Remove allowlisted user IP")
            print("  quit                 Stop SDS")
            continue

        if cmd == "status":
            print(f"packet_count={packet_processor.packet_count}")
            print(f"blocked_ips={len(data_manager_instance.blocked_ips)}")
            print(f"dns_entries={len(data_manager_instance.dns_expiration_table)}")
            print(f"logs={len(data_manager_instance.logs)}")
            continue

        if cmd == "blocked":
            if not data_manager_instance.blocked_ips:
                print("No blocked IPs.")
            else:
                now = time.time()
                for ip, exp in data_manager_instance.blocked_ips.items():
                    remaining = max(0, int(exp - now))
                    print(f"{ip} (expires in {remaining}s)")
            continue

        if cmd == "suspicious":
            if not data_manager_instance.suspicious_count:
                print("No suspicious counters.")
            else:
                for ip, count in data_manager_instance.suspicious_count.items():
                    print(f"{ip}: {count}")
            continue

        if cmd == "dns":
            print(f"DNS table entries: {len(data_manager_instance.dns_expiration_table)}")
            continue

        if cmd in ["logs", "attacks"]:
            n = 10
            if len(parts) > 1 and parts[1].isdigit():
                n = int(parts[1])
            source = data_manager_instance.logs if cmd == "logs" else data_manager_instance.attack_history
            if not source:
                print("No entries.")
            else:
                for item in source[-n:]:
                    print(item)
            continue

        if cmd in ["block", "unblock", "allow", "unallow"]:
            if len(parts) < 2:
                print("IP required.")
                continue
            ip = parts[1]
            if cmd == "block":
                data_manager_instance.add_blocked_ip(ip, Config.BLOCK_DURATION, reason="Manual CLI block")
                print(f"Blocked {ip}")
            elif cmd == "unblock":
                data_manager_instance.remove_blocked_ip(ip)
                print(f"Unblocked {ip}")
            elif cmd == "allow":
                data_manager_instance.add_allowlisted_user(ip)
                print(f"Allowlisted {ip}")
            elif cmd == "unallow":
                data_manager_instance.remove_allowlisted_user(ip)
                print(f"Removed allowlist {ip}")
            continue

        print("Unknown command. Type 'help'.")


def parse_args():
    parser = argparse.ArgumentParser(description="DNS-based Scan Detection System")
    parser.add_argument("--mode", choices=["cli", "web"], default="cli", help="Run mode (default: cli)")
    parser.add_argument("--iface", default=None, help="Network interface for ARP scan (example: enp1s0)")
    parser.add_argument("--subnet", default=None, help="Subnet to scan (example: 192.168.0.0/24)")
    parser.add_argument("--detector-ip", default=None, help="SDS local IP (example: 192.168.0.159)")
    parser.add_argument("--scan", dest="scan", action="store_true", help="Enable ARP device scanning")
    parser.add_argument("--no-scan", dest="scan", action="store_false", help="Disable ARP device scanning")
    parser.set_defaults(scan=True)
    parser.add_argument("--web-host", default="127.0.0.1", help="Web bind host when mode=web")
    parser.add_argument("--web-port", type=int, default=5000, help="Web bind port when mode=web")
    return parser.parse_args()

def main():
    args = parse_args()
    data_manager_instance = DataManager(dns_expiration_file=Config.DNS_EXPIRATION_FILE)
    signal.signal(signal.SIGINT, create_signal_handler(data_manager_instance))
    clear_nfqueue_rules()

    packet_processor = PacketProcessor(
        data_manager_instance,
        block_threshold=Config.BLOCK_THRESHOLD,
        block_duration=Config.BLOCK_DURATION,
        ttl=Config.TTL
    )

    scanner = None
    if args.scan:
        scanner = NetworkScanner(subnet=args.subnet, detector_ip=args.detector_ip, iface=args.iface)
        scanner.start_scan()

    set_data_manager(data_manager_instance)
    set_packet_processor(packet_processor)
    set_scanner(scanner)

    processor_thread = threading.Thread(target=packet_processor.start)
    processor_thread.daemon = True
    processor_thread.start()

    print("SDS started with settings:")
    print(f"  mode={args.mode}")
    print(f"  scan_enabled={args.scan}")
    print(f"  iface={args.iface if args.iface else 'auto'}")
    print(f"  subnet={args.subnet if args.subnet else 'auto'}")
    print(f"  detector_ip={args.detector_ip if args.detector_ip else 'auto'}")

    if args.mode == "web":
        app.run(host=args.web_host, port=args.web_port)
    else:
        sticky_console = StickyConsole(prompt="sds> ")
        sticky_console.install()
        try:
            run_cli_console(data_manager_instance, packet_processor)
        finally:
            sticky_console.uninstall()
            if scanner:
                scanner.stop_scan()
            data_manager_instance.save_dns_expiration_table()
            data_manager_instance.save_logs_and_history()
            restore_iptables()

if __name__ == '__main__':
    main()
