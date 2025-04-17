import threading
import time
import scapy.all as scapy
import logging

class NetworkDevice:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.is_attacker = False
        self.is_gateway = False

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "is_attacker": self.is_attacker,
            "is_gateway": self.is_gateway
        }

class NetworkScanner:
    def __init__(self, subnet="192.168.100.0/24", detector_ip="192.168.100.10", iface="enp0s3"):
        self.subnet = subnet
        self.detector_ip = detector_ip
        self.iface = iface
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger(__name__)
        self.detector_mac = self.get_detector_mac()
        self.devices = {}
        self.devices[detector_ip] = NetworkDevice(detector_ip, self.detector_mac)
        self.devices[detector_ip].is_gateway = True
        self.logger.debug(f"Initialized devices with detector: {detector_ip}")
        self.scan_running = False
        self.scan_thread = None
        self.lock = threading.Lock()

    def get_detector_mac(self):
        try:
            mac = scapy.get_if_hwaddr(self.iface)
            self.logger.debug(f"Detector MAC for {self.detector_ip} on {self.iface}: {mac}")
            return mac
        except Exception as e:
            self.logger.error(f"Error getting detector MAC: {e}")
            return "00:00:00:00:00:00"

    def start_scan(self):
        if not self.scan_running:
            self.scan_running = True
            self.scan_thread = threading.Thread(target=self._periodic_scan)
            self.scan_thread.daemon = True
            self.scan_thread.start()
            self.logger.info("Network scan started")

    def stop_scan(self):
        self.scan_running = False
        if self.scan_thread:
            self.scan_thread.join()
        self.logger.info("Network scan stopped")

    def get_blocked_ips(self):
        try:
            from controller.app import data_manager
            blocked_ips = data_manager.blocked_ips
            self.logger.debug(f"Blocked IPs retrieved: {blocked_ips}")
            return blocked_ips
        except Exception as e:
            self.logger.error(f"Error accessing blocked IPs: {e}")
            return []

    def update_attacker_status(self, ip):
        with self.lock:
            if ip in self.devices:
                blocked_ips = self.get_blocked_ips()
                self.devices[ip].is_attacker = ip in blocked_ips
                self.logger.info(f"Updated attacker status for {ip}: is_attacker={self.devices[ip].is_attacker}")

    def _periodic_scan(self):
        while self.scan_running:
            self.logger.debug(f"Starting ARP scan on {self.subnet} via {self.iface}")
            live_devices = {}
            try:
                arp_request = scapy.ARP(pdst=self.subnet)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request
                answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False, iface=self.iface)[0]
                self.logger.debug(f"ARP scan received {len(answered_list)} responses")
                for sent, received in answered_list:
                    live_devices[received.psrc] = received.hwsrc
                    self.logger.debug(f"Detected: {received.psrc} -> {received.hwsrc}")
                live_devices[self.detector_ip] = self.detector_mac
                self.logger.debug(f"Live devices collected: {list(live_devices.keys())}")
            except Exception as e:
                self.logger.error(f"ARP scan error: {e}")
                time.sleep(5)
                continue

            with self.lock:
                # Create new devices dict with only live devices
                new_devices = {}
                # Always include detector
                new_devices[self.detector_ip] = self.devices.get(self.detector_ip, NetworkDevice(self.detector_ip, self.detector_mac))
                new_devices[self.detector_ip].is_gateway = True
                new_devices[self.detector_ip].is_attacker = self.detector_ip in self.get_blocked_ips()

                # Add or update live devices
                for ip, mac in live_devices.items():
                    if ip != self.detector_ip:  # Detector handled above
                        if ip in self.devices:
                            # Preserve existing device attributes
                            new_devices[ip] = self.devices[ip]
                            new_devices[ip].mac = mac
                        else:
                            new_devices[ip] = NetworkDevice(ip, mac)
                        new_devices[ip].is_attacker = ip in self.get_blocked_ips()
                        new_devices[ip].is_gateway = False
                        self.logger.debug(f"Updated device: {ip} -> {mac}, is_attacker={new_devices[ip].is_attacker}")

                # Log removed devices
                removed_ips = set(self.devices.keys()) - set(new_devices.keys())
                if removed_ips:
                    self.logger.info(f"Removed devices no longer responding: {removed_ips}")

                # Update devices
                self.devices = new_devices
                self.logger.debug(f"Devices after update: {[ip for ip in self.devices.keys()]}")

            time.sleep(120)
            for _ in range(12):
                with self.lock:
                    blocked_ips = self.get_blocked_ips()
                    self.logger.debug(f"Checking blocked IPs: {blocked_ips}")
                    for ip, device in self.devices.items():
                        was_attacker = device.is_attacker
                        device.is_attacker = ip in blocked_ips
                        if device.is_attacker and not was_attacker:
                            self.logger.info(f"Marked as attacker: {ip}")
                time.sleep(10)

    def get_devices(self):
        with self.lock:
            self.logger.debug(f"Scanner instance: {id(self)}, Accessing devices: {[ip for ip in self.devices.keys()]}")
            devices = [device.to_dict() for device in self.devices.values()]
            self.logger.info(f"Returning devices: {devices}")
            return devices