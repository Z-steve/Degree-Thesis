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
            from controller.app import data_manager  # Import here to avoid circular import
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
                current_devices = self.devices.copy()
                self.logger.debug(f"Before update, devices: {[ip for ip in current_devices.keys()]}")
                for ip, mac in live_devices.items():
                    if ip not in current_devices:
                        current_devices[ip] = NetworkDevice(ip, mac)
                        self.logger.debug(f"New device added: {ip} -> {mac}")
                    else:
                        current_devices[ip].mac = mac
                        self.logger.debug(f"Existing device updated: {ip} -> {mac}")
                    current_devices[ip].is_gateway = (ip == self.detector_ip)
                    current_devices[ip].is_attacker = ip in self.get_blocked_ips()
                    self.logger.info(f"Device updated: {ip} -> {mac}, is_attacker={current_devices[ip].is_attacker}")
                self.devices = {ip: dev for ip, dev in current_devices.items()}
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