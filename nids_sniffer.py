from scapy.all import IP, sniff, TCP
from datetime import datetime
import configparser
import logging
import netifaces

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

iface = config.get('settings', 'interface')
alert_threshold = config.getint('settings', 'alert_threshold')
log_file = config.get('settings', 'log_file')

# Setup logging
logging.basicConfig(filename=log_file, level=logging.INFO,
                    format='%(asctime)s - %(message)s')

# Collect IPs to ignore (our own interfaces)
ignore_ips = set()
for i in netifaces.interfaces():
    addrs = netifaces.ifaddresses(i)
    if netifaces.AF_INET in addrs:
        for link in addrs[netifaces.AF_INET]:
            ignore_ips.add(link['addr'])

port_tracker = {}

# Process packets
def process_packet(packet):
    #print(packet.summary())
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        if src_ip in ignore_ips or src_ip.startswith("127."):
            return
        print(f"[DEBUG] Packet from {src_ip} to port {dst_port}")

        if src_ip not in port_tracker:
            port_tracker[src_ip] = set()

        port_tracker[src_ip].add(dst_port)
        print(f"[DEBUG] {src_ip} has scanned ports: {port_tracker[src_ip]}")

        if len(port_tracker[src_ip]) > alert_threshold:
            alert_msg = f"[!] Port Scan Detected from {src_ip}"
            print(alert_msg)
            logging.info(alert_msg)

# Main
if __name__ == '__main__':
    print("[*] Starting NIDS... sniffing network traffic. Press Ctrl + C to stop.")
    sniff(filter="tcp", iface=iface, prn=process_packet, store=False)
