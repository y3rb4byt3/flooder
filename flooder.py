import logging
import signal
import sys
import time
import threading
from collections import defaultdict
from scapy.all import sniff, IP, UDP, TCP, ICMP, DNS

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PacketMonitor:
    def __init__(self, thresholds):
        self.thresholds = thresholds
        self.packet_counts = defaultdict(int)
        self.running = True

    def packet_handler(self, packet, packet_type):
        """Handle incoming packets based on their type."""
        if packet_type == 'UDP' and packet.haslayer(UDP):
            src_ip = packet[IP].src
        elif packet_type == 'SYN' and packet.haslayer(TCP) and packet[TCP].flags & 0x02:  # SYN flag
            src_ip = packet[IP].src
        elif packet_type == 'ICMP' and packet.haslayer(ICMP):
            src_ip = packet[IP].src
        elif packet_type == 'HTTP' and packet.haslayer(TCP) and packet[TCP].dport == 80:  # HTTP traffic on port 80
            src_ip = packet[IP].src
        elif packet_type == 'TCP' and packet.haslayer(TCP):
            src_ip = packet[IP].src
        elif packet_type == 'DNS' and packet.haslayer(DNS):
            src_ip = packet[IP].src
        else:
            return  # Ignore other packets
        
        self.packet_counts[(src_ip, packet_type)] += 1
        logging.info(f"{packet_type} Packet received from {src_ip}. Total count: {self.packet_counts[(src_ip, packet_type)]}")

    def monitor_flood(self, packet_type):
        """Monitor packets for flood attacks based on their type."""
        logging.info(f"Monitoring for {packet_type} packets...")
        while self.running:
            time.sleep(1)  # Check every second
            for (src_ip, ptype), count in list(self.packet_counts.items()):
                if ptype == packet_type and count > self.thresholds[packet_type]:
                    logging.warning(f"ALERT: Possible {ptype} flood attack detected from {src_ip}! Count: {count}")
                if ptype == packet_type:  # Reset counts only for the current packet type
                    self.packet_counts[(src_ip, packet_type)] = 0

    def start_sniffing(self):
        """Start sniffing for packets."""
        packet_types = ['UDP', 'SYN', 'ICMP', 'HTTP', 'TCP', 'DNS']
        for packet_type in packet_types:
            threading.Thread(target=sniff, kwargs={'filter': self.get_filter(packet_type), 
                                                    'prn': lambda p, pt=packet_type: self.packet_handler(p, pt), 
                                                    'store': 0}).start()

    def get_filter(self, packet_type):
        """Return the appropriate filter for sniffing based on packet type."""
        filters = {
            'UDP': 'udp',
            'SYN': 'tcp',
            'ICMP': 'icmp',
            'HTTP': 'tcp port 80',
            'TCP': 'tcp',
            'DNS': 'udp port 53'
        }
        return filters.get(packet_type, '')

    def stop(self):
        """Stop the monitoring and sniffing."""
        self.running = False
        logging.info("Shutting down monitoring...")

def signal_handler(signal, frame):
    """Handle termination signals."""
    monitor.stop()
    sys.exit(0)

if __name__ == "__main__":
    # Define thresholds for each type of packet
    thresholds = {
        'UDP': 100,
        'SYN': 50,
        'ICMP': 100,
        'HTTP': 50,
        'TCP': 100,
        'DNS': 100
    }
    
    # Initialize the packet monitor
    monitor = PacketMonitor(thresholds)

    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start monitoring
    monitor.start_sniffing()
    
    # Start monitoring floods in separate threads
    for packet_type in thresholds.keys():
        threading.Thread(target=monitor.monitor_flood, args=(packet_type,)).start()
