import os
import sqlite3
import pyshark
from scapy.all import rdpcap, Ether, IP, TCP, UDP, Raw, DNS, DNSQR

# Database & PCAP File Paths
DB_FILE = "captured_packets.db"
PCAP_FILE = "captured_packets.pcap"

def analyze_pcap():
    """Reads packets from a PCAP file and extracts metadata."""
    
    if not os.path.exists(PCAP_FILE):
        print("[!] PCAP file not found.")
        return

    print(f"[*] Analyzing packets from {PCAP_FILE}...")

    packets = rdpcap(PCAP_FILE)  # Read all packets from PCAP

    for packet in packets:
        analyze_packet(packet)  # Process each packet

    print("[✅] PCAP Analysis Complete.\n")

def analyze_database():
    """Reads packets from SQLite database and extracts metadata."""
    
    if not os.path.exists(DB_FILE):
        print("[!] Database file not found.")
        return

    print(f"[*] Analyzing packets from {DB_FILE}...")

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT raw_data FROM packets")

        for row in cursor.fetchall():
            packet = Ether(row[0])  # Convert raw bytes to a Scapy packet
            analyze_packet(packet)  # Process each packet

        conn.close()

    except sqlite3.Error as e:
        print(f"[!] Database Error: {e}")

    print("[✅] Database Analysis Complete.\n")

def analyze_packet(packet):
    """Extracts metadata from a packet and performs DPI."""
    metadata = {}

    # Decode Ethernet
    if packet.haslayer(Ether):
        eth_layer = packet[Ether]
        print(f"\n📡 Ethernet: {eth_layer.src} → {eth_layer.dst} | Type: {hex(eth_layer.type)}")

    # Decode IP
    if packet.haslayer(IP):
        metadata["src_ip"] = packet[IP].src
        metadata["dst_ip"] = packet[IP].dst
        metadata["protocol"] = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"

    # Decode TCP
    if packet.haslayer(TCP):
        metadata["src_port"] = packet[TCP].sport
        metadata["dst_port"] = packet[TCP].dport
        metadata["flags"] = str(packet[TCP].flags)
    
    # Decode UDP
    if packet.haslayer(UDP):
        metadata["src_port"] = packet[UDP].sport
        metadata["dst_port"] = packet[UDP].dport
        metadata["length"] = packet[UDP].len

    # Print Extracted Metadata
    print(f"[+] {metadata.get('src_ip', 'Unknown')} → {metadata.get('dst_ip', 'Unknown')} | {metadata.get('protocol', 'N/A')}")
    
    # Debugging: Confirm that DPI is called
    print(f"[*] Calling DPI for Packet from {metadata.get('src_ip', 'Unknown')} to {metadata.get('dst_ip', 'Unknown')}")
    
    # Perform Deep Packet Inspection (DPI)
    deep_packet_inspection(packet, metadata)

def deep_packet_inspection(packet, metadata):
    """Detects anomalies and flags suspicious packets."""

    src_ip = metadata.get("src_ip", "Unknown")
    dst_ip = metadata.get("dst_ip", "Unknown")

    # 🚨 Anomaly 1: Large Packet Size (Potential DDoS)
    if len(packet) > 1500:
        print(f"[⚠️] Large Packet Detected: {len(packet)} bytes | {src_ip} → {dst_ip}")

    # 🚨 Anomaly 2: Unusual TCP Flags (Port Scanning)
    if packet.haslayer(TCP):
        if packet[TCP].flags == "FPU":  # FIN-PSH-URG Flag (Common in Scans)
            print(f"[⚠️] Suspicious TCP Flags from {src_ip} to {dst_ip}")

    # 🚨 Anomaly 3: Non-Standard Payloads (Possible Exploit)
    if packet.haslayer(Raw):
        raw_data = bytes(packet[Raw])
        if b"evil_payload" in raw_data:
            print(f"[🚨] Malicious Payload Detected: {src_ip} → {dst_ip}")

    # 🚨 Anomaly 4: SYN Flood Detection (Multiple SYNs from One Source)
    if packet.haslayer(TCP) and packet[TCP].flags == "S":  # SYN Flag
        print(f"[⚠️] Possible SYN Flood: {src_ip} sent SYN to {dst_ip}")

    # 🚨 Anomaly 5: DNS Tunneling Detection (Large DNS Query)
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):  # DNS Query Layer
        dns_query = packet[DNSQR].qname.decode() if isinstance(packet[DNSQR].qname, bytes) else packet[DNSQR].qname
        if len(dns_query) > 100:  # DNS Queries are usually short
            print(f"[⚠️] Possible DNS Tunneling: Large Query from {src_ip}: {dns_query}")

if __name__ == "__main__":
    print("[*] Starting Packet Analysis...\n")
    analyze_pcap()      # Analyze PCAP File
    analyze_database()  # Analyze Database
