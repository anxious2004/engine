import os
import time
import sqlite3
import threading
import multiprocessing
import pyshark
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import runner

# Define global variables
DB_FILE = "captured_packets.db"
PCAP_FILE = "captured_packets.pcap"
INTERFACE = "Wi-Fi"
PACKET_COUNT = 1000

# Manually specify TShark path
TSHARK_PATH = r"C:\Users\asus\OneDrive\Desktop\Desktops\Wireshark\tshark.exe"

def setup_database():
    """Creates the SQLite database and required table if it doesn't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            length INTEGER,
            raw_data BLOB
        )
    """)
    conn.commit()
    conn.close()

def packet_handler(packet, target_ip):
    """Processes and logs each captured packet, filtering by target IP."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if target_ip and target_ip not in [src_ip, dst_ip]:
            return  # Ignore packets that don't match target IP
        
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        length = len(packet)

        print(f"[+] Captured {protocol} Packet | {src_ip} → {dst_ip} | Length: {length} bytes")

        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, raw_data) VALUES (?, ?, ?, ?, ?, ?)",
                           (time.strftime("%Y-%m-%d %H:%M:%S"), src_ip, dst_ip, protocol, length, bytes(packet)))
            conn.commit()
            conn.close()
            print("[✅] Packet saved to database.")

        except sqlite3.Error as e:
            print(f"[!] Database Error: {e}")


def start_sniffing(target_ip):
    """Starts packet sniffing using Scapy with a target IP filter."""
    print(f"[*] Starting packet capture on interface: {INTERFACE} for target IP: {target_ip}")

    def debug_packet(packet):
        print(f"[DEBUG] Raw Packet: {packet.summary()}")  # Print summary of each packet

    sniff(prn=debug_packet, iface=INTERFACE, count=PACKET_COUNT, store=False)

def pyshark_sniff(target_ip):
    """Capture packets using PyShark with a target IP filter."""
    PCAP_FILE_PATH = os.path.abspath(PCAP_FILE)
    print(f"[*] Starting PyShark capture on: {INTERFACE} for target IP: {target_ip}")
    print(f"[+] PCAP file will be saved at: {PCAP_FILE_PATH}")

    try:
        capture = pyshark.LiveCapture(
            interface=INTERFACE,
            output_file=PCAP_FILE_PATH,
            tshark_path=TSHARK_PATH
        )

        for packet in capture.sniff_continuously(packet_count=PACKET_COUNT):
            try:
                if hasattr(packet, "ip"):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    
                    if target_ip and target_ip not in [src_ip, dst_ip]:
                        continue  # Skip packets not matching target IP
                    
                    highest_layer = packet.highest_layer if hasattr(packet, "highest_layer") else "Unknown"
                    length = packet.length if hasattr(packet, "length") else "Unknown"

                    print(f"[+] PyShark Captured Packet | {highest_layer} | {src_ip} → {dst_ip} | Length: {length} bytes")

            except AttributeError as e:
                print(f"[!] Skipped packet due to missing attributes: {e}")

        print(f"[✅] Packets captured and saved to: {PCAP_FILE_PATH}")

    except Exception as e:
        print(f"[!] PyShark Sniffing Error: {e}")

def run_pyshark_process(target_ip):
    """Function to run PyShark in a separate process with a target IP."""
    pyshark_sniff(target_ip)

def run_sniffer(target_ip):
    """Runs the packet sniffer in separate threads for Scapy and a separate process for PyShark."""
    setup_database()
    
    # Thread for Scapy-based live sniffing
    scapy_thread = threading.Thread(target=start_sniffing, args=(target_ip,), daemon=True)
    scapy_thread.start()

    # Process for PyShark-based packet capture
    pyshark_process = multiprocessing.Process(target=run_pyshark_process, args=(target_ip,), daemon=True)
    pyshark_process.start()
    pyshark_process.join()  # Ensuring PyShark process stays active
    try:
        while True:  # Keep script running
            time.sleep(1)
    except KeyboardInterrupt:
        runner.load_detail()
        print("\n[*] Stopping packet capture...")

    print("[*] Scapy and PyShark sniffers running in background...")

        

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")  # Clear console
    print("[*] Initializing Packet Capturing Module...\n")

    # Set the target IP address here
    TARGET_IP = "45.33.32.156"  # Change this to the IP you want to monitor

    # Run packet capturing in separate threads and processes with target IP filtering
    run_sniffer(TARGET_IP)

    try:
        while True:  # Keep script running
            time.sleep(1)
    except KeyboardInterrupt:
        runner.load_detail()
        print("\n[*] Stopping packet capture...")
        