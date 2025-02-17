import os
import asyncio
import time
import sqlite3
import threading
import multiprocessing
import pyshark
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Define global variables
DB_FILE = "captured_packets.db"
PCAP_FILE = "captured_packets.pcap"
INTERFACE = "Wi-Fi"
PACKET_COUNT = 10

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

def packet_handler(packet):
    """Processes and logs each captured packet."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
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

def start_sniffing():
    """Starts packet sniffing using Scapy."""
    print(f"[*] Starting packet capture on interface: {INTERFACE}")
    sniff(prn=packet_handler, iface=INTERFACE, count=PACKET_COUNT, store=False)

def pyshark_sniff():
    """Capture packets using PyShark."""
    PCAP_FILE_PATH = os.path.abspath(PCAP_FILE)
    print(f"[*] Starting PyShark capture on: {INTERFACE}")
    print(f"[+] PCAP file will be saved at: {PCAP_FILE_PATH}")

    try:
        capture = pyshark.LiveCapture(
            interface=INTERFACE,
            output_file=PCAP_FILE_PATH,
            tshark_path=TSHARK_PATH
        )

        for packet in capture.sniff_continuously(packet_count=PACKET_COUNT):
            try:
                # Ensure packet has an IP layer
                src_ip = packet.ip.src if hasattr(packet, "ip") else "N/A"
                dst_ip = packet.ip.dst if hasattr(packet, "ip") else "N/A"
                highest_layer = packet.highest_layer if hasattr(packet, "highest_layer") else "Unknown"
                length = packet.length if hasattr(packet, "length") else "Unknown"

                print(f"[+] PyShark Captured Packet | {highest_layer} | {src_ip} → {dst_ip} | Length: {length} bytes")

            except AttributeError as e:
                print(f"[!] Skipped packet due to missing attributes: {e}")

        print(f"[✅] Packets captured and saved to: {PCAP_FILE_PATH}")

    except Exception as e:
        print(f"[!] PyShark Sniffing Error: {e}")

def run_pyshark_process():
    """Function to run PyShark in a separate process."""
    pyshark_sniff()

def run_sniffer():
    """Runs the packet sniffer in separate threads for Scapy and a separate process for PyShark."""
    
    # Thread for Scapy-based live sniffing
    scapy_thread = threading.Thread(target=start_sniffing, daemon=True)
    scapy_thread.start()

    # Process for PyShark-based packet capture
    pyshark_process = multiprocessing.Process(target=run_pyshark_process, daemon=True)
    pyshark_process.start()

    print("[*] Scapy and PyShark sniffers running in background...")

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")  # Clear console
    print("[*] Initializing Packet Capturing Module...\n")

    setup_database()  # Ensure database is set up

    # Run packet capturing in separate threads and processes
    run_sniffer()

    try:
        while True:  # Keep script running
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture...")
