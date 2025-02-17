from scapy.all import rdpcap, wrpcap

def filter_packets(packets, src_ip=None, dst_ip=None, extract_all=False):
    filtered_packets = []
    
    for packet in packets:
        if packet.haslayer("IP"):
            packet_src = packet["IP"].src
            packet_dst = packet["IP"].dst
            
            if src_ip and packet_src != src_ip:
                continue
            if dst_ip and packet_dst != dst_ip:
                continue
            
            filtered_packets.append(packet)
            
            if extract_all and packet.haslayer("Raw"):
                print(f"Packet from {packet_src} → {packet_dst}")
                print(packet["Raw"].load)
                print("-" * 50)
    
    return filtered_packets
def load_detail():
    pcap_file = input("Enter the path to the PCAP file: ")
    packets = rdpcap(pcap_file)
    
    src_ip = input("Enter Source IP to filter (leave blank for all): ").strip() or None
    dst_ip = input("Enter Destination IP to filter (leave blank for all): ").strip() or None
    extract_all = input("Do you want to extract entire data? (yes/no): ").strip().lower() == "yes"
    
    filtered_packets = filter_packets(packets, src_ip, dst_ip, extract_all)
    
    print(f"Total Packets Found: {len(filtered_packets)}")
    
    save_output = input("Do you want to save the filtered packets to a new PCAP file? (yes/no): ").strip().lower()
    if save_output == "yes":
        output_file = input("Enter output PCAP filename: ")
        wrpcap(output_file, filtered_packets)
        print(f"Filtered packets saved to {output_file}")


# def main():
#     pcap_file = input("Enter the path to the PCAP file: ")
#     packets = rdpcap(pcap_file)
    
#     src_ip = input("Enter Source IP to filter (leave blank for all): ").strip() or None
#     dst_ip = input("Enter Destination IP to filter (leave blank for all): ").strip() or None
#     extract_all = input("Do you want to extract entire data? (yes/no): ").strip().lower() == "yes"
    
#     filtered_packets = filter_packets(packets, src_ip, dst_ip, extract_all)
    
#     print(f"Total Packets Found: {len(filtered_packets)}")
    
#     save_output = input("Do you want to save the filtered packets to a new PCAP file? (yes/no): ").strip().lower()
#     if save_output == "yes":
#         output_file = input("Enter output PCAP filename: ")
#         wrpcap(output_file, filtered_packets)
#         print(f"Filtered packets saved to {output_file}")

# if __name__ == "__main__":
#     main()
