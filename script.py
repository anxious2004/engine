import os
import socket
import webbrowser
import multiprocessing
import packet  # Import the main capture module

def resolve_domain(domain):
    """Resolve a domain name to its IP address."""
    try:
        
        ip = socket.gethostbyname(domain)
        print(f"[+] Resolved {domain} to {ip}")
        return ip
    except socket.gaierror:
        print(f"[!] Failed to resolve {domain}")
        return None

def get_script_input():
    """Prompt the user to enter a script dynamically."""
    print("\nEnter your script (type 'RUN' to start capturing):")
    targets = []
    
    while True:
        line = input("> ").strip()
        if line.upper() == "RUN":
            break
        if line.startswith("CAPTURE FROM "):
            domain = line.replace("CAPTURE FROM ", "").strip()
            ip = resolve_domain(domain)
            if ip:
                targets.append(ip)
                open_browser = input(f"[?] Open {domain} in browser? (y/n): ").strip().lower()
                if open_browser == 'y':
                    webbrowser.open(f"http://{domain}")
        else:
            print("[!] Invalid command. Use 'CAPTURE FROM <website>'")

    return targets

def start_capture(target_ips):
    """Start packet capturing with the resolved IPs."""
    if not target_ips:
        print("[!] No valid targets found. Exiting.")
        return
    
    print(f"[DEBUG] Resolved Target IPs: {target_ips}")  # Debugging step
    
    # Ensure only one target IP is passed
    for target_ip in target_ips:
        packet.run_sniffer(target_ip)  # Pass each IP individually

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")  # Clear console
    print("[*] Script Engine Started...\n")

    target_ips = get_script_input()  # Get script input from user
    start_capture(target_ips)  # Start capturing based on script
