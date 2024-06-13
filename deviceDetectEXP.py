deviceDetectEXP.py

import argparse
from scapy.all import *

def scan_network(ip_range):
    print("Scanning network for devices...\n")
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=5, verbose=False)
        
        devices = [(pkt[1].psrc, pkt[1].src) for pkt in ans]

        if devices:
            print("Found active devices:")
            for i, (ip, mac) in enumerate(devices, start=1):
                print(f"Device {i}:")
                print(f"  IP Address: {ip}")
                print(f"  MAC Address: {mac}")
                print("  Status: Online")
                print()
        else:
            print("No active devices found in the specified IP range.")
    except Exception as e:
        print(f"An error occurred during scanning: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="LAN Network Monitoring Tool")
    parser.add_argument("command", choices=["scan"], help="Command to execute")
    parser.add_argument("--range", "-r", help="IP range to scan (e.g., 192.168.1.1/24)")
    args = parser.parse_args()

    if args.command == "scan":
        if args.range:
            scan_network(args.range)
        else:
            print("Error: IP range not specified.")
            parser.print_help()

if __name__ == "__main__":
    main()