#!/usr/bin/env python3
import socket
import sys
import datetime

# Sentinel Recon - Simple Port Scanner
# Part of the Cyber Sentinel Red Team Arsenal

def banner():
    print("-" * 50)
    print("      🔴 SENTINEL RECON: TARGET ACQUISITION 🔴")
    print("-" * 50)

def scan_target(target, ports):
    try:
        print(f"[*] Scanning Target: {target}")
        print(f"[*] Time Started: {datetime.datetime.now()}")
        print("-" * 50)
        
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                
                # Returns 0 if connection is successful
                result = s.connect_ex((target, port))
                
                if result == 0:
                    try:
                        # Try to grab banner
                        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner_data = s.recv(1024).decode().strip()
                        print(f"[+] Port {port} is OPEN | Banner: {banner_data[:50]}...")
                    except:
                        print(f"[+] Port {port} is OPEN")
                s.close()
            except KeyboardInterrupt:
                print("\n[!] Exiting Program.")
                sys.exit()
            except socket.error:
                print(f"[!] Could not connect to server.")
                sys.exit()

    except KeyboardInterrupt:
        print("\n[!] Exiting Program.")
        sys.exit()
    except socket.gaierror:
        print("\n[!] Hostname could not be resolved.")
        sys.exit()

if __name__ == "__main__":
    banner()
    if len(sys.argv) == 2:
        target_ip = sys.argv[1]
        # Common ports to scan
        target_ports = [21, 22, 23, 25, 53, 80, 110, 443, 3389, 8080] 
        scan_target(target_ip, target_ports)
    else:
        print("[?] Usage: python3 sentinel_recon.py <Target IP>")
