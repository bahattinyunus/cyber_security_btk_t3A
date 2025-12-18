#!/usr/bin/env python3
import socket
import sys

# Sentinel Whois - OSINT Data Gathering
# Part of the Cyber Sentinel Intel Arsenal

def banner():
    print("-" * 50)
    print("      👁️ SENTINEL WHOIS: INTELLIGENCE GATHERING 👁️")
    print("-" * 50)

def perform_whois(domain):
    print(f"[*] Querying WHOIS Database for: {domain}")
    try:
        # Connect to a WHOIS server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("whois.iana.org", 43))
        s.send(f"{domain}\r\n".encode())
        
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        
        print(response.decode(errors='ignore'))
        
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    banner()
    if len(sys.argv) == 2:
        target_domain = sys.argv[1]
        perform_whois(target_domain)
    else:
        print("[?] Usage: python3 sentinel_whois.py <Domain>")
