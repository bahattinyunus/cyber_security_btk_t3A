#!/usr/bin/env python3
import sys
import argparse
import time
import random

# Sentinel Serial - Part of Cyber Sentinel Hardware Dominion
# Simulates a Serial Console interaction for educational purposes.
# (Real hardware interaction requires 'pyserial' library, this is a mock).

def banner():
    print("=" * 60)
    print("      🔌 SENTINEL SERIAL: HARDWARE INTERFACE 🔌")
    print("=" * 60)

def bruteforce_baudrate():
    print("[*] Auto-detecting Baud Rate...")
    common_rates = [9600, 19200, 38400, 57600, 115200]
    
    # Simulate scanning
    for rate in common_rates:
        print(f"[*] Testing {rate} bps...", end='')
        time.sleep(0.5)
        if random.choice([True, False]) and rate == 115200:
            print(" SIGNAL DETECTED!")
            return rate
        elif rate == common_rates[-1]:
             print(" SIGNAL DETECTED!") # Fallback match
             return rate
        else:
            print(" noise.")
    return 9600

def start_console(port, baud):
    print(f"\n[+] Connected to {port} at {baud} bps")
    print("[+] Opening Serial Console... (Press Ctrl+C to exit)")
    print("-" * 60)
    
    print("\nU-Boot 2024.01-rc4 (Dec 18 2025 - 12:00:00 +0000)")
    print("CPU:   ARMv8 Multi-Core")
    print("DRAM:  1 GiB")
    print("MMC:   Yes")
    print("In:    serial")
    print("Out:   serial")
    print("Err:   serial")
    print("Hit any key to stop autoboot:  0")
    print("Booting Linux Kernel...")
    print("[    0.000000] Booting Linux on physical CPU 0x0")
    print("[    1.240000] Systemd[1]: Started Network Service.")
    print("\nSentinel-IoT-Device login: ")
    
    try:
        while True:
            cmd = input("")
            if cmd.strip() == "root":
                print("Password: ")
                input("") # Simulate password entry
                print("\n# Welcome to Embedded Linux")
                print("# ")
            else:
                print(f"Unknown command or login: {cmd}")
    except KeyboardInterrupt:
        print("\n[!] Disconnected.")

if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="Sentinel Serial Console")
    parser.add_argument("--port", help="Serial Port (e.g. COM1 or /dev/ttyUSB0)", default="/dev/ttyUSB0")
    parser.add_argument("--baud", help="Baud Rate", type=int)
    
    args = parser.parse_args()
    
    baud_rate = args.baud
    if not baud_rate:
        baud_rate = bruteforce_baudrate()
        
    start_console(args.port, baud_rate)
