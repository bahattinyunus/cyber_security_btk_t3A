#!/usr/bin/env python3
import hashlib
import sys
import os

# Sentinel Integrity - File Integrity Monitor
# Part of the Cyber Sentinel Blue Team Arsenal

def banner():
    print("-" * 50)
    print("      🔵 SENTINEL INTEGRITY: ARTIFACT VERIFICATION 🔵")
    print("-" * 50)

def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read file in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None

def verify_file(file_path, expected_hash=None):
    current_hash = calculate_hash(file_path)
    
    if current_hash:
        print(f"[*] File: {file_path}")
        print(f"[*] SHA-256: {current_hash}")
        
        if expected_hash:
            if current_hash == expected_hash:
                print("[+] INTEGRITY VERIFIED: Match.")
            else:
                print("[!] SECURITY ALERT: HASH MISMATCH! File may be compromised.")
    else:
        print(f"[!] File not found: {file_path}")

if __name__ == "__main__":
    banner()
    if len(sys.argv) >= 2:
        target_file = sys.argv[1]
        expected = sys.argv[2] if len(sys.argv) > 2 else None
        verify_file(target_file, expected)
    else:
        print("[?] Usage: python3 sentinel_integrity.py <File Path> [Expected Hash]")
