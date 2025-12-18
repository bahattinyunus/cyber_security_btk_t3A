#!/usr/bin/env python3
import sys
import argparse
import itertools
import string

# Sentinel WiFi - Part of Cyber Sentinel Wireless Dominion
# Analyzes WPA2 password strength and generates wordlists.

def banner():
    print("=" * 60)
    print("      📡 SENTINEL WIFI: SIGNAL INTELLIGENCE 📡")
    print("=" * 60)

def check_strength(password):
    score = 0
    print(f"\n[*] Analyzing Password: '{password}'")
    
    # WPA2 Length Requirement
    if len(password) < 8:
        print("[-] FAILED: Too short (Min 8 chars for WPA2)")
        return
    elif len(password) > 63:
        print("[-] FAILED: Too long (Max 63 chars)")
        return
    else:
        score += 20
        print("[+] Length OK")

    # Complexity
    if any(c.isdigit() for c in password): score += 20
    if any(c.isupper() for c in password): score += 20
    if any(c.islower() for c in password): score += 20
    if any(c in string.punctuation for c in password): score += 20

    print(f"[*] Security Score: {score}/100")
    
    if score < 60:
        print("[-] WEAK: Easily crackable with dictionary attack.")
    elif score < 80:
        print("[~] MODERATE: Might take time.")
    else:
        print("[+] STRONG: Resistant to standard brute-force.")
    print("-" * 60)

def generate_wordlist(base, output):
    print(f"\n[*] Generating variations for base: '{base}'")
    print(f"[*] Output File: {output}")
    
    count = 0
    try:
        with open(output, 'w') as f:
            # Add base
            f.write(base + '\n')
            count += 1
            
            # Common mutations: Append years
            for year in range(2010, 2030):
                f.write(f"{base}{year}\n")
                f.write(f"{base}@{year}\n")
                count += 2
            
            # Append common suffixes
            suffixes = ["123", "!", ".", "123!", "pass", "admin"]
            for s in suffixes:
                f.write(f"{base}{s}\n")
                count += 1
                
            # L33t speak variations (basic)
            l33t = base.replace('e', '3').replace('a', '4').replace('o', '0').replace('i', '1')
            f.write(l33t + '\n')
            count += 1
            
        print(f"[+] Done. Generated {count} variations.")
    except Exception as e:
        print(f"[!] File Error: {e}")
    print("-" * 60)

if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="Sentinel WiFi Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--strength", help="Check WPA2 password strength")
    group.add_argument("-g", "--generate", help="Generate wordlist from base word")
    
    parser.add_argument("-o", "--output", help="Output file for wordlist", default="wordlist.txt")
    
    args = parser.parse_args()

    if args.strength:
        check_strength(args.strength)
    elif args.generate:
        generate_wordlist(args.generate, args.output)
