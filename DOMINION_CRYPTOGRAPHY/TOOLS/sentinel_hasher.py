#!/usr/bin/env python3
import hashlib
import sys
import argparse
import os

# Sentinel Hasher - Part of Cyber Sentinel Cryptography Dominion
# Generates Message Digests (Hashes) for strings and files.

def banner():
    print("=" * 60)
    print("      🔐 SENTINEL HASHER: INTEGRITY VERIFICATION 🔐")
    print("=" * 60)

def hash_string(text):
    print(f"\n[*] Input String: '{text}'")
    print("-" * 60)
    print(f"MD5    : {hashlib.md5(text.encode()).hexdigest()}")
    print(f"SHA1   : {hashlib.sha1(text.encode()).hexdigest()}")
    print(f"SHA256 : {hashlib.sha256(text.encode()).hexdigest()}")
    print(f"SHA512 : {hashlib.sha512(text.encode()).hexdigest()}")
    print("-" * 60)

def hash_file(filepath):
    if not os.path.exists(filepath):
        print(f"\n[!] Error: File '{filepath}' not found.")
        return

    print(f"\n[*] Hashing File: {filepath}")
    print(f"[*] Size: {os.path.getsize(filepath)} bytes")
    print("-" * 60)

    # Initialize algorithms
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        print(f"MD5    : {md5.hexdigest()}")
        print(f"SHA1   : {sha1.hexdigest()}")
        print(f"SHA256 : {sha256.hexdigest()}")
    except Exception as e:
        print(f"[!] Error reading file: {e}")
    
    print("-" * 60)

if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="Sentinel Hasher Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--string", help="String to hash")
    group.add_argument("-f", "--file", help="File path to hash")
    
    args = parser.parse_args()

    if args.string:
        hash_string(args.string)
    elif args.file:
        hash_file(args.file)
