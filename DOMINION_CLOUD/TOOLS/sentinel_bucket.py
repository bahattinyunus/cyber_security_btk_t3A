#!/usr/bin/env python3
import requests
import sys
import argparse

# Sentinel Bucket - Part of Cyber Sentinel Cloud Dominion
# Checks if an S3 bucket is publicly accessible (LIST or GET).

def banner():
    print("=" * 60)
    print("      ☁️ SENTINEL BUCKET: S3 RECONNAISSANCE ☁️")
    print("=" * 60)

def check_bucket(bucket_name):
    # AWS S3 URL patterns
    urls = [
        f"http://{bucket_name}.s3.amazonaws.com",
        f"http://s3.amazonaws.com/{bucket_name}"
    ]

    print(f"[*] Probing Bucket: '{bucket_name}'")
    print("-" * 60)

    for url in urls:
        try:
            r = requests.get(url, timeout=5)
            status = r.status_code
            
            if status == 200:
                print(f"[+] PUBLIC ACCESS OPEN! (Tags: LIST/GET Allowed)")
                print(f"    URL: {url}")
                print(f"    Code: 200 OK")
                return # Found it
            elif status == 403:
                print(f"[-] Access Denied (Protected).")
                print(f"    URL: {url}")
                print(f"    Code: 403 Forbidden")
            elif status == 404:
                print(f"[!] Bucket Not Found.")
                print(f"    URL: {url}")
            else:
                print(f"[?] Code: {status} URL: {url}")
                
        except requests.exceptions.RequestException as e:
            print(f"[!] Connection Error: {e}")
    
    print("-" * 60)

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        print("Usage: python3 sentinel_bucket.py <bucket_name>")
        sys.exit(1)
    
    bucket = sys.argv[1]
    check_bucket(bucket)
