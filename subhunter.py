#!/usr/bin/env python3
"""
SubHunter - Passive + Active Subdomain Reconnaissance Tool
Author: Nihara Dewindini

Combines two subdomain discovery techniques:
  1. Passive: queries crt.sh (Certificate Transparency logs) - no traffic sent to the target
  2. Active: DNS brute-force against a wordlist of common subdomain names

Usage:
    python subhunter.py -d example.com
    python subhunter.py -d example.com --active-only
    python subhunter.py -d example.com --passive-only
    python subhunter.py -d example.com -o results.txt
"""

import argparse
import socket
import sys
import json
import urllib.request
import urllib.error
import concurrent.futures

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "admin",
    "portal", "api", "dev", "staging", "test", "vpn", "remote", "blog",
    "shop", "store", "app", "mobile", "secure", "cdn", "static", "media",
    "support", "help", "docs", "status", "beta", "demo", "login", "dashboard",
    "cpanel", "webdisk", "autodiscover", "m", "old", "new", "internal",
]


def banner():
    print(r"""
   _____       _     _   _             _
  / ____|     | |   | | | |           | |
 | (___  _   _| |__ | |_| |_   _ _ __ | |_ ___ _ __
  \___ \| | | | '_ \| __| | | | | '_ \| __/ _ \ '__|
  ____) | |_| | |_) | |_| | |_| | | | | ||  __/ |
 |_____/ \__,_|_.__/ \__|_|\__,_|_| |_|\__\___|_|

 Passive + Active Subdomain Recon | by Nihara Dewindini
""")


def passive_lookup(domain):
    """Query crt.sh certificate transparency logs for known subdomains."""
    found = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SubHunter/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name.endswith(domain) and "*" not in name:
                    found.add(name)
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
        print(f"[!] Passive lookup failed: {e}")
    return found


def resolve(sub_domain):
    """Try to resolve a subdomain via DNS. Returns (subdomain, ip) or None."""
    try:
        ip = socket.gethostbyname(sub_domain)
        return sub_domain, ip
    except socket.gaierror:
        return None


def active_bruteforce(domain, wordlist, threads=20):
    """Brute-force common subdomain names via DNS resolution."""
    found = {}
    candidates = [f"{word}.{domain}" for word in wordlist]
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(resolve, candidates)
        for r in results:
            if r:
                sub, ip = r
                found[sub] = ip
    return found


def main():
    parser = argparse.ArgumentParser(description="SubHunter - Subdomain Reconnaissance Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", help="Save results to a file")
    parser.add_argument("--passive-only", action="store_true", help="Only run passive (crt.sh) lookup")
    parser.add_argument("--active-only", action="store_true", help="Only run active DNS brute-force")
    parser.add_argument("--wordlist", help="Path to a custom subdomain wordlist file")
    args = parser.parse_args()

    banner()
    domain = args.domain.strip().lower()
    all_results = {}

    if not args.active_only:
        print(f"[*] Running passive lookup (crt.sh) for {domain} ...")
        passive_found = passive_lookup(domain)
        print(f"[+] Passive: {len(passive_found)} unique names found in certificate logs\n")
        for name in sorted(passive_found):
            all_results.setdefault(name, "unresolved (cert-log only)")

    if not args.passive_only:
        wordlist = DEFAULT_WORDLIST
        if args.wordlist:
            with open(args.wordlist) as f:
                wordlist = [line.strip() for line in f if line.strip()]
        print(f"[*] Running active DNS brute-force ({len(wordlist)} candidates) ...")
        active_found = active_bruteforce(domain, wordlist)
        print(f"[+] Active: {len(active_found)} subdomains resolved via DNS\n")
        all_results.update(active_found)

    print("=" * 60)
    print(f" RESULTS for {domain}  ({len(all_results)} total)")
    print("=" * 60)
    for sub, ip in sorted(all_results.items()):
        print(f"  {sub:<45} {ip}")

    if args.output:
        with open(args.output, "w") as f:
            for sub, ip in sorted(all_results.items()):
                f.write(f"{sub}\t{ip}\n")
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)
