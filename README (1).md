# 🕵️ SubHunter — Passive + Active Subdomain Reconnaissance Tool

A Python CLI tool that discovers subdomains of a target domain using two techniques:

1. **Passive** — queries [crt.sh](https://crt.sh) (public Certificate Transparency logs) to find subdomains that have ever had an SSL certificate issued, without sending a single packet to the target.
2. **Active** — DNS brute-forces a wordlist of common subdomain names (`www`, `mail`, `api`, `staging`, `vpn`, etc.) and resolves them concurrently using a thread pool.

## Why I built this
During my penetration testing labs I used Nmap and Sublist3r for network reconnaissance and asset discovery. SubHunter combines the two enumeration approaches I found most useful — passive OSINT and active DNS brute-forcing — into a single lightweight script with no external dependencies beyond the Python standard library.

## Features
- Zero third-party dependencies — pure Python standard library (`socket`, `urllib`, `concurrent.futures`)
- Multi-threaded DNS resolution for fast active enumeration
- Passive certificate-transparency lookup (no traffic sent to target)
- Custom wordlist support
- Save results to file for reporting

## Usage
```bash
# Full scan (passive + active)
python subhunter.py -d example.com

# Passive only (OSINT, zero direct contact with target)
python subhunter.py -d example.com --passive-only

# Active only (DNS brute-force)
python subhunter.py -d example.com --active-only

# Custom wordlist
python subhunter.py -d example.com --wordlist my_wordlist.txt

# Save results
python subhunter.py -d example.com -o results.txt
```

## Example output
```
============================================================
 RESULTS for example.com  (12 total)
============================================================
  api.example.com                              93.184.216.34
  mail.example.com                             93.184.216.35
  www.example.com                              93.184.216.34
  ...
```
## Screen Shot 
<img width="897" height="885" alt="image" src="https://github.com/user-attachments/assets/4bf847cb-e9cb-4b9f-afba-dbfa84a373e0" />

## Tech Stack
`Python 3` `socket` `urllib` `concurrent.futures`

## Disclaimer
For authorized security testing and educational purposes only. Only run this against domains you own or have explicit written permission to test.

---
Built by **Nihara Dewindini** — Cyber Security Undergraduate, SLIIT
