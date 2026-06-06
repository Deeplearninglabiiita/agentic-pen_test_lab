---
name: pt-scanning
description: >
  Performs layered vulnerability scanning on assets from reconnaissance.
  Covers host/port/service discovery, CVE-based scanning, and application-layer assessment.
  Use when moving from asset inventory to vulnerability identification, running nuclei,
  or assessing a target's attack surface.
  Activates on: "scan the target", "run vulnerability scan", "check for CVEs", "assess attack surface".
---

# Penetration Test Scanning

## Authorization
- Only scan assets explicitly listed in the recon handoff
- Confirm test window is active before starting
- Stop immediately if client systems show signs of instability

## Objectives
1. Confirm live hosts and open ports from the recon asset list
2. Fingerprint services with version information for CVE matching
3. Run vulnerability scanner against web targets
4. Flag likely false positives with confidence ratings before handoff

## Scanning layers

### Layer 1: Host and port discovery
```bash
nmap -sS -sV -sC -p- --min-rate 1000 -oA scan_output [target]
```

### Layer 2: CVE and vulnerability scanning
```bash
nuclei -u [target] -t cves/ -severity critical,high,medium
nikto -h [target] -output nikto_output.txt
```

### Layer 3: Application-layer (web targets only)
- Directory enumeration, JavaScript analysis, API schema discovery

## Confidence tagging
CONFIRMED | LIKELY | POSSIBLE | FALSE_POSITIVE

## Output template
