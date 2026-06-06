---
name: pt-planning-recon
description: >
  Defines penetration test scope and performs authorized reconnaissance using passive
  and active methods. Use when planning a test engagement, collecting target intelligence,
  building asset inventories, or preparing recon findings for the scanning phase.
  Activates on: "plan a pentest", "scope the engagement", "passive recon", "asset inventory".
---

# Pen Test Planning and Reconnaissance

## Authorization (read before proceeding)
- Confirm written authorization before touching any target
- Identify in-scope and out-of-scope assets and prohibited actions
- Note test window start and end times
- STOP and ask for confirmation if scope is unclear

## Objectives
1. Build a complete asset inventory of in-scope targets
2. Collect passive intelligence without interacting with target systems
3. Plan active reconnaissance within approved scope and rate limits
4. Produce a structured handoff document for the scanning phase

## Workflow

### Phase 1: Passive intelligence (no target interaction)
- Query DNS records (A, MX, NS, TXT, SOA)
- Search Certificate Transparency logs for subdomains
- Check Shodan/Censys for previously indexed exposure
- Review GitHub and job postings for technology stack clues

### Phase 2: Asset inventory
For each asset record: hostname, IP, confidence (HIGH/MEDIUM/LOW), asset type, source, in-scope status.

### Phase 3: Active reconnaissance (authorized scope only)
- Host discovery, service fingerprinting, web crawling
- Rate limit: no more than 10 requests/second without explicit approval

## Output template
