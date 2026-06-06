---
name: pt-gaining-access
description: >
  Controlled exploitation of confirmed vulnerabilities to establish initial access.
  Use when you have confirmed scan findings and need to attempt exploitation, obtain
  proof-of-concept access, or prepare evidence packages.
  REQUIRES explicit authorization and a rollback plan before proceeding.
  Activates on: "exploit the vulnerability", "attempt access", "proof of concept", "gain a foothold".
---

# Penetration Test — Gaining Access (Exploitation)

## Authorization (mandatory — do not skip)
1. Confirm authorization explicitly covers exploitation (not just scanning)
2. Confirm rollback plan exists for each target
3. Confirm test window is active
4. Notify client security team that exploitation phase is beginning
5. If any above is unconfirmed: STOP and escalate

## Scope of this phase
- Only attempt exploitation of findings from the scanning phase
- Use minimum payload needed to confirm exploitability
- Do NOT establish persistence at this stage unless separately authorized
- Do NOT exfiltrate real data

## Exploitation workflow

### Step 1: Prioritize by CVSS score then confidence
### Step 2: Pre-exploitation checklist per target
- [ ] Target is in scope | [ ] Rollback plan confirmed | [ ] Test window active

### Step 3: Use minimum viable payload
- SQL injection: start with `' OR '1'='1` before UNION-based extraction
- XSS: `<script>alert(document.domain)</script>` before data capture
- Command injection: `id` or `whoami` before any file operations

### Step 4: Frame impact in business terms
- What data could be accessed?
- What regulatory obligations are affected (PCI DSS, HIPAA, GDPR)?

## Evidence package per finding
