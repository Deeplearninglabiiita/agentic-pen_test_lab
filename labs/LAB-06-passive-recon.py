"""
LAB-06: Passive Reconnaissance Agent
======================================
Estimated time: 20 minutes
Mirrors: Hour 2 Block 2

LEARNING OBJECTIVES
- Perform legal passive reconnaissance using public data sources
- Build an agent that aggregates intelligence from multiple passive sources
- Understand what an attacker learns before touching a target
- Produce a structured intelligence report

ALL TECHNIQUES IN THIS LAB ARE LEGAL:
- DNS lookups use public resolvers reading public records
- WHOIS reads publicly registered data
- Certificate transparency reads public browser logs
- No packets are sent to the target system

TASKS
1. Run passive recon on python.org (safe public target)
2. Run on a domain of your choice
3. Build an agent that connects findings across sources
4. Produce an attack surface map
"""

import sys, json, subprocess
sys.path.insert(0, '.')
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("dnspython not installed. Run: pip install dnspython")

llm = get_llm()
DIVIDER = "=" * 60


def dns_lookup(domain, record_types=None):
    if not DNS_AVAILABLE:
        return {"domain": domain, "error": "dnspython not installed", "records": {}}
    if record_types is None:
        record_types = ["A", "MX", "NS", "TXT"]
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8"]
    results = {"domain": domain, "records": {}}
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            results["records"][rtype] = [str(r) for r in answers]
        except Exception:
            results["records"][rtype] = []
    return results


def whois_lookup(domain):
    try:
        result = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.splitlines()
        relevant = [l for l in lines if any(k in l.lower() for k in
            ["registrar", "created", "expir", "name server", "registrant"])]
        return {"domain": domain, "data": relevant[:15]}
    except Exception as e:
        return {"domain": domain, "error": str(e)}


def cert_transparency(domain):
    import urllib.request
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        subdomains = list(set(
            e["name_value"].replace("*.", "").strip()
            for e in data[:100]
            if "name_value" in e and "\n" not in e["name_value"]
        ))
        return {"domain": domain, "subdomain_count": len(subdomains),
                "subdomains": sorted(subdomains)[:20]}
    except Exception as e:
        return {"domain": domain, "error": str(e),
                "note": "crt.sh may be temporarily unavailable"}


def full_passive_recon(target_domain):
    print(f"\nRunning passive recon on: {target_domain}")
    print("(DNS queries only — zero contact with target systems)\n")

    print("  [1/3] DNS enumeration...")
    dns_results = dns_lookup(target_domain)

    print("  [2/3] WHOIS lookup...")
    whois_results = whois_lookup(target_domain)

    print("  [3/3] Certificate transparency...")
    ct_results = cert_transparency(target_domain)

    return {
        "target": target_domain,
        "dns": dns_results,
        "whois": whois_results,
        "certificate_transparency": ct_results
    }


# ──────────────────────────────────────────────────────────────
# EXERCISE 1: Passive recon on python.org
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 1: Passive recon on python.org (safe public target)")
print(DIVIDER)

recon_data = full_passive_recon("python.org")

# Show raw data summary
dns = recon_data["dns"]["records"]
ct = recon_data["certificate_transparency"]
print(f"\nRaw findings:")
print(f"  A records: {dns.get('A', [])}")
print(f"  Name servers: {dns.get('NS', [])}")
print(f"  MX records: {dns.get('MX', [])}")
print(f"  Subdomains found: {ct.get('subdomain_count', 0)}")
if ct.get("subdomains"):
    print(f"  Sample subdomains: {ct['subdomains'][:5]}")

# Intelligence synthesis
response = llm.invoke([
    SystemMessage(content="You are a threat intelligence analyst producing an attack surface map."),
    HumanMessage(content=f"""Passive reconnaissance results:
{json.dumps(recon_data, indent=2)}

Produce an attack surface analysis:
1. Infrastructure overview (hosting provider, registrar, CDN if any)
2. Interesting subdomains (dev, staging, admin, api) and why they matter
3. Technology indicators from DNS (mail provider reveals email security)
4. What an attacker learns in 5 minutes from this data
5. Top 3 attack vectors suggested by this passive data
6. What is NOT visible from passive recon (requires active scanning)

Keep each section to 3 lines.""")
])
print(f"\nIntelligence Synthesis:\n{response.content}")


# ──────────────────────────────────────────────────────────────
# TASK 1: Choose your own target
# Pick any public domain (not private networks)
# Run the full passive recon and analyse the results
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 1: Passive recon on your chosen domain")
print(DIVIDER)

# TODO: Replace with any public domain you want to investigate
# Good choices for research:
# - Your university's domain
# - A government agency's public site
# - An open-source project domain
# DO NOT use private companies without permission

YOUR_TARGET = "example.com"

print(f"Target: {YOUR_TARGET}")
your_recon = full_passive_recon(YOUR_TARGET)

response = llm.invoke([HumanMessage(content=f"""Passive recon results for {YOUR_TARGET}:
{json.dumps(your_recon, indent=2)}

From an attacker's perspective write:
1. What entry points would you prioritise and why?
2. What does the subdomain structure reveal about internal architecture?
3. What social engineering opportunities exist from this data?
4. What active reconnaissance would you do next (and what is the legal risk)?""")])
print(response.content)


# ──────────────────────────────────────────────────────────────
# TASK 2: Compare two organisations
# Run passive recon on two domains in the same sector
# Ask the agent to compare their security posture from passive data alone
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Compare two organisations (passive data only)")
print(DIVIDER)

# Two public domains to compare
DOMAIN_A = "apache.org"
DOMAIN_B = "nginx.org"

print(f"Comparing {DOMAIN_A} vs {DOMAIN_B}...")

recon_a = full_passive_recon(DOMAIN_A)
recon_b = full_passive_recon(DOMAIN_B)

response = llm.invoke([HumanMessage(content=f"""Compare the attack surface of two open-source projects
based solely on passive reconnaissance data.

{DOMAIN_A} data:
{json.dumps({'dns': recon_a['dns']['records'], 'subdomains': recon_a['certificate_transparency'].get('subdomain_count', 0)}, indent=2)}

{DOMAIN_B} data:
{json.dumps({'dns': recon_b['dns']['records'], 'subdomains': recon_b['certificate_transparency'].get('subdomain_count', 0)}, indent=2)}

Compare:
1. Attack surface size (which has more exposure?)
2. Infrastructure diversity (centralised vs distributed?)
3. What each reveals about their internal architecture
4. Which presents a larger attack surface from passive data alone?
5. What you CANNOT determine from passive data (and why that matters)""")])
print(response.content)
