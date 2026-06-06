import sys, os, json, subprocess
sys.path.insert(0, '.')
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool
import dns.resolver

# Use a public domain that belongs to a major organization for demonstration
# We are doing PASSIVE reconnaissance only — reading public DNS records
TARGET_DOMAIN = "python.org"  # Public open-source project — safe to demo

@tool
def dns_enumerate(domain: str) -> str:
    """Enumerate DNS records for a domain using public DNS servers.
    Args:
        domain: Domain name to enumerate
    """
    results = {"domain": domain, "records": {}}
    record_types = ["A", "MX", "NS", "TXT", "CNAME"]
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8"]

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            results["records"][rtype] = [str(r) for r in answers]
        except Exception:
            results["records"][rtype] = []
    return json.dumps(results, indent=2)

@tool
def whois_lookup(domain: str) -> str:
    """Perform a WHOIS lookup on a domain.
    Args:
        domain: Domain to look up
    """
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.splitlines()
        relevant = [l for l in lines if any(k in l.lower() for k in
            ["registrar", "created", "expires", "name server", "registrant", "tech", "admin"])]
        return json.dumps({"domain": domain, "whois_summary": relevant[:20]}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})

@tool  
def certificate_transparency(domain: str) -> str:
    """Search certificate transparency logs for subdomains.
    Args:
        domain: Root domain to search
    """
    import urllib.request
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        subdomains = list(set(
            entry["name_value"].replace("*.", "")
            for entry in data[:50]
            if "name_value" in entry
        ))[:20]
        return json.dumps({"domain": domain, "subdomains_found": len(subdomains),
                          "sample": subdomains[:10]}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "note": "crt.sh may be rate limiting"})

llm = get_llm()
passive_tools = [dns_enumerate, whois_lookup, certificate_transparency]
llm_with_tools = llm.bind_tools(passive_tools)

print("=" * 60)
print(f"PASSIVE RECONNAISSANCE AGENT")
print(f"Target: {TARGET_DOMAIN} (public domain — read-only DNS queries)")
print("=" * 60)

response = llm_with_tools.invoke([
    SystemMessage(content=f"""You are performing authorized passive reconnaissance.
Target: {TARGET_DOMAIN}
Rules: Only use DNS, WHOIS, and certificate transparency — no active scanning.

Step 1: Run dns_enumerate on the target
Step 2: Run whois_lookup on the target  
Step 3: Run certificate_transparency to find subdomains

Call all three tools."""),
    HumanMessage(content=f"Perform complete passive reconnaissance on {TARGET_DOMAIN}")
])

all_results = {}
if response.tool_calls:
    tool_map = {t.name: t for t in passive_tools}
    for tc in response.tool_calls:
        print(f"\n[TOOL] {tc['name']}({tc['args']})")
        fn = tool_map.get(tc["name"])
        if fn:
            result = fn.invoke(tc["args"])
            all_results[tc["name"]] = json.loads(result)
            data = json.loads(result)
            if "error" not in data:
                print(f"  Success — got {len(str(result))} bytes of data")
            else:
                print(f"  Note: {data.get('error', 'unknown error')}")

# Now have the LLM synthesise the findings
synthesis = llm.invoke([
    SystemMessage(content="""You are an expert threat intelligence analyst.
Synthesise passive recon findings into an intelligence report covering:
1. Infrastructure overview (hosting, registrar, name servers)
2. Subdomain attack surface (interesting entries from cert transparency)
3. Technology indicators from DNS (mail servers reveal email provider etc)
4. What an attacker learns from this in under 5 minutes
5. Defensive recommendations for this organisation
Keep to 15 lines."""),
    HumanMessage(content=f"Passive recon results:\n{json.dumps(all_results, indent=2)}")
])

print(f"\n{'=' * 60}")
print("INTELLIGENCE SYNTHESIS")
print("=" * 60)
print(synthesis.content)
