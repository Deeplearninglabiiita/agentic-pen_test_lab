import sys, os, json
sys.path.insert(0, '.')
from dotenv import load_dotenv
load_dotenv()

import shodan
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool

SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")
api = shodan.Shodan(SHODAN_KEY)

@tool
def shodan_search(query: str, limit: int = 5) -> str:
    """Search Shodan for publicly indexed internet hosts.
    Args:
        query: Shodan search query e.g. 'apache country:US port:80'
        limit: Maximum results to return (max 10)
    """
    try:
        results = api.search(query, limit=min(limit, 10))
        simplified = []
        for r in results["matches"][:limit]:
            simplified.append({
                "ip": r.get("ip_str", ""),
                "port": r.get("port", ""),
                "org": r.get("org", ""),
                "country": r.get("location", {}).get("country_name", ""),
                "product": r.get("product", ""),
                "version": r.get("version", ""),
                "banner": r.get("data", "")[:200],
                "vulns": list(r.get("vulns", {}).keys())[:5],
            })
        return json.dumps({
            "total_results": results["total"],
            "shown": len(simplified),
            "hosts": simplified
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})

@tool
def shodan_host_info(ip: str) -> str:
    """Get detailed Shodan information about a specific IP address.
    Args:
        ip: IP address to look up
    """
    try:
        host = api.host(ip)
        return json.dumps({
            "ip": host.get("ip_str"),
            "org": host.get("org"),
            "country": host.get("country_name"),
            "open_ports": host.get("ports", []),
            "hostnames": host.get("hostnames", []),
            "vulns": list(host.get("vulns", {}).keys()),
            "tags": host.get("tags", []),
            "last_update": host.get("last_update"),
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})

# Demonstration queries — all passive, all legal, reading public data
demo_queries = [
    ("Flask debug mode exposed", 'flask debug mode "Werkzeug Debugger"'),
    ("Exposed PostgreSQL databases", "product:PostgreSQL port:5432"),
    ("Apache with known CVEs", "apache has_vuln:true country:US"),
]

llm = get_llm()

print("=" * 60)
print("REAL SHODAN OSINT AGENT")
print("Reading publicly indexed internet data — fully legal")
print("=" * 60)

for name, query in demo_queries:
    print(f"\n{'─' * 50}")
    print(f"Intelligence Request: {name}")
    print(f"Shodan Query: {query}")
    print("─" * 50)

    # Get real Shodan data
    result = shodan_search.invoke({"query": query, "limit": 3})
    data = json.loads(result)

    if "error" in data:
        print(f"Shodan error: {data['error']}")
        print("Using simulated data for demo...")
        result = json.dumps({"total_results": 1247, "hosts": [
            {"ip": "x.x.x.x", "port": 5000, "org": "Example Org",
             "country": "United States", "product": "Flask", "vulns": []}
        ]})

    # Have the LLM reason about the results
    response = llm.invoke([
        SystemMessage(content="""You are a threat intelligence analyst.
Analyse Shodan results and provide:
1. What this exposure means for defenders
2. What an attacker would do with this information
3. The scale of the problem (use the total_results number)
4. Three specific recommendations for organizations in these results
Keep to 8 lines total."""),
        HumanMessage(content=f"Shodan results for '{name}':\n{result}")
    ])
    print(f"\nIntelligence Analysis:\n{response.content}")
