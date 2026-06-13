"""
LAB-05: Real Shodan OSINT Agent
=================================
Estimated time: 20 minutes
Mirrors: Hour 2 Block 1

LEARNING OBJECTIVES
- Use the real Shodan API to retrieve public internet data
- Build a simple OSINT agent that reasons over Shodan results
- Understand the attacker's OSINT process from the defender's perspective
- Learn what your organisation looks like to an attacker

PREREQUISITE
- Shodan API key in .env (free at https://account.shodan.io)
- pip install shodan

TASKS
1. Run a Shodan search for exposed Flask debug mode
2. Task: search for your institution's IP range or domain
3. Task: build an agent that prioritises Shodan findings by risk
4. Task: produce a defensive report from the attacker's view
"""

import sys, os, json
sys.path.insert(0, '.')
from dotenv import load_dotenv
load_dotenv()

from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

llm = get_llm()
DIVIDER = "=" * 60

SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")

if not SHODAN_KEY or SHODAN_KEY == "your-shodan-key-here":
    print("Shodan API key not set. Using simulated data for this lab.")
    print("Get a free key at https://account.shodan.io\n")
    SIMULATED = True
else:
    import shodan
    api = shodan.Shodan(SHODAN_KEY)
    SIMULATED = False


def shodan_query(query, limit=5):
    if SIMULATED:
        return {
            "total": 1247,
            "query": query,
            "matches": [
                {"ip_str": "x.x.x.1", "port": 5000, "org": "Kanpur University",
                 "product": "Werkzeug httpd", "version": "2.3.0",
                 "location": {"country_name": "United Kingdom"},
                 "vulns": {"CVE-2024-001": {"cvss": 7.5}},
                 "data": "HTTP/1.1 200 OK\nServer: Werkzeug/2.3.0\nX-Debug: true\n"},
                {"ip_str": "x.x.x.2", "port": 5000, "org": "Research Institute",
                 "product": "Flask", "version": "2.3.0",
                 "location": {"country_name": "Germany"},
                 "vulns": {},
                 "data": "HTTP/1.1 200 OK\nServer: Werkzeug/2.3.0 Python/3.11\n"},
            ]
        }
    try:
        results = api.search(query, limit=limit)
        return {
            "total": results["total"],
            "query": query,
            "matches": [{
                "ip_str": r.get("ip_str", ""),
                "port": r.get("port", 0),
                "org": r.get("org", ""),
                "product": r.get("product", ""),
                "version": r.get("version", ""),
                "location": r.get("location", {}),
                "vulns": r.get("vulns", {}),
                "data": r.get("data", "")[:300],
            } for r in results["matches"][:limit]]
        }
    except Exception as e:
        return {"error": str(e), "total": 0, "matches": []}


# ──────────────────────────────────────────────────────────────
# EXERCISE 1: Exposed Flask debug mode
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 1: Finding exposed Flask debug mode via Shodan")
print(DIVIDER)

query = 'product:"Werkzeug httpd" "Werkzeug Debugger"'
results = shodan_query(query, limit=3)

print(f"Query: {query}")
print(f"Total results globally: {results.get('total', 'N/A')}")
print(f"Sample results:")
for m in results.get("matches", [])[:3]:
    print(f"  {m['ip_str']}:{m['port']} | {m.get('org','')} | {m.get('location',{}).get('country_name','')} | CVEs: {list(m.get('vulns',{}).keys())}")

response = llm.invoke([
    SystemMessage(content="You are a threat intelligence analyst. Analyse Shodan results from a defender's perspective."),
    HumanMessage(content=f"""Shodan results for exposed Flask debug mode:
{json.dumps(results, indent=2)}

Provide:
1. What an attacker does with this in the next 5 minutes
2. The business impact if one of these is a financial institution
3. Three defensive actions an organisation can take TODAY
4. Why this exposure exists (what development practice caused it)
Keep to 12 lines.""")
])
print(f"\nIntelligence Analysis:\n{response.content}")


# ──────────────────────────────────────────────────────────────
# TASK 1: Search for exposed databases
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 1: Exposed PostgreSQL databases")
print(DIVIDER)

# TODO: Try different Shodan queries to find different exposures
# Suggestions to try:
# 'product:PostgreSQL port:5432 country:GB'
# 'product:MongoDB port:27017'
# 'product:Elasticsearch port:9200'
# 'apache has_vuln:true'

YOUR_QUERY = "product:PostgreSQL port:5432"
results = shodan_query(YOUR_QUERY, limit=5)

print(f"Query: {YOUR_QUERY}")
print(f"Total: {results.get('total', 'N/A')}")
for m in results.get("matches", [])[:3]:
    vulns = list(m.get("vulns", {}).keys())
    print(f"  {m['ip_str']}:{m['port']} | {m.get('org','')} | CVEs: {vulns}")

response = llm.invoke([HumanMessage(content=f"""Analyse these exposed database results:
{json.dumps(results, indent=2)}

From an attacker's perspective: what is the value of finding these?
From a defender's perspective: why are these exposed and what is the fix?
Which finding is highest priority? Why?""")])
print(f"\n{response.content}")


# ──────────────────────────────────────────────────────────────
# TASK 2: Risk prioritisation agent
# The agent receives multiple Shodan findings and prioritises them
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Risk prioritisation from multiple Shodan queries")
print(DIVIDER)

all_findings = []

queries_to_run = [
    ('flask_debug', 'product:"Werkzeug httpd" debug'),
    ('open_postgres', 'product:PostgreSQL port:5432'),
    ('apache_vulns', 'apache has_vuln:true'),
]

for name, q in queries_to_run:
    r = shodan_query(q, limit=2)
    all_findings.append({
        "category": name,
        "query": q,
        "total_exposed": r.get("total", 0),
        "sample": r.get("matches", [])[:2]
    })
    print(f"  {name}: {r.get('total', 0)} exposed globally")


# Summarise counts only to stay under Groq 100K token limit
risk_summary = [
    {"category": f["category"], "total_exposed": f["total_exposed"]}
    for f in all_findings
]

response = llm.invoke([HumanMessage(content=(
    "You are a CISO reviewing Shodan exposure data. "
    "Rank these three exposure types by risk (Critical/High/Medium/Low). "
    "For each give: business impact, exploitation likelihood, recommended action.\n\n"
    f"Data: {json.dumps(risk_summary, indent=2)}"
))])
print(response.content)
# TASK 3: Attacker's view of your institution
# Search Shodan for your own institution's IP range
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 3: What does your institution look like to an attacker?")
print(DIVIDER)

# TODO: Replace with your institution's domain or IP range
# This is PASSIVE — Shodan already scanned these, you are just reading
# Example: 'org:"University of Manchester"'
# Example: 'net:192.168.0.0/24' (use your actual range)

YOUR_INSTITUTION_QUERY = 'org:"Kanpur University"'

print(f"Searching Shodan for: {YOUR_INSTITUTION_QUERY}")
print("(Replace with your actual institution name or IP range)")

results = shodan_query(YOUR_INSTITUTION_QUERY, limit=5)
print(f"Total exposed services found: {results.get('total', 0)}")

if results.get("matches"):
    response = llm.invoke([HumanMessage(content=f"""An attacker has run Shodan on your institution.
Results:
{json.dumps(results, indent=2)}

Write a short attack planning document FROM THE ATTACKER'S PERSPECTIVE:
- Most valuable entry points
- Estimated time to initial access
- Estimated time to sensitive data
- What defences might be in place (infer from the data)
Then flip perspective: what should the defender do THIS WEEK?""")])
    print(response.content)
else:
    print("No results found (or simulated mode). Try a different search term.")
