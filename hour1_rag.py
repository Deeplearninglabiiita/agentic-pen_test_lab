import sys
sys.path.insert(0, '.')
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage

llm = get_llm()

KB = [
    {"id": "cve-werkzeug", "text": "CVE-2024-001: Werkzeug 2.3.0 path traversal vulnerability. CVSS 7.5. Patch: upgrade to 2.3.1."},
    {"id": "mitre-t1190", "text": "MITRE T1190: Exploit Public-Facing Application. Used for initial access by APT groups including Cobalt Strike operators."},
    {"id": "ioc-185", "text": "IOC: 185.220.101.5 is a known Cobalt Strike C2 node. Confidence: HIGH. Last active: November 2024. Source: ThreatFox."},
    {"id": "sqli-technique", "text": "SQL injection UNION-based extraction: payload ' UNION SELECT username,password FROM users-- extracts credentials when error messages are suppressed."},
    {"id": "flask-debug", "text": "Flask debug=True exposes the Werkzeug interactive debugger at /console. Unauthenticated remote code execution possible if publicly accessible."},
]

queries = [
    "Our Flask server contacted 185.220.101.5. What happened and what do we do?",
    "We found debug=True on our production Flask app. How serious is this?",
    "Is our web server compromised?",  # Intentionally vague — tests reasoning under uncertainty
]

for query in queries:
    print(f"\n{'=' * 60}")
    print(f"QUERY: {query}")
    print("=" * 60)

    # Keyword search
    words = set(query.lower().split())
    keyword_hits = []
    for doc in KB:
        if len(words & set(doc["text"].lower().split())) > 0:
            keyword_hits.append(doc["id"])

    print(f"Keyword search hits: {keyword_hits if keyword_hits else 'NONE'}")

    # Agentic RAG
    context = "\n".join(f"[{d['id']}] {d['text']}" for d in KB)
    response = llm.invoke([HumanMessage(content=f"""You are an autonomous SOC agent.

Intel database:
{context}

Task: {query}

Step 1 (REASON): What do I need to know?
Step 2 (RETRIEVE): Which document IDs are relevant? What connections exist between them?
Step 3 (ACT): What specific actions do I take in the next 30 minutes?
Step 4 (ESCALATE): What needs human decision-making vs what can I handle autonomously?""")])
    print(f"\nAgentic RAG Response:\n{response.content}")
