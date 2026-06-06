"""
LAB-04: RAG and Agentic RAG
============================
Estimated time: 20 minutes
Mirrors: PPT Slides 12-16, Hour 1 Block 4

LEARNING OBJECTIVES
- Understand why keyword search fails for security intelligence
- Build your own threat intelligence knowledge base
- See how Agentic RAG connects evidence across documents
- Identify the hallucination risk when knowledge base is incomplete

TASKS
1. Run default demo to see keyword search vs Agentic RAG
2. Add your own document to the knowledge base
3. Query something NOT in the knowledge base — observe hallucination risk
4. Design a knowledge base for your research domain
"""

import sys, json
sys.path.insert(0, '.')
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

llm = get_llm()
DIVIDER = "=" * 60


# ──────────────────────────────────────────────────────────────
# Base knowledge base — 5 threat intel documents
# ──────────────────────────────────────────────────────────────

BASE_KB = [
    {"id": "cve-werkzeug",
     "text": "CVE-2024-001: Werkzeug 2.3.0 path traversal vulnerability in static file serving. CVSS 7.5. Patch: upgrade to 2.3.1."},
    {"id": "mitre-t1190",
     "text": "MITRE T1190: Exploit Public-Facing Application. Used for initial access by APT groups. Often combined with T1059 for persistence."},
    {"id": "ioc-185",
     "text": "IOC: 185.220.101.5 is a Cobalt Strike C2 node. Confidence HIGH. Last active November 2024. Associated with APT group BRONZE SILHOUETTE."},
    {"id": "sqli-technique",
     "text": "SQL injection UNION extraction: ' UNION SELECT username,password FROM users-- exfiltrates credentials. Effective when error messages suppressed."},
    {"id": "flask-debug",
     "text": "Flask debug=True exposes Werkzeug debugger at /console. Allows unauthenticated remote code execution. Never deploy with debug=True."},
]


def keyword_search(query, kb, top_k=2):
    words = set(query.lower().split())
    scored = []
    for doc in kb:
        overlap = len(words & set(doc["text"].lower().split()))
        if overlap > 0:
            scored.append((overlap, doc))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [r[1] for r in scored[:top_k]]


def agentic_rag(query, kb):
    context = "\n".join(f"[{d['id']}] {d['text']}" for d in kb)
    response = llm.invoke([
        SystemMessage(content="""You are an autonomous SOC agent with threat intelligence access.
Reason across ALL available documents. Connect evidence between documents.
Always cite document IDs when making claims."""),
        HumanMessage(content=f"""Intel database:
{context}

Task: {query}

Step 1 (REASON): What do I need to determine?
Step 2 (RETRIEVE): Which document IDs are relevant? What connections exist between them?
Step 3 (ACT): What concrete actions do I take in the next 30 minutes?
Step 4 (GAPS): What is NOT in my knowledge base that I need?""")
    ])
    return response.content


# ──────────────────────────────────────────────────────────────
# EXERCISE 1: Keyword search vs Agentic RAG
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 1: Keyword search vs Agentic RAG")
print(DIVIDER)

query = "Our Flask server contacted 185.220.101.5. What happened and what do we do?"

kw_results = keyword_search(query, BASE_KB)
print(f"Query: {query}")
print(f"\nKeyword search found {len(kw_results)} documents:")
for d in kw_results:
    print(f"  [{d['id']}] {d['text'][:80]}...")

print(f"\nAgentic RAG response:")
print(agentic_rag(query, BASE_KB))


# ──────────────────────────────────────────────────────────────
# TASK 1: Add your own document to the knowledge base
# Add a document relevant to your research domain.
# Then query for something that requires it.
# Observe: does the agent use your new document?
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 1: Extend the knowledge base with your own document")
print(DIVIDER)

# TODO: Replace with a document from your research domain
# Ideas: a specific CVE, a threat actor TTP, an IOC, 
# a compliance requirement, a detection rule

YOUR_DOCUMENT = {
    "id": "apt-bronze-silhouette",
    "text": "APT group BRONZE SILHOUETTE (China-nexus) targets financial sector. "
            "Uses Cobalt Strike and custom loaders. Known to pivot from web shells "
            "to internal Active Directory within 4 hours of initial access. "
            "Exfiltrates via DNS tunneling to avoid detection."
}

EXTENDED_KB = BASE_KB + [YOUR_DOCUMENT]

# Now query something that requires your new document
YOUR_QUERY = "We found Cobalt Strike C2 traffic and our Flask app was compromised. What APT group is this?"

print(f"Added document: [{YOUR_DOCUMENT['id']}]")
print(f"\nQuerying with extended KB:")
print(f"Query: {YOUR_QUERY}\n")
print(agentic_rag(YOUR_QUERY, EXTENDED_KB))


# ──────────────────────────────────────────────────────────────
# TASK 2: Hallucination risk — query outside the knowledge base
# Ask about something NOT in the knowledge base.
# Does the agent admit it does not know, or does it hallucinate?
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Hallucination risk — querying outside the knowledge base")
print(DIVIDER)

out_of_scope_query = "What is the CVE number for the Log4Shell vulnerability and how do we patch it?"

print(f"Query: {out_of_scope_query}")
print("(Log4Shell is NOT in our knowledge base)")
print("\nKeyword search hits:", [d["id"] for d in keyword_search(out_of_scope_query, BASE_KB)])
print("\nAgentic RAG response:")
print(agentic_rag(out_of_scope_query, BASE_KB))

print("""
OBSERVATION QUESTIONS:
1. Did the agent admit the information was not in the knowledge base?
2. Did it produce any plausible-sounding but fabricated CVE details?
3. Did it recommend external sources?
4. What is the danger if this agent is used by a SOC analyst who
   trusts its output without verification?
""")


# ──────────────────────────────────────────────────────────────
# TASK 3: Design a knowledge base for your research domain
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 3: Design a domain-specific knowledge base")
print(DIVIDER)

response = llm.invoke([HumanMessage(content="""You are helping design a threat intelligence knowledge base
for a research institution's SOC.

The institution runs:
- Machine learning training clusters (GPU servers)
- Research data repositories (multi-TB datasets)
- Collaboration tools (Slack, SharePoint, Zoom)
- Remote access for international researchers

Design a knowledge base with 6 documents covering:
1. The most likely threat actors targeting this type of institution
2. The most exploited entry points for research institutions
3. The most valuable data for exfiltration
4. Specific IOCs relevant to academic research targeting
5. Detection rules specific to ML/GPU infrastructure
6. Compliance requirements for research data protection

Format each document as:
ID: [short-id]
Text: [2-3 sentences of threat intelligence content]""")])
print(response.content)
print("""
FOLLOW-UP:
Copy the documents above and add them to EXTENDED_KB.
Then test whether Agentic RAG can correctly answer:
'A researcher reported their GPU cluster is making unusual network connections
to Chinese IP addresses during training jobs. What do we do?'
""")
