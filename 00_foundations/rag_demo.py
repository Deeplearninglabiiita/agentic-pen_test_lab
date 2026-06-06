import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

DIVIDER = "=" * 60

THREAT_INTEL_KB = [
    {"id": "cve-2024-001",
     "text": "CVE-2024-001: Werkzeug 2.3.0 has a path traversal vulnerability. CVSS 7.5. Patch: upgrade to 2.3.1."},
    {"id": "mitre-t1190",
     "text": "MITRE T1190: Exploit Public-Facing Application. Adversaries exploit weaknesses in internet-facing software for initial access."},
    {"id": "ioc-185",
     "text": "IOC: 185.220.101.5 associated with Cobalt Strike C2 infrastructure. Last seen: 2024-11. Confidence: High. Source: ThreatFox."},
    {"id": "sqli-guide",
     "text": "SQL injection via UNION-based extraction: payloads like ' UNION SELECT username,password FROM users-- allow data exfiltration when error-based injection is filtered."},
]

def keyword_search(query: str) -> list:
    words = set(query.lower().split())
    results = []
    for doc in THREAT_INTEL_KB:
        overlap = len(words & set(doc["text"].lower().split()))
        if overlap > 0:
            results.append((overlap, doc))
    results.sort(key=lambda x: x[0], reverse=True)
    return [r[1] for r in results[:2]]

def demo_traditional_rag(query: str):
    print(f"\n{DIVIDER}")
    print("TRADITIONAL RAG: retrieve → generate (PPT Slide 13)")
    print(DIVIDER)
    retrieved = keyword_search(query)
    context = "\n\n".join(d["text"] for d in retrieved)
    llm = get_llm()
    response = llm.invoke([HumanMessage(content=f"""Use only the context below to answer.

Context:
{context}

Question: {query}""")])
    print(f"Query: {query}")
    print(f"Retrieved {len(retrieved)} docs via keyword search")
    print(f"\nAnswer:\n{response.content}")

def demo_agentic_rag(query: str):
    print(f"\n{DIVIDER}")
    print("AGENTIC RAG: reason → retrieve → plan → act (PPT Slide 16)")
    print(DIVIDER)
    context = "\n\n".join(f"[{d['id']}] {d['text']}" for d in THREAT_INTEL_KB)
    llm = get_llm()
    response = llm.invoke([HumanMessage(content=f"""You are an autonomous SOC agent with threat intelligence access.

Available intel:
{context}

Task: {query}

Show Agentic RAG — four steps:
Step 1 (REASON): What information do I need?
Step 2 (RETRIEVE): Which document IDs are relevant and why?
Step 3 (ACT): What concrete actions do I take?
Step 4 (REFLECT): What else might I need? What is still uncertain?

Reference document IDs when citing intel.""")])
    print(f"Query: {query}")
    print(f"\nAgentic RAG Response:\n{response.content}")

if __name__ == "__main__":
    print("Lab 0b: RAG and Agentic RAG — PPT Slides 12-16")
    query = "We found a connection to 185.220.101.5 from our Flask web server. Is it compromised?"
    demo_traditional_rag(query)
    demo_agentic_rag(query)
    print(f"\n{DIVIDER}")
    print("Key insight: Agentic RAG reasons across docs and produces an action plan.")
    print("Next: python 01_cobalt_flow/scout_agent.py")
    print(DIVIDER)
