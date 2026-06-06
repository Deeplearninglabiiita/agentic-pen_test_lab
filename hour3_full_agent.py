import sys
sys.path.insert(0, '.')
sys.path.insert(0, './02_langgraph_agent')
from state import PentestState
from graph import build_pentest_graph
from shared.config import config

DIVIDER = "=" * 60

print(DIVIDER)
print("FULL LANGGRAPH PENETRATION TESTING AGENT")
print("Chapter 8, Examples 8-3 to 8-6")
print("Watch the conditional routing — the agent decides its own path")
print(DIVIDER)

print("""
Graph structure:
  recon → enumerate → assess_vulns → [if vulns found] → exploit → report
                                    → [if no vulns]   → report

This is not a script. The agent decides at each node what to do next.
""")

initial: PentestState = {
    "scope": [config.LAB_TARGET_DOMAIN, config.LAB_TARGET_URL],
    "objectives": [
        "Identify all web-facing services and open ports",
        "Discover and confirm SQL injection vulnerabilities",
        "Attempt credential extraction via SQL injection",
        "Identify any authentication weaknesses",
        "Document all findings with CVSS scores and CWE identifiers",
    ],
    "targets": [], "current_target": None,
    "credentials": [], "shells": [],
    "messages": [],
    "phase": "recon",
    "iteration": 0,
    "max_iterations": 10,
    "findings": [], "errors": [],
}

agent = build_pentest_graph()
result = agent.invoke(initial)

print(f"\n{DIVIDER}")
print("FINAL REPORT")
print(DIVIDER)
for f in result["findings"]:
    if "[REPORT]" in f:
        print(f.replace("[REPORT]\n", ""))

print(f"\n{DIVIDER}")
print(f"Agent statistics:")
print(f"  Iterations: {result['iteration']}")
print(f"  Total findings: {len(result['findings'])}")
print(f"  Phases completed: recon, enumeration, vuln_assessment, exploitation, reporting")
print(f"  Routing decisions made: {result['iteration']} (one per node)")
print(DIVIDER)
