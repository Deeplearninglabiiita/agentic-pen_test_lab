import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from state import PentestState
from graph import build_pentest_graph
from shared.config import config

DIVIDER = "=" * 60

if __name__ == "__main__":
    print(DIVIDER)
    print("Lab 2: Full LangGraph Penetration Testing Agent")
    print("Chapter 8, Examples 8-3 to 8-6")
    print(f"Target: {config.LAB_TARGET_URL} (scope-locked)")
    print(DIVIDER)

    initial_state: PentestState = {
        "scope": [config.LAB_TARGET_DOMAIN, config.LAB_TARGET_URL],
        "objectives": [
            "Identify all web-facing services and open ports",
            "Discover SQL injection vulnerabilities",
            "Attempt credential extraction via SQL injection",
            "Document all findings",
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
    result = agent.invoke(initial_state)

    print(f"\n{DIVIDER}")
    print("FINAL REPORT")
    print(DIVIDER)
    for f in result["findings"]:
        if "[REPORT]" in f:
            print(f.replace("[REPORT]\n", ""))

    print(f"\n{DIVIDER}")
    print(f"Completed in {result['iteration']} iterations | Phase: {result['phase']}")
    print("Next: python 06_hitl_governance/hitl_breakpoint.py")
    print(DIVIDER)
