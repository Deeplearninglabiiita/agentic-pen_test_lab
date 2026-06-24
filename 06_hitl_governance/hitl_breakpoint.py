import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "02_langgraph_agent"))

import json
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from shared.config import config
from state import PentestState
from nodes import (reconnaissance_node, enumeration_node,
    vulnerability_assessment_node, exploitation_node, reporting_node)
from graph import should_continue

DIVIDER = "=" * 60

def build_controlled_graph():
    wf = StateGraph(PentestState)
    wf.add_node("recon", reconnaissance_node)
    wf.add_node("enumerate", enumeration_node)
    wf.add_node("assess_vulns", vulnerability_assessment_node)
    wf.add_node("exploit", exploitation_node)
    wf.add_node("report", reporting_node)
    wf.set_entry_point("recon")
    for node in ("recon", "enumerate", "assess_vulns", "exploit"):
        wf.add_conditional_edges(node, should_continue,
            {"enumerate": "enumerate", "assess_vulns": "assess_vulns",
             "exploit": "exploit", "report": "report", END: END})
    wf.add_edge("report", END)
    memory = MemorySaver()
    return wf.compile(checkpointer=memory, interrupt_before=["exploit"])

if __name__ == "__main__":
    print(DIVIDER)
    print("Lab 6: Human-in-the-Loop Controls — Chapter 8, Example 8-8")
    print(f"Target: {config.LAB_TARGET_URL} | interrupt_before=['exploit']")
    print(DIVIDER)

    agent = build_controlled_graph()
    cfg = {"configurable": {"thread_id": "lab-hitl-001"}}
    initial: PentestState = {
        "scope": [config.LAB_TARGET_DOMAIN, config.LAB_TARGET_URL],
        "objectives": ["Test for SQL injection", "Evaluate XSS exposure", "Document findings"],
        "targets": [], "current_target": None, "credentials": [], "shells": [],
        "messages": [], "phase": "recon", "iteration": 0, "max_iterations": 10,
        "findings": [], "errors": [],
    }

    print("\n[HITL] Running recon → enumeration → vulnerability assessment...")
    print("[HITL] Will PAUSE before exploitation for human approval.\n")

    for event in agent.stream(initial, cfg):
        node_name = list(event.keys())[0]
        if node_name not in ("__start__", "__end__"):
            print(f"  Completed: {node_name}")

    current = agent.get_state(cfg)
    vuln_findings = [f for f in current.values["findings"] if "[VULN]" in f and '"vulnerable": true' in f.lower()]

    print(f"\n{DIVIDER}")
    print("HUMAN APPROVAL REQUIRED — Chapter 8, Example 8-8")
    print(DIVIDER)
    print(f"\nConfirmed vulnerabilities pending exploitation:")
    for i, f in enumerate(vuln_findings, 1):
        try:
            data = json.loads(f.split(": ", 1)[1])
            if data.get("vulnerable"):
                print(f"  {i}. {data.get('vuln_type','?').upper()} | CVSS {data.get('cvss',0)} | {data.get('endpoint','n/a')}")
        except Exception:
            print(f"  {i}. {f[:100]}")

    print(f"\nRequired before proceeding:")
    print("  [x] Written authorisation from asset owner")
    print("  [x] Defined test window confirmed")
    print("  [x] Rollback plan in place")

    from shared.gui_input import gui_input
approval = gui_input("\nProceed with exploitation? (yes/no): ").strip().lower()

    if approval == "yes":
        print("\n[HITL] Approval granted. Resuming...")
        for event in agent.stream(None, cfg):
            node_name = list(event.keys())[0]
            if node_name not in ("__start__", "__end__"):
                print(f"  Completed: {node_name}")
        final = agent.get_state(cfg)
        for f in final.values["findings"]:
            if "[REPORT]" in f:
                print(f"\n{DIVIDER}\nREPORT\n{DIVIDER}")
                print(f.replace("[REPORT]\n", ""))
    else:
        print("\n[HITL] Exploitation CANCELLED by operator.")
        print("[HITL] This is the correct responsible action.")
        print("[HITL] Proceeding to reporting with scan findings only.")
