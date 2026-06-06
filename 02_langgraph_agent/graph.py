import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from langgraph.graph import StateGraph, END
from state import PentestState
from nodes import (reconnaissance_node, enumeration_node,
    vulnerability_assessment_node, exploitation_node, reporting_node)

def should_continue(state: PentestState) -> str:
    if state["iteration"] >= state["max_iterations"]:
        return "report"
    phase = state["phase"]
    if phase == "recon":
        return "enumerate"
    elif phase == "enumeration":
        return "assess_vulns"
    elif phase == "vulnerability_assessment":
        has_vuln = any('"vulnerable": true' in f.lower() for f in state["findings"] if "[VULN]" in f)
        return "exploit" if has_vuln else "report"
    elif phase == "exploitation":
        return "report"
    elif phase in ("reporting", "complete"):
        return END
    return "report"

def build_pentest_graph():
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
    return wf.compile()
