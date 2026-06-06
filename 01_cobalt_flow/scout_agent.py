import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
from typing import TypedDict, Annotated, List, Optional
import operator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, SystemMessage

from shared.llm_client import get_llm_with_tools, get_llm
from shared.config import config
from shared.mock_tools import mock_subdomain_discovery, mock_port_scan, mock_web_enumerate

DIVIDER = "=" * 60
SCOUT_TOOLS = [mock_subdomain_discovery, mock_port_scan, mock_web_enumerate]

class ScoutState(TypedDict):
    target_domain: str
    subdomains: Annotated[List[dict], operator.add]
    services: Annotated[List[dict], operator.add]
    entry_point: Optional[str]
    recon_complete: bool
    target_package: Optional[dict]
    messages: Annotated[List, operator.add]
    iteration: int

def subdomain_node(state: ScoutState) -> ScoutState:
    print(f"\n[SCOUT] Phase 1: Subdomain discovery on {state['target_domain']}")
    llm = get_llm_with_tools(SCOUT_TOOLS)
    response = llm.invoke([
        SystemMessage(content="You are the Scout agent. Call mock_subdomain_discovery on the target domain. Stay passive."),
        HumanMessage(content=f"Discover subdomains of {state['target_domain']}")
    ])
    found = []
    if response.tool_calls:
        for tc in response.tool_calls:
            if tc["name"] == "mock_subdomain_discovery":
                data = json.loads(mock_subdomain_discovery.invoke(tc["args"]))
                found = data.get("subdomains", [])
                for sd in found:
                    print(f"  • {sd['subdomain']}  [{sd['status']}]  {sd['note']}")
    return {**state, "subdomains": found, "messages": state["messages"] + [response], "iteration": state["iteration"] + 1}

def fingerprint_node(state: ScoutState) -> ScoutState:
    print(f"\n[SCOUT] Phase 2: Service fingerprinting")
    targets = [s for s in state["subdomains"] if s["status"] == 200]
    if not targets:
        return {**state, "recon_complete": True}
    target_url = config.LAB_TARGET_URL
    print(f"  Targeting: {target_url}")
    llm = get_llm_with_tools(SCOUT_TOOLS)
    response = llm.invoke([
        SystemMessage(content="Call mock_port_scan with target='localhost' then mock_web_enumerate with the target URL."),
        HumanMessage(content=f"Fingerprint services at {target_url}")
    ])
    services = []
    if response.tool_calls:
        for tc in response.tool_calls:
            if tc["name"] == "mock_port_scan":
                data = json.loads(mock_port_scan.invoke(tc["args"]))
                for host in data.get("hosts", []):
                    for port in host.get("ports", []):
                        if port["state"] == "open":
                            services.append(port)
                            print(f"  • Port {port['port']}/{port['service']} — {port['product']} {port['version']}")
            elif tc["name"] == "mock_web_enumerate":
                data = json.loads(mock_web_enumerate.invoke(tc["args"]))
                for issue in data.get("potential_issues", []):
                    print(f"  ⚠  {issue}")
    return {**state, "entry_point": target_url, "services": services, "messages": state["messages"] + [response], "iteration": state["iteration"] + 1}

def decision_node(state: ScoutState) -> ScoutState:
    print(f"\n[SCOUT] Phase 3: Exploitability decision")
    llm = get_llm()
    response = llm.invoke([
        SystemMessage(content='Evaluate findings. Return ONLY valid JSON: {"exploit": true/false, "reason": "...", "technique": "..."}'),
        HumanMessage(content=f"Services: {json.dumps(state['services'])}. Known issue: SQL injection on /search. Exploitable?")
    ])
    try:
        raw = response.content.strip().strip("```json").strip("```").strip()
        decision = json.loads(raw)
    except Exception:
        decision = {"exploit": True, "reason": "Fallback: SQLi confirmed", "technique": "sql_injection"}
    print(f"  Decision: exploit={decision.get('exploit')} | {decision.get('reason', '')}")
    pkg = {
        "entry_point": state["entry_point"],
        "technique": decision.get("technique", "sql_injection"),
        "services": state["services"],
        "scout_confidence": "HIGH",
    } if decision.get("exploit") else None
    if pkg:
        print(f"\n  Target package ready for Breacher")
    return {**state, "target_package": pkg, "recon_complete": True, "messages": state["messages"] + [response], "iteration": state["iteration"] + 1}

def handoff_node(state: ScoutState) -> ScoutState:
    print(f"\n[SCOUT] Phase 4: Breacher handoff")
    if not state["target_package"]:
        print("  No exploitable target — Scout stands down.")
        return state
    print(f"  [SIMULATED] POST → breacher webhook")
    print(f"  entry_point={state['target_package']['entry_point']}")
    print(f"  technique={state['target_package']['technique']}")
    print(f"  Scout complete. Breacher pipeline would now trigger.")
    return state

def build_scout_graph():
    g = StateGraph(ScoutState)
    g.add_node("subdomain", subdomain_node)
    g.add_node("fingerprint", fingerprint_node)
    g.add_node("decision", decision_node)
    g.add_node("handoff", handoff_node)
    g.set_entry_point("subdomain")
    g.add_edge("subdomain", "fingerprint")
    g.add_edge("fingerprint", "decision")
    g.add_edge("decision", "handoff")
    g.add_edge("handoff", END)
    return g.compile()

if __name__ == "__main__":
    print(DIVIDER)
    print("Lab 1: Cobalt Flow Scout Agent — Chapter 8 pp. 4-7")
    print(f"Scope-locked to: {config.LAB_TARGET_URL}")
    print(DIVIDER)
    scout = build_scout_graph()
    final = scout.invoke({
        "target_domain": config.LAB_TARGET_DOMAIN,
        "subdomains": [], "services": [], "entry_point": None,
        "recon_complete": False, "target_package": None,
        "messages": [], "iteration": 0,
    })
    print(f"\n{DIVIDER}")
    print("Scout finished. Run: python 01_cobalt_flow/breacher_sim.py")
    print(DIVIDER)
