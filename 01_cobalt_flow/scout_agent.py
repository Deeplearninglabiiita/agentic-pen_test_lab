import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
from typing import TypedDict, Annotated, List, Optional
import operator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, SystemMessage

from shared.llm_client import get_llm_with_tools, get_llm
from shared.config import config
from shared.mock_tools import ALL_REAL_TOOLS
real_port_scan = next(t for t in ALL_REAL_TOOLS if t.name == 'real_port_scan')
real_web_enumerate = next(t for t in ALL_REAL_TOOLS if t.name == 'real_web_enumerate')
real_sqli_check = next(t for t in ALL_REAL_TOOLS if t.name == 'real_sqli_check')
real_xss_check = next(t for t in ALL_REAL_TOOLS if t.name == 'real_xss_check')

DIVIDER = "=" * 60
SCOUT_TOOLS = [real_port_scan, real_web_enumerate]

class ScoutState(TypedDict):
    target_url: str
    services: Annotated[List[dict], operator.add]
    entry_point: Optional[str]
    recon_complete: bool
    target_package: Optional[dict]
    messages: Annotated[List, operator.add]
    iteration: int

def port_scan_node(state: ScoutState) -> ScoutState:
    print(f"\n[SCOUT] Phase 1: Port scan on {state['target_url']}")
    llm = get_llm_with_tools(SCOUT_TOOLS)
    response = llm.invoke([
        SystemMessage(content="You are the Scout agent. Call real_port_scan on the target IP. Stay methodical."),
        HumanMessage(content=f"Scan ports on {config.LAB_TARGET_DOMAIN}")
    ])
    services = []
    if response.tool_calls:
        for tc in response.tool_calls:
            if tc["name"] == "real_port_scan":
                result = json.loads(real_port_scan.invoke(tc["args"]))
                for port in result.get("open_ports", []):
                    services.append(port)
                    print(f"  Open: {port['port']}/{port['scheme']} — {port.get('server','')}")
    return {**state, "services": services,
            "messages": state["messages"] + [response],
            "iteration": state["iteration"] + 1}

def enumerate_node(state: ScoutState) -> ScoutState:
    print(f"\n[SCOUT] Phase 2: Web enumeration on {state['target_url']}")
    llm = get_llm_with_tools(SCOUT_TOOLS)
    response = llm.invoke([
        SystemMessage(content="Call real_web_enumerate on the target URL. Report missing headers, forms, and technologies."),
        HumanMessage(content=f"Enumerate {state['target_url']}")
    ])
    if response.tool_calls:
        for tc in response.tool_calls:
            if tc["name"] == "real_web_enumerate":
                result = json.loads(real_web_enumerate.invoke(tc["args"]))
                print(f"  Server: {result.get('server','')}")
                print(f"  Technologies: {result.get('technologies', [])}")
                for issue in result.get("missing_security_headers", [])[:3]:
                    print(f"  Missing: {issue}")
    return {**state,
            "entry_point": state["target_url"] + "/search?q=",
            "messages": state["messages"] + [response],
            "iteration": state["iteration"] + 1}

def decision_node(state: ScoutState) -> ScoutState:
    print(f"\n[SCOUT] Phase 3: Exploitability decision")
    llm = get_llm()
    response = llm.invoke([
        SystemMessage(content='Evaluate findings. Return ONLY valid JSON: {"exploit": true/false, "reason": "...", "technique": "sql_injection"}'),
        HumanMessage(content=f"Services: {json.dumps(state['services'])}. Entry point: {state['entry_point']}. SQLi endpoint known. Exploitable?")
    ])
    try:
        raw = response.content.strip().strip("```json").strip("```").strip()
        decision = json.loads(raw)
    except Exception:
        decision = {"exploit": True, "reason": "SQLi entry point confirmed", "technique": "sql_injection"}

    print(f"  Decision: exploit={decision.get('exploit')} | {decision.get('reason','')}")
    pkg = {
        "entry_point": state["entry_point"],
        "technique": decision.get("technique", "sql_injection"),
        "services": state["services"],
        "scout_confidence": "HIGH",
    } if decision.get("exploit") else None

    return {**state, "target_package": pkg, "recon_complete": True,
            "messages": state["messages"] + [response],
            "iteration": state["iteration"] + 1}

def handoff_node(state: ScoutState) -> ScoutState:
    print(f"\n[SCOUT] Phase 4: Breacher handoff")
    if not state["target_package"]:
        print("  No exploitable target — Scout stands down.")
        return state
    print(f"  [SIMULATED] POST → breacher webhook")
    print(f"  entry_point = {state['target_package']['entry_point']}")
    print(f"  technique   = {state['target_package']['technique']}")
    print(f"  Scout complete. Breacher pipeline triggered.")
    return state

def build_scout_graph():
    g = StateGraph(ScoutState)
    g.add_node("port_scan",  port_scan_node)
    g.add_node("enumerate",  enumerate_node)
    g.add_node("decision",   decision_node)
    g.add_node("handoff",    handoff_node)
    g.set_entry_point("port_scan")
    g.add_edge("port_scan",  "enumerate")
    g.add_edge("enumerate",  "decision")
    g.add_edge("decision",   "handoff")
    g.add_edge("handoff",    END)
    return g.compile()

if __name__ == "__main__":
    print(DIVIDER)
    print("Lab 1: Cobalt Flow Scout Agent — Chapter 8 pp. 4-7")
    print(f"Target: {config.LAB_TARGET_URL}")
    print(DIVIDER)
    scout = build_scout_graph()
    final = scout.invoke({
        "target_url": config.LAB_TARGET_URL,
        "services": [], "entry_point": None,
        "recon_complete": False, "target_package": None,
        "messages": [], "iteration": 0,
    })
    print(f"\n{DIVIDER}")
    if final.get("target_package"):
        print("Target package ready for Breacher.")
        print("Run: python 01_cobalt_flow/breacher_sim.py")
    else:
        print("No exploitable target found.")
    print(DIVIDER)
