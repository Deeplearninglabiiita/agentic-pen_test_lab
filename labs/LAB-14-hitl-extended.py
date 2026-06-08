"""
LAB-14: Human-in-the-Loop — Extended Governance
=================================================
Estimated time: 20 minutes
Mirrors: 06_hitl_governance/hitl_breakpoint.py, Chapter 8 pp. 23-24

LEARNING OBJECTIVES
- Understand LangGraph breakpoints and MemorySaver checkpointing
- Add multiple breakpoints at different risk thresholds
- Implement a timed approval window
- Design HITL for a multi-agent scenario

TASKS
1. Run HITL with single breakpoint (standard demo)
2. Run with double breakpoint — pause before exploit AND report
3. Run with timed approval window — auto-deny after 30 seconds
4. Design HITL governance for 10 parallel agents
"""

import sys, os, json, time, threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "02_langgraph_agent"))

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from shared.config import config
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage
from state import PentestState
from nodes import (reconnaissance_node, enumeration_node,
    vulnerability_assessment_node, exploitation_node, reporting_node)
from graph import should_continue

DIVIDER = "=" * 60


def build_graph(interrupt_before: list):
    wf = StateGraph(PentestState)
    wf.add_node("recon",        reconnaissance_node)
    wf.add_node("enumerate",    enumeration_node)
    wf.add_node("assess_vulns", vulnerability_assessment_node)
    wf.add_node("exploit",      exploitation_node)
    wf.add_node("report",       reporting_node)
    wf.set_entry_point("recon")
    for node in ("recon", "enumerate", "assess_vulns", "exploit"):
        wf.add_conditional_edges(node, should_continue, {
            "enumerate": "enumerate", "assess_vulns": "assess_vulns",
            "exploit": "exploit", "report": "report", END: END
        })
    wf.add_edge("report", END)
    memory = MemorySaver()
    return wf.compile(checkpointer=memory, interrupt_before=interrupt_before)


def make_initial_state(objectives=None) -> PentestState:
    return {
        "scope": [config.LAB_TARGET_DOMAIN, config.LAB_TARGET_URL],
        "objectives": objectives or ["Test for SQL injection", "Evaluate XSS exposure"],
        "targets": [], "current_target": None, "credentials": [], "shells": [],
        "messages": [], "phase": "recon", "iteration": 0, "max_iterations": 8,
        "findings": [], "errors": [],
    }


def stream_until_pause(agent, state_or_none, cfg):
    for event in agent.stream(state_or_none, cfg):
        node_name = list(event.keys())[0]
        if node_name not in ("__start__", "__end__"):
            print(f"  Completed: {node_name}")


def show_vuln_summary(agent, cfg):
    current = agent.get_state(cfg)
    vulns = [
        f for f in current.values.get("findings", [])
        if "[VULN]" in f and '"vulnerable": true' in f.lower()
    ]
    if vulns:
        print(f"\nConfirmed vulnerabilities:")
        for v in vulns:
            try:
                data = json.loads(v.split(": ", 1)[1])
                if data.get("vulnerable"):
                    print(f"  • {data['vuln_type'].upper()} | CVSS {data['cvss']} | {data.get('endpoint','')}")
            except Exception:
                print(f"  • {v[:80]}")
    return vulns


# ─────────────────────────────────────────────────────────────
# EXERCISE 1: Standard single breakpoint
# ─────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 1: Standard HITL — interrupt_before=['exploit']")
print("Mirrors Chapter 8 Example 8-8")
print(DIVIDER)

agent1 = build_graph(interrupt_before=["exploit"])
cfg1 = {"configurable": {"thread_id": "lab14-ex1"}}

print("\n[HITL] Running recon → assessment... will pause before exploit.\n")
stream_until_pause(agent1, make_initial_state(), cfg1)

vulns = show_vuln_summary(agent1, cfg1)

print(f"\n{DIVIDER}")
print("BREAKPOINT: Agent paused. Awaiting human decision.")
print(DIVIDER)
print("\nRequired before proceeding:")
print("  [x] Written authorisation covers target")
print("  [x] Test window is active")
print("  [x] Rollback plan confirmed")

decision = input("\nApprove exploitation? (yes/no): ").strip().lower()

if decision == "yes":
    print("\n[HITL] Approved. Resuming...")
    stream_until_pause(agent1, None, cfg1)
    final = agent1.get_state(cfg1)
    reports = [f for f in final.values.get("findings", []) if "[REPORT]" in f]
    if reports:
        print(f"\nReport generated ({len(reports[0])} chars)")
        print(reports[0].replace("[REPORT]\n", "")[:600])
else:
    print("\n[HITL] Exploitation CANCELLED. Agent stopped.")
    print("  Key point: the breakpoint cannot be bypassed by the agent.")


# ─────────────────────────────────────────────────────────────
# TASK 1: Double breakpoint
# ─────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 1: Double breakpoint — pause before exploit AND report")
print("Humans approve both the action and the document that describes it")
print(DIVIDER)

agent2 = build_graph(interrupt_before=["exploit", "report"])
cfg2 = {"configurable": {"thread_id": "lab14-task1"}}

stream_until_pause(agent2, make_initial_state(), cfg2)
show_vuln_summary(agent2, cfg2)

d1 = input("\nApprove exploitation phase? (yes/no): ").strip().lower()
if d1 == "yes":
    stream_until_pause(agent2, None, cfg2)
    print("\n[HITL] Agent paused again — wants to generate report.")
    print("  Operator must approve report content before release.")
    d2 = input("Approve report generation? (yes/no): ").strip().lower()
    if d2 == "yes":
        stream_until_pause(agent2, None, cfg2)
        final2 = agent2.get_state(cfg2)
        reports2 = [f for f in final2.values.get("findings", []) if "[REPORT]" in f]
        print(f"\n[HITL] Report approved and generated.")
    else:
        print("\n[HITL] Report blocked. Findings exist but no document produced.")
        print("  Useful when findings are sensitive and need review before release.")
else:
    print("\n[HITL] Exploitation and report both cancelled.")


# ─────────────────────────────────────────────────────────────
# TASK 2: Timed approval window
# ─────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Timed approval window — auto-DENY after 30 seconds")
print("Fail-safe default: when in doubt, block rather than allow")
print(DIVIDER)

def timed_input(prompt: str, timeout: int = 30) -> str:
    result = [None]
    def get_input():
        result[0] = input(prompt).strip().lower()
    t = threading.Thread(target=get_input, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if result[0] is None:
        print(f"\n[TIMEOUT] {timeout}s elapsed — automatically DENIED (fail-safe)")
        return "no"
    return result[0]

agent3 = build_graph(interrupt_before=["exploit"])
cfg3 = {"configurable": {"thread_id": "lab14-task2"}}

stream_until_pause(agent3, make_initial_state(), cfg3)
show_vuln_summary(agent3, cfg3)

decision3 = timed_input(
    f"\nApprove exploitation? (yes/no) — auto-deny in 30 seconds: ",
    timeout=30
)

if decision3 == "yes":
    stream_until_pause(agent3, None, cfg3)
    print("\n[HITL] Exploitation completed within approval window.")
else:
    print("\n[HITL] Exploitation denied or timed out.")

print("""
OBSERVATION:
- Fail-safe default: deny is always safer than approve on timeout
- Real systems use 15-60 minute windows for less urgent decisions
- Time pressure degrades human decision quality — this is a research problem
- What is the right timeout for a CVSS 9.1 finding at 3 AM?
""")


# ─────────────────────────────────────────────────────────────
# TASK 3: Design HITL for parallel agents
# ─────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 3: Design HITL governance for 10 parallel agents")
print(DIVIDER)

llm = get_llm()
response = llm.invoke([HumanMessage(content="""Design a Human-in-the-Loop governance system
for 10 penetration testing agents running simultaneously.

Each agent hits an exploitation decision point within 5 minutes of starting.
One security lead on duty must approve exploitation decisions.
Maximum 2 minutes to respond to each request.
Agents should not queue indefinitely — abort after 5 minutes.

Design:
1. The approval queue architecture
2. What the security lead sees for each decision (5 items maximum)
3. Escalation path if the security lead is unavailable
4. How to prevent approval fatigue
5. What happens to agents that time out

Then answer: at what scale does human approval become impossible?
What replaces it and what are the risks?""")])
print(response.content)
