import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage

DIVIDER = "=" * 60

# ── Read inputs from GUI environment variables ─────────────────
DEFAULT_Q1 = """Compare Traditional AI Agents vs Modern Agentic AI Systems
across: Autonomy, Goal Management, Adaptability, Decision Making, Tool Use, Memory.
Format as a table then give one cybersecurity example for each."""

DEFAULT_Q2 = """Alert: Unusual outbound traffic to 185.220.101.5 from WS-042. Volume: 4.2 GB in 8 minutes."""

DEFAULT_Q3 = """Demonstrate the ReAct paradigm for a PhD class.
Task: Investigate whether http://localhost:8080 is vulnerable to SQL injection.
Show exactly 3 Thought → Action → Observation cycles.
Final Answer: [conclusion]"""

DEFAULT_Q4 = """Teaching PhD students about AI planning in cybersecurity.
Scenario: Ransomware alert on 3 servers in a hospital network.
Show all three paradigms: STATIC, DYNAMIC, HIERARCHICAL (ASCII goal tree).
Keep each section to 5-7 lines."""

Q1 = os.environ.get("GUI_Q1", "").strip() or DEFAULT_Q1
Q2 = os.environ.get("GUI_Q2", "").strip() or DEFAULT_Q2
Q3 = os.environ.get("GUI_Q3", "").strip() or DEFAULT_Q3
Q4 = os.environ.get("GUI_Q4", "").strip() or DEFAULT_Q4

# ── Demos ──────────────────────────────────────────────────────

def demo_1_what_is_agentic_ai():
    print(f"\n{DIVIDER}")
    print("DEMO 1: Traditional AI vs Agentic AI (PPT Slide 5)")
    print(f"Question: {Q1[:80]}...")
    print(DIVIDER)
    llm = get_llm()
    response = llm.invoke([HumanMessage(content=Q1)])
    print(response.content)

def demo_2_cognitive_loop():
    print(f"\n{DIVIDER}")
    print("DEMO 2: Agent Cognitive Loop — Perceive, Reason, Plan, Act (PPT Slide 7)")
    print(DIVIDER)
    print(f"\n[PERCEIVE] {Q2}")
    llm = get_llm()
    response = llm.invoke([HumanMessage(content=f"""You are an AI SOC agent.
Observation: {Q2}
Step 1 - REASON: What does this indicate?
Step 2 - PLAN: What actions should you take? List in priority order.
Step 3 - ACT: Describe the first action you execute right now.
Use Chain-of-Thought. Be concise.""")])
    print(f"\n[REASON → PLAN → ACT]:\n{response.content}")

def demo_3_react_paradigm():
    print(f"\n{DIVIDER}")
    print("DEMO 3: ReAct Paradigm — Reason + Act Interleaved (PPT Slide 8)")
    print(DIVIDER)
    llm = get_llm()
    response = llm.invoke([HumanMessage(content=Q3)])
    print(response.content)

def demo_4_planning_paradigms():
    print(f"\n{DIVIDER}")
    print("DEMO 4: Planning Paradigms — Static, Dynamic, Hierarchical (PPT Slides 9-10)")
    print(DIVIDER)
    llm = get_llm()
    response = llm.invoke([HumanMessage(content=Q4)])
    print(response.content)

if __name__ == "__main__":
    print("Lab 0: Agentic AI Foundations — PPT Slides 5-10")
    print(f"Custom Q1: {bool(os.environ.get('GUI_Q1'))}")
    print(f"Custom Q2: {bool(os.environ.get('GUI_Q2'))}")
    print(f"Custom Q3: {bool(os.environ.get('GUI_Q3'))}")
    print(f"Custom Q4: {bool(os.environ.get('GUI_Q4'))}")
    demo_1_what_is_agentic_ai()
    demo_2_cognitive_loop()
    demo_3_react_paradigm()
    demo_4_planning_paradigms()
    print(f"\n{DIVIDER}")
    print("Lab 0 complete. Next: python 00_foundations/rag_demo.py")
    print(DIVIDER)
