import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

DIVIDER = "=" * 60

def demo_1_what_is_agentic_ai():
    print(f"\n{DIVIDER}")
    print("DEMO 1: Traditional AI vs Agentic AI (PPT Slide 5)")
    print(DIVIDER)
    llm = get_llm()
    response = llm.invoke([HumanMessage(content="""Compare Traditional AI Agents vs Modern Agentic AI Systems
    across: Autonomy, Goal Management, Adaptability, Decision Making, Tool Use, Memory.
    Format as a table then give one cybersecurity example for each.""")])
    print(response.content)

def demo_2_cognitive_loop():
    print(f"\n{DIVIDER}")
    print("DEMO 2: Agent Cognitive Loop — Perceive, Reason, Plan, Act (PPT Slide 7)")
    print(DIVIDER)
    perception = "Alert: Unusual outbound traffic to 185.220.101.5 from WS-042. Volume: 4.2 GB in 8 minutes."
    print(f"\n[PERCEIVE] {perception}")
    llm = get_llm()
    response = llm.invoke([HumanMessage(content=f"""You are an AI SOC agent.
Observation: {perception}

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
    response = llm.invoke([HumanMessage(content="""Demonstrate the ReAct paradigm for a PhD class.
Task: Investigate whether http://localhost:8080 is vulnerable to SQL injection.

Show exactly 3 Thought → Action → Observation cycles:

Thought 1: [reasoning]
Action 1: [tool call]
Observation 1: [what you learn]

Thought 2: ...
(etc.)

Final Answer: [conclusion]""")])
    print(response.content)

def demo_4_planning_paradigms():
    print(f"\n{DIVIDER}")
    print("DEMO 4: Planning Paradigms — Static, Dynamic, Hierarchical (PPT Slides 9-10)")
    print(DIVIDER)
    llm = get_llm()
    response = llm.invoke([HumanMessage(content="""Teaching PhD students about AI planning in cybersecurity.
Scenario: Ransomware alert on 3 servers in a hospital network.

Show all three paradigms:
1. STATIC PLANNING — fixed steps decided upfront
2. DYNAMIC PLANNING — adapts as new information arrives
3. HIERARCHICAL PLANNING — draw the goal tree in ASCII art

Keep each section to 5-7 lines.""")])
    print(response.content)

if __name__ == "__main__":
    print("Lab 0: Agentic AI Foundations — PPT Slides 5-10")
    demo_1_what_is_agentic_ai()
    demo_2_cognitive_loop()
    demo_3_react_paradigm()
    demo_4_planning_paradigms()
    print(f"\n{DIVIDER}")
    print("Lab 0 complete. Next: python 00_foundations/rag_demo.py")
    print(DIVIDER)
