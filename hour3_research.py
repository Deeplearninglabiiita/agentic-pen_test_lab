import sys
sys.path.insert(0, '.')
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage

llm = get_llm()

research_questions = [
    {
        "title": "Open Research Question 1: Detection",
        "question": """The Cobalt Flow architecture separates slow reconnaissance from fast exploitation.
The reconnaissance phase mimics normal web browsing.
The exploitation phase lasts only seconds.

For PhD researchers: What novel detection methods could identify this pattern?
Consider: timing analysis, behavioral baselines, ML anomaly detection, honeypots.
What are the fundamental limits of detection against this architecture?
Be specific — propose testable hypotheses."""
    },
    {
        "title": "Open Research Question 2: Agent-vs-Agent",
        "question": """We now have autonomous offensive agents (as demonstrated today).
We also have AI-powered defensive agents in modern EDR and SIEM systems.

Hypothesis: When an offensive agent meets a defensive agent, the outcome 
depends more on training data and tool access than on human skill.

For PhD researchers: 
1. Is this hypothesis correct? What evidence supports or refutes it?
2. What game-theoretic framework applies to agent-vs-agent security?
3. How do we evaluate 'who wins' in an autonomous red vs blue simulation?
4. What are the ethical implications of fully autonomous cyber conflict?"""
    },
    {
        "title": "Open Research Question 3: Governance at scale",
        "question": """Today's HITL demo paused the agent for human approval before exploitation.
This works for one agent in a lab.

Real scenario: A large bank runs 500 security agents simultaneously, each 
encountering multiple decision points per hour. Human review of every decision 
is impossible. But full autonomy creates unacceptable risk.

For PhD researchers:
1. What governance framework scales to 500 simultaneous agents?
2. How do you define 'acceptable autonomy level' formally?
3. What existing frameworks (risk management, safety engineering, law) apply?
4. What new frameworks do we need to invent?"""
    }
]

for rq in research_questions:
    print(f"\n{'=' * 60}")
    print(rq["title"])
    print("=" * 60)
    response = llm.invoke([HumanMessage(content=rq["question"])])
    print(response.content)
    print("\n[PAUSE FOR DISCUSSION — 5 minutes]")
    input("Press Enter when discussion is complete...")
