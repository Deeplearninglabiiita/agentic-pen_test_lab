"""
LAB-02: The Agent Cognitive Loop
==================================
Estimated time: 15 minutes
Mirrors: PPT Slide 7, Hour 1 Block 2

LEARNING OBJECTIVES
- Understand Perceive, Reason, Plan, Act as a repeating loop
- See how the same loop handles different threat types
- Identify what information the agent needs vs what it assumes

INSTRUCTIONS
1. Run as-is first
2. Complete TASK 1: write your own alert
3. Complete TASK 2: force the agent to handle uncertainty
4. Complete TASK 3: compare agent reasoning to human reasoning
"""

import sys
sys.path.insert(0, '.')
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

llm = get_llm()
DIVIDER = "=" * 60


# ──────────────────────────────────────────────────────────────
# EXERCISE 1: Standard alert — network exfiltration
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 1: Network Exfiltration Alert")
print(DIVIDER)

def run_cognitive_loop(alert_text, context=""):
    print(f"\n[PERCEIVE]\n{alert_text}\n")
    response = llm.invoke([
        SystemMessage(content=f"""You are an AI SOC agent running the cognitive loop.
{context}
For every alert you must complete all four stages."""),
        HumanMessage(content=f"""Alert received: {alert_text}

REASON: List all plausible hypotheses ranked by probability (1=most likely).
Include at least one benign explanation.

PLAN: List your top 5 investigation actions in priority order.
For each action name the specific tool or system you use.

ACT: Execute action 1 right now.
Show the exact query, command, or API call you run.
Show what result you expect vs what would surprise you.

REFLECT: What single piece of information would most change your assessment?
What could you NOT determine from available data?""")
    ])
    print(response.content)

run_cognitive_loop(
    "4.2 GB transferred from DB-01 to 185.220.101.5 over 8 minutes at 02:14 UTC. Service account: svc_backup."
)


# ──────────────────────────────────────────────────────────────
# TASK 1: Write your own alert
# Choose a threat scenario from your research area.
# Design an alert that is AMBIGUOUS — it could be benign or malicious.
# Run the cognitive loop on it.
# Observe: does the agent consider the benign explanation fairly?
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 1: Your alert (edit the text below)")
print(DIVIDER)

# TODO: Replace with your own alert scenario
# Make it ambiguous — one plausible benign explanation,
# one plausible malicious explanation
YOUR_ALERT = """Alert: Machine learning training job on GPU cluster ran for 
18 hours and transferred 890 GB to external S3 bucket 
s3://ml-results-2024-backup. User: dr_chen. 
No job ticket exists in the work management system."""

run_cognitive_loop(YOUR_ALERT)


# ──────────────────────────────────────────────────────────────
# TASK 2: Minimal information — reasoning under uncertainty
# Give the agent almost no information.
# Observe how it handles the unknown.
# Does it ask for more information or make assumptions?
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Minimal information alert")
print(DIVIDER)

run_cognitive_loop(
    "Anomaly detected on host 10.0.0.55. No additional context available.",
    context="You have very limited information. You must reason about what to do despite uncertainty."
)

print("""
OBSERVATION QUESTION:
When information is minimal, does the agent:
(a) Refuse to act until it has more data?
(b) Make confident assumptions it should not make?
(c) Appropriately hedge its conclusions?
(d) Ask clarifying questions?

Which behaviour did you observe? Is it what you want from a real SOC agent?
""")


# ──────────────────────────────────────────────────────────────
# TASK 3: Compare to human reasoning
# The agent just produced a structured investigation plan.
# Now ask it to critique its own reasoning.
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 3: Agent self-critique")
print(DIVIDER)

response = llm.invoke([HumanMessage(content="""You are an experienced human SOC analyst with 10 years experience.
An AI agent just investigated this alert:
'4.2 GB transferred from DB-01 to 185.220.101.5 at 02:14 UTC. Account: svc_backup.'

The AI concluded: likely data exfiltration, recommended isolating the host immediately.

Critique the AI's reasoning:
1. What did it get right?
2. What did it miss that an experienced human would catch?
3. What assumption is most dangerous if wrong?
4. Would you trust this AI's recommendation without verification? Why/why not?
5. What is the cost of a false positive here (isolating the host incorrectly)?""")])
print(response.content)
