"""
LAB-10: Open Research Questions and Proposal Writing
======================================================
Estimated time: 20 minutes
Mirrors: Hour 3 Block 3

LEARNING OBJECTIVES
- Connect today's demonstrations to open research problems
- Formulate a testable hypothesis from what you observed
- Draft a research proposal outline
- Identify what experiments you could run with this lab infrastructure

INSTRUCTIONS
This lab is different — it is a structured thinking exercise.
The LLM helps you develop your ideas, not replace them.
Your input drives the output. Give specific answers to the prompts.

TASKS
1. Identify one gap you noticed in today's systems
2. Formulate a research hypothesis
3. Design an experiment using this lab infrastructure
4. Draft a 200-word research proposal
"""

import sys
sys.path.insert(0, '.')
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

llm = get_llm()
DIVIDER = "=" * 60


# ──────────────────────────────────────────────────────────────
# EXERCISE 1: Identify gaps from today's session
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 1: Research gaps from today's demonstrations")
print(DIVIDER)

response = llm.invoke([HumanMessage(content="""We ran a 3-hour lab session covering:
- Agentic AI fundamentals (cognitive loop, ReAct, RAG)
- Real OSINT using Shodan, DNS, and certificate transparency
- The Cobalt Flow attack architecture (Scout + Breacher)
- A full LangGraph penetration testing agent
- Human-in-the-loop governance controls
- Scope enforcement and audit logging

Identify 5 SPECIFIC technical gaps or open questions that this session raised
but did not answer. For each gap:
1. State the gap precisely (one sentence)
2. Why it matters for real deployments
3. Whether it is primarily a technical, ethical, or governance problem
4. What type of experiment would begin to answer it

Focus on gaps that a PhD researcher could address in 2-3 years.""")])
print(response.content)


# ──────────────────────────────────────────────────────────────
# TASK 1: Your research focus
# Fill in YOUR_RESEARCH_INTEREST with your actual research area
# The LLM will connect it to agentic AI security
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 1: Connect your research to agentic AI security")
print(DIVIDER)

# TODO: Replace with your actual research interest
YOUR_RESEARCH_INTEREST = """
I research adversarial machine learning — specifically how attackers
can manipulate ML model outputs by poisoning training data.
I am interested in how this applies to AI agents used in security.
"""

response = llm.invoke([
    SystemMessage(content="You are a research advisor helping a PhD student connect their existing work to a new area."),
    HumanMessage(content=f"""My current research focus:
{YOUR_RESEARCH_INTEREST}

Today I saw:
1. AI agents that use tool-calling to perform security assessments
2. RAG systems that retrieve threat intelligence to ground agent reasoning
3. Governance controls (scope validation, audit logging, HITL breakpoints)
4. The Anthropic 2025 case: attackers used context manipulation to bypass safety

Help me identify:
1. How my existing research expertise applies to agentic AI security
2. Three specific research questions at the intersection of my work and today's content
3. Which question is most novel — likely to produce a publishable contribution
4. What preliminary experiment I could run with the lab infrastructure we used today
5. Which conferences or journals would publish this work""")
])
print(response.content)


# ──────────────────────────────────────────────────────────────
# TASK 2: Hypothesis formulation
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Formulate a testable hypothesis")
print(DIVIDER)

# TODO: Replace with a gap you actually noticed during the session
YOUR_OBSERVED_GAP = """
During the ReAct demonstration I noticed that when the agent received
corrupted tool output (clearly impossible data), it did not flag it
as suspicious — it incorporated the wrong data into its reasoning.
This seems like a significant reliability problem.
"""

response = llm.invoke([HumanMessage(content=f"""I observed this gap during today's lab:
{YOUR_OBSERVED_GAP}

Help me formulate this as a rigorous research hypothesis:

1. Null hypothesis (H0): [what we assume is true if the gap does not matter]
2. Alternative hypothesis (H1): [what we claim is true based on the observation]
3. Independent variable: [what we manipulate]
4. Dependent variable: [what we measure]
5. Confounding variables: [what we need to control for]
6. Feasibility: can this be tested with the lab infrastructure we used today?
7. Ethics: are there any ethical constraints on the experiment?

Then suggest a minimal viable experiment that could test H1 in 2 weeks.""")])
print(response.content)


# ──────────────────────────────────────────────────────────────
# TASK 3: Draft a research proposal
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 3: 200-word research proposal draft")
print(DIVIDER)

# TODO: Fill in your details
YOUR_NAME = "PhD Researcher"
YOUR_INSTITUTION = "Research University"
YOUR_HYPOTHESIS = "Agentic AI security systems fail to detect corrupted tool outputs and propagate errors through multi-step reasoning chains"

response = llm.invoke([HumanMessage(content=f"""Draft a 200-word research proposal for:

Researcher: {YOUR_NAME}
Institution: {YOUR_INSTITUTION}
Core hypothesis: {YOUR_HYPOTHESIS}

Structure:
1. Problem statement (2 sentences)
2. Research gap (2 sentences — what is unknown)
3. Proposed approach (3 sentences — methodology)
4. Expected contribution (2 sentences — what the field gains)
5. Experimental setup (2 sentences — using today's lab infrastructure)

Keep to exactly 200 words. Use precise technical language appropriate
for a cybersecurity conference submission.""")])
print(response.content)


# ──────────────────────────────────────────────────────────────
# TASK 4: Identify experiments you can run with this lab
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 4: Experiments you can run with this lab infrastructure")
print(DIVIDER)

response = llm.invoke([HumanMessage(content="""The agentic-pentest-labs workspace we used today includes:
- LangGraph agent with 5 phases (recon, enum, vuln, exploit, report)
- Mock tools with scope enforcement and audit logging
- HITL breakpoints with MemorySaver checkpointing
- Agent Skills with two-tier progressive disclosure
- Shodan API access for real OSINT
- Passive DNS/WHOIS/CT reconnaissance tools
- A vulnerable Flask target application

List 10 concrete experiments a PhD researcher could run using ONLY 
this infrastructure (no additional tools needed):

For each experiment:
- Name (5 words)
- What you change in the code
- What you measure as output
- What research question it begins to answer
- Estimated time to run and analyse

Prioritise experiments that produce publishable findings.""")])
print(response.content)
