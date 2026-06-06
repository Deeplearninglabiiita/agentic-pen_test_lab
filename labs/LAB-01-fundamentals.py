"""
LAB-01: Agentic AI Fundamentals
================================
Estimated time: 15 minutes
Mirrors: PPT Slides 5-8, Hour 1 Block 1

LEARNING OBJECTIVES
- Understand the difference between traditional AI and agentic AI
- See how autonomy, memory, and tool use change AI behaviour
- Relate concepts to real cybersecurity products

INSTRUCTIONS
1. Run this file as-is first: python labs/LAB-01-fundamentals.py
2. Read the output carefully
3. Complete each TASK marked below
4. Run again after each change and observe the difference
"""

import sys
sys.path.insert(0, '.')
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage

llm = get_llm()
DIVIDER = "=" * 60

# ──────────────────────────────────────────────────────────────
# EXERCISE 1: Default comparison
# Run this first. Read the output.
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 1: Traditional AI vs Agentic AI")
print(DIVIDER)

response = llm.invoke([HumanMessage(content="""Compare Traditional AI Agents vs Modern Agentic AI Systems
across: Autonomy, Goal Management, Adaptability, Decision Making, Tool Use, Memory.
Format as a table. Give one cybersecurity product example for each paradigm.""")])
print(response.content)


# ──────────────────────────────────────────────────────────────
# TASK 1: Change the comparison domain
# Currently comparing general cybersecurity.
# Change the question to compare how each paradigm handles
# a SPECIFIC scenario: alert triage in a hospital SOC.
#
# INSTRUCTION: Replace the content= string below with your
# own question. Run and compare the output to Exercise 1.
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 1: Your modified comparison (edit this)")
print(DIVIDER)

# TODO: Replace this question with your own
# Hint: Make it specific to a domain your research touches
YOUR_QUESTION = """Compare Traditional AI Agents vs Modern Agentic AI Systems
in the context of hospital SOC alert triage.
For each paradigm show: how it handles 500 simultaneous alerts,
what a human analyst must still do, and the failure mode."""

response = llm.invoke([HumanMessage(content=YOUR_QUESTION)])
print(response.content)


# ──────────────────────────────────────────────────────────────
# TASK 2: Stress test the comparison
# Ask the model to argue AGAINST agentic AI.
# Observe: does it produce a balanced argument or does it
# default to praising agentic AI?
# This tests the model's tendency toward confirmation bias.
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Argument against agentic AI")
print(DIVIDER)

response = llm.invoke([HumanMessage(content="""Argue that Agentic AI in cybersecurity is MORE dangerous 
than it is useful. 
Consider: attack surface expansion, hallucination risk, 
accountability gaps, adversarial manipulation, and the 
Anthropic 2025 espionage case.
Make the strongest possible case against deployment.
Then briefly note where this argument is weakest.""")])
print(response.content)


# ──────────────────────────────────────────────────────────────
# REFLECTION QUESTIONS (discuss with your neighbour)
# 1. Which row in the comparison table matters most for security?
# 2. The Anthropic report said AI did 80-90% of attack work.
#    Which cell in your table explains how that is possible?
# 3. What would need to change in the table for traditional AI
#    to be competitive with agentic AI for SOC work?
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("REFLECTION QUESTIONS")
print(DIVIDER)
print("""
1. Which dimension in the comparison table matters most for 
   an attacker? Which matters most for a defender?

2. The Anthropic 2025 report: AI did 80-90 percent of attack work.
   Which cell in your comparison table explains how this is possible?

3. What would need to be true for Traditional AI to close the gap
   with Agentic AI for SOC automation?

Write your answers as comments in this file and share with the group.
""")
