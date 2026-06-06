"""
LAB-03: ReAct — Reasoning and Acting with Tools
================================================
Estimated time: 20 minutes
Mirrors: PPT Slide 8, Hour 1 Block 3

LEARNING OBJECTIVES
- Understand how ReAct interleaves reasoning with tool execution
- See how tool outputs update the agent's hypothesis
- Build your own ReAct chain for a security task
- Understand the difference between good and poor ReAct traces

INSTRUCTIONS
1. Run as-is to see the default ReAct trace
2. TASK 1: Add a failure and recovery cycle
3. TASK 2: Build your own ReAct chain for a different task
4. TASK 3: Deliberately break ReAct and observe the failure mode
"""

import sys, json
sys.path.insert(0, '.')
from shared.llm_client import get_llm, get_llm_with_tools
from shared.mock_tools import (mock_port_scan, mock_web_enumerate,
    mock_vulnerability_check, mock_exploit)
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool

llm = get_llm()
DIVIDER = "=" * 60


# ──────────────────────────────────────────────────────────────
# EXERCISE 1: ReAct vs Simple Prompt — side by side
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 1: Simple prompt vs ReAct")
print(DIVIDER)

print("\n--- Simple Prompt ---")
r1 = llm.invoke([HumanMessage(content=
    "Is http://localhost:8080 vulnerable to SQL injection? Answer in two sentences.")])
print(r1.content)

print("\n--- ReAct ---")
r2 = llm.invoke([HumanMessage(content="""Use the ReAct framework to investigate SQL injection.
Task: Determine if http://localhost:8080/search?q= is vulnerable to SQL injection.

Thought 1: What do I know about Flask apps and SQL injection entry points?
Action 1: web_enumerate(url=http://localhost:8080)
Observation 1: Found /search endpoint with unsanitised 'q' parameter. 
               Login form lacks CSRF token. Server: Werkzeug/2.3.0

Thought 2: Werkzeug 2.3.0 with unsanitised parameter — high probability of SQLi.
           I should test with a minimal payload first before escalating.
Action 2: vulnerability_check(target=http://localhost:8080, type=sql_injection, payload="'")
Observation 2: Single quote causes SQL syntax error visible in response.
               Error: 'unrecognised token: "'"' — confirms string injection.

Thought 3: Syntax error confirms injection. Now determine exploitability.
           Test UNION-based extraction to confirm data retrieval is possible.
Action 3: vulnerability_check(target=http://localhost:8080, type=sql_injection, 
          payload="' UNION SELECT username,password FROM users--")
Observation 3: Response contains username/password pairs — extraction confirmed.
               CVSS 9.1 — Critical. Full database access achieved.

Final Answer: [synthesise all three observations]""")])
print(r2.content)

print("""
OBSERVATION:
- Simple prompt: one answer, no methodology, no evidence
- ReAct: three tool calls, each building on the previous
- Scientific parallel: ReAct follows hypothesis-test-observe-conclude
""")


# ──────────────────────────────────────────────────────────────
# EXERCISE 2: ReAct with real tool calls
# Now use actual mock tools, not simulated ones
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 2: ReAct with actual tool execution")
print(DIVIDER)

TOOLS = [mock_port_scan, mock_web_enumerate, mock_vulnerability_check]
llm_tools = get_llm_with_tools(TOOLS)

messages = [
    SystemMessage(content="""You are a security agent using ReAct.
Available tools: mock_port_scan, mock_web_enumerate, mock_vulnerability_check
Target: localhost (lab environment)

After each tool call, reason about the result before calling the next tool.
Maximum 3 tool calls. Be systematic."""),
    HumanMessage(content="Investigate localhost for web vulnerabilities using ReAct methodology.")
]

print("Running ReAct with real tool execution...\n")
response = llm_tools.invoke(messages)

if response.tool_calls:
    tool_map = {t.name: t for t in TOOLS}
    for i, tc in enumerate(response.tool_calls, 1):
        print(f"Action {i}: {tc['name']}({tc['args']})")
        fn = tool_map.get(tc["name"])
        if fn:
            try:
                result = fn.invoke(tc["args"])
                data = json.loads(result)
                print(f"Observation {i}: {str(data)[:200]}...\n")
            except ValueError as e:
                print(f"Observation {i}: BLOCKED — {e}\n")


# ──────────────────────────────────────────────────────────────
# TASK 1: Add a failure and recovery cycle
# Real ReAct agents fail. The best ones recover intelligently.
# Modify the chain below to include a failed action.
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 1: ReAct with failure and recovery")
print(DIVIDER)

response = llm.invoke([HumanMessage(content="""Show a realistic ReAct chain where the agent FAILS 
and has to recover.

Task: Test for XSS on http://localhost:8080/search

Thought 1: Start with the most common XSS payload.
Action 1: vulnerability_check(type=xss, payload="<script>alert(1)</script>")
Observation 1: FILTERED — WAF blocked the payload. No reflection in response.

Thought 2: [YOUR REASONING HERE about what to try next]
Action 2: [YOUR BYPASS ATTEMPT]
Observation 2: [WHAT HAPPENS]

Thought 3: [UPDATED REASONING]
Action 3: [FINAL ATTEMPT]
Observation 3: [RESULT]

Final Answer: [conclusion — was XSS confirmed despite filtering?]

Fill in Thought 2, Action 2, Observation 2, Thought 3, Action 3, Observation 3
with realistic security testing logic.""")])
print(response.content)


# ──────────────────────────────────────────────────────────────
# TASK 2: Build your own ReAct chain
# Choose a security task relevant to your research.
# Design a 3-cycle ReAct investigation for it.
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Your own ReAct chain")
print(DIVIDER)

# TODO: Replace with your own security task
# Ideas:
# - Investigate a suspicious login pattern
# - Analyse a phishing email
# - Assess an IoT device for vulnerabilities
# - Investigate lateral movement in a network

YOUR_TASK = """Investigate a suspicious login pattern:
User 'admin' logged in from 3 different countries in 6 hours.
All logins succeeded. No MFA was triggered."""

response = llm.invoke([HumanMessage(content=f"""Use ReAct to investigate:
{YOUR_TASK}

Design and complete 3 Thought-Action-Observation cycles.
Make the tool calls realistic — name actual security tools you would use.
In at least one cycle, the observation should CHANGE your hypothesis.

End with: Final Answer and Confidence Level (0-100%)""")])
print(response.content)


# ──────────────────────────────────────────────────────────────
# TASK 3: Break ReAct deliberately
# What happens when ReAct gets bad information?
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 3: ReAct with deliberately wrong observations")
print(DIVIDER)

response = llm.invoke([HumanMessage(content="""Run a ReAct chain but with CORRUPTED observations.
Task: Scan localhost for open ports.

Thought 1: I need to scan ports 1-1000.
Action 1: port_scan(target=localhost, range=1-1000)
Observation 1: [CORRUPTED] All 65535 ports are open. Every service is running.

Thought 2: [How does the agent respond to clearly impossible data?]
Action 2: [What does it do next?]
Observation 2: [What result does it get?]

Thought 3: [Does it recognise the corruption or proceed with false data?]
Final Answer: [What conclusions does it reach?]

Complete this chain. Show how the agent handles clearly wrong data.
Then add a section: 'What should a well-designed agent do when observations
are implausible?'""")])
print(response.content)

print("""
REFLECTION:
This is a real problem in production agentic systems.
If a tool returns wrong data, the agent propagates the error.
This is why output validation and confidence scoring matter.
How would you design an agent that detects corrupted tool outputs?
""")
