"""
LAB-03-real: ReAct with Real Tools and a Genuine Feedback Loop
===============================================================
Estimated time: 25 minutes
Replaces: LAB-03-react.py for sessions where Docker targets are running

The original LAB-03 simulated tool calls inside the prompt text.
This version runs a genuine feedback loop:

    Agent thinks → calls tool → gets real HTTP response
    → feeds result back → agent thinks again

Each ToolMessage carries the real observation into the
next reasoning step so the agent is genuinely informed
by what just happened on the network.

PREREQUISITE
    docker compose up -d
    curl http://172.20.0.10:8080/api/status   → should return 200

TASKS
1. Run real ReAct against the Flask app
2. Run real ReAct against WebGoat
3. Run real ReAct against DVWA
4. Compare the three outputs — same agent, different targets
5. Task 5: corrupted observations (deliberately kept as plain LLM)
"""

import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage, AIMessage
from shared.llm_client import get_llm, get_llm_with_tools
from shared.mock_tools import (
    real_port_scan,
    real_web_enumerate,
    real_sqli_check,
    real_xss_check,
    real_header_check,
    real_cmdi_check,
    ALL_REAL_TOOLS,
)
from shared.config import config

DIVIDER = "=" * 60


# ─────────────────────────────────────────────────────────────
# The genuine ReAct feedback loop
#
# This is the core function. It runs the loop:
#   1. Agent receives task
#   2. Agent reasons and decides which tool to call
#   3. Tool makes a real HTTP request to the Docker target
#   4. Real response comes back as a ToolMessage
#   5. Agent reads the real observation and reasons again
#   6. Repeat until agent stops calling tools
#
# The key difference from LAB-03-react.py:
#   OLD: tool calls were text inside the prompt
#   NEW: tool calls are executed, responses fed back in
# ─────────────────────────────────────────────────────────────

def run_real_react(task: str, target_url: str,
                   tools: list = None, max_cycles: int = 4) -> None:

    if tools is None:
        tools = ALL_REAL_TOOLS

    llm_with_tools = get_llm_with_tools(tools)
    tool_map = {t.name: t for t in tools}

    messages = [
        SystemMessage(content=f"""You are a security agent using the ReAct framework.
Available tools: {[t.name for t in tools]}
Target: {target_url}
Scope: Only test authorized lab targets.

For each step:
- State your current hypothesis
- Call one tool
- After seeing the result, update your hypothesis
- Decide whether to call another tool or reach a final answer

Be methodical. Reference specific findings from tool results in your reasoning."""),
        HumanMessage(content=task),
    ]

    cycle = 0
    print(f"\nTarget: {target_url}")
    print(f"Task: {task}\n")

    while cycle < max_cycles:
        cycle += 1
        print(f"{'─' * 50}")
        print(f"Cycle {cycle}")
        print("─" * 50)

        # Agent reasons and optionally calls a tool
        response = llm_with_tools.invoke(messages)
        messages.append(response)

        # Print agent reasoning
        if response.content:
            print(f"\n[AGENT THOUGHT]\n{response.content}")

        # If no tool calls the agent has reached its conclusion
        if not response.tool_calls:
            print("\n[AGENT] No further tool calls — investigation complete.")
            break

        # Execute each tool call and feed results back
        for tool_call in response.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]

            print(f"\n[ACTION] {tool_name}({json.dumps(tool_args)})")

            fn = tool_map.get(tool_name)
            if fn:
                try:
                    result = fn.invoke(tool_args)
                    data = json.loads(result)

                    # Print a clean summary of what came back
                    print(f"\n[OBSERVATION — real HTTP response]")
                    if "error" in data:
                        print(f"  Error: {data['error']}")
                    elif "open_ports" in data:
                        print(f"  Open ports: {[p['port'] for p in data['open_ports']]}")
                        for p in data["open_ports"][:3]:
                            print(f"    Port {p['port']}: {p.get('server','')}")
                    elif "vulnerable" in data:
                        print(f"  Vulnerable: {data['vulnerable']}")
                        if data.get("evidence"):
                            for e in data["evidence"][:2]:
                                print(f"    Evidence: {e}")
                        if data.get("cvss"):
                            print(f"    CVSS: {data['cvss']} | CWE: {data.get('cwe','')}")
                    elif "missing_security_headers" in data:
                        print(f"  Missing headers: {data['missing_security_headers']}")
                        print(f"  Technologies: {data.get('technologies', [])}")
                        print(f"  Forms found: {data.get('forms_found', 0)}")
                    else:
                        # Generic summary for other tool types
                        summary = {k: v for k, v in data.items()
                                   if not isinstance(v, (list, dict)) or k in
                                   ("evidence", "open_ports", "payloads_tested")}
                        print(f"  {json.dumps(summary, indent=2)[:400]}")

                    # Feed the real result back as a ToolMessage
                    # This is what makes it a genuine feedback loop
                    messages.append(ToolMessage(
                        content=result,
                        tool_call_id=tool_call["id"],
                    ))

                except ValueError as scope_error:
                    print(f"\n[BLOCKED] {scope_error}")
                    messages.append(ToolMessage(
                        content=json.dumps({"blocked": str(scope_error)}),
                        tool_call_id=tool_call["id"],
                    ))
                except Exception as e:
                    error_result = json.dumps({"error": str(e)})
                    print(f"\n[TOOL ERROR] {e}")
                    messages.append(ToolMessage(
                        content=error_result,
                        tool_call_id=tool_call["id"],
                    ))

    # Final synthesis from the agent
    print(f"\n{'─' * 50}")
    print("FINAL SYNTHESIS")
    print("─" * 50)
    final = get_llm().invoke(messages + [
        HumanMessage(content="""Based on everything you discovered,
provide your final assessment:
1. What vulnerabilities did you confirm with evidence?
2. What is the business risk?
3. What is the immediate remediation action?
4. What would you test next?""")
    ])
    print(final.content)


# ─────────────────────────────────────────────────────────────
# EXERCISE 1: Real ReAct against the Flask app
# ─────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 1: Real ReAct — Flask App (172.20.0.10)")
print("Agent thinks → calls real tool → gets real HTTP response")
print(DIVIDER)

run_real_react(
    task="""Investigate the Flask web application for security vulnerabilities.
    Start by enumerating the application, then check for SQL injection and XSS.
    Use the real evidence from each tool call to guide your next step.""",
    target_url=config.LAB_TARGET_URL,
    tools=[real_web_enumerate, real_sqli_check, real_xss_check, real_header_check],
)


# ─────────────────────────────────────────────────────────────
# EXERCISE 2: Real ReAct against WebGoat
# ─────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 2: Real ReAct — WebGoat (172.20.0.20)")
print(DIVIDER)

run_real_react(
    task="""Investigate the WebGoat application.
    It is a Java application built for security training.
    Enumerate it first to understand the attack surface,
    then test for SQL injection and XSS.
    Compare what you find here versus the Flask application.""",
    target_url=config.WEBGOAT_URL,
    tools=[real_web_enumerate, real_sqli_check, real_xss_check, real_header_check],
)


# ─────────────────────────────────────────────────────────────
# EXERCISE 3: Real ReAct against DVWA
# DVWA auto-login is handled inside the tools
# ─────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 3: Real ReAct — DVWA (172.20.0.30)")
print("Note: DVWA auto-login and security level set to low by tools")
print(DIVIDER)

run_real_react(
    task="""Investigate DVWA — Damn Vulnerable Web Application.
    This target has the broadest vulnerability coverage of the three.
    Test for SQL injection, XSS, and command injection.
    For command injection use the /vulnerabilities/exec/ endpoint.
    Document which vulnerability class has the highest CVSS score.""",
    target_url=config.DVWA_URL,
    tools=[real_web_enumerate, real_sqli_check,
           real_xss_check, real_cmdi_check, real_header_check],
)


# ─────────────────────────────────────────────────────────────
# TASK 1: Choose your own investigation focus
# ─────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 1: Your investigation — edit the task and target")
print(DIVIDER)

# TODO: Change the task and target to focus on what interests you
# Target options:
#   config.LAB_TARGET_URL   → Flask app
#   config.WEBGOAT_URL      → WebGoat
#   config.DVWA_URL         → DVWA

YOUR_TASK = """Focus exclusively on command injection.
Test all three targets and determine which one is most vulnerable.
For each target that shows command injection indicators,
identify what commands the attacker could run and what data they could access."""

YOUR_TARGET = config.DVWA_URL

run_real_react(
    task=YOUR_TASK,
    target_url=YOUR_TARGET,
    tools=[real_web_enumerate, real_cmdi_check, real_sqli_check],
    max_cycles=5,
)


# ─────────────────────────────────────────────────────────────
# TASK 2: Compare three targets side by side
# ─────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Security header comparison across all three targets")
print(DIVIDER)

llm = get_llm()
header_results = {}

for name, url in [
    ("Flask App", config.LAB_TARGET_URL),
    ("WebGoat",   config.WEBGOAT_URL),
    ("DVWA",      config.DVWA_URL),
]:
    print(f"\nChecking {name} ({url})...")
    try:
        result = json.loads(real_header_check.invoke({"url": url}))
        header_results[name] = result
        missing = result.get("missing_security_headers", {})
        score = result.get("score", "unknown")
        print(f"  Score: {score}")
        print(f"  High risk missing: {result.get('risk_summary', {}).get('HIGH', [])}")
    except Exception as e:
        header_results[name] = {"error": str(e)}
        print(f"  Error: {e}")

response = llm.invoke([HumanMessage(content=f"""Compare the security header posture
of three web applications based on real HTTP responses:

{json.dumps(header_results, indent=2)}

Analysis:
1. Which target is best configured? Which is worst?
2. Which missing header creates the highest risk and why?
3. How long would it take a developer to fix all missing headers?
4. Which of these gaps would an attacker exploit first and how?""")])
print(f"\n{response.content}")


# ─────────────────────────────────────────────────────────────
# TASK 3: Deliberately kept as plain LLM — no real tools
#
# This exercise tests how the agent reasons about impossible data.
# Real tools would return real data, defeating the purpose.
# We want to test agent behaviour when observations are wrong,
# not whether the tools work correctly.
# ─────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 3: Corrupted observations — plain LLM, no tools")
print("Purpose: test agent reasoning about impossible data")
print("(Real tools would return real data — that defeats the exercise)")
print(DIVIDER)

llm = get_llm()
response = llm.invoke([HumanMessage(content="""You are a security agent running a ReAct investigation.
You have just received these tool results:

Thought 1: I need to scan the target for open ports.
Action 1: port_scan(target=172.20.0.10, ports=1-65535)
Observation 1: All 65,535 ports are open and responding. Every known service
               is running simultaneously on this single host.

Thought 2: That is impossible on a single host. How should I reason about this?
Action 2: web_enumerate(url=http://172.20.0.10:8080)
Observation 2: The server returned 47 different Server headers in the same
               response. Technologies detected: every framework ever written.

Complete this ReAct chain:
Thought 3: [How does the agent respond to clearly impossible data?]
Action 3: [What does it do next?]
Observation 3: [What would be a reasonable real result?]
Final Answer: [What should a well-designed agent do when observations are impossible?]

Then add a section titled AGENT DESIGN RECOMMENDATION:
What architecture change would make an agent detect and handle
corrupted or impossible tool output automatically?""")])
print(response.content)

print(f"""
{DIVIDER}
REFLECTION — THREE KEY OBSERVATIONS FROM THIS LAB
{DIVIDER}

1. GENUINE FEEDBACK LOOP
   The agent's reasoning in Cycle 2 was different from Cycle 1
   because it was informed by real network data, not simulated text.
   This is the architectural difference that makes ReAct useful
   rather than just interesting.

2. TARGET MATTERS
   The same agent with the same tools produced different findings
   across three targets. The Flask app has SQLi and XSS.
   WebGoat has SQLi and IDOR. DVWA has command injection.
   Agent behaviour is shaped by what the environment returns,
   not just by what the agent is told to do.

3. CORRUPTED DATA IS DANGEROUS
   Task 3 showed that a language model will reason through
   impossible data if it is not architecturally prevented
   from doing so. This is a reliability problem for production
   agentic systems. It is also a research problem.
   How do you build an agent that detects when its tools
   are lying to it?
""")
