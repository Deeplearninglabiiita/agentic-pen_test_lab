"""
LAB-08: Customising the LangGraph Penetration Testing Agent
=============================================================
Estimated time: 20 minutes
Mirrors: Chapter 8 Examples 8-3 to 8-6, Hour 3 Block 1

LEARNING OBJECTIVES
- Understand how PentestState flows through the graph
- Change agent objectives and observe how findings change
- Add a new vulnerability to the mock tools
- Understand conditional routing and how to extend it

TASKS
1. Run the agent with default objectives
2. Change objectives and compare the report
3. Add a new vulnerability class (SSRF) to the agent
4. Add a new graph node for post-exploitation
"""

import sys, json
sys.path.insert(0, '.')
sys.path.insert(0, './02_langgraph_agent')
from state import PentestState
from graph import build_pentest_graph
from shared.config import config
from shared.llm_client import get_llm_with_tools
from langchain_core.messages import HumanMessage, SystemMessage

DIVIDER = "=" * 60


def run_agent(objectives, label, max_iterations=8):
    print(f"\n{DIVIDER}")
    print(f"AGENT RUN: {label}")
    print(DIVIDER)

    initial: PentestState = {
        "scope": [config.LAB_TARGET_DOMAIN, config.LAB_TARGET_URL],
        "objectives": objectives,
        "targets": [], "current_target": None,
        "credentials": [], "shells": [],
        "messages": [], "phase": "recon",
        "iteration": 0, "max_iterations": max_iterations,
        "findings": [], "errors": [],
    }

    agent = build_pentest_graph()
    result = agent.invoke(initial)

    for f in result["findings"]:
        if "[REPORT]" in f:
            print(f.replace("[REPORT]\n", ""))
    print(f"\nIterations: {result['iteration']} | Phase: {result['phase']}")
    return result


# ──────────────────────────────────────────────────────────────
# EXERCISE 1: Default objectives
# ──────────────────────────────────────────────────────────────

result_default = run_agent(
    objectives=[
        "Identify all web-facing services",
        "Discover SQL injection vulnerabilities",
        "Attempt credential extraction",
        "Document findings with CVSS scores",
    ],
    label="Default objectives"
)


# ──────────────────────────────────────────────────────────────
# TASK 1: Change objectives — authentication focus
# Run with different objectives and compare the report sections
# Observe: same tools, same target, different report focus
# ──────────────────────────────────────────────────────────────

result_auth = run_agent(
    objectives=[
        "Focus exclusively on authentication and session management",
        "Check for missing CSRF protection on all forms",
        "Identify any credentials transmitted without HTTPS",
        "Test for weak or default passwords on admin endpoints",
        "Assess multi-factor authentication implementation",
    ],
    label="Authentication-focused objectives"
)


# ──────────────────────────────────────────────────────────────
# TASK 2: Add a new vulnerability class
# Add SSRF to the mock tools and agent assessment
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Add SSRF vulnerability to the agent")
print(DIVIDER)

from langchain_core.tools import tool
from shared.config import config as cfg

@tool
def mock_ssrf_check(target: str) -> str:
    """Check target for Server-Side Request Forgery vulnerability.
    Args:
        target: Target URL to check for SSRF
    """
    allowed = ["localhost", "127.0.0.1", cfg.LAB_TARGET_DOMAIN]
    if not any(a in target for a in allowed):
        raise ValueError(f"SCOPE VIOLATION: {target}")

    result = {
        "target": target,
        "vuln_type": "ssrf",
        "vulnerable": True,
        "endpoint": "/api/fetch?url=",
        "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "evidence": "AWS metadata endpoint accessible — IAM credentials exposed",
        "cvss": 8.6,
        "cwe": "CWE-918",
        "impact": "Cloud credential theft — full AWS account takeover possible"
    }
    return json.dumps(result, indent=2)

# Test the new tool
print("Testing new SSRF check tool...")
ssrf_result = json.loads(mock_ssrf_check.invoke({"target": config.LAB_TARGET_URL}))
print(f"SSRF check result: vulnerable={ssrf_result['vulnerable']}, CVSS={ssrf_result['cvss']}")
print(f"Impact: {ssrf_result['impact']}")

# Now have the agent analyse the SSRF finding
llm = get_llm_with_tools([mock_ssrf_check])
response = llm.invoke([
    SystemMessage(content=f"You are a penetration tester. Check {config.LAB_TARGET_URL} for SSRF using mock_ssrf_check."),
    HumanMessage(content="Assess SSRF vulnerability and explain the business impact.")
])

if response.tool_calls:
    for tc in response.tool_calls:
        if tc["name"] == "mock_ssrf_check":
            result = json.loads(mock_ssrf_check.invoke(tc["args"]))
            print(f"\nSSRF confirmed: {result['evidence']}")

print(response.content)


# ──────────────────────────────────────────────────────────────
# TASK 3: Compare two agent runs
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 3: Comparing default vs authentication-focused reports")
print(DIVIDER)

from shared.llm_client import get_llm
llm_compare = get_llm()

default_report = next((f for f in result_default["findings"] if "[REPORT]" in f), "No report")
auth_report = next((f for f in result_auth["findings"] if "[REPORT]" in f), "No report")

response = llm_compare.invoke([HumanMessage(content=f"""Compare two penetration test reports 
from the same target but with different objectives.

REPORT A (General assessment):
{default_report[:800]}

REPORT B (Authentication-focused):
{auth_report[:800]}

Analysis:
1. What findings appear in both reports?
2. What does Report A find that Report B misses?
3. What does Report B find that Report A misses?
4. Which report is more useful for a CISO? For a developer? For a regulator?
5. What does this tell us about how agent objectives shape investigation?""")])
print(response.content)
