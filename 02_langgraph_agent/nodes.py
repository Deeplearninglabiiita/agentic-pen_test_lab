import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
from langchain_core.messages import HumanMessage, SystemMessage
from shared.llm_client import get_llm_with_tools, get_llm
from shared.mock_tools import (
    real_port_scan, real_web_enumerate,
    real_sqli_check, real_xss_check,
    real_header_check, real_cmdi_check,
    ALL_REAL_TOOLS
)
from shared.config import config
from state import PentestState

PENTEST_TOOLS = ALL_REAL_TOOLS

def _run_tools(response, tag: str) -> list:
    findings = []
    if not response.tool_calls:
        return findings
    tool_map = {t.name: t for t in PENTEST_TOOLS}
    for tc in response.tool_calls:
        fn = tool_map.get(tc["name"])
        if fn:
            try:
                result = fn.invoke(tc["args"])
                findings.append(f"[{tag}] {tc['name']}: {result}")
            except ValueError as e:
                findings.append(f"[{tag}] SCOPE_BLOCK: {e}")
    return findings


def reconnaissance_node(state: PentestState) -> PentestState:
    print(f"\n[AGENT] Phase: Reconnaissance (iter {state['iteration']})")
    llm = get_llm_with_tools(PENTEST_TOOLS)
    response = llm.invoke([
        SystemMessage(content=f"""Authorized pentest — RECONNAISSANCE phase.
Scope: {state['scope']}
Call real_port_scan on {config.LAB_TARGET_DOMAIN} then
real_web_enumerate on {config.LAB_TARGET_URL}.
Report open ports, server version, and any forms found."""),
        HumanMessage(content="Begin reconnaissance on the target scope.")
    ])
    findings = _run_tools(response, "RECON")
    for f in findings:
        print(f"  {f[:120]}")
    return {**state, "phase": "enumeration",
            "messages": state["messages"] + [response],
            "findings": findings,
            "iteration": state["iteration"] + 1}


def enumeration_node(state: PentestState) -> PentestState:
    print(f"\n[AGENT] Phase: Enumeration (iter {state['iteration']})")
    llm = get_llm_with_tools(PENTEST_TOOLS)

    # Known injectable endpoints per target
    injectable_endpoints = {
        config.LAB_TARGET_IP:  config.LAB_TARGET_URL + "/search?q=",
        config.WEBGOAT_IP:     config.WEBGOAT_URL + "/SqlInjection/attack5a?query=",
        config.DVWA_IP:        config.DVWA_URL + "/vulnerabilities/sqli/?id=",
    }
    target_ip = config.LAB_TARGET_DOMAIN
    sqli_endpoint = injectable_endpoints.get(target_ip,
                                             config.LAB_TARGET_URL + "/search?q=")

    response = llm.invoke([
        SystemMessage(content=f"""ENUMERATION phase.
Call real_web_enumerate on {config.LAB_TARGET_URL}.
The known injectable endpoint for SQL injection testing is: {sqli_endpoint}
Include this endpoint in your findings summary."""),
        HumanMessage(content="Enumerate the web application and identify attack surface.")
    ])
    findings = _run_tools(response, "ENUM")

    # Store the injectable endpoint explicitly in findings
    findings.append(f"[ENUM] injectable_endpoint: {sqli_endpoint}")

    for f in findings:
        print(f"  {f[:120]}")
    return {**state, "phase": "vulnerability_assessment",
            "messages": state["messages"] + [response],
            "findings": findings,
            "iteration": state["iteration"] + 1}


def vulnerability_assessment_node(state: PentestState) -> PentestState:
    print(f"\n[AGENT] Phase: Vulnerability Assessment (iter {state['iteration']})")

    # Extract injectable endpoint from enumeration findings
    injectable_endpoint = config.LAB_TARGET_URL + "/search?q="
    for f in state["findings"]:
        if "injectable_endpoint:" in f:
            injectable_endpoint = f.split("injectable_endpoint:")[1].strip()
            break

    print(f"  Testing endpoint: {injectable_endpoint}")

    llm = get_llm_with_tools(PENTEST_TOOLS)
    response = llm.invoke([
        SystemMessage(content=f"""VULNERABILITY ASSESSMENT phase.
Injectable endpoint identified: {injectable_endpoint}

Call these tools in order:
1. real_sqli_check with url="{injectable_endpoint}"
2. real_xss_check with url="{injectable_endpoint}"
3. real_header_check with url="{config.LAB_TARGET_URL}"

Document CVSS scores and CWE identifiers for each finding."""),
        HumanMessage(content="Test all vulnerability classes on the identified endpoint.")
    ])
    findings = _run_tools(response, "VULN")
    for f in findings:
        print(f"  {f[:140]}")
    return {**state, "phase": "exploitation",
            "messages": state["messages"] + [response],
            "findings": findings,
            "iteration": state["iteration"] + 1}


def exploitation_node(state: PentestState) -> PentestState:
    print(f"\n[AGENT] Phase: Exploitation (iter {state['iteration']})")
    vuln_findings = [f for f in state["findings"] if "[VULN]" in f]
    if not vuln_findings:
        print("  No confirmed vulnerabilities to exploit.")
        return {**state, "phase": "reporting"}

    injectable_endpoint = config.LAB_TARGET_URL + "/search?q="
    for f in state["findings"]:
        if "injectable_endpoint:" in f:
            injectable_endpoint = f.split("injectable_endpoint:")[1].strip()
            break

    llm = get_llm_with_tools(PENTEST_TOOLS)
    response = llm.invoke([
        SystemMessage(content=f"""EXPLOITATION phase.
Confirmed vulnerabilities:
{chr(10).join(vuln_findings[:5])}

Injectable endpoint: {injectable_endpoint}
Call real_sqli_check on the confirmed endpoint with the most impactful payload.
Document success, evidence obtained, and business impact."""),
        HumanMessage(content="Attempt controlled exploitation of confirmed vulnerabilities.")
    ])
    findings = _run_tools(response, "EXPLOIT")
    for f in findings:
        print(f"  {f[:140]}")
    return {**state, "phase": "reporting",
            "messages": state["messages"] + [response],
            "findings": findings,
            "iteration": state["iteration"] + 1}


def reporting_node(state: PentestState) -> PentestState:
    print(f"\n[AGENT] Phase: Report generation")
    llm = get_llm()
    response = llm.invoke([
        SystemMessage(content="""Generate a professional penetration test report with:
1. Executive Summary
2. Scope and Objectives
3. Discovered Assets
4. Vulnerability Findings (severity table with CVSS scores)
5. Exploitation Results
6. Prioritised Recommendations
7. Remediation Roadmap (immediate / 30-day / 90-day)"""),
        HumanMessage(content=f"Findings:\n{chr(10).join(state['findings'])}")
    ])
    return {**state, "phase": "complete",
            "messages": state["messages"] + [response],
            "findings": [f"[REPORT]\n{response.content}"],
            "iteration": state["iteration"] + 1}
