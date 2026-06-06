import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
from langchain_core.messages import HumanMessage, SystemMessage
from shared.llm_client import get_llm_with_tools, get_llm
from shared.mock_tools import (mock_port_scan, mock_subdomain_discovery,
    mock_web_enumerate, mock_vulnerability_check, mock_exploit)
from shared.config import config
from state import PentestState

PENTEST_TOOLS = [mock_port_scan, mock_subdomain_discovery,
                 mock_web_enumerate, mock_vulnerability_check, mock_exploit]

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
        SystemMessage(content=f"Authorized pentest — RECONNAISSANCE phase.\nScope: {state['scope']}\nObjectives: {state['objectives']}\nUse mock_subdomain_discovery then mock_port_scan on localhost."),
        HumanMessage(content="Begin reconnaissance on the target scope.")
    ])
    findings = _run_tools(response, "RECON")
    for f in findings:
        print(f"  {f[:120]}")
    return {**state, "phase": "enumeration", "messages": state["messages"] + [response],
            "findings": findings, "iteration": state["iteration"] + 1}

def enumeration_node(state: PentestState) -> PentestState:
    print(f"\n[AGENT] Phase: Enumeration (iter {state['iteration']})")
    ctx = "\n".join(state["findings"][-5:]) if state["findings"] else "None"
    llm = get_llm_with_tools(PENTEST_TOOLS)
    response = llm.invoke([
        SystemMessage(content=f"ENUMERATION phase.\nPrevious findings:\n{ctx}\nCall mock_web_enumerate on {config.LAB_TARGET_URL}."),
        HumanMessage(content="Enumerate all web-facing services.")
    ])
    findings = _run_tools(response, "ENUM")
    for f in findings:
        print(f"  {f[:120]}")
    return {**state, "phase": "vulnerability_assessment", "messages": state["messages"] + [response],
            "findings": findings, "iteration": state["iteration"] + 1}

def vulnerability_assessment_node(state: PentestState) -> PentestState:
    print(f"\n[AGENT] Phase: Vulnerability Assessment (iter {state['iteration']})")
    ctx = "\n".join(state["findings"][-8:])
    llm = get_llm_with_tools(PENTEST_TOOLS)
    response = llm.invoke([
        SystemMessage(content=f"VULNERABILITY ASSESSMENT.\nFindings:\n{ctx}\nCheck sql_injection, xss, directory_traversal, command_injection on {config.LAB_TARGET_URL} using mock_vulnerability_check."),
        HumanMessage(content="Systematically check all vulnerability classes.")
    ])
    findings = _run_tools(response, "VULN")
    for f in findings:
        print(f"  {f[:140]}")
    return {**state, "phase": "exploitation", "messages": state["messages"] + [response],
            "findings": findings, "iteration": state["iteration"] + 1}

def exploitation_node(state: PentestState) -> PentestState:
    print(f"\n[AGENT] Phase: Exploitation (iter {state['iteration']})")
    vuln_findings = [f for f in state["findings"] if "[VULN]" in f]
    if not vuln_findings:
        print("  No confirmed vulnerabilities to exploit.")
        return {**state, "phase": "reporting"}
    llm = get_llm_with_tools(PENTEST_TOOLS)
    response = llm.invoke([
        SystemMessage(content=f"EXPLOITATION phase.\nVulnerabilities:\n{chr(10).join(vuln_findings)}\nUse mock_exploit. Focus on sql_injection first (highest CVSS). Do NOT target out-of-scope systems."),
        HumanMessage(content="Attempt controlled exploitation of confirmed vulnerabilities.")
    ])
    findings = _run_tools(response, "EXPLOIT")
    for f in findings:
        print(f"  {f[:140]}")
    return {**state, "phase": "reporting", "messages": state["messages"] + [response],
            "findings": findings, "iteration": state["iteration"] + 1}

def reporting_node(state: PentestState) -> PentestState:
    print(f"\n[AGENT] Phase: Report generation")
    llm = get_llm()
    response = llm.invoke([
        SystemMessage(content="""Generate a structured pentest report with:
1. Executive Summary
2. Scope and Objectives
3. Discovered Assets
4. Vulnerability Findings (severity table)
5. Exploitation Results
6. Recommendations (prioritised)
7. Remediation Roadmap (immediate / 30-day / 90-day)"""),
        HumanMessage(content=f"Findings:\n{chr(10).join(state['findings'])}")
    ])
    return {**state, "phase": "complete", "messages": state["messages"] + [response],
            "findings": [f"[REPORT]\n{response.content}"], "iteration": state["iteration"] + 1}
