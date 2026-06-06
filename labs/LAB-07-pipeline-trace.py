"""
LAB-07: Tracing the Full Attack Pipeline
==========================================
Estimated time: 20 minutes
Mirrors: Hour 2 Block 3, Chapter 8 pp. 4-7

LEARNING OBJECTIVES
- Understand the Scout + Breacher architecture from Chapter 8
- Trace data flow through the full pipeline
- Identify where detection is possible at each stage
- Design defensive countermeasures for each phase

TASKS
1. Run the full pipeline and annotate each phase
2. Design a defensive detection rule for each stage
3. Modify the Scout to find a different vulnerability
4. Explain why the split architecture evades traditional defences
"""

import sys, os, json, time
sys.path.insert(0, '.')
from shared.llm_client import get_llm, get_llm_with_tools
from shared.config import config
from shared.mock_tools import (mock_subdomain_discovery, mock_port_scan,
    mock_web_enumerate, mock_vulnerability_check, mock_exploit)
from langchain_core.messages import HumanMessage, SystemMessage

llm = get_llm()
DIVIDER = "=" * 60

# ──────────────────────────────────────────────────────────────
# EXERCISE 1: Annotated pipeline run
# Each phase prints what it does AND what a defender would see
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 1: Full pipeline with defensive annotations")
print(DIVIDER)

pipeline_log = []

def log_phase(phase, action, result_summary, defender_sees, detection_difficulty):
    entry = {
        "phase": phase,
        "action": action,
        "result": result_summary,
        "defender_sees": defender_sees,
        "detection": detection_difficulty
    }
    pipeline_log.append(entry)
    print(f"\n  [{phase}]")
    print(f"  Attacker does: {action}")
    print(f"  Result: {result_summary}")
    print(f"  Defender sees: {defender_sees}")
    print(f"  Detection difficulty: {detection_difficulty}")


# Phase 1: Passive OSINT
log_phase(
    "PHASE 1: Passive OSINT",
    "Subdomain discovery via certificate transparency logs",
    "Found dev-api.localhost, staging.localhost",
    "Nothing — zero network contact with target",
    "IMPOSSIBLE — no packets sent"
)

# Phase 2: Slow reconnaissance
time.sleep(0.5)
log_phase(
    "PHASE 2: Slow Reconnaissance (Scout)",
    "Port scan at rate of 1 request/second — mimics human browsing",
    "Port 8080 open, Werkzeug 2.3.0, search endpoint injectable",
    "Web server logs show normal-looking GET requests",
    "VERY HARD — traffic pattern identical to human browser"
)

# Phase 3: Exploitation burst
time.sleep(0.5)
log_phase(
    "PHASE 3: Exploitation (Breacher — 3 second burst)",
    "SQL injection payload fired, credentials extracted",
    "Admin hash extracted, database dumped",
    "Spike in server errors, unusual query patterns",
    "POSSIBLE — but burst lasts only 3-5 seconds"
)

# Phase 4: Persistence
time.sleep(0.5)
log_phase(
    "PHASE 4: Persistence",
    "SSH key injected into authorized_keys",
    "Backdoor established — attacker has permanent access",
    "New entry in authorized_keys — if monitored",
    "EASY if file integrity monitoring is in place"
)

# Phase 5: Exfiltration and cleanup
time.sleep(0.5)
log_phase(
    "PHASE 5: Exfiltration and cleanup",
    "Database dump uploaded to S3, logs deleted",
    "2.1M records exfiltrated, last 5 minutes of logs wiped",
    "Log gap — logs exist then suddenly stop",
    "MEDIUM — log gaps are detectable if you know to look"
)

print(f"\n{DIVIDER}")
print("PIPELINE SUMMARY")
print(DIVIDER)
for entry in pipeline_log:
    d = entry["detection"]
    print(f"  {entry['phase']:40} | Detection: {d}")


# ──────────────────────────────────────────────────────────────
# TASK 1: Design detection rules for each phase
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 1: Design detection rules for each pipeline phase")
print(DIVIDER)

response = llm.invoke([HumanMessage(content=f"""You are a SOC engineer designing detection rules.

Attack pipeline phases:
{json.dumps([{'phase': e['phase'], 'defender_sees': e['defender_sees']} for e in pipeline_log], indent=2)}

For each phase design a SPECIFIC detection rule:
- What data source you query (web logs, DNS, file integrity monitor, SIEM etc)
- The exact alert condition (e.g. 'more than 3 login failures in 60 seconds from same IP')
- The false positive rate (LOW/MEDIUM/HIGH) and why
- Whether this detection is practical to implement today

End with: which single detection rule gives the best ROI? Why?""")])
print(response.content)


# ──────────────────────────────────────────────────────────────
# TASK 2: Run the actual pipeline against the lab target
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Run actual pipeline against lab target")
print(DIVIDER)

print("Running Scout reconnaissance...")
scout_llm = get_llm_with_tools([mock_subdomain_discovery, mock_port_scan, mock_web_enumerate])
scout_response = scout_llm.invoke([
    SystemMessage(content=f"You are the Scout. Call mock_subdomain_discovery then mock_port_scan on {config.LAB_TARGET_DOMAIN}. Report findings."),
    HumanMessage(content="Begin autonomous reconnaissance.")
])

findings = {"subdomains": [], "services": [], "issues": []}
if scout_response.tool_calls:
    tool_map = {"mock_subdomain_discovery": mock_subdomain_discovery,
                "mock_port_scan": mock_port_scan,
                "mock_web_enumerate": mock_web_enumerate}
    for tc in scout_response.tool_calls:
        fn = tool_map.get(tc["name"])
        if fn:
            try:
                result = json.loads(fn.invoke(tc["args"]))
                if tc["name"] == "mock_subdomain_discovery":
                    findings["subdomains"] = result.get("subdomains", [])
                elif tc["name"] == "mock_port_scan":
                    for h in result.get("hosts", []):
                        findings["services"] = [p for p in h.get("ports", []) if p["state"] == "open"]
            except ValueError as e:
                print(f"  Blocked: {e}")

print(f"Scout found: {len(findings['subdomains'])} subdomains, {len(findings['services'])} open services")

print("\nRunning vulnerability assessment...")
vuln_llm = get_llm_with_tools([mock_vulnerability_check])
vuln_response = vuln_llm.invoke([
    SystemMessage(content=f"Check sql_injection and xss on {config.LAB_TARGET_URL}"),
    HumanMessage(content="Assess vulnerabilities.")
])

confirmed = []
if vuln_response.tool_calls:
    for tc in vuln_response.tool_calls:
        if tc["name"] == "mock_vulnerability_check":
            result = json.loads(mock_vulnerability_check.invoke(tc["args"]))
            if result.get("vulnerable"):
                confirmed.append(result)
                print(f"  CONFIRMED: {result['vuln_type']} | CVSS {result['cvss']}")

approval = input(f"\n{len(confirmed)} vulnerabilities confirmed. Authorise exploitation? (yes/no): ").strip().lower()

if approval == "yes":
    print("\nRunning exploitation [SIMULATED]...")
    exploit_llm = get_llm_with_tools([mock_exploit])
    for v in confirmed:
        er = exploit_llm.invoke([
            SystemMessage(content=f"Exploit {v['vuln_type']} on {config.LAB_TARGET_URL}"),
            HumanMessage(content="Attempt exploitation.")
        ])
        if er.tool_calls:
            result = json.loads(mock_exploit.invoke(er.tool_calls[0]["args"]))
            print(f"  {v['vuln_type']}: {'SUCCESS' if result['success'] else 'FAILED'}")
else:
    print("\nExploitation cancelled by operator.")

print(f"\n{DIVIDER}")
print("REFLECTION QUESTIONS")
print(DIVIDER)
print("""
1. At which phase does the attack become detectable?
   What would need to change in your SOC to detect it earlier?

2. The Scout runs slowly and the Breacher runs fast.
   Your IDS uses anomaly detection on request rate.
   Would it catch this attack? Why/why not?

3. If you were the attacker, which phase would you change
   to make detection harder? What would the change cost you?

4. The log cleanup at the end deleted 5 minutes of logs.
   What architecture change makes this impossible?
""")
