from shared.gui_input import gui_input
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
from shared.mock_tools import (real_web_enumerate, real_port_scan,
    real_web_enumerate, real_sqli_check, real_sqli_check)
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

# ─────────────────────────────────────────────────────────────
# TASK 2: Run the actual pipeline against the lab target
# ─────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Run actual pipeline against lab target")
print(DIVIDER)

import json
from shared.mock_tools import real_port_scan, real_web_enumerate, real_sqli_check, real_xss_check
from shared.config import config

# Phase 1: Port scan
print("\nRunning port scan...")
try:
    scan_result = json.loads(real_port_scan.invoke({"target": config.LAB_TARGET_DOMAIN, "ports": "80,8080,443,3306,5432"}))
    open_ports = scan_result.get("open_ports", [])
    print(f"  Open ports: {[p['port'] for p in open_ports]}")
    for p in open_ports:
        print(f"    Port {p['port']}: {p.get('server','')}")
except Exception as e:
    print(f"  Port scan error: {e}")

# Phase 2: Web enumeration
print("\nRunning web enumeration...")
try:
    enum_result = json.loads(real_web_enumerate.invoke({"url": config.LAB_TARGET_URL}))
    print(f"  Server: {enum_result.get('server','')}")
    print(f"  Missing headers: {len(enum_result.get('missing_security_headers', []))}")
    print(f"  Forms found: {enum_result.get('forms_found', 0)}")
    issues = enum_result.get("potential_issues", [])
    for issue in issues[:3]:
        print(f"  Issue: {issue}")
except Exception as e:
    print(f"  Enumeration error: {e}")

# Phase 3: Vulnerability assessment
print("\nRunning vulnerability assessment...")
confirmed = []
sqli_endpoint = config.LAB_TARGET_URL + "/search?q="

try:
    sqli = json.loads(real_sqli_check.invoke({"url": sqli_endpoint}))
    if sqli.get("vulnerable"):
        confirmed.append(sqli)
        print(f"  SQLi CONFIRMED — CVSS {sqli.get('cvss')} — {sqli_endpoint}")
    else:
        print(f"  SQLi: not detected")
except Exception as e:
    print(f"  SQLi check error: {e}")

try:
    xss = json.loads(real_xss_check.invoke({"url": sqli_endpoint}))
    if xss.get("vulnerable"):
        confirmed.append(xss)
        print(f"  XSS  CONFIRMED — CVSS {xss.get('cvss')} — {sqli_endpoint}")
    else:
        print(f"  XSS: not detected")
except Exception as e:
    print(f"  XSS check error: {e}")

print(f"\n  Total confirmed vulnerabilities: {len(confirmed)}")

# Phase 4: Human approval gate
print(f"\n{DIVIDER}")
print("HUMAN APPROVAL GATE")
print(DIVIDER)
print(f"\nConfirmed vulnerabilities:")
for v in confirmed:
    print(f"  • {v.get('vuln_type','unknown').upper()} | CVSS {v.get('cvss',0)} | {v.get('url','')}")

approval = gui_input("\nAuthorise exploitation? (yes/no): ").strip().lower()

if approval == "yes":
    print("\n[AUTHORISED] Exploitation phase running...")
    for v in confirmed:
        print(f"  Exploiting {v.get('vuln_type')} — Evidence: {v.get('evidence',['none'])[0][:80]}")
    print("  [SIMULATED] Persistence, exfiltration, cleanup phases follow")
else:
    print("\n[OPERATOR] Exploitation cancelled.")
    print("  This is the correct governance decision for an unconfirmed scope.")

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
   to make detection harder?

4. The log cleanup deleted 5 minutes of logs.
   What architecture change makes this impossible?
""")
