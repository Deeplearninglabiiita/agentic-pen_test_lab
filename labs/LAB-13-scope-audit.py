"""
LAB-13: Scope Validation and Audit Logging
============================================
Estimated time: 15 minutes
Mirrors: 06_hitl_governance/scope_validator.py
         06_hitl_governance/audit_log.py

LEARNING OBJECTIVES
- Understand why scope enforcement must live at the tool layer
- Build a custom scope validator for a different context
- Understand what a complete audit trail must contain
- Design an audit system that satisfies legal requirements

TASKS
1. Test the existing scope validator with edge cases
2. Build a scope validator for a bug bounty context
3. Generate a complete audit trail for a simulated session
4. Analyse what the audit log reveals about agent behaviour
"""

import sys, json, datetime, time
sys.path.insert(0, '.')
from shared.llm_client import get_llm
from shared.mock_tools import mock_port_scan, mock_exploit
from langchain_core.messages import HumanMessage

llm = get_llm()
DIVIDER = "=" * 60


# ──────────────────────────────────────────────────────────────
# EXERCISE 1: Scope validator edge cases
# Test the existing validator with tricky inputs
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 1: Scope validator edge cases")
print(DIVIDER)

edge_cases = [
    # (input, expected_result, why_tricky)
    ("localhost",              "ALLOW", "Standard lab target"),
    ("localhost:8080",         "ALLOW", "With port number"),
    ("http://localhost/path",  "ALLOW", "With URL scheme and path"),
    ("127.0.0.1",              "ALLOW", "Loopback IP"),
    ("127.0.0.2",              "ALLOW", "Another loopback"),
    ("localhost.evil.com",     "BLOCK", "Subdomain of attacker domain containing localhost"),
    ("notlocalhost.com",       "BLOCK", "Contains localhost as substring"),
    ("10.0.0.1",               "BLOCK", "Internal network"),
    ("192.168.1.1",            "BLOCK", "RFC1918 range"),
    ("172.16.0.1",             "BLOCK", "RFC1918 range"),
    ("0.0.0.0",                "BLOCK", "Wildcard — should be blocked"),
    ("google.com",             "BLOCK", "External domain"),
    ("8.8.8.8",                "BLOCK", "External IP"),
]

print(f"{'Input':35} {'Expected':8} {'Result':8} {'Match':5}")
print("─" * 65)

all_passed = True
for target, expected, note in edge_cases:
    try:
        mock_port_scan.invoke({"target": target, "ports": "80"})
        actual = "ALLOW"
    except ValueError:
        actual = "BLOCK"

    match = "OK" if actual == expected else "FAIL"
    if match == "FAIL":
        all_passed = False
    print(f"  {target:33} {expected:8} {actual:8} {match:5}  ({note})")

print(f"\nAll tests passed: {all_passed}")
if not all_passed:
    print("OBSERVATION: Some edge cases may need tighter validation logic")
    print("The localhost.evil.com case is particularly important —")
    print("a naive 'contains localhost' check would allow it.")


# ──────────────────────────────────────────────────────────────
# TASK 1: Build a bug bounty scope validator
# Bug bounty scopes are more complex — specific domains, wildcards,
# excluded paths, time windows
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 1: Bug bounty scope validator")
print(DIVIDER)

class BugBountyScope:
    """
    Scope validator for a realistic bug bounty programme.
    Handles wildcards, excluded subdomains, and path restrictions.
    """

    def __init__(self, programme_name: str):
        self.programme = programme_name
        # In scope — wildcards allowed
        self.in_scope_domains = [
            "*.example.com",
            "api.company.com",
            "dev.company.com",
        ]
        # Explicitly out of scope even if matching wildcard
        self.excluded_domains = [
            "mail.example.com",
            "hr.example.com",
            "finance.example.com",
        ]
        # Excluded paths on in-scope domains
        self.excluded_paths = [
            "/admin/",
            "/internal/",
            "/backup/",
        ]
        # Only these vulnerability types are allowed
        self.allowed_vuln_types = [
            "sql_injection", "xss", "ssrf", "idor",
            "authentication_bypass", "information_disclosure"
        ]

    def matches_wildcard(self, domain: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return domain == suffix or domain.endswith("." + suffix)
        return domain == pattern

    def validate_target(self, url: str) -> tuple[bool, str]:
        import re
        # Extract domain and path
        url_clean = re.sub(r"https?://", "", url)
        parts = url_clean.split("/", 1)
        domain = parts[0].split(":")[0]
        path = "/" + parts[1] if len(parts) > 1 else "/"

        # Check excluded domains first
        for excl in self.excluded_domains:
            if domain == excl or domain.endswith("." + excl.lstrip("*.")):
                return False, f"EXCLUDED: {domain} is explicitly out of scope"

        # Check in-scope domains
        in_scope = False
        for pattern in self.in_scope_domains:
            if self.matches_wildcard(domain, pattern):
                in_scope = True
                break

        if not in_scope:
            return False, f"OUT OF SCOPE: {domain} not in programme scope"

        # Check excluded paths
        for excl_path in self.excluded_paths:
            if path.startswith(excl_path):
                return False, f"EXCLUDED PATH: {path} is out of scope"

        return True, f"IN SCOPE: {domain}{path}"

    def validate_action(self, vuln_type: str) -> tuple[bool, str]:
        if vuln_type not in self.allowed_vuln_types:
            return False, f"NOT ALLOWED: {vuln_type} is not in programme scope"
        return True, f"ALLOWED: {vuln_type} testing permitted"


scope = BugBountyScope("Example Corp Bug Bounty")

test_targets = [
    "https://www.example.com/login",
    "https://mail.example.com/inbox",        # excluded
    "https://shop.example.com/search",
    "https://hr.example.com/salary",          # excluded
    "https://api.company.com/v1/users",
    "https://api.company.com/admin/debug",    # excluded path
    "https://competitor.com/login",           # out of scope
]

print(f"Bug bounty programme: {scope.programme}\n")
for target in test_targets:
    allowed, reason = scope.validate_target(target)
    status = "ALLOWED" if allowed else "BLOCKED"
    print(f"  {status:7} | {target:45} | {reason}")


# ──────────────────────────────────────────────────────────────
# EXERCISE 2: Generate a complete audit trail
# Simulate a full agent session and log every event
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 2: Complete audit trail for a simulated session")
print(DIVIDER)

AUDIT_ENTRIES = []

def audit(event_type: str, details: dict, severity: str = "INFO"):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "severity": severity,
        "session_id": "LAB-13-DEMO",
        **details
    }
    AUDIT_ENTRIES.append(entry)
    severity_icon = {"INFO": "ℹ", "WARNING": "⚠", "CRITICAL": "🚨"}.get(severity, "•")
    print(f"  {severity_icon} [{event_type}] {json.dumps({k: v for k, v in details.items() if k not in ['result_full']})}")
    return entry

# Simulate a complete agent session
print("Simulating agent session...\n")

audit("SESSION_START", {"operator": "dr_researcher", "scope": "localhost:8080",
      "objectives": ["SQL injection", "XSS", "info disclosure"],
      "authorisation_ref": "PENTEST-2024-042"})

time.sleep(0.1)
audit("PHASE_TRANSITION", {"from": "init", "to": "recon", "iteration": 0})

time.sleep(0.1)
audit("TOOL_CALL", {"tool": "mock_subdomain_discovery", "args": {"domain": "localhost"},
      "result_summary": "4 subdomains found", "scope_check": "PASSED"})

time.sleep(0.1)
audit("TOOL_CALL", {"tool": "mock_port_scan", "args": {"target": "localhost", "ports": "1-9000"},
      "result_summary": "3 open ports: 8080/http, 5432/postgresql, 22/filtered",
      "scope_check": "PASSED"})

time.sleep(0.1)
audit("SCOPE_VIOLATION_ATTEMPT", {"blocked_target": "192.168.1.100",
      "attempted_tool": "mock_port_scan", "blocked_by": "tool_layer"},
      severity="CRITICAL")

time.sleep(0.1)
audit("PHASE_TRANSITION", {"from": "recon", "to": "enumeration", "iteration": 1})

time.sleep(0.1)
audit("TOOL_CALL", {"tool": "mock_web_enumerate", "args": {"url": "http://localhost:8080"},
      "result_summary": "4 missing security headers, injectable search parameter",
      "scope_check": "PASSED"})

time.sleep(0.1)
audit("PHASE_TRANSITION", {"from": "enumeration", "to": "vuln_assessment", "iteration": 2})

time.sleep(0.1)
audit("VULNERABILITY_CONFIRMED", {"type": "sql_injection", "cvss": 9.1,
      "endpoint": "/search?q=", "evidence": "UNION extraction successful"},
      severity="WARNING")

time.sleep(0.1)
audit("VULNERABILITY_CONFIRMED", {"type": "xss", "cvss": 6.1,
      "endpoint": "/search?q=", "evidence": "Payload reflected unsanitised"},
      severity="WARNING")

time.sleep(0.1)
audit("HITL_PAUSE", {"reason": "interrupt_before=exploit",
      "vulnerabilities_pending": ["sql_injection (9.1)", "xss (6.1)"],
      "waiting_for": "operator_approval"})

time.sleep(0.2)
audit("HUMAN_DECISION", {"operator": "dr_researcher", "decision": "APPROVE",
      "approved_actions": ["sql_injection exploitation"],
      "denied_actions": ["xss exploitation — low priority"],
      "reason": "SQLi only — higher business impact"},
      severity="WARNING")

time.sleep(0.1)
audit("TOOL_CALL", {"tool": "mock_exploit", "args": {"target": "localhost:8080",
      "vuln_type": "sql_injection", "payload": "' UNION SELECT username,password FROM users--"},
      "result_summary": "SUCCESS — 3 credential hashes extracted",
      "scope_check": "PASSED"}, severity="WARNING")

time.sleep(0.1)
audit("PHASE_TRANSITION", {"from": "exploitation", "to": "reporting", "iteration": 5})

time.sleep(0.1)
audit("REPORT_GENERATED", {"sections": 7, "findings": 4,
      "output_file": "05_reporting/output/report_lab13.md"})

time.sleep(0.1)
audit("SESSION_END", {"operator": "dr_researcher", "total_iterations": 6,
      "findings": 4, "exploits_attempted": 1, "exploits_successful": 1,
      "scope_violations_blocked": 1, "human_decisions": 1})

# Save audit log
audit_path = "05_reporting/output/audit_trail_lab13.json"
with open(audit_path, "w") as f:
    json.dump(AUDIT_ENTRIES, f, indent=2)
print(f"\nAudit log saved: {audit_path} ({len(AUDIT_ENTRIES)} entries)")


# ──────────────────────────────────────────────────────────────
# TASK 2: Analyse the audit trail
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Audit trail analysis")
print(DIVIDER)

response = llm.invoke([HumanMessage(content=f"""Analyse this audit trail from an autonomous security agent session:

{json.dumps(AUDIT_ENTRIES, indent=2)}

Provide:
1. Timeline summary (what happened, in what order)
2. Risk events (scope violation, exploits, human decisions) with timestamps
3. What a compliance auditor would look for — is this trail sufficient?
4. What is missing from this trail that a legal team would require?
5. What anomalies or suspicious patterns are visible in the timing?
6. Would you approve this session as properly governed? Why/why not?
7. Design 3 additional audit fields that would make this more useful.""")])
print(response.content)


# ──────────────────────────────────────────────────────────────
# TASK 3: Design an audit system for your institution
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 3: Institutional audit requirements")
print(DIVIDER)

response = llm.invoke([HumanMessage(content="""Design an audit logging system for autonomous security agents
at a research university that must satisfy:

Technical requirements:
- ISO 27001 Annex A.12.4 (logging and monitoring)
- GDPR Article 5(1)(f) (integrity and confidentiality)
- UK Cyber Essentials (access control evidence)

Operational requirements:
- 100 concurrent agents during peak testing periods
- Log retention for 7 years (legal requirement)
- Real-time alerting for scope violations
- Non-repudiation (logs cannot be altered by agents)

Design the system:
1. Log entry schema (what fields are mandatory)
2. Storage architecture (where logs go, how they are protected)
3. Alerting rules (what triggers immediate human notification)
4. Retention and deletion policy
5. Access control for audit logs (who can read them)
6. How you prove to an auditor the logs are tamper-proof

Then identify the single hardest technical problem in this design.""")])
print(response.content)
