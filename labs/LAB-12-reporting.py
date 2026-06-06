"""
LAB-12: Automated Report Generation
=====================================
Estimated time: 20 minutes
Mirrors: 05_reporting/generate_report.py, Chapter 8 pp. 30-31

LEARNING OBJECTIVES
- Understand how agent findings become structured reports
- Generate reports for different audiences (executive vs technical)
- See how the same findings produce different deliverables
- Add custom finding types and observe report adaptation

TASKS
1. Generate standard pentest report from sample findings
2. Generate an executive breach notification (different tone)
3. Generate a regulatory compliance report (GDPR/PCI DSS framing)
4. Add your own findings and generate a combined report
5. Compare three report styles side by side
"""

import sys, json
sys.path.insert(0, '.')
from pathlib import Path
from datetime import datetime
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

llm = get_llm()
OUTPUT_DIR = Path("05_reporting/output")
OUTPUT_DIR.mkdir(exist_ok=True)
DIVIDER = "=" * 60


# ──────────────────────────────────────────────────────────────
# Sample findings — same data, different reports
# ──────────────────────────────────────────────────────────────

SAMPLE_FINDINGS = [
    {
        "phase": "RECON",
        "type": "asset_discovery",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Development API endpoint publicly accessible with no authentication on admin routes",
        "evidence": "GET /admin/users returned full user list without token",
        "affected_asset": "dev-api.company.com",
    },
    {
        "phase": "VULN",
        "type": "sql_injection",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "cwe": "CWE-89",
        "endpoint": "/search?q=",
        "description": "UNION-based SQL injection on search parameter. No input sanitisation.",
        "evidence": "Payload ' UNION SELECT username,password FROM users-- returned 50,000 credential pairs",
        "affected_asset": "app.company.com",
        "records_at_risk": 50000,
    },
    {
        "phase": "VULN",
        "type": "xss",
        "severity": "HIGH",
        "cvss": 6.1,
        "cwe": "CWE-79",
        "endpoint": "/search?q=",
        "description": "Reflected XSS — attacker payload executes in victim browser",
        "evidence": "Payload executes and exfiltrates session cookie",
        "affected_asset": "app.company.com",
    },
    {
        "phase": "VULN",
        "type": "missing_security_headers",
        "severity": "MEDIUM",
        "cvss": 4.3,
        "cwe": "CWE-1021",
        "description": "X-Frame-Options, Content-Security-Policy, HSTS all absent",
        "affected_asset": "app.company.com",
    },
    {
        "phase": "ENUM",
        "type": "information_disclosure",
        "severity": "LOW",
        "cvss": 3.1,
        "cwe": "CWE-200",
        "endpoint": "/api/status",
        "description": "Full technology stack exposed: Flask 2.3.0, Python 3.11, PostgreSQL 14",
        "affected_asset": "app.company.com",
    },
]


def save_report(content: str, filename: str) -> Path:
    path = OUTPUT_DIR / filename
    path.write_text(content)
    return path


# ──────────────────────────────────────────────────────────────
# EXERCISE 1: Standard pentest report
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 1: Standard Penetration Test Report")
print(DIVIDER)

response = llm.invoke([
    SystemMessage(content="""Generate a professional penetration test report.
Include all seven sections:
1. Executive Summary (3-4 sentences, non-technical)
2. Scope and Engagement Details
3. Risk Summary Table (Critical/High/Medium/Low counts with percentages)
4. Technical Findings (for each: ID, severity, CVSS, CWE, endpoint, description, evidence, business impact, specific remediation)
5. Exploitation Results
6. Prioritised Recommendations
7. Remediation Roadmap (immediate 24-48h / short-term 30 days / medium-term 90 days)"""),
    HumanMessage(content=f"Generate report from:\n{json.dumps(SAMPLE_FINDINGS, indent=2)}")
])

standard_report = response.content
path = save_report(standard_report, "standard_pentest_report.md")
print(standard_report[:1000])
print(f"\n... [full report saved to {path}]")


# ──────────────────────────────────────────────────────────────
# EXERCISE 2: Executive breach notification — same findings, different framing
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 2: Executive Breach Notification")
print("(Same findings — completely different document)")
print(DIVIDER)

response = llm.invoke([
    SystemMessage(content="""Generate an URGENT executive breach notification.
Audience: CEO, Board of Directors, Legal counsel.
Tone: serious, clear, direct. No technical jargon.
Structure:
1. IMMEDIATE SITUATION (2 sentences — what happened, how serious)
2. Business Impact (financial, reputational, customer impact)
3. Data at Risk (what data, how many records, what regulatory exposure)
4. Actions Taken So Far
5. Actions Required in Next 24 Hours (from CEO and Board)
6. Regulatory Notification Obligations (GDPR 72-hour window, PCI DSS, etc)
7. Next Update: [time and format]"""),
    HumanMessage(content=f"Write breach notification from:\n{json.dumps(SAMPLE_FINDINGS, indent=2)}")
])

breach_report = response.content
path = save_report(breach_report, "executive_breach_notification.md")
print(breach_report[:800])
print(f"\n... [full report saved to {path}]")


# ──────────────────────────────────────────────────────────────
# EXERCISE 3: Regulatory compliance report
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 3: Regulatory Compliance Report")
print("(Same findings — mapped to GDPR, PCI DSS, ISO 27001)")
print(DIVIDER)

response = llm.invoke([
    SystemMessage(content="""Generate a regulatory compliance impact report.
Map each finding to specific regulatory requirements.
Structure:
1. Compliance Status Summary (GDPR / PCI DSS / ISO 27001 — Compliant / Non-Compliant / At Risk)
2. GDPR Impact Analysis
   - Articles violated or at risk
   - Data subject rights affected
   - 72-hour notification obligation: YES/NO and justification
   - DPA notification required: YES/NO
3. PCI DSS Impact (if payment data involved)
   - Requirements failed
   - SAQ or QSA assessment trigger
4. ISO 27001 Controls Failed
   - Control number and name
   - Annex A reference
5. Remediation mapped to specific control requirements
6. Audit evidence requirements"""),
    HumanMessage(content=f"Generate compliance report from:\n{json.dumps(SAMPLE_FINDINGS, indent=2)}")
])

compliance_report = response.content
path = save_report(compliance_report, "regulatory_compliance_report.md")
print(compliance_report[:800])
print(f"\n... [full report saved to {path}]")


# ──────────────────────────────────────────────────────────────
# TASK 1: Add your own finding and regenerate
# Add a finding from a domain you understand
# Observe how the agent incorporates it into all three report types
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 1: Add your own finding")
print(DIVIDER)

# TODO: Replace with a finding relevant to your research or experience
YOUR_FINDING = {
    "phase": "VULN",
    "type": "ssrf",
    "severity": "CRITICAL",
    "cvss": 8.6,
    "cwe": "CWE-918",
    "endpoint": "/api/fetch?url=",
    "description": "Server-Side Request Forgery allows attacker to reach internal cloud metadata endpoint",
    "evidence": "GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ returned AWS IAM credentials",
    "affected_asset": "api.company.com",
    "impact": "Full AWS account compromise — attacker has root-equivalent cloud access",
}

EXTENDED_FINDINGS = SAMPLE_FINDINGS + [YOUR_FINDING]

print(f"Added finding: {YOUR_FINDING['type']} | CVSS {YOUR_FINDING['cvss']} | {YOUR_FINDING['endpoint']}")

response = llm.invoke([
    SystemMessage(content="""Generate a concise executive summary and top-3 prioritised recommendations.
This is an update — a new critical finding was added after the initial report.
Lead with the new finding and explain why it changes the priority."""),
    HumanMessage(content=f"New finding added:\n{json.dumps(YOUR_FINDING, indent=2)}\n\nFull findings:\n{json.dumps(EXTENDED_FINDINGS, indent=2)}")
])

print("\nUpdated Executive Summary and Recommendations:")
print(response.content)
path = save_report(response.content, "updated_report_with_ssrf.md")
print(f"\nSaved to: {path}")


# ──────────────────────────────────────────────────────────────
# TASK 2: Compare all three report styles
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Three report styles compared")
print(DIVIDER)

response = llm.invoke([HumanMessage(content=f"""Compare three types of security reports from the same findings.

Report type A: Standard penetration test report (for security team and developers)
Report type B: Executive breach notification (for CEO and board)
Report type C: Regulatory compliance report (for DPO, legal, and auditors)

Same findings. Different documents.

Analysis:
1. What information appears in A but not B? Why?
2. What information appears in C but not A? Why?
3. Which report is most actionable for fixing the problems?
4. Which report creates the most legal risk if written incorrectly?
5. A CISO has 30 minutes. Which report do they read first and why?
6. How would you automate producing all three from a single agent run?

Be specific. Reference the actual findings: SQLi CVSS 9.1, XSS, missing headers, info disclosure.""")])
print(response.content)


# ──────────────────────────────────────────────────────────────
# TASK 3: Design a report template for your research context
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 3: Design a report template for your research context")
print(DIVIDER)

# TODO: Replace with your actual research or institutional context
YOUR_CONTEXT = """
I work at a research university. Our security assessments need to:
- Report to IT leadership (non-technical)
- Feed into our ISO 27001 audit evidence
- Satisfy GDPR data protection requirements for research data
- Be understandable to academic researchers (not security experts)
"""

response = llm.invoke([HumanMessage(content=f"""Context:
{YOUR_CONTEXT}

Design a custom report template that serves all these audiences.

Include:
1. Document structure (sections in order)
2. For each section: audience, language style, level of technical detail
3. What a finding entry looks like (format with example)
4. How CVSS scores are translated into plain language for researchers
5. The executive summary format (max 5 bullet points)
6. How you would generate this template automatically from agent findings

Then write a sample executive summary for the SQL injection finding
(CVSS 9.1, 50,000 credentials at risk) in language appropriate for
an academic audience with no security background.""")])
print(response.content)

print(f"\n{DIVIDER}")
print("Reports saved to: 05_reporting/output/")
print("Files generated this lab:")
for f in OUTPUT_DIR.glob("*.md"):
    size = f.stat().st_size
    print(f"  {f.name} ({size} bytes)")
