import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
from pathlib import Path
from datetime import datetime
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

DIVIDER = "=" * 60
OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

SAMPLE_FINDINGS = [
    {"phase": "RECON", "type": "asset_discovery", "severity": "HIGH", "cvss": 7.5,
     "description": "Dev API endpoint found with no authentication on admin routes"},
    {"phase": "VULN", "type": "sql_injection", "endpoint": "/search?q=", "severity": "CRITICAL",
     "cvss": 9.1, "cwe": "CWE-89", "description": "UNION-based SQL injection confirmed. Password hashes extracted."},
    {"phase": "VULN", "type": "xss", "endpoint": "/search?q=", "severity": "HIGH",
     "cvss": 6.1, "cwe": "CWE-79", "description": "Reflected XSS — payload executes in victim browser."},
    {"phase": "VULN", "type": "missing_headers", "severity": "MEDIUM", "cvss": 4.3,
     "cwe": "CWE-1021", "description": "X-Frame-Options, CSP, HSTS all absent. Clickjacking risk."},
    {"phase": "ENUM", "type": "info_disclosure", "endpoint": "/api/status", "severity": "LOW",
     "cvss": 3.1, "cwe": "CWE-200", "description": "Full tech stack exposed in API response."},
]

if __name__ == "__main__":
    print(DIVIDER)
    print("Lab 5: Automated Report Generation — Chapter 8, pp. 30-31")
    print(DIVIDER)

    llm = get_llm()
    response = llm.invoke([
        SystemMessage(content="""Generate a professional pentest report with these sections:
1. Executive Summary (3-4 sentences, non-technical)
2. Scope and Engagement Details
3. Risk Summary Table (Critical/High/Medium/Low counts)
4. Findings (for each: severity, CVSS, CWE, endpoint, description, business impact, recommendation)
5. Remediation Roadmap (immediate / 30-day / 90-day)
6. Conclusion"""),
        HumanMessage(content=f"Generate report from these findings:\n\n{json.dumps(SAMPLE_FINDINGS, indent=2)}")
    ])

    report = response.content
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    md_path = OUTPUT_DIR / f"report_{timestamp}.md"
    md_path.write_text(report)

    print(f"\n{report[:2000]}")
    if len(report) > 2000:
        print("\n... [truncated — full report saved to file]")
    print(f"\n{DIVIDER}")
    print(f"Report saved: {md_path}")
    print(DIVIDER)
