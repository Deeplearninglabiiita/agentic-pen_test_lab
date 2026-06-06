import sys
sys.path.insert(0, '.')
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage

llm = get_llm()

scenarios = [
    {
        "name": "Scenario A — Data Exfiltration",
        "alert": "Alert: 4.2 GB transferred from database server DB-01 to external IP 185.220.101.5 over 8 minutes at 02:14 UTC. User account: svc_backup."
    },
    {
        "name": "Scenario B — Supply Chain Attack", 
        "alert": "Alert: Software update process on 47 endpoints contacted update.microsoftwindows-cdn.net (unregistered domain) and downloaded unsigned 340KB executable."
    },
    {
        "name": "Scenario C — Insider Threat",
        "alert": "Alert: HR manager account accessed 2.1 million salary records on Saturday at 03:00 AM. Records exported to personal USB. No business justification on record."
    }
]

for s in scenarios:
    print(f"\n{'=' * 60}")
    print(f"COGNITIVE LOOP: {s['name']}")
    print("=" * 60)
    print(f"[PERCEIVE] {s['alert']}\n")
    response = llm.invoke([HumanMessage(content=f"""You are an AI SOC agent.
Observation: {s['alert']}

REASON: What does this indicate? List all plausible hypotheses ranked by probability.
PLAN: What are your top 3 actions in priority order?
ACT: Execute the first action now. What specific command or query do you run?
UNCERTAINTY: What information would change your assessment?""")])
    print(response.content)
    print()
