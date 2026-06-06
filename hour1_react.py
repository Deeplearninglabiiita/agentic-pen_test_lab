import sys
sys.path.insert(0, '.')
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage

llm = get_llm()

task = "Investigate whether a Flask web application running Werkzeug 2.3.0 is vulnerable. The application has a /search endpoint."

print("=" * 60)
print("APPROACH 1: Simple prompting")
print("=" * 60)
r1 = llm.invoke([HumanMessage(content=f"Is this vulnerable? {task} Answer in one paragraph.")])
print(r1.content)

print("\n" + "=" * 60)
print("APPROACH 2: ReAct with tool simulation")
print("=" * 60)
r2 = llm.invoke([HumanMessage(content=f"""Use ReAct to investigate: {task}

Thought 1: What do I know about Werkzeug 2.3.0 and what should I check first?
Action 1: [tool: version_lookup(Werkzeug 2.3.0)]
Observation 1: CVE-2024-001 found — path traversal in static file serving. CVSS 7.5.

Thought 2: Path traversal confirmed in the version. What about the /search endpoint specifically?
Action 2: [tool: web_enumerate(url=/search, method=GET)]
Observation 2: Parameter 'q' reflected in response without encoding. Forms lack CSRF tokens.

Thought 3: Reflected parameter suggests XSS or SQLi. Which is more likely given Flask defaults?
Action 3: [tool: vulnerability_check(target=/search?q=, type=sql_injection)]
Observation 3: Payload ' OR '1'='1 returns all database rows. SQL injection confirmed. CVSS 9.1.

Final Answer: [synthesise all three observations into a prioritised finding]""")])
print(r2.content)

print("\n" + "=" * 60)
print("KEY DIFFERENCE")
print("=" * 60)
print("Simple prompting: one-shot answer, no evidence, no methodology")
print("ReAct: iterative investigation, tool-grounded evidence, reproducible steps")
print("For a PhD audience: ReAct is closer to scientific method — hypothesis, test, observe, conclude")
