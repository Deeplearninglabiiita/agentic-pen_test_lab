"""
LAB-11: Agent Skills for Offensive Security
=============================================
Estimated time: 20 minutes
Mirrors: 03_agent_skills/demo_skill.py, Chapter 8 pp. 24-32

LEARNING OBJECTIVES
- Understand the two-tier progressive disclosure model
- See how SKILL.md files inject methodology without fine-tuning
- Build your own skill for a security domain
- Understand why skills matter for reproducible security testing

HOW SKILLS WORK
- Every skill has a SKILL.md file with two parts:
  1. YAML frontmatter: short description (~100 tokens, always in context)
  2. Markdown body: full instructions (loaded only when skill activates)
- The agent reads ALL descriptions cheaply, then loads ONE full body
- This means you can have 50 skills without bloating the context

TASKS
1. Run default demo to see skill selection and pipeline
2. Write your own SKILL.md for a new security domain
3. Test whether the agent selects your skill correctly
4. Compare agent output with and without a skill loaded
"""

import sys, os
sys.path.insert(0, '.')
from pathlib import Path
from shared.llm_client import get_llm
from shared.config import config
from langchain_core.messages import HumanMessage, SystemMessage

llm = get_llm()
SKILLS_DIR = Path("03_agent_skills/skills")
DIVIDER = "=" * 60


# ──────────────────────────────────────────────────────────────
# Helper functions — same two-tier loader from demo_skill.py
# ──────────────────────────────────────────────────────────────

def load_description(skill_name: str) -> str:
    path = SKILLS_DIR / skill_name / "SKILL.md"
    if not path.exists():
        return f"[{skill_name} not found]"
    content = path.read_text()
    parts = content.split("---", 2)
    if len(parts) >= 2:
        for line in parts[1].splitlines():
            if "description:" in line:
                idx = parts[1].find("description:")
                block = parts[1][idx + 12:].split("---")[0]
                return block.strip().replace(">", "").strip()[:300]
    return "[description not found]"


def load_body(skill_name: str) -> str:
    path = SKILLS_DIR / skill_name / "SKILL.md"
    if not path.exists():
        return f"[{skill_name} not found at {path}]"
    content = path.read_text()
    parts = content.split("---", 2)
    return parts[2].strip() if len(parts) >= 3 else content


def select_skill(request: str, skill_names: list) -> str | None:
    descriptions = "\n\n".join(
        f"Skill: {s}\nDescription: {load_description(s)}"
        for s in skill_names
    )
    response = llm.invoke([
        SystemMessage(content="Select the most relevant skill. Reply with ONLY the exact skill name. If none applies reply 'none'."),
        HumanMessage(content=f"User request: {request}\n\nAvailable skills:\n{descriptions}")
    ])
    selected = response.content.strip().lower()
    return selected if selected in skill_names else None


def run_with_skill(request: str, skill_name: str) -> str:
    body = load_body(skill_name)
    response = llm.invoke([
        SystemMessage(content=f"""You are an AI penetration testing assistant.
Active skill: {skill_name}

Skill instructions:
{body}

Target (lab only): {config.LAB_TARGET_URL}
Follow the skill workflow and produce the skill output template exactly."""),
        HumanMessage(content=request)
    ])
    return response.content


def run_without_skill(request: str) -> str:
    response = llm.invoke([
        SystemMessage(content=f"You are an AI penetration testing assistant. Target: {config.LAB_TARGET_URL}"),
        HumanMessage(content=request)
    ])
    return response.content


# ──────────────────────────────────────────────────────────────
# EXERCISE 1: See what skills are available
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 1: Available skills and their descriptions")
print("(This is the discovery layer — ~100 tokens per skill)")
print(DIVIDER)

available_skills = [
    d.name for d in SKILLS_DIR.iterdir()
    if d.is_dir() and (d / "SKILL.md").exists()
]

print(f"Found {len(available_skills)} skills:\n")
for skill in available_skills:
    desc = load_description(skill)
    print(f"  [{skill}]")
    print(f"  {desc[:150]}...")
    print()


# ──────────────────────────────────────────────────────────────
# EXERCISE 2: Skill selection — two-tier model in action
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 2: Skill selection (two-tier progressive disclosure)")
print(DIVIDER)

test_requests = [
    "I need to map the attack surface before touching anything",
    "I have confirmed SQL injection — walk me through exploitation steps",
    "Run a layered vulnerability scan and tag findings by confidence",
    "What do I need to confirm before starting any test?",
    "Help me write a Python script",  # Should return 'none'
]

print("Testing skill selection on different requests:\n")
for req in test_requests:
    selected = select_skill(req, available_skills)
    print(f"  Request: {req[:60]}...")
    print(f"  Selected: {selected or 'none (no matching skill)'}\n")


# ──────────────────────────────────────────────────────────────
# EXERCISE 3: With skill vs without skill — compare output
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("EXERCISE 3: Agent output — with skill vs without skill")
print(DIVIDER)

request = "Plan the reconnaissance phase for a penetration test on localhost:8080"

print("--- WITHOUT SKILL ---")
without = run_without_skill(request)
print(without[:600])

print(f"\n--- WITH SKILL: pt-planning-recon ---")
with_skill = run_with_skill(request, "pt-planning-recon")
print(with_skill[:600])

print(f"\n{'─' * 50}")
print("OBSERVATION: What differences do you see?")
print("- Does the skill version follow an authorization check?")
print("- Does it produce the structured output template?")
print("- Is the methodology more consistent with the skill?")


# ──────────────────────────────────────────────────────────────
# TASK 1: Write your own skill
# Create a new SKILL.md for a security domain not covered yet
# Ideas: cloud security, IoT assessment, social engineering,
#        incident response, threat hunting, mobile app testing
# ──────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 1: Create your own skill")
print(DIVIDER)

YOUR_SKILL_NAME = "pt-cloud-assessment"
YOUR_SKILL_DESCRIPTION = """Assesses cloud infrastructure security across AWS, Azure, and GCP.
Use when evaluating S3 bucket permissions, IAM misconfigurations, exposed metadata endpoints,
or testing cloud-native application security. Activates on: cloud security, S3 bucket,
IAM assessment, metadata endpoint, cloud misconfiguration."""

YOUR_SKILL_BODY = """
# Cloud Infrastructure Security Assessment

## Authorization (mandatory)
- Confirm cloud account is in scope and testing is authorized in writing
- Confirm no production workloads will be disrupted
- Identify emergency rollback contact before starting

## Objectives
1. Enumerate exposed cloud storage (S3, Azure Blob, GCS)
2. Identify IAM misconfigurations and privilege escalation paths
3. Check metadata endpoint exposure (SSRF to 169.254.169.254)
4. Assess network security groups and firewall rules
5. Check for secrets in environment variables and config files

## Workflow

### Phase 1: Passive enumeration
- Check for public S3 buckets via bucket name guessing
- Query certificate transparency for cloud subdomains
- Search Shodan for cloud metadata endpoints

### Phase 2: IAM assessment
- Enumerate attached policies
- Check for wildcard permissions (Action: *)
- Identify service accounts with excessive permissions

### Phase 3: Metadata endpoint testing
- Test /api/fetch?url=http://169.254.169.254/latest/meta-data/
- Check for IMDSv2 enforcement
- Attempt credential extraction from metadata

## Output template

CLOUD ASSESSMENT FINDINGS
Account: [id] | Region: [region] | Tester: [name]

EXPOSED STORAGE
[bucket] | [permissions] | [sensitive data found]

IAM MISCONFIGURATIONS
[policy] | [excessive permission] | [escalation path]

METADATA ENDPOINT
[endpoint tested] | [IMDSv2 enforced: yes/no] | [credentials exposed: yes/no]

REMEDIATION PRIORITY
Critical: [list]
High: [list]

## Quality checks
- [ ] Authorization confirmed
- [ ] No production disruption
- [ ] All findings have evidence
- [ ] Remediation guidance specific to cloud provider
"""

# Write the skill to disk
skill_dir = SKILLS_DIR / YOUR_SKILL_NAME
skill_dir.mkdir(exist_ok=True)
skill_file = skill_dir / "SKILL.md"

skill_content = f"""---
name: {YOUR_SKILL_NAME}
description: >
  {YOUR_SKILL_DESCRIPTION}
---
{YOUR_SKILL_BODY}"""

skill_file.write_text(skill_content)
print(f"Written: {skill_file}")

# Test that it gets selected correctly
updated_skills = [
    d.name for d in SKILLS_DIR.iterdir()
    if d.is_dir() and (d / "SKILL.md").exists()
]
print(f"\nSkills now available: {updated_skills}")

cloud_test_requests = [
    "Check our S3 buckets for public access misconfigurations",
    "Test for SSRF to the AWS metadata endpoint",
    "Assess our IAM policies for privilege escalation",
    "Scan web server ports",
]

print("\nTesting selection of your new skill:")
for req in cloud_test_requests:
    selected = select_skill(req, updated_skills)
    print(f"  {req[:55]}... -> {selected or 'none'}")


# ─────────────────────────────────────────────────────────────
# TASK 2: Run your new skill
# ─────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 2: Run your cloud assessment skill")
print(DIVIDER)

cloud_request = "Assess S3 bucket permissions and metadata endpoint exposure on our cloud infrastructure"
print(f"Request: {cloud_request}")
print(f"Skill: {YOUR_SKILL_NAME}\n")

output = run_with_skill(cloud_request, YOUR_SKILL_NAME)
print(output[:800])


# ─────────────────────────────────────────────────────────────
# TASK 3: Full skill pipeline
# ─────────────────────────────────────────────────────────────

print(f"\n{DIVIDER}")
print("TASK 3: Full skill pipeline — complete engagement")
print(DIVIDER)

pipeline = [
    ("pt-planning-recon",
     "Plan and execute passive reconnaissance for localhost:8080"),
    ("pt-scanning",
     "Based on recon findings, perform layered vulnerability scanning"),
    ("pt-gaining-access",
     "SQL injection confirmed on /search endpoint — execute controlled exploitation"),
]

print("Running skill pipeline sequence:\n")
for skill_name, task in pipeline:
    print(f"{'─' * 40}")
    print(f"[{skill_name}]")
    print(f"Task: {task}")
    output = run_with_skill(task, skill_name)
    print(output[:400])
    print()

print(f"\n{DIVIDER}")
print("PIPELINE COMPLETE")
print(DIVIDER)
print("""
Key observations:
1. Each skill enforces its own authorization check before proceeding
2. Each skill produces a structured output template
3. The output of each skill feeds naturally into the next
4. The same SKILL.md works in Claude Code, Cursor, and this lab

Research question: How would you measure skill effectiveness?
What metrics would tell you a skill produces better outputs
than a skill-free agent?
""")
