import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pathlib import Path
from shared.llm_client import get_llm
from shared.config import config
from langchain_core.messages import HumanMessage, SystemMessage

DIVIDER = "=" * 60
SKILLS_DIR = Path(__file__).parent / "skills"

def load_skill_description(skill_name: str) -> str:
    path = SKILLS_DIR / skill_name / "SKILL.md"
    if not path.exists():
        return f"[Skill '{skill_name}' not found]"
    content = path.read_text()
    parts = content.split("---", 2)
    if len(parts) >= 2:
        for line in parts[1].splitlines():
            if "description:" in line:
                idx = parts[1].find("description:")
                desc_block = parts[1][idx + len("description:"):].split("\n---")[0]
                return desc_block.strip().replace(">", "").strip()
    return "[description not found]"

def load_skill_body(skill_name: str) -> str:
    path = SKILLS_DIR / skill_name / "SKILL.md"
    if not path.exists():
        return f"[Skill '{skill_name}' not found]"
    content = path.read_text()
    parts = content.split("---", 2)
    return parts[2].strip() if len(parts) >= 3 else content

def select_skill(request: str, skills: list) -> str | None:
    llm = get_llm()
    descs = "\n\n".join(f"Skill: {s}\nDescription: {load_skill_description(s)}" for s in skills)
    response = llm.invoke([
        SystemMessage(content="Select the most relevant skill. Reply with ONLY the skill name exactly as listed. If none applies, reply 'none'."),
        HumanMessage(content=f"User request: {request}\n\nAvailable skills:\n{descs}")
    ])
    selected = response.content.strip().lower()
    return selected if selected in skills else None

def run_skill_guided_task(request: str, skills: list):
    print(f"\n{DIVIDER}")
    print(f"User request: {request}")
    print(DIVIDER)
    selected = select_skill(request, skills)
    if not selected:
        print("[SKILL] No matching skill found.")
        return
    print(f"[SKILL] Selected: {selected}")
    body = load_skill_body(selected)
    print(f"[SKILL] Loaded {len(body)} chars from {selected}/SKILL.md")
    llm = get_llm()
    response = llm.invoke([
        SystemMessage(content=f"""You are an AI penetration testing assistant.
Skill: {selected}
Instructions:
{body}

Target (lab scope only): {config.LAB_TARGET_URL}
Follow the skill workflow and output template exactly."""),
        HumanMessage(content=request)
    ])
    print(f"\n[SKILL] Agent response:\n{response.content}")

def demonstrate_pipeline(skills: list):
    print(f"\n{DIVIDER}")
    print("SKILL PIPELINE: recon → scanning → gaining-access (Chapter 8, Example 8-11)")
    print(DIVIDER)
    tasks = [
        ("pt-planning-recon", "Plan reconnaissance for the lab web app at localhost:8080"),
        ("pt-scanning", "Based on recon findings, what scanning approach should I use?"),
        ("pt-gaining-access", "SQLi confirmed on /search. What exploitation steps should I follow?"),
    ]
    for skill_name, request in tasks:
        body = load_skill_body(skill_name)
        llm = get_llm()
        response = llm.invoke([
            SystemMessage(content=f"Skill: {skill_name}\nInstructions (abbreviated):\n{body[:1000]}...\nProduce the output template. Keep to 12 lines maximum."),
            HumanMessage(content=request)
        ])
        print(f"\n{'─'*40}\n[{skill_name}]\n{response.content[:500]}")

if __name__ == "__main__":
    print(DIVIDER)
    print("Lab 3: Agent Skills — Chapter 8, pp. 24-32")
    print(DIVIDER)
    skills = ["pt-planning-recon", "pt-scanning", "pt-gaining-access"]
    run_skill_guided_task(
        "I need to scope a penetration test and collect passive intelligence on localhost",
        skills
    )
    demonstrate_pipeline(skills)
    print(f"\n{DIVIDER}")
    print("Key insight: Skills inject methodology without fine-tuning the model.")
    print("The same SKILL.md works in Claude Code, Cursor, and any compliant agent.")
    print(DIVIDER)
