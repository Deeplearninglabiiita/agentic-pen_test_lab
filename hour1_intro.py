import sys
sys.path.insert(0, '.')
from shared.llm_client import get_llm
from langchain_core.messages import HumanMessage

llm = get_llm()

print("=" * 60)
print("DISCUSSION PROMPT 1")
print("=" * 60)
response = llm.invoke([HumanMessage(content="""You are presenting to PhD researchers and faculty.

The Anthropic 2025 report revealed a Chinese state-sponsored group used Claude Code 
to perform 80-90% of cyberattack work autonomously across 30 targets in tech, 
finance, and government.

Address these three questions concisely:
1. What does '80-90% autonomous' actually mean technically?
2. Why was this impossible 3 years ago but possible today?
3. What is the single most important defensive implication for a SOC?

Keep each answer to 4 sentences.""")])
print(response.content)
