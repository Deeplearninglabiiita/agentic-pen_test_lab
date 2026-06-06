import os
from pathlib import Path
from dotenv import load_dotenv

_root = Path(__file__).parent.parent
load_dotenv(_root / ".env")

class Config:
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    GOOGLE_API_KEY: str = os.getenv("GOOGLE_API_KEY", "")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "groq")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
    LAB_TARGET_URL: str = os.getenv("LAB_TARGET_URL", "http://localhost:8080")
    LAB_TARGET_DOMAIN: str = os.getenv("LAB_TARGET_DOMAIN", "localhost")
    MAX_ITERATIONS: int = int(os.getenv("MAX_ITERATIONS", "15"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    AUDIT_LOG_FILE: str = os.getenv("AUDIT_LOG_FILE", "audit.log")

config = Config()
