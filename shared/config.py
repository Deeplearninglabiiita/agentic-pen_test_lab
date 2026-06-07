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

    LAB_TARGET_URL: str = os.getenv("LAB_TARGET_URL", "http://172.20.0.10:8080")
    LAB_TARGET_DOMAIN: str = os.getenv("LAB_TARGET_DOMAIN", "172.20.0.10")
    LAB_TARGET_IP: str = os.getenv("LAB_TARGET_DOMAIN", "172.20.0.10")

    WEBGOAT_URL: str = os.getenv("WEBGOAT_URL", "http://172.20.0.20:8080/WebGoat")
    WEBGOAT_IP: str = os.getenv("WEBGOAT_IP", "172.20.0.20")

    DVWA_URL: str = os.getenv("DVWA_URL", "http://172.20.0.30")
    DVWA_IP: str = os.getenv("DVWA_IP", "172.20.0.30")

    ALLOWED_TARGETS: list = [
        "172.20.0.10", "172.20.0.20", "172.20.0.30",
        "localhost", "127.0.0.1",
    ]

    MAX_ITERATIONS: int = int(os.getenv("MAX_ITERATIONS", "15"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    AUDIT_LOG_FILE: str = os.getenv("AUDIT_LOG_FILE", "audit.log")

config = Config()
