import requests
import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env")

targets = [
    ("Lab Flask target", "http://localhost:8080", "/"),
    ("OWASP WebGoat",    "http://localhost:8081", "/WebGoat/login"),
    ("DVWA",             "http://localhost:8082", "/"),
]

print("\nHealth Check")
print("=" * 45)

groq_key = os.getenv("GROQ_API_KEY", "")
if groq_key:
    print(f"Groq API key    OK ({groq_key[:8]}...)")
else:
    print("Groq API key    MISSING - add to .env")

for name, base, path in targets:
    try:
        r = requests.get(base + path, timeout=5)
        status = "OK" if r.status_code in [200, 302] else "WARN"
        print(f"{name:<20} {status} HTTP {r.status_code}")
    except Exception as e:
        print(f"{name:<20} FAIL - {e}")

print("=" * 45)
