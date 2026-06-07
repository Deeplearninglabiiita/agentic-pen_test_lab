"""
shared/dvwa_session.py
Singleton DVWA session — created once, reused across all tool calls.
"""
import requests
import re
import threading
from shared.config import config

urllib3_imported = False
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    urllib3_imported = True
except Exception:
    pass

_lock = threading.Lock()
_session = None

def get_dvwa_session() -> requests.Session:
    global _session
    with _lock:
        if _session is not None:
            return _session

        s = requests.Session()
        s.headers.update({"User-Agent": "Mozilla/5.0 (SecurityResearch/LabSession)"})
        base = config.DVWA_URL

        try:
            login_page = s.get(f"{base}/login.php", timeout=10, verify=False)
            token_match = re.search(
                r"user_token.*?value=['\"]([a-f0-9]+)['\"]",
                login_page.text
            )
            token = token_match.group(1) if token_match else ""
        except Exception:
            token = ""

        try:
            s.post(
                f"{base}/login.php",
                data={"username": "admin", "password": "password",
                      "Login": "Login", "user_token": token},
                timeout=10, verify=False, allow_redirects=True,
            )
        except Exception:
            pass

        try:
            s.get(f"{base}/security.php", timeout=10, verify=False)
            s.post(
                f"{base}/security.php",
                data={"security": "low", "seclev_submit": "Submit"},
                timeout=10, verify=False,
            )
        except Exception:
            pass

        _session = s
        return _session


def reset_dvwa_session():
    global _session
    with _lock:
        _session = None
