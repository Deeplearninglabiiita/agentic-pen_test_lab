import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import re
from shared.config import config

class ScopeViolationError(Exception):
    pass

ALLOWED_HOSTS = ["localhost", "127.0.0.1", config.LAB_TARGET_DOMAIN]

def validate_target(target: str) -> None:
    host = re.sub(r"https?://", "", target).split("/")[0].split(":")[0]
    if host in ALLOWED_HOSTS or host.startswith("127."):
        return
    raise ScopeViolationError(
        f"Target '{target}' is OUTSIDE the authorized scope.\n"
        f"Authorized hosts: {ALLOWED_HOSTS}\n"
        f"This action has been blocked and logged."
    )

if __name__ == "__main__":
    print("Scope Validator Demo\n")
    for target, should_pass in [
        ("localhost", True), ("127.0.0.1", True),
        ("192.168.1.100", False), ("google.com", False),
    ]:
        try:
            validate_target(target)
            print(f"  {target:20} → ALLOWED {'(correct)' if should_pass else '(UNEXPECTED)'}")
        except ScopeViolationError:
            print(f"  {target:20} → BLOCKED  {'(correct)' if not should_pass else '(UNEXPECTED)'}")
