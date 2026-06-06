import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json, logging, datetime
from shared.config import config

_logger = logging.getLogger("audit")
_logger.setLevel(logging.DEBUG)

_ch = logging.StreamHandler()
_ch.setLevel(logging.INFO)
_ch.setFormatter(logging.Formatter("[AUDIT] %(message)s"))
_logger.addHandler(_ch)

_fh = logging.FileHandler(config.AUDIT_LOG_FILE)
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
_logger.addHandler(_fh)

def log_event(event_type: str, details: dict, severity: str = "INFO") -> None:
    record = {"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
              "event_type": event_type, "severity": severity, **details}
    msg = json.dumps(record)
    if severity == "CRITICAL":
        _logger.critical(msg)
    elif severity == "WARNING":
        _logger.warning(msg)
    else:
        _logger.info(msg)

def log_tool_call(tool_name: str, args: dict, result: str) -> None:
    log_event("TOOL_CALL", {"tool": tool_name, "args": args, "result_preview": result[:200]})

def log_phase_transition(from_phase: str, to_phase: str, iteration: int) -> None:
    log_event("PHASE_TRANSITION", {"from": from_phase, "to": to_phase, "iteration": iteration})

def log_human_decision(decision: str, context: str) -> None:
    log_event("HUMAN_DECISION", {"decision": decision, "context": context},
              severity="WARNING" if decision == "approve_exploit" else "INFO")

def log_scope_violation(target: str) -> None:
    log_event("SCOPE_VIOLATION", {"blocked_target": target}, severity="CRITICAL")

if __name__ == "__main__":
    print(f"Writing test audit events to {config.AUDIT_LOG_FILE}")
    log_tool_call("mock_port_scan", {"target": "localhost"}, '{"hosts":[...]}')
    log_phase_transition("recon", "enumeration", 1)
    log_human_decision("approve_exploit", "SQLi confirmed on /search")
    log_scope_violation("google.com")
    print("Done. Check audit.log")
