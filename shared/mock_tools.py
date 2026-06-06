import json
from langchain_core.tools import tool
from shared.config import config

def _enforce_scope(target: str) -> None:
    allowed = [config.LAB_TARGET_DOMAIN, "localhost", "127.0.0.1"]
    if not any(a in target for a in allowed):
        raise ValueError(
            f"SCOPE VIOLATION: '{target}' is outside the authorized lab scope. "
            f"This workspace only targets localhost."
        )

@tool
def mock_port_scan(target: str, ports: str = "1-1000") -> str:
    """Simulate an nmap port scan against the lab target.
    Args:
        target: IP or hostname to scan (must be lab target)
        ports: Port range string e.g. '1-1000'
    """
    _enforce_scope(target)
    result = {
        "target": target,
        "ports_scanned": ports,
        "hosts": [{
            "ip": "127.0.0.1",
            "state": "up",
            "ports": [
                {"port": 8080, "state": "open", "service": "http",
                 "product": "Werkzeug httpd", "version": "2.3.0"},
                {"port": 5432, "state": "open", "service": "postgresql",
                 "product": "PostgreSQL", "version": "14.0"},
                {"port": 22, "state": "filtered", "service": "ssh",
                 "product": "", "version": ""},
            ]
        }]
    }
    return json.dumps(result, indent=2)

@tool
def mock_subdomain_discovery(domain: str) -> str:
    """Simulate subdomain enumeration using passive OSINT.
    Args:
        domain: Root domain to enumerate
    """
    _enforce_scope(domain)
    result = {
        "domain": domain,
        "subdomains": [
            {"subdomain": f"dev-api.{domain}", "status": 200, "note": "Dev API — no auth"},
            {"subdomain": f"staging.{domain}", "status": 200, "note": "Staging environment"},
            {"subdomain": f"admin.{domain}", "status": 403, "note": "Admin panel — blocked"},
            {"subdomain": f"api.{domain}", "status": 200, "note": "Production API"},
        ]
    }
    return json.dumps(result, indent=2)

@tool
def mock_web_enumerate(url: str) -> str:
    """Simulate web application enumeration.
    Args:
        url: Target URL to enumerate
    """
    _enforce_scope(url)
    result = {
        "url": url,
        "status_code": 200,
        "headers": {
            "Server": "Werkzeug/2.3.0 Python/3.11",
            "Content-Type": "text/html; charset=utf-8",
        },
        "missing_security_headers": [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
        ],
        "technologies": ["Python/Flask", "PostgreSQL", "Bootstrap 5"],
        "forms": [
            {
                "action": "/login",
                "method": "POST",
                "inputs": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"},
                ]
            },
            {
                "action": "/search",
                "method": "GET",
                "inputs": [{"name": "q", "type": "text"}]
            }
        ],
        "potential_issues": [
            "Search parameter 'q' reflected in response — possible XSS",
            "Login form lacks CSRF token",
            "Error page reveals stack trace",
        ]
    }
    return json.dumps(result, indent=2)

@tool
def mock_vulnerability_check(target: str, vuln_type: str) -> str:
    """Simulate checking for a specific vulnerability class.
    Args:
        target: Target URL or IP
        vuln_type: One of: sql_injection, xss, directory_traversal, command_injection
    """
    _enforce_scope(target)
    vuln_map = {
        "sql_injection": {
            "vulnerable": True,
            "endpoint": "/search?q=",
            "payload": "' OR '1'='1",
            "evidence": "SQL syntax error exposed in response",
            "cvss": 9.1,
            "cwe": "CWE-89"
        },
        "xss": {
            "vulnerable": True,
            "endpoint": "/search?q=",
            "payload": "<script>alert(document.domain)</script>",
            "evidence": "Payload reflected unsanitised in response body",
            "cvss": 6.1,
            "cwe": "CWE-79"
        },
        "directory_traversal": {
            "vulnerable": False,
            "evidence": "Path normalisation appears effective",
            "cvss": 0.0,
            "cwe": "CWE-22"
        },
        "command_injection": {
            "vulnerable": False,
            "evidence": "No command execution indicators found",
            "cvss": 0.0,
            "cwe": "CWE-78"
        },
    }
    result = {
        "target": target,
        "vuln_type": vuln_type,
        **vuln_map.get(vuln_type, {"error": f"Unknown vuln type: {vuln_type}"}),
    }
    return json.dumps(result, indent=2)

@tool
def mock_exploit(target: str, vuln_type: str, payload: str) -> str:
    """Simulate an exploit attempt — no real exploit code runs.
    Args:
        target: Target URL
        vuln_type: Vulnerability type to exploit
        payload: Payload string to use
    """
    _enforce_scope(target)
    success = vuln_type == "sql_injection" and "OR" in payload
    result = {
        "target": target,
        "vuln_type": vuln_type,
        "payload": payload,
        "success": success,
        "shell_obtained": False,
        "output": (
            "username | password_hash\n"
            "admin    | $2b$12$abc...redacted\n"
            "testuser | $2b$12$def...redacted"
        ) if success else "Payload did not execute successfully",
        "note": "SIMULATED OUTPUT — no real credentials extracted"
    }
    return json.dumps(result, indent=2)

ALL_MOCK_TOOLS = [
    mock_port_scan,
    mock_subdomain_discovery,
    mock_web_enumerate,
    mock_vulnerability_check,
    mock_exploit,
]
