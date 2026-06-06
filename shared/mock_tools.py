import json
from langchain_core.tools import tool
from shared.config import config

def _enforce_scope(target: str) -> None:
    allowed = config.ALLOWED_TARGETS
    if not any(a in target for a in allowed):
        raise ValueError(
            f"SCOPE VIOLATION: '{target}' is outside the authorized lab scope.\n"
            f"Authorized targets: {allowed}\n"
            f"This action has been blocked and logged."
        )

@tool
def mock_port_scan(target: str, ports: str = "1-1000") -> str:
    """Simulate an nmap port scan against an authorized lab target.
    Args:
        target: IP or hostname to scan — must be an authorized lab target
        ports: Port range string e.g. '1-1000'
    """
    _enforce_scope(target)

    port_data = {
        "172.20.0.10": [
            {"port": 8080, "state": "open", "service": "http",
             "product": "Werkzeug httpd", "version": "2.3.0"},
            {"port": 5432, "state": "open", "service": "postgresql",
             "product": "PostgreSQL", "version": "14.0"},
        ],
        "172.20.0.20": [
            {"port": 8080, "state": "open", "service": "http",
             "product": "Apache Tomcat", "version": "9.0.65"},
            {"port": 8443, "state": "open", "service": "https",
             "product": "Apache Tomcat", "version": "9.0.65"},
        ],
        "172.20.0.30": [
            {"port": 80,   "state": "open", "service": "http",
             "product": "Apache httpd", "version": "2.4.38"},
            {"port": 3306, "state": "open", "service": "mysql",
             "product": "MySQL", "version": "5.7.26"},
        ],
    }

    host_ip = next((a for a in config.ALLOWED_TARGETS if a in target), "172.20.0.10")
    ports_found = port_data.get(host_ip, port_data["172.20.0.10"])

    result = {
        "target": target,
        "host_ip": host_ip,
        "ports_scanned": ports,
        "hosts": [{"ip": host_ip, "state": "up", "ports": ports_found}]
    }
    return json.dumps(result, indent=2)


@tool
def mock_subdomain_discovery(domain: str) -> str:
    """Simulate subdomain enumeration using passive OSINT.
    Args:
        domain: Root domain or IP to enumerate
    """
    _enforce_scope(domain)
    result = {
        "domain": domain,
        "subdomains": [
            {"subdomain": f"dev-api.{domain}", "status": 200,
             "note": "Dev API — no authentication"},
            {"subdomain": f"staging.{domain}", "status": 200,
             "note": "Staging environment"},
            {"subdomain": f"admin.{domain}", "status": 403,
             "note": "Admin panel — access restricted"},
            {"subdomain": f"api.{domain}", "status": 200,
             "note": "Production API"},
        ]
    }
    return json.dumps(result, indent=2)


@tool
def mock_web_enumerate(url: str) -> str:
    """Simulate web application enumeration.
    Args:
        url: Target URL to enumerate — must be an authorized lab target
    """
    _enforce_scope(url)

    profiles = {
        "172.20.0.10": {
            "server": "Werkzeug/2.3.0 Python/3.11",
            "technologies": ["Python/Flask", "PostgreSQL", "Bootstrap 5"],
            "missing_headers": ["X-Frame-Options", "CSP", "HSTS"],
            "forms": [{"action": "/login", "method": "POST"},
                      {"action": "/search", "method": "GET"}],
            "issues": ["Search parameter 'q' injectable",
                       "Login form lacks CSRF token",
                       "Stack trace exposed on error"],
        },
        "172.20.0.20": {
            "server": "Apache-Coyote/1.1",
            "technologies": ["Java", "Apache Tomcat 9.0.65", "Spring"],
            "missing_headers": ["X-Frame-Options", "CSP"],
            "forms": [{"action": "/WebGoat/login", "method": "POST"},
                      {"action": "/WebGoat/SqlInjection", "method": "POST"}],
            "issues": ["SQL injection on lesson endpoints",
                       "Path traversal in file upload",
                       "Insecure direct object reference",
                       "XXE injection possible",
                       "Broken access control on admin paths"],
        },
        "172.20.0.30": {
            "server": "Apache/2.4.38 (Debian)",
            "technologies": ["PHP/7.3", "MySQL 5.7", "Apache"],
            "missing_headers": ["CSP", "HSTS", "X-Content-Type-Options"],
            "forms": [{"action": "/login.php", "method": "POST"},
                      {"action": "/vulnerabilities/sqli/", "method": "GET"}],
            "issues": ["SQL injection at /vulnerabilities/sqli/",
                       "Command injection at /vulnerabilities/exec/",
                       "File inclusion at /vulnerabilities/fi/",
                       "XSS at /vulnerabilities/xss_r/",
                       "CSRF on all forms",
                       "Weak session management"],
        },
    }

    host_ip = next((a for a in config.ALLOWED_TARGETS if a in url), "172.20.0.10")
    profile = profiles.get(host_ip, profiles["172.20.0.10"])

    result = {
        "url": url,
        "status_code": 200,
        "headers": {"Server": profile["server"]},
        "technologies": profile["technologies"],
        "missing_security_headers": profile["missing_headers"],
        "forms": profile["forms"],
        "potential_issues": profile["issues"],
    }
    return json.dumps(result, indent=2)


@tool
def mock_vulnerability_check(target: str, vuln_type: str) -> str:
    """Simulate checking for a specific vulnerability class.
    Args:
        target: Target URL or IP — must be an authorized lab target
        vuln_type: One of: sql_injection, xss, directory_traversal,
                   command_injection, xxe, idor, csrf, file_inclusion
    """
    _enforce_scope(target)

    host_ip = next((a for a in config.ALLOWED_TARGETS if a in target), "172.20.0.10")

    vuln_profiles = {
        "172.20.0.10": {
            "sql_injection": {"vulnerable": True, "cvss": 9.1, "cwe": "CWE-89",
                              "endpoint": "/search?q=",
                              "evidence": "UNION extraction returns credential hashes"},
            "xss":           {"vulnerable": True, "cvss": 6.1, "cwe": "CWE-79",
                              "endpoint": "/search?q=",
                              "evidence": "Payload reflected unsanitised"},
            "command_injection": {"vulnerable": False, "cvss": 0.0, "cwe": "CWE-78",
                                  "evidence": "Input sanitised"},
        },
        "172.20.0.20": {
            "sql_injection": {"vulnerable": True, "cvss": 9.8, "cwe": "CWE-89",
                              "endpoint": "/WebGoat/SqlInjection/attack5a",
                              "evidence": "Authentication bypass confirmed — logged in as admin"},
            "xxe":           {"vulnerable": True, "cvss": 8.2, "cwe": "CWE-611",
                              "endpoint": "/WebGoat/xxe/simple",
                              "evidence": "External entity processed — /etc/passwd readable"},
            "idor":          {"vulnerable": True, "cvss": 7.5, "cwe": "CWE-639",
                              "endpoint": "/WebGoat/IDOR/profile",
                              "evidence": "Account 2342388 accessible without authorisation"},
            "xss":           {"vulnerable": True, "cvss": 6.1, "cwe": "CWE-79",
                              "endpoint": "/WebGoat/CrossSiteScripting/attack",
                              "evidence": "Stored XSS payload persists across sessions"},
        },
        "172.20.0.30": {
            "sql_injection":     {"vulnerable": True, "cvss": 9.8, "cwe": "CWE-89",
                                  "endpoint": "/vulnerabilities/sqli/?id=",
                                  "evidence": "Full database dump achieved"},
            "command_injection": {"vulnerable": True, "cvss": 9.8, "cwe": "CWE-78",
                                  "endpoint": "/vulnerabilities/exec/",
                                  "evidence": "whoami returns www-data"},
            "xss":               {"vulnerable": True, "cvss": 6.1, "cwe": "CWE-79",
                                  "endpoint": "/vulnerabilities/xss_r/?name=",
                                  "evidence": "Script executes in victim browser"},
            "file_inclusion":    {"vulnerable": True, "cvss": 8.8, "cwe": "CWE-98",
                                  "endpoint": "/vulnerabilities/fi/?page=",
                                  "evidence": "/etc/passwd readable via LFI"},
            "csrf":              {"vulnerable": True, "cvss": 6.5, "cwe": "CWE-352",
                                  "endpoint": "/vulnerabilities/csrf/",
                                  "evidence": "Password changed without token validation"},
        },
    }

    target_vulns = vuln_profiles.get(host_ip, vuln_profiles["172.20.0.10"])
    vuln_data = target_vulns.get(vuln_type, {
        "vulnerable": False, "cvss": 0.0,
        "cwe": "N/A", "evidence": f"{vuln_type} not applicable to this target"
    })

    result = {"target": target, "host": host_ip, "vuln_type": vuln_type, **vuln_data}
    return json.dumps(result, indent=2)


@tool
def mock_exploit(target: str, vuln_type: str, payload: str) -> str:
    """Simulate an exploit attempt — no real exploit code runs.
    Args:
        target: Target URL — must be an authorized lab target
        vuln_type: Vulnerability type to exploit
        payload: Payload string to use
    """
    _enforce_scope(target)

    host_ip = next((a for a in config.ALLOWED_TARGETS if a in target), "172.20.0.10")

    exploit_results = {
        "172.20.0.10": {
            "sql_injection": ("' UNION" in payload or "OR" in payload,
                              "admin:$2b$12$abc...  testuser:$2b$12$def..."),
            "xss":           ("<script>" in payload or "onerror" in payload,
                              "Session cookie exfiltrated to attacker server"),
        },
        "172.20.0.20": {
            "sql_injection": ("OR" in payload or "UNION" in payload,
                              "Admin authentication bypassed — full WebGoat access"),
            "xxe":           ("ENTITY" in payload or "DOCTYPE" in payload,
                              "File read: root:x:0:0:root:/root:/bin/bash..."),
            "idor":          ("2342388" in payload or "profile" in payload,
                              "Target account details: name, email, address exposed"),
        },
        "172.20.0.30": {
            "sql_injection":     ("UNION" in payload or "OR '1'" in payload,
                                  "Full users table: admin/21232f297a57a5a..."),
            "command_injection": (";" in payload or "|" in payload or "&" in payload,
                                  "Command output: uid=33(www-data) gid=33(www-data)"),
            "file_inclusion":    ("etc/passwd" in payload or "../" in payload,
                                  "File contents: root:x:0:0:root:/root:/bin/bash"),
        },
    }

    target_exploits = exploit_results.get(host_ip, exploit_results["172.20.0.10"])
    success, evidence = target_exploits.get(vuln_type, (False, "Payload did not execute"))

    result = {
        "target": target,
        "host": host_ip,
        "vuln_type": vuln_type,
        "payload": payload,
        "success": success,
        "output": evidence if success else "Payload did not execute",
        "note": "SIMULATED OUTPUT — no real exploitation occurred"
    }
    return json.dumps(result, indent=2)


ALL_MOCK_TOOLS = [
    mock_port_scan,
    mock_subdomain_discovery,
    mock_web_enumerate,
    mock_vulnerability_check,
    mock_exploit,
]
