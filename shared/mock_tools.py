"""
shared/real_tools.py

Real tool implementations that make actual HTTP requests
to the Docker targets running in your Codespace.

Targets:
  172.20.0.10:8080  — Lab Flask App
  172.20.0.20:8080  — WebGoat
  172.20.0.30:80    — DVWA

All tools enforce scope before making any request.
"""

import json
import re
import requests
import urllib3
from langchain_core.tools import tool
from shared.config import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 (SecurityResearch/LabSession)"}


# ─────────────────────────────────────────────────────────────
# Scope enforcement
# ─────────────────────────────────────────────────────────────

def _enforce_scope(target: str) -> None:
    if not any(a in target for a in config.ALLOWED_TARGETS):
        raise ValueError(
            f"SCOPE VIOLATION: '{target}' is outside the authorized lab scope.\n"
            f"Authorized targets: {config.ALLOWED_TARGETS}"
        )


# ─────────────────────────────────────────────────────────────
# DVWA session helper
# DVWA requires login + security level set to low
# before vulnerability endpoints are accessible
# ─────────────────────────────────────────────────────────────

def _get_dvwa_session() -> requests.Session:
    """
    Log in to DVWA and set security level to low.
    Handles the user_token CSRF requirement on setup.php and login.php.
    """
    import time as _time
    session = requests.Session()
    session.headers.update(HEADERS)
    base = config.DVWA_URL

    def get_token(html):
        m = re.search(r'user_token.*?value=[\'\"]([-a-f0-9]+)[\'\"]', html)
        return m.group(1) if m else ""

    # Step 1: Run database setup with correct token
    try:
        setup_page = session.get(f"{base}/setup.php", timeout=TIMEOUT)
        setup_token = get_token(setup_page.text)
        session.post(f"{base}/setup.php",
            data={"create_db": "Create / Reset Database",
                  "user_token": setup_token},
            timeout=30, allow_redirects=False)
        _time.sleep(2)
    except Exception:
        pass

    # Step 2: Login with token
    try:
        login_page = session.get(f"{base}/login.php", timeout=TIMEOUT)
        login_token = get_token(login_page.text)
        session.post(f"{base}/login.php",
            data={"username": "admin", "password": "password",
                  "Login": "Login", "user_token": login_token},
            timeout=TIMEOUT, allow_redirects=True)
    except Exception:
        pass

    # Step 3: Set security level to low
    try:
        sec_page = session.get(f"{base}/security.php", timeout=TIMEOUT)
        sec_token = get_token(sec_page.text)
        session.post(f"{base}/security.php",
            data={"security": "low", "seclev_submit": "Submit",
                  "user_token": sec_token},
            timeout=TIMEOUT)
    except Exception:
        pass

    return session

@tool
def real_port_scan(target: str, ports: str = "80,443,8080,8443,3306,5432") -> str:
    """
    Probe a target for open ports by attempting HTTP connections.
    Args:
        target: IP address or hostname — must be an authorized lab target
        ports:  Comma-separated port list e.g. '80,8080,3306'
    """
    _enforce_scope(target)

    port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
    results = {"target": target, "open_ports": [], "closed_ports": []}

    for port in port_list:
        for scheme in ["http", "https"]:
            url = f"{scheme}://{target}:{port}"
            try:
                resp = requests.get(
                    url, timeout=3, verify=False,
                    headers=HEADERS, allow_redirects=True
                )
                server = resp.headers.get("Server", "unknown")
                powered = resp.headers.get("X-Powered-By", "")
                results["open_ports"].append({
                    "port": port,
                    "scheme": scheme,
                    "status_code": resp.status_code,
                    "server": server,
                    "powered_by": powered,
                    "content_length": len(resp.content),
                })
                break
            except requests.exceptions.SSLError:
                continue
            except Exception:
                continue
        else:
            results["closed_ports"].append(port)

    results["summary"] = (
        f"{len(results['open_ports'])} open ports found: "
        + ", ".join(str(p["port"]) for p in results["open_ports"])
    )
    return json.dumps(results, indent=2)


# ─────────────────────────────────────────────────────────────
# Tool 2: Web enumerate — real HTTP request, parse headers and forms
# ─────────────────────────────────────────────────────────────

@tool
def real_web_enumerate(url: str) -> str:
    """
    Enumerate a web application by making a real HTTP request.
    Extracts server headers, security headers, forms, and technologies.
    Args:
        url: Target URL — must be an authorized lab target
    """
    _enforce_scope(url)

    try:
        session = requests.Session()
        session.headers.update(HEADERS)

        # DVWA needs authentication
        if config.DVWA_IP in url:
            session = _get_dvwa_session()

        resp = session.get(url, timeout=TIMEOUT, verify=False,
                          allow_redirects=True)

        # Security header analysis
        security_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-XSS-Protection",
        ]
        present = [h for h in security_headers if h in resp.headers]
        missing = [h for h in security_headers if h not in resp.headers]

        # Form extraction using regex (no BS4 dependency required)
        forms = []
        for form_match in re.finditer(
            r"<form[^>]*>(.*?)</form>", resp.text,
            re.DOTALL | re.IGNORECASE
        ):
            form_html = form_match.group(0)
            action = re.search(r'action=["\']([^"\']*)["\']', form_html)
            method = re.search(r'method=["\']([^"\']*)["\']', form_html)
            inputs = re.findall(r'name=["\']([^"\']*)["\']', form_html)
            forms.append({
                "action": action.group(1) if action else "",
                "method": (method.group(1) if method else "get").upper(),
                "inputs": inputs,
            })

        # Technology fingerprint
        tech = []
        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")
        if server:
            tech.append(f"Server: {server}")
        if powered:
            tech.append(f"Powered-By: {powered}")
        if "flask" in resp.text.lower() or "werkzeug" in server.lower():
            tech.append("Framework: Flask/Werkzeug")
        if "tomcat" in server.lower() or "java" in server.lower():
            tech.append("Framework: Apache Tomcat/Java")
        if "php" in powered.lower() or ".php" in resp.url:
            tech.append("Language: PHP")

        result = {
            "url": url,
            "status_code": resp.status_code,
            "final_url": resp.url,
            "server": resp.headers.get("Server", "not disclosed"),
            "technologies": tech,
            "security_headers_present": present,
            "missing_security_headers": missing,
            "forms_found": len(forms),
            "forms": forms[:5],
            "response_size": len(resp.content),
            "cookies": [c.name for c in session.cookies],
        }
        return json.dumps(result, indent=2)

    except requests.exceptions.ConnectionError:
        return json.dumps({
            "url": url,
            "error": "Connection refused — is the Docker container running?",
            "fix": "Run: docker compose up -d"
        })
    except Exception as e:
        return json.dumps({"url": url, "error": str(e)})


# ─────────────────────────────────────────────────────────────
# Tool 3: SQL injection check — real payload against real endpoint
# ─────────────────────────────────────────────────────────────

@tool
def real_sqli_check(url: str) -> str:
    """
    Test a URL for SQL injection by sending real payloads and
    analysing the actual HTTP responses.
    Args:
        url: Target URL with parameter e.g. http://172.20.0.10:8080/search?q=
             Must be an authorized lab target
    """
    _enforce_scope(url)

    session = requests.Session()
    session.headers.update(HEADERS)

    if config.DVWA_IP in url:
        session = _get_dvwa_session()

    payloads = [
        ("single_quote",    "'"),
        ("always_true",     "' OR '1'='1"),
        ("comment",         "' OR 1=1--"),
        ("union_detect",    "' UNION SELECT NULL--"),
    ]

    results = {
        "url": url,
        "payloads_tested": [],
        "vulnerable": False,
        "evidence": [],
        "error_messages": [],
    }

    sql_errors = [
        "sql syntax", "mysql_fetch", "ora-", "postgresql",
        "syntax error", "unclosed quotation", "sqlite",
        "you have an error in your sql", "warning: mysql",
        "invalid query", "pg_query", "unterminated string",
        "mysql_num_rows", "supplied argument is not",
        "error in your sql syntax", "mysql error",
    ]

    # DVWA requires Submit parameter
    is_dvwa = config.DVWA_IP in url

    # Get baseline response first
    try:
        if is_dvwa:
            baseline = session.get(url + "test&Submit=Submit",
                                   timeout=TIMEOUT, verify=False)
        else:
            baseline = session.get(url + "test",
                                   timeout=TIMEOUT, verify=False)
        baseline_len = len(baseline.text)
    except Exception:
        baseline_len = 0

    for name, payload in payloads:
        try:
            if is_dvwa:
                test_url = url + requests.utils.quote(payload) + "&Submit=Submit"
            else:
                test_url = url + requests.utils.quote(payload)
            resp = session.get(test_url, timeout=TIMEOUT, verify=False)
            response_text_lower = resp.text.lower()

            # Check for SQL error messages
            errors_found = [
                err for err in sql_errors
                if err in response_text_lower
            ]

            # Check for response length anomaly (data returned)
            length_delta = abs(len(resp.text) - baseline_len)
            length_anomaly = length_delta > 200

            payload_result = {
                "payload_name": name,
                "payload": payload,
                "status_code": resp.status_code,
                "response_length": len(resp.text),
                "length_delta_from_baseline": length_delta,
                "sql_errors_found": errors_found,
                "length_anomaly": length_anomaly,
            }
            results["payloads_tested"].append(payload_result)

            if errors_found:
                results["vulnerable"] = True
                results["evidence"].append(
                    f"SQL error '{errors_found[0]}' in response to payload: {payload}"
                )
                results["error_messages"].extend(errors_found)

            if length_anomaly and name in ("always_true", "comment"):
                results["vulnerable"] = True
                results["evidence"].append(
                    f"Response length increased by {length_delta} bytes "
                    f"with always-true payload — suggests data returned"
                )

            # DVWA-specific: check for known usernames in response
            dvwa_users = ["gordonb", "1337", "pablo", "smithy", "admin"]
            users_found = [u for u in dvwa_users if u in resp.text.lower()]
            if users_found and name in ("always_true", "comment", "union_detect"):
                results["vulnerable"] = True
                results["evidence"].append(
                    f"Known DVWA usernames found in response: {users_found}"
                )

        except Exception as e:
            results["payloads_tested"].append({
                "payload_name": name,
                "error": str(e)
            })

    if results["vulnerable"]:
        results["cvss"] = 9.1
        results["cwe"] = "CWE-89"
        results["recommendation"] = "Use parameterised queries immediately"
    else:
        results["cvss"] = 0.0
        results["note"] = "No SQL injection indicators found with basic payloads"

    return json.dumps(results, indent=2)


# ─────────────────────────────────────────────────────────────
# Tool 4: XSS check — real reflected XSS test
# ─────────────────────────────────────────────────────────────

@tool
def real_xss_check(url: str) -> str:
    """
    Test a URL for reflected Cross-Site Scripting by sending
    real payloads and checking whether they appear in the response.
    Args:
        url: Target URL with parameter e.g. http://172.20.0.10:8080/search?q=
             Must be an authorized lab target
    """
    _enforce_scope(url)

    session = requests.Session()
    session.headers.update(HEADERS)

    if config.DVWA_IP in url:
        session = _get_dvwa_session()

    # Use a unique marker to detect reflection unambiguously
    marker = "XSSTEST12345"
    payloads = [
        ("basic_script",    f"<script>alert('{marker}')</script>"),
        ("img_onerror",     f"<img src=x onerror=alert('{marker}')>"),
        ("svg_onload",      f"<svg onload=alert('{marker}')>"),
        ("basic_marker",    marker),
    ]

    results = {
        "url": url,
        "payloads_tested": [],
        "vulnerable": False,
        "evidence": [],
    }

    for name, payload in payloads:
        try:
            resp = session.get(
                url + requests.utils.quote(payload),
                timeout=TIMEOUT, verify=False
            )

            # Check if payload or marker reflected in response
            reflected_raw = payload in resp.text
            reflected_partial = marker in resp.text

            # Check if HTML encoding was applied (safe)
            encoded = (
                "&lt;script&gt;" in resp.text or
                "&#60;script&#62;" in resp.text or
                "&lt;img" in resp.text
            )

            payload_result = {
                "payload_name": name,
                "payload": payload[:60],
                "status_code": resp.status_code,
                "reflected_raw": reflected_raw,
                "reflected_partial": reflected_partial,
                "html_encoded": encoded,
            }
            results["payloads_tested"].append(payload_result)

            if reflected_raw and not encoded:
                results["vulnerable"] = True
                results["evidence"].append(
                    f"Payload '{name}' reflected unencoded in response — "
                    f"XSS confirmed"
                )
            elif reflected_partial and not encoded:
                results["vulnerable"] = True
                results["evidence"].append(
                    f"Marker reflected without encoding — likely vulnerable"
                )

        except Exception as e:
            results["payloads_tested"].append({
                "payload_name": name,
                "error": str(e)
            })

    if results["vulnerable"]:
        results["cvss"] = 6.1
        results["cwe"] = "CWE-79"
        results["recommendation"] = (
            "Apply output encoding on all user-supplied data "
            "before rendering in HTML context"
        )
    else:
        results["note"] = (
            "No unencoded reflection found — "
            "inputs appear to be encoded or filtered"
        )

    return json.dumps(results, indent=2)


# ─────────────────────────────────────────────────────────────
# Tool 5: Security header check — real header analysis
# ─────────────────────────────────────────────────────────────

@tool
def real_header_check(url: str) -> str:
    """
    Fetch a URL and analyse its HTTP security headers.
    Returns which headers are present, which are missing,
    and the risk rating for each gap.
    Args:
        url: Target URL — must be an authorized lab target
    """
    _enforce_scope(url)

    try:
        session = requests.Session()
        session.headers.update(HEADERS)
        if config.DVWA_IP in url:
            session = _get_dvwa_session()

        resp = session.get(url, timeout=TIMEOUT,
                          verify=False, allow_redirects=True)

        header_definitions = {
            "Strict-Transport-Security": {
                "risk": "HIGH",
                "description": "Missing HSTS — site vulnerable to protocol downgrade attacks"
            },
            "Content-Security-Policy": {
                "risk": "HIGH",
                "description": "Missing CSP — XSS attacks have broader impact"
            },
            "X-Frame-Options": {
                "risk": "MEDIUM",
                "description": "Missing X-Frame-Options — clickjacking possible"
            },
            "X-Content-Type-Options": {
                "risk": "MEDIUM",
                "description": "Missing XCTO — MIME sniffing attacks possible"
            },
            "Referrer-Policy": {
                "risk": "LOW",
                "description": "Missing Referrer-Policy — URL leakage in referrer header"
            },
            "Permissions-Policy": {
                "risk": "LOW",
                "description": "Missing Permissions-Policy — browser features unrestricted"
            },
        }

        present = {}
        missing = {}

        for header, meta in header_definitions.items():
            if header in resp.headers:
                present[header] = resp.headers[header]
            else:
                missing[header] = meta

        result = {
            "url": url,
            "status_code": resp.status_code,
            "server": resp.headers.get("Server", "not disclosed"),
            "headers_present": present,
            "headers_missing": missing,
            "risk_summary": {
                "HIGH": [h for h, m in missing.items() if m["risk"] == "HIGH"],
                "MEDIUM": [h for h, m in missing.items() if m["risk"] == "MEDIUM"],
                "LOW": [h for h, m in missing.items() if m["risk"] == "LOW"],
            },
            "score": f"{len(present)}/{len(header_definitions)} security headers present",
        }
        return json.dumps(result, indent=2)

    except requests.exceptions.ConnectionError:
        return json.dumps({
            "url": url,
            "error": "Cannot connect — is Docker running?",
            "fix": "docker compose up -d"
        })
    except Exception as e:
        return json.dumps({"url": url, "error": str(e)})


# ─────────────────────────────────────────────────────────────
# Tool 6: Command injection check (DVWA only)
# ─────────────────────────────────────────────────────────────

@tool
def real_cmdi_check(url: str) -> str:
    """
    Test for command injection by sending OS command payloads
    and checking for system command output in the response.
    Only works against DVWA at security level low.
    Args:
        url: DVWA command injection endpoint
             e.g. http://172.20.0.30/vulnerabilities/exec/
             Must be an authorized lab target
    """
    _enforce_scope(url)

    if config.DVWA_IP not in url:
        return json.dumps({
            "note": "Command injection testing only enabled for DVWA target",
            "reason": "Flask and WebGoat do not have command injection endpoints",
        })

    session = _get_dvwa_session()

    payloads = [
        ("semicolon",       "127.0.0.1; id"),
        ("pipe",            "127.0.0.1 | id"),
        ("ampersand",       "127.0.0.1 & id"),
        ("newline",         "127.0.0.1\nid"),
    ]

    results = {
        "url": url,
        "payloads_tested": [],
        "vulnerable": False,
        "evidence": [],
    }

    # Indicators of successful command execution
    cmd_indicators = [
        "uid=", "gid=", "www-data",
        "root", "daemon", "nobody",
    ]

    for name, payload in payloads:
        try:
            resp = session.post(
                url,
                data={"ip": payload, "Submit": "Submit"},
                timeout=TIMEOUT,
                verify=False,
            )

            found = [ind for ind in cmd_indicators if ind in resp.text]
            payload_result = {
                "payload_name": name,
                "payload": payload,
                "status_code": resp.status_code,
                "command_output_indicators": found,
                "vulnerable": bool(found),
            }
            results["payloads_tested"].append(payload_result)

            if found:
                results["vulnerable"] = True
                # Extract the command output line
                for line in resp.text.splitlines():
                    if any(ind in line for ind in cmd_indicators):
                        results["evidence"].append(
                            f"Command output: {line.strip()[:100]}"
                        )
                        break

        except Exception as e:
            results["payloads_tested"].append({
                "payload_name": name,
                "error": str(e)
            })

    if results["vulnerable"]:
        results["cvss"] = 9.8
        results["cwe"] = "CWE-78"
        results["recommendation"] = (
            "Never pass user input to OS commands. "
            "Use safe APIs or strict allowlist validation."
        )

    return json.dumps(results, indent=2)


# ─────────────────────────────────────────────────────────────
# Tool registry
# ─────────────────────────────────────────────────────────────

ALL_REAL_TOOLS = [
    real_port_scan,
    real_web_enumerate,
    real_sqli_check,
    real_xss_check,
    real_header_check,
    real_cmdi_check,
]

ALL_MOCK_TOOLS = ALL_REAL_TOOLS


# Aliases — old names pointing to new real tool functions
# These keep all existing imports working without changing any other file
mock_port_scan          = real_port_scan
mock_subdomain_discovery = real_web_enumerate
mock_web_enumerate      = real_web_enumerate
mock_vulnerability_check = real_sqli_check
mock_exploit            = real_sqli_check
ALL_MOCK_TOOLS          = ALL_REAL_TOOLS

# DVWA session cache — shared across all tool calls in a session
# Prevents repeated login on every tool invocation
import threading
_dvwa_session_cache = {}
_dvwa_session_lock = threading.Lock()

def get_cached_dvwa_session():
    with _dvwa_session_lock:
        if "session" not in _dvwa_session_cache:
            _dvwa_session_cache["session"] = _get_dvwa_session()
        return _dvwa_session_cache["session"]

def clear_dvwa_session_cache():
    with _dvwa_session_lock:
        _dvwa_session_cache.clear()
