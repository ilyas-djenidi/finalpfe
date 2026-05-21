# scanners/web_scanner.py
"""
Web Application Scanner — Passive + External API Reconnaissance
═══════════════════════════════════════════════════════════════
External APIs used (no custom scripts):
  • SSL Labs API      — full SSL/TLS grade    (free, no key)
  • Mozilla Observatory — HTTP header grade   (free, no key)
  • Shodan InternetDB — open ports + CVEs     (free, no key)
  • VirusTotal        — URL/IP reputation     (free key: virustotal.com)
  • AbuseIPDB         — IP abuse score        (free key: abuseipdb.com)

Local passive checks:
  • Security headers, Cookies, CORS, HTTP methods
  • Sensitive path probing, Server version CVE matching
  • Passive SQLi/XSS/error disclosure detection
"""

import logging
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import os

logger = logging.getLogger(__name__)

# ── API timeouts ──────────────────────────────────────────────────────────────
_API_TIMEOUT   = 12   # seconds per API call
_SSLLABS_POLL  = 8    # poll interval (seconds) while SSL Labs is scanning
_SSLLABS_MAX   = 120  # max wait (seconds) for SSL Labs result

# ── Required security headers ─────────────────────────────────────────────────
REQUIRED_HEADERS = [
    ("Strict-Transport-Security",    "high",   "HSTS missing — browser won't force HTTPS"),
    ("Content-Security-Policy",      "high",   "CSP missing — no XSS / injection protection"),
    ("X-Frame-Options",              "medium", "X-Frame-Options missing — clickjacking possible"),
    ("X-Content-Type-Options",       "medium", "X-Content-Type-Options missing — MIME sniffing possible"),
    ("Referrer-Policy",              "low",    "Referrer-Policy missing — URL info may leak"),
    ("Permissions-Policy",           "low",    "Permissions-Policy missing — no browser API restrictions"),
    ("Cross-Origin-Opener-Policy",   "low",    "COOP missing — cross-origin isolation not enforced"),
]

# ── Sensitive paths ───────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    ("/.git/config",              "critical", "Git config exposed — source code leakage"),
    ("/.git/HEAD",                "critical", "Git repo exposed"),
    ("/.env",                     "critical", "Environment file exposed — API keys / passwords"),
    ("/.env.local",               "critical", ".env.local exposed"),
    ("/.env.production",          "critical", ".env.production exposed"),
    ("/.htpasswd",                "critical", "Password file exposed"),
    ("/wp-config.php",            "critical", "WordPress config exposed — DB credentials"),
    ("/config.php",               "critical", "PHP config exposed"),
    ("/phpinfo.php",              "high",     "phpinfo() exposed — full server config disclosed"),
    ("/server-status",            "high",     "Apache mod_status — live request info exposed"),
    ("/server-info",              "high",     "Apache mod_info — module config exposed"),
    ("/actuator",                 "high",     "Spring Boot Actuator exposed — app internals disclosed"),
    ("/actuator/env",             "critical", "Spring Boot /actuator/env — env vars exposed"),
    ("/actuator/heapdump",        "critical", "Spring Boot heap dump — memory contents downloadable"),
    ("/.aws/credentials",         "critical", "AWS credentials exposed"),
    ("/backup.zip",               "critical", "Backup archive downloadable"),
    ("/backup.sql",               "critical", "SQL backup downloadable"),
    ("/dump.sql",                 "critical", "Database dump downloadable"),
    ("/api/swagger.json",         "medium",   "Swagger/OpenAPI spec exposed"),
    ("/swagger.json",             "medium",   "Swagger spec exposed"),
    ("/api/docs",                 "medium",   "API docs exposed"),
    ("/graphql",                  "medium",   "GraphQL endpoint — check introspection"),
    ("/admin",                    "medium",   "Admin panel exposed — verify brute-force protection"),
    ("/wp-login.php",             "low",      "WordPress login — verify brute-force protection"),
    ("/robots.txt",               "info",     "robots.txt present — check for hidden paths"),
    ("/.well-known/security.txt", "info",     "security.txt present — good practice"),
]

# ── Dangerous HTTP methods ────────────────────────────────────────────────────
DANGEROUS_METHODS = [
    ("TRACE",   "medium", "XST (Cross-Site Tracing) attack vector"),
    ("PUT",     "high",   "Arbitrary file upload to server possible"),
    ("DELETE",  "high",   "File deletion on server possible"),
    ("CONNECT", "medium", "Server can be used as proxy"),
]

# ── Known vulnerable server signatures ───────────────────────────────────────
VULN_SERVER_RE = [
    (r"Apache/2\.4\.(4[89]|50)\b", "CVE-2021-41773", "Apache 2.4.49/50 Path Traversal + RCE", "critical"),
    (r"Apache/2\.4\.([0-3]\d|4[0-8])\b", "CVE-2022-22721", "Apache mod_sed buffer overflow", "high"),
    (r"nginx/1\.(1[0-7]|[0-9])\.", "CVE-2021-23017", "nginx DNS resolver buffer overwrite", "high"),
    (r"nginx/1\.18\.[01]\b", "CVE-2021-23017", "nginx 1.18 DNS resolver issue", "medium"),
    (r"PHP/([0-7]\.|8\.0\.[0-9]$|8\.1\.[0-7]\b)", "CVE-2023-3824", "PHP heap buffer overflow", "critical"),
    (r"OpenSSL/1\.[01]\.", "CVE-2022-0778", "OpenSSL 1.x infinite loop DoS", "high"),
    (r"OpenSSL/3\.0\.[0-6]\b", "CVE-2022-3786", "OpenSSL 3.0.x buffer overrun", "high"),
    (r"IIS/[0-7]\.", "CVE-2021-31166", "IIS HTTP protocol stack RCE (< IIS 10)", "critical"),
]

# ── Error / info disclosure patterns in response body ────────────────────────
ERROR_PATTERNS = [
    (r"SQL syntax.*MySQL",                     "critical", "MySQL error exposed — SQL Injection possible"),
    (r"Warning.*mysql_",                       "critical", "PHP MySQL error — SQL Injection possible"),
    (r"ORA-\d{5}",                             "critical", "Oracle DB error exposed"),
    (r"Microsoft OLE DB.*SQL Server",          "critical", "MSSQL error exposed — SQL Injection possible"),
    (r"Traceback \(most recent call last\)",   "high",     "Python traceback exposed — stack trace disclosure"),
    (r"at [\w\.]+\([\w\.]+\.java:\d+\)",       "high",     "Java stack trace exposed"),
    (r"<b>Warning</b>.*on line \d+",           "medium",   "PHP warning exposed"),
    (r"Fatal error.*PHP",                      "high",     "PHP fatal error exposed"),
    (r"DEBUG.*True",                           "medium",   "Debug mode enabled in production"),
    (r"CSRF token.*missing",                   "medium",   "CSRF token error exposed — framework info leak"),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _session() -> requests.Session:
    s = requests.Session()
    r = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    s.mount("http://",  HTTPAdapter(max_retries=r))
    s.mount("https://", HTTPAdapter(max_retries=r))
    s.headers.update({"User-Agent": "CyBrain-Security-Scanner/4.1"})
    return s


def _norm_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def _resolve_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def _is_private_ip(ip: str) -> bool:
    try:
        return ip_address(ip).is_private
    except Exception:
        return False


def _vuln(title, severity, description, evidence="", remediation="", cve_ids=None, check="web") -> dict:
    v = {
        "check":       check,
        "title":       title,
        "severity":    severity,
        "description": description,
    }
    if evidence:    v["evidence"]    = evidence
    if remediation: v["remediation"] = remediation
    if cve_ids:     v["cve_ids"]     = cve_ids
    return v


# ══════════════════════════════════════════════════════════════════════════════
#  EXTERNAL API CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def _check_ssllabs(hostname: str, vulns: list) -> dict:
    """
    SSL Labs API v3 — full TLS/SSL grading.
    Free, no key required. https://api.ssllabs.com/
    """
    base = "https://api.ssllabs.com/api/v3"
    meta = {}
    try:
        # Request fresh assessment (or use cache ≤ 24h)
        resp = requests.get(
            f"{base}/analyze",
            params={"host": hostname, "all": "done", "ignoreMismatch": "on"},
            timeout=_API_TIMEOUT,
        )
        if resp.status_code != 200:
            meta["ssllabs_error"] = f"HTTP {resp.status_code}"
            return meta

        data   = resp.json()
        status = data.get("status", "")

        # Poll while scanning
        waited = 0
        while status not in ("READY", "ERROR") and waited < _SSLLABS_MAX:
            time.sleep(_SSLLABS_POLL)
            waited += _SSLLABS_POLL
            resp   = requests.get(f"{base}/analyze",
                                  params={"host": hostname, "all": "done"},
                                  timeout=_API_TIMEOUT)
            data   = resp.json()
            status = data.get("status", "")

        if status == "ERROR":
            meta["ssllabs_error"] = data.get("statusMessage", "SSL Labs scan error")
            return meta

        if status != "READY":
            meta["ssllabs_error"] = f"SSL Labs timed out after {_SSLLABS_MAX}s"
            return meta

        endpoints = data.get("endpoints", [])
        grades    = []
        for ep in endpoints:
            grade = ep.get("grade", "")
            if grade:
                grades.append(grade)

            # Flag weak grades
            if grade and grade not in ("A", "A+", "A-", "B"):
                sev = "critical" if grade in ("F", "T") else "high" if grade in ("C", "D") else "medium"
                vulns.append(_vuln(
                    f"SSL Labs grade: {grade} for {hostname}",
                    sev,
                    f"SSL/TLS configuration is weak. Grade: {grade}. "
                    "Review cipher suites, protocol versions, and certificate.",
                    evidence=f"SSL Labs: {grade}",
                    remediation="Enable TLS 1.3, disable TLS 1.0/1.1, use strong cipher suites. "
                                "Reference: https://ssl-config.mozilla.org/",
                    check="ssl_labs",
                ))

            # Protocol issues
            for proto in ep.get("details", {}).get("protocols", []):
                ver = proto.get("version", "")
                if ver in ("1.0", "1.1"):
                    vulns.append(_vuln(
                        f"Deprecated TLS {ver} enabled",
                        "high",
                        f"TLS {ver} is deprecated since 2020 and must be disabled.",
                        evidence=f"SSL Labs detected TLS {ver} on {hostname}",
                        remediation="SSLProtocol -all +TLSv1.2 +TLSv1.3",
                        check="ssl_labs",
                    ))

            # Certificate expiry
            cert = ep.get("details", {}).get("cert", {})
            if cert:
                not_after = cert.get("notAfter", 0)
                if not_after:
                    exp = datetime.fromtimestamp(not_after / 1000, tz=timezone.utc)
                    days_left = (exp - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        vulns.append(_vuln("SSL Certificate expired", "critical",
                                           f"Certificate expired {-days_left} days ago.",
                                           check="ssl_labs"))
                    elif days_left < 14:
                        vulns.append(_vuln(f"SSL Certificate expires in {days_left} days", "high",
                                           "Certificate will expire very soon.", check="ssl_labs"))
                    elif days_left < 30:
                        vulns.append(_vuln(f"SSL Certificate expires in {days_left} days", "medium",
                                           "Certificate expiring soon.", check="ssl_labs"))

            # HSTS check from SSL Labs
            sts = ep.get("details", {}).get("hstsPolicy", {})
            if sts.get("status") not in ("present", "absent"):
                pass  # already covered by header check
            elif sts.get("status") == "present" and sts.get("maxAge", 0) < 15552000:
                vulns.append(_vuln("HSTS max-age too short", "medium",
                                   f"HSTS max-age is {sts.get('maxAge')}s — should be ≥ 15552000 (6 months).",
                                   check="ssl_labs"))

        meta["ssllabs_grade"]  = "/".join(grades) if grades else "N/A"
        meta["ssllabs_status"] = status
        logger.info("SSL Labs | host=%s | grade=%s", hostname, meta["ssllabs_grade"])

    except Exception as exc:
        meta["ssllabs_error"] = str(exc)
        logger.debug("SSL Labs API error: %s", exc)

    return meta


def _check_mozilla_observatory(hostname: str, vulns: list) -> dict:
    """
    Mozilla HTTP Observatory API — security header grading.
    Free, no key. https://observatory.mozilla.org/
    """
    meta = {}
    try:
        # Trigger scan
        r = requests.post(
            "https://http-observatory.security.mozilla.org/api/v1/analyze",
            params={"host": hostname},
            data={"hidden": "true", "rescan": "false"},
            timeout=_API_TIMEOUT,
        )
        if r.status_code != 200:
            meta["observatory_error"] = f"HTTP {r.status_code}"
            return meta

        data   = r.json()
        status = data.get("state", "")

        # Poll while running
        waited = 0
        while status not in ("FINISHED", "FAILED", "ABORTED") and waited < 60:
            time.sleep(5)
            waited += 5
            r      = requests.get(
                "https://http-observatory.security.mozilla.org/api/v1/analyze",
                params={"host": hostname},
                timeout=_API_TIMEOUT,
            )
            data   = r.json()
            status = data.get("state", "")

        grade = data.get("grade", "")
        score = data.get("score", 0)
        meta["observatory_grade"] = grade
        meta["observatory_score"] = score

        if grade and grade not in ("A+", "A"):
            sev = "high" if grade in ("D", "F") else "medium" if grade in ("C",) else "low"
            vulns.append(_vuln(
                f"Mozilla Observatory grade: {grade} (score {score}/100)",
                sev,
                f"Security header configuration is weak. Grade {grade}.",
                evidence=f"https://observatory.mozilla.org/analyze/{hostname}",
                remediation="Review Mozilla Observatory report for specific header fixes.",
                check="observatory",
            ))

        logger.info("Observatory | host=%s | grade=%s score=%s", hostname, grade, score)

    except Exception as exc:
        meta["observatory_error"] = str(exc)
        logger.debug("Observatory API error: %s", exc)

    return meta


def _check_shodan_internetdb(ip: str, vulns: list) -> dict:
    """
    Shodan InternetDB — free IP intelligence (no key required).
    Returns open ports, CPEs, CVEs, tags, hostnames.
    https://internetdb.shodan.io/
    """
    meta = {}
    if not ip or _is_private_ip(ip):
        return meta
    try:
        r    = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=_API_TIMEOUT)
        if r.status_code == 404:
            meta["shodan_note"] = "IP not indexed by Shodan"
            return meta
        if r.status_code != 200:
            meta["shodan_error"] = f"HTTP {r.status_code}"
            return meta

        data  = r.json()
        ports = data.get("ports", [])
        cves  = data.get("vulns", [])
        tags  = data.get("tags", [])

        meta["shodan_ports"] = ports
        meta["shodan_cves"]  = cves
        meta["shodan_tags"]  = tags

        # Exposed ports from Shodan's perspective
        risky_ports = {21, 22, 23, 25, 3306, 3389, 5432, 5900, 6379, 27017, 1433, 1521}
        for p in ports:
            if p in risky_ports:
                vulns.append(_vuln(
                    f"Shodan: risky port {p} exposed on {ip}",
                    "high",
                    f"Port {p} is publicly reachable according to Shodan internet scan.",
                    evidence=f"Shodan InternetDB: {ip} — port {p}",
                    remediation="Firewall this port if not required publicly.",
                    check="shodan",
                ))

        # CVEs from Shodan
        for cve_id in cves[:10]:  # cap at 10
            vulns.append(_vuln(
                f"Shodan: known CVE on {ip} — {cve_id}",
                "high",
                f"Shodan has indexed {cve_id} as affecting {ip}.",
                evidence=f"Shodan InternetDB: {ip}",
                remediation=f"Patch or mitigate {cve_id}. Check https://nvd.nist.gov/vuln/detail/{cve_id}",
                cve_ids=[cve_id],
                check="shodan",
            ))

        # Honeypot tag
        if "honeypot" in tags:
            meta["shodan_honeypot"] = True

        logger.info("Shodan | ip=%s | ports=%s | cves=%d", ip, ports, len(cves))

    except Exception as exc:
        meta["shodan_error"] = str(exc)
        logger.debug("Shodan InternetDB error: %s", exc)

    return meta


def _check_virustotal(url: str, ip: str, vulns: list) -> dict:
    """
    VirusTotal URL + IP reputation check.
    Free key: https://www.virustotal.com → My Account → API Key
    Set VT_API_KEY in .env
    """
    meta = {}
    vt_key = os.environ.get("VT_API_KEY", "").strip()
    if not vt_key:
        meta["virustotal_note"] = "VT_API_KEY not set — skipped"
        return meta

    headers = {"x-apikey": vt_key}
    try:
        import base64 as _b64
        url_id = _b64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=_API_TIMEOUT,
        )
        if r.status_code == 200:
            attrs     = r.json().get("data", {}).get("attributes", {})
            stats     = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total     = sum(stats.values())
            meta["vt_malicious"]  = malicious
            meta["vt_suspicious"] = suspicious
            meta["vt_total"]      = total

            if malicious > 0:
                vulns.append(_vuln(
                    f"VirusTotal: {malicious}/{total} engines flagged URL as malicious",
                    "critical",
                    f"{malicious} security vendors flagged this URL.",
                    evidence=f"VT URL scan: {malicious}/{total} malicious",
                    check="virustotal",
                ))
            elif suspicious > 0:
                vulns.append(_vuln(
                    f"VirusTotal: {suspicious}/{total} engines flagged URL as suspicious",
                    "medium",
                    f"{suspicious} security vendors consider this URL suspicious.",
                    evidence=f"VT URL scan: {suspicious}/{total} suspicious",
                    check="virustotal",
                ))
            logger.info("VirusTotal URL | malicious=%d suspicious=%d total=%d", malicious, suspicious, total)

        # Also check IP reputation
        if ip and not _is_private_ip(ip):
            r2 = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers, timeout=_API_TIMEOUT,
            )
            if r2.status_code == 200:
                attrs2     = r2.json().get("data", {}).get("attributes", {})
                stats2     = attrs2.get("last_analysis_stats", {})
                mal2       = stats2.get("malicious", 0)
                meta["vt_ip_malicious"] = mal2
                if mal2 > 0:
                    vulns.append(_vuln(
                        f"VirusTotal: IP {ip} flagged as malicious by {mal2} engines",
                        "high",
                        f"Server IP is on security vendor blocklists.",
                        evidence=f"VT IP scan: {ip}",
                        check="virustotal",
                    ))

    except Exception as exc:
        meta["virustotal_error"] = str(exc)
        logger.debug("VirusTotal error: %s", exc)

    return meta


def _check_abuseipdb(ip: str, vulns: list) -> dict:
    """
    AbuseIPDB — IP abuse score.
    Free key (1000 req/day): https://www.abuseipdb.com → API
    Set ABUSEIPDB_KEY in .env
    """
    meta = {}
    key = os.environ.get("ABUSEIPDB_KEY", "").strip()
    if not key or not ip or _is_private_ip(ip):
        return meta
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=_API_TIMEOUT,
        )
        if r.status_code == 200:
            data  = r.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            total = data.get("totalReports", 0)
            meta["abuseipdb_score"]   = score
            meta["abuseipdb_reports"] = total

            if score >= 75:
                vulns.append(_vuln(
                    f"AbuseIPDB: {ip} has abuse score {score}/100",
                    "high",
                    f"IP has been reported {total} times in 90 days (score {score}/100).",
                    evidence=f"AbuseIPDB: https://www.abuseipdb.com/check/{ip}",
                    check="abuseipdb",
                ))
            elif score >= 25:
                vulns.append(_vuln(
                    f"AbuseIPDB: {ip} has moderate abuse score {score}/100",
                    "medium",
                    f"IP has {total} abuse reports (score {score}/100).",
                    check="abuseipdb",
                ))
            logger.info("AbuseIPDB | ip=%s | score=%d reports=%d", ip, score, total)

    except Exception as exc:
        meta["abuseipdb_error"] = str(exc)
        logger.debug("AbuseIPDB error: %s", exc)

    return meta


# ══════════════════════════════════════════════════════════════════════════════
#  LOCAL PASSIVE CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def _check_headers(headers: dict, vulns: list) -> None:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for name, severity, description in REQUIRED_HEADERS:
        if name.lower() not in headers_lower:
            vulns.append(_vuln(
                f"Missing security header: {name}", severity, description,
                remediation=f"Add to server config: {name}: <value>",
                check="headers",
            ))

    # CSP quality check
    csp = headers_lower.get("content-security-policy", "")
    if csp:
        if "unsafe-inline" in csp:
            vulns.append(_vuln("CSP allows unsafe-inline scripts", "high",
                               "unsafe-inline in CSP negates XSS protection.",
                               evidence=f"CSP: {csp[:200]}", check="headers"))
        if "unsafe-eval" in csp:
            vulns.append(_vuln("CSP allows unsafe-eval", "medium",
                               "unsafe-eval allows eval() which widens XSS surface.",
                               check="headers"))
        if "default-src *" in csp or "script-src *" in csp:
            vulns.append(_vuln("CSP uses wildcard source", "high",
                               "Wildcard (*) in CSP allows loading resources from any origin.",
                               check="headers"))

    # HSTS quality
    hsts = headers_lower.get("strict-transport-security", "")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 15552000:
            vulns.append(_vuln("HSTS max-age too short", "medium",
                               f"HSTS max-age={m.group(1)} — should be ≥ 15552000 (6 months).",
                               evidence=f"HSTS: {hsts}", check="headers"))
        if "includeSubDomains" not in hsts:
            vulns.append(_vuln("HSTS missing includeSubDomains", "low",
                               "Subdomains are not covered by HSTS policy.",
                               check="headers"))


def _check_server_disclosure(headers: dict, vulns: list) -> None:
    server = headers.get("Server", "")
    if server:
        if re.search(r"\d+\.\d+", server):
            vulns.append(_vuln(f"Server version exposed: {server}", "medium",
                               "Server header reveals software version — aids targeted attacks.",
                               remediation="Apache: ServerTokens Prod | Nginx: server_tokens off",
                               check="disclosure"))
        # CVE matching
        for pattern, cve, desc, sev in VULN_SERVER_RE:
            if re.search(pattern, server, re.IGNORECASE):
                vulns.append(_vuln(f"Vulnerable server version — {cve}", sev, desc,
                                   evidence=f"Server: {server}",
                                   cve_ids=[cve], check="server_cve"))

    x_powered = headers.get("X-Powered-By", "")
    if x_powered:
        vulns.append(_vuln(f"X-Powered-By exposed: {x_powered}", "low",
                           "Reveals backend technology — helps attackers target known vulnerabilities.",
                           remediation="PHP: expose_php = Off | Express: app.disable('x-powered-by')",
                           check="disclosure"))
        for pattern, cve, desc, sev in VULN_SERVER_RE:
            if re.search(pattern, x_powered, re.IGNORECASE):
                vulns.append(_vuln(f"Vulnerable framework — {cve}", sev, desc,
                                   evidence=f"X-Powered-By: {x_powered}",
                                   cve_ids=[cve], check="server_cve"))


def _check_cookies(resp: requests.Response, vulns: list) -> None:
    for cookie in resp.cookies:
        if not cookie.secure:
            vulns.append(_vuln(f"Cookie missing Secure flag: {cookie.name}", "medium",
                               "Cookie transmitted over HTTP — interception possible.",
                               check="cookies"))
        if not cookie.has_nonstandard_attr("HttpOnly"):
            vulns.append(_vuln(f"Cookie missing HttpOnly flag: {cookie.name}", "medium",
                               "Cookie readable by JavaScript — XSS can steal session.",
                               check="cookies"))
        if not cookie.has_nonstandard_attr("SameSite"):
            vulns.append(_vuln(f"Cookie missing SameSite: {cookie.name}", "low",
                               "No CSRF protection via SameSite attribute.",
                               check="cookies"))


def _check_cors(headers: dict, vulns: list) -> None:
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*":
        vulns.append(_vuln("CORS: wildcard origin (Access-Control-Allow-Origin: *)", "medium",
                           "Any website can make cross-origin requests to this server.",
                           check="cors"))
    if acao == "*" and acac.lower() == "true":
        vulns.append(_vuln("CORS: wildcard + credentials — critical misconfiguration", "critical",
                           "Wildcard CORS with credentials=true allows credential theft from any origin.",
                           cve_ids=["CWE-942"], check="cors"))


def _check_sensitive_paths(base_url: str, sess: requests.Session, vulns: list) -> None:
    base = base_url.rstrip("/")
    for path, severity, description in SENSITIVE_PATHS:
        if severity == "info":
            continue  # skip info-only paths to reduce noise
        try:
            r = sess.get(f"{base}{path}", timeout=5, allow_redirects=False, verify=False)
            # Only flag real 200s with actual content (not soft-404s)
            if r.status_code == 200 and len(r.content) > 0:
                ct = r.headers.get("Content-Type", "")
                # Skip HTML pages that are likely custom 404s
                if "text/html" in ct and len(r.content) > 5000:
                    continue
                vulns.append(_vuln(
                    f"Sensitive path exposed: {path}", severity, description,
                    evidence=f"HTTP 200 — {base}{path} ({len(r.content)} bytes)",
                    remediation=f"Restrict access: <Files \"{path.lstrip('/')}\">\\n  Require all denied\\n</Files>",
                    check="sensitive_paths",
                ))
        except requests.RequestException:
            pass


def _check_http_methods(url: str, sess: requests.Session, vulns: list) -> None:
    try:
        r = sess.options(url, timeout=5, allow_redirects=False, verify=False)
        allow = r.headers.get("Allow", "")
        if allow:
            for method, severity, description in DANGEROUS_METHODS:
                if method in allow.upper():
                    vulns.append(_vuln(
                        f"Dangerous HTTP method enabled: {method}", severity, description,
                        evidence=f"OPTIONS Allow: {allow}",
                        remediation="<LimitExcept GET POST HEAD>\\n  Require all denied\\n</LimitExcept>",
                        check="http_methods",
                    ))
    except requests.RequestException:
        pass


def _check_response_body(resp: requests.Response, vulns: list) -> None:
    """Passive check of response body for error disclosure / info leaks."""
    try:
        body = resp.text[:50000]  # first 50KB only
    except Exception:
        return
    for pattern, severity, description in ERROR_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            vulns.append(_vuln(
                f"Information disclosure: {description}", severity, description,
                evidence=f"Pattern '{pattern}' found in response body",
                remediation="Disable debug mode and custom error pages in production.",
                check="disclosure",
            ))


def _check_redirect_http(base_url: str, hostname: str, sess: requests.Session, vulns: list) -> None:
    """Check if HTTP redirects to HTTPS."""
    if base_url.startswith("https://"):
        try:
            r = sess.get(f"http://{hostname}", timeout=5, allow_redirects=True, verify=False)
            if not r.url.startswith("https://"):
                vulns.append(_vuln(
                    "HTTP not redirected to HTTPS", "high",
                    "The site is accessible over plain HTTP without redirect to HTTPS.",
                    evidence=f"http://{hostname} → {r.url}",
                    remediation="RewriteEngine On\\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]",
                    check="https_redirect",
                ))
        except Exception:
            pass


def _check_ssl_basic(hostname: str, vulns: list) -> None:
    """Quick direct SSL check (fallback if SSL Labs is slow)."""
    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=5),
            server_hostname=hostname,
        )
        cert        = conn.getpeercert()
        tls_version = conn.version()
        conn.close()

        if tls_version in ("TLSv1", "TLSv1.1"):
            vulns.append(_vuln(f"Deprecated TLS version: {tls_version}", "high",
                               f"TLS {tls_version} is deprecated. Upgrade to TLS 1.2/1.3.",
                               check="ssl"))

        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                exp  = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    vulns.append(_vuln("SSL Certificate expired", "critical",
                                       f"Expired {-days} days ago.", check="ssl"))
                elif days < 30:
                    sev = "high" if days < 7 else "medium"
                    vulns.append(_vuln(f"SSL Certificate expires in {days} days", sev,
                                       f"Renew before {exp.strftime('%Y-%m-%d')}.", check="ssl"))
            except ValueError:
                pass
    except ssl.SSLError as e:
        vulns.append(_vuln("SSL Certificate error", "critical", str(e), check="ssl"))
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def run_web_scan(target: str, cve_check: bool = True, ssl_check: bool = True) -> dict:  # noqa: ARG001 cve_check kept for API compatibility
    """
    Full passive web security scan with external API enrichment.

    External APIs called:
      - SSL Labs API       (free, no key)
      - Mozilla Observatory (free, no key)
      - Shodan InternetDB  (free, no key)
      - VirusTotal         (optional — set VT_API_KEY)
      - AbuseIPDB          (optional — set ABUSEIPDB_KEY)
    """
    url     = _norm_url(target)
    parsed  = urlparse(url)
    host    = parsed.hostname or target
    sess    = _session()
    vulns:  list[dict] = []
    api_meta: dict     = {}

    logger.info("web_scan start | url=%s", url)

    # ── 1. HTTP request ───────────────────────────────────────────────────────
    try:
        resp = sess.get(url, timeout=12, verify=True, allow_redirects=True)
    except requests.exceptions.SSLError as exc:
        vulns.append(_vuln("SSL/TLS error", "critical", str(exc), check="ssl"))
        try:
            resp = sess.get(url, timeout=12, verify=False, allow_redirects=True)
        except requests.RequestException as exc2:
            raise RuntimeError(f"Cannot reach target: {exc2}") from exc2
    except requests.RequestException as exc:
        raise RuntimeError(f"Cannot reach target: {exc}") from exc

    headers = resp.headers

    # ── 2. Resolve IP ─────────────────────────────────────────────────────────
    ip = _resolve_ip(host)
    api_meta["resolved_ip"] = ip

    # ── 3. Local passive checks ───────────────────────────────────────────────
    _check_headers(headers, vulns)
    _check_server_disclosure(headers, vulns)
    _check_cookies(resp, vulns)
    _check_cors(headers, vulns)
    _check_response_body(resp, vulns)
    _check_redirect_http(url, host, sess, vulns)
    _check_http_methods(url, sess, vulns)
    _check_sensitive_paths(url, sess, vulns)

    if ssl_check and parsed.scheme == "https":
        _check_ssl_basic(host, vulns)

    # ── 4. External API checks ────────────────────────────────────────────────
    # SSL Labs (full TLS grade — only for HTTPS targets)
    if ssl_check and parsed.scheme == "https":
        ssl_meta = _check_ssllabs(host, vulns)
        api_meta.update(ssl_meta)

    # Mozilla Observatory
    obs_meta = _check_mozilla_observatory(host, vulns)
    api_meta.update(obs_meta)

    # Shodan InternetDB (free, no key)
    if ip:
        sh_meta = _check_shodan_internetdb(ip, vulns)
        api_meta.update(sh_meta)

    # VirusTotal (optional key)
    vt_meta = _check_virustotal(url, ip or "", vulns)
    api_meta.update(vt_meta)

    # AbuseIPDB (optional key)
    if ip:
        ab_meta = _check_abuseipdb(ip, vulns)
        api_meta.update(ab_meta)

    # ── 5. Deduplicate & sort ─────────────────────────────────────────────────
    seen, unique = set(), []
    for v in vulns:
        k = (v.get("check",""), v.get("title","")[:80])
        if k not in seen:
            seen.add(k)
            unique.append(v)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    unique.sort(key=lambda v: order.get(v.get("severity","info"), 5))

    logger.info(
        "web_scan done | host=%s | findings=%d | ssl_grade=%s | obs_grade=%s",
        host, len(unique),
        api_meta.get("ssllabs_grade", "N/A"),
        api_meta.get("observatory_grade", "N/A"),
    )

    return {
        "scan_type":       "web",
        "target":          target,
        "url":             resp.url,
        "status_code":     resp.status_code,
        "vulnerabilities": unique,
        "meta": {
            "scan_time":          datetime.now(timezone.utc).isoformat(),
            "host":               host,
            "resolved_ip":        ip,
            "findings_count":     len(unique),
            "ssl_grade":          api_meta.get("ssllabs_grade"),
            "observatory_grade":  api_meta.get("observatory_grade"),
            "observatory_score":  api_meta.get("observatory_score"),
            "shodan_ports":       api_meta.get("shodan_ports"),
            "shodan_cves":        api_meta.get("shodan_cves"),
            "vt_malicious":       api_meta.get("vt_malicious"),
            "abuseipdb_score":    api_meta.get("abuseipdb_score"),
            "apis_used": [
                k for k in ["SSL Labs", "Mozilla Observatory", "Shodan InternetDB",
                             "VirusTotal", "AbuseIPDB"]
            ],
        },
    }
