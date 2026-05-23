# scanners/web_scanner.py
"""
Web Application Scanner  v2
════════════════════════════════════════════════════════════════════
All external API calls run in parallel (ThreadPoolExecutor + as_completed).
Each check returns (list[dict], dict) — vulns + meta.

APIs used — International Grade, Free Tier:
┌──────────────────────────┬──────────────┬──────────────────────────────────────────────────────┐
│ API                      │ Key needed?  │ How to get the key                                   │
├──────────────────────────┼──────────────┼──────────────────────────────────────────────────────┤
│ SSL Labs                 │ No           │ https://www.ssllabs.com  (auto)                      │
│ Mozilla Observatory v2   │ No           │ https://observatory.mozilla.org  (auto)              │
│ Shodan InternetDB        │ No           │ https://internetdb.shodan.io  (auto)                 │
│ crt.sh  (CT logs)        │ No           │ https://crt.sh  (auto)                              │
│ URLhaus / abuse.ch       │ No           │ https://urlhaus.abuse.ch  (auto)                    │
│ GreyNoise Community      │ No           │ https://viz.greynoise.io  (auto)                    │
│ IPinfo.io                │ No*          │ https://ipinfo.io  (50k req/month free, auto)        │
│ VirusTotal v3            │ Yes (free)   │ virustotal.com → My Account → API Key → VT_API_KEY  │
│ AbuseIPDB v2             │ Yes (free)   │ abuseipdb.com → Account → API → ABUSEIPDB_KEY       │
│ Google Safe Browsing v4  │ Yes (free)   │ 1. console.cloud.google.com → new project            │
│                          │              │ 2. APIs & Services → Enable "Safe Browsing API"      │
│                          │              │ 3. Credentials → Create API Key                      │
│                          │              │    → GOOGLE_SAFE_BROWSING_KEY                        │
│ URLScan.io               │ Yes (free)   │ urlscan.io → Register → API Key → URLSCAN_API_KEY   │
│                          │              │ (without key: searches recent public scans)           │
└──────────────────────────┴──────────────┴──────────────────────────────────────────────────────┘

Local passive checks (zero external cost):
  • 7 required security headers with quality validation
  • Deep CSP analysis: unsafe-inline/eval, wildcards, data: URI, upgrade-insecure-requests
  • Cookie security: Secure, HttpOnly, SameSite + __Secure-/__Host- prefix violations
  • CORS: wildcard, arbitrary origin reflection, null-origin bypass, credentials+wildcard
  • Server version disclosure + 10 CVE patterns (Apache, nginx, PHP, OpenSSL, IIS)
  • 16 error/info disclosure patterns (DB errors, tracebacks, private keys, AWS keys)
  • HTTP dangerous methods (TRACE, PUT, DELETE, CONNECT) via OPTIONS probe
  • 50 sensitive paths with smart soft-404 fingerprinting
  • HTTP → HTTPS redirect enforcement check
  • Direct TLS/SSL check (cert expiry, deprecated protocol negotiation)
  • WAF/CDN detection: Cloudflare, AWS CloudFront, Imperva, Akamai, Sucuri, Azure, F5, Fastly
  • Technology fingerprinting: WordPress, Laravel, Django, Next.js, React, Angular, PHP, ASP.NET
  • DNS security: SPF + DMARC via Google DNS-over-HTTPS (no extra packages required)
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import socket
import ssl
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ── Timeouts ─────────────────────────────────────────────────────────────────
_API_TO       = 15
_PROBE_TO     = 5
_SSLLABS_POLL = 8
_SSLLABS_MAX  = 120
_URLSCAN_POLL = 8
_URLSCAN_MAX  = 90
_MAX_WORKERS  = 18   # 17 tasks total; extra slack so SSL Labs polling never starves others

# ── Required security headers ─────────────────────────────────────────────────
REQUIRED_HEADERS = [
    ("Strict-Transport-Security",  "high",   "HSTS missing — browser will not enforce HTTPS"),
    ("Content-Security-Policy",    "high",   "CSP missing — no XSS / injection protection policy"),
    ("X-Frame-Options",            "medium", "X-Frame-Options missing — clickjacking possible"),
    ("X-Content-Type-Options",     "medium", "MIME-sniffing protection missing"),
    ("Referrer-Policy",            "low",    "Referrer-Policy missing — URL may leak to third parties"),
    ("Permissions-Policy",         "low",    "Permissions-Policy missing — browser APIs unrestricted"),
    ("Cross-Origin-Opener-Policy", "low",    "COOP missing — cross-origin isolation not enforced"),
]

# ── Sensitive paths ───────────────────────────────────────────────────────────
SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    # Critical
    ("/.git/config",              "critical", "Git config exposed — source code accessible"),
    ("/.git/HEAD",                "critical", "Git repo exposed — full history downloadable"),
    ("/.git/COMMIT_EDITMSG",      "critical", "Git commit messages exposed"),
    ("/.env",                     "critical", ".env exposed — API keys / DB passwords"),
    ("/.env.local",               "critical", ".env.local exposed"),
    ("/.env.production",          "critical", ".env.production exposed"),
    ("/.env.backup",              "critical", ".env.backup exposed"),
    ("/.htpasswd",                "critical", ".htpasswd password file exposed"),
    ("/wp-config.php",            "critical", "WordPress config exposed — DB credentials"),
    ("/.aws/credentials",         "critical", "AWS credentials file exposed"),
    ("/.npmrc",                   "critical", "npm credentials file exposed"),
    ("/backup.zip",               "critical", "Site backup archive downloadable"),
    ("/backup.sql",               "critical", "SQL backup downloadable"),
    ("/dump.sql",                 "critical", "Database dump downloadable"),
    ("/db.sql",                   "critical", "Database dump downloadable"),
    ("/config/database.php",      "critical", "Laravel database config exposed"),
    # High
    ("/phpinfo.php",              "high",     "phpinfo() exposed — full server config"),
    ("/server-status",            "high",     "Apache mod_status — live requests exposed"),
    ("/server-info",              "high",     "Apache mod_info — module config exposed"),
    ("/actuator",                 "high",     "Spring Boot Actuator base endpoint"),
    ("/actuator/env",             "critical", "Spring Boot /actuator/env — secrets exposed"),
    ("/actuator/heapdump",        "critical", "Spring Boot heap dump downloadable"),
    ("/actuator/beans",           "high",     "Spring Boot beans endpoint exposed"),
    ("/actuator/mappings",        "high",     "Spring Boot route mappings exposed"),
    ("/_profiler",                "high",     "Symfony Profiler exposed"),
    ("/storage/logs/laravel.log", "high",     "Laravel log — stack traces and secrets"),
    ("/web.config",               "high",     "IIS web.config exposed"),
    ("/Dockerfile",               "high",     "Dockerfile exposed — infrastructure info"),
    ("/docker-compose.yml",       "high",     "Docker Compose config exposed"),
    ("/.travis.yml",              "high",     "CI config exposed — may contain secrets"),
    ("/Jenkinsfile",              "high",     "Jenkins pipeline script exposed"),
    ("/wp-content/debug.log",     "high",     "WordPress debug log exposed"),
    # Medium
    ("/api/swagger.json",         "medium",   "Swagger/OpenAPI spec exposed"),
    ("/swagger.json",             "medium",   "Swagger spec exposed"),
    ("/openapi.json",             "medium",   "OpenAPI spec exposed"),
    ("/api/docs",                 "medium",   "API documentation exposed"),
    ("/graphql",                  "medium",   "GraphQL — verify introspection disabled"),
    ("/admin",                    "medium",   "Admin panel — verify authentication"),
    ("/wp-admin/",                "medium",   "WordPress admin panel"),
    ("/wp-json/wp/v2/users",      "medium",   "WordPress user enumeration endpoint"),
    ("/package.json",             "medium",   "package.json — dependency versions exposed"),
    ("/composer.json",            "medium",   "composer.json — PHP dependencies exposed"),
    # Low / Info
    ("/.DS_Store",                "low",      ".DS_Store — macOS directory structure leak"),
    ("/robots.txt",               "info",     "robots.txt — review for sensitive path hints"),
    ("/sitemap.xml",              "info",     "Sitemap exposed — full URL structure"),
    ("/.well-known/security.txt", "info",     "security.txt present"),
]

# ── Dangerous HTTP methods ────────────────────────────────────────────────────
DANGEROUS_METHODS = [
    ("TRACE",   "medium", "HTTP TRACE enabled — Cross-Site Tracing (XST) possible"),
    ("PUT",     "high",   "HTTP PUT enabled — arbitrary file upload possible"),
    ("DELETE",  "high",   "HTTP DELETE enabled — file deletion possible"),
    ("CONNECT", "medium", "HTTP CONNECT enabled — server usable as proxy"),
]

# ── Server CVE patterns ───────────────────────────────────────────────────────
VULN_SERVER_RE = [
    (r"Apache/2\.4\.(4[89]|50)\b",        "CVE-2021-41773", "Apache 2.4.49/50 Path Traversal + RCE",    "critical"),
    (r"Apache/2\.4\.(5[0-5])\b",          "CVE-2023-25690", "Apache < 2.4.56 Request Splitting",         "critical"),
    (r"Apache/2\.4\.([0-3]\d|4[0-8])\b",  "CVE-2022-22721", "Apache mod_sed buffer overflow",            "high"),
    (r"nginx/1\.(1[0-7]|[0-9])\.",        "CVE-2021-23017", "nginx DNS resolver buffer overwrite",       "high"),
    (r"nginx/1\.18\.[01]\b",              "CVE-2021-23017", "nginx 1.18 DNS resolver issue",             "medium"),
    (r"PHP/([0-7]\.|8\.[012]\.)",         "CVE-2024-4577",  "PHP CGI argument injection (< 8.3.8)",      "critical"),
    (r"OpenSSL/1\.[01]\.",                "CVE-2022-0778",  "OpenSSL 1.x infinite loop DoS",             "high"),
    (r"OpenSSL/3\.0\.[0-6]\b",           "CVE-2022-3786",  "OpenSSL 3.0.x buffer overrun",              "high"),
    (r"IIS/[0-7]\.",                      "CVE-2021-31166", "IIS HTTP stack RCE (< IIS 10)",             "critical"),
    (r"IIS/10\.0",                        "CVE-2022-21907", "IIS 10 HTTP Protocol Stack RCE",            "critical"),
]

# ── Error / info disclosure body patterns ────────────────────────────────────
ERROR_PATTERNS = [
    (r"SQL syntax.*?MySQL",                        "critical", "MySQL error — SQL Injection likely"),
    (r"Warning.*?mysql_",                          "critical", "PHP MySQL error — SQL Injection likely"),
    (r"ORA-\d{5}",                                "critical", "Oracle DB error exposed"),
    (r"Microsoft OLE DB.*?SQL Server",             "critical", "MSSQL error — SQL Injection likely"),
    (r"PostgreSQL.*?ERROR:\s",                     "critical", "PostgreSQL error exposed"),
    (r"Traceback \(most recent call last\)",       "high",     "Python traceback — stack trace disclosed"),
    (r"at [\w\.]+\([\w\.]+\.java:\d+\)",           "high",     "Java stack trace disclosed"),
    (r"<b>Warning</b>.*?on line \d+",              "medium",   "PHP warning in HTTP response"),
    (r"Fatal error.*?PHP",                         "high",     "PHP fatal error exposed"),
    (r"DEBUG\s*=\s*True",                          "medium",   "Django DEBUG=True in production"),
    (r"<title>(?:Django|Werkzeug).*?Error",        "high",     "Framework debug error page exposed"),
    (r"Caused by:.*?Exception",                    "high",     "Java exception chain disclosed"),
    (r"root:x:0:0:",                               "critical", "Possible /etc/passwd contents in response"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",  "critical", "Private key in HTTP response"),
    (r"AKIA[0-9A-Z]{16}",                          "critical", "AWS access key in HTTP response"),
    (r"sk_live_[0-9a-zA-Z]{24,}",                 "critical", "Stripe live API key in HTTP response"),
]

# ── WAF / CDN signatures ──────────────────────────────────────────────────────
_WAF_SIGS: dict[str, list[tuple[str, str | None]]] = {
    "Cloudflare":     [("server", "cloudflare"),    ("cf-ray", None)],
    "AWS CloudFront": [("x-amz-cf-id", None),       ("x-amz-cf-pop", None)],
    "AWS WAF":        [("x-amzn-requestid", None),  ("x-amzn-trace-id", None)],
    "Imperva":        [("x-iinfo", None),            ("x-cdn", "Incapsula")],
    "Akamai":         [("x-check-cacheable", None),  ("akamai-grn", None)],
    "Sucuri":         [("x-sucuri-id", None),        ("x-sucuri-cache", None)],
    "Azure CDN/WAF":  [("x-azure-ref", None),        ("x-ec-custom-error", None)],
    "F5 BIG-IP":      [("x-wa-info", None),          ("bigipserver", None)],
    "Fastly":         [("x-fastly-request-id", None),("fastly-debug-digest", None)],
    "Varnish":        [("x-varnish", None),          ("via", "varnish")],
    "ModSecurity":    [("x-modsecurity", None)],
}

# ── Technology fingerprints ───────────────────────────────────────────────────
_TECH_SIGS: dict[str, list[tuple[str, str]]] = {
    "WordPress":     [("header", r"x-pingback"), ("cookie", r"^wordpress_"), ("body", r"wp-content|wp-includes")],
    "Drupal":        [("header", r"x-generator.*drupal"), ("cookie", r"^SESS[a-f0-9]{32}")],
    "Joomla":        [("body", r"generator.*Joomla"), ("cookie", r"^joomla_")],
    "Laravel":       [("cookie", r"XSRF-TOKEN"), ("cookie", r"laravel_session")],
    "Django":        [("cookie", r"^csrftoken"), ("body", r"csrfmiddlewaretoken")],
    "Spring/Java":   [("cookie", r"JSESSIONID"), ("header", r"x-application-context")],
    "ASP.NET":       [("header", r"x-powered-by.*asp\.net"), ("cookie", r"ASP\.NET_SessionId")],
    "PHP":           [("header", r"x-powered-by.*php"), ("cookie", r"PHPSESSID")],
    "Express/Node":  [("header", r"x-powered-by.*express")],
    "Ruby on Rails": [("cookie", r"_\w+_session$")],
    "Next.js":       [("body", r"__NEXT_DATA__"), ("header", r"x-nextjs-cache")],
    "Nuxt.js":       [("body", r"__NUXT__")],
    "React":         [("body", r"data-reactroot|__react_fiber")],
    "Angular":       [("body", r"ng-version|angular\.min\.js")],
    "Vue.js":        [("body", r"__vue__|vue\.runtime\.min\.js")],
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_session() -> requests.Session:
    sess = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=0.4,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    sess.mount("https://", adapter)
    sess.mount("http://",  adapter)
    sess.headers["User-Agent"] = "CyBrain-Security-Scanner/4.2"
    return sess


def _norm_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def _resolve_ip(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _is_private(ip: str) -> bool:
    try:
        a = ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except Exception:
        return False


def _vuln(
    title: str,
    severity: str,
    description: str,
    evidence: str = "",
    remediation: str = "",
    cve_ids: list | None = None,
    check: str = "web",
) -> dict:
    v: dict = {"check": check, "title": title, "severity": severity, "description": description}
    if evidence:    v["evidence"]    = evidence
    if remediation: v["remediation"] = remediation
    if cve_ids:     v["cve_ids"]     = cve_ids
    return v


def _dedup_key(v: dict) -> str:
    raw = v.get("check", "") + "|" + re.sub(r"https?://\S+", "URL", v.get("title", ""))[:80]
    return hashlib.md5(raw.lower().encode(), usedforsecurity=False).hexdigest()


def _404_fingerprint(base_url: str, sess: requests.Session) -> tuple[int, str]:
    """Probe a nonexistent path to fingerprint soft-404 responses."""
    probe = f"/cybrain-probe-{os.urandom(4).hex()}-notfound.html"
    try:
        r = sess.get(f"{base_url}{probe}", timeout=_PROBE_TO,
                     allow_redirects=False, verify=False)
        return len(r.content), hashlib.md5(r.content[:512], usedforsecurity=False).hexdigest()
    except Exception:
        return 0, ""


def _is_soft_404(content: bytes, fp: tuple[int, str]) -> bool:
    fp_len, fp_hash = fp
    if fp_len == 0:
        return False
    h = hashlib.md5(content[:512], usedforsecurity=False).hexdigest()
    if h == fp_hash:
        return True
    # within 8% of 404 size → very likely a custom 404 page
    if fp_len > 0 and abs(len(content) - fp_len) / max(fp_len, 1) < 0.08:
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# External API checks  (each returns  (list[dict], dict))
# ─────────────────────────────────────────────────────────────────────────────

def _api_ssllabs(host: str) -> tuple[list[dict], dict]:
    """
    Qualys SSL Labs API v3 — industry standard TLS grading.
    https://www.ssllabs.com/ssltest/
    Free, no key required.
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    sess = _make_session()
    base = "https://api.ssllabs.com/api/v3"

    try:
        r = sess.get(f"{base}/analyze",
                     params={"host": host, "all": "done", "ignoreMismatch": "on"},
                     timeout=_API_TO)
        if r.status_code != 200:
            return vulns, {"ssllabs_error": f"HTTP {r.status_code}"}

        data = r.json()
        waited = 0
        while data.get("status") not in ("READY", "ERROR") and waited < _SSLLABS_MAX:
            time.sleep(_SSLLABS_POLL)
            waited += _SSLLABS_POLL
            r    = sess.get(f"{base}/analyze",
                            params={"host": host, "all": "done"}, timeout=_API_TO)
            data = r.json()

        if data.get("status") == "ERROR":
            return vulns, {"ssllabs_error": data.get("statusMessage", "SSL Labs error")}
        if data.get("status") != "READY":
            return vulns, {"ssllabs_error": f"SSL Labs timed out after {_SSLLABS_MAX}s"}

        grades = []
        for ep in data.get("endpoints", []):
            grade   = ep.get("grade", "")
            details = ep.get("details", {}) or {}
            if grade:
                grades.append(grade)

            # Weak grade
            if grade and grade not in ("A", "A+", "A-", "B"):
                sev = "critical" if grade in ("F", "T") else "high" if grade in ("C", "D") else "medium"
                vulns.append(_vuln(
                    f"SSL Labs grade: {grade}",
                    sev,
                    f"TLS configuration is weak. Grade {grade} for {host}. "
                    "Review cipher suites, protocol versions and certificate chain.",
                    evidence=f"SSL Labs: {grade}",
                    remediation="Enable TLS 1.3, disable TLS 1.0/1.1, use strong ciphers. "
                                "Reference: https://ssl-config.mozilla.org/",
                    check="ssl_labs",
                ))

            # Deprecated protocols
            for proto in details.get("protocols", []):
                ver = proto.get("version", "")
                if ver in ("1.0", "1.1"):
                    vulns.append(_vuln(
                        f"Deprecated TLS {ver} supported",
                        "high",
                        f"TLS {ver} deprecated RFC 8996 — must be disabled.",
                        evidence=f"SSL Labs detected TLS {ver} on {host}",
                        remediation="SSLProtocol -all +TLSv1.2 +TLSv1.3",
                        check="ssl_labs",
                    ))

            # SSL 3.0
            if details.get("sslv3"):
                vulns.append(_vuln(
                    "SSL 3.0 enabled (POODLE)",
                    "critical",
                    "SSLv3 is broken and vulnerable to POODLE attack.",
                    check="ssl_labs",
                ))

            # Certificate expiry
            cert = details.get("cert") or {}
            not_after = cert.get("notAfter", 0)
            if not_after:
                exp       = datetime.fromtimestamp(not_after / 1000, tz=timezone.utc)
                days_left = (exp - datetime.now(timezone.utc)).days
                if days_left < 0:
                    vulns.append(_vuln("SSL Certificate EXPIRED", "critical",
                                       f"Expired {-days_left} days ago.", check="ssl_labs"))
                elif days_left < 7:
                    vulns.append(_vuln(f"SSL Certificate expires in {days_left} days", "critical",
                                       "Immediate renewal required.", check="ssl_labs"))
                elif days_left < 14:
                    vulns.append(_vuln(f"SSL Certificate expires in {days_left} days", "high",
                                       "Renew urgently.", check="ssl_labs"))
                elif days_left < 30:
                    vulns.append(_vuln(f"SSL Certificate expires in {days_left} days", "medium",
                                       f"Renew before {exp.strftime('%Y-%m-%d')}.", check="ssl_labs"))

            # Self-signed — check selfSigned flag directly (issues==0 is a separate concern)
            if cert.get("selfSigned"):
                vulns.append(_vuln("Self-signed SSL certificate", "high",
                                   "Certificate not trusted by browsers.", check="ssl_labs"))

            # HSTS max-age
            sts = details.get("hstsPolicy") or {}
            if sts.get("status") == "present" and sts.get("maxAge", 0) < 15_552_000:
                vulns.append(_vuln("HSTS max-age too short", "medium",
                                   f"HSTS max-age={sts['maxAge']}s — should be ≥ 15552000 (6 months).",
                                   check="ssl_labs"))

        meta["ssllabs_grade"]  = "/".join(grades) or "N/A"
        meta["ssllabs_status"] = "READY"
        logger.info("SSL Labs | host=%s | grade=%s", host, meta["ssllabs_grade"])

    except Exception as exc:
        meta["ssllabs_error"] = str(exc)
        logger.debug("SSL Labs error: %s", exc)

    return vulns, meta


def _api_observatory(host: str) -> tuple[list[dict], dict]:
    """
    Mozilla HTTP Observatory v2 — security header grading.
    New v2 API is synchronous (no polling).
    https://observatory.mozilla.org/
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    sess = _make_session()

    def _try_v2() -> dict | None:
        r = sess.post(
            f"https://observatory-api.mdn.mozilla.net/api/v2/analyze?host={host}",
            timeout=_API_TO,
        )
        if r.status_code == 200:
            return r.json()
        return None

    def _try_v1() -> dict | None:
        r = sess.post(
            "https://http-observatory.security.mozilla.org/api/v1/analyze",
            params={"host": host},
            data={"hidden": "true", "rescan": "false"},
            timeout=_API_TO,
        )
        if r.status_code != 200:
            return None
        data   = r.json()
        waited = 0
        while data.get("state") not in ("FINISHED", "FAILED", "ABORTED") and waited < 60:
            time.sleep(5)
            waited += 5
            r    = sess.get("https://http-observatory.security.mozilla.org/api/v1/analyze",
                            params={"host": host}, timeout=_API_TO)
            data = r.json()
        return data

    try:
        data = _try_v2() or _try_v1()
        if not data:
            return vulns, {"observatory_error": "Both v1 and v2 unreachable"}

        grade = data.get("grade", "")
        score = int(data.get("score", 0))
        meta["observatory_grade"] = grade
        meta["observatory_score"] = score

        if grade and grade not in ("A+", "A"):
            sev = "high" if grade in ("D", "F") else "medium" if grade == "C" else "low"
            vulns.append(_vuln(
                f"Mozilla Observatory grade: {grade} (score {score}/100)",
                sev,
                f"Security header configuration weak. Grade {grade}, score {score}/100.",
                evidence=f"https://observatory.mozilla.org/analyze/{host}",
                remediation="Review the full report at observatory.mozilla.org for exact fixes.",
                check="observatory",
            ))
        logger.info("Observatory | host=%s grade=%s score=%d", host, grade, score)

    except Exception as exc:
        meta["observatory_error"] = str(exc)
        logger.debug("Observatory error: %s", exc)

    return vulns, meta


def _api_shodan(ip: str | None) -> tuple[list[dict], dict]:
    """
    Shodan InternetDB — free IP intelligence (no key).
    Returns CVEs, open ports, hostnames, tags.
    https://internetdb.shodan.io/
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    if not ip or _is_private(ip):
        return vulns, meta

    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=_API_TO)
        if r.status_code == 404:
            return vulns, {"shodan_note": "IP not indexed"}
        if r.status_code != 200:
            return vulns, {"shodan_error": f"HTTP {r.status_code}"}

        data  = r.json()
        ports = data.get("ports", [])
        cves  = data.get("vulns", [])
        tags  = data.get("tags", [])
        meta.update({"shodan_ports": ports, "shodan_cves": cves, "shodan_tags": tags})

        risky = {21, 22, 23, 25, 3306, 3389, 5432, 5900, 6379, 9200, 27017, 1433, 1521, 11211}
        for p in ports:
            if p in risky:
                vulns.append(_vuln(
                    f"Shodan: risky port {p} exposed on {ip}",
                    "high",
                    f"Port {p} is publicly reachable per Shodan internet-wide scan.",
                    evidence=f"Shodan InternetDB: {ip} — port {p}",
                    remediation="Firewall this port if not required publicly.",
                    check="shodan",
                ))

        for cve_id in cves[:10]:
            vulns.append(_vuln(
                f"Shodan: known CVE on {ip} — {cve_id}",
                "high",
                f"Shodan has indexed {cve_id} as affecting {ip}.",
                evidence=f"Shodan InternetDB: {ip}",
                remediation=f"Patch: https://nvd.nist.gov/vuln/detail/{cve_id}",
                cve_ids=[cve_id], check="shodan",
            ))

        tag_map = {
            "malware":     ("critical", "Shodan: host tagged as malware distribution"),
            "self-signed": ("medium",   "Shodan: self-signed certificate detected"),
            "tor":         ("medium",   "Shodan: Tor exit node"),
            "honeypot":    ("info",     "Shodan: possible honeypot"),
        }
        for tag in tags:
            if tag.lower() in tag_map:
                sev, msg = tag_map[tag.lower()]
                vulns.append(_vuln(msg, sev, f"Shodan tag '{tag}' on {ip}.", check="shodan"))

        logger.info("Shodan | ip=%s ports=%s cves=%d", ip, ports, len(cves))

    except Exception as exc:
        meta["shodan_error"] = str(exc)
        logger.debug("Shodan error: %s", exc)

    return vulns, meta


def _api_virustotal(url: str, ip: str | None) -> tuple[list[dict], dict]:
    """
    VirusTotal v3 — URL + IP reputation against 90+ security vendors.
    Free key: https://www.virustotal.com → My Account → API Key → VT_API_KEY
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        return vulns, {"virustotal_note": "VT_API_KEY not set — skipped"}

    headers = {"x-apikey": key}
    sess    = _make_session()

    try:
        # URL check
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = sess.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                     headers=headers, timeout=_API_TO)
        if r.status_code == 200:
            attrs     = r.json().get("data", {}).get("attributes", {})
            stats     = attrs.get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values())
            meta.update({"vt_malicious": malicious, "vt_suspicious": suspicious, "vt_total": total})

            if malicious > 0:
                vulns.append(_vuln(
                    f"VirusTotal: {malicious}/{total} vendors flagged URL as malicious",
                    "critical",
                    f"{malicious} security vendors flagged this URL. Categories: "
                    f"{list(attrs.get('categories', {}).values())[:3]}",
                    evidence=f"VirusTotal URL: malicious={malicious}/{total}",
                    check="virustotal",
                ))
            elif suspicious > 0:
                vulns.append(_vuln(
                    f"VirusTotal: {suspicious}/{total} vendors flagged URL as suspicious",
                    "medium",
                    f"{suspicious} security vendors consider this URL suspicious.",
                    check="virustotal",
                ))

        # IP check
        if ip and not _is_private(ip):
            r2 = sess.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                          headers=headers, timeout=_API_TO)
            if r2.status_code == 200:
                stats2 = r2.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                mal2   = stats2.get("malicious", 0)
                meta["vt_ip_malicious"] = mal2
                if mal2 > 0:
                    vulns.append(_vuln(
                        f"VirusTotal: IP {ip} flagged by {mal2} vendors",
                        "high",
                        f"Server IP is on {mal2} security vendor blocklists.",
                        evidence=f"VirusTotal IP: {ip}",
                        check="virustotal",
                    ))
        logger.info("VirusTotal | url malicious=%s ip_malicious=%s",
                    meta.get("vt_malicious"), meta.get("vt_ip_malicious"))

    except Exception as exc:
        meta["virustotal_error"] = str(exc)
        logger.debug("VirusTotal error: %s", exc)

    return vulns, meta


def _api_abuseipdb(ip: str | None) -> tuple[list[dict], dict]:
    """
    AbuseIPDB v2 — IP abuse confidence score (1000 req/day free).
    https://www.abuseipdb.com → Account → API Key → ABUSEIPDB_KEY
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    key = os.environ.get("ABUSEIPDB_KEY", "").strip()
    if not key or not ip or _is_private(ip):
        return vulns, meta

    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": key, "Accept": "application/json"},
            timeout=_API_TO,
        )
        if r.status_code == 200:
            data    = r.json().get("data", {})
            score   = data.get("abuseConfidenceScore", 0)
            total   = data.get("totalReports", 0)
            country = data.get("countryCode", "")
            isp     = data.get("isp", "")
            meta.update({"abuseipdb_score": score, "abuseipdb_reports": total,
                         "abuseipdb_isp": isp, "abuseipdb_country": country})

            if score >= 75:
                vulns.append(_vuln(
                    f"AbuseIPDB: {ip} abuse score {score}/100 — HIGH RISK",
                    "high",
                    f"IP reported {total} times in 90 days. Score {score}/100. ISP: {isp}.",
                    evidence=f"https://www.abuseipdb.com/check/{ip}",
                    check="abuseipdb",
                ))
            elif score >= 25:
                vulns.append(_vuln(
                    f"AbuseIPDB: {ip} moderate abuse score {score}/100",
                    "medium",
                    f"IP has {total} abuse reports (score {score}/100). ISP: {isp}.",
                    check="abuseipdb",
                ))
        logger.info("AbuseIPDB | ip=%s score=%s", ip, meta.get("abuseipdb_score"))

    except Exception as exc:
        meta["abuseipdb_error"] = str(exc)
        logger.debug("AbuseIPDB error: %s", exc)

    return vulns, meta


def _api_google_safebrowsing(url: str) -> tuple[list[dict], dict]:
    """
    Google Safe Browsing API v4 — used by Chrome, Safari, Firefox.
    Detects malware, phishing, unwanted software, harmful apps.
    Free key (10k req/day):
      1. console.cloud.google.com → new project
      2. APIs & Services → Enable "Safe Browsing API"
      3. Credentials → Create API Key
      Set GOOGLE_SAFE_BROWSING_KEY in .env
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "").strip()
    if not key:
        return vulns, {"gsb_note": "GOOGLE_SAFE_BROWSING_KEY not set — skipped"}

    try:
        body = {
            "client":     {"clientId": "cybrain-scanner", "clientVersion": "4.2"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                     "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}],
            },
        }
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=body, timeout=_API_TO,
        )
        if r.status_code == 200:
            matches = r.json().get("matches", [])
            meta["gsb_threats"] = len(matches)
            for m in matches:
                threat_type = m.get("threatType", "UNKNOWN")
                sev = "critical" if threat_type in ("MALWARE", "SOCIAL_ENGINEERING") else "high"
                vulns.append(_vuln(
                    f"Google Safe Browsing: {threat_type}",
                    sev,
                    f"URL flagged by Google Safe Browsing as {threat_type}. "
                    "This URL is blocked by Chrome, Firefox and Safari.",
                    evidence=f"GSB threat type: {threat_type}",
                    check="google_safebrowsing",
                ))
            logger.info("Google Safe Browsing | url=%s threats=%d", url, len(matches))

    except Exception as exc:
        meta["gsb_error"] = str(exc)
        logger.debug("Google Safe Browsing error: %s", exc)

    return vulns, meta


def _api_urlscan(url: str, host: str) -> tuple[list[dict], dict]:
    """
    URLScan.io — URL analysis with screenshot, redirect chain, verdict.
    Used by CERTs and SOC teams worldwide.
    Free key: https://urlscan.io/user/apikey → URLSCAN_API_KEY
    Without key: searches recent public scans for the domain.
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    key  = os.environ.get("URLSCAN_API_KEY", "").strip()
    sess = _make_session()

    try:
        if key:
            # Submit new private scan
            r = sess.post(
                "https://urlscan.io/api/v1/scan/",
                headers={"API-Key": key, "Content-Type": "application/json"},
                json={"url": url, "visibility": "private"},
                timeout=_API_TO,
            )
            if r.status_code in (200, 201):
                scan_uuid = r.json().get("uuid", "")
                meta["urlscan_uuid"] = scan_uuid
                if scan_uuid:
                    # Poll for result
                    waited = 0
                    result_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
                    while waited < _URLSCAN_MAX:
                        time.sleep(_URLSCAN_POLL)
                        waited += _URLSCAN_POLL
                        res = sess.get(result_url, headers={"API-Key": key}, timeout=_API_TO)
                        if res.status_code == 200:
                            data = res.json()
                            verdict = data.get("verdicts", {}).get("overall", {})
                            score   = verdict.get("score", 0)
                            mal     = verdict.get("malicious", False)
                            meta.update({"urlscan_score": score, "urlscan_malicious": mal})
                            if mal:
                                vulns.append(_vuln(
                                    "URLScan.io: URL flagged as malicious",
                                    "critical",
                                    f"URLScan.io verdict: malicious, score={score}. "
                                    f"Report: https://urlscan.io/result/{scan_uuid}/",
                                    evidence=f"URLScan score={score}",
                                    check="urlscan",
                                ))
                            elif score and score > 50:
                                vulns.append(_vuln(
                                    f"URLScan.io: suspicious score {score}/100",
                                    "medium",
                                    f"URLScan.io score={score}/100. "
                                    f"Report: https://urlscan.io/result/{scan_uuid}/",
                                    check="urlscan",
                                ))
                            break
                        elif res.status_code == 404:
                            continue
            return vulns, meta

        # No key: search recent public scans for this domain
        r = sess.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{host}", "sort": "date:desc", "size": "5"},
            timeout=_API_TO,
        )
        if r.status_code == 200:
            results = r.json().get("results", [])
            for item in results:
                verdict = item.get("verdicts", {}).get("overall", {})
                if verdict.get("malicious"):
                    scan_id = item.get("_id", "")
                    vulns.append(_vuln(
                        "URLScan.io: recent scan flagged domain as malicious",
                        "critical",
                        f"A recent URLScan.io public scan found this domain malicious. "
                        f"Report: https://urlscan.io/result/{scan_id}/",
                        check="urlscan",
                    ))
                    break
            meta["urlscan_recent_scans"] = len(results)
        logger.info("URLScan.io | host=%s results=%s", host, meta.get("urlscan_recent_scans"))

    except Exception as exc:
        meta["urlscan_error"] = str(exc)
        logger.debug("URLScan error: %s", exc)

    return vulns, meta


def _api_urlhaus(url: str) -> tuple[list[dict], dict]:
    """
    URLhaus by abuse.ch — malware distribution URL database.
    Used by all major CERTs. Free, no key required.
    https://urlhaus.abuse.ch/
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=_API_TO,
        )
        if r.status_code == 200:
            data   = r.json()
            status = data.get("query_status", "")
            meta["urlhaus_status"] = status

            if status == "is_online":
                tags     = data.get("tags") or []
                payloads = data.get("payloads") or []
                vulns.append(_vuln(
                    "URLhaus: URL is a known ACTIVE malware distribution site",
                    "critical",
                    f"This URL is listed in URLhaus as an ACTIVE malware host. "
                    f"Tags: {tags}. Payloads: {len(payloads)}.",
                    evidence=f"URLhaus: {url}",
                    check="urlhaus",
                ))
            elif status == "offline":
                vulns.append(_vuln(
                    "URLhaus: URL was previously a malware distribution site (now offline)",
                    "high",
                    "This URL was flagged as a malware host by URLhaus. Currently offline.",
                    check="urlhaus",
                ))
        logger.info("URLhaus | url=%s status=%s", url, meta.get("urlhaus_status"))

    except Exception as exc:
        meta["urlhaus_error"] = str(exc)
        logger.debug("URLhaus error: %s", exc)

    return vulns, meta


def _api_greynoise(ip: str | None) -> tuple[list[dict], dict]:
    """
    GreyNoise Community API — separates internet noise from targeted attacks.
    noise=true → IP is a known scanner/attacker.
    riot=true  → IP is a known benign service (Google, Cloudflare, etc.).
    Free, no key required. https://viz.greynoise.io/
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    if not ip or _is_private(ip):
        return vulns, meta

    try:
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}", timeout=_API_TO)
        if r.status_code == 200:
            data           = r.json()
            noise          = data.get("noise", False)
            riot           = data.get("riot", False)
            classification = data.get("classification", "")
            name           = data.get("name", "")
            meta.update({"greynoise_noise": noise, "greynoise_riot": riot,
                         "greynoise_class": classification, "greynoise_name": name})

            if noise and classification == "malicious":
                vulns.append(_vuln(
                    f"GreyNoise: {ip} is a known MALICIOUS internet scanner",
                    "critical",
                    f"GreyNoise classifies {ip} as malicious ({name}). "
                    "This IP is actively scanning the internet with malicious intent.",
                    evidence=f"GreyNoise: noise=True, classification=malicious",
                    check="greynoise",
                ))
            elif noise:
                vulns.append(_vuln(
                    f"GreyNoise: {ip} is a known internet scanner ({classification})",
                    "medium",
                    f"GreyNoise identifies {ip} as an active scanner ({name}). "
                    "Investigate whether this IP should be serving your web application.",
                    check="greynoise",
                ))
        elif r.status_code == 404:
            meta["greynoise_note"] = "IP not in GreyNoise dataset (not observed scanning)"
        logger.info("GreyNoise | ip=%s noise=%s riot=%s", ip,
                    meta.get("greynoise_noise"), meta.get("greynoise_riot"))

    except Exception as exc:
        meta["greynoise_error"] = str(exc)
        logger.debug("GreyNoise error: %s", exc)

    return vulns, meta


def _api_ipinfo(ip: str | None) -> tuple[list[dict], dict]:
    """
    IPinfo.io — IP context: org, ASN, country, hosting flag.
    Free up to 50 000 req/month, no key required.
    https://ipinfo.io/
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    if not ip or _is_private(ip):
        return vulns, meta

    try:
        # IPINFO_TOKEN = free 50k/month; with paid token: full privacy/hosting data
        # Get token free at https://ipinfo.io/signup  → IPINFO_TOKEN in .env
        _token = os.environ.get("IPINFO_TOKEN", "").strip()
        _headers = {"Authorization": f"Bearer {_token}"} if _token else {}
        r = requests.get(f"https://ipinfo.io/{ip}/json", headers=_headers, timeout=_API_TO)
        if r.status_code == 200:
            data = r.json()
            org     = data.get("org", "")
            country = data.get("country", "")
            asn     = data.get("asn", {}).get("asn", "") if isinstance(data.get("asn"), dict) else ""
            hosting = data.get("hosting", False)
            vpn     = data.get("privacy", {}).get("vpn", False) if isinstance(data.get("privacy"), dict) else False
            tor     = data.get("privacy", {}).get("tor", False) if isinstance(data.get("privacy"), dict) else False
            meta.update({"ipinfo_org": org, "ipinfo_country": country,
                         "ipinfo_asn": asn, "ipinfo_hosting": hosting})

            if tor:
                vulns.append(_vuln(
                    f"IPinfo: {ip} is a TOR exit node",
                    "high",
                    "Server IP is identified as a Tor exit node — investigate.",
                    check="ipinfo",
                ))
            elif vpn:
                vulns.append(_vuln(
                    f"IPinfo: {ip} is a VPN/proxy endpoint",
                    "medium",
                    "Server IP is identified as a VPN or anonymous proxy.",
                    check="ipinfo",
                ))
        logger.info("IPinfo | ip=%s org=%s country=%s", ip,
                    meta.get("ipinfo_org"), meta.get("ipinfo_country"))

    except Exception as exc:
        meta["ipinfo_error"] = str(exc)
        logger.debug("IPinfo error: %s", exc)

    return vulns, meta


def _api_crtsh(host: str) -> tuple[list[dict], dict]:
    """
    crt.sh — Certificate Transparency logs.
    Discovers subdomains registered in public SSL certificates.
    Free, no key required. https://crt.sh/
    """
    vulns: list[dict] = []
    meta:  dict       = {}
    try:
        _crt_sess = _make_session()   # retries help — crt.sh is often slow
        r = _crt_sess.get(
            "https://crt.sh/",
            params={"q": f"%.{host}", "output": "json"},
            timeout=20,
            headers={"Accept": "application/json"},
        )
        if r.status_code != 200:
            return vulns, meta

        seen: set[str] = set()
        for entry in r.json():
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name and host in name and name != host:
                    seen.add(name)

        subs = sorted(seen)
        meta["subdomains"] = subs

        if subs:
            vulns.append(_vuln(
                f"crt.sh: {len(subs)} subdomains discovered for {host}",
                "info",
                f"Certificate Transparency logs reveal {len(subs)} public subdomains. "
                "Each represents potential attack surface to review.",
                evidence=", ".join(subs[:20]) + ("…" if len(subs) > 20 else ""),
                remediation="Audit all subdomains — verify each is intentionally public and secured.",
                check="attack_surface",
            ))
        logger.info("crt.sh | host=%s subdomains=%d", host, len(subs))

    except Exception as exc:
        meta["crtsh_error"] = str(exc)
        logger.debug("crt.sh error: %s", exc)

    return vulns, meta


def _api_dns_security(host: str) -> tuple[list[dict], dict]:
    """
    DNS security checks via Google DNS-over-HTTPS.
    Verifies SPF and DMARC records — no extra packages required.
    """
    vulns: list[dict] = []
    meta:  dict       = {}

    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

    def _doh(name: str, rtype: str) -> list[str]:
        try:
            r = requests.get(
                "https://dns.google/resolve",
                params={"name": name, "type": rtype},
                timeout=8,
            )
            if r.status_code == 200:
                return [a.get("data", "") for a in r.json().get("Answer", [])
                        if a.get("type") == 16]  # TXT = 16
        except Exception:
            pass
        return []

    try:
        # SPF
        txt_records = _doh(domain, "TXT")
        spf_records = [t for t in txt_records if "v=spf1" in t.lower()]
        meta["dns_spf"] = spf_records[0] if spf_records else None

        if not spf_records:
            vulns.append(_vuln(
                f"No SPF record on {domain}",
                "medium",
                "Missing SPF (Sender Policy Framework) record allows email spoofing. "
                "Attackers can send emails pretending to be from your domain.",
                remediation='Add TXT record: "v=spf1 include:your-mail-provider.com ~all"',
                check="dns_security",
            ))
        elif len(spf_records) > 1:
            vulns.append(_vuln(
                f"Multiple SPF records on {domain}",
                "medium",
                "Multiple SPF records is invalid per RFC 7208 — only one is allowed.",
                check="dns_security",
            ))

        # DMARC
        dmarc_records = _doh(f"_dmarc.{domain}", "TXT")
        dmarc = next((r for r in dmarc_records if "v=dmarc1" in r.lower()), None)
        meta["dns_dmarc"] = dmarc

        if not dmarc:
            vulns.append(_vuln(
                f"No DMARC record on {domain}",
                "medium",
                "Missing DMARC record. Without DMARC, email spoofing and phishing "
                "using your domain cannot be detected or blocked.",
                remediation=f'Add TXT record on _dmarc.{domain}: '
                            '"v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"',
                check="dns_security",
            ))
        else:
            # Check DMARC policy strength
            if "p=none" in dmarc.lower():
                vulns.append(_vuln(
                    f"DMARC policy is 'none' (monitoring only) on {domain}",
                    "low",
                    "DMARC p=none only monitors — it does NOT block spoofed emails. "
                    "Upgrade to p=quarantine or p=reject.",
                    check="dns_security",
                ))

        logger.info("DNS security | domain=%s spf=%s dmarc=%s",
                    domain, bool(spf_records), bool(dmarc))

    except Exception as exc:
        meta["dns_error"] = str(exc)
        logger.debug("DNS security error: %s", exc)

    return vulns, meta


# ─────────────────────────────────────────────────────────────────────────────
# Local passive checks  (return list[dict])
# ─────────────────────────────────────────────────────────────────────────────

def _local_headers(headers: dict) -> list[dict]:
    vulns: list[dict] = []
    hl = {k.lower(): v for k, v in headers.items()}

    for name, severity, description in REQUIRED_HEADERS:
        if name.lower() not in hl:
            vulns.append(_vuln(
                f"Missing security header: {name}", severity, description,
                remediation=f"Add to server config: {name}: <value>",
                check="headers",
            ))

    # HSTS quality
    hsts = hl.get("strict-transport-security", "")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 15_552_000:
            vulns.append(_vuln("HSTS max-age too short", "medium",
                               f"max-age={m.group(1)} — should be ≥ 15552000 (6 months).",
                               evidence=f"STS: {hsts}", check="headers"))
        if "includeSubDomains" not in hsts:
            vulns.append(_vuln("HSTS missing includeSubDomains", "low",
                               "Subdomains not covered by HSTS policy.", check="headers"))

    # CSP quality
    csp = hl.get("content-security-policy", "")
    if csp:
        csp_l = csp.lower()
        if "unsafe-inline" in csp_l:
            vulns.append(_vuln("CSP: unsafe-inline allowed", "high",
                               "unsafe-inline defeats XSS protection.",
                               evidence=f"CSP: {csp[:200]}", check="headers"))
        if "unsafe-eval" in csp_l:
            vulns.append(_vuln("CSP: unsafe-eval allowed", "medium",
                               "unsafe-eval permits eval() — widens XSS attack surface.",
                               check="headers"))
        if re.search(r"(script-src|default-src)\s+\*", csp_l):
            vulns.append(_vuln("CSP: wildcard script source", "high",
                               "Wildcard (*) in script-src loads scripts from any origin.",
                               check="headers"))
        if "http:" in csp_l and "https:" not in csp_l:
            vulns.append(_vuln("CSP: allows http: sources on HTTPS page", "medium",
                               "Allowing http: sources downgrades mixed-content protection.",
                               check="headers"))
        if "data:" in csp_l and "script-src" in csp_l:
            vulns.append(_vuln("CSP: data: URI allowed in script-src", "medium",
                               "data: URIs in script-src can be used for XSS payloads.",
                               check="headers"))
        if "upgrade-insecure-requests" not in csp_l:
            vulns.append(_vuln("CSP: missing upgrade-insecure-requests", "low",
                               "Add upgrade-insecure-requests to auto-upgrade mixed content.",
                               check="headers"))

    # X-Frame-Options value
    xfo = hl.get("x-frame-options", "")
    if xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
        vulns.append(_vuln(f"X-Frame-Options insecure value: {xfo}", "medium",
                           "ALLOW-FROM is obsolete — use CSP frame-ancestors instead.",
                           check="headers"))

    return vulns


def _local_server_disclosure(headers: dict) -> list[dict]:
    vulns: list[dict] = []
    server     = headers.get("Server", "")
    x_powered  = headers.get("X-Powered-By", "")

    for value, header_name in ((server, "Server"), (x_powered, "X-Powered-By")):
        if not value:
            continue
        if re.search(r"\d+\.\d+", value):
            vulns.append(_vuln(
                f"{header_name} header reveals version: {value}", "medium",
                f"{header_name} header exposes software version — aids targeted attacks.",
                remediation="Apache: ServerTokens Prod | Nginx: server_tokens off | "
                            "PHP: expose_php = Off",
                check="disclosure",
            ))
        for pattern, cve, desc, sev in VULN_SERVER_RE:
            if re.search(pattern, value, re.IGNORECASE):
                vulns.append(_vuln(
                    f"Vulnerable server detected — {cve}", sev, desc,
                    evidence=f"{header_name}: {value}",
                    cve_ids=[cve], check="server_cve",
                ))

    return vulns


def _local_cookies(resp: requests.Response) -> list[dict]:
    """
    Parse Set-Cookie headers directly from raw response (including redirect history).
    Avoids using private cookiejar internals — safe across requests versions.
    """
    vulns: list[dict] = []
    seen_names: set[str] = set()

    # Collect raw Set-Cookie values from every hop (redirects + final response)
    raw_headers: list[str] = []
    for hist in resp.history:
        raw_headers += hist.raw.headers.getlist("Set-Cookie")
    raw_headers += resp.raw.headers.getlist("Set-Cookie")

    for raw_cookie in raw_headers:
        parts = [p.strip() for p in raw_cookie.split(";")]
        if not parts or not parts[0]:
            continue
        name_val = parts[0]
        name = name_val.split("=", 1)[0].strip()
        if not name or name in seen_names:
            continue
        seen_names.add(name)

        # Build lowercase attribute set  {attr_name: value_or_True}
        attrs: dict[str, str | bool] = {}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            elif part.strip():
                attrs[part.strip().lower()] = True

        is_secure   = "secure"   in attrs
        is_httponly = "httponly" in attrs
        samesite    = attrs.get("samesite")  # str value like "Strict"/"Lax"/"None" or True

        if not is_secure:
            vulns.append(_vuln(f"Cookie missing Secure flag: {name}", "medium",
                               "Cookie transmitted over HTTP — session interception possible.",
                               check="cookies"))
        if not is_httponly:
            vulns.append(_vuln(f"Cookie missing HttpOnly flag: {name}", "medium",
                               "JavaScript can read this cookie — XSS can steal sessions.",
                               check="cookies"))
        if not samesite:
            vulns.append(_vuln(f"Cookie missing SameSite attribute: {name}", "low",
                               "No SameSite attribute — CSRF protection reduced.",
                               check="cookies"))
        elif isinstance(samesite, str) and samesite.lower() == "none" and not is_secure:
            vulns.append(_vuln(f"Cookie SameSite=None without Secure: {name}", "medium",
                               "SameSite=None requires the Secure flag or it will be rejected "
                               "by modern browsers.", check="cookies"))

        # __Secure- prefix violations
        if name.startswith("__Secure-") and not is_secure:
            vulns.append(_vuln(f"__Secure- cookie missing Secure flag: {name}", "high",
                               "__Secure- prefix requires the Secure flag (RFC 8941).",
                               check="cookies"))
        # __Host- prefix violations
        if name.startswith("__Host-"):
            if not is_secure:
                vulns.append(_vuln(f"__Host- cookie missing Secure flag: {name}", "high",
                                   "__Host- requires Secure, no Domain attribute, Path=/.",
                                   check="cookies"))
            elif "domain" in attrs:
                vulns.append(_vuln(f"__Host- cookie has Domain attribute: {name}", "high",
                                   "__Host- must NOT have a Domain attribute.",
                                   check="cookies"))
            elif attrs.get("path") not in ("/", True):
                vulns.append(_vuln(f"__Host- cookie Path is not '/': {name}", "medium",
                                   "__Host- must have Path=/ only.",
                                   check="cookies"))

    return vulns


def _local_cors(url: str, initial_headers: dict) -> list[dict]:
    """
    Check CORS configuration.
    Creates its own session — thread-safe; does NOT share state with other workers.
    """
    vulns: list[dict] = []
    sess = _make_session()
    hl = {k.lower(): v for k, v in initial_headers.items()}

    acao = hl.get("access-control-allow-origin", "")
    acac = hl.get("access-control-allow-credentials", "").lower()

    # Wildcard + credentials (critical)
    if acao == "*" and acac == "true":
        vulns.append(_vuln(
            "CORS: wildcard origin + credentials=true — critical misconfiguration",
            "critical",
            "Access-Control-Allow-Origin: * combined with credentials=true is invalid "
            "per spec but some parsers accept it — credential theft from any origin.",
            cve_ids=["CWE-942"], check="cors",
        ))
    elif acao == "*":
        vulns.append(_vuln(
            "CORS: wildcard origin (any website can cross-origin request this server)",
            "medium",
            "Access-Control-Allow-Origin: * allows any website to read responses.",
            check="cors",
        ))

    # Test arbitrary origin reflection
    try:
        evil_origin = "https://evil-attacker-cybrain.com"
        r = sess.get(url, headers={"Origin": evil_origin},
                     timeout=_PROBE_TO, verify=False, allow_redirects=False)
        r_acao = r.headers.get("Access-Control-Allow-Origin", "")
        r_acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if r_acao == evil_origin:
            sev = "critical" if r_acac == "true" else "high"
            vulns.append(_vuln(
                "CORS: arbitrary origin reflected" + (" + credentials" if r_acac == "true" else ""),
                sev,
                "Server reflects arbitrary Origin header back in ACAO. "
                + ("With credentials=true, attacker can steal authenticated session data." if r_acac == "true"
                   else "Attacker can cross-origin read server responses."),
                evidence=f"Sent Origin: {evil_origin} → ACAO: {r_acao}",
                check="cors",
            ))
    except Exception:
        pass

    # Test null origin bypass
    try:
        r2 = sess.get(url, headers={"Origin": "null"},
                      timeout=_PROBE_TO, verify=False, allow_redirects=False)
        if r2.headers.get("Access-Control-Allow-Origin", "").lower() == "null":
            vulns.append(_vuln(
                "CORS: null origin accepted — sandbox bypass possible",
                "high",
                "Server accepts Origin: null, which can be set by sandboxed iframes "
                "and data: URIs — allows cross-origin attacks from attacker-controlled pages.",
                check="cors",
            ))
    except Exception:
        pass

    return vulns


def _local_sensitive_paths(url: str) -> list[dict]:
    """
    Probe sensitive paths with smart soft-404 fingerprinting.
    Gets a 404 baseline first to avoid false positives.
    Each call creates its own session — thread-safe.
    """
    vulns: list[dict] = []
    sess  = _make_session()
    base  = url.rstrip("/")
    fp    = _404_fingerprint(base, sess)

    for path, severity, description in SENSITIVE_PATHS:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                r = sess.get(f"{base}{path}", timeout=_PROBE_TO,
                             allow_redirects=False, verify=False)

            if r.status_code != 200:
                continue
            if not r.content:
                continue
            if _is_soft_404(r.content, fp):
                continue

            vulns.append(_vuln(
                f"Sensitive path exposed: {path}", severity, description,
                evidence=f"HTTP 200 — {base}{path} ({len(r.content)} bytes)",
                remediation="Block access: deny from all / Require all denied",
                check="sensitive_paths",
            ))
        except requests.RequestException:
            pass

    return vulns


def _local_http_methods(url: str) -> list[dict]:
    vulns: list[dict] = []
    try:
        sess = _make_session()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            r = sess.options(url, timeout=_PROBE_TO, allow_redirects=False, verify=False)
        allow = r.headers.get("Allow", "")
        if allow:
            for method, severity, description in DANGEROUS_METHODS:
                if method in allow.upper():
                    vulns.append(_vuln(
                        f"Dangerous HTTP method: {method}", severity, description,
                        evidence=f"OPTIONS Allow: {allow}",
                        remediation="<LimitExcept GET POST HEAD>\\n  Require all denied\\n</LimitExcept>",
                        check="http_methods",
                    ))
    except Exception:
        pass
    return vulns


def _local_response_body(resp: requests.Response) -> list[dict]:
    vulns: list[dict] = []
    try:
        # Skip very large bodies to prevent MemoryError (e.g. binary downloads)
        cl = int(resp.headers.get("Content-Length", 0) or 0)
        if cl > 10_000_000:
            return vulns
        body = resp.text[:60_000]
    except Exception:
        return vulns
    for pattern, severity, description in ERROR_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
            vulns.append(_vuln(
                f"Information disclosure: {description.split(' — ')[0]}", severity, description,
                evidence=f"Pattern matched in HTTP response body",
                remediation="Disable debug mode. Use custom error pages. Never expose internal errors.",
                check="disclosure",
            ))
    return vulns


def _local_https_redirect(url: str, host: str) -> list[dict]:
    """Own session — thread-safe, no shared state with other workers."""
    vulns: list[dict] = []
    if not url.startswith("https://"):
        return vulns
    try:
        sess = _make_session()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            r = sess.get(f"http://{host}", timeout=_PROBE_TO,
                         allow_redirects=True, verify=False)
        if not r.url.startswith("https://"):
            vulns.append(_vuln(
                "HTTP not redirected to HTTPS",
                "high",
                "Plain HTTP is accessible without redirect to HTTPS — data sent unencrypted.",
                evidence=f"http://{host} → {r.url}",
                remediation="Redirect: RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]",
                check="https_redirect",
            ))
    except Exception:
        pass
    return vulns


def _local_ssl_direct(host: str) -> list[dict]:
    """Direct TLS check: deprecated protocol negotiation, cert expiry."""
    vulns: list[dict] = []
    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((host, 443), timeout=6),
            server_hostname=host,
        )
        cert        = conn.getpeercert()
        tls_version = conn.version()
        conn.close()

        if tls_version in ("TLSv1", "TLSv1.1"):
            vulns.append(_vuln(f"Deprecated TLS version: {tls_version}", "high",
                               f"Python negotiated {tls_version} — server still supports deprecated protocol.",
                               check="ssl"))

        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                exp  = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    vulns.append(_vuln("SSL Certificate EXPIRED", "critical",
                                       f"Expired {-days} days ago.", check="ssl"))
                elif days < 7:
                    vulns.append(_vuln(f"SSL Certificate expires in {days} days", "critical",
                                       "Immediate renewal required.", check="ssl"))
                elif days < 30:
                    sev = "high" if days < 14 else "medium"
                    vulns.append(_vuln(f"SSL Certificate expires in {days} days", sev,
                                       f"Renew before {exp.strftime('%Y-%m-%d')}.", check="ssl"))
            except ValueError:
                pass

    except ssl.SSLError as exc:
        vulns.append(_vuln("SSL/TLS error", "critical", str(exc), check="ssl"))
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return vulns


def _local_waf(headers: dict) -> list[dict]:
    """Detect WAF / CDN presence from response headers."""
    vulns: list[dict] = []
    hl = {k.lower(): v.lower() for k, v in headers.items()}
    detected: list[str] = []

    for name, checks in _WAF_SIGS.items():
        for header_key, header_val in checks:
            if header_key in hl:
                if header_val is None or header_val.lower() in hl[header_key]:
                    detected.append(name)
                    break

    if detected:
        vulns.append(_vuln(
            f"WAF/CDN detected: {', '.join(detected)}",
            "info",
            f"The following WAF/CDN layers were identified: {', '.join(detected)}. "
            "This is informational — verify security policies are correctly configured.",
            check="waf_detection",
        ))
    return vulns


def _local_tech(resp: requests.Response) -> list[dict]:
    """Fingerprint technology stack from headers, cookies, response body."""
    vulns: list[dict] = []
    hl     = {k.lower(): v for k, v in resp.headers.items()}
    cookies_str = " ".join(c.name for c in resp.cookies)
    try:
        body = resp.text[:40_000]
    except Exception:
        body = ""

    detected: list[str] = []
    for tech, sigs in _TECH_SIGS.items():
        for sig_type, pattern in sigs:
            try:
                if sig_type == "header":
                    target = " ".join(f"{k}: {v}" for k, v in hl.items())
                elif sig_type == "cookie":
                    target = cookies_str
                else:
                    target = body
                if re.search(pattern, target, re.IGNORECASE):
                    detected.append(tech)
                    break
            except Exception:
                pass

    if detected:
        vulns.append(_vuln(
            f"Technology stack identified: {', '.join(detected)}",
            "info",
            f"Detected: {', '.join(detected)}. Ensure all components are up-to-date "
            "and hardened for production use.",
            check="tech_detection",
        ))
    return vulns


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def run_web_scan(
    target: str,
    cve_check: bool = True,
    ssl_check: bool = True,
) -> dict:
    """
    Full passive web security scan — local checks + 11 external APIs in parallel.

    Args:
        target:    URL, domain, or IP. http/https added automatically if missing.
        cve_check: If False, skip Shodan/VirusTotal/AbuseIPDB/GreyNoise reputation APIs.
        ssl_check: If False, skip SSL Labs and direct SSL probe (faster for HTTP-only targets).

    Returns:
        { "scan_type": "web", "vulnerabilities": [...], "meta": {...} }
    """
    url    = _norm_url(target)
    parsed = urlparse(url)
    host   = parsed.hostname or target
    sess   = _make_session()
    vulns: list[dict] = []
    meta:  dict       = {}

    logger.info("web_scan start | url=%s", url)

    # ── Step 1: Initial HTTP fetch ────────────────────────────────────────────
    resp = None
    try:
        resp = sess.get(url, timeout=14, verify=True, allow_redirects=True)
    except requests.exceptions.SSLError as exc:
        vulns.append(_vuln("SSL/TLS error on initial request", "critical",
                           str(exc), check="ssl"))
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                resp = sess.get(url, timeout=14, verify=False, allow_redirects=True)
        except requests.RequestException as exc2:
            raise RuntimeError(f"Cannot reach target: {exc2}") from exc2
    except requests.RequestException as exc:
        raise RuntimeError(f"Cannot reach target: {exc}") from exc

    # ── Step 2: Resolve IP ────────────────────────────────────────────────────
    ip = _resolve_ip(host)
    meta["resolved_ip"] = ip

    # ── Step 3: Instant local checks (no network, sequential) ─────────────────
    vulns += _local_headers(resp.headers)
    vulns += _local_server_disclosure(resp.headers)
    vulns += _local_cookies(resp)
    vulns += _local_response_body(resp)
    vulns += _local_waf(resp.headers)
    vulns += _local_tech(resp)

    # ── Step 4: All external API calls + network probes in parallel ───────────
    tasks: list[tuple] = [
        ("ssllabs",    _api_ssllabs,          (host,),            True,  ssl_check and parsed.scheme == "https"),
        ("observatory",_api_observatory,       (host,),            True,  True),
        ("shodan",     _api_shodan,            (ip,),              True,  cve_check),
        ("virustotal", _api_virustotal,        (url, ip),          True,  cve_check),
        ("abuseipdb",  _api_abuseipdb,         (ip,),              True,  cve_check),
        ("gsb",        _api_google_safebrowsing,(url,),            True,  True),
        ("urlscan",    _api_urlscan,           (url, host),        True,  cve_check),
        ("urlhaus",    _api_urlhaus,           (url,),             True,  cve_check),
        ("greynoise",  _api_greynoise,         (ip,),              True,  cve_check),
        ("ipinfo",     _api_ipinfo,            (ip,),              True,  True),
        ("crtsh",      _api_crtsh,             (host,),            True,  True),
        ("dns",        _api_dns_security,      (host,),            True,  True),
        ("methods",    _local_http_methods,    (url,),              False, True),
        ("paths",      _local_sensitive_paths, (url,),              False, True),
        ("redirect",   _local_https_redirect,  (url, host),         False, True),
        ("ssl_direct", _local_ssl_direct,      (host,),             False, ssl_check and parsed.scheme == "https"),
        ("cors",       _local_cors,            (url, dict(resp.headers)), False, True),
    ]

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="webscan") as pool:
        futures: dict = {}
        for name, fn, args, is_api, enabled in tasks:
            if not enabled:
                continue
            futures[pool.submit(fn, *args)] = (name, is_api)

        for fut in as_completed(futures):
            name, is_api = futures[fut]
            try:
                result = fut.result()
                if is_api:
                    task_vulns, task_meta = result
                    vulns.extend(task_vulns)
                    meta.update(task_meta)
                else:
                    vulns.extend(result)
            except Exception as exc:
                logger.warning("webscan task '%s' raised: %s", name, exc)

    # ── Step 5: Deduplicate + sort ────────────────────────────────────────────
    seen:   set[str]   = set()
    unique: list[dict] = []
    for v in vulns:
        k = _dedup_key(v)
        if k not in seen:
            seen.add(k)
            unique.append(v)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    unique.sort(key=lambda v: order.get(v.get("severity", "info"), 5))

    subdomains = meta.get("subdomains", [])
    apis_used  = [
        "SSL Labs", "Mozilla Observatory", "Shodan InternetDB",
        "VirusTotal", "AbuseIPDB", "URLhaus", "GreyNoise", "IPinfo",
        "URLScan.io", "crt.sh", "DNS-over-HTTPS",
    ]
    if os.environ.get("GOOGLE_SAFE_BROWSING_KEY"):
        apis_used.append("Google Safe Browsing")

    logger.info(
        "web_scan done | host=%s findings=%d ssl=%s obs=%s",
        host, len(unique),
        meta.get("ssllabs_grade", "N/A"),
        meta.get("observatory_grade", "N/A"),
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
            "ssl_grade":          meta.get("ssllabs_grade"),
            "observatory_grade":  meta.get("observatory_grade"),
            "observatory_score":  meta.get("observatory_score"),
            "shodan_ports":       meta.get("shodan_ports"),
            "shodan_cves":        meta.get("shodan_cves"),
            "vt_malicious":       meta.get("vt_malicious"),
            "abuseipdb_score":    meta.get("abuseipdb_score"),
            "greynoise_noise":    meta.get("greynoise_noise"),
            "greynoise_class":    meta.get("greynoise_class"),
            "ipinfo_org":         meta.get("ipinfo_org"),
            "ipinfo_country":     meta.get("ipinfo_country"),
            "urlhaus_status":     meta.get("urlhaus_status"),
            "gsb_threats":        meta.get("gsb_threats", 0),
            "dns_spf":            meta.get("dns_spf"),
            "dns_dmarc":          meta.get("dns_dmarc"),
            "subdomains":         subdomains,
            "subdomains_count":   len(subdomains),
            "apis_used":          apis_used,
        },
    }
