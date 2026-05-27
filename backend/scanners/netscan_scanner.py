# scanners/netscan_scanner.py
"""
Network Scanner  v3 — Nmap + Multi-Source IP Intelligence
══════════════════════════════════════════════════════════════════════════
All post-scan enrichment calls run in parallel (ThreadPoolExecutor).
crt.sh runs concurrently with Nmap so its result is ready when Nmap finishes.

┌──────────────────────┬────────────┬────────────────────────────────────────────────────────┐
│ API / Tool           │ Key needed │ How to get it                                          │
├──────────────────────┼────────────┼────────────────────────────────────────────────────────┤
│ Nmap                 │ No         │ https://nmap.org/download.html  /  apt install nmap    │
│ Shodan InternetDB    │ No         │ https://internetdb.shodan.io  (auto)                   │
│ GreyNoise Community  │ No         │ https://viz.greynoise.io  (auto)                       │
│ crt.sh CT logs       │ No         │ https://crt.sh  (auto)                                 │
│ NVD API v2           │ Optional   │ https://nvd.nist.gov/developers/request-an-api-key     │
│                      │            │ Raises rate limit 5→50 req/30s → NVD_API_KEY in .env  │
│ AbuseIPDB v2         │ Yes (free) │ https://abuseipdb.com → Account → API → ABUSEIPDB_KEY │
└──────────────────────┴────────────┴────────────────────────────────────────────────────────┘

Why these tools?
  Nmap    — the industry standard for network discovery/enumeration (SANS, OWASP)
  Shodan  — shows what the internet sees about each IP (CVEs, open ports, tags)
  GreyNoise — distinguishes background internet noise from targeted attacks
  NVD     — NIST official CVE database with CVSS scores and version ranges
  AbuseIPDB — community-sourced IP abuse score (phishing, DDoS, scanning)
  crt.sh  — Certificate Transparency: discovers subdomains via SSL cert history
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ── Retry-enabled session ─────────────────────────────────────────────────────

def _make_session() -> requests.Session:
    sess    = requests.Session()
    adapter = HTTPAdapter(max_retries=Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    ))
    sess.mount("https://", adapter)
    sess.mount("http://",  adapter)
    sess.headers["User-Agent"] = "CyBrain-NetScanner/3.0"
    return sess


# ── Port risk classification ──────────────────────────────────────────────────

_CRITICAL_PORTS = {
    4444,   # Metasploit default listener
    5554,   # Sasser worm
    9001,   # Tor relay
    31337,  # Back Orifice
}
_HIGH_PORTS = {
    21,    # FTP — plaintext credentials
    22,    # SSH — brute-force target
    23,    # Telnet — plaintext, fully deprecated
    25,    # SMTP — relay abuse
    53,    # DNS — amplification / zone transfer
    135, 137, 138, 139, 445,  # NetBIOS/SMB — EternalBlue territory
    512, 513, 514,  # rsh/rlogin/syslog — unauthenticated legacy
    1433,  # MSSQL
    1521,  # Oracle DB
    2049,  # NFS
    3306,  # MySQL exposed
    3389,  # RDP — BlueKeep territory
    5432,  # PostgreSQL exposed
    5900,  # VNC — often no auth
    6379,  # Redis — unauthenticated by default
    8080,  # HTTP alt — often dev server
    8443,  # HTTPS alt
    9200, 9300,   # Elasticsearch — no auth by default
    27017, 27018, # MongoDB — no auth by default
    28017,        # MongoDB HTTP admin
    11211,        # Memcached — DDoS amplification
    2181,         # ZooKeeper
    7001,         # WebLogic — frequent RCE target
    8161,         # ActiveMQ web console
    50070,        # Hadoop NameNode
}
_MEDIUM_PORTS = {80, 443, 8888, 8000, 8001}

# ── NSE scripts by service group ──────────────────────────────────────────────

_NSE_BY_SERVICE: dict[str, list[str]] = {
    "smb": [
        "smb-vuln-ms17-010",        # EternalBlue / WannaCry
        "smb-vuln-ms08-067",        # Conficker MS08-067
        "smb-vuln-cve2009-3103",
        "smb-vuln-ms10-054",
        "smb-vuln-ms10-061",
        "smb-security-mode",        # SMB signing disabled?
        "smb2-security-mode",
        "smb-enum-shares",
    ],
    "ssl": [
        "ssl-heartbleed",           # Heartbleed CVE-2014-0160
        "ssl-poodle",               # POODLE SSLv3
        "ssl-dh-params",            # Logjam / FREAK
        "ssl-ccs-injection",        # OpenSSL CCS CVE-2014-0224
        "tls-ticketbleed",          # F5 Ticketbleed CVE-2016-9244
        "ssl-enum-ciphers",
        "ssl-cert",
    ],
    "ftp": [
        "ftp-anon",
        "ftp-proftpd-backdoor",
        "ftp-vsftpd-backdoor",
        "ftp-bounce",
    ],
    "ssh": [
        "ssh-auth-methods",
        "ssh2-enum-algos",
        "ssh-hostkey",
    ],
    "http": [
        "http-shellshock",
        "http-slowloris-check",
        "http-vuln-cve2017-5638",   # Apache Struts (Equifax breach)
        "http-vuln-cve2017-1001000",
        "http-vuln-cve2015-1427",   # Elasticsearch Groovy RCE
        "http-default-accounts",
        "http-methods",
        "http-auth-finder",
        "http-robots.txt",
    ],
    "rdp": [
        "rdp-vuln-ms12-020",
        "rdp-enum-encryption",
    ],
    "database": [
        "mysql-empty-password",
        "mysql-vuln-cve2012-2122",
        "ms-sql-empty-password",
        "ms-sql-info",
        "mongodb-brute",
        "redis-info",
        "memcached-info",
        "pgsql-brute",
    ],
    "misc": ["vuln", "auth"],
}

_PORT_TO_GROUP: dict[int, str] = {
    **{p: "smb"      for p in (139, 445)},
    **{p: "ssl"      for p in (443, 8443, 465, 993, 995)},
    **{p: "ftp"      for p in (21,)},
    **{p: "ssh"      for p in (22,)},
    **{p: "http"     for p in (80, 8080, 8000, 8001, 8888)},
    **{p: "rdp"      for p in (3389,)},
    **{p: "database" for p in (3306, 1433, 5432, 27017, 6379, 11211, 9200)},
}

_SERVICE_NVD_KEYWORDS: dict[str, str] = {
    "openssh":       "openssh",
    "ssh":           "openssh",
    "apache":        "apache http server",
    "nginx":         "nginx",
    "iis":           "microsoft iis",
    "ftp":           "vsftpd",
    "vsftpd":        "vsftpd",
    "proftpd":       "proftpd",
    "mysql":         "mysql",
    "mariadb":       "mariadb",
    "postgresql":    "postgresql",
    "mssql":         "sql server",
    "smb":           "windows smb",
    "samba":         "samba",
    "vnc":           "realvnc",
    "rdp":           "remote desktop",
    "redis":         "redis",
    "mongodb":       "mongodb",
    "elasticsearch": "elasticsearch",
    "tomcat":        "apache tomcat",
    "weblogic":      "weblogic",
}


# ── Severity helpers ──────────────────────────────────────────────────────────

def _assess_severity(port: int, service: str) -> str:
    if port in _CRITICAL_PORTS:
        return "critical"
    if port in _HIGH_PORTS or service in ("telnet", "ftp", "netbios-ssn", "msrpc", "ms-wbt-server"):
        return "high"
    if port in _MEDIUM_PORTS:
        return "medium"
    return "low"


def _is_public_ip(host: str) -> bool:
    """Return True if host is a public (routable) IP address."""
    try:
        addr = ipaddress.ip_address(host)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except ValueError:
        return False   # hostname — treat as public


# ── External API functions (all use retry session) ────────────────────────────

def _shodan_internetdb(ip: str) -> dict:
    """
    Shodan InternetDB — known CVEs, open ports, tags per IP.
    Free, no API key required. https://internetdb.shodan.io/
    """
    try:
        r = _make_session().get(f"https://internetdb.shodan.io/{ip}", timeout=8)
        if r.status_code == 200:
            return r.json()
    except Exception as exc:
        logger.debug("Shodan InternetDB error for %s: %s", ip, exc)
    return {}


def _greynoise_ip(ip: str) -> dict:
    """
    GreyNoise Community API — separates internet background noise from targeted attacks.
    noise=True  → IP is an active internet scanner.
    riot=True   → IP is a known benign service (Google, Cloudflare …).
    Free, no key required. https://viz.greynoise.io/
    """
    try:
        r = _make_session().get(
            f"https://api.greynoise.io/v3/community/{ip}",
            timeout=8,
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 429:
            logger.debug("GreyNoise rate-limited for %s", ip)
    except Exception as exc:
        logger.debug("GreyNoise error for %s: %s", ip, exc)
    return {}


def _abuseipdb_ip(ip: str) -> dict:
    """
    AbuseIPDB v2 — IP abuse confidence score.
    Used by SOC teams globally to identify compromised / attacker IPs.
    Free key (1000 req/day): https://abuseipdb.com → Account → API → ABUSEIPDB_KEY
    """
    key = os.environ.get("ABUSEIPDB_KEY", "").strip()
    if not key:
        return {}
    try:
        r = _make_session().get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=8,
        )
        if r.status_code == 200:
            return r.json().get("data", {})
    except Exception as exc:
        logger.debug("AbuseIPDB error for %s: %s", ip, exc)
    return {}


def _crtsh_subdomains(hostname: str) -> list[str]:
    """
    crt.sh — Certificate Transparency log search.
    Discovers subdomains registered in public SSL certificates.
    Free, no key. https://crt.sh/
    """
    try:
        r = _make_session().get(
            "https://crt.sh/",
            params={"q": f"%.{hostname}", "output": "json"},
            timeout=20,  # crt.sh is slow under load
            headers={"Accept": "application/json"},
        )
        if r.status_code != 200:
            return []
        seen: set[str] = set()
        for entry in r.json():
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name and hostname in name:
                    seen.add(name)
        return sorted(seen)
    except Exception as exc:
        logger.debug("crt.sh error for %s: %s", hostname, exc)
        return []


def _nvd_cve_lookup(service: str, version: str) -> list[dict]:
    """
    NVD API v2 — NIST CVE database with CVSS scores.
    Returns up to 3 high-severity CVEs for the given service version.
    Optional key: NVD_API_KEY (raises rate limit 5→50 req/30s).
    Key obtained free at https://nvd.nist.gov/developers/request-an-api-key
    """
    keyword = _SERVICE_NVD_KEYWORDS.get(service.lower(), service.lower())
    if not keyword or not version:
        return []

    # Read key at call time (not module import) so it's always fresh
    nvd_key = os.environ.get("NVD_API_KEY", "").strip()
    headers = {"apiKey": nvd_key} if nvd_key else {}

    try:
        r = _make_session().get(
            _NVD_BASE,
            params={"keywordSearch": keyword, "resultsPerPage": 5},
            headers=headers,
            timeout=10,
        )
        if r.status_code != 200:
            return []
        if "json" not in r.headers.get("Content-Type", ""):
            return []

        cves: list[dict] = []
        for item in r.json().get("vulnerabilities", []):
            cve  = item.get("cve", {})
            cid  = cve.get("id", "")
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )
            metrics   = cve.get("metrics", {})
            cvss_data = (
                (metrics.get("cvssMetricV31") or [{}])[0].get("cvssData", {}) or
                (metrics.get("cvssMetricV30") or [{}])[0].get("cvssData", {}) or
                (metrics.get("cvssMetricV2")  or [{}])[0].get("cvssData", {})
            )
            score = cvss_data.get("baseScore", 0)
            if score and float(score) >= 7.0:
                cves.append({
                    "id":          cid,
                    "score":       float(score),
                    "description": desc[:250],
                })
        cves.sort(key=lambda x: x["score"], reverse=True)
        return cves[:3]

    except Exception as exc:
        logger.debug("NVD lookup error for %s: %s", service, exc)
        return []


# ── NSE output parser ─────────────────────────────────────────────────────────

def _parse_nse_vulns(script_output: dict) -> list[dict]:
    """Extract confirmed vulnerabilities from Nmap NSE script output."""
    findings: list[dict] = []
    for script_id, output in script_output.items():
        if not output or "ERROR" in output:
            continue

        if any(kw in script_id for kw in ("heartbleed", "ms17-010", "ms08-067", "shellshock")):
            sev = "critical"
        elif any(kw in script_id for kw in ("poodle", "dh-params", "proftpd-backdoor", "vsftpd-backdoor")):
            sev = "high"
        elif any(kw in script_id for kw in ("ftp-anon", "mysql-empty", "ms-sql-empty")):
            sev = "high"
        else:
            sev = "medium"

        cve_ids = re.findall(r"CVE-\d{4}-\d+", output)

        is_vuln = any(kw in output.upper() for kw in
                      ["VULNERABLE", "LIKELY VULNERABLE", "CHECK FAILED"])
        if not is_vuln and script_id == "ftp-anon" and "Anonymous FTP login allowed" in output:
            is_vuln = True
        if not is_vuln and "auth-methods" in script_id:
            is_vuln = "password" in output.lower()
        if not is_vuln and script_id in ("mysql-empty-password", "ms-sql-empty-password"):
            is_vuln = "success" in output.lower() or "login" in output.lower()

        if is_vuln:
            findings.append({
                "script":   script_id,
                "output":   output[:500],
                "severity": sev,
                "cve_ids":  cve_ids,
            })
    return findings


# ── Graceful unavailable result ───────────────────────────────────────────────

def _nmap_unavailable_result(target: str, internal: bool, reason: str) -> dict:
    """Return a well-formed scan result when nmap is not available on this host."""
    return {
        "scan_type":       "network_int" if internal else "network_ext",
        "target":          target,
        "vulnerabilities": [
            {
                "check":       "nmap_unavailable",
                "title":       "Network Scan Unavailable",
                "severity":    "info",
                "description": (
                    f"The nmap network scanner is not installed in this deployment environment. "
                    f"Network scanning requires nmap to be configured on the server. "
                    f"Detail: {reason}"
                ),
                "remediation": (
                    "To enable network scanning, install nmap on the server: "
                    "apt install nmap (Debian/Ubuntu) | brew install nmap (macOS) | "
                    "choco install nmap (Windows). "
                    "On Render, add a build command: apt-get install -y nmap"
                ),
            }
        ],
        "hosts":      [],
        "subdomains": [],
        "meta": {
            "scan_time":   datetime.now(timezone.utc).isoformat(),
            "nmap_args":   "N/A — nmap not installed",
            "deep":        False,
            "internal":    internal,
            "hosts_up":    "0",
            "total_hosts": "0",
            "tools_used":  [],
            "nmap_unavailable": True,
        },
    }


# ── Main entry point ──────────────────────────────────────────────────────────

def run_nmap_scan(target: str, deep: bool = False, internal: bool = False) -> dict:
    """
    Network scan with Nmap + parallel IP intelligence enrichment.

    Phase flow:
      1. Start crt.sh lookup in background thread (if hostname target)
      2. Run Nmap (blocking — can take 1-10 min for deep scans)
         Phase 2a (deep): service/version discovery
         Phase 2b (deep): targeted NSE scripts based on discovered services
      3. After Nmap: fire Shodan + GreyNoise + AbuseIPDB + NVD in parallel
      4. Assemble final report

    Args:
        target:   IP, CIDR, or hostname
        deep:     OS detection + NSE vuln scripts (requires root/admin, slower)
        internal: LAN profile (lower timing, skip internet API enrichment)
    """
    try:
        import nmap  # type: ignore
    except ImportError:
        logger.warning("python-nmap not installed — returning graceful result")
        return _nmap_unavailable_result(target, internal, "python-nmap package not installed.")

    if not shutil.which("nmap"):
        logger.warning("nmap binary not in PATH — returning graceful result")
        return _nmap_unavailable_result(
            target, internal,
            "nmap binary not found. Install via: apt install nmap / brew install nmap / choco install nmap"
        )

    nm = nmap.PortScanner()

    # ── Step 1: start crt.sh in a background thread NOW ──────────────────────
    # crt.sh can take 10-20 seconds — overlap it with the Nmap scan.
    subdomains: list[str] = []
    crt_thread = None
    is_hostname = not re.match(r"[\d./]+$", target.strip())
    if not internal and is_hostname:
        def _crt_worker() -> None:
            subdomains.extend(_crtsh_subdomains(target.strip()))
        crt_thread = threading.Thread(target=_crt_worker, daemon=True, name="crt-lookup")
        crt_thread.start()

    # ── Step 2: Run Nmap ──────────────────────────────────────────────────────
    arguments = ""
    if deep:
        disc_args = "-sV -O --open -T4 -p 1-65535"
        logger.info("nmap phase-1 (discovery) | target=%s", target)
        try:
            nm.scan(hosts=target, arguments=disc_args)
        except nmap.PortScannerError as exc:
            raise RuntimeError(f"Nmap scan failed: {exc}") from exc

        # Build targeted NSE script list from discovered open ports
        open_groups: set[str] = set()
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    if nm[host][proto][port].get("state") == "open":
                        grp = _PORT_TO_GROUP.get(port)
                        if grp:
                            open_groups.add(grp)
        open_groups.add("misc")

        targeted_scripts: list[str] = []
        seen_scripts: set[str] = set()
        for grp in sorted(open_groups):
            for s in _NSE_BY_SERVICE.get(grp, []):
                if s not in seen_scripts:
                    targeted_scripts.append(s)
                    seen_scripts.add(s)

        if targeted_scripts:
            nse        = ",".join(targeted_scripts)
            script_args = f"--script={nse} -sV --open -T4"
            logger.info("nmap phase-2 (NSE: %d scripts | groups=%s) | target=%s",
                        len(targeted_scripts), sorted(open_groups), target)
            try:
                nm.scan(hosts=target, arguments=script_args)
            except nmap.PortScannerError as exc:
                logger.warning("nmap NSE phase failed: %s — using phase-1 results", exc)
            arguments = f"{disc_args} + NSE({nse[:80]})"
        else:
            arguments = disc_args + " (no open ports for NSE)"

    elif internal:
        arguments = "-sV --open -T3 --top-ports 2000"
        logger.info("nmap (internal) | target=%s", target)
        try:
            nm.scan(hosts=target, arguments=arguments)
        except nmap.PortScannerError as exc:
            raise RuntimeError(f"Nmap scan failed: {exc}") from exc
    else:
        arguments = "-sV --open -T4 --top-ports 1000"
        logger.info("nmap | target=%s", target)
        try:
            nm.scan(hosts=target, arguments=arguments)
        except nmap.PortScannerError as exc:
            raise RuntimeError(f"Nmap scan failed: {exc}") from exc

    # ── Step 3: Collect public IPs + unique service signatures for enrichment ─
    public_ips: list[str] = []
    # (service_keyword, version) — deduplicated to avoid NVD rate-limit waste
    svc_seen: set[str]                  = set()
    nvd_checks: list[tuple[str, str]]   = []
    # Map: (host, port) → (service, product, version) for later vuln injection
    port_svc_map: dict[tuple[str, int], tuple[str, str, str]] = {}

    for host in nm.all_hosts():
        # Use ipaddress — works for both IPv4 and IPv6
        try:
            if _is_public_ip(host):
                public_ips.append(host)
        except Exception:
            pass  # hostname — skip for IP-based APIs

        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                pi    = nm[host][proto][port]
                if pi.get("state") != "open":
                    continue
                svc   = pi.get("name",    "unknown")
                prod  = pi.get("product", "")
                ver   = pi.get("version", "")
                port_svc_map[(host, port)] = (svc, prod, ver)

                # Deduplicate NVD queries by (keyword, version_fingerprint)
                kw      = _SERVICE_NVD_KEYWORDS.get(svc.lower(), "")
                ver_fp  = (ver or prod)[:40]
                svc_key = f"{kw}:{ver_fp}"
                if kw and ver_fp and svc_key not in svc_seen:
                    svc_seen.add(svc_key)
                    nvd_checks.append((svc, ver or prod))

    # ── Step 4: Fire all enrichment in parallel ───────────────────────────────
    shodan_results:   dict[str, dict] = {}
    greynoise_results: dict[str, dict] = {}
    abuse_results:    dict[str, dict] = {}
    nvd_results:      dict[tuple[str, str], list[dict]] = {}

    if not internal:
        n_workers = max(1, len(public_ips) * 3 + len(nvd_checks) + 1)
        with ThreadPoolExecutor(
            max_workers=min(n_workers, 16),
            thread_name_prefix="netscan",
        ) as pool:
            sh_futs   = {pool.submit(_shodan_internetdb, ip):  ip  for ip in public_ips}
            gn_futs   = {pool.submit(_greynoise_ip, ip):       ip  for ip in public_ips}
            ab_futs   = {pool.submit(_abuseipdb_ip, ip):       ip  for ip in public_ips}
            nvd_futs  = {
                pool.submit(_nvd_cve_lookup, svc, ver): (svc, ver)
                for svc, ver in nvd_checks
            }

            for fut in as_completed(sh_futs):
                try: shodan_results[sh_futs[fut]] = fut.result()
                except Exception: shodan_results[sh_futs[fut]] = {}

            for fut in as_completed(gn_futs):
                try: greynoise_results[gn_futs[fut]] = fut.result()
                except Exception: greynoise_results[gn_futs[fut]] = {}

            for fut in as_completed(ab_futs):
                try: abuse_results[ab_futs[fut]] = fut.result()
                except Exception: abuse_results[ab_futs[fut]] = {}

            for fut in as_completed(nvd_futs):
                key = nvd_futs[fut]
                try: nvd_results[key] = fut.result()
                except Exception: nvd_results[key] = []

    # Wait for crt.sh background thread
    if crt_thread:
        crt_thread.join(timeout=25)

    # ── Step 5: Build vulnerability findings ──────────────────────────────────
    vulns:     list[dict] = []
    host_info: list[dict] = []

    for host in nm.all_hosts():
        host_state = nm[host].state()
        osmatch    = nm[host].get("osmatch", [{}])
        os_guess   = osmatch[0].get("name", "")   if osmatch else ""
        os_acc     = osmatch[0].get("accuracy", "") if osmatch else ""

        shodan_data  = shodan_results.get(host, {})
        gn_data      = greynoise_results.get(host, {})
        abuse_data   = abuse_results.get(host, {})
        shodan_cves  = shodan_data.get("vulns",  [])
        shodan_ports = shodan_data.get("ports",  [])
        shodan_tags  = shodan_data.get("tags",   [])

        host_entry = {
            "host":          host,
            "state":         host_state,
            "os":            os_guess,
            "os_accuracy":   os_acc,
            "shodan_cves":   shodan_cves,
            "shodan_ports":  shodan_ports,
            "shodan_tags":   shodan_tags,
            "greynoise":     gn_data,
            "abuseipdb_score": abuse_data.get("abuseConfidenceScore"),
        }
        host_info.append(host_entry)

        # ── Shodan CVE findings ───────────────────────────────────────────────
        for cve_id in shodan_cves[:10]:
            vulns.append({
                "check":       "shodan_cve",
                "title":       f"Shodan: known CVE on {host} — {cve_id}",
                "severity":    "high",
                "description": f"Shodan has indexed {cve_id} as affecting {host}.",
                "evidence":    f"Shodan InternetDB: {host}",
                "remediation": f"Patch: https://nvd.nist.gov/vuln/detail/{cve_id}",
                "cve_ids":     [cve_id],
                "host":        host,
            })

        # ── Shodan tag findings ───────────────────────────────────────────────
        _tag_map = {
            "self-signed": ("Self-signed SSL certificate on {h}", "medium",
                            "Certificate not trusted by browsers — MITM possible."),
            "honeypot":    ("Possible honeypot detected: {h}", "info",
                            "Shodan tagged this host as a potential honeypot."),
            "tor":         ("Tor exit node: {h}", "medium",
                            "Host is a Tor exit node."),
            "malware":     ("Shodan malware tag on {h}", "critical",
                            "Host tagged as associated with malware distribution."),
        }
        for tag in shodan_tags:
            if tag.lower() in _tag_map:
                tpl, sev, desc = _tag_map[tag.lower()]
                vulns.append({
                    "check": "shodan_tag", "title": tpl.format(h=host),
                    "severity": sev, "description": desc, "host": host,
                })

        # ── GreyNoise findings ────────────────────────────────────────────────
        if gn_data:
            noise          = gn_data.get("noise", False)
            classification = gn_data.get("classification", "")
            name           = gn_data.get("name", "")
            if noise and classification == "malicious":
                vulns.append({
                    "check":       "greynoise",
                    "title":       f"GreyNoise: {host} is a known MALICIOUS scanner",
                    "severity":    "critical",
                    "description": (
                        f"GreyNoise classifies {host} as malicious ({name}). "
                        "This IP actively scans the internet with malicious intent. "
                        "Consider blocking all traffic from/to this IP."
                    ),
                    "evidence":    f"GreyNoise noise=True classification=malicious name={name}",
                    "host":        host,
                })
            elif noise:
                vulns.append({
                    "check":       "greynoise",
                    "title":       f"GreyNoise: {host} is a known internet scanner ({classification})",
                    "severity":    "medium",
                    "description": (
                        f"GreyNoise identifies {host} as an active internet scanner ({name}). "
                        "Investigate whether this IP should serve your application."
                    ),
                    "host": host,
                })

        # ── AbuseIPDB findings ────────────────────────────────────────────────
        if abuse_data:
            score  = abuse_data.get("abuseConfidenceScore", 0)
            total  = abuse_data.get("totalReports", 0)
            isp    = abuse_data.get("isp", "")
            if score >= 75:
                vulns.append({
                    "check":       "abuseipdb",
                    "title":       f"AbuseIPDB: {host} abuse score {score}/100 — HIGH RISK",
                    "severity":    "high",
                    "description": (
                        f"IP {host} has been reported {total} times in the last 90 days. "
                        f"Abuse confidence: {score}/100. ISP: {isp}."
                    ),
                    "evidence":    f"https://www.abuseipdb.com/check/{host}",
                    "host":        host,
                })
            elif score >= 25:
                vulns.append({
                    "check":       "abuseipdb",
                    "title":       f"AbuseIPDB: {host} moderate abuse score {score}/100",
                    "severity":    "medium",
                    "description": f"IP has {total} abuse reports (score {score}/100). ISP: {isp}.",
                    "host":        host,
                })

        # ── Port / service findings + NSE + NVD ──────────────────────────────
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                pi    = nm[host][proto][port]
                if pi.get("state") != "open":
                    continue

                svc, prod, ver = port_svc_map.get((host, port), ("unknown", "", ""))
                ver_str = f"{prod} {ver}".strip()
                sev     = _assess_severity(port, svc)

                vuln: dict = {
                    "check":       "open_port",
                    "title":       f"Open port: {port}/{proto} ({svc})",
                    "severity":    sev,
                    "description": f"Port {port}/{proto} is open running {svc}",
                    "evidence":    (f"{host}:{port}/{proto} — {ver_str}"
                                    if ver_str else f"{host}:{port}/{proto}"),
                    "remediation": "Firewall or disable if not required.",
                    "port":        port,
                    "protocol":    proto,
                    "service":     svc,
                    "version":     ver_str,
                    "host":        host,
                }

                if svc == "telnet":
                    vuln["remediation"] = "Disable Telnet — use SSH instead."
                elif svc == "ftp" and port == 21:
                    vuln["remediation"] = "Use SFTP/SCP. Disable anonymous login."
                elif port == 3389 or svc == "ms-wbt-server":
                    vuln["remediation"] = "Restrict RDP to VPN only. Enable NLA."
                elif port == 6379:
                    vuln["remediation"] = "Redis: set requirepass, bind 127.0.0.1."
                elif port in (27017, 27018):
                    vuln["remediation"] = "MongoDB: enable --auth, bind to localhost."
                elif port in (9200, 9300):
                    vuln["remediation"] = "Elasticsearch: enable X-Pack security."

                # NSE script results
                for nse_f in _parse_nse_vulns(pi.get("script", {})):
                    vulns.append({
                        "check":       f"nse_{nse_f['script']}",
                        "title":       f"[NSE] {nse_f['script']} — VULNERABLE on {host}:{port}",
                        "severity":    nse_f["severity"],
                        "description": nse_f["output"],
                        "evidence":    f"{host}:{port}",
                        "cve_ids":     nse_f["cve_ids"],
                        "host":        host,
                        "port":        port,
                    })

                # NVD CVEs — use deduplicated lookup result
                if ver_str and not internal and svc != "unknown":
                    kw      = _SERVICE_NVD_KEYWORDS.get(svc.lower(), "")
                    ver_fp  = (ver or prod)[:40]
                    nvd_key = (svc, ver_fp)
                    for c in nvd_results.get(nvd_key, []):
                        vulns.append({
                            "check":       "nvd_cve",
                            "title":       f"CVE {c['id']} — {svc} {ver_str}",
                            "severity":    "critical" if c["score"] >= 9.0 else "high",
                            "description": c["description"],
                            "evidence":    f"{host}:{port} — {ver_str}",
                            "remediation": f"https://nvd.nist.gov/vuln/detail/{c['id']}",
                            "cve_ids":     [c["id"]],
                            "host":        host,
                            "port":        port,
                        })

                vulns.append(vuln)

        # ── OS end-of-life check ──────────────────────────────────────────────
        if os_guess:
            if re.search(r"Windows (XP|2003|Vista|7\b|Server 2008)", os_guess, re.IGNORECASE):
                vulns.append({
                    "check":       "eol_os",
                    "title":       f"End-of-life OS detected: {os_guess}",
                    "severity":    "critical",
                    "description": f"{os_guess} is no longer supported — no security patches.",
                    "evidence":    f"Nmap OS: {os_guess} ({os_acc}% accuracy)",
                    "remediation": "Upgrade to a supported OS version immediately.",
                    "host":        host,
                })
            elif re.search(r"Windows (8\.0|Server 2012\b(?! R2))", os_guess, re.IGNORECASE):
                vulns.append({
                    "check":       "eol_os",
                    "title":       f"Near-EOL OS: {os_guess}",
                    "severity":    "high",
                    "description": "OS nearing end-of-life — plan upgrade.",
                    "host":        host,
                })

    # ── crt.sh subdomain findings ─────────────────────────────────────────────
    if subdomains:
        vulns.append({
            "check":       "attack_surface",
            "title":       f"crt.sh: {len(subdomains)} subdomains for {target}",
            "severity":    "info",
            "description": (
                f"Certificate Transparency logs reveal {len(subdomains)} subdomains. "
                "Each represents potential attack surface that should be in scope."
            ),
            "evidence":    ", ".join(subdomains[:20]) + ("…" if len(subdomains) > 20 else ""),
            "remediation": "Review all subdomains — ensure each is secured and intentionally public.",
        })

    # ── Sort by severity ──────────────────────────────────────────────────────
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns.sort(key=lambda v: order.get(v.get("severity", "info"), 5))

    stats     = nm.scanstats()
    tools_used = ["nmap", "shodan-internetdb", "greynoise"]
    if os.environ.get("ABUSEIPDB_KEY"):
        tools_used.append("abuseipdb")
    if nvd_results:
        tools_used.append("nvd-api-v2")
    if subdomains:
        tools_used.append("crt.sh")

    return {
        "scan_type":       "network_int" if internal else "network_ext",
        "target":          target,
        "vulnerabilities": vulns,
        "hosts":           host_info,
        "subdomains":      subdomains,
        "meta": {
            "scan_time":   datetime.now(timezone.utc).isoformat(),
            "nmap_args":   arguments,
            "deep":        deep,
            "internal":    internal,
            "hosts_up":    stats.get("uphosts", "0"),
            "total_hosts": stats.get("totalhosts", "0"),
            "tools_used":  tools_used,
        },
    }


# backward-compat alias
run_netscan_scan = run_nmap_scan
