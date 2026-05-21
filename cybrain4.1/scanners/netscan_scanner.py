# scanners/netscan_scanner.py
"""
Network Scanner — Nmap + Shodan InternetDB + NVD CVE Lookup
═══════════════════════════════════════════════════════════
External APIs used:
  • Shodan InternetDB  — free IP intel, CVEs, tags  (no key needed)
  • NVD API v2         — CVE details for discovered service versions (optional key)

Tools used:
  • Nmap  — port scan + service/version detection + NSE vuln scripts
    Install: https://nmap.org/download.html
    Linux:   sudo apt install nmap
    Windows: https://nmap.org/download.html#windows
"""

import logging
import os
import re
import socket
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

_NVD_KEY  = os.environ.get("NVD_API_KEY", "").strip()
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── Port risk classification ───────────────────────────────────────────────────
_CRITICAL_PORTS = {
    4444,   # Metasploit default shell
    5554,   # Sasser worm
    9001,   # Tor relay
    31337,  # Back Orifice
}
_HIGH_PORTS = {
    21,    # FTP — plaintext credentials
    22,    # SSH — brute-force target (medium if properly secured)
    23,    # Telnet — plaintext, deprecated
    25,    # SMTP — relay abuse
    53,    # DNS — amplification/zone transfer
    135, 137, 138, 139, 445,  # NetBIOS/SMB — EternalBlue territory
    512, 513, 514,  # rsh/rlogin/syslog — legacy, unauthenticated
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
    9200, 9300,  # Elasticsearch — no auth by default
    27017, 27018,  # MongoDB — no auth by default
    28017,  # MongoDB HTTP admin
    11211,  # Memcached — amplification DDoS
    2181,  # ZooKeeper
    7001,  # WebLogic — frequent RCE target
    8161,  # ActiveMQ web console
    50070,  # Hadoop NameNode
}
_MEDIUM_PORTS = {80, 443, 8888, 8000, 8001}
_INFO_PORTS   = set()

# ── NSE vulnerability scripts (used only with deep scan) ─────────────────────
_NSE_VULN_SCRIPTS = [
    "vuln",               # entire vuln category
    "smb-vuln-ms17-010",  # EternalBlue / WannaCry
    "smb-vuln-ms08-067",  # Conficker
    "smb-vuln-cve2009-3103",
    "ssl-heartbleed",     # Heartbleed
    "ssl-poodle",         # POODLE
    "ssl-dh-params",      # Logjam
    "ftp-anon",           # anonymous FTP login
    "ftp-proftpd-backdoor",
    "ssh-auth-methods",   # lists accepted SSH auth methods
    "http-shellshock",    # Shellshock
    "http-slowloris-check",
]

# ── Service to CVE keyword mapping for NVD search ────────────────────────────
_SERVICE_NVD_KEYWORDS = {
    "openssh":   "openssh",
    "ssh":       "openssh",
    "apache":    "apache http server",
    "nginx":     "nginx",
    "iis":       "microsoft iis",
    "ftp":       "vsftpd",
    "vsftpd":    "vsftpd",
    "proftpd":   "proftpd",
    "mysql":     "mysql",
    "mariadb":   "mariadb",
    "postgresql": "postgresql",
    "mssql":     "sql server",
    "smb":       "windows smb",
    "samba":     "samba",
    "vnc":       "realvnc",
    "rdp":       "remote desktop",
    "redis":     "redis",
    "mongodb":   "mongodb",
    "elasticsearch": "elasticsearch",
    "tomcat":    "apache tomcat",
    "weblogic":  "weblogic",
}


def _assess_severity(port: int, service: str) -> str:
    if port in _CRITICAL_PORTS:
        return "critical"
    if port in _HIGH_PORTS or service in ("telnet", "ftp", "netbios-ssn", "msrpc", "ms-wbt-server"):
        return "high"
    if port in _MEDIUM_PORTS:
        return "medium"
    if port in _INFO_PORTS:
        return "info"
    return "low"


def _shodan_internetdb(ip: str) -> dict:
    """
    Query Shodan InternetDB for known CVEs, open ports, tags.
    Free — no API key required. https://internetdb.shodan.io/
    """
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=8)
        if r.status_code == 200:
            return r.json()
    except Exception as exc:
        logger.debug("Shodan InternetDB error for %s: %s", ip, exc)
    return {}


def _nvd_cve_lookup(service: str, version: str) -> list[dict]:
    """
    Query NVD API v2 for CVEs matching a service + version.
    Returns up to 3 top CVEs (sorted by CVSS score).
    Optional key: NVD_API_KEY in .env (raises rate limit from 5 to 50 req/30s).
    """
    keyword = _SERVICE_NVD_KEYWORDS.get(service.lower(), service.lower())
    if not keyword or not version:
        return []
    headers = {}
    if _NVD_KEY:
        headers["apiKey"] = _NVD_KEY
    try:
        r = requests.get(
            _NVD_BASE,
            params={"keywordSearch": keyword, "resultsPerPage": 5},
            headers=headers,
            timeout=8,
        )
        if r.status_code != 200:
            return []
        cves = []
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
                cves.append({"id": cid, "score": float(score), "description": desc[:200]})
        cves.sort(key=lambda x: x["score"], reverse=True)
        return cves[:3]
    except Exception as exc:
        logger.debug("NVD lookup error for %s: %s", service, exc)
        return []


def _parse_nse_vulns(script_output: dict) -> list[dict]:
    """Extract vulnerabilities from Nmap NSE script output."""
    findings = []
    for script_id, output in script_output.items():
        if not output or "ERROR" in output:
            continue
        # Severity from script name
        if any(kw in script_id for kw in ("heartbleed", "ms17-010", "ms08-067", "shellshock")):
            sev = "critical"
        elif any(kw in script_id for kw in ("poodle", "dh-params", "proftpd-backdoor")):
            sev = "high"
        elif any(kw in script_id for kw in ("ftp-anon",)):
            sev = "high"
        else:
            sev = "medium"

        # Extract CVE if mentioned
        cve_ids = re.findall(r"CVE-\d{4}-\d+", output)

        # Check if it's actually VULNERABLE (not just checked)
        is_vuln = any(kw in output.upper() for kw in ["VULNERABLE", "LIKELY VULNERABLE", "CHECK FAILED"])
        if not is_vuln and script_id == "ftp-anon" and "Anonymous FTP login allowed" in output:
            is_vuln = True
        if not is_vuln and "auth-methods" in script_id:
            is_vuln = "password" in output.lower()

        if is_vuln:
            findings.append({
                "script":   script_id,
                "output":   output[:500],
                "severity": sev,
                "cve_ids":  cve_ids,
            })
    return findings


def run_nmap_scan(target: str, deep: bool = False, internal: bool = False) -> dict:
    """
    Nmap network scan with Shodan InternetDB enrichment and NVD CVE lookup.

    Args:
        target:   IP, CIDR, or hostname
        deep:     enable OS detection + NSE vuln scripts (slower, requires root/admin)
        internal: LAN scan profile (lower timing, no internet APIs)
    """
    try:
        import nmap  # type: ignore
    except ImportError:
        raise RuntimeError("python-nmap not installed. Run: pip install python-nmap")

    nm = nmap.PortScanner()

    # Build Nmap arguments
    if deep:
        # Full: version + OS + vuln scripts (needs privileged on Linux)
        nse = ",".join(_NSE_VULN_SCRIPTS[:6])  # cap scripts to avoid timeouts
        arguments = f"-sV -sC --script={nse} -O --open -T4 -p 1-65535"
    elif internal:
        arguments = "-sV --open -T3 --top-ports 2000"
    else:
        arguments = "-sV --open -T4 --top-ports 1000"

    logger.info("nmap | target=%s | args=%s", target, arguments)

    try:
        nm.scan(hosts=target, arguments=arguments)
    except nmap.PortScannerError as exc:
        raise RuntimeError(f"Nmap scan failed: {exc}") from exc

    vulns: list[dict] = []
    host_info: list[dict] = []

    for host in nm.all_hosts():
        # ── Host state ───────────────────────────────────────────────────────
        host_state = nm[host].state()
        osmatch    = nm[host].get("osmatch", [{}])
        os_guess   = osmatch[0].get("name", "") if osmatch else ""
        os_acc     = osmatch[0].get("accuracy", "") if osmatch else ""

        host_entry = {
            "host": host, "state": host_state, "os": os_guess, "os_accuracy": os_acc,
        }

        # ── Shodan InternetDB enrichment (skip for private IPs / internal scan) ──
        shodan_data = {}
        if not internal:
            try:
                socket.inet_aton(host)  # is valid IP?
                from ipaddress import ip_address as _ipa
                if not _ipa(host).is_private:
                    shodan_data = _shodan_internetdb(host)
            except Exception:
                pass

        shodan_cves  = shodan_data.get("vulns", [])
        shodan_ports = shodan_data.get("ports", [])
        shodan_tags  = shodan_data.get("tags", [])

        host_entry["shodan_cves"]  = shodan_cves
        host_entry["shodan_ports"] = shodan_ports
        host_entry["shodan_tags"]  = shodan_tags
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

        # ── Tag-based findings ────────────────────────────────────────────────
        tag_vulns = {
            "self-signed":  ("Self-signed SSL certificate on {h}", "medium",
                             "Certificate not trusted by browsers — MITM possible."),
            "honeypot":     ("Possible honeypot detected: {h}", "info",
                             "Shodan tagged this host as a potential honeypot."),
            "tor":          ("Tor exit node: {h}", "medium",
                             "Host is a Tor exit node — unusual for production."),
            "malware":      ("Shodan malware tag on {h}", "critical",
                             "Host tagged as associated with malware distribution."),
        }
        for tag in shodan_tags:
            if tag.lower() in tag_vulns:
                title_tpl, sev, desc = tag_vulns[tag.lower()]
                vulns.append({
                    "check": "shodan_tag", "title": title_tpl.format(h=host),
                    "severity": sev, "description": desc, "host": host,
                })

        # ── Port / service findings ───────────────────────────────────────────
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                pi      = nm[host][proto][port]
                state   = pi.get("state", "")
                if state != "open":
                    continue

                service = pi.get("name", "unknown")
                product = pi.get("product", "")
                version = pi.get("version", "")
                ver_str = f"{product} {version}".strip()
                sev     = _assess_severity(port, service)

                vuln = {
                    "check":       "open_port",
                    "title":       f"Open port: {port}/{proto} ({service})",
                    "severity":    sev,
                    "description": f"Port {port}/{proto} is open running {service}",
                    "evidence":    f"{host}:{port}/{proto} — {ver_str}" if ver_str else f"{host}:{port}/{proto}",
                    "remediation": "Firewall or disable if not required.",
                    "port":        port,
                    "protocol":    proto,
                    "service":     service,
                    "version":     ver_str,
                    "host":        host,
                }

                # Flag specific high-risk services
                if service in ("telnet",):
                    vuln["remediation"] = "Disable Telnet — use SSH instead."
                elif service in ("ftp",) and port == 21:
                    vuln["remediation"] = "Use SFTP/SCP instead of FTP. Disable anonymous login."
                elif service in ("ms-wbt-server",) or port == 3389:
                    vuln["remediation"] = "Restrict RDP to VPN only. Enable NLA authentication."
                elif port == 6379:
                    vuln["remediation"] = "Redis: set requirepass, bind 127.0.0.1, disable CONFIG/DEBUG."
                elif port in (27017, 27018):
                    vuln["remediation"] = "MongoDB: enable authentication (--auth), bind to localhost."
                elif port in (9200, 9300):
                    vuln["remediation"] = "Elasticsearch: enable X-Pack security, restrict network binding."

                # NSE script findings (deep scan only)
                scripts = pi.get("script", {})
                if scripts:
                    for nse_f in _parse_nse_vulns(scripts):
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

                # NVD CVE lookup for identified service version
                if ver_str and not internal and service != "unknown":
                    nvd_cves = _nvd_cve_lookup(service, version or product)
                    for c in nvd_cves:
                        vulns.append({
                            "check":       "nvd_cve",
                            "title":       f"CVE {c['id']} — {service} {ver_str}",
                            "severity":    "critical" if c["score"] >= 9.0 else "high",
                            "description": c["description"],
                            "evidence":    f"{host}:{port} — {ver_str}",
                            "remediation": f"https://nvd.nist.gov/vuln/detail/{c['id']}",
                            "cve_ids":     [c["id"]],
                            "host":        host,
                            "port":        port,
                        })

                vulns.append(vuln)

        # ── OS-based risk ─────────────────────────────────────────────────────
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

    # ── Sort by severity ──────────────────────────────────────────────────────
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns.sort(key=lambda v: order.get(v.get("severity", "info"), 5))

    stats = nm.scanstats()
    return {
        "scan_type":       "network_int" if internal else "network_ext",
        "target":          target,
        "vulnerabilities": vulns,
        "hosts":           host_info,
        "meta": {
            "scan_time":    datetime.now(timezone.utc).isoformat(),
            "nmap_args":    arguments,
            "deep":         deep,
            "internal":     internal,
            "hosts_up":     stats.get("uphosts", "0"),
            "total_hosts":  stats.get("totalhosts", "0"),
            "tools_used":   ["nmap", "shodan-internetdb", "nvd-api"],
        },
    }


# backward-compat alias
run_netscan_scan = run_nmap_scan
