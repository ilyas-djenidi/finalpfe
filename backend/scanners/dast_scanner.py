# scanners/dast_scanner.py
"""
DAST Scanner — Dynamic Application Security Testing  v2
═══════════════════════════════════════════════════════════
Three complementary engines run in parallel:

  ① Nuclei  (CLI  OR  ProjectDiscovery Cloud API)
     9 000+ templates: CVE, exposure, misconfiguration,
     default-login, takeover, XSS, SQLi, RCE, LFI, SSRF.

     • CLI:  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
     • Cloud API (free tier):
         1. Sign up at  https://cloud.projectdiscovery.io
         2. Dashboard → API Keys → Generate
         3. Set env:   PDCP_API_KEY=<your key>
       Cloud is tried first when PDCP_API_KEY is set; CLI is the fallback.

  ② ZAP  (OWASP ZAP daemon — self-hosted, completely free)
     Spider + Active Scan + passive alert harvest.
     Start the daemon once, leave it running:

       docker run -d --name zap -p 8080:8080 zaproxy/zap-stable \\
         zap.sh -daemon -host 0.0.0.0 -port 8080 \\
         -config api.key=changeme \\
         -config api.addrs.addr.name=.* \\
         -config api.addrs.addr.enabled=true

     Set env:  ZAP_URL=http://127.0.0.1:8080   ZAP_API_KEY=changeme
     Disable:  ZAP_ENABLED=0

  ③ Nikto  (CLI — web server misconfiguration checks, free)
       apt install nikto   OR   brew install nikto
       Docker fallback: docker pull frapsoft/nikto  (auto-detected)

Scan Profiles:
  quick    — Nuclei critical/high CVEs only, ZAP spider only (no active scan)
  standard — All engines, balanced tags, full ZAP active scan  (default)
  deep     — All engines, full Nuclei template set, deep spider

SSRF Protection:
  Private / loopback / link-local IPs are blocked by default.
  Set  DAST_ALLOW_INTERNAL=1  to scan internal targets (pentest labs).

Warning: Only scan targets you are authorised to test.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Literal
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ── Timeouts ────────────────────────────────────────────────────────────────
_NIKTO_PROC_TIMEOUT = 390       # subprocess wall-clock limit (30 s grace above maxtime)
_NIKTO_MAXTIME      = "360s"    # -maxtime flag passed to nikto
_ZAP_SPIDER_TIMEOUT = 120       # seconds to wait for spider
_ZAP_ASCAN_TIMEOUT  = 360       # seconds to wait for active scan
_NUCLEI_CLI_TIMEOUT = 360
_PDCP_POLL_MAX      = 300       # seconds to poll cloud scan

# ── Nuclei tags by profile ───────────────────────────────────────────────────
_NUCLEI_TAGS: dict[str, str] = {
    "quick":    "cve,critical,high,default-login,exposure",
    "standard": "cve,exposure,misconfiguration,default-login,takeover,xss,sqli,rce,lfi,ssrf",
    "deep":     "cve,exposure,misconfiguration,default-login,takeover,xss,sqli,rce,lfi,ssrf"
                ",tech,network,file,dns,headless",
}

# ── Nikto false-positive patterns to suppress ────────────────────────────────
_FP_PATTERNS = [
    r"anti-clickjacking x-frame-options",
    r"retrieved via a get request",
    r"no cgi",
]

# ── ZAP risk → internal severity mapping ─────────────────────────────────────
_ZAP_RISK_MAP: dict[str, str] = {
    "critical":      "critical",   # ZAP ≥ 2.14
    "high":          "high",
    "medium":        "medium",
    "low":           "low",
    "informational": "info",
    "false positive":"info",
}


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DASTConfig:
    """Runtime parameters for a single DAST scan."""
    profile:        Literal["quick", "standard", "deep"] = "standard"
    allow_internal: bool  = False
    progress_cb:    Callable[[str, int], None] | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target.rstrip("/")


def _check_ssrf(url: str) -> None:
    """Block private/loopback/reserved addresses (SSRF guard)."""
    host = urlparse(url).hostname or ""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError(f"DNS resolution failed for '{host}': {exc}") from exc

    for _, _, _, _, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                raise ValueError(
                    f"SSRF protection: '{host}' resolves to private/reserved address {ip_str}. "
                    "Set DAST_ALLOW_INTERNAL=1 to allow scanning internal targets."
                )
        except ValueError as exc:
            if "SSRF protection" in str(exc):
                raise
            continue  # malformed IP string — skip


def _parse_severity(text: str) -> str:
    t = text.lower()
    if any(w in t for w in [
        "remote code", "rce", "execute", "shell", "overflow",
        "command injection", "sql injection", "critical",
        "arbitrary code", "unauthenticated rce", "zero-day",
    ]):
        return "critical"
    if any(w in t for w in [
        "xss", "cross-site scripting", "injection", "backdoor",
        "default credential", "authentication bypass", "bypass auth",
        "unrestricted file upload", "privilege escalation",
        "rdp enabled", "vnc enabled", "telnet enabled",
        "ftp anonymous", "anonymous ftp",
        "ssh weak", "high",
    ]):
        return "high"
    if any(w in t for w in [
        "version", "outdated", "disclosure", "misconfiguration",
        "insecure", "deprecated", "medium",
    ]):
        return "medium"
    # "enabled" / "open" alone is just informational — not blanket-medium
    return "low"


def _severity_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)


def _dedup_key(v: dict) -> str:
    """Stable dedup key that ignores URL params and evidence differences."""
    norm = re.sub(r"https?://\S+", "URL", v.get("title", "") + v.get("description", "")[:200])
    norm = re.sub(r"\s+", " ", norm).lower().strip()
    raw  = norm + "|" + v.get("check", "")
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()


def _make_session(retries: int = 2, backoff: float = 0.4) -> requests.Session:
    sess    = requests.Session()
    adapter = HTTPAdapter(max_retries=Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    ))
    sess.mount("https://", adapter)
    sess.mount("http://",  adapter)
    return sess


def _merge_findings(
    nikto_vulns:  list[dict],
    zap_vulns:    list[dict],
    nuclei_vulns: list[dict],
) -> list[dict]:
    merged: dict[str, dict] = {}
    confidence_map = {"nuclei": "high", "zap": "high", "nikto": "medium"}

    for src, vulns in (("nikto", nikto_vulns), ("zap", zap_vulns), ("nuclei", nuclei_vulns)):
        for v in vulns:
            k = _dedup_key(v)
            if k in merged:
                ex = merged[k]
                if src not in ex["source"]:
                    ex["source"] += f"+{src}"
                if "+" in ex["source"]:
                    ex["confidence"] = "confirmed"  # 2+ independent tools agree
                if _severity_rank(v.get("severity", "")) > _severity_rank(ex.get("severity", "")):
                    ex["severity"] = v["severity"]
            else:
                item = dict(v)
                item["source"]     = src
                item["confidence"] = confidence_map.get(src, "medium")
                merged[k] = item

    result = list(merged.values())
    result.sort(key=lambda x: _severity_rank(x.get("severity", "")), reverse=True)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Nuclei
# ─────────────────────────────────────────────────────────────────────────────

def _parse_nuclei_jsonl(path: str, fallback_url: str) -> list[dict]:
    vulns: list[dict] = []
    if not os.path.exists(path):
        return vulns
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                r    = json.loads(raw)
                info = r.get("info", {})
                sev  = info.get("severity", "info").lower()
                if sev not in ("critical", "high", "medium", "low", "info"):
                    sev = "medium"
                tid     = r.get("template-id", "")
                name    = info.get("name", tid)
                desc    = info.get("description", name)
                cls     = info.get("classification", {}) or {}
                cve_ids = cls.get("cve-id") or []
                if isinstance(cve_ids, str):
                    cve_ids = [cve_ids]
                refs = info.get("reference") or []
                vulns.append({
                    "check":       tid,
                    "title":       f"[Nuclei] {name}",
                    "severity":    sev,
                    "description": desc,
                    "evidence":    r.get("matched-at", fallback_url),
                    "remediation": info.get("remediation") or
                                   "See template: https://nuclei.projectdiscovery.io/",
                    "cve_ids":     cve_ids,
                    "cvss_score":  cls.get("cvss-score"),
                    "references":  refs if isinstance(refs, list) else [refs],
                    "tags":        info.get("tags", []),
                })
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
    return vulns


def _run_nuclei_cli(url: str, profile: str) -> tuple[list[dict], str | None]:
    nuclei_cmd = shutil.which("nuclei")
    if not nuclei_cmd:
        return [], (
            "Nuclei not installed. "
            "Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  "
            "or set PDCP_API_KEY to use the cloud API instead."
        )

    tags = _NUCLEI_TAGS.get(profile, _NUCLEI_TAGS["standard"])
    fd, tmp_out = tempfile.mkstemp(suffix="_nuclei.jsonl")
    os.close(fd)

    try:
        cmd = [
            nuclei_cmd,
            "-u", url,
            "-tags", tags,
            "-jsonl",
            "-o", tmp_out,
            "-silent",
            "-no-color",
            "-timeout", "15",
            "-rate-limit", "50",
            "-retries", "1",
            "-severity", "critical,high,medium,low",
        ]
        if profile == "deep":
            cmd += ["-rate-limit", "100", "-bulk-size", "25"]

        logger.info("DAST(Nuclei-CLI) target=%s profile=%s", url, profile)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_NUCLEI_CLI_TIMEOUT,
        )
        # nuclei exits 0 (no findings) or 1 (findings found) — both are normal
        if proc.returncode not in (0, 1):
            logger.debug("Nuclei stderr: %s", proc.stderr[:400])

        return _parse_nuclei_jsonl(tmp_out, url), None

    except subprocess.TimeoutExpired:
        return [], f"Nuclei timed out after {_NUCLEI_CLI_TIMEOUT}s"
    except Exception as exc:
        return [], f"Nuclei CLI error: {exc}"
    finally:
        try:
            os.unlink(tmp_out)
        except OSError:
            pass


def _run_nuclei_cloud(url: str, profile: str) -> tuple[list[dict], str | None]:
    """
    ProjectDiscovery Cloud Platform (PDCP) REST API.
    Free tier available — no credit card required.
    Docs: https://docs.projectdiscovery.io/api-reference/introduction
    """
    api_key = os.environ.get("PDCP_API_KEY", "").strip()
    if not api_key:
        return [], "PDCP_API_KEY not set"

    base    = "https://api.projectdiscovery.io"
    tags    = _NUCLEI_TAGS.get(profile, _NUCLEI_TAGS["standard"])
    sess    = _make_session()
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

    try:
        resp = sess.post(
            f"{base}/v1/scans",
            headers=headers,
            json={"targets": [url], "tags": tags.split(",")},
            timeout=(10, 30),
        )
        resp.raise_for_status()
        if "json" not in resp.headers.get("Content-Type", ""):
            return [], f"PDCP: unexpected Content-Type={resp.headers.get('Content-Type')!r}: {resp.text[:200]}"
        body    = resp.json()
        scan_id = body.get("id") or body.get("scan_id", "")
        if not scan_id:
            return [], f"PDCP: unexpected response (no scan_id): {body}"

        logger.info("DAST(Nuclei-Cloud) scan_id=%s target=%s", scan_id, url)

        deadline = time.monotonic() + _PDCP_POLL_MAX
        interval = 5
        while time.monotonic() < deadline:
            st = sess.get(f"{base}/v1/scans/{scan_id}", headers=headers, timeout=(10, 20))
            st.raise_for_status()
            if "json" not in st.headers.get("Content-Type", ""):
                logger.warning("PDCP status: non-JSON response, retrying — %s", st.text[:80])
                time.sleep(min(interval, deadline - time.monotonic()))
                interval = min(interval * 1.5, 30)
                continue
            status = st.json().get("status", "").lower()
            if status in ("completed", "done", "finished"):
                break
            if status in ("failed", "error"):
                return [], f"PDCP scan failed: {st.json()}"
            time.sleep(min(interval, deadline - time.monotonic()))
            interval = min(interval * 1.5, 30)
        else:
            return [], f"PDCP scan timed out after {_PDCP_POLL_MAX}s"

        res = sess.get(f"{base}/v1/scans/{scan_id}/results", headers=headers, timeout=(10, 30))
        res.raise_for_status()
        items = res.json().get("results", res.json().get("data", []))

        vulns: list[dict] = []
        for r in items:
            info    = r.get("info", {})
            sev     = (info.get("severity") or r.get("severity") or "info").lower()
            if sev not in ("critical", "high", "medium", "low", "info"):
                sev = "medium"
            cls     = info.get("classification", {}) or {}
            cve_ids = cls.get("cve-id") or []
            vulns.append({
                "check":       r.get("template-id", r.get("templateID", "")),
                "title":       f"[Nuclei-Cloud] {info.get('name', 'Finding')}",
                "severity":    sev,
                "description": info.get("description", ""),
                "evidence":    r.get("matched-at", url),
                "remediation": info.get("remediation", ""),
                "cve_ids":     cve_ids if isinstance(cve_ids, list) else [cve_ids],
                "cvss_score":  cls.get("cvss-score"),
                "references":  info.get("reference", []),
                "tags":        info.get("tags", []),
            })
        return vulns, None

    except requests.RequestException as exc:
        return [], f"PDCP API error: {exc}"


def _run_nuclei_scan(url: str, profile: str = "standard") -> tuple[list[dict], str | None]:
    """Try cloud API first (if key set), fall back to CLI."""
    if os.environ.get("PDCP_API_KEY"):
        vulns, err = _run_nuclei_cloud(url, profile)
        if err and "PDCP_API_KEY not set" not in err:
            logger.warning("DAST(Nuclei-Cloud) failed: %s — falling back to CLI", err)
        if vulns:
            return vulns, None
    return _run_nuclei_cli(url, profile)


# ─────────────────────────────────────────────────────────────────────────────
# ZAP
# ─────────────────────────────────────────────────────────────────────────────

class _ZAPClient:
    """
    Thin, clean wrapper around the OWASP ZAP REST API.
    API key is sent in the  X-ZAP-API-Key  header (not as a query param)
    to prevent leakage in server logs.
    """

    def __init__(self, base: str, api_key: str):
        self._base = base.rstrip("/")
        self._key  = api_key
        self._sess = _make_session()

    # ── low-level ────────────────────────────────────────────────────────────

    def _get(self, path: str, params: dict | None = None) -> dict:
        resp = self._sess.get(
            f"{self._base}{path}",
            params=params or {},
            headers={"X-ZAP-API-Key": self._key},
            timeout=(8, 30),
        )
        resp.raise_for_status()
        return resp.json()

    # ── context ──────────────────────────────────────────────────────────────

    def version(self) -> str:
        return self._get("/JSON/core/view/version/").get("version", "?")

    def new_context(self, name: str = "cybrain") -> str:
        return self._get("/JSON/context/action/newContext/", {"contextName": name}).get("contextId", "1")

    def include_in_context(self, ctx_id: str, pattern: str) -> None:
        self._get("/JSON/context/action/includeInContext/", {"contextId": ctx_id, "regex": pattern})

    def remove_context(self, ctx_id: str) -> None:
        try:
            self._get("/JSON/context/action/removeContext/", {"contextId": ctx_id})
        except Exception:
            pass

    # ── spider ───────────────────────────────────────────────────────────────

    def start_spider(self, url: str, ctx_id: str, max_depth: int = 5) -> str:
        return self._get(
            "/JSON/spider/action/scan/",
            {"url": url, "contextId": ctx_id, "maxDepth": max_depth},
        ).get("scan", "0")

    def spider_progress(self, scan_id: str) -> int:
        return int(self._get("/JSON/spider/view/status/", {"scanId": scan_id}).get("status", 0))

    # ── active scan ──────────────────────────────────────────────────────────

    def start_ascan(self, url: str, ctx_id: str) -> str:
        return self._get(
            "/JSON/ascan/action/scan/",
            {"url": url, "contextId": ctx_id, "recurse": "true"},
        ).get("scan", "0")

    def ascan_progress(self, scan_id: str) -> int:
        return int(self._get("/JSON/ascan/view/status/", {"scanId": scan_id}).get("status", 0))

    # ── alerts ───────────────────────────────────────────────────────────────

    def clear_alerts(self) -> None:
        """Purge all ZAP alerts before a scan — prevents stale results bleeding in."""
        try:
            self._get("/JSON/alert/action/clearAlerts/")
        except Exception:
            pass  # non-fatal: stale alerts are better than aborting the scan

    def get_alerts(self, url: str) -> list[dict]:
        return self._get("/JSON/alert/view/alerts/", {"baseurl": url}).get("alerts", [])

    # ── polling helper ───────────────────────────────────────────────────────

    def _poll(
        self,
        progress_fn: Callable[[], int],
        timeout: int,
        label: str,
        cb: Callable[[str, int], None] | None,
    ) -> None:
        deadline = time.monotonic() + timeout
        interval = 2.0
        while time.monotonic() < deadline:
            pct = progress_fn()
            if cb:
                cb(f"zap-{label}", pct)
            if pct >= 100:
                return
            time.sleep(min(interval, max(0, deadline - time.monotonic())))
            interval = min(interval * 1.6, 15.0)
        logger.warning("ZAP %s did not complete within %ds — collecting partial results", label, timeout)

    # ── full scan flow ────────────────────────────────────────────────────────

    def run_full_scan(
        self,
        url: str,
        profile: str = "standard",
        progress_cb: Callable[[str, int], None] | None = None,
    ) -> list[dict]:
        self.clear_alerts()   # purge any results from previous scans
        host   = urlparse(url).hostname or url
        ctx_id = self.new_context("cybrain_scan")
        self.include_in_context(ctx_id, f".*{re.escape(host)}.*")

        try:
            spider_depth   = 3 if profile == "quick" else (8 if profile == "deep" else 5)
            spider_timeout = 60 if profile == "quick" else _ZAP_SPIDER_TIMEOUT

            sid = self.start_spider(url, ctx_id, spider_depth)
            self._poll(lambda: self.spider_progress(sid), spider_timeout, "spider", progress_cb)

            if profile != "quick":
                ascan_timeout = _ZAP_ASCAN_TIMEOUT * (2 if profile == "deep" else 1)
                aid = self.start_ascan(url, ctx_id)
                self._poll(lambda: self.ascan_progress(aid), ascan_timeout, "ascan", progress_cb)

            return self._map_alerts(self.get_alerts(url))
        finally:
            self.remove_context(ctx_id)

    def _map_alerts(self, alerts: list[dict]) -> list[dict]:
        vulns: list[dict] = []
        for a in alerts:
            risk = (a.get("risk") or "").lower()
            sev  = _ZAP_RISK_MAP.get(risk, "low")
            desc = (a.get("desc") or a.get("alert") or "").strip()
            if not desc:
                continue
            cwe   = a.get("cweid", "")
            wasc  = a.get("wascid", "")
            ref   = a.get("reference", "")
            vulns.append({
                "check":       f"ZAP-{a.get('pluginid', 'unknown')}",
                "title":       f"[ZAP] {a.get('alert', 'Finding')[:120]}",
                "severity":    sev,
                "description": desc,
                "evidence":    a.get("url", ""),
                "remediation": a.get("solution") or "Refer to OWASP guidelines",
                "cve_ids":     [],
                "cwe_id":      f"CWE-{cwe}" if cwe and cwe != "0" else "",
                "wasc_id":     f"WASC-{wasc}" if wasc and wasc != "0" else "",
                "references":  [ref] if ref else [],
                "param":       a.get("param", ""),
                "attack":      a.get("attack", ""),
            })
        return vulns


def _run_zap_scan(
    url: str,
    profile: str = "standard",
    progress_cb: Callable[[str, int], None] | None = None,
) -> tuple[list[dict], str | None]:
    zap_url = os.environ.get("ZAP_URL", "http://127.0.0.1:8080").rstrip("/")
    zap_key = os.environ.get("ZAP_API_KEY", "")
    if os.environ.get("ZAP_ENABLED", "1").lower() in ("0", "false"):
        return [], "ZAP disabled via ZAP_ENABLED=0"

    client = _ZAPClient(zap_url, zap_key)
    try:
        ver = client.version()
        logger.info("DAST(ZAP %s) target=%s zap=%s profile=%s", ver, url, zap_url, profile)
    except Exception as exc:
        return [], f"ZAP not reachable at {zap_url}: {exc}"

    try:
        return client.run_full_scan(url, profile, progress_cb), None
    except Exception as exc:
        logger.exception("ZAP scan failed")
        return [], f"ZAP scan error: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Nikto
# ─────────────────────────────────────────────────────────────────────────────

def _find_nikto_cmd() -> list[str] | None:
    """Return the shell command list to invoke Nikto, or None if unavailable."""
    # 1. Native binary / script already in PATH
    for name in ("nikto", "nikto.pl"):
        path = shutil.which(name)
        if path:
            return [path]

    # 2. Perl + known script locations
    perl = shutil.which("perl")
    if perl:
        for candidate in (
            "/usr/lib/cgi-bin/nikto.pl",
            "/usr/share/nikto/nikto.pl",
            "/opt/nikto/program/nikto.pl",
        ):
            if os.path.isfile(candidate):
                return [perl, candidate]

    # 3. Docker fallback (uses locally cached image if available)
    docker = shutil.which("docker")
    if docker:
        try:
            subprocess.run(
                [docker, "image", "inspect", "frapsoft/nikto"],
                capture_output=True, timeout=5, check=True,
            )
            return [docker, "run", "--rm", "frapsoft/nikto"]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    return None


def _parse_nikto_csv(path: str, base_url: str) -> list[dict]:
    vulns: list[dict] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        rows = list(csv.reader(io.StringIO(fh.read())))  # consume inside with
    for row in rows:
        if not row:
            continue
        head = row[0].lstrip()
        if head.startswith(("#", "Nikto", "Target", '"Nikto')):
            continue
        if len(row) < 5:
            continue

        # CSV layout: host, ip, port, uri, osvdb, method, description
        uri   = row[3].strip() if len(row) > 3 else ""
        desc  = row[6].strip() if len(row) > 6 else (row[4].strip() if len(row) > 4 else "")
        osvdb = row[4].strip() if len(row) > 4 else ""
        if not desc:
            continue
        if any(re.search(fp, desc, re.IGNORECASE) for fp in _FP_PATTERNS):
            continue

        evidence = (
            f"{base_url.rstrip('/')}{uri}"
            if uri and not uri.startswith("http")
            else (uri or base_url)
        )
        vulns.append({
            "check":       f"OSVDB-{osvdb}" if osvdb.isdigit() else "nikto-finding",
            "title":       f"[Nikto] {desc[:120]}",
            "severity":    _parse_severity(desc),
            "description": desc,
            "evidence":    evidence,
            "remediation": "Refer to OWASP remediation guidance for the identified issue",
            "cve_ids":     [],
        })
    return vulns


def _parse_nikto_text(stdout: str, base_url: str) -> list[dict]:
    vulns: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not (line.startswith("+") and len(line) > 10):
            continue
        desc = line.lstrip("+ ").strip()
        if any(re.search(fp, desc, re.IGNORECASE) for fp in _FP_PATTERNS):
            continue
        vulns.append({
            "check":       "nikto-finding",
            "title":       f"[Nikto] {desc[:120]}",
            "severity":    _parse_severity(desc),
            "description": desc,
            "evidence":    base_url,
            "remediation": "Refer to OWASP remediation guidance",
            "cve_ids":     [],
        })
    return vulns


def _run_nikto_scan(url: str) -> tuple[list[dict], str | None]:
    nikto_cmd = _find_nikto_cmd()
    if not nikto_cmd:
        return [], (
            "Nikto not installed. "
            "Install: apt install nikto  |  brew install nikto  |  docker pull frapsoft/nikto"
        )

    fd, tmp_csv = tempfile.mkstemp(suffix="_nikto.csv")
    os.close(fd)

    try:
        cmd = nikto_cmd + [
            "-h", url,
            "-Format", "csv",
            "-o", tmp_csv,
            "-nointeractive",
            "-timeout", "10",
            "-maxtime", _NIKTO_MAXTIME,
            "-C", "all",
            "-no404",
        ]
        logger.info("DAST(Nikto) target=%s", url)
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_NIKTO_PROC_TIMEOUT,
        )
        if proc.returncode not in (0, 1):
            logger.debug("Nikto stderr: %s", proc.stderr[:400])

        if os.path.exists(tmp_csv) and os.path.getsize(tmp_csv) > 0:
            return _parse_nikto_csv(tmp_csv, url), None
        if proc.stdout:
            return _parse_nikto_text(proc.stdout, url), None
        return [], None

    except subprocess.TimeoutExpired:
        return [], f"Nikto timed out after {_NIKTO_PROC_TIMEOUT}s"
    except Exception as exc:
        return [], f"Nikto error: {exc}"
    finally:
        try:
            os.unlink(tmp_csv)
        except OSError:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def run_dast_scan(target: str, config: DASTConfig | None = None) -> dict:
    """
    Run a full DAST scan against *target* using all available engines in parallel.

    Args:
        target: URL, domain, or IP (http/https added automatically if missing).
        config: Optional DASTConfig for profile, auth flags, progress callback.

    Returns:
        {"scan_type": "dast", "target": ..., "vulnerabilities": [...], "meta": {...}}

    Raises:
        ValueError:   SSRF protection blocked a private/reserved address.
        RuntimeError: No engine could run (all tools missing or unavailable).
    """
    cfg = config or DASTConfig()
    url = _normalise_url(target)

    allow_internal = (
        cfg.allow_internal
        or os.environ.get("DAST_ALLOW_INTERNAL", "0").lower() in ("1", "true")
    )
    if not allow_internal:
        _check_ssrf(url)

    nikto_vulns = zap_vulns = nuclei_vulns = []
    nikto_error = zap_error = nuclei_error = None

    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="dast") as pool:
        futures = {
            pool.submit(_run_nikto_scan, url):                               "nikto",
            pool.submit(_run_zap_scan, url, cfg.profile, cfg.progress_cb):  "zap",
            pool.submit(_run_nuclei_scan, url, cfg.profile):                 "nuclei",
        }
        results: dict[str, tuple[list, str | None]] = {}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                results[name] = fut.result()
            except Exception as exc:
                results[name] = ([], str(exc))

    nikto_vulns,  nikto_error  = results.get("nikto",  ([], None))
    zap_vulns,    zap_error    = results.get("zap",    ([], None))
    nuclei_vulns, nuclei_error = results.get("nuclei", ([], None))

    for tool, err in (("Nikto", nikto_error), ("ZAP", zap_error), ("Nuclei", nuclei_error)):
        if err:
            logger.warning("DAST(%s) skipped — %s", tool, err)

    # All three engines unavailable (not installed / not running) — return gracefully
    if nikto_error and zap_error and nuclei_error:
        logger.warning("DAST: all engines unavailable — returning informational result")
        return {
            "scan_type":       "dast",
            "target":          target,
            "vulnerabilities": [
                {
                    "title":       "DAST Scan Unavailable",
                    "severity":    "INFO",
                    "description": (
                        "Dynamic scanning tools (Nikto, ZAP, Nuclei) are not installed "
                        "in this deployment environment. DAST requires these tools to be "
                        "configured on the server. Please contact your administrator to "
                        "enable DAST scanning capabilities."
                    ),
                    "evidence":    "",
                    "remediation": (
                        "Install and configure at least one DAST engine: "
                        "Nikto (https://cirt.net/Nikto2), "
                        "OWASP ZAP (https://www.zaproxy.org), or "
                        "Nuclei (https://nuclei.projectdiscovery.io)."
                    ),
                }
            ],
            "meta": {
                "scan_time":     datetime.now(timezone.utc).isoformat(),
                "profile":       cfg.profile,
                "tools":         [],
                "target_url":    target,
                "issues_found":  0,
                "nikto_issues":  0,
                "zap_issues":    0,
                "nuclei_issues": 0,
                "errors": {
                    "nikto":  nikto_error,
                    "zap":    zap_error,
                    "nuclei": nuclei_error,
                },
                "engines_unavailable": True,
            },
        }

    vulns = _merge_findings(nikto_vulns, zap_vulns, nuclei_vulns)

    return {
        "scan_type":       "dast",
        "target":          target,
        "vulnerabilities": vulns,
        "meta": {
            "scan_time":     datetime.now(timezone.utc).isoformat(),
            "profile":       cfg.profile,
            "tools":         [t for t, v in (("nikto", nikto_vulns), ("zap", zap_vulns), ("nuclei", nuclei_vulns)) if v],
            "target_url":    url,
            "issues_found":  len(vulns),
            "nikto_issues":  len(nikto_vulns),
            "zap_issues":    len(zap_vulns),
            "nuclei_issues": len(nuclei_vulns),
            "errors": {
                "nikto":  nikto_error,
                "zap":    zap_error,
                "nuclei": nuclei_error,
            },
        },
    }
