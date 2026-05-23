# scanners/dep_scanner.py
"""
Dependency Vulnerability Scanner  v3
══════════════════════════════════════════════════════════════════════════
Professional-grade dependency scanning using real APIs.  No home-grown CVE
databases — every finding is backed by an authoritative source.

┌────────────────────────────┬────────────────┬───────────────────────────────────────────────────┐
│ Scanner / API              │ Key needed?    │ How to get the key                                │
├────────────────────────────┼────────────────┼───────────────────────────────────────────────────┤
│ pip-audit (CLI)            │ No             │ pip install pip-audit                             │
│ npm audit (CLI)            │ No             │ bundled with Node.js / npm                        │
│ OSV.dev API (Google)       │ No             │ https://osv.dev — free, no key needed             │
│   covers PyPI, npm, Maven, │                │ Aggregates NVD, GitHub Advisory DB, and 10+ more  │
│   Go, Rust, RubyGems…      │                │                                                   │
│ Snyk REST API              │ Yes (free)     │ 1. Sign up at https://snyk.io                     │
│   200 scans/month free     │                │ 2. Account Settings → General → Auth Token        │
│   Python + npm + more      │                │ 3. Set SNYK_API_KEY in .env                       │
│ PyPI JSON API              │ No             │ https://pypi.org/pypi/<pkg>/json (auto)           │
│   Latest version lookup    │                │ Used to enrich "upgrade to" information           │
│ npm Registry API           │ No             │ https://registry.npmjs.org/<pkg>/latest (auto)    │
│   Latest version lookup    │                │ Used to enrich "upgrade to" information           │
└────────────────────────────┴────────────────┴───────────────────────────────────────────────────┘

Supported manifest files:
  requirements.txt | package.json | Pipfile | pyproject.toml

Scan priority (highest confidence first):
  1. pip-audit / npm-audit  (official, integrated with package repositories)
  2. Snyk REST API          (if SNYK_API_KEY is set)
  3. OSV.dev batch API      (always runs in parallel — catches what others miss)
  4. Latest-version lookup  (enriches fix_version with concrete version numbers)

All three scanners run concurrently with ThreadPoolExecutor.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
_API_TO    = 30


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
    sess.headers["User-Agent"] = "CyBrain-DepScanner/3.0"
    return sess


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class DepFinding:
    package:     str
    version:     str
    cve_id:      str
    severity:    str
    description: str
    fix_version: str  = "update to latest"
    source:      str  = "osv"
    aliases:     list = field(default_factory=list)
    cvss_score:  Optional[float] = None


@dataclass
class DepScanResult:
    file_type:       str
    scanned_at:      str  = ""
    total_packages:  int  = 0
    vulnerabilities: list = field(default_factory=list)
    packages:        list = field(default_factory=list)
    error:           Optional[str] = None
    scanner_used:    str  = "osv"

    def to_dict(self) -> dict:
        return {
            "scan_type":       "dependencies",
            "target":          self.file_type,
            "file_type":       self.file_type,
            "scanned_at":      self.scanned_at,
            "total_packages":  self.total_packages,
            "scanner_used":    self.scanner_used,
            "packages":        self.packages,
            "vulnerabilities": [
                {
                    "check":       "dep_vuln",
                    "package":     v.package,
                    "version":     v.version,
                    "title":       f"{v.package}@{v.version} — {v.cve_id}",
                    "severity":    v.severity,
                    "description": v.description,
                    "fix_version": v.fix_version,
                    "evidence":    f"{v.package}=={v.version}",
                    "remediation": f"Upgrade {v.package} to {v.fix_version}",
                    "cve_ids":     ([v.cve_id] if v.cve_id else []) + (v.aliases or []),
                    "source":      v.source,
                    "cvss_score":  v.cvss_score,
                }
                for v in self.vulnerabilities
            ],
            "error": self.error,
        }


# ── Manifest parsers ──────────────────────────────────────────────────────────

def _parse_requirements_txt(content: str) -> list[dict]:
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=<>~!]+\s*([\d][^\s;#,]*)", line)
        if m:
            # Take only the leading numeric part (handles "1.2.3,<2.0" → "1.2.3")
            raw_ver = m.group(2).strip()
            clean   = re.match(r"[\d][0-9.]*", raw_ver)
            packages.append({"name": m.group(1), "version": clean.group() if clean else raw_ver})
        else:
            m2 = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
            if m2:
                packages.append({"name": m2.group(1), "version": ""})
    return packages


def _parse_package_json(content: str) -> list[dict]:
    packages = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid package.json: {exc}") from exc
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, ver in data.get(section, {}).items():
            # Strip range operators: ^1.2.3, >=1.2.3, ~1.2.3 → 1.2.3
            clean = re.sub(r"[^0-9.]", "", ver.split(" ")[0].split("-")[0])
            packages.append({"name": name, "version": clean or ""})
    return packages


def _parse_pipfile(content: str) -> list[dict]:
    packages, in_section = [], False
    for line in content.splitlines():
        line = line.strip()
        if line in ("[packages]", "[dev-packages]"):
            in_section = True
            continue
        if line.startswith("["):
            in_section = False
        if in_section and "=" in line:
            name, ver = line.split("=", 1)
            packages.append({
                "name":    name.strip(),
                "version": re.sub(r'["\'\s<>=~!*]', "", ver).split(",")[0],
            })
    return packages


def _parse_pyproject(content: str) -> list[dict]:
    packages = []
    for line in content.splitlines():
        m = re.search(r'"([A-Za-z0-9_\-\.]+)\s*[>=<~!]+\s*([\d.]+)"', line)
        if m:
            packages.append({"name": m.group(1), "version": m.group(2)})
    return packages


# ── Version helpers ───────────────────────────────────────────────────────────

def _ver_tuple(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts[:4]) if parts else (0,)


def _cvss_to_sev(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    return "low"


# ── Latest version lookups (PyPI + npm registry) ──────────────────────────────

def _pypi_latest(package: str, sess: requests.Session) -> str | None:
    """Free PyPI JSON API — returns the current latest release version."""
    try:
        r = sess.get(f"https://pypi.org/pypi/{package}/json", timeout=8)
        if r.status_code == 200:
            return r.json().get("info", {}).get("version")
    except Exception:
        pass
    return None


def _npm_latest(package: str, sess: requests.Session) -> str | None:
    """Free npm registry API — returns the dist-tags.latest version."""
    try:
        r = sess.get(f"https://registry.npmjs.org/{package}/latest", timeout=8)
        if r.status_code == 200:
            return r.json().get("version")
    except Exception:
        pass
    return None


def _enrich_fix_versions(
    findings: list[DepFinding],
    ecosystem: str,
    sess: requests.Session,
) -> None:
    """
    For findings where fix_version == "latest", look up the real latest version
    from PyPI or npm and replace "latest" with the concrete version number.
    This is purely informational — enriches the remediation advice.
    """
    needs_latest = [f for f in findings if f.fix_version in ("latest", "")]
    if not needs_latest:
        return

    packages = list({f.package for f in needs_latest})
    lookup   = _pypi_latest if ecosystem == "PyPI" else _npm_latest

    with ThreadPoolExecutor(max_workers=min(len(packages), 8),
                            thread_name_prefix="dep_enrich") as pool:
        futs = {pool.submit(lookup, pkg, sess): pkg for pkg in packages}
        latest_map: dict[str, str] = {}
        for fut in as_completed(futs):
            pkg = futs[fut]
            try:
                ver = fut.result()
                if ver:
                    latest_map[pkg.lower()] = ver
            except Exception:
                pass

    for f in needs_latest:
        concrete = latest_map.get(f.package.lower())
        if concrete:
            f.fix_version = concrete


# ── OSV.dev API ───────────────────────────────────────────────────────────────

_OSV_ECOSYSTEM = {
    "requirements.txt": "PyPI",
    "pipfile":          "PyPI",
    "pyproject.toml":   "PyPI",
    "package.json":     "npm",
}


def _osv_batch_query(
    packages: list[dict],
    ecosystem: str,
    sess: requests.Session,
) -> list[DepFinding]:
    """
    OSV.dev batch API — Google Open Source Vulnerability Database.
    Aggregates NVD, GitHub Advisory DB, PyPI Advisory, npm Advisory,
    RustSec, Go Vulnerability DB, and more.
    Free, no key required. https://osv.dev/
    """
    if not packages:
        return []

    queries = [
        {
            "package": {"name": p["name"], "ecosystem": ecosystem},
            **({"version": p["version"]} if p.get("version") else {}),
        }
        for p in packages
    ]

    try:
        resp = sess.post(_OSV_BATCH, json={"queries": queries}, timeout=_API_TO)
        if resp.status_code != 200:
            logger.warning("OSV batch API HTTP %s", resp.status_code)
            return []

        results  = resp.json().get("results", [])
        findings: list[DepFinding] = []

        for pkg, res in zip(packages, results):
            for vuln in res.get("vulns", []):
                osv_id  = vuln.get("id", "")
                aliases = [a for a in vuln.get("aliases", []) if a != osv_id]
                cve_id  = next((a for a in aliases if a.startswith("CVE-")), osv_id)
                summary = (vuln.get("summary") or vuln.get("details") or "")[:300]

                # Severity: prefer CVSS numeric, then database_specific string
                sev        = "high"  # conservative default
                cvss_score = None
                for s in vuln.get("severity", []):
                    score = s.get("score", "")
                    if not score:
                        continue
                    try:
                        cvss_score = float(score)
                        sev        = _cvss_to_sev(cvss_score)
                        break
                    except ValueError:
                        # CVSS vector string — extract base score if present
                        m = re.search(r"/CVSS:[\d.]+/(.+)", score)
                        if m and "AV:N" in score and "AC:L" in score:
                            sev = "high"
                        break

                # Fallback: database_specific.severity (GitHub Advisory style)
                db_sev = (vuln.get("database_specific") or {}).get("severity", "")
                if db_sev and sev == "high" and cvss_score is None:
                    db_sev_l = db_sev.lower()
                    if db_sev_l in ("critical", "high", "moderate", "medium", "low"):
                        sev = "medium" if db_sev_l == "moderate" else db_sev_l

                # Fixed version from affected[].ranges[].events
                fix_ver = "latest"
                for aff in vuln.get("affected", []):
                    if aff.get("package", {}).get("name", "").lower() != pkg["name"].lower():
                        continue
                    for rng in aff.get("ranges", []):
                        for evt in rng.get("events", []):
                            if "fixed" in evt:
                                fix_ver = evt["fixed"]
                                break

                findings.append(DepFinding(
                    package     = pkg["name"],
                    version     = pkg.get("version", ""),
                    cve_id      = cve_id,
                    severity    = sev,
                    description = summary,
                    fix_version = fix_ver,
                    source      = "osv.dev",
                    aliases     = aliases,
                    cvss_score  = cvss_score,
                ))

        return findings

    except Exception as exc:
        logger.warning("OSV batch query failed: %s", exc)
        return []


# ── Snyk REST API ─────────────────────────────────────────────────────────────

def _run_snyk_scan(file_path: str, ecosystem: str) -> list[DepFinding] | None:
    """
    Snyk API v1 — commercial-grade dependency vulnerability scanner.
    Why Snyk over OSV alone? Snyk catches more npm/PyPI vulns that haven't been
    assigned a CVE yet, rates severity using proprietary intelligence, and gives
    precise remediation advice.

    Free tier: 200 scans/month, no credit card needed.
    Sign up:   https://snyk.io
    Get key:   Account Settings → General → Auth Token → SNYK_API_KEY in .env
    Docs:      https://snyk.docs.apiary.io/#reference/test
    """
    api_key = os.environ.get("SNYK_API_KEY", "").strip()
    if not api_key:
        return None

    path = Path(file_path)
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    if ecosystem == "PyPI":
        endpoint = "https://snyk.io/api/v1/test/pip"
    elif ecosystem == "npm":
        endpoint = "https://snyk.io/api/v1/test/npm"
    else:
        return None

    headers = {
        "Authorization": f"token {api_key}",
        "Content-Type":  "application/json",
    }
    payload = {"files": {"target": {"contents": content}}}

    try:
        sess = _make_session()
        resp = sess.post(endpoint, json=payload, headers=headers, timeout=_API_TO)
        if resp.status_code == 401:
            logger.warning("Snyk: invalid API key (401)")
            return None
        if resp.status_code == 422:
            logger.warning("Snyk: could not parse manifest (422)")
            return None
        if resp.status_code not in (200, 201):
            logger.warning("Snyk: HTTP %s", resp.status_code)
            return None

        if "json" not in resp.headers.get("Content-Type", ""):
            logger.warning("Snyk: non-JSON response")
            return None

        data     = resp.json()
        vuln_list = data.get("issues", {}).get("vulnerabilities", [])
        findings: list[DepFinding] = []

        for v in vuln_list:
            sev = v.get("severity", "medium").lower()
            if sev not in ("critical", "high", "medium", "low"):
                sev = "medium"

            pkg_name = v.get("package", "")
            pkg_ver  = v.get("version", "")
            fixed_in = v.get("fixedIn", [])
            fix_ver  = fixed_in[0] if fixed_in else "latest"

            # Snyk cvssScore is a float
            cvss_raw = v.get("cvssScore")
            try:
                cvss_val: float | None = float(cvss_raw) if cvss_raw is not None else None
            except (TypeError, ValueError):
                cvss_val = None

            findings.append(DepFinding(
                package     = pkg_name,
                version     = pkg_ver,
                cve_id      = v.get("id", ""),
                severity    = sev,
                description = v.get("title", ""),
                fix_version = fix_ver,
                source      = "snyk",
                aliases     = v.get("identifiers", {}).get("CVE", []),
                cvss_score  = cvss_val,
            ))

        logger.info("Snyk | %s findings for %s", len(findings), path.name)
        return findings if findings else None

    except Exception as exc:
        logger.warning("Snyk scan failed: %s", exc)
        return None


# ── pip-audit ─────────────────────────────────────────────────────────────────

def _run_pip_audit(req_path: str) -> list[DepFinding] | None:
    """
    pip-audit — official Python vulnerability scanner backed by PyPI advisory DB.
    Install: pip install pip-audit
    """
    if not shutil.which("pip-audit"):
        return None
    try:
        proc = subprocess.run(
            ["pip-audit", "--requirement", req_path, "--format", "json", "--no-deps"],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode not in (0, 1):
            logger.debug("pip-audit exited %d: %s", proc.returncode, proc.stderr[:200])
            return None

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            logger.warning("pip-audit: could not parse JSON output")
            return None

        findings: list[DepFinding] = []
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                score = 0.0
                for m in (vuln.get("metrics", {}).get("CVSS", []) or []):
                    try:
                        score = float(m.get("score", 0))
                    except (TypeError, ValueError):
                        pass
                    break
                sev = _cvss_to_sev(score) if score else "high"
                findings.append(DepFinding(
                    package     = dep.get("name", ""),
                    version     = dep.get("version", ""),
                    cve_id      = vuln.get("id", ""),
                    severity    = sev,
                    description = vuln.get("description", ""),
                    fix_version = ", ".join(vuln.get("fix_versions", [])) or "latest",
                    source      = "pip-audit",
                    cvss_score  = score or None,
                ))
        return findings

    except subprocess.TimeoutExpired:
        logger.warning("pip-audit timed out")
        return None
    except Exception as exc:
        logger.warning("pip-audit failed: %s", exc)
        return None


# ── npm audit ─────────────────────────────────────────────────────────────────

def _run_npm_audit(file_path: str) -> list[DepFinding] | None:
    """
    npm audit — official Node.js vulnerability checker.
    Bundled with Node.js. No install needed if Node is present.
    """
    if not shutil.which("npm"):
        return None
    npm_dir = str(Path(file_path).parent)
    try:
        proc = subprocess.run(
            ["npm", "audit", "--json", "--audit-level=none"],
            capture_output=True, text=True, timeout=60, cwd=npm_dir,
        )
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            logger.warning("npm audit: non-JSON output (returncode=%d)", proc.returncode)
            return None

    except subprocess.TimeoutExpired:
        logger.warning("npm audit timed out")
        return None
    except Exception as exc:
        logger.warning("npm audit failed: %s", exc)
        return None

    findings: list[DepFinding] = []

    # npm 7+ format
    for pkg_name, info in data.get("vulnerabilities", {}).items():
        sev  = info.get("severity", "medium")
        desc = ""
        cves: list[str] = []
        for v in info.get("via", []):
            if isinstance(v, dict):
                desc = desc or v.get("title", "")
                url  = v.get("url", "")
                m    = re.search(r"CVE-\d{4}-\d+", url)
                if m:
                    cves.append(m.group())
        fix_info = info.get("fixAvailable", {})
        fix_ver  = fix_info.get("version", "upgrade") if isinstance(fix_info, dict) else "upgrade"
        findings.append(DepFinding(
            package     = pkg_name,
            version     = info.get("range", ""),
            cve_id      = cves[0] if cves else "",
            severity    = sev if sev in ("critical", "high", "medium", "low") else "medium",
            description = desc,
            fix_version = fix_ver,
            source      = "npm-audit",
            aliases     = cves[1:],
        ))
    if findings:
        return findings

    # npm 6 format
    for adv in data.get("advisories", {}).values():
        cve_list = [v["cve"] for v in adv.get("cves", []) if v.get("cve")]
        sev      = adv.get("severity", "medium")
        ver      = (adv.get("findings") or [{}])[0].get("version", "")
        findings.append(DepFinding(
            package     = adv.get("module_name", ""),
            version     = ver,
            cve_id      = cve_list[0] if cve_list else "",
            severity    = sev if sev in ("critical", "high", "medium", "low") else "medium",
            description = adv.get("overview", ""),
            fix_version = adv.get("recommendation", "upgrade"),
            source      = "npm-audit",
            aliases     = cve_list[1:],
        ))
    return findings or None


# ── Deduplication ─────────────────────────────────────────────────────────────

def _dedup_findings(findings: list[DepFinding]) -> list[DepFinding]:
    """
    Merge findings from multiple scanners.
    Key = (package, cve_id). If a CVE is found by multiple scanners:
      - Keep highest severity
      - Keep most precise fix_version
      - Append source names
    """
    merged: dict[tuple[str, str], DepFinding] = {}
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    for f in findings:
        key = (f.package.lower(), f.cve_id.upper() if f.cve_id else f.description[:60].lower())
        if key in merged:
            ex = merged[key]
            if order.get(f.severity, 0) > order.get(ex.severity, 0):
                ex.severity = f.severity
            if f.source not in ex.source:
                ex.source += f"+{f.source}"
            # Prefer a concrete version over "latest"
            if ex.fix_version in ("latest", "upgrade", "") and f.fix_version not in ("latest", "upgrade", ""):
                ex.fix_version = f.fix_version
            if f.cvss_score and (ex.cvss_score is None or f.cvss_score > ex.cvss_score):
                ex.cvss_score = f.cvss_score
        else:
            merged[key] = DepFinding(
                package     = f.package,
                version     = f.version,
                cve_id      = f.cve_id,
                severity    = f.severity,
                description = f.description,
                fix_version = f.fix_version,
                source      = f.source,
                aliases     = list(f.aliases),
                cvss_score  = f.cvss_score,
            )

    return list(merged.values())


# ── Main ──────────────────────────────────────────────────────────────────────

def run_dep_scan(file_path: str) -> dict:
    """
    Scan a dependency manifest for known vulnerabilities.

    All scanners run concurrently:
      pip-audit / npm-audit   ─┐
      Snyk REST API            ├─ parallel → merge + dedup → sort by severity
      OSV.dev batch API       ─┘
      + Latest-version enrichment

    Args:
        file_path: Path to requirements.txt, package.json, Pipfile, or pyproject.toml

    Returns:
        Standard CyBrain scan result dict
    """
    path = Path(file_path)
    if not path.exists():
        return DepScanResult(
            file_type  = "unknown",
            scanned_at = datetime.now(timezone.utc).isoformat(),
            error      = f"File not found: {file_path}",
        ).to_dict()

    filename = path.name.lower()
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return DepScanResult(
            file_type  = filename,
            scanned_at = datetime.now(timezone.utc).isoformat(),
            error      = str(exc),
        ).to_dict()

    # Detect file type and parse packages
    try:
        if filename == "package.json":
            packages, file_type, ecosystem = _parse_package_json(content), "package.json", "npm"
        elif filename == "pipfile":
            packages, file_type, ecosystem = _parse_pipfile(content), "Pipfile", "PyPI"
        elif filename.endswith(".toml"):
            packages, file_type, ecosystem = _parse_pyproject(content), "pyproject.toml", "PyPI"
        else:
            packages, file_type, ecosystem = _parse_requirements_txt(content), "requirements.txt", "PyPI"
    except ValueError as exc:
        return DepScanResult(
            file_type  = filename,
            scanned_at = datetime.now(timezone.utc).isoformat(),
            error      = str(exc),
        ).to_dict()

    logger.info("dep_scan | file=%s | packages=%d | ecosystem=%s", filename, len(packages), ecosystem)

    versioned   = [p for p in packages if p.get("version")]
    sess        = _make_session()
    all_findings: list[DepFinding] = []
    sources_used: list[str]        = []

    # ── Run all scanners concurrently ─────────────────────────────────────────
    futures: dict = {}
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="dep") as pool:

        if ecosystem == "PyPI":
            futures["pip_audit"] = pool.submit(_run_pip_audit, str(path))
        elif ecosystem == "npm":
            futures["npm_audit"] = pool.submit(_run_npm_audit, str(path))

        if os.environ.get("SNYK_API_KEY"):
            futures["snyk"] = pool.submit(_run_snyk_scan, str(path), ecosystem)

        if versioned:
            futures["osv"] = pool.submit(_osv_batch_query, versioned, ecosystem, sess)

        results: dict[str, list[DepFinding] | None] = {}
        for name, fut in futures.items():
            try:
                results[name] = fut.result()
            except Exception as exc:
                logger.warning("dep_scan[%s] error: %s", name, exc)
                results[name] = None

    # ── Merge results ─────────────────────────────────────────────────────────
    for name in ("pip_audit", "npm_audit", "snyk", "osv"):
        r = results.get(name)
        if r:
            all_findings.extend(r)
            scanner_label = {
                "pip_audit": "pip-audit",
                "npm_audit": "npm-audit",
                "snyk":      "snyk",
                "osv":       "osv.dev",
            }.get(name, name)
            sources_used.append(scanner_label)

    all_findings = _dedup_findings(all_findings)

    # ── Enrich fix_version with concrete latest versions ─────────────────────
    if all_findings:
        _enrich_fix_versions(all_findings, ecosystem, sess)

    # ── Sort by severity ──────────────────────────────────────────────────────
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings.sort(key=lambda f: order.get(f.severity, 4))

    scanner_used = "+".join(sources_used) if sources_used else "osv.dev"
    result = DepScanResult(
        file_type       = file_type,
        scanned_at      = datetime.now(timezone.utc).isoformat(),
        total_packages  = len(packages),
        vulnerabilities = all_findings,
        packages        = packages,
        scanner_used    = scanner_used,
    )

    logger.info(
        "dep_scan done | packages=%d | vulns=%d | scanners=%s",
        result.total_packages, len(all_findings), scanner_used,
    )
    return result.to_dict()
