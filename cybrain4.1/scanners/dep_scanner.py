# scanners/dep_scanner.py
"""
Dependency Vulnerability Scanner
═════════════════════════════════
External APIs + tools used:
  • pip-audit   — Python deps against PyPI Advisory DB  (pip install pip-audit)
  • npm audit   — Node.js deps against npm advisory DB  (bundled with npm)
  • OSV.dev API — Google Open Source Vulnerability DB   (free, no key needed)
    https://osv.dev/  — covers PyPI, npm, Maven, Go, Rust, RubyGems, etc.

Supported files:
  requirements.txt | package.json | Pipfile | pyproject.toml
"""

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
_OSV_QUERY = "https://api.osv.dev/v1/query"


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class DepFinding:
    package:     str
    version:     str
    cve_id:      str
    severity:    str
    description: str
    fix_version: str = "update to latest"
    source:      str = "osv"
    aliases:     list = field(default_factory=list)


@dataclass
class DepScanResult:
    file_type:       str
    scanned_at:      str = ""
    total_packages:  int = 0
    vulnerabilities: list = field(default_factory=list)
    packages:        list = field(default_factory=list)
    error:           Optional[str] = None
    scanner_used:    str = "osv"

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
                }
                for v in self.vulnerabilities
            ],
            "error": self.error,
        }


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_requirements_txt(content: str) -> list[dict]:
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=<>~!]+\s*([\d.][^\s;#]*)", line)
        if m:
            packages.append({"name": m.group(1), "version": m.group(2).strip()})
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
            clean = re.sub(r"[^0-9.]", "", ver.split(" ")[0])
            packages.append({"name": name, "version": clean or ""})
    return packages


def _parse_pipfile(content: str) -> list[dict]:
    packages, in_section = [], False
    for line in content.splitlines():
        line = line.strip()
        if line in ("[packages]", "[dev-packages]"):
            in_section = True; continue
        if line.startswith("["):
            in_section = False
        if in_section and "=" in line:
            name, ver = line.split("=", 1)
            packages.append({"name": name.strip(), "version": re.sub(r'["\'\s<>=~!*]', "", ver)})
    return packages


def _parse_pyproject(content: str) -> list[dict]:
    packages = []
    for line in content.splitlines():
        m = re.search(r'"([A-Za-z0-9_\-\.]+)\s*[>=<~!]+\s*([\d.]+)"', line)
        if m:
            packages.append({"name": m.group(1), "version": m.group(2)})
    return packages


# ── Version comparison ────────────────────────────────────────────────────────

def _ver_tuple(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts[:4]) if parts else (0,)


# ── OSV.dev API ───────────────────────────────────────────────────────────────

_OSV_ECOSYSTEM = {
    "requirements.txt": "PyPI",
    "pipfile":          "PyPI",
    "pyproject.toml":   "PyPI",
    "package.json":     "npm",
}


def _osv_batch_query(packages: list[dict], ecosystem: str) -> list[DepFinding]:
    """
    Query OSV.dev batch API for all packages at once.
    https://osv.dev/ — completely free, no key required.
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
        resp = requests.post(
            _OSV_BATCH,
            json={"queries": queries},
            timeout=20,
        )
        if resp.status_code != 200:
            logger.warning("OSV batch API HTTP %s", resp.status_code)
            return []

        results  = resp.json().get("results", [])
        findings = []

        for pkg, res in zip(packages, results):
            for vuln in res.get("vulns", []):
                osv_id   = vuln.get("id", "")
                aliases  = [a for a in vuln.get("aliases", []) if a != osv_id]
                cve_id   = next((a for a in aliases if a.startswith("CVE-")), osv_id)
                summary  = vuln.get("summary", "") or vuln.get("details", "")[:200]

                # Severity from database_specific CVSS or severity array
                sev      = "high"  # conservative default
                severity_list = vuln.get("severity", [])
                for s in severity_list:
                    score = s.get("score", "")
                    if score:
                        try:
                            f = float(score)
                            sev = "critical" if f >= 9.0 else "high" if f >= 7.0 else "medium" if f >= 4.0 else "low"
                        except ValueError:
                            # score might be "CVSS:3.1/AV:N/..." vector string
                            if "AV:N" in score and "AC:L" in score:
                                sev = "high"
                        break

                # Fixed version from affected[].ranges
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
                ))

        return findings

    except Exception as exc:
        logger.warning("OSV batch query failed: %s", exc)
        return []


# ── pip-audit ─────────────────────────────────────────────────────────────────

def _run_pip_audit(req_path: str) -> list[DepFinding] | None:
    if not shutil.which("pip-audit"):
        return None
    try:
        proc = subprocess.run(
            ["pip-audit", "--requirement", req_path, "--format", "json", "--no-deps"],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode not in (0, 1):
            return None
        data     = json.loads(proc.stdout)
        findings = []
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                score = 0.0
                for m in (vuln.get("metrics", {}).get("CVSS", [])):
                    score = float(m.get("score", 0))
                    break
                sev = ("critical" if score >= 9.0 else "high" if score >= 7.0
                       else "medium" if score >= 4.0 else "low") if score else "high"
                findings.append(DepFinding(
                    package     = dep.get("name", ""),
                    version     = dep.get("version", ""),
                    cve_id      = vuln.get("id", ""),
                    severity    = sev,
                    description = vuln.get("description", ""),
                    fix_version = ", ".join(vuln.get("fix_versions", ["latest"])) or "latest",
                    source      = "pip-audit",
                ))
        return findings
    except Exception as exc:
        logger.warning("pip-audit failed: %s", exc)
        return None


# ── npm audit ─────────────────────────────────────────────────────────────────

def _run_npm_audit(file_path: str) -> list[DepFinding] | None:
    if not shutil.which("npm"):
        return None
    npm_dir = str(Path(file_path).parent)
    try:
        proc = subprocess.run(
            ["npm", "audit", "--json", "--audit-level=none"],
            capture_output=True, text=True, timeout=60, cwd=npm_dir,
        )
        data = json.loads(proc.stdout)
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
                desc = v.get("title", "")
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
            severity    = sev if sev in ("critical","high","medium","low") else "medium",
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
            severity    = sev if sev in ("critical","high","medium","low") else "medium",
            description = adv.get("overview", ""),
            fix_version = adv.get("recommendation", "upgrade"),
            source      = "npm-audit",
            aliases     = cve_list[1:],
        ))
    return findings or None


# ── Main ──────────────────────────────────────────────────────────────────────

def run_dep_scan(file_path: str) -> dict:
    """
    Scan a dependency file for known vulnerabilities.
    Priority: pip-audit / npm-audit → OSV.dev batch API → local DB

    Args:
        file_path: Path to requirements.txt, package.json, Pipfile, or pyproject.toml
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

    scanner_used = "osv.dev"
    findings: list[DepFinding] = []

    # 1. pip-audit (Python)
    if ecosystem == "PyPI":
        pip_result = _run_pip_audit(str(path))
        if pip_result is not None:
            findings     = pip_result
            scanner_used = "pip-audit+osv.dev"

    # 2. npm audit (Node)
    elif ecosystem == "npm":
        npm_result = _run_npm_audit(str(path))
        if npm_result is not None:
            findings     = npm_result
            scanner_used = "npm-audit+osv.dev"

    # 3. OSV.dev API (always run to catch what pip-audit/npm-audit may miss)
    versioned = [p for p in packages if p.get("version")]
    if versioned:
        osv_findings = _osv_batch_query(versioned, ecosystem)
        # Merge: add OSV findings not already in findings (deduplicate by package+cve)
        existing_keys = {(f.package.lower(), f.cve_id) for f in findings}
        for osv_f in osv_findings:
            key = (osv_f.package.lower(), osv_f.cve_id)
            if key not in existing_keys:
                findings.append(osv_f)
                existing_keys.add(key)
        if not findings:
            scanner_used = "osv.dev"

    # Sort by severity
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order.get(f.severity, 4))

    result = DepScanResult(
        file_type       = file_type,
        scanned_at      = datetime.now(timezone.utc).isoformat(),
        total_packages  = len(packages),
        vulnerabilities = findings,
        packages        = packages,
        scanner_used    = scanner_used,
    )

    logger.info(
        "dep_scan done | packages=%d | vulns=%d | scanner=%s",
        result.total_packages, len(findings), scanner_used,
    )
    return result.to_dict()
