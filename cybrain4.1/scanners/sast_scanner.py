# scanners/sast_scanner.py
"""
SAST Scanner — Static Application Security Testing
═══════════════════════════════════════════════════
Tools used (no custom scripts — real industry tools):
  • Bandit   — Python security linter   (pip install bandit)
  • Semgrep  — Multi-language OWASP/CWE rules (pip install semgrep)
    Rulesets:
      p/python           — Python security
      p/javascript       — JS/Node security
      p/typescript       — TypeScript security
      p/java             — Java security
      p/php              — PHP security
      p/owasp-top-ten    — OWASP Top 10 2021
      p/cwe-top-25       — CWE Top 25 Most Dangerous
      p/secrets          — Hardcoded secrets / credentials
      p/r2c-security-audit — r2c audit rules

Input: ZIP file containing source code (any language)
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_ZIP_SIZE     = 10 * 1024 * 1024   # 10 MB upload limit
MAX_UNCOMPRESSED = 150 * 1024 * 1024  # 150 MB extracted limit
MAX_FILES        = 2000
BANDIT_TIMEOUT   = 120
SEMGREP_TIMEOUT  = 180   # semgrep with multiple rulesets needs more time

# ── Semgrep rulesets to run ───────────────────────────────────────────────────
# Detected automatically based on files found in the ZIP
_RULESETS_BY_LANG = {
    "python":     ["p/python", "p/owasp-top-ten", "p/cwe-top-25", "p/secrets"],
    "javascript": ["p/javascript", "p/owasp-top-ten", "p/secrets", "p/r2c-security-audit"],
    "typescript": ["p/typescript", "p/javascript", "p/secrets"],
    "java":       ["p/java", "p/owasp-top-ten", "p/cwe-top-25"],
    "php":        ["p/php", "p/owasp-top-ten", "p/secrets"],
    "generic":    ["p/secrets", "p/cwe-top-25"],
}

# Always-on rulesets regardless of language
_ALWAYS_RULESETS = ["p/secrets", "p/owasp-top-ten"]

# File extension → language map
_EXT_LANG = {
    ".py":   "python",
    ".js":   "javascript",
    ".jsx":  "javascript",
    ".ts":   "typescript",
    ".tsx":  "typescript",
    ".java": "java",
    ".php":  "php",
    ".go":   "go",
    ".rb":   "ruby",
    ".cs":   "csharp",
}


def _detect_languages(root: Path) -> set[str]:
    langs = set()
    for ext, lang in _EXT_LANG.items():
        if list(root.rglob(f"*{ext}")):
            langs.add(lang)
    return langs


def _build_semgrep_rulesets(langs: set[str]) -> list[str]:
    rulesets: list[str] = list(_ALWAYS_RULESETS)
    for lang in langs:
        for rs in _RULESETS_BY_LANG.get(lang, []):
            if rs not in rulesets:
                rulesets.append(rs)
    return rulesets


def run_sast_scan(file_path: str) -> dict:
    """
    Analyse uploaded ZIP with Bandit (Python) + Semgrep (multi-language).

    Returns standard { "scan_type": "sast", "vulnerabilities": [...], "meta": {...} }
    """
    vulns: list[dict] = []
    meta: dict = {
        "scan_time":        datetime.now(timezone.utc).isoformat(),
        "tools":            [],
        "files_scanned":    0,
        "languages":        [],
        "semgrep_rulesets": [],
    }
    tmp_dir: str | None = None

    try:
        # ── 1. Validate ZIP ───────────────────────────────────────────────────
        if not zipfile.is_zipfile(file_path):
            raise RuntimeError("Uploaded file is not a valid ZIP archive.")

        tmp_dir = tempfile.mkdtemp(prefix="cybrain_sast_")

        with zipfile.ZipFile(file_path, "r") as zf:
            members = zf.namelist()
            if len(members) > MAX_FILES:
                raise RuntimeError(f"ZIP contains {len(members)} files — limit is {MAX_FILES}.")

            # Path traversal guard
            for m in members:
                norm = os.path.normpath(m)
                if os.path.isabs(norm) or norm.startswith(".."):
                    raise RuntimeError(f"Unsafe path in ZIP: {m}")

            # ZIP bomb guard
            total_size = sum(i.file_size for i in zf.infolist())
            if total_size > MAX_UNCOMPRESSED:
                raise RuntimeError(
                    f"ZIP extracted size ({total_size // (1024*1024)} MB) exceeds limit "
                    f"({MAX_UNCOMPRESSED // (1024*1024)} MB). Possible ZIP bomb."
                )

            zf.extractall(tmp_dir)

        root = Path(tmp_dir)

        # ── 2. Detect languages ───────────────────────────────────────────────
        langs = _detect_languages(root)
        meta["languages"] = sorted(langs)

        all_files = [f for f in root.rglob("*") if f.is_file()]
        meta["files_scanned"] = len(all_files)

        if not all_files:
            meta["note"] = "No source files found in ZIP."
            return _result(vulns, meta)

        # ── 3. Bandit (Python only) ───────────────────────────────────────────
        py_files = list(root.rglob("*.py"))
        if py_files:
            bandit_cmd = shutil.which("bandit") or shutil.which("bandit3")
            if not bandit_cmd:
                # Try python -m bandit
                try:
                    subprocess.run(
                        ["python", "-m", "bandit", "--version"],
                        capture_output=True, timeout=5,
                    )
                    bandit_cmd = "python -m bandit"
                except Exception:
                    bandit_cmd = None

            if bandit_cmd:
                _run_bandit(bandit_cmd, tmp_dir, vulns, meta)
            else:
                meta["bandit_note"] = "Bandit not installed — pip install bandit"

        # ── 4. Semgrep (multi-language) ───────────────────────────────────────
        semgrep_cmd = shutil.which("semgrep")
        if semgrep_cmd:
            rulesets = _build_semgrep_rulesets(langs)
            meta["semgrep_rulesets"] = rulesets
            _run_semgrep(semgrep_cmd, tmp_dir, rulesets, vulns, meta)
        else:
            meta["semgrep_note"] = "Semgrep not installed — pip install semgrep"

        meta["issues_found"] = len(vulns)

    except subprocess.TimeoutExpired:
        raise RuntimeError(f"SAST scan timed out. Upload a smaller project.")
    except (json.JSONDecodeError, KeyError) as exc:
        logger.warning("SAST output parse error: %s", exc)
        meta["parse_error"] = str(exc)
    finally:
        if tmp_dir and os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return _result(vulns, meta)


def _result(vulns: list, meta: dict) -> dict:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns.sort(key=lambda v: (order.get(v.get("severity", "info"), 5),
                              -v.get("confidence", 0)))
    return {
        "scan_type":       "sast",
        "target":          "uploaded_code",
        "vulnerabilities": vulns,
        "meta":            meta,
    }


def _run_bandit(bandit_cmd: str, tmp_dir: str, vulns: list, meta: dict) -> None:
    if " " in bandit_cmd:
        cmd = bandit_cmd.split() + ["-r", tmp_dir, "-f", "json", "--quiet", "-ll"]
    else:
        cmd = [bandit_cmd, "-r", tmp_dir, "-f", "json", "--quiet", "-ll"]

    logger.info("SAST Bandit | dir=%s", tmp_dir)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=BANDIT_TIMEOUT)

    stdout = proc.stdout.strip()
    if not stdout:
        logger.warning("Bandit produced no output | stderr=%s", proc.stderr[:300])
        return

    data   = json.loads(stdout)
    sev_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    conf_w  = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    count   = 0

    for issue in data.get("results", []):
        sev  = sev_map.get(issue.get("issue_severity", "LOW"), "low")
        conf = conf_w.get(issue.get("issue_confidence", "LOW"), 1)
        fname = issue.get("filename", "").replace(tmp_dir, "").lstrip("/\\")
        snippet = (issue.get("code") or "").strip()[:400]
        cwe_id  = str(issue.get("issue_cwe", {}).get("id", "") or "")

        vulns.append({
            "check":       f"bandit_{issue.get('test_id','B000')}",
            "title":       f"[Bandit] {issue.get('issue_text', 'Security Issue')}",
            "severity":    sev,
            "description": (
                f"{issue.get('issue_text','')} "
                f"— test: {issue.get('test_id','')} / {issue.get('test_name','')} "
                f"— confidence: {issue.get('issue_confidence','?')}"
            ),
            "evidence":    f"{fname}:{issue.get('line_number','?')}\n{snippet}",
            "remediation": issue.get("more_info", "See Bandit docs."),
            "cwe":         cwe_id,
            "line_number": int(issue.get("line_number", 0) or 0),
            "confidence":  conf,
            "source":      "bandit",
        })
        count += 1

    meta["tools"].append("bandit")
    meta["bandit_issues"] = count
    logger.info("Bandit | issues=%d", count)


def _run_semgrep(semgrep_cmd: str, tmp_dir: str, rulesets: list, vulns: list, meta: dict) -> None:
    # Build config args
    config_args: list[str] = []
    for rs in rulesets:
        config_args += ["--config", rs]

    cmd = [
        semgrep_cmd, "scan",
        *config_args,
        "--json", "--quiet", "--no-git-ignore",
        "--timeout", "30",   # per-rule timeout
        tmp_dir,
    ]
    logger.info("SAST Semgrep | rulesets=%s", rulesets)

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SEMGREP_TIMEOUT)
    stdout = proc.stdout.strip()
    if not stdout:
        logger.debug("Semgrep no output | stderr=%s", proc.stderr[:300])
        return

    data    = json.loads(stdout)
    results = data.get("results", [])
    sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

    # Dedup key: (file, line) already seen by Bandit
    existing: set[tuple] = set()
    for v in vulns:
        ev = v.get("evidence", "")
        m  = re.match(r"([^:]+):(\d+)", ev)
        if m:
            existing.add((m.group(1), m.group(2)))

    count = 0
    for r in results:
        path    = r.get("path", "").replace(tmp_dir, "").lstrip("/\\")
        line    = str(r.get("start", {}).get("line", "0"))
        key     = (path, line)
        if key in existing:
            continue

        sev     = sev_map.get(r.get("extra", {}).get("severity", "WARNING"), "medium")
        msg     = r.get("extra", {}).get("message") or r.get("check_id", "Security Issue")
        snippet = (r.get("extra", {}).get("lines") or "").strip()[:400]
        fix     = r.get("extra", {}).get("fix") or r.get("extra", {}).get("fix_regex", {}).get("replacement", "")
        cwe_list = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        cwe     = str(cwe_list[0]) if cwe_list else ""
        owasp   = r.get("extra", {}).get("metadata", {}).get("owasp", "")
        check_id = r.get("check_id", "")

        # Escalate hardcoded secrets to critical
        if "secret" in check_id.lower() or "credential" in check_id.lower() or "api-key" in check_id.lower():
            sev = "critical"

        vulns.append({
            "check":       f"semgrep_{check_id.replace('/', '_')[:40]}",
            "title":       f"[Semgrep] {check_id.split('.')[-1].replace('-', ' ').title()}",
            "severity":    sev,
            "description": msg,
            "evidence":    f"{path}:{line}\n{snippet}" if snippet else f"{path}:{line}",
            "remediation": fix or "Review Semgrep rule documentation.",
            "cwe":         cwe,
            "owasp":       owasp,
            "line_number": int(line) if line.isdigit() else 0,
            "confidence":  2,
            "source":      "semgrep",
            "rule_id":     check_id,
        })
        existing.add(key)
        count += 1

    meta["tools"].append("semgrep")
    meta["semgrep_issues"] = count
    logger.info("Semgrep | issues=%d | rulesets=%d", count, len(rulesets))
