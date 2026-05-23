# scanners/sast_scanner.py
"""
SAST Scanner — Static Application Security Testing  v3
══════════════════════════════════════════════════════════════════════════
All three scanners run in parallel (ThreadPoolExecutor).

┌────────────────────┬────────────┬────────────────────────────────────────────────────────────┐
│ Tool               │ Key needed │ How to install / get                                       │
├────────────────────┼────────────┼────────────────────────────────────────────────────────────┤
│ Bandit             │ No         │ pip install bandit                                         │
│   Python security  │            │ Finds SQL injection, hardcoded passwords, weak crypto, etc.│
│   linter           │            │ Used by every major Python project (Django, Flask, …)      │
├────────────────────┼────────────┼────────────────────────────────────────────────────────────┤
│ Semgrep            │ No         │ pip install semgrep                                        │
│   Multi-language   │            │ OWASP Top 10, CWE Top 25, secrets, per-language rules      │
│   OWASP/CWE rules  │            │ Rulesets pulled live from semgrep.dev (free public rules)  │
│                    │            │ Optional: SEMGREP_APP_TOKEN for Pro rules (semgrep.dev)    │
├────────────────────┼────────────┼────────────────────────────────────────────────────────────┤
│ Gitleaks           │ No         │ brew install gitleaks  /  go install gitleaks/gitleaks@v8  │
│   Hardcoded secrets│            │ https://github.com/gitleaks/gitleaks/releases              │
│                    │            │ Detects 150+ secret types: AWS, GCP, GitHub, Stripe, etc.  │
└────────────────────┴────────────┴────────────────────────────────────────────────────────────┘

Why these tools?
  Bandit  — the standard Python SAST tool; backed by PyCQA (Python Code Quality Authority)
  Semgrep — used by Dropbox, Figma, Trail of Bits; fastest multi-language SAST available
  Gitleaks — used by GitHub, GitLab, and most major CI/CD pipelines for secret detection

Input: ZIP file containing source code (any language supported by Semgrep)
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_ZIP_SIZE      = 10 * 1024 * 1024    # 10 MB upload limit
MAX_UNCOMPRESSED  = 150 * 1024 * 1024   # 150 MB extracted limit
MAX_FILES         = 2_000
BANDIT_TIMEOUT    = 120
SEMGREP_TIMEOUT   = 180
GITLEAKS_TIMEOUT  = 90

# ── Semgrep rulesets by language ──────────────────────────────────────────────

_RULESETS_BY_LANG: dict[str, list[str]] = {
    "python":     ["p/python", "p/owasp-top-ten", "p/cwe-top-25", "p/secrets"],
    "javascript": ["p/javascript", "p/owasp-top-ten", "p/secrets", "p/r2c-security-audit"],
    "typescript": ["p/typescript", "p/javascript", "p/secrets"],
    "java":       ["p/java", "p/owasp-top-ten", "p/cwe-top-25"],
    "php":        ["p/php", "p/owasp-top-ten", "p/secrets"],
    "go":         ["p/golang", "p/owasp-top-ten", "p/secrets"],
    "ruby":       ["p/ruby", "p/secrets"],
    "csharp":     ["p/csharp", "p/owasp-top-ten", "p/secrets"],
}

_ALWAYS_RULESETS = ["p/secrets", "p/owasp-top-ten"]

# ── Built-in scanner — runs WITHOUT any external tools installed ───────────────
# These patterns are the baseline guarantee: even if Semgrep/Gitleaks/Bandit
# are missing, we still catch the most critical issues.

_JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"}
_PY_EXTS = {".py"}
_ALL_EXTS = _JS_EXTS | _PY_EXTS | {".env", ".yml", ".yaml", ".json", ".xml", ".config", ".toml", ".rb", ".go", ".java", ".php", ".cs"}

# Secret patterns — applied to EVERY file regardless of language
_SECRET_PATTERNS: list[tuple] = [
    # AWS Access Key ID — 20-char AKIA… string
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'critical',
     'Hardcoded AWS Access Key ID',
     'AWS Access Key ID found in source code. Revoke and rotate immediately via AWS IAM console.'),
    # AWS Secret Access Key — 40-char base64 value after aws_secret… variable
    (re.compile(r'(?i)\b\w*aws_secret\w*\s*=\s*["\'][A-Za-z0-9/+=]{35,}["\']'), 'critical',
     'Hardcoded AWS Secret Access Key',
     'AWS Secret Access Key in source code. Revoke immediately and use IAM roles or environment variables.'),
    # Stripe live key
    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), 'critical',
     'Hardcoded Stripe Live Secret Key',
     'Stripe live key found. Revoke at dashboard.stripe.com → Developers → API keys immediately.'),
    # GitHub PAT
    (re.compile(r'ghp_[0-9a-zA-Z]{36}'), 'critical',
     'Hardcoded GitHub Personal Access Token',
     'GitHub PAT found. Revoke at github.com/settings/tokens immediately.'),
    # Generic PEM private keys
    (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), 'critical',
     'Private key material in source code',
     'Private key found in source code. Remove and rotate immediately — assume it is compromised.'),
    # Variables whose NAME contains a secret keyword assigned a string value
    (re.compile(r'(?i)\b\w*(?:password|passwd|secret|api_?key|access_?key|auth_?token|db_?pass)\w*\s*=\s*["\'][^"\']{4,}["\']'), 'critical',
     'Hardcoded credential in source variable',
     'Sensitive credential hardcoded in source code. Use environment variables or a secrets manager instead.'),
    # Google API key prefix
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 'critical',
     'Hardcoded Google API Key',
     'Google API key found. Revoke at console.cloud.google.com → Credentials.'),
    # Slack tokens
    (re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'), 'critical',
     'Hardcoded Slack Token',
     'Slack token found in source code. Revoke at api.slack.com/apps.'),
]

# JavaScript/TypeScript/JSX patterns
_JS_PATTERNS: list[tuple] = [
    (re.compile(r'\beval\s*\('), 'high',
     'Dangerous eval() — arbitrary code execution',
     'eval() executes arbitrary code strings. If the argument comes from user input this is RCE. '
     'Replace with JSON.parse() for data, or refactor to avoid dynamic code execution entirely.'),
    (re.compile(r'dangerouslySetInnerHTML'), 'high',
     'React dangerouslySetInnerHTML — XSS',
     'dangerouslySetInnerHTML bypasses React\'s built-in XSS escaping. '
     'Sanitize HTML with DOMPurify before passing it: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(val) }}'),
    (re.compile(r'\.innerHTML\s*=(?!=)'), 'high',
     'Direct innerHTML assignment — XSS',
     'Setting innerHTML with user-controlled data enables stored or reflected XSS. '
     'Use element.textContent for text, or DOMPurify.sanitize() before assigning innerHTML.'),
    (re.compile(r'document\.write\s*\('), 'high',
     'document.write() — XSS risk',
     'document.write() with user-controlled input enables XSS. '
     'Avoid it entirely — use DOM manipulation methods instead.'),
    (re.compile(r'new\s+Function\s*\('), 'high',
     'Dynamic Function constructor — code injection',
     'new Function() constructs and executes code dynamically — equivalent to eval(). '
     'Avoid or validate and whitelist inputs strictly.'),
    (re.compile(r'setTimeout\s*\(\s*(?:["\']|`)[^)]{3}'), 'medium',
     'setTimeout with string argument — implicit eval',
     'Passing a string to setTimeout is equivalent to eval(). '
     'Use an arrow function: setTimeout(() => yourFn(), ms)'),
    (re.compile(r'setInterval\s*\(\s*(?:["\']|`)[^)]{3}'), 'medium',
     'setInterval with string argument — implicit eval',
     'Passing a string to setInterval is equivalent to eval(). '
     'Use an arrow function: setInterval(() => yourFn(), ms)'),
    (re.compile(r'__html\s*:'), 'medium',
     '__html prop passed to dangerouslySetInnerHTML',
     '__html value is rendered as raw HTML by React. '
     'Ensure it is sanitized with DOMPurify.sanitize() before use.'),
    (re.compile(r'location\.href\s*=\s*\w'), 'medium',
     'Open redirect via location.href',
     'Setting location.href with user-controlled input enables open redirect attacks. '
     'Validate the URL against an allowlist before redirecting.'),
    (re.compile(r'postMessage\s*\([^,]+,\s*["\*]'), 'low',
     'postMessage with wildcard or unvalidated origin',
     'Using "*" as targetOrigin in postMessage leaks data to any listening frame. '
     'Always specify the exact target origin.'),
]

# Python-specific patterns
_PY_PATTERNS: list[tuple] = [
    (re.compile(r'\bexec\s*\('), 'high',
     'exec() — arbitrary code execution',
     'exec() evaluates arbitrary Python code strings. Never use with user-controlled input.'),
    (re.compile(r'\beval\s*\('), 'high',
     'eval() — arbitrary code execution',
     'eval() evaluates arbitrary Python expressions. Never use with user-controlled input.'),
    (re.compile(r'\bos\.system\s*\('), 'high',
     'os.system() — shell command injection',
     'os.system() passes the string directly to the shell. '
     'Use subprocess.run([...], shell=False) with a list to prevent injection.'),
    (re.compile(r'subprocess\.[a-zA-Z]+\s*\([^)]*shell\s*=\s*True'), 'high',
     'subprocess with shell=True — command injection',
     'shell=True allows shell metacharacters to be injected. '
     'Pass a list of arguments and use shell=False (the default).'),
    (re.compile(r'\bpickle\.loads?\s*\('), 'high',
     'Insecure pickle deserialization',
     'pickle.load(s) with untrusted data allows arbitrary code execution. '
     'Use JSON, MessagePack, or another safe serialization format.'),
    (re.compile(r'\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)'), 'medium',
     'Unsafe yaml.load() — arbitrary code execution',
     'yaml.load() without SafeLoader can execute arbitrary Python. '
     'Replace with yaml.safe_load() or pass Loader=yaml.SafeLoader explicitly.'),
    (re.compile(r'\bhashlib\.(md5|sha1)\s*\('), 'medium',
     'Weak hash algorithm (MD5/SHA-1)',
     'MD5 and SHA-1 are cryptographically broken. '
     'Use hashlib.sha256() or hashlib.sha3_256() for security-sensitive hashing.'),
    (re.compile(r'\brandom\.(random|randint|choice|shuffle|randbytes)\s*\('), 'low',
     'Insecure random — not cryptographically safe',
     'The random module is not cryptographically secure. '
     'Use the secrets module for tokens, passwords, or nonces.'),
    (re.compile(r'SELECT\s+.+\s+FROM\s+.+\s*\+\s*\w|\bformat\s*\(.*SELECT'), 'high',
     'Possible SQL injection via string concatenation',
     'Building SQL queries with string concatenation or format() enables SQL injection. '
     'Use parameterized queries: cursor.execute(sql, (param,))'),
]

_EXT_LANG: dict[str, str] = {
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


# ── Language detection — single rglob pass ────────────────────────────────────

def _detect_languages(root: Path) -> set[str]:
    """One rglob pass over all files — O(N) instead of O(N × extensions)."""
    langs: set[str] = set()
    for f in root.rglob("*"):
        if f.is_file():
            lang = _EXT_LANG.get(f.suffix.lower())
            if lang:
                langs.add(lang)
    return langs


def _build_semgrep_rulesets(langs: set[str]) -> list[str]:
    rulesets: list[str] = list(_ALWAYS_RULESETS)
    for lang in langs:
        for rs in _RULESETS_BY_LANG.get(lang, []):
            if rs not in rulesets:
                rulesets.append(rs)
    return rulesets


# ── Deduplication ─────────────────────────────────────────────────────────────

def _dedup_sast(vulns: list[dict]) -> list[dict]:
    """
    Remove duplicate findings across tools.
    Key: (file, line_number) — if Bandit and Semgrep both flag the same line,
    keep the higher-severity one (usually Bandit since it has Python context).
    """
    seen: dict[tuple, dict] = {}
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for v in vulns:
        ev   = v.get("evidence", "")
        line = v.get("line_number", 0)
        m    = re.match(r"([^:\n]+):(\d+)", ev)
        key  = (m.group(1), m.group(2)) if m else (ev[:60], str(line))
        if key in seen:
            if order.get(v["severity"], 5) < order.get(seen[key]["severity"], 5):
                seen[key] = v
        else:
            seen[key] = v
    return list(seen.values())


# ── Result builder ────────────────────────────────────────────────────────────

def _result(vulns: list[dict], meta: dict) -> dict:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns.sort(key=lambda v: (order.get(v.get("severity", "info"), 5),
                               -v.get("confidence", 0)))
    return {
        "scan_type":       "sast",
        "target":          "uploaded_code",
        "vulnerabilities": vulns,
        "meta":            meta,
    }


# ── Tool runners — each returns (list[dict], dict) ────────────────────────────

def _run_bandit(bandit_cmd: str, tmp_dir: str) -> tuple[list[dict], dict]:
    """
    Bandit — Python security linter.
    Returns (findings, meta_partial).
    """
    findings: list[dict] = []
    meta: dict = {}

    if " " in bandit_cmd:
        cmd = bandit_cmd.split() + ["-r", tmp_dir, "-f", "json", "--quiet", "-l"]
    else:
        cmd = [bandit_cmd, "-r", tmp_dir, "-f", "json", "--quiet", "-l"]

    logger.info("SAST Bandit | dir=%s", tmp_dir)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=BANDIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        logger.warning("Bandit timed out after %ds", BANDIT_TIMEOUT)
        return findings, {"bandit_error": f"Timed out after {BANDIT_TIMEOUT}s"}

    stdout = proc.stdout.strip()
    if not stdout:
        logger.warning("Bandit produced no output | stderr=%s", proc.stderr[:300])
        return findings, {"bandit_note": "No output (check installation)"}

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        logger.warning("Bandit JSON parse error: %s", exc)
        return findings, {"bandit_error": f"JSON parse failed: {exc}"}

    sev_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    conf_w  = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    count   = 0

    for issue in data.get("results", []):
        sev     = sev_map.get(issue.get("issue_severity", "LOW"), "low")
        conf    = conf_w.get(issue.get("issue_confidence", "LOW"), 1)
        fname   = issue.get("filename", "").replace(tmp_dir, "").lstrip("/\\")
        snippet = (issue.get("code") or "").strip()[:400]
        cwe_id  = str(issue.get("issue_cwe", {}).get("id", "") or "")

        findings.append({
            "check":       f"bandit_{issue.get('test_id', 'B000')}",
            "title":       f"[Bandit] {issue.get('issue_text', 'Security Issue')}",
            "severity":    sev,
            "description": (
                f"{issue.get('issue_text', '')} "
                f"— test: {issue.get('test_id', '')} / {issue.get('test_name', '')} "
                f"— confidence: {issue.get('issue_confidence', '?')}"
            ),
            "evidence":    f"{fname}:{issue.get('line_number', '?')}\n{snippet}",
            "remediation": issue.get("more_info", "See Bandit docs."),
            "cwe":         cwe_id,
            "line_number": int(issue.get("line_number", 0) or 0),
            "confidence":  conf,
            "source":      "bandit",
        })
        count += 1

    meta["bandit_issues"] = count
    logger.info("Bandit | issues=%d", count)
    return findings, meta


def _run_semgrep(
    semgrep_cmd: str,
    tmp_dir: str,
    rulesets: list[str],
) -> tuple[list[dict], dict]:
    """
    Semgrep — multi-language OWASP/CWE/secrets scanner.
    Returns (findings, meta_partial).
    Deduplication against Bandit is done in the caller after all tools finish.
    """
    findings: list[dict] = []
    meta: dict = {}

    config_args: list[str] = []
    for rs in rulesets:
        config_args += ["--config", rs]

    cmd = [
        semgrep_cmd, "scan",
        *config_args,
        "--json", "--quiet", "--no-git-ignore",
        "--timeout", "30",
        tmp_dir,
    ]
    logger.info("SAST Semgrep | rulesets=%s", rulesets)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SEMGREP_TIMEOUT)
    except subprocess.TimeoutExpired:
        logger.warning("Semgrep timed out after %ds", SEMGREP_TIMEOUT)
        return findings, {"semgrep_error": f"Timed out after {SEMGREP_TIMEOUT}s"}

    stdout = proc.stdout.strip()
    if not stdout:
        if proc.stderr:
            logger.debug("Semgrep stderr: %s", proc.stderr[:400])
        return findings, {"semgrep_note": "No findings or tool error"}

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        logger.warning("Semgrep JSON parse error: %s", exc)
        return findings, {"semgrep_error": f"JSON parse failed: {exc}"}

    results  = data.get("results", [])
    sev_map  = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    count    = 0

    for r in results:
        path     = r.get("path", "").replace(tmp_dir, "").lstrip("/\\")
        line     = str(r.get("start", {}).get("line", "0"))
        sev      = sev_map.get(r.get("extra", {}).get("severity", "WARNING"), "medium")
        msg      = r.get("extra", {}).get("message") or r.get("check_id", "Security Issue")
        snippet  = (r.get("extra", {}).get("lines") or "").strip()[:400]
        fix      = (r.get("extra", {}).get("fix") or
                    r.get("extra", {}).get("fix_regex", {}).get("replacement", ""))
        cwe_list = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        cwe      = str(cwe_list[0]) if cwe_list else ""
        owasp    = r.get("extra", {}).get("metadata", {}).get("owasp", "")
        check_id = r.get("check_id", "")

        # Escalate hardcoded secrets to critical
        if any(kw in check_id.lower() for kw in ("secret", "credential", "api-key", "token", "password")):
            sev = "critical"

        findings.append({
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
        count += 1

    meta["semgrep_issues"] = count
    logger.info("Semgrep | issues=%d | rulesets=%d", count, len(rulesets))
    return findings, meta


def _run_gitleaks(gitleaks_cmd: str, tmp_dir: str) -> tuple[list[dict], dict]:
    """
    Gitleaks — detects 150+ hardcoded secret types in source code.
    Runs on extracted directory (no git history needed — --no-git flag).
    Returns (findings, meta_partial).
    """
    findings: list[dict] = []
    meta: dict = {}

    # mkstemp — atomic file creation, no TOCTOU race condition
    fd, tmp_report = tempfile.mkstemp(suffix="_gitleaks.json")
    os.close(fd)

    try:
        cmd = [
            gitleaks_cmd, "detect",
            "--source",        tmp_dir,
            "--report-format", "json",
            "--report-path",   tmp_report,
            "--no-git",        # scan files directly, no git history needed
            "--exit-code",     "0",  # always exit 0 (findings don't fail the process)
        ]
        logger.info("SAST Gitleaks | dir=%s", tmp_dir)
        proc = subprocess.run(cmd, capture_output=True, timeout=GITLEAKS_TIMEOUT)

        if proc.returncode not in (0, 1):
            logger.debug("Gitleaks exited %d: %s", proc.returncode,
                         proc.stderr.decode(errors="replace")[:200])

        # Report file may be empty ("null") when no secrets found
        try:
            raw = Path(tmp_report).read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return findings, meta

        if not raw or raw == "null":
            meta["gitleaks_issues"] = 0
            return findings, meta

        try:
            leak_list = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("Gitleaks JSON parse error: %s", exc)
            return findings, {"gitleaks_error": f"JSON parse failed: {exc}"}

        if not isinstance(leak_list, list):
            return findings, meta

        count = 0
        for leak in leak_list:
            rule_id = leak.get("RuleID", "secret")
            secret  = leak.get("Secret", "")
            # Mask most of the secret — show only first 4 and last 4 chars
            masked  = (secret[:4] + "****" + secret[-4:]) if len(secret) > 8 else "****"
            file_p  = leak.get("File", "").replace(tmp_dir, "").lstrip("/\\")
            line    = leak.get("StartLine", 0)
            match   = leak.get("Match", "")[:200]

            findings.append({
                "check":       f"gitleaks_{rule_id}",
                "title":       f"[Gitleaks] Hardcoded secret: {rule_id}",
                "severity":    "critical",
                "description": (
                    f"Hardcoded secret detected — rule: {rule_id}. "
                    f"Masked value: {masked}"
                ),
                "evidence":    f"{file_p}:{line}\n{match}",
                "remediation": (
                    "Remove the secret from source code immediately. "
                    "Use environment variables (.env) instead. "
                    "If the code was ever committed or deployed, revoke and rotate "
                    "the credential immediately — assume it is compromised."
                ),
                "line_number": int(line) if isinstance(line, int) else 0,
                "confidence":  3,
                "source":      "gitleaks",
                "rule_id":     rule_id,
            })
            count += 1

        meta["gitleaks_issues"] = count
        logger.info("Gitleaks | secrets_found=%d", count)

    except subprocess.TimeoutExpired:
        logger.warning("Gitleaks timed out after %ds", GITLEAKS_TIMEOUT)
        meta["gitleaks_error"] = f"Timed out after {GITLEAKS_TIMEOUT}s"
    except Exception as exc:
        logger.warning("Gitleaks unexpected error: %s", exc)
        meta["gitleaks_error"] = str(exc)
    finally:
        try:
            os.unlink(tmp_report)
        except OSError:
            pass

    return findings, meta


# ── Built-in scanner — no external tools required ────────────────────────────

def _run_builtin_scan(root: Path) -> tuple[list[dict], dict]:
    """
    Regex-based scanner that runs regardless of whether Semgrep/Gitleaks/Bandit
    are installed. Covers hardcoded secrets (all files), JS/JSX dangerous
    patterns, and Python injection sinks.
    """
    findings: list[dict] = []
    files_checked = 0

    for fpath in root.rglob("*"):
        if not fpath.is_file():
            continue
        if fpath.suffix.lower() not in _ALL_EXTS:
            continue

        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if len(content) > 1_000_000:
            content = content[:1_000_000]

        files_checked += 1
        rel_path = str(fpath.relative_to(root)).replace("\\", "/")
        lines    = content.splitlines()
        ext      = fpath.suffix.lower()

        def _make_finding(sev: str, title: str, desc: str, category: str, m: re.Match) -> dict:
            lineno  = content[:m.start()].count("\n") + 1
            snippet = lines[lineno - 1].strip()[:200] if lineno <= len(lines) else ""
            slug    = re.sub(r"[^a-z0-9]+", "_", title.lower())[:40]
            return {
                "check":       f"builtin_{category}_{slug}",
                "title":       f"[Built-in] {title}",
                "severity":    sev,
                "description": desc,
                "evidence":    f"{rel_path}:{lineno}\n{snippet}" if snippet else f"{rel_path}:{lineno}",
                "remediation": desc,
                "line_number": lineno,
                "confidence":  3,
                "source":      "builtin",
            }

        # Secrets — all file types
        for _pat, _sev, _title, _desc in _SECRET_PATTERNS:
            for m in _pat.finditer(content):
                findings.append(_make_finding(_sev, _title, _desc, "secret", m))

        # JS/TS/JSX — XSS and injection sinks
        if ext in _JS_EXTS:
            for _pat, _sev, _title, _desc in _JS_PATTERNS:
                for m in _pat.finditer(content):
                    findings.append(_make_finding(_sev, _title, _desc, "js", m))

        # Python — injection and dangerous function calls
        if ext in _PY_EXTS:
            for _pat, _sev, _title, _desc in _PY_PATTERNS:
                for m in _pat.finditer(content):
                    findings.append(_make_finding(_sev, _title, _desc, "py", m))

    meta = {
        "builtin_issues":        len(findings),
        "builtin_files_checked": files_checked,
    }
    logger.info("Built-in scan | files=%d issues=%d", files_checked, len(findings))
    return findings, meta


# ── Main entry point ──────────────────────────────────────────────────────────

def run_sast_scan(file_path: str) -> dict:
    """
    Scan an uploaded ZIP with Bandit + Semgrep + Gitleaks running in parallel.

    Returns:
        { "scan_type": "sast", "vulnerabilities": [...], "meta": {...} }
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

        # Check ZIP file size before extracting (MAX_ZIP_SIZE was defined but never used)
        zip_size = os.path.getsize(file_path)
        if zip_size > MAX_ZIP_SIZE:
            raise RuntimeError(
                f"ZIP file is {zip_size // (1024*1024)} MB — limit is "
                f"{MAX_ZIP_SIZE // (1024*1024)} MB."
            )

        tmp_dir = tempfile.mkdtemp(prefix="cybrain_sast_")

        with zipfile.ZipFile(file_path, "r") as zf:
            members = zf.namelist()
            if len(members) > MAX_FILES:
                raise RuntimeError(
                    f"ZIP contains {len(members)} files — limit is {MAX_FILES}."
                )

            # Path traversal guard — check for absolute paths, `..`, and symlinks
            for info in zf.infolist():
                norm = os.path.normpath(info.filename)
                if os.path.isabs(norm) or norm.startswith(".."):
                    raise RuntimeError(f"Unsafe path in ZIP: {info.filename}")
                # Unix attribute upper 16 bits encode file type: 0xA000 = symlink
                if (info.external_attr >> 16) & 0xFFFF == 0xA1ED:
                    raise RuntimeError(f"Symlink in ZIP rejected: {info.filename}")

            # ZIP bomb guard
            total_size = sum(i.file_size for i in zf.infolist())
            if total_size > MAX_UNCOMPRESSED:
                raise RuntimeError(
                    f"ZIP extracted size ({total_size // (1024*1024)} MB) exceeds "
                    f"limit ({MAX_UNCOMPRESSED // (1024*1024)} MB). Possible ZIP bomb."
                )

            zf.extractall(tmp_dir)

        root = Path(tmp_dir)

        # ── 2. Detect languages (single rglob pass) ───────────────────────────
        langs = _detect_languages(root)
        meta["languages"] = sorted(langs)

        all_files = [f for f in root.rglob("*") if f.is_file()]
        meta["files_scanned"] = len(all_files)

        if not all_files:
            meta["note"] = "No source files found in ZIP."
            return _result(vulns, meta)

        # ── 3. Discover available tools ───────────────────────────────────────
        bandit_cmd: str | None = None
        py_files = list(root.rglob("*.py"))
        if py_files:
            bandit_cmd = shutil.which("bandit") or shutil.which("bandit3")
            if not bandit_cmd:
                # Use the same Python interpreter that's running right now
                try:
                    subprocess.run(
                        [sys.executable, "-m", "bandit", "--version"],
                        capture_output=True, timeout=5, check=True,
                    )
                    bandit_cmd = f"{sys.executable} -m bandit"
                except Exception:
                    pass

        semgrep_cmd  = shutil.which("semgrep")
        gitleaks_cmd = shutil.which("gitleaks")

        rulesets: list[str] = []
        if semgrep_cmd:
            rulesets = _build_semgrep_rulesets(langs)
            meta["semgrep_rulesets"] = rulesets

        if not bandit_cmd:
            meta["bandit_note"] = "Bandit not installed — pip install bandit"
        if not semgrep_cmd:
            meta["semgrep_note"] = "Semgrep not installed — pip install semgrep"
        if not gitleaks_cmd:
            meta["gitleaks_note"] = (
                "Gitleaks not installed — "
                "https://github.com/gitleaks/gitleaks/releases"
            )

        # ── 4. Built-in scanner — always runs, no tools required ─────────────
        try:
            builtin_findings, builtin_meta = _run_builtin_scan(root)
            vulns.extend(builtin_findings)
            meta.update(builtin_meta)
            if builtin_findings:
                meta["tools"].append("builtin")
        except Exception as exc:
            logger.warning("SAST[builtin] failed: %s", exc)
            meta["builtin_error"] = str(exc)

        # ── 5. External tools — run concurrently when available ───────────────
        futures: dict = {}
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="sast") as pool:
            if bandit_cmd:
                futures["bandit"] = pool.submit(_run_bandit, bandit_cmd, tmp_dir)
            if semgrep_cmd:
                futures["semgrep"] = pool.submit(_run_semgrep, semgrep_cmd, tmp_dir, rulesets)
            if gitleaks_cmd:
                futures["gitleaks"] = pool.submit(_run_gitleaks, gitleaks_cmd, tmp_dir)

            for name, fut in futures.items():
                try:
                    tool_findings, tool_meta = fut.result()
                    vulns.extend(tool_findings)
                    meta.update(tool_meta)
                    meta["tools"].append(name)
                except Exception as exc:
                    logger.warning("SAST[%s] failed: %s", name, exc)
                    meta[f"{name}_error"] = str(exc)

        # ── 6. Cross-tool deduplication + final count ─────────────────────────
        vulns = _dedup_sast(vulns)
        meta["issues_found"] = len(vulns)

    except RuntimeError:
        raise
    except Exception as exc:
        logger.warning("SAST scan unexpected error: %s", exc)
        meta["error"] = str(exc)
    finally:
        if tmp_dir and os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return _result(vulns, meta)
