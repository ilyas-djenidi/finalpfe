# CYBRAIN — PFE Presentation Prompt for Claude

Use the following prompt to have Claude generate a deep, thorough explanation of this project
for your PFE jury, professor, or technical audience.

---

## THE PROMPT

```
You are a senior cybersecurity engineer and university professor reviewing a Final Year Project
(PFE — Projet de Fin d'Études) for a Master 2 in Information Security at the University of
Mohamed Boudiaf, M'sila, Algeria.

The project is called **CYBRAIN** — an AI-powered cybersecurity intelligence platform.
Please write an exhaustive, deeply technical presentation of this project. Cover every aspect
listed below in full detail. This will be used in front of a jury panel, so be thorough,
precise, and impressive. Use professional academic and technical language.

---

## PROJECT IDENTITY

- Name: CYBRAIN (Cyber Brain)
- Version: 2.1
- Type: Enterprise Security Intelligence Platform (SaaS)
- Authors: PFE Master 2 — Information Security, University of Mohamed Boudiaf, M'sila, Algeria
- Purpose: Multi-vector vulnerability scanning, analysis, and AI-powered security reporting
- Deployment: React (Netlify) + Flask (Render.com) + Python scanning engines
- GitHub: https://github.com/ilyas-djenidi/cybrain

---

## 1. PROJECT OVERVIEW & MOTIVATION

Explain why this project exists. Cover:
- The global rise of cyberattacks and the shortage of security tools accessible to SMEs
- The OWASP Top 10 2025 as the gold standard for web security
- How traditional scanners (Nessus, Burp Suite) are expensive and complex
- How CYBRAIN democratises professional-grade security scanning
- The academic contribution: combining automated OWASP testing, SAST, network recon,
  Apache hardening, and AI analysis in a single unified platform
- Benefits to developers, sysadmins, students, and security teams
- The ethical design: private IP blocking, educational-use-only notices, no destructive payloads

---

## 2. ARCHITECTURE & TECHNOLOGY STACK

Explain the full technical architecture in depth:

### Frontend (React + Vite)
- React 18 with functional components and hooks
- Vite as build tool (faster than CRA, ESBuild compiler)
- Tailwind CSS for utility-first styling
- Axios for HTTP requests to the Flask backend
- React Router for SPA navigation between: WebScan, ApacheScan, CodeScan, NetworkScan,
  Report, Login, Register, Pricing pages
- Custom hook `useScanner.js` encapsulating all API calls with loading/error state
- `logicProtection.js` for centralized constants, severity ordering, and API endpoints
- Key components: ScannerSuite, ResultsPanel, ScanProgress, ChatBot, AnimatedCubes,
  SeverityBadge, TabCards, Navbar

### Backend (Flask + Python)
- Flask 3.x with flask-cors for CORS management
- Gunicorn for production WSGI serving on Render.com
- python-dotenv for environment variables (GEMINI_API_KEY)
- Modular architecture: each scan type is a separate Python module
- Thread-safe design: threading.Lock() on all shared findings lists
- Concurrent scanning: ThreadPoolExecutor with 8 workers for parallel checks
- AI response cache: MD5-keyed dict with 5-minute TTL, max 200 entries

### Scanning Engines (7 Python modules)
1. url_scanner.py — orchestrates web vulnerability scanning
2. owasp_checks.py — OWASP Top 10 2025 implementation (1000+ lines)
3. detect_apache_misconf.py — Apache configuration hardening
4. code_analyzer.py — Static Application Security Testing (SAST)
5. network_scanner.py — network scan orchestrator
6. network_recon.py — network reconnaissance (DNS, OS fingerprint, ports)
7. network_vulns.py — service-level vulnerability detection

### AI Engine (ai_agent.py)
- Primary: Google Gemini 2.0 Flash via google-generativeai SDK
- Fallback: Pure Python offline rule-based engine (zero quota, always available)
- MD5-based response caching to reduce API costs
- 5 AI capabilities: chat, findings analysis, code fixing, config hardening, compliance mapping

---

## 3. SCANNING MODULES — DEEP TECHNICAL EXPLANATION

### 3a. Web Vulnerability Scanner (url_scanner.py + owasp_checks.py)

Explain the full scanning pipeline in detail:

**Step 1 — Target Validation**
- Private IP blocklist: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8,
  169.254.0.0/16, 100.64.0.0/10
- Blocked hostnames: localhost, metadata.google.internal, 169.254.169.254
- URL normalization: auto-prefix http://, strip fragments

**Step 2 — Connection Verification**
- 3 retry attempts with 1.5 second exponential backoff
- Follows redirects (captures final URL after redirect chains)

**Step 3 — Target Spidering**
- Regex-based link extraction from HTML
- Form discovery: action, method, input field names
- Parameter discovery from URL query strings
- SPA detection: if React/Angular/Vue bundles detected, adds /api, /v1 endpoints

**Step 4 — Core OWASP Checks (parallel, 8 threads)**

OWASP A01 — Broken Access Control:
- IDOR: tests /api/users/1 endpoints for PII in JSON responses; compares with invalid ID to confirm
- Admin panel discovery: 12 paths including /admin, /wp-admin, /console
- CSRF: checks HTML forms for missing _token / csrf / xsrf fields
- Forced browsing: /backup, /test, /dev, /staging
- HTTP method override headers: X-HTTP-Method-Override: DELETE

OWASP A02 — Security Misconfiguration:
- 8 required security headers checked: CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
  X-XSS-Protection, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy
- Server technology disclosure: Server, X-Powered-By, X-AspNet-Version headers
- 60+ sensitive file paths tested in parallel (20 threads): .env, .git/config, backup.sql,
  phpinfo.php, /actuator/env, /.ssh/id_rsa, docker-compose.yml, etc.
- Smart soft-404 detection: HTML responses to sensitive file paths are ignored
- Directory listing: "Index of /" pattern
- CORS wildcard (Access-Control-Allow-Origin: *)
- CORS with credentials misconfiguration

OWASP A03 — Software Supply Chain:
- Version detection for jQuery, Bootstrap, Angular, React, Apache, Nginx, PHP, Log4j, Struts
- Critical version matching: Log4j 2.0-2.14 → CVE-2021-44228 (Log4Shell, CVSS 10.0)
- External scripts without Subresource Integrity (SRI) hashes

OWASP A04 — Cryptographic Failures:
- HTTP protocol (no TLS): flags plaintext traffic
- Insecure cookie flags: missing HttpOnly, Secure, SameSite
- JWT analysis: base64 decode, alg:none detection (signature bypass), weak HS256
- Sensitive data in URL parameters: password=, token=, api_key=

OWASP A05 — Injection:
- SQL Injection (error-based): 10 payloads × form params and URL params; matches 20+ DB error signatures
- SQL Injection (POST forms): discovers and tests all form fields
- SQL Injection (auth bypass): OR 1=1, admin'--, classic patterns on /login endpoints
- SQL Injection (boolean-blind): compares true/false condition responses to baseline;
  flags if false diverges by >100 bytes while true stays within 20 bytes of baseline
- SQL Injection (time-based): SLEEP(3), WAITFOR DELAY with baseline comparison
  to eliminate slow-server false positives
- XSS (reflected): 17 payloads including CSP bypasses, event handlers, DOM triggers
- XSS (stored): submits payload to /api/comments, /api/posts, etc.; checks read endpoints
- XSS (DOM): source→sink pattern analysis in JavaScript (location.hash → innerHTML)
- XSS (CSP bypass): unsafe-inline, unsafe-eval, wildcard script-src, JSONP CDN bypass
- Command injection: 12 Unix+Windows payloads; matches OS output signatures
- SSTI: 15 template expressions for Jinja2, Twig, Freemarker, Velocity, Mako, Smarty
- LDAP injection: filter bypass payloads
- Path traversal / LFI: 11 encodings including double-encoded, null byte, UNC paths

OWASP A06 — Insecure Design:
- Rate limiting: 12 failed logins; flags if no HTTP 429 returned
- User enumeration via password reset: compares response sizes for valid vs invalid emails

OWASP A07 — Authentication Failures:
- 12 default credential pairs × 4 login paths in parallel thread pool
- Weak session token detection: short length, pure numeric, pure alpha, known test values

OWASP A08 — Integrity Failures:
- Java serialized object in response (AC ED 00 05 magic bytes, base64 rO0AB)
- PHP serialized objects (O:N: pattern)
- .NET ViewState without MAC validation
- Serialized objects in cookies (base64 decoded)

OWASP A09 — Security Logging Failures:
- Verbose error messages: stack traces, werkzeug debugger, Django debug mode
- Exposed log files: /logs/access.log, /error.log, /debug.log (with SPA soft-404 filtering)

OWASP A10 — Exception Handling + SSRF:
- 6 edge-case inputs: special chars, 5000-char string, null byte, NaN, undefined, invalid encoding
- SSRF: 15 payloads × 20 URL parameters; tests internal IPs, AWS metadata, GCP metadata,
  cloud provider ranges

**Step 5 — Extended Checks (sequential)**
These are injected as methods onto OWASPChecker at runtime via Python's types.MethodType:
- Race Condition (CWE-362): 15 concurrent POST requests to /api/redeem, /api/vote, /api/transfer;
  flags if 2+ succeed simultaneously
- Mass Assignment (CWE-915): sends isAdmin=true, role=admin, balance=99999 in registration payload;
  checks reflection in response
- Log4Shell (CVE-2021-44228): JNDI canary string in 9 HTTP headers; Spring4Shell class-binding probe
- GraphQL: introspection schema exposure, batch query abuse, old API version detection

**Step 6 — Post-processing**
- Deduplication by title (set-based)
- Severity sorting: CRITICAL → HIGH → MEDIUM → LOW → INFO
- HTML-formatted message generation with CWE links, CVSS scores, OWASP IDs
- Report generation: Markdown + CSV + JSON

---

### 3b. Apache Misconfiguration Detector (detect_apache_misconf.py)

Explain the 22 security checks performed on Apache httpd.conf / .htaccess files:

The detector performs both static analysis (regex pattern matching) and
semantic analysis (tag matching, dependency checking) on the config text.

Key checks include:
1. Directory listing (Options +Indexes) — CWE-548
2. Server signature/token disclosure — CWE-693
3. Weak SSL/TLS protocols: SSLv2, SSLv3, TLSv1.0, TLSv1.1 — CWE-327
4. Weak cipher suites: NULL, EXPORT, RC4, DES, anon — CWE-327
5. TRACE method enabled (XST attack vector) — CWE-200
6. 5 missing HTTP security headers checked individually — CWE-693
7. LimitRequestBody = 0 (unlimited upload → DoS) — CWE-770
8. Timeout too large (Slowloris DoS) — CWE-770
9. FollowSymLinks without SymLinksIfOwnerMatch — CWE-367
10. AllowOverride All (too permissive) — CWE-693
11. Cleartext password in config file — CWE-798 (CRITICAL)
12. AuthUserFile security — CWE-276
13. CORS wildcard Allow-Origin — CWE-942
14. mod_status publicly exposed — CWE-200
15. mod_info publicly exposed — CWE-200
16. CGI script execution — CWE-94
17. PHP version exposure via AddType — CWE-200
18. Missing access log configuration — CWE-778
19. Missing error log configuration — CWE-778
20. Deprecated mod_php — CWE-1059
21. SSLVerifyClient none — CWE-295
22. HTTP/2 Push enabled (header leak) — CWE-200

Additional: deprecated directive detection (Order/Allow/Deny/Satisfy → replaced by Require),
syntax validation (unclosed <VirtualHost>, <Directory> tags), module dependency checks
(e.g., using mod_rewrite without LoadModule).

---

### 3c. Static Application Security Testing — SAST (code_analyzer.py)

Explain the 20+ vulnerability patterns detected across PHP, Python, JavaScript, and Java:
- SQL Injection: string concatenation in queries
- XSS: echo without htmlspecialchars, innerHTML assignment
- Command injection: system(), exec(), shell_exec() with variables
- Hardcoded credentials: password = "literal", SECRET_KEY = "..."
- Weak cryptography: md5(), sha1(), DES usage
- Path traversal: file_get_contents() with user input
- Insecure deserialization: unserialize(), pickle.loads()
- JWT issues: jwt.decode() without verify=True
- LDAP injection: ldap_search() with unsanitized input
- XML injection: SimpleXML / XMLParser with external entities
- JavaScript prototype pollution: Object.assign() with user data
- CORS misconfiguration: res.header('Access-Control-Allow-Origin', '*')
- Insecure randomness: Math.random() for security tokens
- Eval injection: eval() with user input
- Template injection: render_template_string() with user data

The analyzer detects language automatically and provides line numbers for each finding.
It also generates AI-powered fix suggestions via the Gemini integration.

---

### 3d. Network Security Assessment (network_scanner.py + network_recon.py + network_vulns.py)

Explain the network scanning pipeline:

**Reconnaissance Phase (network_recon.py)**
- DNS resolution: A, AAAA, MX, NS, TXT, CNAME records
- Reverse DNS lookup
- IPv6 detection
- GeoIP (country/AS) lookup via ipapi.co
- OS fingerprinting: banner analysis (SSH, HTTP headers, FTP), TTL-based OS hints
- Traceroute hop count estimation

**Port Scanning**
- 80+ common ports with service mapping
- Parallel socket connections (1.5s timeout per port)
- SSL/TLS probing on HTTPS ports
- Banner grabbing on open ports

**Vulnerability Detection (network_vulns.py)**
- Service version extraction from banners
- SSH weak algorithms: diffie-hellman-group1-sha1, arcfour
- FTP anonymous login detection
- Open dangerous ports: Telnet (23), RDP (3389), SMB (445), Redis (6379), MongoDB (27017)
- Outdated service version detection with CVE mapping
- MySQL/PostgreSQL without password detection
- SMTP open relay test
- TLS certificate validation

---

### 3e. AI Security Analysis Engine (ai_agent.py)

Explain the dual-mode AI design:

**Online Mode — Gemini 2.0 Flash**
- Google Generative AI SDK integration
- System prompt engineering: role is "professional penetration tester and security engineer"
- 5 specialized AI tasks:
  1. chat(): security Q&A assistant via ChatBot widget
  2. analyze_findings(): generates executive Markdown report from scan findings
  3. fix_code(): rewrites vulnerable code with secure alternatives
  4. fix_apache_config(): hardens Apache config based on scan findings
  5. (implicit): compliance impact analysis (GDPR, PCI-DSS, ISO 27001)

**Offline Mode — Rule-Based Engine**
- CVE database with 20+ entries (SQL Injection, XSS, RCE, SSRF, etc.)
- Each entry contains: CVE ID, CWE, CVSS score, OWASP category, attack scenario, fix command
- Security scoring algorithm: 100 - min(weighted_sum × 3, 95)
  - CRITICAL = weight 10, HIGH = 5, MEDIUM = 2, LOW = 1
- Generates structured Markdown report with executive summary, top 5 prioritized fixes,
  compliance impact table, CVSS breakdown
- Works completely offline with zero API quota consumption

**Cost Optimization**
- MD5 hash of (message + context) as cache key
- 5-minute TTL on cached responses
- LRU-style eviction when cache exceeds 200 entries
- Automatic failover from Gemini to offline engine

---

## 4. ALGORITHMS & DATA STRUCTURES

Explain each algorithm used:

### Boolean-Blind SQLi Detection Algorithm
```
1. Measure baseline response length for param=1
2. Send true condition: param="1 AND 1=1"
3. Send false condition: param="1 AND 1=2"
4. Compute: diff_true = |len(true_response) - baseline|
            diff_false = |len(false_response) - baseline|
5. Flag if: diff_true < 20 AND diff_false > 100 AND both HTTP 200
   (true matches baseline, false diverges significantly)
```

### Time-Based SQLi Detection Algorithm
```
1. Measure baseline response time for param=1
2. Send time-delay payload: SLEEP(3), WAITFOR DELAY, pg_sleep(3)
3. Measure elapsed time
4. Flag if: elapsed >= 3.0s AND elapsed >= baseline + 2.4s
   (requires BOTH absolute threshold AND relative improvement over baseline)
   This eliminates false positives from slow servers
```

### Risk Calculator
```
for level in (CRITICAL, HIGH, MEDIUM, LOW):
    if any finding has this severity:
        return level
return INFO
```

### Security Score (Offline AI Engine)
```
total_weight = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
score = max(0, 100 - min(total_weight × 3, 95))
# CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1
# Score 0 = completely insecure, 100 = perfectly clean
```

### Deduplication
```
seen = set()
for finding in checker.findings:
    if finding["title"] not in seen:
        unique.append(finding)
        seen.add(finding["title"])
```

### Thread-Safe Finding Accumulation
```python
# Every check method uses:
with self._lock:   # threading.Lock
    self.findings.append(finding)
# Prevents race conditions when 8 parallel checks write simultaneously
```

### Dynamic Method Injection (Python Metaprogramming)
```python
# ExtendedChecks methods are bound onto OWASPChecker at runtime:
method = getattr(ExtendedChecks, "_race_condition_check")
setattr(checker, "_race_condition_check", types.MethodType(method, checker))
# This gives extended checks access to checker.session, checker._add(), etc.
```

---

## 5. WHERE AI IS USED

List all AI touchpoints and explain the prompt engineering:

1. **ChatBot widget** — real-time Q&A, understands scan context (current findings injected)
2. **Findings Analyzer** — post-scan: takes all findings as JSON, generates executive report
   with GDPR/PCI-DSS/ISO 27001 compliance impact, top 5 prioritized remediations
3. **Code Fixer** — takes vulnerable source code + language, returns patched version with
   explanations; output saved to /fixed_files/fixed_{filename}
4. **Apache Config Hardener** — takes raw config + finding list, returns hardened config
5. **Offline Fallback** — when Gemini is unavailable: rule-based CVE database generates
   the same report structure locally

**Prompt Engineering technique used:**
- Role injection: "You are Cybrain, a professional penetration tester..."
- Context injection: scan findings (JSON, up to 20 findings) + target URL + scan type
- Output format specification: "Format as professional Markdown. Include executive summary,
  top 5 prioritized fixes with code examples, compliance impact, security score."
- Response caching keyed on MD5(prompt + context)

---

## 6. THEORETICAL FOUNDATIONS

Connect the project to academic theory:

### OWASP Top 10 2025
The Open Web Application Security Project maintains the industry-standard ranking of the
10 most critical web application security risks, updated in 2025 to reflect modern threats.
CYBRAIN covers all 10 categories (A01–A10). Explain each briefly.

### CWE (Common Weakness Enumeration)
A hierarchical taxonomy of software weaknesses maintained by MITRE. Each finding maps to
a specific CWE ID (e.g., CWE-89 SQL Injection, CWE-79 XSS, CWE-22 Path Traversal).

### CVSS v3.1 (Common Vulnerability Scoring System)
A standardized 0–10 severity scoring framework. CYBRAIN assigns CVSS scores to each finding
(e.g., SQL Injection = 9.8, XSS = 7.4). Explain the formula: AV × AC × PR × UI × S × C × I × A.

### SANS Top 25 Most Dangerous Software Errors
CWE-89 = SANS #3, CWE-79 = SANS #2, CWE-78 = SANS #5, etc. CYBRAIN maps findings to
SANS positions alongside OWASP categories.

### Penetration Testing Methodology
CYBRAIN follows the PTES (Penetration Testing Execution Standard) reconnaissance → scanning
→ exploitation detection → reporting phases.

### Static Application Security Testing (SAST)
White-box analysis of source code without execution. CYBRAIN implements pattern-based SAST
using regex matching against known vulnerability signatures. Compare to dynamic (DAST)
testing which executes the application.

### Defense in Depth
The principle that security should be layered. CYBRAIN reflects this by checking multiple
layers: network (ports/services), infrastructure (Apache config), application (OWASP checks),
and code (SAST) simultaneously.

### Threat Modeling (STRIDE)
CYBRAIN findings can be categorized by STRIDE:
- Spoofing → authentication failures (A07)
- Tampering → injection, CSRF (A05, A01)
- Repudiation → logging failures (A09)
- Information Disclosure → sensitive files, CORS (A02)
- Denial of Service → rate limiting, LimitRequestBody (A06, Apache)
- Elevation of Privilege → IDOR, mass assignment, admin panel (A01)

---

## 7. PRO VERSION FEATURES (PREMIUM TIER)

Explain what the Pro version adds beyond the free tier:

- **Continuous Monitoring**: scheduled scans with email/webhook alerts on new findings
- **CI/CD Integration**: GitHub Actions / GitLab CI pipeline integration for automated
  security gates — blocks deployment if CRITICAL findings detected
- **Advanced AI Analysis**: deeper Gemini analysis with code-fix pull request generation,
  compliance audit trails, risk trend graphs
- **Team Collaboration**: multi-user workspaces, role-based access control (RBAC),
  finding assignment and remediation tracking
- **Historical Reports**: scan history comparison, regression detection (new findings
  introduced between scans), CVSS score trending
- **Custom Rule Engine**: user-defined detection patterns, domain-specific checks
- **API Access**: REST API for integration with SIEMs, ticketing systems (JIRA, ServiceNow)
- **Extended Network Scanning**: nmap-powered full port range, NSE script execution,
  CVE correlation via NVD API
- **Compliance Reports**: formatted PCI-DSS, ISO 27001, HIPAA compliance reports
  with attestation-ready exports
- **White-label**: custom branding for security consultancy firms
- **SLA**: 99.9% uptime SLA, priority support, dedicated scan workers

---

## 8. DEPLOYMENT & INFRASTRUCTURE

- Frontend: Netlify CDN (global edge network, auto-deploy from GitHub)
- Backend: Render.com (Python/Flask server, auto-scaling, HTTPS)
- Environment: GEMINI_API_KEY via .env / Render environment variables
- CORS: fully configured for cross-origin requests between frontend and backend domains
- No database required: stateless design — reports stored as files in /report directory
- Development: Vite dev server (port 5173) + Flask dev server (port 5000)
- Python version: 3.12+
- Node version: 18+

---

## 9. LIMITATIONS & FUTURE WORK

Be honest about current limitations for academic credibility:

- No authentication/login persistence backend (login page is frontend-only demo)
- No real-time streaming: scan results returned as single JSON response (no WebSocket)
- No database: findings not persisted between sessions
- Rate limiting not implemented on the scanner itself (WAF bypass not handled)
- Network scanner requires root/admin privileges for raw socket operations on some OS
- Gemini API quota limits (free tier: 15 req/min)
- False positives possible in SSRF and DOM XSS checks on JavaScript-heavy SPAs

### Future Work
- WebSocket streaming for real-time scan progress
- PostgreSQL backend for user accounts and scan history
- Authenticated scanning (cookie/JWT injection for post-login testing)
- Integration with Nuclei templates for extended CVE coverage
- Mobile application (React Native)
- Machine learning model trained on vulnerability patterns for zero-day detection

---

## 10. COMPARISON WITH EXISTING TOOLS

| Feature | CYBRAIN | Burp Suite Community | OWASP ZAP | Nessus |
|---------|---------|---------------------|-----------|--------|
| Price | Free + Pro | Free (limited) | Free | $$$$ |
| Web DAST | ✓ Full OWASP | ✓ | ✓ | Partial |
| SAST | ✓ | ✗ | ✗ | ✗ |
| Network | ✓ | ✗ | ✗ | ✓ |
| Apache Config | ✓ | ✗ | ✗ | Partial |
| AI Analysis | ✓ Gemini | ✗ | ✗ | ✗ |
| Reports | MD+CSV+JSON | HTML | HTML | PDF |
| API | ✓ Flask REST | Pro only | ✓ | ✓ |
| Open Source | ✓ | ✗ | ✓ | ✗ |
| Setup Time | < 2 min | Medium | Medium | Complex |

---

Please write this entire presentation in fluent, professional English (or French if preferred)
suitable for a Master 2 jury panel. Be detailed, technical, and impressive. Include code
snippets where relevant. Show mastery of the theoretical foundations. This is a high-stakes
academic defence.
```

---

## DIAGRAMS PROMPT (Use this separately — paste it alone into Claude)

```
You are a software architect and UML expert. Generate the three UML diagrams below for
the CYBRAIN project — an AI-powered cybersecurity intelligence platform (Flask + React + Python).

Output each diagram in valid PlantUML syntax inside a ```plantuml code block.
After each diagram, write 2–3 sentences explaining what the diagram shows and why it matters
for the PFE jury.

---

### DIAGRAM 1 — Diagramme de Cas d'Utilisation (Use Case Diagram)

Actors:
- Utilisateur (User): anonymous visitor who can register/login
- Analyste Sécurité (Security Analyst): authenticated user who runs scans
- Administrateur (Admin): manages users and platform
- Gemini AI: external AI service
- Système CYBRAIN: the platform itself

Use cases to include:
- S'inscrire / Se connecter (Register / Login)
- Lancer un scan URL (Web vulnerability scan — OWASP A01–A10)
- Analyser une configuration Apache (Apache misconfiguration detection)
- Analyser du code source (SAST — Static code analysis)
- Scanner le réseau (Network port scan + vulnerability detection)
- Consulter les résultats (View findings with severity levels)
- Télécharger le rapport (Download MD / CSV / JSON report)
- Discuter avec le ChatBot IA (AI chat assistant)
- Analyser les findings avec l'IA (AI executive report generation)
- Corriger le code automatiquement (AI code fix)
- Corriger la config Apache (AI config hardening)

Show include/extend relationships where relevant (e.g., "Analyser findings" extends
"Lancer un scan URL"; "Corriger le code" includes "Analyser du code source").

---

### DIAGRAM 2 — Diagramme de Classes (Class Diagram)

Include the following classes with their key attributes and methods:

UrlScanner:
- target_url: str
- session: requests.Session
- last_findings: list
- _raw_findings: list
- __init__(target_url)
- scan() -> list
- _check_connection() -> bool
- _attach_extended(checker)
- _calc_overall_risk() -> str

OWASPChecker:
- target: str
- base: str
- session: Session
- findings: list
- _lock: threading.Lock
- fast_mode: bool
- __init__(target_url, session)
- run_all() -> list
- _add(owasp_id, owasp_name, severity, title, description, ...)
- _get(url) -> Response
- _post(url, json_data, data) -> Response
- _spider_target(html)
- _a01_broken_access_control(resp)
- _a02_security_misconfiguration(resp)
- _a03_supply_chain(resp)
- _a04_cryptographic_failures(resp)
- _a05_injection(resp)
- _a06_insecure_design(resp)
- _a07_auth_failures(resp)
- _a08_integrity_failures(resp)
- _a09_logging_failures(resp)
- _a10_mishandling_exceptions(resp)
- _sqli_boolean()
- _sqli_time_based()
- _ssrf_extended()
- _cwe_path_traversal()
- _cwe_xxe()
- _cwe_clickjacking(resp)

ExtendedChecks (Mixin — bound onto OWASPChecker at runtime):
- _race_condition_check()
- _mass_assignment_check()
- _log4shell_check()
- _graphql_introspection()

ApacheMisconfigDetector:
- config_text: str
- source_name: str
- findings: list
- detect() -> list
- _check_directory_listing()
- _check_ssl_protocols()
- _check_ssl_ciphers()
- _check_security_headers()
- _check_cleartext_password()
- _check_cors()
- _check_syntax()

CodeAnalyzer:
- language: str
- findings: list
- analyze(code, filename) -> dict
- _detect_language(filename) -> str
- _check_sqli(code) -> list
- _check_xss(code) -> list
- _check_hardcoded_creds(code) -> list
- _check_command_injection(code) -> list
- _check_weak_crypto(code) -> list

CybrainAgent:
- ai_active: bool
- model: GenerativeModel
- chat(message, context) -> str
- analyze_findings(findings, target, scan_type) -> str
- fix_code(code, filename) -> dict
- fix_apache_config(config, findings) -> dict
- _gemini(prompt, system) -> str
- _analyze_offline(findings, target, scan_type) -> str

ReportGenerator:
- target: str
- findings: list
- output_dir: str
- generate_all()
- generate_markdown() -> str
- generate_csv() -> str
- generate_json() -> str

NetworkScanner:
- target: str
- recon_data: dict
- findings: list
- scan(mode) -> list
- _calc_overall_risk() -> str

Relationships:
- UrlScanner creates OWASPChecker (association)
- UrlScanner injects ExtendedChecks into OWASPChecker (dependency)
- OWASPChecker uses ExtendedChecks (mixin/dependency)
- UrlScanner creates ReportGenerator (association)
- Flask app.py uses UrlScanner, ApacheMisconfigDetector, CodeAnalyzer,
  NetworkScanner, CybrainAgent (dependency)
- CybrainAgent uses ReportGenerator (association)

---

### DIAGRAM 3 — Diagramme de Séquence (Sequence Diagram)

Draw the complete sequence for a Web URL Scan (the most important flow):

Participants:
- Utilisateur (browser / React frontend)
- React Frontend (ScannerSuite component + useScanner hook)
- Flask Backend (app.py /scan_url route)
- UrlScanner (url_scanner.py)
- OWASPChecker (owasp_checks.py)
- ExtendedChecks (mixin methods)
- CybrainAgent / AI (ai_agent.py)
- ReportGenerator (report_generator.py)
- Target Website (the scanned URL)

Sequence of events:
1. User enters URL and clicks "Scan" in the React UI
2. React calls POST /scan_url with {url: "http://target.com"} via Axios
3. Flask validates URL (checks private IP blocklist)
4. Flask instantiates UrlScanner(url)
5. UrlScanner._check_connection(): 3 retry attempts to Target Website → HTTP 200
6. Flask calls scanner.scan()
7. UrlScanner creates OWASPChecker instance
8. UrlScanner._attach_extended(): binds ExtendedChecks methods onto checker
9. OWASPChecker.run_all() starts:
   a. GET Target Website → HTML response for spidering
   b. Parallel ThreadPoolExecutor (8 workers): A01 + A02 + A03 + A04 + A05 + A06 + A07 + A08
      Each check sends multiple HTTP requests to Target Website
   c. Sequential extras: path traversal, XXE, clickjacking, host header, HTTP methods,
      file upload, deserialization, DOM XSS, stored XSS, CSP bypass, boolean SQLi, time SQLi, SSRF
   d. Extended checks (injected): race condition, mass assignment, Log4Shell, GraphQL
10. UrlScanner deduplicates + sorts findings by severity
11. UrlScanner creates ReportGenerator → generates MD + CSV + JSON files
12. UrlScanner formats findings as HTML for React display
13. Flask returns JSON {findings: [...], total: N, risk: "HIGH"} to React
14. React (ResultsPanel) renders findings with SeverityBadge components
15. User optionally clicks "Analyse avec IA"
16. React calls POST /api/analyze_findings with findings list
17. Flask calls CybrainAgent.analyze_findings()
18. CybrainAgent calls Gemini API (or offline fallback) → returns Markdown report
19. Flask returns {analysis: "## Executive Report..."} to React
20. React displays AI analysis in the ChatBot / results panel

---

Make all three diagrams complete, accurate, and suitable for inclusion in a Master 2
PFE report chapter titled "Conception et Modélisation". Use PlantUML syntax.
Add a @startuml / @enduml wrapper to each diagram.
```
