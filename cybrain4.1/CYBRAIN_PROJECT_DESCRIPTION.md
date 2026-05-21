# CyBrain Security Platform — Theoretical Project Description

---

## 1. Introduction and Context

In an era where cyberattacks are growing exponentially in frequency, sophistication, and impact, organisations of every size face a critical need: the ability to continuously assess, understand, and remediate security vulnerabilities in their digital infrastructure. Traditional approaches — periodic manual audits conducted by consultants, isolated point-tools operated by specialists — are simply too slow, too fragmented, and too expensive to keep pace with the modern threat landscape.

**CyBrain** is a production-grade, multi-vector security scanning and intelligence platform designed to address this gap. It centralises every phase of a security assessment cycle — discovery, analysis, prioritisation, remediation guidance, and compliance reporting — into a single, cohesive web application. The platform is built for security analysts, penetration testers, system administrators, and DevSecOps teams who need real results, not vendor reports filled with theoretical warnings.

CyBrain is not a concept project. It integrates with the world's most respected open-source and free-tier security tools and data sources — OWASP ZAP, Nikto, Nmap, Bandit, Semgrep, pip-audit, npm audit, NIST NVD API, and Google Gemini AI — and produces actionable intelligence on real targets using real data.

---

## 2. Why CyBrain Is Important

### 2.1 The Security Vacuum in Small and Mid-Sized Organisations

Enterprise security teams have access to commercial SIEM platforms, managed detection services, and dedicated penetration testing budgets. Small and mid-sized organisations — which represent the vast majority of businesses worldwide — do not. They are simultaneously the most targeted and the least protected.

CyBrain fills this vacuum by packaging professional-grade scanning capabilities into a self-hosted, open-source platform that requires no commercial licensing, no vendor lock-in, and no expensive consultants for routine assessments.

### 2.2 Fragmented Tooling Creates Blind Spots

Most organisations that do run security scans use isolated tools: Nmap for network discovery, a web scanner for HTTP headers, a SAST tool for code review. Each tool produces its own report in its own format, with no shared context and no unified risk score. A critical SQL injection in the code and an exposed service on the network exist in separate silos — neither analyst nor manager can see the combined risk.

CyBrain unifies all these vectors under one roof with a single risk score, a single report format, and a single AI-powered analysis layer that reasons across all findings simultaneously.

### 2.3 The Time-to-Remediation Problem

The industry average time-to-remediation for a critical vulnerability is measured in weeks. Much of that delay is not technical — it is organisational: developers do not understand the vulnerability, managers cannot prioritise it, and the remediation guidance is buried in a 40-page PDF report. CyBrain's ARIA AI agent generates instant, copy-pasteable remediation code, links every finding to MITRE ATT&CK techniques, and chains vulnerabilities into a realistic attack scenario so that stakeholders at every level understand the urgency.

### 2.4 Compliance Is No Longer Optional

GDPR (Europe), PCI-DSS (payment card industry), and ISO 27001 (information security management) are not optional frameworks — they carry legal liability and financial penalties. CyBrain's automated compliance assessment maps every scan finding to these three frameworks, immediately flagging which regulations are at risk and why. This transforms a technical scan report into a compliance document that management and legal teams can act on directly.

---

## 3. Architectural Design Philosophy

### 3.1 Real Tools. No Custom Scripts.

One of the most important architectural decisions in CyBrain is the deliberate choice to **use established, internationally recognised security tools** for every scanning function where such tools exist. Writing custom scripts to replicate functionality that OWASP ZAP, Nikto, Nmap, Bandit, or Semgrep already implements would be redundant, less accurate, less maintained, and less trusted by the security community.

The philosophy is: **CyBrain is the orchestration layer and intelligence layer, not the detection layer.** The detection is delegated to the best available tools.

The **only** custom-developed scanner in the entire platform is `server_int.py` — the Apache/httpd configuration file analyser. This module exists because no mature open-source tool adequately performs white-box static analysis of Apache `httpd.conf` files for the specific set of misconfigurations that are most commonly exploited in production environments (exposed server tokens, missing security headers in config, dangerous `Options` directives, directory listing, weak TLS configuration). This is a genuine gap in the open-source ecosystem, and CyBrain fills it.

Everything else delegates to proven tools:

| Function | Tool Used | Reason |
|----------|-----------|--------|
| Dynamic web scanning (active) | **OWASP ZAP** | OWASP's official scanner; industry standard for DAST |
| Dynamic web scanning (passive) | **Nikto** | 30+ years of web server vulnerability signatures |
| Network port/service discovery | **Nmap** | The definitive network scanner; used by every penetration tester |
| Python static analysis | **Bandit** | PyCQA's official Python security linter |
| Multi-language static analysis | **Semgrep** | Used by security teams at major tech companies; supports 30+ languages |
| Python dependency CVE scanning | **pip-audit** | Official PyPA tool for auditing Python packages |
| Node.js dependency CVE scanning | **npm audit** | Built into npm; queries the npm advisory database |
| Real-time CVE data | **NIST NVD API v2** | The authoritative US government CVE database |
| AI analysis and narrative | **Google Gemini 1.5 Flash** | State-of-the-art LLM with free tier access |

### 3.2 Production-Grade Security Architecture

CyBrain practices what it preaches. The platform itself is hardened according to OWASP Secure Coding Guidelines and NIST SP 800-63B standards:

- **Password security**: bcrypt with 12 rounds (computationally resistant to brute force); minimum complexity enforced (10 chars, uppercase, lowercase, digit, special character per NIST SP 800-63B)
- **Multi-Factor Authentication**: TOTP (RFC 6238) implemented via pyotp; full QR code setup flow; per-user enable/disable with password confirmation
- **Session management**: Flask-Login with 30-minute idle timeout; HttpOnly, SameSite=Lax, Secure (production) cookies; server-side Redis sessions in production
- **CSRF protection**: Flask-WTF CSRF tokens on all state-changing forms and a `X-CSRFToken` meta header for AJAX calls
- **Rate limiting**: Flask-Limiter on all sensitive endpoints (login: 10/minute, scans: 5/minute, AI analysis: 20/hour)
- **IDOR prevention**: Every report access checks `user_id == current_user.id` before returning data
- **Input validation**: WTForms with server-side validators for all scan inputs; regex-based token validation before database queries
- **Security headers**: X-Frame-Options: DENY (clickjacking), X-Content-Type-Options: nosniff, Content-Security-Policy, HSTS (production), Referrer-Policy, Permissions-Policy
- **Audit logging**: Every action — login, logout, scan, report view, admin operation — is recorded to a structured audit log with timestamp, IP, user agent, and outcome
- **Account lockout**: 5 failed login attempts triggers a 15-minute lockout; timing attack mitigation via constant-time bcrypt dummy check

---

## 4. Technology Stack

### 4.1 Backend Framework

**Flask 3.1** — Python's most widely deployed micro-framework. Chosen for its flexibility, ecosystem maturity, and the ability to compose exactly the extensions needed without unnecessary bloat. Flask Blueprint architecture allows clean separation of concerns: `auth/`, `routes/main`, `routes/admin`, `routes/api`.

The application is structured using the **Application Factory pattern** (`create_app()` in `app.py`). This is the Flask community's recommended approach for production applications — it supports multiple instances, easier testing, and clean configuration injection.

### 4.2 Database: Supabase PostgreSQL

**Supabase** provides a managed PostgreSQL database with a PostgREST API layer and Python SDK. Replacing the development SQLite backend with Supabase gives CyBrain:

- Full PostgreSQL semantics (foreign keys, JSONB columns, proper timestamps)
- PostgREST RPC functions for complex aggregations (`get_dashboard_stats`, `get_system_stats`, etc.)
- Row Level Security capability for multi-tenant deployment
- Built-in connection pooling and high availability
- Real-time subscriptions (available for future dashboard live-updates)

The `database/client.py` module provides a complete abstraction layer — the rest of the application calls the same function signatures regardless of the underlying database.

### 4.3 Authentication and Authorisation

- **Flask-Login**: Session management and `current_user` proxy
- **Flask-WTF / CSRFProtect**: Form CSRF tokens
- **bcrypt** (rounds=12): Password hashing — computationally infeasible to crack with modern hardware
- **pyotp + qrcode**: RFC 6238 TOTP multi-factor authentication
- **Role-Based Access Control (RBAC)**: Three roles (admin, analyst, viewer) with four permissions (run_scan, view_reports, manage_users, view_audit). The `require_permission()` decorator enforces this at the route level.

### 4.4 Scanning Infrastructure

#### Web Scanner (`scanners/web_scanner.py`)
Passive HTTP-based scanner performing OWASP Top 10 checks without sending active attack payloads: missing security headers, SSL/TLS configuration, sensitive file exposure (`.env`, `.git`, backup files), clickjacking, CORS misconfiguration, boolean-based SQLi detection, IDOR indicators, rate limit testing, cookie security attributes.

#### DAST Scanner (`scanners/dast_scanner.py`)
Integrates with **OWASP ZAP** via its REST API and **Nikto** via CLI. ZAP performs active penetration testing — spidering the target, injecting payloads, and detecting XSS, SQLi, CSRF, and dozens of other vulnerabilities. Nikto adds server-level checks: outdated software, dangerous HTTP methods, default files, and configuration weaknesses. Together they represent the gold standard of web application dynamic analysis.

#### SAST Scanner (`scanners/sast_scanner.py`)
Accepts a ZIP archive of source code and runs two complementary static analysis engines:
- **Bandit**: Python-specific security linter that detects hardcoded secrets, weak cryptography, SQL injection via string formatting, unsafe subprocess usage, and 40+ other Python security antipatterns.
- **Semgrep**: Multi-language pattern matching engine using the `p/python` and `p/secrets` rulesets. Where Bandit is Python-only and rule-bound, Semgrep is language-agnostic and extensible. Together they catch what neither finds alone.

ZIP bomb protection is implemented (150MB uncompressed limit) to prevent resource exhaustion attacks.

#### Dependency Scanner (`scanners/dep_scanner.py`)
- **pip-audit**: Queries the Python Advisory Database (PyAD) and NIST NVD for CVEs in Python packages listed in `requirements.txt` or `pyproject.toml`.
- **npm audit**: Queries the npm security advisory database for Node.js packages in `package.json`.

This scanner addresses OWASP A06:2021 — Vulnerable and Outdated Components, one of the most common sources of real-world breaches.

#### Network Scanner (`scanners/netscan_scanner.py`)
**Nmap** integration via `python-nmap`. Performs host discovery, port scanning, service version detection, and OS fingerprinting. Supports both external (internet-facing) and internal (LAN) network scan profiles. Deep scan mode enables script scanning (`-sC`) and version detection (`-sV`).

#### External Server Scanner (`scanners/server_ext.py`)
Black-box server fingerprinting: banner grabbing, exposed version strings, HTTP response analysis, default error pages, server token disclosure, and dangerous HTTP method detection (TRACE, DELETE, PUT).

#### Internal Server Scanner (`scanners/server_int.py`) — The Only Custom Scanner
White-box analysis of Apache `httpd.conf` configuration files. This is the only scanner in CyBrain that is a custom-developed script, and its existence is justified by a genuine gap in available tooling.

The scanner checks for: exposed `ServerTokens Full`, missing security headers in config, `TraceEnable On`, `Options Indexes` (directory listing), weak TLS protocol versions (SSLv2, SSLv3, TLS 1.0/1.1), missing `X-Frame-Options`, dangerous `AllowOverride All`, and other configuration weaknesses that are regularly exploited in production Apache deployments.

Uniquely, CyBrain also **generates a corrected configuration file** — a patched version of the uploaded `httpd.conf` with all detected misconfigurations fixed and change annotations added. This "Download Fixed Config" feature turns a finding into an immediate, deployable remedy.

### 4.5 Risk Scoring Engine (`core/risk_engine.py`)

CyBrain implements a custom risk aggregation algorithm built on **CVSS v3.1 methodology**. The scoring process has five stages:

1. **Representative CVSS Mapping**: Each vulnerability severity maps to its CVSS v3.1 midpoint (Critical → 9.5, High → 8.0, Medium → 5.5, Low → 2.0)
2. **Base Score**: The maximum CVSS score among all findings. Rationale: one critical vulnerability is sufficient to compromise a system — the base is not averaged.
3. **Density Factor**: `1 + log₂(1 + Σ(count × weight))` where Critical=1.5, High=0.8, Medium=0.3. This captures the cumulative risk of multiple vulnerabilities without linear inflation.
4. **Normalisation**: Raw score capped at 10.0
5. **Environmental Modifier**: Multiplied by a criticality factor (1.0 for production, 0.7 for internal systems, 0.4 for test environments). A critical finding on a test server is less urgent than the same finding on a payment gateway.

The result is a single float from 0.0 to 10.0 that accurately reflects both the worst-case vulnerability and the overall exposure surface of the target.

### 4.6 ARIA — Autonomous Risk Intelligence Agent (`ai/aria.py`)

ARIA is CyBrain's most innovative component. It is not a chatbot bolted onto a security tool — it is an **autonomous analysis agent** that activates after every scan and produces enriched intelligence that no individual scanner can generate.

ARIA operates in five stages:

**Stage 1 — NVD CVE Enrichment**
ARIA extracts all CVE identifiers mentioned in scan findings and queries the NIST National Vulnerability Database API v2 in real time. For each CVE it retrieves: the official CVSS v3.1 score and vector string, the English vulnerability description, associated CWE weaknesses, and the NVD publication date. This replaces scanner-estimated severity with authoritative, government-published scores.

**Stage 2 — MITRE ATT&CK Mapping**
ARIA maintains an offline mapping table of 30+ security keywords to MITRE ATT&CK technique IDs (T-codes) and tactics. Every finding is matched against this table. The result: each vulnerability is presented not just as a technical weakness but as a concrete attacker technique — "SQL Injection → T1212 Exploitation for Credential Access" — giving analysts and developers the adversarial context needed to understand real-world impact.

**Stage 3 — Attack Chain Generation**
This is ARIA's most distinctive capability. Rather than presenting findings as an isolated list, ARIA generates a realistic, step-by-step **attack chain** narrative: how a skilled attacker would use the discovered vulnerabilities in sequence to progressively compromise the target. When Gemini 1.5 Flash is available, the chain is generated with LLM-quality reasoning and specificity. When operating offline, ARIA's rule-based engine produces a structured chain ordered by severity with MITRE technique references.

**Stage 4 — Prioritised Remediation Plan**
ARIA generates a remediation plan ordered by business impact, not just CVSS score. Each item includes a specific, copy-pasteable code fix in the appropriate language (Python, Bash, Apache config). When Gemini is available, the plan is rich and contextual. In offline mode, ARIA's remediation rule engine covers the 10 most common finding types with precise code examples.

**Stage 5 — Compliance Assessment**
ARIA evaluates the scan findings against three major frameworks:
- **GDPR** (Article 32 — security of processing): Critical vulnerabilities that could expose personal data constitute a compliance violation
- **PCI-DSS** (Requirements 6.3.1/6.3.2 — secure development): Unpatched critical/high vulnerabilities fail PCI-DSS assessment
- **ISO 27001** (Annex A.14.2 — secure development lifecycle): Non-conformities are flagged with specific control references

ARIA also functions as an interactive security assistant. Analysts can ask natural language questions about their scan results, OWASP Top 10, CVSS scoring, MITRE ATT&CK, and specific vulnerability types — receiving expert-level, markdown-formatted answers with code examples.

---

## 5. Frontend and User Experience

The frontend is built with a cyberpunk aesthetic — dark backgrounds, neon cyan accents, glowing borders — that reflects the security domain. Key pages:

- **Login**: CSRF-protected form with MFA (TOTP) second step
- **Dashboard**: Real-time statistics, risk score trend charts, scan history, vulnerability breakdown by type and severity
- **Scanner Interface**: Dynamic form that adapts to scan type (file upload for SAST/config, URL input for web/DAST/network)
- **Report Viewer**: Full vulnerability listing with CVSS scores, evidence, and remediation; ARIA analysis panel with five tabs (Attack Chain, MITRE ATT&CK, Remediation, Compliance, NVD CVE Data)
- **Admin Hub**: System statistics, top vulnerability trends, user management, audit log viewer with filtering and export

---

## 6. Production Deployment Architecture

```
Internet → Reverse Proxy (Nginx) → Gunicorn (4 workers) → Flask App
                                                         ↓
                                                 Supabase PostgreSQL
                                                         ↓
                                           ZAP (port 8080) / Nikto / Nmap
```

**Production server**: `gunicorn -w 4 -b 127.0.0.1:5000 wsgi:application`

The `wsgi.py` entry point calls `create_app()` from the factory. Redis provides rate limiting storage and server-side session persistence. All secrets are injected via `.env` (never hardcoded). HSTS, secure cookies, and CSP headers are activated automatically when `FLASK_ENV=production`.

---

## 7. Security Standards Compliance

| Standard | Implementation |
|----------|---------------|
| OWASP Top 10 (2021) | Each scanner maps findings to OWASP categories |
| CVSS v3.1 | Risk scoring methodology |
| NIST SP 800-63B | Password complexity and session timeout requirements |
| RFC 6238 | TOTP multi-factor authentication |
| GDPR Art. 32 | Assessed automatically by ARIA compliance module |
| PCI-DSS Req. 6.3 | Assessed automatically by ARIA compliance module |
| ISO 27001 A.14.2 | Assessed automatically by ARIA compliance module |
| OWASP Secure Headers | X-Frame-Options, CSP, HSTS, X-Content-Type-Options |

---

## 8. Summary

CyBrain is a serious, production-ready security platform that demonstrates a mature understanding of both the technical and organisational dimensions of information security. Its strength lies in three principles:

1. **Use the best available tools** — never reinvent the wheel. OWASP ZAP, Nikto, Nmap, Bandit, Semgrep, pip-audit, and npm audit represent decades of collective security research. CyBrain orchestrates them rather than replacing them.

2. **Intelligence over information** — raw vulnerability lists are not actionable. ARIA transforms data into understanding: attack chains, MITRE mappings, compliance assessments, and prioritised remediation with real code.

3. **Security of the platform itself** — a security tool that is itself insecure would be worse than no tool. CyBrain implements bcrypt, TOTP, CSRF protection, IDOR prevention, rate limiting, audit logging, and OWASP security headers as non-negotiable baseline requirements.

The result is a platform that an analyst can deploy today, point at a target, and receive — within minutes — a comprehensive security assessment enriched with real CVE data, MITRE ATT&CK mappings, compliance status, and an AI-generated attack chain that makes the risk immediately understandable to everyone from the developer who must fix it to the executive who must approve the remediation budget.
