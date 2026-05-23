# risk_engine.py
"""
CyBrain Professional Risk Scoring Engine — v3
==============================================
References:
  - CVSS v3.1  (NIST SP 800-30)
  - OWASP Risk Rating Methodology
  - FAIR (Factor Analysis of Information Risk)
  - ISO/IEC 27005
  - CISA Known Exploited Vulnerabilities (KEV) Catalog
"""

import math
import logging
import re
import threading
import time
from dataclasses import dataclass, field

import requests

logger = logging.getLogger(__name__)

# ── CISA KEV integration ──────────────────────────────────────────────────────
_KEV_URL          = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEV_CACHE: set[str] = set()
_KEV_LAST_FETCH: float = 0.0
_KEV_TTL: float   = 86400.0   # 24 hours
_KEV_LOCK         = threading.Lock()
_KEV_THREAD_STARTED = False


def _fetch_kev_blocking() -> set[str]:
    try:
        r = requests.get(_KEV_URL, timeout=12)
        r.raise_for_status()
        data = r.json().get("vulnerabilities", [])
        kev  = {v["cveID"] for v in data if "cveID" in v}
        logger.info("CISA KEV updated | entries=%d", len(kev))
        return kev
    except Exception as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        return set()


def _kev_background_worker():
    """Background thread: refresh KEV every 24 hours."""
    global _KEV_CACHE, _KEV_LAST_FETCH
    while True:
        now = time.time()
        if now - _KEV_LAST_FETCH >= _KEV_TTL:
            with _KEV_LOCK:
                if time.time() - _KEV_LAST_FETCH >= _KEV_TTL:
                    new_kev = _fetch_kev_blocking()
                    if new_kev:
                        _KEV_CACHE = new_kev
                    _KEV_LAST_FETCH = time.time()
        time.sleep(3600)   # check every hour, TTL controls actual fetches


def _start_kev_thread():
    global _KEV_THREAD_STARTED
    if _KEV_THREAD_STARTED:
        return
    _KEV_THREAD_STARTED = True
    t = threading.Thread(target=_kev_background_worker, daemon=True, name="cisa-kev-refresh")
    t.start()


def get_kev_set() -> set[str]:
    """Return the current CISA KEV set (lazy-fetch on first call)."""
    global _KEV_CACHE, _KEV_LAST_FETCH
    _start_kev_thread()
    now = time.time()
    if now - _KEV_LAST_FETCH >= _KEV_TTL:
        with _KEV_LOCK:
            if time.time() - _KEV_LAST_FETCH >= _KEV_TTL:
                new_kev = _fetch_kev_blocking()
                if new_kev:
                    _KEV_CACHE = new_kev
                _KEV_LAST_FETCH = time.time()
    return _KEV_CACHE


# ── Base scores (aligned with CVSS v3.1) ─────────────────────────────────────
BASE_SCORES: dict[str, float] = {
    "critical": 9.5,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.0,
    "info":     0.0,
}

# ── Scan-type confidence weights ──────────────────────────────────────────────
_SCAN_TYPE_WEIGHT: dict[str, float] = {
    "dast":         1.2,
    "dependencies": 1.1,
    "network_ext":  1.1,
    "sast":         1.0,
    "web":          1.0,
    "server_int":   0.9,
    "server_ext":   0.95,
    "network_int":  0.8,
}

# ── Vulnerability-type boosters ───────────────────────────────────────────────
_TYPE_BOOSTERS: dict[str, float] = {
    "rce":                    2.0,
    "remote code":            2.0,
    "command injection":      2.0,
    "command_injection":      2.0,
    "sql injection":          1.8,
    "sqli":                   1.8,
    "authentication bypass":  1.7,
    "hardcoded":              1.7,
    "hardcoded_secret":       1.7,
    "credential":             1.6,
    "xxe":                    1.5,
    "ssrf":                   1.5,
    "deserialization":        1.5,
    "path traversal":         1.4,
    "path_traversal":         1.4,
    "lfi":                    1.4,
    "idor":                   1.3,
    "xss":                    1.2,
    "csrf":                   1.1,
    "open_port":              0.8,
    "missing_header":         0.7,
    "missing header":         0.7,
    "information_disclosure": 0.75,
}


@dataclass
class RiskBreakdown:
    """Full multi-dimensional risk score returned by calculate_risk_v2()."""
    raw_score:          float
    base_score:         float
    temporal_score:     float
    env_score:          float
    final_score:        float
    risk_level:         str              # minimal / low / medium / high / critical
    confidence:         float            # 0.0–1.0
    severity_counts:    dict
    highest_sev:        str
    top_findings:       list
    recommendations:    list[str]
    attack_chains:      list[str]        = field(default_factory=list)
    cisa_kev_findings:  list[str]        = field(default_factory=list)  # CVE IDs in KEV


# ── Attack chain detection ────────────────────────────────────────────────────

def _detect_attack_chains(vulns: list[dict], internet_facing: bool) -> list[str]:
    """Identify dangerous vulnerability combinations that form attack chains."""
    if not vulns:
        return []

    check_all = " ".join(
        ((v.get("check") or "") + " " + (v.get("title") or "") + " " + (v.get("description") or "")).lower()
        for v in vulns
    )

    has_xss          = any(k in check_all for k in ("xss", "cross-site script", "innerhtml", "dangerouslysetinnerhtml"))
    has_sqli         = any(k in check_all for k in ("sql inject", "sqli"))
    has_rce          = any(k in check_all for k in ("rce", "remote code", "command injection", "eval()"))
    has_smb_port     = any("445" in str(v.get("evidence") or "") or "smb" in (v.get("check") or "").lower() for v in vulns)
    has_old_os       = any(k in check_all for k in ("windows xp", "windows 2003", "end of life", "end-of-life", "eol"))
    has_open_admin   = any(k in check_all for k in ("admin panel", "phpmyadmin", "wp-admin", "exposed admin", "admin interface"))
    has_default_cred = any(k in check_all for k in ("default credential", "default password", "default login"))
    has_missing_csp  = any(
        "csp" in (v.get("check") or v.get("title") or "").lower() or
        "content-security-policy" in (v.get("check") or v.get("title") or "").lower()
        for v in vulns
        if "missing" in (v.get("check") or v.get("title") or "").lower()
    )

    chains = []

    if has_xss and has_missing_csp:
        chains.append(
            "Stored XSS with no CSP barrier — attacker can execute arbitrary JavaScript "
            "in all authenticated user sessions, stealing tokens and credentials."
        )

    if has_sqli:
        chains.append(
            "SQL Injection with direct DB access — attacker can exfiltrate, modify, "
            "or destroy the entire database without additional exploitation steps."
        )

    if has_open_admin and has_default_cred:
        chains.append(
            "Administrative takeover path — exposed admin panel combined with default credentials "
            "enables full system compromise with zero technical skill required."
        )

    if has_rce and internet_facing:
        chains.append(
            "Remote Code Execution exposed to internet — attacker can gain full server control "
            "without authentication, enabling data theft, ransomware, and lateral movement."
        )

    if has_old_os and has_smb_port:
        chains.append(
            "EternalBlue / ransomware attack path — unpatched OS combined with open SMB (port 445) "
            "enables worm-propagating ransomware (WannaCry, NotPetya attack pattern)."
        )

    return chains


# ── Main scoring function ─────────────────────────────────────────────────────

def calculate_risk_v2(
    scan_result:     dict,
    criticality:     float = 1.0,
    exploit_known:   bool  = False,
    internet_facing: bool  = True,
    has_pii:         bool  = False,
    has_payment:     bool  = False,
) -> RiskBreakdown:
    """
    Multi-dimensional professional risk scoring.

    Steps:
      1. Per-finding score (base × type-booster × exploit-factor × KEV-factor)
      2. Logarithmic aggregation (prevents low-vuln inflation)
      3. Sigmoid normalization to 0–10
      4. Temporal adjustment (CVE presence, known exploit)
      5. Environmental adjustment (criticality, exposure, data sensitivity)
      6. Floor guarantees (critical ≥ 7.5, high ≥ 5.0)
    """
    vulns     = scan_result.get("vulnerabilities", [])
    scan_type = scan_result.get("scan_type", "web")
    scan_wt   = _SCAN_TYPE_WEIGHT.get(scan_type, 1.0)

    _empty_counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    }

    if not vulns:
        return RiskBreakdown(
            raw_score=0.0, base_score=0.0, temporal_score=0.0,
            env_score=0.0, final_score=0.0, risk_level="minimal",
            confidence=0.9, severity_counts=_empty_counts,
            highest_sev="info", top_findings=[],
            recommendations=["No vulnerabilities found — maintain regular scan schedule."],
            attack_chains=[], cisa_kev_findings=[],
        )

    # ── Load CISA KEV (lazy, non-blocking on error) ───────────────────────────
    try:
        kev_set = get_kev_set()
    except Exception:
        kev_set = set()

    # ── Step 1: Per-finding score ─────────────────────────────────────────────
    scored: list[tuple[float, str, dict]] = []
    sev_counts: dict[str, int] = dict(_empty_counts)
    kev_cves: list[str] = []

    for v in vulns:
        sev = (v.get("severity") or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

        base = BASE_SCORES.get(sev, 0.0)

        check_text = (
            (v.get("check")       or "") + " " +
            (v.get("title")       or "") + " " +
            (v.get("description") or "")
        ).lower()
        booster = max(
            (mult for kw, mult in _TYPE_BOOSTERS.items() if kw in check_text),
            default=1.0,
        )

        # CISA KEV check — 2.5× if finding has a CVE that's in KEV
        cve_ids = v.get("cve_ids") or []
        if isinstance(cve_ids, str):
            cve_ids = re.findall(r"CVE-\d{4}-\d+", cve_ids, re.IGNORECASE)
        is_kev = any(str(c).upper() in kev_set for c in cve_ids)
        if is_kev:
            for c in cve_ids:
                if str(c).upper() in kev_set and str(c).upper() not in kev_cves:
                    kev_cves.append(str(c).upper())

        # Exploit factor: 2.5× for KEV, 1.3× for known exploit otherwise
        if is_kev and sev in ("critical", "high"):
            exploit_f = 2.5
        elif exploit_known and sev in ("critical", "high"):
            exploit_f = 1.3
        else:
            exploit_f = 1.0

        individual = min(base * booster * exploit_f, 10.0)
        scored.append((individual, sev, v))

    # ── Step 2: Logarithmic aggregation ──────────────────────────────────────
    scored.sort(key=lambda x: x[0], reverse=True)

    raw_score    = 0.0
    decay_factor = 1.0
    for score, _, _ in scored:
        raw_score    += score * decay_factor
        decay_factor *= 0.85

    # ── Step 3: Sigmoid normalization → 0–10 ─────────────────────────────────
    base_score = round(10.0 * (1.0 - math.exp(-raw_score / 15.0)), 2)

    # ── Step 4: Temporal adjustment ───────────────────────────────────────────
    has_cve       = any(v.get("cve_ids") for v in vulns)
    temporal_mult = 1.0
    if has_cve:        temporal_mult += 0.05
    if kev_cves:       temporal_mult += 0.15   # KEV is stronger than generic exploit_known
    elif exploit_known: temporal_mult += 0.10
    temporal_score = round(min(base_score * temporal_mult, 10.0), 2)

    # ── Step 5: Environmental adjustment ─────────────────────────────────────
    env_mult = max(0.1, min(float(criticality), 1.0))
    if internet_facing: env_mult *= 1.20
    if has_pii:         env_mult *= 1.15
    if has_payment:     env_mult *= 1.20
    env_mult *= scan_wt

    env_score = round(min(temporal_score * env_mult, 10.0), 2)

    # ── Step 6: Floor guarantees ──────────────────────────────────────────────
    final_score = env_score
    if sev_counts.get("critical", 0) > 0:
        final_score = max(final_score, 7.5)
    elif sev_counts.get("high", 0) > 0:
        final_score = max(final_score, 5.0)
    final_score = round(min(final_score, 10.0), 2)

    # ── Risk level ────────────────────────────────────────────────────────────
    risk_level = (
        "critical" if final_score >= 9.0 else
        "high"     if final_score >= 7.0 else
        "medium"   if final_score >= 4.0 else
        "low"      if final_score >= 1.0 else
        "minimal"
    )

    # ── Highest severity present ──────────────────────────────────────────────
    highest_sev = next(
        (s for s in ("critical", "high", "medium", "low") if sev_counts.get(s, 0) > 0),
        "info",
    )

    # ── Scan-type confidence ──────────────────────────────────────────────────
    confidence = {
        "dependencies": 0.95, "dast": 0.90, "sast": 0.85,
        "server_int": 0.90, "network_ext": 0.75,
        "web": 0.70, "server_ext": 0.70,
    }.get(scan_type, 0.75)

    top_findings = [v for _, _, v in scored[:3]]

    recommendations = _build_recommendations(
        sev_counts, has_pii, has_payment, internet_facing, kev_cves
    )

    attack_chains = _detect_attack_chains(vulns, internet_facing)

    logger.info(
        "risk_v2 | scan=%s | raw=%.1f base=%.2f temporal=%.2f env=%.2f final=%.2f "
        "level=%s | kev=%d chains=%d",
        scan_type, raw_score, base_score, temporal_score, env_score, final_score,
        risk_level, len(kev_cves), len(attack_chains),
    )

    return RiskBreakdown(
        raw_score        = round(raw_score, 2),
        base_score       = base_score,
        temporal_score   = temporal_score,
        env_score        = env_score,
        final_score      = final_score,
        risk_level       = risk_level,
        confidence       = confidence,
        severity_counts  = sev_counts,
        highest_sev      = highest_sev,
        top_findings     = top_findings,
        recommendations  = recommendations,
        attack_chains    = attack_chains,
        cisa_kev_findings = kev_cves,
    )


def _build_recommendations(
    counts:          dict[str, int],
    has_pii:         bool,
    has_payment:     bool,
    internet_facing: bool,
    kev_cves:        list[str],
) -> list[str]:
    recs: list[str] = []
    if kev_cves:
        recs.append(
            f"CISA KEV: {len(kev_cves)} finding(s) match CISA's Known Exploited Vulnerabilities catalog "
            f"({', '.join(kev_cves[:3])}{'...' if len(kev_cves) > 3 else ''}) — patch IMMEDIATELY, these are actively exploited in the wild."
        )
    if counts.get("critical", 0) > 0:
        recs.append("CRITICAL: Apply fix immediately — target time: 24 hours.")
    if counts.get("high", 0) > 0:
        recs.append("HIGH: Remediate within 48–72 hours.")
    if counts.get("medium", 0) > 5:
        recs.append("Multiple medium findings — schedule a remediation sprint.")
    if has_pii and (counts.get("critical", 0) + counts.get("high", 0)) > 0:
        recs.append("GDPR Art.33: Assess breach notification requirement within 72 hours.")
    if has_payment:
        recs.append("PCI-DSS Req.6.3.3: All critical/high findings must be remediated immediately.")
    if internet_facing and counts.get("medium", 0) > 3:
        recs.append("Internet-facing system: prioritize medium findings urgently.")
    if not recs:
        recs.append("Security posture acceptable — maintain a regular scan schedule.")
    return recs


# ── Backward-compatible interfaces ───────────────────────────────────────────

def calculate_risk(scan_result: dict, criticality: float = 1.0) -> float:
    """Legacy interface — returns final score only."""
    return calculate_risk_v2(scan_result, criticality=criticality).final_score


def get_risk_breakdown(scan_result: dict) -> dict:
    """Legacy interface — returns dict."""
    bd = calculate_risk_v2(scan_result)
    return {
        "counts":             bd.severity_counts,
        "highest":            bd.highest_sev,
        "total":              sum(bd.severity_counts.values()),
        "risk_level":         bd.risk_level,
        "confidence":         bd.confidence,
        "recommendations":    bd.recommendations,
        "top_findings":       bd.top_findings,
        "attack_chains":      bd.attack_chains,
        "cisa_kev_findings":  bd.cisa_kev_findings,
    }
