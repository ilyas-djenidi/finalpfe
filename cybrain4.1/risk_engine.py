# risk_engine.py
"""
CVSS v3.1-inspired risk scoring engine.
Accepts any scanner result dict with a "vulnerabilities" list.
"""

import logging

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high":      7.0,
    "medium":    4.0,
    "low":       1.5,
    "info":      0.0,
}

MAX_RAW_SCORE = 40.0


def calculate_risk(scan_result: dict, criticality: float = 1.0) -> float:
    """
    Returns a 0.0–10.0 risk score weighted by environment criticality.
    criticality: 1.0 production | 0.6 internal | 0.3 test
    """
    vulns = scan_result.get("vulnerabilities", [])
    if not vulns:
        return 0.0

    raw = sum(SEVERITY_WEIGHTS.get((v.get("severity") or "info").lower(), 0.0) for v in vulns)
    normalized  = min((raw / MAX_RAW_SCORE) * 10.0, 10.0)
    final_score = round(normalized * criticality, 2)

    logger.info(
        "risk | raw=%.1f normalized=%.2f criticality=%s final=%.2f",
        raw, normalized, criticality, final_score,
    )
    return final_score


def get_risk_breakdown(scan_result: dict) -> dict:
    """Counts by severity + highest severity label."""
    vulns = scan_result.get("vulnerabilities", [])
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        sev = (v.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1

    highest = "info"
    for sev in ("critical", "high", "medium", "low"):
        if counts[sev] > 0:
            highest = sev
            break

    return {"counts": counts, "highest": highest, "total": len(vulns)}
