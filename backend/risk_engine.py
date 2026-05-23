# risk_engine.py
"""
CyBrain Professional Risk Scoring Engine — v2
==============================================
مراجع:
  - CVSS v3.1  (NIST SP 800-30)
  - OWASP Risk Rating Methodology
  - FAIR (Factor Analysis of Information Risk)
  - ISO/IEC 27005
"""

import math
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ── درجات الأساس (متوافقة مع CVSS v3.1) ────────────────────────────────────
BASE_SCORES: dict[str, float] = {
    "critical": 9.5,    # CVSS 9.0–10.0
    "high":     7.5,    # CVSS 7.0–8.9
    "medium":   5.0,    # CVSS 4.0–6.9
    "low":      2.0,    # CVSS 0.1–3.9
    "info":     0.0,
}

# ── أوزان ثقة نوع الفحص ──────────────────────────────────────────────────────
_SCAN_TYPE_WEIGHT: dict[str, float] = {
    "dast":         1.2,    # اختبار ديناميكي مؤكَّد — أعلى ثقة
    "dependencies": 1.1,    # CVE معروف مطابق
    "network_ext":  1.1,    # استخراج خارجي
    "sast":         1.0,    # تحليل على مستوى الكود
    "web":          1.0,
    "server_int":   0.9,    # تحليل إعدادات
    "server_ext":   0.95,
    "network_int":  0.8,    # شبكة داخلية — تعرّض أقل
}

# ── معاملات تضخيم نوع الثغرة ────────────────────────────────────────────────
_TYPE_BOOSTERS: dict[str, float] = {
    # تأثير حرج
    "rce":                    2.0,
    "remote code":            2.0,
    "command injection":      2.0,
    "command_injection":      2.0,
    # تأثير عالٍ
    "sql injection":          1.8,
    "sqli":                   1.8,
    "authentication bypass":  1.7,
    "hardcoded":              1.7,
    "hardcoded_secret":       1.7,
    "credential":             1.6,
    # تأثير متوسط-عالٍ
    "xxe":                    1.5,
    "ssrf":                   1.5,
    "deserialization":        1.5,
    "path traversal":         1.4,
    "path_traversal":         1.4,
    "lfi":                    1.4,
    "idor":                   1.3,
    # تأثير متوسط
    "xss":                    1.2,
    "csrf":                   1.1,
    # تخفيض التأثير
    "open_port":              0.8,
    "missing_header":         0.7,
    "missing header":         0.7,
    "information_disclosure": 0.75,
}


@dataclass
class RiskBreakdown:
    """تفصيل كامل لحساب المخاطر — يُعاد من calculate_risk_v2()."""
    raw_score:       float
    base_score:      float
    temporal_score:  float
    env_score:       float
    final_score:     float
    risk_level:      str            # minimal / low / medium / high / critical
    confidence:      float          # 0.0–1.0
    severity_counts: dict
    highest_sev:     str
    top_findings:    list
    recommendations: list[str]


def calculate_risk_v2(
    scan_result:     dict,
    criticality:     float = 1.0,   # 1.0 إنتاج | 0.6 داخلي | 0.3 اختبار
    exploit_known:   bool  = False,  # يوجد exploit عام معروف؟
    internet_facing: bool  = True,   # مكشوف على الإنترنت؟
    has_pii:         bool  = False,  # يحتوي بيانات شخصية (GDPR)؟
    has_payment:     bool  = False,  # يعالج بيانات دفع (PCI-DSS)؟
) -> RiskBreakdown:
    """
    حساب المخاطر متعدد الأبعاد الاحترافي.

    الخطوات:
      1. حساب درجة كل ثغرة بشكل مستقل (الأساس × مضاعف النوع × عامل الاستغلال)
      2. تجميع لوغاريتمي (يمنع تضخّم الثغرات المنخفضة)
      3. تطبيع بمنحنى sigmoid إلى 0–10
      4. تعديل زمني (وجود CVE + توفر exploit)
      5. تعديل بيئي (الحساسية + التعرض + حساسية البيانات)
      6. ضمان حدود دنيا (critical دائماً ≥ 7.0)
    """
    vulns     = scan_result.get("vulnerabilities", [])
    scan_type = scan_result.get("scan_type", "web")
    scan_wt   = _SCAN_TYPE_WEIGHT.get(scan_type, 1.0)

    _empty_counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    }

    # ── حالة فارغة ────────────────────────────────────────────────────────────
    if not vulns:
        return RiskBreakdown(
            raw_score=0.0, base_score=0.0, temporal_score=0.0,
            env_score=0.0, final_score=0.0, risk_level="minimal",
            confidence=0.9, severity_counts=_empty_counts,
            highest_sev="info", top_findings=[],
            recommendations=["لا ثغرات مكتشفة — حافظ على جدول فحص دوري منتظم."],
        )

    # ── الخطوة 1: حساب درجة كل ثغرة بشكل مستقل ──────────────────────────────
    scored: list[tuple[float, str, dict]] = []
    sev_counts: dict[str, int] = dict(_empty_counts)

    for v in vulns:
        sev = (v.get("severity") or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

        base = BASE_SCORES.get(sev, 0.0)

        # أعلى مضاعف نوع ينطبق
        check_text = (
            v.get("check",       "") + " " +
            v.get("title",       "") + " " +
            v.get("description", "")
        ).lower()
        booster = max(
            (mult for kw, mult in _TYPE_BOOSTERS.items() if kw in check_text),
            default=1.0,
        )

        # عامل الاستغلال: exploit معروف يرفع الدرجة 30%
        exploit_f = 1.3 if exploit_known and sev in ("critical", "high") else 1.0

        individual = min(base * booster * exploit_f, 10.0)
        scored.append((individual, sev, v))

    # ── الخطوة 2: تجميع لوغاريتمي ────────────────────────────────────────────
    # يمنع "100 ثغرة منخفضة > 1 ثغرة حرجة"
    scored.sort(key=lambda x: x[0], reverse=True)

    raw_score    = 0.0
    decay_factor = 1.0
    for score, _, _ in scored:
        raw_score    += score * decay_factor
        decay_factor *= 0.85  # كل ثغرة إضافية تُضيف 15% أقل

    # ── الخطوة 3: تطبيع sigmoid إلى 0–10 ─────────────────────────────────────
    # يتجنب القطع الحاد — القيم العالية جداً تقترب من 10 بشكل تدريجي
    base_score = round(10.0 * (1.0 - math.exp(-raw_score / 15.0)), 2)

    # ── الخطوة 4: الدرجة الزمنية ─────────────────────────────────────────────
    has_cve       = any(v.get("cve_ids") for v in vulns)
    temporal_mult = 1.0
    if has_cve:        temporal_mult += 0.05
    if exploit_known:  temporal_mult += 0.10
    temporal_score = round(min(base_score * temporal_mult, 10.0), 2)

    # ── الخطوة 5: الدرجة البيئية ─────────────────────────────────────────────
    env_mult = max(0.1, min(float(criticality), 1.0))
    if internet_facing: env_mult *= 1.20
    if has_pii:         env_mult *= 1.15
    if has_payment:     env_mult *= 1.20
    env_mult *= scan_wt

    env_score = round(min(temporal_score * env_mult, 10.0), 2)

    # ── الخطوة 6: ضمان حدود دنيا ─────────────────────────────────────────────
    final_score = env_score
    if sev_counts.get("critical", 0) > 0:
        final_score = max(final_score, 7.5)   # critical دائماً → خطر عالٍ (فوق التراكم المنخفض)
    elif sev_counts.get("high", 0) > 0:
        final_score = max(final_score, 5.0)   # high دائماً → خطر متوسط
    final_score = round(min(final_score, 10.0), 2)

    # ── مستوى الخطر ──────────────────────────────────────────────────────────
    risk_level = (
        "critical" if final_score >= 9.0 else
        "high"     if final_score >= 7.0 else
        "medium"   if final_score >= 4.0 else
        "low"      if final_score >= 1.0 else
        "minimal"
    )

    # ── أعلى درجة خطورة موجودة ───────────────────────────────────────────────
    highest_sev = next(
        (s for s in ("critical", "high", "medium", "low") if sev_counts.get(s, 0) > 0),
        "info",
    )

    # موثوقية نوع الفحص: قيمة ثابتة تعكس مدى تغطية الأدوات المستخدمة لكل نوع،
    # وليست مقياساً لدقة النتائج الفعلية.
    confidence = {
        "dependencies": 0.95, "dast": 0.90, "sast": 0.85,
        "server_int": 0.90, "network_ext": 0.75,
        "web": 0.70, "server_ext": 0.70,
    }.get(scan_type, 0.75)

    # ── أعلى 3 نتائج بالدرجة ─────────────────────────────────────────────────
    top_findings = [v for _, _, v in scored[:3]]

    # ── التوصيات ─────────────────────────────────────────────────────────────
    recommendations = _build_recommendations(
        sev_counts, has_pii, has_payment, internet_facing
    )

    logger.info(
        "risk_v2 | scan=%s | raw=%.1f base=%.2f temporal=%.2f env=%.2f final=%.2f level=%s",
        scan_type, raw_score, base_score, temporal_score, env_score, final_score, risk_level,
    )

    return RiskBreakdown(
        raw_score       = round(raw_score, 2),
        base_score      = base_score,
        temporal_score  = temporal_score,
        env_score       = env_score,
        final_score     = final_score,
        risk_level      = risk_level,
        confidence      = confidence,
        severity_counts = sev_counts,
        highest_sev     = highest_sev,
        top_findings    = top_findings,
        recommendations = recommendations,
    )


def _build_recommendations(
    counts:          dict[str, int],
    has_pii:         bool,
    has_payment:     bool,
    internet_facing: bool,
) -> list[str]:
    recs: list[str] = []
    if counts.get("critical", 0) > 0:
        recs.append("CRITICAL: تطبيق الإصلاح فوراً — الهدف الزمني: 24 ساعة")
    if counts.get("high", 0) > 0:
        recs.append("HIGH: المعالجة خلال 48–72 ساعة")
    if counts.get("medium", 0) > 5:
        recs.append("ثغرات متوسطة متعددة — جدولة sprint للمعالجة")
    if has_pii and (counts.get("critical", 0) + counts.get("high", 0)) > 0:
        recs.append("GDPR المادة 33: تقييم الإشعار بالخرق (72 ساعة)")
    if has_payment:
        recs.append("PCI-DSS Req.6.3.3: تطبيق جميع الإصلاحات الحرجة فوراً")
    if internet_facing and counts.get("medium", 0) > 3:
        recs.append("النظام مكشوف على الإنترنت: إعطاء أولوية للثغرات المتوسطة")
    if not recs:
        recs.append("الوضع الأمني مقبول — حافظ على جدول فحص دوري منتظم")
    return recs


# ── واجهة متوافقة مع الإصدار السابق (drop-in replacement) ───────────────────
def calculate_risk(scan_result: dict, criticality: float = 1.0) -> float:
    """واجهة قديمة — تُعيد الدرجة فقط. استخدم calculate_risk_v2() للتفصيل الكامل."""
    return calculate_risk_v2(scan_result, criticality=criticality).final_score


def get_risk_breakdown(scan_result: dict) -> dict:
    """
    إحصاءات الخطورة + أعلى مستوى + التوصيات.
    واجهة متوافقة مع الإصدار السابق.
    """
    bd = calculate_risk_v2(scan_result)
    return {
        "counts":          bd.severity_counts,
        "highest":         bd.highest_sev,
        "total":           sum(bd.severity_counts.values()),
        "risk_level":      bd.risk_level,
        "confidence":      bd.confidence,
        "recommendations": bd.recommendations,
        "top_findings":    bd.top_findings,
    }
