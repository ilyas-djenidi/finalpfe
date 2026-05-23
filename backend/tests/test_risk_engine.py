"""Tests for risk_engine.calculate_risk_v2()"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from risk_engine import calculate_risk_v2, calculate_risk, RiskBreakdown


def _scan(vulns, scan_type="web"):
    return {"scan_type": scan_type, "vulnerabilities": vulns}


def _vuln(severity, check="test"):
    return {"severity": severity, "check": check, "title": check, "description": ""}


class TestEmptyScan:
    def test_no_vulns_returns_minimal(self):
        bd = calculate_risk_v2(_scan([]))
        assert bd.risk_level == "minimal"
        assert bd.final_score == 0.0

    def test_no_vulns_confidence_is_float(self):
        bd = calculate_risk_v2(_scan([], scan_type="dependencies"))
        assert 0.0 < bd.confidence <= 1.0


class TestSeverityFloors:
    def test_critical_floor(self):
        bd = calculate_risk_v2(_scan([_vuln("critical")]))
        assert bd.final_score >= 7.5
        assert bd.risk_level in ("high", "critical")

    def test_high_floor(self):
        bd = calculate_risk_v2(_scan([_vuln("high")]))
        assert bd.final_score >= 5.0

    def test_critical_always_not_low(self):
        bd = calculate_risk_v2(_scan([_vuln("critical")]), criticality=0.1)
        assert bd.final_score >= 7.5


class TestInternetFacing:
    def test_internet_facing_raises_score(self):
        scan = _scan([_vuln("high")])
        bd_ext = calculate_risk_v2(scan, internet_facing=True)
        bd_int = calculate_risk_v2(scan, internet_facing=False)
        assert bd_ext.final_score >= bd_int.final_score


class TestTypeBoosters:
    def test_rce_boosts_score(self):
        rce_scan   = _scan([_vuln("high", check="remote code execution")])
        plain_scan = _scan([_vuln("high", check="open_port")])
        bd_rce   = calculate_risk_v2(rce_scan)
        bd_plain = calculate_risk_v2(plain_scan)
        assert bd_rce.final_score >= bd_plain.final_score

    def test_missing_header_reduces_score(self):
        header_scan = _scan([_vuln("medium", check="missing_header")])
        normal_scan = _scan([_vuln("medium", check="sql injection")])
        bd_h = calculate_risk_v2(header_scan)
        bd_n = calculate_risk_v2(normal_scan)
        assert bd_n.final_score >= bd_h.final_score


class TestLogarithmicDecay:
    def test_many_low_vulns_less_than_one_critical(self):
        many_low = _scan([_vuln("low")] * 50)
        one_crit = _scan([_vuln("critical")])
        bd_low  = calculate_risk_v2(many_low)
        bd_crit = calculate_risk_v2(one_crit)
        assert bd_crit.final_score >= bd_low.final_score


class TestRiskBreakdownFields:
    def test_returns_dataclass(self):
        bd = calculate_risk_v2(_scan([_vuln("medium")]))
        assert isinstance(bd, RiskBreakdown)
        assert isinstance(bd.recommendations, list)
        assert len(bd.recommendations) > 0

    def test_top_findings_limit(self):
        scan = _scan([_vuln("critical")] * 10)
        bd   = calculate_risk_v2(scan)
        assert len(bd.top_findings) <= 3


class TestLegacyWrapper:
    def test_calculate_risk_returns_float(self):
        score = calculate_risk(_scan([_vuln("high")]))
        assert isinstance(score, float)
        assert 0.0 <= score <= 10.0


class TestRecommendations:
    def test_critical_recommendation(self):
        bd = calculate_risk_v2(_scan([_vuln("critical")]))
        assert any("CRITICAL" in r or "24" in r for r in bd.recommendations)

    def test_pci_recommendation(self):
        bd = calculate_risk_v2(_scan([_vuln("critical")]), has_payment=True)
        assert any("PCI" in r for r in bd.recommendations)
