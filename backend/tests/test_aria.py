"""Tests for ARIA ai_agent structured analysis output."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from unittest.mock import patch
from ai_agent import ARIA


def _finding(severity, check, title=""):
    return {"severity": severity, "check": check, "title": title or check,
            "description": "", "cve_ids": []}


class TestAriaStructuredOutput:
    def setup_method(self):
        # Force offline mode — no Gemini needed
        with patch("ai_agent._GENAI_AVAILABLE", False):
            self.aria = ARIA()

    def test_analyze_returns_dict(self):
        findings = [_finding("high", "sql injection")]
        result = self.aria.analyze_findings(findings, "example.com", "web")
        assert isinstance(result, dict)

    def test_required_keys_present(self):
        findings = [_finding("critical", "command injection")]
        result = self.aria.analyze_findings(findings, "test.com", "dast")
        for key in ("aria_mode", "attack_chain", "mitre_mappings",
                    "remediation_md", "compliance", "nvd_enriched"):
            assert key in result, f"Missing key: {key}"

    def test_mitre_mappings_is_list(self):
        findings = [_finding("high", "sql injection")]
        result = self.aria.analyze_findings(findings, "t.com", "web")
        assert isinstance(result["mitre_mappings"], list)

    def test_mitre_sqli_maps_to_t1190(self):
        findings = [_finding("high", "sql injection")]
        result = self.aria.analyze_findings(findings, "t.com", "web")
        tids = [m["technique_id"] for m in result["mitre_mappings"]]
        assert "T1190" in tids

    def test_compliance_structure(self):
        findings = [_finding("critical", "rce")]
        result = self.aria.analyze_findings(findings, "t.com", "web")
        comp = result["compliance"]
        for std in ("gdpr", "pci_dss", "iso_27001"):
            assert std in comp
            assert "status" in comp[std]
            assert "color" in comp[std]

    def test_compliance_critical_is_red(self):
        findings = [_finding("critical", "rce")]
        result = self.aria.analyze_findings(findings, "t.com", "web")
        assert result["compliance"]["gdpr"]["color"] == "critical"

    def test_empty_findings_returns_valid_dict(self):
        result = self.aria.analyze_findings([], "t.com", "web")
        assert result["risk_level"] if "risk_level" in result else True
        assert isinstance(result["mitre_mappings"], list)
        assert len(result["mitre_mappings"]) == 0

    def test_offline_mode_flag(self):
        result = self.aria.analyze_findings([_finding("low", "open_port")], "t.com", "web")
        assert result["aria_mode"] == "offline"

    def test_attack_chain_is_string(self):
        findings = [_finding("high", "xss")]
        result = self.aria.analyze_findings(findings, "t.com", "web")
        assert isinstance(result["attack_chain"], str)
        assert len(result["attack_chain"]) > 0

    def test_remediation_md_is_string(self):
        findings = [_finding("medium", "missing_header")]
        result = self.aria.analyze_findings(findings, "t.com", "web")
        assert isinstance(result["remediation_md"], str)
