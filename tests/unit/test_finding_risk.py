import pytest

from src.domain.models import Confidence, Finding, Severity
from src.domain.vendors import Vendor
from src.services.analysis import AnalysisApplicationService
from src.services.analyzer import AnalyzerService


def make_finding(severity, confidence):
    return Finding(
        rule_id="TEST", title="Synthetic", category="TEST",
        severity=severity, confidence=confidence,
        technical_impact="Synthetic", remediation="Synthetic",
        safe_config_example="N/A",
    )


@pytest.mark.parametrize("severity,scores", [
    (Severity.CRITICAL, (10, 9, 8)),
    (Severity.HIGH, (8, 7, 6)),
    (Severity.MEDIUM, (5, 4, 3)),
    (Severity.LOW, (3, 2, 1)),
])
@pytest.mark.parametrize("confidence,index", [
    (Confidence.HIGH, 0), (Confidence.MEDIUM, 1), (Confidence.LOW, 2),
])
def test_finding_risk_mapping(severity, scores, confidence, index):
    finding = make_finding(severity, confidence)
    assert finding.risk_score == scores[index]
    assert finding.risk_score == make_finding(severity, confidence).risk_score
    assert type(finding.risk_score) is int
    assert 1 <= finding.risk_score <= 10


def test_finding_risk_is_monotonic_in_severity_and_confidence():
    for confidence in Confidence:
        scores = [make_finding(severity, confidence).risk_score for severity in Severity]
        assert scores == sorted(scores)
    for severity in Severity:
        scores = [make_finding(severity, confidence).risk_score for confidence in Confidence]
        assert scores == sorted(scores)


def test_finding_risk_tracks_current_profile_without_manual_assignment():
    finding = make_finding(Severity.HIGH, Confidence.HIGH)
    assert finding.risk_score == 8
    finding.confidence = Confidence.LOW
    assert finding.risk_score == 6


@pytest.mark.parametrize("vendor,config", [
    (Vendor.CISCO_IOS, "ip dhcp snooping vlan 10\n"),
    (Vendor.ARUBA_AOS_CX, "vlan 10\n dhcpv4-snooping\n"),
    (Vendor.ARUBA_AOS_S, "dhcp-snooping vlan 10\n"),
    (Vendor.HUAWEI_VRP, "vlan 10\n dhcp snooping enable\n#\n"),
])
def test_existing_findings_receive_same_risk_across_platforms(vendor, config):
    findings = AnalysisApplicationService().analyze(config, vendor).findings
    assert findings
    assert [(f.rule_id, f.risk_score) for f in findings] == [("DHCP-001", 8)]


def test_direct_analyzer_findings_receive_risk_automatically():
    findings = AnalyzerService().analyze("ip http server\n")
    assert [(f.rule_id, f.risk_score) for f in findings] == [("MGMT-002", 8)]


def test_posture_does_not_consume_finding_risk(monkeypatch):
    from dataclasses import asdict
    from pathlib import Path

    samples = sorted(Path("samples").rglob("*.cfg"))
    service = AnalysisApplicationService()

    def posture(sample):
        vendor = Vendor.ARUBA_AOS_CX if sample.parent.name == "aruba" else Vendor.CISCO_IOS
        return asdict(service.analyze(sample.read_text(), vendor).posture)

    expected = [posture(sample) for sample in samples]

    def reject_risk_access(self):
        raise AssertionError("Device posture must not consume finding risk")

    monkeypatch.setattr(Finding, "risk_score", property(reject_risk_access))
    assert [posture(sample) for sample in samples] == expected
