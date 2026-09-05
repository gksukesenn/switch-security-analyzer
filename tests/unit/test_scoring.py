import pytest

from src.domain.models import (
    AnalysisConfidence,
    Confidence,
    Finding,
    RuleEvaluation,
    Severity,
)
from src.domain.scoring import RiskLevel
from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.dhcp.dhcp_003 import DHCP003TrustedAccessPortRule
from src.services.scoring import ScoringCalculator, ScoringService


def finding(
    rule_id: str,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    affected_interfaces: list[str] | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Synthetic scoring finding",
        category="TEST",
        severity=severity,
        confidence=confidence,
        technical_impact="Synthetic impact.",
        remediation="Synthetic remediation.",
        safe_config_example="synthetic safe config",
        affected_interfaces=affected_interfaces or [],
    )


def evaluations(
    total: int = 9,
    assessed: int = 6,
) -> dict[str, RuleEvaluation]:
    return {
        f"RULE-{index}": RuleEvaluation(
            findings=[],
            assessed_units=int(index < assessed),
        )
        for index in range(total)
    }


def test_zero_findings_with_insufficient_assessment_is_unavailable():
    result = ScoringCalculator.calculate(
        evaluations(assessed=5),
        AnalysisConfidence.HIGH,
    )

    assert result.score is None
    assert result.risk_level is None
    assert result.unavailable_reason == "insufficient_rule_assessment"


def test_fully_assessed_clean_score_is_100_low_risk():
    result = ScoringCalculator.calculate(
        evaluations(assessed=9),
        AnalysisConfidence.HIGH,
    )

    assert result.score == 100.0
    assert result.display_score == 100
    assert result.total_penalty == 0.0
    assert result.risk_level == RiskLevel.LOW


def test_one_high_high_finding_scores_85_moderate():
    rule_evaluations = evaluations()
    rule_evaluations["RULE-0"] = RuleEvaluation(
        findings=[finding("RULE-0")],
        assessed_units=1,
    )

    result = ScoringCalculator.calculate(
        rule_evaluations,
        AnalysisConfidence.HIGH,
    )

    assert result.total_penalty == 15.0
    assert result.score == 85.0
    assert result.display_score == 85
    assert result.risk_level == RiskLevel.MODERATE


def test_high_medium_uses_confidence_multiplier():
    rule_evaluations = evaluations()
    rule_evaluations["RULE-0"] = RuleEvaluation(
        findings=[
            finding("RULE-0", confidence=Confidence.MEDIUM)
        ],
        assessed_units=1,
    )

    result = ScoringCalculator.calculate(
        rule_evaluations,
        AnalysisConfidence.HIGH,
    )

    assert result.rule_penalties[0].base_penalty == 10.5
    assert result.total_penalty == 10.5
    assert result.score == 89.5
    assert result.total_penalty != 15.0


def test_repeated_dhcp_findings_use_capped_nonlinear_exposure():
    rule_evaluations = evaluations()
    rule_evaluations.pop("RULE-0")
    interface_config = "\n".join(
        (
            f"interface GigabitEthernet1/0/{index}\n"
            " switchport mode access\n"
            " switchport access vlan 10\n"
            " ip dhcp snooping trust\n"
            "!"
        )
        for index in range(1, 21)
    )
    config = CiscoIOSParser().parse(
        "ip dhcp snooping\n"
        "ip dhcp snooping vlan 10\n"
        f"{interface_config}\n"
    )
    rule_evaluations["DHCP-003"] = (
        DHCP003TrustedAccessPortRule().evaluate_detailed(config)
    )

    result = ScoringCalculator.calculate(
        rule_evaluations,
        AnalysisConfidence.HIGH,
    )
    penalty = result.rule_penalties[0]

    assert len(rule_evaluations["DHCP-003"].findings) == 20
    assert rule_evaluations["DHCP-003"].assessed_units == 20
    assert penalty.base_penalty == 10.5
    assert penalty.violating_units == 20
    assert penalty.exposure_factor == 1.60
    assert penalty.penalty == pytest.approx(16.8)
    assert penalty.penalty != 20 * 10.5


def test_stp_aggregate_interfaces_reach_exposure_cap():
    rule_evaluations = evaluations()
    interfaces = [f"GigabitEthernet1/0/{index}" for index in range(1, 21)]
    rule_evaluations["STP-001"] = RuleEvaluation(
        findings=[finding("STP-001", affected_interfaces=interfaces)],
        assessed_units=20,
    )

    result = ScoringCalculator.calculate(
        rule_evaluations,
        AnalysisConfidence.HIGH,
    )
    penalty = result.rule_penalties[0]

    assert penalty.violating_units == 20
    assert penalty.exposure_factor == 1.60


def test_vlan_assessment_caps_dai_interface_exposure_at_one():
    rule_evaluations = evaluations()
    interfaces = [f"GigabitEthernet1/0/{index}" for index in range(1, 21)]
    rule_evaluations["DAI-001"] = RuleEvaluation(
        findings=[finding("DAI-001", affected_interfaces=interfaces)],
        assessed_units=1,
    )

    result = ScoringCalculator.calculate(
        rule_evaluations,
        AnalysisConfidence.HIGH,
    )
    penalty = result.rule_penalties[0]

    assert penalty.violating_units == 1
    assert penalty.exposure_factor == 1.0


def test_low_analysis_confidence_makes_score_unavailable():
    rule_evaluations = evaluations(assessed=9)
    rule_evaluations["RULE-0"] = RuleEvaluation(
        findings=[finding("RULE-0")],
        assessed_units=1,
    )

    result = ScoringCalculator.calculate(
        rule_evaluations,
        AnalysisConfidence.LOW,
    )

    assert result.score is None
    assert result.risk_level is None
    assert result.unavailable_reason == "analysis_confidence_low"


def test_medium_analysis_confidence_does_not_reduce_score():
    rule_evaluations = evaluations()
    rule_evaluations["RULE-0"] = RuleEvaluation(
        findings=[finding("RULE-0")],
        assessed_units=1,
    )

    high = ScoringCalculator.calculate(
        rule_evaluations,
        AnalysisConfidence.HIGH,
    )
    medium = ScoringCalculator.calculate(
        rule_evaluations,
        AnalysisConfidence.MEDIUM,
    )

    assert medium.score == high.score == 85.0
    assert medium.analysis_confidence == AnalysisConfidence.MEDIUM


def test_rule_assessment_ratio_at_boundary_is_allowed():
    result = ScoringCalculator.calculate(
        evaluations(total=10, assessed=6),
        AnalysisConfidence.HIGH,
    )

    assert result.rule_assessment_ratio == 0.60
    assert result.score == 100.0


def test_rule_assessment_ratio_below_boundary_is_unavailable():
    result = ScoringCalculator.calculate(
        evaluations(total=10, assessed=5),
        AnalysisConfidence.HIGH,
    )

    assert result.rule_assessment_ratio == 0.50
    assert result.score is None


@pytest.mark.parametrize(
    ("raw_score", "expected"),
    [
        (90.0, RiskLevel.LOW),
        (89.5, RiskLevel.MODERATE),
        (75.0, RiskLevel.MODERATE),
        (74.5, RiskLevel.HIGH),
        (50.0, RiskLevel.HIGH),
        (49.5, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_uses_raw_score_boundaries(raw_score, expected):
    assert ScoringCalculator._risk_level(raw_score) == expected


def test_findings_without_assessed_units_violate_invariant():
    rule_evaluations = evaluations()
    rule_evaluations["RULE-0"] = RuleEvaluation(
        findings=[finding("RULE-0")],
        assessed_units=0,
    )

    with pytest.raises(ValueError, match="without assessed units"):
        ScoringCalculator.calculate(
            rule_evaluations,
            AnalysisConfidence.HIGH,
        )


def test_scoring_service_keeps_zero_finding_unassessed_config_unavailable():
    result = ScoringService().evaluate("hostname UNASSESSED-SWITCH\n")

    assert result.score is None
    assert result.assessed_rule_count == 0
    assert result.analysis_confidence == AnalysisConfidence.UNKNOWN


def test_scoring_service_scores_fully_assessed_clean_config():
    raw_text = """ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
no ip http server
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 switchport port-security
 spanning-tree portfast
 spanning-tree bpduguard enable
 ip verify source
!
line vty 0 4
 transport input ssh
"""

    result = ScoringService().evaluate(raw_text)

    assert result.assessed_rule_count == 9
    assert result.total_rule_count == 10
    assert result.rule_assessment_ratio == 0.9
    assert result.score == 100.0
    assert result.risk_level == RiskLevel.LOW
