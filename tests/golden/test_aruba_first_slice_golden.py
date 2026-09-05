from pathlib import Path

import pytest

from src.domain.models import ConfigState
from src.parsers.aruba.aos_cx import ArubaAOSCXParser
from src.renderers.safe_config import ArubaSafeConfigRenderer
from src.rules.dai.dai_001 import DAI001DhcpVlanWithoutDAIRule
from src.rules.dhcp.dhcp_001 import DHCP001GloballyInactiveRule
from src.rules.dhcp.dhcp_002 import DHCP002AccessVlanNotCoveredRule
from src.rules.dhcp.dhcp_003 import DHCP003TrustedAccessPortRule
from src.rules.ip_source_guard.ipsg_001 import (
    IPSG001DhcpEndpointWithoutIPSGRule,
)
from src.rules.stp.stp_001 import STP001PortFastWithoutBPDUGuardRule


SAMPLES = Path("samples/aruba")
RENDERER = ArubaSafeConfigRenderer()


@pytest.mark.parametrize(
    ("rule", "unsafe", "safe", "rule_id"),
    [
        (
            DHCP001GloballyInactiveRule(RENDERER),
            "dhcp_001_global_inactive.cfg",
            "dhcp_001_global_active.cfg",
            "DHCP-001",
        ),
        (
            DHCP002AccessVlanNotCoveredRule(RENDERER),
            "dhcp_002_access_vlan_uncovered.cfg",
            "dhcp_002_access_vlan_covered.cfg",
            "DHCP-002",
        ),
        (
            DHCP003TrustedAccessPortRule(RENDERER),
            "dhcp_003_trusted_access.cfg",
            "dhcp_003_untrusted_access.cfg",
            "DHCP-003",
        ),
        (
            DAI001DhcpVlanWithoutDAIRule(RENDERER),
            "dai_001_vlan_without_dai.cfg",
            "dai_001_vlan_with_dai.cfg",
            "DAI-001",
        ),
        (
            STP001PortFastWithoutBPDUGuardRule(RENDERER),
            "stp_001_admin_edge_without_bpdu_guard.cfg",
            "stp_001_admin_edge_with_bpdu_guard.cfg",
            "STP-001",
        ),
    ],
)
def test_aruba_first_slice_unsafe_and_safe_fixtures(
    rule,
    unsafe,
    safe,
    rule_id,
):
    parser = ArubaAOSCXParser()

    findings = rule.evaluate(parser.parse((SAMPLES / unsafe).read_text()))

    assert [finding.rule_id for finding in findings] == [rule_id]
    assert rule.evaluate(parser.parse((SAMPLES / safe).read_text())) == []
    assert all(
        "switchport" not in line.text
        and "ip dhcp snooping" not in line.text
        for line in findings[0].evidence
    )


def test_unsupported_aruba_controls_do_not_create_ipsg_or_portsec_findings():
    from src.services.analysis import AnalysisApplicationService
    from src.domain.vendors import Vendor

    result = AnalysisApplicationService().analyze(
        (SAMPLES / "coverage_supported_only.cfg").read_text(),
        Vendor.ARUBA_AOS_CX,
    )

    assert "IPSG-001" not in [finding.rule_id for finding in result.findings]
    assert "PORTSEC-001" not in [
        finding.rule_id for finding in result.findings
    ]
    assert result.evaluations["IPSG-001"].findings == []
    assert result.evaluations["IPSG-001"].assessed_units == 0
    assert result.posture.assessed_rule_count == 5
    assert result.posture.total_rule_count == 10
    assert result.posture.rule_assessment_ratio == pytest.approx(5 / 10)
    assert result.posture.score is None
    assert result.posture.risk_level is None


def test_aruba_unknown_ipsg_endpoint_is_not_assessed():
    config = ArubaAOSCXParser().parse(
        (SAMPLES / "coverage_supported_only.cfg").read_text()
    )

    evaluation = IPSG001DhcpEndpointWithoutIPSGRule(
        RENDERER
    ).evaluate_detailed(config)

    assert config.interfaces[0].ip_source_guard == ConfigState.UNKNOWN
    assert evaluation.findings == []
    assert evaluation.assessed_units == 0
