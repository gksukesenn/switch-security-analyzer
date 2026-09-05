import pytest

from src.domain.models import ConfigState, InterfaceMode
from src.domain.vendors import Vendor
from src.services.analysis import AnalysisApplicationService


REGISTERED_RULE_IDS = {
    "DHCP-001",
    "DHCP-002",
    "DHCP-003",
    "DAI-001",
    "IPSG-001",
    "PORTSEC-001",
    "STP-001",
    "MGMT-001",
    "MGMT-002",
}
HUAWEI_SUPPORTED_RULE_IDS = {
    "DHCP-001",
    "DHCP-002",
    "DHCP-003",
    "STP-001",
}


def analyze(raw_text, vendor=Vendor.HUAWEI_VRP):
    return AnalysisApplicationService().analyze(raw_text, vendor)


def finding_ids(result):
    return [finding.rule_id for finding in result.findings]


def test_dhcp_001_requires_effective_global_enable():
    without_global = analyze(
        "vlan 10\n"
        " dhcp snooping enable\n"
        "#\n"
    )
    with_global = analyze(
        "dhcp snooping enable\n"
        "vlan 10\n"
        " dhcp snooping enable\n"
        "#\n"
    )

    assert "DHCP-001" in finding_ids(without_global)
    assert without_global.evaluations["DHCP-001"].assessed_units == 1
    assert "DHCP-001" not in finding_ids(with_global)
    assert with_global.evaluations["DHCP-001"].assessed_units == 1


def test_dhcp_002_assesses_explicit_access_vlan_scope():
    uncovered = analyze(
        "dhcp snooping enable\n"
        "vlan 10\n"
        " dhcp snooping enable\n"
        "#\n"
        "interface GigabitEthernet0/0/1\n"
        " port link-type access\n"
        " port default vlan 20\n"
        "#\n"
    )
    covered = analyze(
        "dhcp snooping enable\n"
        "vlan 10\n"
        " dhcp snooping enable\n"
        "#\n"
        "vlan 20\n"
        " dhcp snooping enable\n"
        "#\n"
        "interface GigabitEthernet0/0/1\n"
        " port link-type access\n"
        " port default vlan 20\n"
        "#\n"
    )

    finding = next(
        finding
        for finding in uncovered.findings
        if finding.rule_id == "DHCP-002"
    )
    assert finding.affected_interfaces == ["GigabitEthernet0/0/1"]
    assert uncovered.evaluations["DHCP-002"].assessed_units == 1
    assert "DHCP-002" not in finding_ids(covered)
    assert covered.evaluations["DHCP-002"].assessed_units == 1


def test_dhcp_002_does_not_assess_hybrid_as_access():
    result = analyze(
        "dhcp snooping enable\n"
        "vlan 10\n"
        " dhcp snooping enable\n"
        "#\n"
        "interface GigabitEthernet0/0/1\n"
        " port link-type hybrid\n"
        " port hybrid pvid vlan 20\n"
        "#\n"
    )

    assert result.config.interfaces[0].mode == InterfaceMode.UNKNOWN
    assert result.config.interfaces[0].access_vlan is None
    assert result.evaluations["DHCP-002"].assessed_units == 0
    assert "DHCP-002" not in finding_ids(result)


def test_dhcp_003_flags_only_trusted_explicit_access_port():
    trusted_access = analyze(
        "dhcp snooping enable\n"
        "vlan 10\n"
        " dhcp snooping enable\n"
        "#\n"
        "interface GigabitEthernet0/0/1\n"
        " port link-type access\n"
        " port default vlan 10\n"
        " dhcp snooping trusted\n"
        "#\n"
    )

    finding = next(
        finding
        for finding in trusted_access.findings
        if finding.rule_id == "DHCP-003"
    )
    assert finding.affected_interfaces == ["GigabitEthernet0/0/1"]
    assert finding.safe_config_example == (
        "interface GigabitEthernet0/0/1\n"
        " undo dhcp snooping trusted\n"
        "quit"
    )

    for mode_command in ("port link-type trunk", "port link-type hybrid"):
        result = analyze(
            "dhcp snooping enable\n"
            "vlan 10\n"
            " dhcp snooping enable\n"
            "#\n"
            "interface GigabitEthernet0/0/1\n"
            f" {mode_command}\n"
            " dhcp snooping trusted\n"
            "#\n"
        )
        assert result.evaluations["DHCP-003"].assessed_units == 0
        assert "DHCP-003" not in finding_ids(result)


def test_stp_001_uses_global_huawei_bpdu_protection():
    weak = analyze(
        "interface GigabitEthernet0/0/1\n"
        " port link-type access\n"
        " port default vlan 10\n"
        " stp edged-port enable\n"
        "#\n"
    )
    protected = analyze(
        "stp bpdu-protection\n"
        "interface GigabitEthernet0/0/1\n"
        " port link-type access\n"
        " port default vlan 10\n"
        " stp edged-port enable\n"
        "#\n"
    )

    finding = next(
        finding for finding in weak.findings if finding.rule_id == "STP-001"
    )
    assert finding.safe_config_example == "stp bpdu-protection"
    assert finding.affected_interfaces == ["GigabitEthernet0/0/1"]
    assert "STP-001" not in finding_ids(protected)
    assert protected.evaluations["STP-001"].assessed_units == 1
    assert protected.config.interfaces[0].bpdu_guard == ConfigState.NOT_CONFIGURED


def test_disabled_edge_intent_is_not_assessed_by_stp_001():
    result = analyze(
        "interface GigabitEthernet0/0/1\n"
        " port link-type access\n"
        " port default vlan 10\n"
        " undo stp edged-port\n"
        "#\n"
    )

    assert result.config.interfaces[0].portfast == ConfigState.DISABLED
    assert result.evaluations["STP-001"].assessed_units == 0
    assert "STP-001" not in finding_ids(result)


def test_deferred_huawei_controls_remain_explicitly_unassessed():
    result = analyze(
        "dhcp snooping enable\n"
        "vlan 10\n"
        " dhcp snooping enable\n"
        " arp anti-attack check user-bind enable\n"
        "#\n"
        "interface GigabitEthernet0/0/1\n"
        " port link-type access\n"
        " port default vlan 10\n"
        " ip source check user-bind enable\n"
        " port-security enable\n"
        "#\n"
        "telnet server enable\n"
        "http server enable\n"
    )

    for rule_id in REGISTERED_RULE_IDS - HUAWEI_SUPPORTED_RULE_IDS:
        evaluation = result.evaluations[rule_id]
        assert evaluation.findings == []
        assert evaluation.assessed_units == 0
    assert result.config.dai_vlans == set()
    assert result.coverage.unsupported_relevant == 5


def test_safe_first_slice_keeps_nine_rule_denominator_and_n_a_posture():
    result = analyze(
        "dhcp snooping enable\n"
        "vlan 10\n"
        " dhcp snooping enable\n"
        "#\n"
        "stp bpdu-protection\n"
        "interface GigabitEthernet0/0/1\n"
        " port link-type access\n"
        " port default vlan 10\n"
        " stp edged-port enable\n"
        "#\n"
    )

    assert set(result.evaluations) == REGISTERED_RULE_IDS
    assert result.findings == ()
    assert result.posture.assessed_rule_count == 4
    assert result.posture.total_rule_count == 9
    assert result.posture.rule_assessment_ratio == pytest.approx(4 / 9)
    assert result.posture.score is None
    assert result.posture.risk_level is None
    assert result.posture.unavailable_reason == "insufficient_rule_assessment"


@pytest.mark.parametrize(
    ("vendor", "raw_text"),
    [
        (
            Vendor.CISCO_IOS,
            "ip dhcp snooping\n"
            "ip dhcp snooping vlan 10\n"
            "interface GigabitEthernet1/0/1\n"
            " switchport mode access\n"
            " switchport access vlan 10\n"
            " ip dhcp snooping trust\n"
            "!\n",
        ),
        (
            Vendor.ARUBA_AOS_CX,
            "dhcpv4-snooping\n"
            "vlan 10\n"
            " dhcpv4-snooping\n"
            "!\n"
            "interface 1/1/1\n"
            " no routing\n"
            " vlan access 10\n"
            " dhcpv4-snooping trust\n"
            "!\n",
        ),
        (
            Vendor.ARUBA_AOS_S,
            "dhcp-snooping\n"
            "dhcp-snooping vlan 10\n"
            "vlan 10\n"
            " untagged 1\n"
            " exit\n"
            "interface 1\n"
            " dhcp-snooping trust\n"
            " exit\n",
        ),
        (
            Vendor.HUAWEI_VRP,
            "dhcp snooping enable\n"
            "vlan 10\n"
            " dhcp snooping enable\n"
            "#\n"
            "interface GigabitEthernet0/0/1\n"
            " port link-type access\n"
            " port default vlan 10\n"
            " dhcp snooping trusted\n"
            "#\n",
        ),
    ],
)
def test_cross_vendor_trusted_endpoint_has_dhcp_003_semantic_parity(
    vendor,
    raw_text,
):
    result = analyze(raw_text, vendor)

    evaluation = result.evaluations["DHCP-003"]
    assert evaluation.assessed_units == 1
    assert [finding.rule_id for finding in evaluation.findings] == [
        "DHCP-003"
    ]
