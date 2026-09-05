import pytest

from src.domain.models import ConfigState
from src.domain.vendors import Vendor
from src.services.analysis import AnalysisApplicationService


def analyze(raw_text, vendor=Vendor.ARUBA_AOS_S):
    return AnalysisApplicationService().analyze(raw_text, vendor)


def finding_ids(result):
    return [finding.rule_id for finding in result.findings]


def test_dhcp_001_requires_effective_global_enable():
    without_global = analyze(
        "dhcp-snooping vlan 20\n"
        "vlan 20\n"
        " untagged 1\n"
        " exit\n"
    )
    with_global = analyze(
        "dhcp-snooping\n"
        "dhcp-snooping vlan 20\n"
        "vlan 20\n"
        " untagged 1\n"
        " exit\n"
    )

    assert "DHCP-001" in finding_ids(without_global)
    assert "DHCP-001" not in finding_ids(with_global)


def test_dhcp_002_assesses_only_access_vlan_scope():
    uncovered = analyze(
        "dhcp-snooping\n"
        "dhcp-snooping vlan 10\n"
        "vlan 20\n"
        " untagged 1\n"
        " exit\n"
    )
    covered = analyze(
        "dhcp-snooping\n"
        "dhcp-snooping vlan 10 20\n"
        "vlan 20\n"
        " untagged 1\n"
        " exit\n"
    )

    finding = next(
        finding
        for finding in uncovered.findings
        if finding.rule_id == "DHCP-002"
    )
    assert finding.affected_interfaces == ["1"]
    assert "DHCP-002" not in finding_ids(covered)


def test_dhcp_003_flags_trusted_access_but_not_trusted_tagged_port():
    trusted_access = analyze(
        "dhcp-snooping\n"
        "dhcp-snooping vlan 20\n"
        "vlan 20\n"
        " untagged 1\n"
        " exit\n"
        "interface 1\n"
        " dhcp-snooping trust\n"
        " exit\n"
    )
    trusted_tagged = analyze(
        "dhcp-snooping\n"
        "dhcp-snooping vlan 20\n"
        "vlan 20\n"
        " tagged 1\n"
        " exit\n"
        "interface 1\n"
        " dhcp-snooping trust\n"
        " exit\n"
    )

    finding = next(
        finding
        for finding in trusted_access.findings
        if finding.rule_id == "DHCP-003"
    )
    assert finding.affected_interfaces == ["1"]
    assert "DHCP-003" not in finding_ids(trusted_tagged)
    assert trusted_tagged.evaluations["DHCP-003"].assessed_units == 0


def test_dai_001_tracks_arp_protect_vlan_scope():
    without_dai = analyze(
        "dhcp-snooping\n"
        "dhcp-snooping vlan 20\n"
        "vlan 20\n"
        " untagged 1\n"
        " exit\n"
    )
    with_dai = analyze(
        "dhcp-snooping\n"
        "dhcp-snooping vlan 20\n"
        "arp-protect vlan 20\n"
        "vlan 20\n"
        " untagged 1\n"
        " exit\n"
    )

    assert "DAI-001" in finding_ids(without_dai)
    assert "DAI-001" not in finding_ids(with_dai)


def test_dynamic_aaa_does_not_create_static_access_vlan_state():
    result = analyze(
        "dhcp-snooping\n"
        "dhcp-snooping vlan 20\n"
        "aaa port-access authenticator 1 auth-vid 20\n"
    )

    assert result.config.interfaces == []
    assert result.evaluations["DHCP-002"].assessed_units == 0
    assert result.evaluations["DHCP-003"].assessed_units == 0
    assert result.evaluations["DAI-001"].assessed_units == 0


def test_limited_first_slice_keeps_other_rules_unassessed_and_score_n_a():
    result = analyze(
        "dhcp-snooping\n"
        "dhcp-snooping vlan 20\n"
        "arp-protect vlan 20\n"
        "vlan 20\n"
        " untagged 1\n"
        " exit\n"
    )

    for rule_id in (
        "PORTSEC-001",
        "STP-001",
        "IPSG-001",
        "MGMT-001",
        "MGMT-002",
    ):
        assert result.evaluations[rule_id].assessed_units == 0
        assert result.evaluations[rule_id].findings == []

    assert result.config.interfaces[0].port_security == ConfigState.UNKNOWN
    assert result.posture.assessed_rule_count == 4
    assert result.posture.total_rule_count == 10
    assert result.posture.rule_assessment_ratio == pytest.approx(4 / 10)
    assert result.posture.score is None
    assert result.posture.risk_level is None
    assert result.posture.unavailable_reason == "insufficient_rule_assessment"


@pytest.mark.parametrize(
    ("vendor", "raw_text"),
    [
        (
            Vendor.CISCO_IOS,
            "ip dhcp snooping\n"
            "ip dhcp snooping vlan 20\n"
            "interface GigabitEthernet1/0/1\n"
            " switchport mode access\n"
            " switchport access vlan 20\n"
            "!\n",
        ),
        (
            Vendor.ARUBA_AOS_CX,
            "dhcpv4-snooping\n"
            "vlan 20\n"
            " dhcpv4-snooping\n"
            "!\n"
            "interface 1/1/1\n"
            " no routing\n"
            " vlan access 20\n"
            "!\n",
        ),
        (
            Vendor.ARUBA_AOS_S,
            "dhcp-snooping\n"
            "dhcp-snooping vlan 20\n"
            "vlan 20\n"
            " untagged 1\n"
            " exit\n",
        ),
    ],
)
def test_cross_vendor_first_slice_has_equivalent_rule_semantics(
    vendor,
    raw_text,
):
    result = analyze(raw_text, vendor)
    applicable = {
        rule_id: (
            evaluation.assessed_units,
            [finding.rule_id for finding in evaluation.findings],
        )
        for rule_id, evaluation in result.evaluations.items()
        if rule_id in {"DHCP-001", "DHCP-002", "DHCP-003", "DAI-001"}
    }

    assert applicable == {
        "DHCP-001": (1, []),
        "DHCP-002": (1, []),
        "DHCP-003": (1, []),
        "DAI-001": (1, ["DAI-001"]),
    }
