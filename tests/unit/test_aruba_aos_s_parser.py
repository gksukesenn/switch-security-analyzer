import pytest

from src.domain.models import ConfigState, InterfaceMode
from src.parsers.aruba.aos_s import ArubaAOSSParser


def interface_by_name(config, name):
    return next(interface for interface in config.interfaces if interface.name == name)


def test_parser_expands_dhcp_snooping_vlan_expression_with_provenance():
    config = ArubaAOSSParser().parse(
        "dhcp-snooping\ndhcp-snooping vlan 10 601-620 777\n"
    )

    assert config.vendor == "aruba_aos_s"
    assert config.dhcp_snooping_global == ConfigState.ENABLED
    assert config.dhcp_snooping_global_evidence.line_number == 1
    assert config.dhcp_snooping_vlans == {10, *range(601, 621), 777}
    assert all(
        config.dhcp_snooping_vlan_evidence[vlan_id].line_number == 2
        for vlan_id in config.dhcp_snooping_vlans
    )
    assert config.dhcp_snooping_vlan_evidence[601].text == (
        "dhcp-snooping vlan 10 601-620 777"
    )


def test_parser_maps_vlan_context_snooping_and_no_form():
    config = ArubaAOSSParser().parse("""vlan 10
 dhcp-snooping
 exit
vlan 20
 dhcp-snooping
 no dhcp-snooping
 exit
no dhcp-snooping vlan 10
""")

    assert config.dhcp_snooping_vlans == set()
    assert config.dhcp_snooping_vlan_evidence == {}


def test_untagged_membership_becomes_access_with_exact_provenance():
    config = ArubaAOSSParser().parse("""vlan 10
 untagged 1-2,4
 exit
""")

    interface = interface_by_name(config, "2")
    assert interface.mode == InterfaceMode.ACCESS
    assert interface.access_vlan == 10
    assert interface.declaration_evidence.line_number == 2
    assert interface.mode_evidence.text == " untagged 1-2,4"
    assert interface.access_vlan_evidence.line_number == 2
    assert interface.port_security == ConfigState.UNKNOWN
    assert interface.ip_source_guard == ConfigState.UNKNOWN
    assert interface.portfast == ConfigState.UNKNOWN
    assert interface.bpdu_guard == ConfigState.UNKNOWN


@pytest.mark.parametrize(
    "membership_lines",
    [
        " untagged 1\n tagged 1",
        " tagged 1\n untagged 1",
    ],
)
def test_any_tagged_membership_becomes_trunk_without_access_vlan(
    membership_lines,
):
    config = ArubaAOSSParser().parse(
        f"vlan 10\n{membership_lines}\n exit\n"
    )

    interface = interface_by_name(config, "1")
    assert interface.mode == InterfaceMode.TRUNK
    assert interface.access_vlan is None
    assert interface.access_vlan_evidence is None
    assert interface.mode_evidence.text == " tagged 1"


def test_conflicting_untagged_memberships_remain_non_assessable():
    config = ArubaAOSSParser().parse("""vlan 10
 untagged 1
 exit
vlan 20
 untagged 1
 exit
""")

    interface = interface_by_name(config, "1")
    assert interface.mode == InterfaceMode.UNKNOWN
    assert interface.access_vlan is None
    assert interface.mode_evidence is None
    assert interface.access_vlan_evidence is None


def test_interface_trust_preserves_access_and_tagged_port_states():
    config = ArubaAOSSParser().parse("""vlan 10
 untagged 1
 tagged 2
 exit
interface 1
 dhcp-snooping trust
 exit
interface 2
 dhcp-snooping trust
 exit
""")

    access = interface_by_name(config, "1")
    tagged = interface_by_name(config, "2")
    assert access.mode == InterfaceMode.ACCESS
    assert access.dhcp_snooping_trust == ConfigState.ENABLED
    assert access.dhcp_snooping_trust_evidence.line_number == 6
    assert tagged.mode == InterfaceMode.TRUNK
    assert tagged.dhcp_snooping_trust == ConfigState.ENABLED
    assert tagged.dhcp_snooping_trust_evidence.line_number == 9


def test_global_port_list_trust_and_no_form_update_interfaces():
    config = ArubaAOSSParser().parse(
        "dhcp-snooping trust 1-3\nno dhcp-snooping trust 2\n"
    )

    assert interface_by_name(config, "1").dhcp_snooping_trust == (
        ConfigState.ENABLED
    )
    assert interface_by_name(config, "2").dhcp_snooping_trust == (
        ConfigState.DISABLED
    )
    assert interface_by_name(config, "2").dhcp_snooping_trust_evidence.line_number == 2
    assert interface_by_name(config, "3").dhcp_snooping_trust == (
        ConfigState.ENABLED
    )


def test_arp_protect_vlan_expression_and_no_form_are_normalized():
    config = ArubaAOSSParser().parse(
        "arp-protect vlan 10 601-603 777\nno arp-protect vlan 602 777\n"
    )

    assert config.dai_vlans == {10, 601, 603}
    assert config.dai_vlan_evidence[10].line_number == 1
    assert config.dai_vlan_evidence[603].text == (
        "arp-protect vlan 10 601-603 777"
    )


@pytest.mark.parametrize(
    "expression",
    ["", "20-10", "0", "4095", "10-", "1-2-3", "ten"],
)
def test_invalid_vlan_expressions_are_left_unparsed(expression):
    raw_text = f"dhcp-snooping vlan {expression}\n"
    config = ArubaAOSSParser().parse(raw_text)

    assert config.dhcp_snooping_vlans == set()
    assert config.dhcp_snooping_vlan_evidence == {}
    assert [line.text for line in config.unparsed_lines] == [raw_text.strip()]
    assert config.parsed_line_coverage == {}
