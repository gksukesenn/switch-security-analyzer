import pytest

from src.domain.models import ConfigState, CoverageClass, InterfaceMode
from src.parsers.huawei.vrp import HuaweiVRPParser


def interface_by_name(config, name):
    return next(interface for interface in config.interfaces if interface.name == name)


def test_parser_maps_sysname_and_global_dhcp_snooping_with_provenance():
    config = HuaweiVRPParser().parse(
        "sysname ACCESS-SW-01\ndhcp snooping enable\n"
    )

    assert config.vendor == "huawei_vrp"
    assert config.hostname == "ACCESS-SW-01"
    assert config.dhcp_snooping_global == ConfigState.ENABLED
    assert config.dhcp_snooping_global_evidence.line_number == 2
    assert config.dhcp_snooping_global_evidence.text == "dhcp snooping enable"
    assert config.parsed_line_coverage[1] == CoverageClass.OUT_OF_SCOPE


def test_parser_maps_global_dhcp_snooping_explicit_disable():
    config = HuaweiVRPParser().parse(
        "dhcp snooping enable\nundo dhcp snooping enable\n"
    )

    assert config.dhcp_snooping_global == ConfigState.DISABLED
    assert config.dhcp_snooping_global_evidence.line_number == 2


def test_vlan_context_dhcp_snooping_and_disable_preserve_provenance():
    config = HuaweiVRPParser().parse("""vlan 10
 dhcp snooping enable
#
vlan 20
 dhcp snooping enable
 undo dhcp snooping enable
#
""")

    assert config.dhcp_snooping_vlans == {10}
    assert config.dhcp_snooping_vlan_evidence[10].line_number == 2
    assert config.dhcp_snooping_vlan_evidence[10].text == (
        " dhcp snooping enable"
    )


def test_section_boundary_resets_vlan_and_interface_context():
    config = HuaweiVRPParser().parse("""vlan 10
#
 dhcp snooping enable
interface GigabitEthernet0/0/1
#
 stp edged-port enable
""")

    assert config.dhcp_snooping_vlans == set()
    interface = config.interfaces[0]
    assert interface.portfast == ConfigState.NOT_CONFIGURED
    assert [line.line_number for line in config.unparsed_lines] == [3, 6]
    assert config.parsed_line_coverage[2] == CoverageClass.OUT_OF_SCOPE
    assert config.parsed_line_coverage[5] == CoverageClass.OUT_OF_SCOPE


def test_vlan_batch_is_not_treated_as_single_vlan_context():
    config = HuaweiVRPParser().parse(
        "vlan batch 10 20\n dhcp snooping enable\n"
    )

    assert config.dhcp_snooping_vlans == set()
    assert [line.line_number for line in config.unparsed_lines] == [1, 2]


def test_interface_declaration_preserves_exact_name_and_source_line():
    config = HuaweiVRPParser().parse(
        "interface GigabitEthernet0/0/1\n#\n"
    )

    interface = config.interfaces[0]
    assert interface.name == "GigabitEthernet0/0/1"
    assert interface.declaration_evidence.line_number == 1
    assert interface.declaration_evidence.text == (
        "interface GigabitEthernet0/0/1"
    )
    assert interface.port_security == ConfigState.UNKNOWN
    assert interface.ip_source_guard == ConfigState.UNKNOWN
    assert interface.bpdu_guard == ConfigState.NOT_CONFIGURED


@pytest.mark.parametrize(
    "commands",
    [
        " port link-type access\n port default vlan 70",
        " port default vlan 70\n port link-type access",
    ],
)
def test_access_vlan_finalization_is_command_order_independent(commands):
    config = HuaweiVRPParser().parse(
        f"interface GigabitEthernet0/0/1\n{commands}\n#\n"
    )

    interface = config.interfaces[0]
    assert interface.mode == InterfaceMode.ACCESS
    assert interface.access_vlan == 70
    assert interface.access_vlan_evidence.text == " port default vlan 70"


def test_explicit_access_without_default_vlan_does_not_infer_vlan():
    interface = HuaweiVRPParser().parse(
        "interface GigabitEthernet0/0/1\n port link-type access\n#\n"
    ).interfaces[0]

    assert interface.mode == InterfaceMode.ACCESS
    assert interface.access_vlan is None


def test_explicit_trunk_clears_pending_access_vlan():
    interface = HuaweiVRPParser().parse("""interface GigabitEthernet0/0/1
 port default vlan 70
 port link-type trunk
#
""").interfaces[0]

    assert interface.mode == InterfaceMode.TRUNK
    assert interface.access_vlan is None
    assert interface.access_vlan_evidence is None


def test_hybrid_and_membership_stay_non_assessable():
    config = HuaweiVRPParser().parse("""interface GigabitEthernet0/0/1
 port default vlan 70
 port link-type hybrid
 port hybrid pvid vlan 70
 port hybrid tagged vlan 10 20
 port hybrid untagged vlan 70
#
""")

    interface = config.interfaces[0]
    assert interface.mode == InterfaceMode.UNKNOWN
    assert interface.access_vlan is None
    assert interface.access_vlan_evidence is None
    assert [line.line_number for line in config.unparsed_lines] == [4, 5, 6]


@pytest.mark.parametrize(
    ("link_type", "expected_mode"),
    [
        ("access", InterfaceMode.ACCESS),
        ("trunk", InterfaceMode.TRUNK),
        ("hybrid", InterfaceMode.UNKNOWN),
    ],
)
def test_dhcp_trust_preserves_interface_mode(link_type, expected_mode):
    interface = HuaweiVRPParser().parse(
        "interface GigabitEthernet0/0/1\n"
        f" port link-type {link_type}\n"
        " dhcp snooping trusted\n"
        "#\n"
    ).interfaces[0]

    assert interface.mode == expected_mode
    assert interface.dhcp_snooping_trust == ConfigState.ENABLED
    assert interface.dhcp_snooping_trust_evidence.line_number == 3


def test_interface_dhcp_snooping_enable_remains_unparsed():
    config = HuaweiVRPParser().parse("""interface GigabitEthernet0/0/1
 port link-type access
 port default vlan 70
 dhcp snooping enable
#
""")

    assert config.dhcp_snooping_vlans == set()
    assert [line.line_number for line in config.unparsed_lines] == [4]


def test_stp_edge_enable_and_verified_undo_are_normalized():
    config = HuaweiVRPParser().parse("""interface GigabitEthernet0/0/1
 stp edged-port enable
 undo stp edged-port
#
""")

    interface = config.interfaces[0]
    assert interface.portfast == ConfigState.DISABLED
    assert interface.portfast_evidence.line_number == 3
    assert interface.portfast_evidence.text == " undo stp edged-port"


def test_global_bpdu_protection_does_not_manufacture_interface_state():
    config = HuaweiVRPParser().parse("""stp bpdu-protection
interface GigabitEthernet0/0/1
 port link-type access
 stp edged-port enable
#
""")

    assert config.bpdu_guard_default == ConfigState.ENABLED
    assert config.bpdu_guard_default_evidence.line_number == 1
    assert config.interfaces[0].bpdu_guard == ConfigState.NOT_CONFIGURED


def test_deferred_security_commands_do_not_create_normalized_state():
    config = HuaweiVRPParser().parse("""http server-source -i Vlanif1
http server enable
telnet server enable
interface GigabitEthernet0/0/1
 port link-type access
 port default vlan 70
 arp anti-attack check user-bind enable
 ip source check user-bind enable
 port-security enable
 stp root-protection
 port trunk allow-pass vlan 10
 port hybrid pvid vlan 70
#
""")

    interface = config.interfaces[0]
    assert config.http_server == ConfigState.NOT_CONFIGURED
    assert config.dai_vlans == set()
    assert interface.port_security == ConfigState.UNKNOWN
    assert interface.ip_source_guard == ConfigState.UNKNOWN
    assert interface.mode == InterfaceMode.ACCESS
    assert interface.access_vlan == 70
    assert [line.line_number for line in config.unparsed_lines] == [
        1, 2, 3, 7, 8, 9, 10, 11, 12
    ]


def test_small_synthetic_fixture_has_conservative_mode_counts():
    config = HuaweiVRPParser().parse("""interface GigabitEthernet0/0/1
 port link-type access
 port default vlan 10
#
interface GigabitEthernet0/0/2
 port link-type trunk
#
interface GigabitEthernet0/0/3
 port link-type hybrid
 port hybrid pvid vlan 20
#
interface Vlanif10
#
""")

    assert sum(i.mode == InterfaceMode.ACCESS for i in config.interfaces) == 1
    assert sum(i.mode == InterfaceMode.TRUNK for i in config.interfaces) == 1
    assert sum(i.mode == InterfaceMode.UNKNOWN for i in config.interfaces) == 2
