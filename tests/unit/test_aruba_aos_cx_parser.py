import pytest

from src.domain.models import ConfigState, CoverageClass, InterfaceMode
from src.parsers.aruba.aos_cx import ArubaAOSCXParser


def test_parser_maps_global_vlan_and_interface_provenance():
    config = ArubaAOSCXParser().parse("""hostname ACCESS-CX-01
dhcpv4-snooping
vlan 20
 dhcpv4-snooping
 arp inspection
!
interface 1/1/1
 no routing
 vlan access 20
 dhcpv4-snooping trust
 spanning-tree port-type admin-edge
 spanning-tree bpdu-guard
!
""")

    assert config.vendor == "aruba_aos_cx"
    assert config.hostname == "ACCESS-CX-01"
    assert config.dhcp_snooping_global == ConfigState.ENABLED
    assert config.dhcp_snooping_global_evidence.text == "dhcpv4-snooping"
    assert config.dhcp_snooping_vlans == {20}
    assert config.dhcp_snooping_vlan_evidence[20].line_number == 4
    assert config.dai_vlans == {20}
    assert config.dai_vlan_evidence[20].text == " arp inspection"

    interface = config.interfaces[0]
    assert interface.name == "1/1/1"
    assert interface.declaration_evidence.line_number == 7
    assert interface.mode == InterfaceMode.ACCESS
    assert interface.mode_evidence.text == " vlan access 20"
    assert interface.access_vlan == 20
    assert interface.access_vlan_evidence.line_number == 9
    assert interface.dhcp_snooping_trust == ConfigState.ENABLED
    assert interface.dhcp_snooping_trust_evidence.line_number == 10
    assert interface.portfast == ConfigState.ENABLED
    assert interface.portfast_evidence.text == (
        " spanning-tree port-type admin-edge"
    )
    assert interface.bpdu_guard == ConfigState.ENABLED
    assert interface.bpdu_guard_evidence.text == (
        " spanning-tree bpdu-guard"
    )


@pytest.mark.parametrize(
    ("commands", "expected_vlan", "evidence_text"),
    [
        (" no routing\n vlan access 20", 20, " vlan access 20"),
        (" no routing", 1, " no routing"),
        (" vlan access 20", 20, " vlan access 20"),
    ],
)
def test_parser_uses_documented_access_mode_semantics(
    commands,
    expected_vlan,
    evidence_text,
):
    config = ArubaAOSCXParser().parse(
        f"interface 1/1/1\n{commands}\n!\n"
    )

    interface = config.interfaces[0]
    assert interface.mode == InterfaceMode.ACCESS
    assert interface.access_vlan == expected_vlan
    assert interface.mode_evidence.text == evidence_text
    assert interface.access_vlan_evidence.text == evidence_text


def test_parser_maps_explicit_disable_forms():
    config = ArubaAOSCXParser().parse("""no dhcpv4-snooping
vlan 20
 dhcpv4-snooping
 no dhcpv4-snooping
 arp inspection
 no arp inspection
!
interface 1/1/1
 no dhcpv4-snooping trust
 no spanning-tree port-type admin-edge
 no spanning-tree bpdu-guard
!
""")

    assert config.dhcp_snooping_global == ConfigState.DISABLED
    assert config.dhcp_snooping_vlans == set()
    assert config.dai_vlans == set()
    interface = config.interfaces[0]
    assert interface.dhcp_snooping_trust == ConfigState.DISABLED
    assert interface.portfast == ConfigState.DISABLED
    assert interface.bpdu_guard == ConfigState.DISABLED
    assert interface.dhcp_snooping_trust_evidence.line_number == 9
    assert interface.portfast_evidence.line_number == 10
    assert interface.bpdu_guard_evidence.line_number == 11


def test_unsupported_security_fields_are_unknown_not_not_configured():
    interface = ArubaAOSCXParser().parse(
        "interface 1/1/1\n no routing\n!\n"
    ).interfaces[0]

    assert interface.port_security == ConfigState.UNKNOWN
    assert interface.ip_source_guard == ConfigState.UNKNOWN


def test_unknown_aruba_syntax_is_preserved_and_not_marked_parsed():
    config = ArubaAOSCXParser().parse("""interface 1/1/1
 mystery security feature
!
""")

    assert config.unparsed_lines[0].line_number == 2
    assert config.unparsed_lines[0].text == " mystery security feature"
    assert config.parsed_line_coverage == {
        1: CoverageClass.SUPPORTED_RELEVANT
    }
