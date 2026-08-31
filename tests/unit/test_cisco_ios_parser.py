from src.domain.models import (
    ConfigState,
    InterfaceMode,
)
from src.parsers.cisco.ios import CiscoIOSParser


def test_parser_reads_basic_dhcp_snooping_config():
    raw_config = """hostname ACCESS-SW-01
ip dhcp snooping
ip dhcp snooping vlan 10
!
interface GigabitEthernet1/0/5
 description USER-PC
 switchport mode access
 switchport access vlan 10
 ip dhcp snooping trust
!
"""

    parser = CiscoIOSParser()

    config = parser.parse(raw_config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"

    assert config.dhcp_snooping_global == ConfigState.ENABLED
    assert config.dhcp_snooping_vlans == {10}

    assert len(config.interfaces) == 1

    interface = config.interfaces[0]

    assert interface.name == "GigabitEthernet1/0/5"
    assert interface.description == "USER-PC"
    assert interface.mode == InterfaceMode.ACCESS
    assert interface.access_vlan == 10
    assert (interface.declaration_evidence.line_number,
            interface.declaration_evidence.text) == (
        5, "interface GigabitEthernet1/0/5")
    assert (interface.mode_evidence.line_number,
            interface.mode_evidence.text) == (7, " switchport mode access")
    assert (interface.access_vlan_evidence.line_number,
            interface.access_vlan_evidence.text) == (
        8, " switchport access vlan 10")
    assert (interface.dhcp_snooping_trust_evidence.line_number,
            interface.dhcp_snooping_trust_evidence.text) == (
        9, " ip dhcp snooping trust")

    assert (
        interface.dhcp_snooping_trust
        == ConfigState.ENABLED
    )

    assert config.dhcp_snooping_global_evidence is not None
    assert config.dhcp_snooping_global_evidence.line_number == 2
    assert (
        config.dhcp_snooping_global_evidence.text.strip()
        == "ip dhcp snooping"
    )

    assert config.dhcp_snooping_vlan_evidence[10].line_number == 3
    assert (
        config.dhcp_snooping_vlan_evidence[10].text.strip()
        == "ip dhcp snooping vlan 10"
    )


def test_parser_reads_port_security_states():
    raw_config = """interface GigabitEthernet1/0/1
 switchport port-security
!
interface GigabitEthernet1/0/2
 no switchport port-security
!
interface GigabitEthernet1/0/3
 description NO-PORT-SECURITY-COMMAND
!
"""

    config = CiscoIOSParser().parse(raw_config)

    assert config.interfaces[0].port_security == ConfigState.ENABLED
    assert config.interfaces[1].port_security == ConfigState.DISABLED
    assert config.interfaces[0].port_security_evidence.text == (
        " switchport port-security")
    assert config.interfaces[0].port_security_evidence.line_number == 2
    assert config.interfaces[1].port_security_evidence.text == (
        " no switchport port-security")
    assert config.interfaces[1].port_security_evidence.line_number == 5
    assert (
        config.interfaces[2].port_security
        == ConfigState.NOT_CONFIGURED
    )


def test_parser_maps_disabled_dhcp_trust_to_its_exact_source_line():
    config = CiscoIOSParser().parse("""interface GigabitEthernet1/0/1
 no ip dhcp snooping trust
""")

    interface = config.interfaces[0]
    assert interface.dhcp_snooping_trust == ConfigState.DISABLED
    assert interface.dhcp_snooping_trust_evidence.line_number == 2
    assert interface.dhcp_snooping_trust_evidence.text == (
        " no ip dhcp snooping trust")


def test_parser_reads_interface_portfast_and_bpdu_guard_states():
    raw_config = """interface GigabitEthernet1/0/1
 spanning-tree portfast
 spanning-tree bpduguard enable
!
interface GigabitEthernet1/0/2
 spanning-tree portfast edge
 spanning-tree bpduguard disable
!
interface GigabitEthernet1/0/3
 spanning-tree bpduguard enable
 no spanning-tree bpduguard
!
"""

    config = CiscoIOSParser().parse(raw_config)

    assert config.interfaces[0].portfast == ConfigState.ENABLED
    assert config.interfaces[0].bpdu_guard == ConfigState.ENABLED
    assert config.interfaces[1].portfast == ConfigState.ENABLED
    assert config.interfaces[1].bpdu_guard == ConfigState.DISABLED
    assert config.interfaces[0].portfast_evidence.line_number == 2
    assert config.interfaces[0].portfast_evidence.text == (
        " spanning-tree portfast")
    assert config.interfaces[1].portfast_evidence.line_number == 6
    assert config.interfaces[1].portfast_evidence.text == (
        " spanning-tree portfast edge")
    assert config.interfaces[0].bpdu_guard_evidence.line_number == 3
    assert config.interfaces[0].bpdu_guard_evidence.text == (
        " spanning-tree bpduguard enable")
    assert config.interfaces[1].bpdu_guard_evidence.line_number == 7
    assert config.interfaces[1].bpdu_guard_evidence.text == (
        " spanning-tree bpduguard disable")
    assert (
        config.interfaces[2].bpdu_guard
        == ConfigState.NOT_CONFIGURED
    )
    assert config.interfaces[2].bpdu_guard_evidence.line_number == 11
    assert config.interfaces[2].bpdu_guard_evidence.text == (
        " no spanning-tree bpduguard")


def test_parser_reads_global_portfast_and_bpdu_guard_defaults():
    raw_config = """spanning-tree portfast edge default
spanning-tree portfast bpduguard default
"""

    config = CiscoIOSParser().parse(raw_config)

    assert config.portfast_default == ConfigState.ENABLED
    assert config.bpdu_guard_default == ConfigState.ENABLED
    assert config.portfast_default_evidence is not None
    assert config.portfast_default_evidence.line_number == 1
    assert config.bpdu_guard_default_evidence is not None
    assert config.bpdu_guard_default_evidence.line_number == 2


def test_parser_reads_combined_bpdu_guard_default_without_inventing_portfast():
    config = CiscoIOSParser().parse(
        "spanning-tree portfast edge bpduguard default"
    )

    assert config.bpdu_guard_default == ConfigState.ENABLED
    assert config.portfast_default == ConfigState.NOT_CONFIGURED


def test_parser_reads_disabled_global_stp_defaults():
    raw_config = """no spanning-tree portfast edge default
no spanning-tree portfast edge bpduguard default
"""

    config = CiscoIOSParser().parse(raw_config)

    assert config.portfast_default == ConfigState.DISABLED
    assert config.bpdu_guard_default == ConfigState.DISABLED


def test_parser_reads_simple_dai_vlan_scope_with_evidence():
    config = CiscoIOSParser().parse(
        "hostname ACCESS-SW-01\nip arp inspection vlan 20"
    )

    assert config.dai_vlans == {20}
    assert config.dai_vlan_evidence[20].line_number == 2
    assert (
        config.dai_vlan_evidence[20].text
        == "ip arp inspection vlan 20"
    )


def test_parser_does_not_treat_unsupported_arp_inspection_as_vlan_scope():
    raw_config = """ip arp inspection vlan 10,20
ip arp inspection validate src-mac
"""

    config = CiscoIOSParser().parse(raw_config)

    assert config.dai_vlans == set()
    assert [line.line_number for line in config.unparsed_lines] == [1, 2]


def test_parser_reads_exact_ip_source_guard_states():
    raw_config = """interface GigabitEthernet1/0/1
 ip verify source
!
interface GigabitEthernet1/0/2
 no ip verify source
!
interface GigabitEthernet1/0/3
 description NO-IPSG-COMMAND
!
"""

    config = CiscoIOSParser().parse(raw_config)

    assert config.interfaces[0].ip_source_guard == ConfigState.ENABLED
    assert config.interfaces[1].ip_source_guard == ConfigState.DISABLED
    assert config.interfaces[0].ip_source_guard_evidence.line_number == 2
    assert config.interfaces[0].ip_source_guard_evidence.text == (
        " ip verify source")
    assert config.interfaces[1].ip_source_guard_evidence.line_number == 5
    assert config.interfaces[1].ip_source_guard_evidence.text == (
        " no ip verify source")
    assert (
        config.interfaces[2].ip_source_guard
        == ConfigState.NOT_CONFIGURED
    )


def test_parser_does_not_match_platform_ipsg_variants_as_basic_command():
    raw_config = """interface GigabitEthernet1/0/1
 ip verify source port-security
!
interface GigabitEthernet1/0/2
 ip verify source mac-check
!
"""

    config = CiscoIOSParser().parse(raw_config)

    assert all(
        interface.ip_source_guard == ConfigState.NOT_CONFIGURED
        for interface in config.interfaces
    )
    assert [line.line_number for line in config.unparsed_lines] == [2, 5]


def test_parser_reads_vty_range_and_transport_input():
    config = CiscoIOSParser().parse("""line vty 0 4
 transport input ssh telnet
!
""")

    assert len(config.vty_lines) == 1
    vty = config.vty_lines[0]
    assert (vty.start, vty.end) == (0, 4)
    assert vty.transport_input == {"ssh", "telnet"}
    assert vty.transport_input_evidence is not None
    assert vty.transport_input_evidence.line_number == 2


def test_parser_keeps_multiple_vty_blocks_independent():
    config = CiscoIOSParser().parse("""line vty 0 4
 transport input ssh
!
line vty 5 15
 transport input telnet
!
""")

    assert [
        (vty.start, vty.end, vty.transport_input)
        for vty in config.vty_lines
    ] == [
        (0, 4, {"ssh"}),
        (5, 15, {"telnet"}),
    ]


def test_parser_normalizes_supported_vty_transport_forms():
    cases = {
        "ssh": (ConfigState.ENABLED, {"ssh"}),
        "telnet": (ConfigState.ENABLED, {"telnet"}),
        "ssh telnet": (ConfigState.ENABLED, {"ssh", "telnet"}),
        "telnet ssh": (ConfigState.ENABLED, {"ssh", "telnet"}),
        "all": (ConfigState.ENABLED, {"ssh", "telnet"}),
        "none": (ConfigState.DISABLED, set()),
    }

    for transport, (expected_state, expected_protocols) in cases.items():
        config = CiscoIOSParser().parse(
            f"line vty 0 4\n transport input {transport}\n!\n"
        )
        vty = config.vty_lines[0]

        assert vty.transport_input_state == expected_state
        assert vty.transport_input == expected_protocols
        assert vty.transport_input_evidence is not None


def test_parser_distinguishes_absent_vty_transport_from_none():
    absent = CiscoIOSParser().parse("line vty 0 4").vty_lines[0]
    explicit_none = CiscoIOSParser().parse(
        "line vty 0 4\n transport input none"
    ).vty_lines[0]

    assert absent.transport_input == set()
    assert absent.transport_input_state == ConfigState.NOT_CONFIGURED
    assert absent.transport_input_evidence is None
    assert explicit_none.transport_input == set()
    assert explicit_none.transport_input_state == ConfigState.DISABLED
    assert explicit_none.transport_input_evidence is not None


def test_parser_marks_partially_supported_vty_transport_unknown():
    config = CiscoIOSParser().parse("""line vty 0 4
 transport input ssh lat
!
""")

    vty = config.vty_lines[0]
    assert vty.transport_input == set()
    assert vty.transport_input_evidence is None
    assert vty.transport_input_state == ConfigState.UNKNOWN
    assert [line.line_number for line in config.unparsed_lines] == [2]


def test_parser_marks_fully_unsupported_vty_transport_unknown():
    config = CiscoIOSParser().parse("""line vty 0 4
 transport input unsupported
!
""")

    vty = config.vty_lines[0]
    assert vty.transport_input == set()
    assert vty.transport_input_evidence is None
    assert vty.transport_input_state == ConfigState.UNKNOWN
    assert [line.line_number for line in config.unparsed_lines] == [2]


def test_parser_marks_repeated_vty_transport_ambiguous():
    config = CiscoIOSParser().parse("""line vty 0 4
 transport input ssh
 transport input telnet
!
""")

    vty = config.vty_lines[0]
    assert vty.transport_input == set()
    assert vty.transport_input_evidence is None
    assert vty.transport_input_state == ConfigState.UNKNOWN
    assert [line.line_number for line in config.unparsed_lines] == [3]


def test_parser_does_not_treat_console_line_as_vty():
    config = CiscoIOSParser().parse("""line console 0
 transport input telnet
!
""")

    assert config.vty_lines == []
    assert [line.line_number for line in config.unparsed_lines] == [1, 2]


def test_parser_maps_exact_http_and_https_server_commands_independently():
    config = CiscoIOSParser().parse("""ip http server
no ip http secure-server
""")

    assert config.http_server == ConfigState.ENABLED
    assert config.http_server_evidence.line_number == 1
    assert config.http_server_evidence.text == "ip http server"
    assert config.https_server == ConfigState.DISABLED
    assert config.https_server_evidence.line_number == 2


def test_parser_maps_exact_disabled_http_and_enabled_https_commands():
    config = CiscoIOSParser().parse("""no ip http server
ip http secure-server
""")

    assert config.http_server == ConfigState.DISABLED
    assert config.http_server_evidence.line_number == 1
    assert config.https_server == ConfigState.ENABLED
    assert config.https_server_evidence.line_number == 2


def test_parser_does_not_treat_unrelated_ip_http_command_as_server_state():
    config = CiscoIOSParser().parse("ip http authentication local\n")

    assert config.http_server == ConfigState.NOT_CONFIGURED
    assert config.https_server == ConfigState.NOT_CONFIGURED
    assert [line.line_number for line in config.unparsed_lines] == [1]
