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
    assert (
        config.interfaces[2].port_security
        == ConfigState.NOT_CONFIGURED
    )


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
    assert (
        config.interfaces[2].bpdu_guard
        == ConfigState.NOT_CONFIGURED
    )


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
