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

