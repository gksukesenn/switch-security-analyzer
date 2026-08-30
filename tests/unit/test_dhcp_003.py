from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.dhcp.dhcp_003 import DHCP003TrustedAccessPortRule


def test_dhcp_003_finds_trusted_access_port():
    raw_config = """hostname ACCESS-SW-01
ip dhcp snooping
ip dhcp snooping vlan 30
!
interface GigabitEthernet1/0/22
 description USER-PC
 switchport mode access
 switchport access vlan 30
 ip dhcp snooping trust
!
"""

    parser = CiscoIOSParser()
    config = parser.parse(raw_config)

    rule = DHCP003TrustedAccessPortRule()
    findings = rule.evaluate(config)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "DHCP-003"
    assert finding.affected_interfaces == [
        "GigabitEthernet1/0/22"
    ]
    assert finding.safe_config_example == (
        "interface GigabitEthernet1/0/22\n"
        " switchport mode access\n"
        " switchport access vlan 30"
    )
    assert "ip dhcp snooping trust" not in finding.safe_config_example


def test_dhcp_003_does_not_fire_when_vlan_is_not_protected():
    raw_config = """hostname ACCESS-SW-01
ip dhcp snooping
ip dhcp snooping vlan 10
!
interface GigabitEthernet1/0/5
 description USER-PC
 switchport mode access
 switchport access vlan 20
 ip dhcp snooping trust
!
"""

    parser = CiscoIOSParser()
    config = parser.parse(raw_config)

    rule = DHCP003TrustedAccessPortRule()
    findings = rule.evaluate(config)

    assert findings == []


def test_dhcp_003_does_not_fire_on_trunk_port():
    raw_config = """hostname ACCESS-SW-01
ip dhcp snooping
ip dhcp snooping vlan 10
!
interface GigabitEthernet1/0/48
 description UPLINK-TO-CORE
 switchport mode trunk
 ip dhcp snooping trust
!
"""

    parser = CiscoIOSParser()
    config = parser.parse(raw_config)

    rule = DHCP003TrustedAccessPortRule()
    findings = rule.evaluate(config)

    assert findings == []


def test_dhcp_003_does_not_fire_when_access_port_is_untrusted():
    raw_config = """hostname ACCESS-SW-01
ip dhcp snooping
ip dhcp snooping vlan 10
!
interface GigabitEthernet1/0/5
 description USER-PC
 switchport mode access
 switchport access vlan 10
!
"""

    parser = CiscoIOSParser()
    config = parser.parse(raw_config)

    rule = DHCP003TrustedAccessPortRule()
    findings = rule.evaluate(config)

    assert findings == []


def test_dhcp_003_does_not_fire_when_global_snooping_is_disabled():
    raw_config = """hostname ACCESS-SW-01
no ip dhcp snooping
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

    rule = DHCP003TrustedAccessPortRule()
    findings = rule.evaluate(config)

    assert findings == []

def test_dhcp_003_contains_interface_evidence():
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

    rule = DHCP003TrustedAccessPortRule()
    findings = rule.evaluate(config)

    assert len(findings) == 1

    finding = findings[0]

    evidence = [
        (line.line_number, line.text.strip())
        for line in finding.evidence
    ]

    assert evidence == [
        (2, "ip dhcp snooping"),
        (3, "ip dhcp snooping vlan 10"),
        (5, "interface GigabitEthernet1/0/5"),
        (7, "switchport mode access"),
        (8, "switchport access vlan 10"),
        (9, "ip dhcp snooping trust"),
    ]
