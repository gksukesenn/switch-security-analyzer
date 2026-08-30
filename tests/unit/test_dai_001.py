from src.domain.models import Confidence, Severity
from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.dai.dai_001 import DAI001DhcpVlanWithoutDAIRule


def evaluate(raw_config: str):
    config = CiscoIOSParser().parse(raw_config)
    return DAI001DhcpVlanWithoutDAIRule().evaluate(config)


def test_dai_001_finds_dhcp_protected_access_vlan_without_dai():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
""")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "DAI-001"
    assert finding.title == (
        "DHCP Snooping protected VLAN lacks Dynamic ARP Inspection"
    )
    assert finding.category == "ARP_SPOOFING"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.MEDIUM
    assert finding.affected_interfaces == ["GigabitEthernet1/0/5"]


def test_dai_001_does_not_fire_when_dai_covers_vlan():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
ip arp inspection vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
""")

    assert findings == []


def test_dai_001_does_not_fire_when_dhcp_snooping_is_inactive():
    disabled_findings = evaluate("""no ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
""")
    not_configured_findings = evaluate("""ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
""")

    assert disabled_findings == []
    assert not_configured_findings == []


def test_dai_001_does_not_fire_without_explicit_access_vlan_context():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
!
""")

    assert findings == []


def test_dai_001_does_not_use_trunk_as_endpoint_context():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/48
 switchport mode trunk
 switchport access vlan 20
!
""")

    assert findings == []


def test_dai_001_orders_findings_by_vlan():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 30
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/30
 switchport mode access
 switchport access vlan 30
!
interface GigabitEthernet1/0/20
 switchport mode access
 switchport access vlan 20
!
""")

    assert [finding.safe_config_example for finding in findings] == [
        "ip arp inspection vlan 20",
        "ip arp inspection vlan 30",
    ]


def test_dai_001_aggregates_and_naturally_sorts_interfaces():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
!
interface GigabitEthernet1/0/10
 switchport mode access
 switchport access vlan 20
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 20
!
""")

    assert len(findings) == 1
    assert findings[0].affected_interfaces == [
        "GigabitEthernet1/0/1",
        "GigabitEthernet1/0/2",
        "GigabitEthernet1/0/10",
    ]


def test_dai_001_contains_dhcp_and_access_context_evidence():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
""")

    evidence = [
        (line.line_number, line.text.strip())
        for line in findings[0].evidence
    ]

    assert evidence == [
        (1, "ip dhcp snooping"),
        (2, "ip dhcp snooping vlan 20"),
        (3, "interface GigabitEthernet1/0/5"),
        (4, "switchport mode access"),
        (5, "switchport access vlan 20"),
    ]


def test_dai_001_safe_example_uses_actual_vlan():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 30
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 30
!
""")

    assert findings[0].safe_config_example == "ip arp inspection vlan 30"
