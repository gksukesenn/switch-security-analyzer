from src.domain.models import Confidence, Severity
from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.dhcp.dhcp_002 import DHCP002AccessVlanNotCoveredRule


def evaluate(raw_config: str):
    config = CiscoIOSParser().parse(raw_config)
    return DHCP002AccessVlanNotCoveredRule().evaluate(config)


def test_dhcp_002_finds_uncovered_access_vlan():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 10
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
""")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "DHCP-002"
    assert finding.title == "Access VLAN not covered by DHCP Snooping"
    assert finding.category == "DHCP_SPOOFING"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.MEDIUM
    assert finding.affected_interfaces == ["GigabitEthernet1/0/5"]


def test_dhcp_002_finds_uncovered_vlan_when_scope_is_empty():
    findings = evaluate("""ip dhcp snooping
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
""")

    assert len(findings) == 1
    assert findings[0].rule_id == "DHCP-002"


def test_dhcp_002_aggregates_interfaces_by_vlan():
    findings = evaluate("""ip dhcp snooping
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 20
!
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
!
""")

    assert len(findings) == 1
    assert findings[0].affected_interfaces == [
        "GigabitEthernet1/0/1",
        "GigabitEthernet1/0/2",
    ]


def test_dhcp_002_naturally_sorts_affected_interfaces():
    findings = evaluate("""ip dhcp snooping
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

    assert findings[0].affected_interfaces == [
        "GigabitEthernet1/0/1",
        "GigabitEthernet1/0/2",
        "GigabitEthernet1/0/10",
    ]


def test_dhcp_002_orders_findings_by_uncovered_vlan():
    findings = evaluate("""ip dhcp snooping
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
        "ip dhcp snooping\nip dhcp snooping vlan 20",
        "ip dhcp snooping\nip dhcp snooping vlan 30",
    ]


def test_dhcp_002_does_not_fire_for_covered_access_vlan():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
""")

    assert findings == []


def test_dhcp_002_does_not_fire_for_trunk_interface():
    findings = evaluate("""ip dhcp snooping
interface GigabitEthernet1/0/48
 switchport mode trunk
!
""")

    assert findings == []


def test_dhcp_002_does_not_fire_for_trusted_access_interface():
    findings = evaluate("""ip dhcp snooping
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
 ip dhcp snooping trust
!
""")

    assert findings == []


def test_dhcp_002_does_not_fire_when_global_is_inactive():
    findings = evaluate("""no ip dhcp snooping
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
""")

    assert findings == []


def test_dhcp_002_does_not_infer_default_access_vlan():
    findings = evaluate("""ip dhcp snooping
interface GigabitEthernet1/0/5
 switchport mode access
!
""")

    assert findings == []


def test_dhcp_002_contains_deterministic_evidence():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 10
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
        (2, "ip dhcp snooping vlan 10"),
        (3, "interface GigabitEthernet1/0/5"),
        (4, "switchport mode access"),
        (5, "switchport access vlan 20"),
    ]


def test_dhcp_002_safe_example_uses_uncovered_vlan():
    findings = evaluate("""ip dhcp snooping
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 30
!
""")

    assert findings[0].safe_config_example == (
        "ip dhcp snooping\n"
        "ip dhcp snooping vlan 30"
    )
