from src.domain.models import Confidence, Severity
from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.dhcp.dhcp_001 import DHCP001GloballyInactiveRule


def evaluate(raw_config: str):
    config = CiscoIOSParser().parse(raw_config)
    return DHCP001GloballyInactiveRule().evaluate(config)


def test_dhcp_001_finds_disabled_global_with_vlan_scope():
    findings = evaluate("""hostname ACCESS-SW-01
no ip dhcp snooping
ip dhcp snooping vlan 10
""")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "DHCP-001"
    assert finding.title == "DHCP Snooping globally inactive"
    assert finding.category == "DHCP_SPOOFING"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.HIGH


def test_dhcp_001_finds_not_configured_global_with_vlan_scope():
    findings = evaluate("""hostname ACCESS-SW-01
ip dhcp snooping vlan 10
""")

    assert len(findings) == 1
    assert findings[0].rule_id == "DHCP-001"


def test_dhcp_001_finds_inactive_global_with_interface_trust():
    findings = evaluate("""hostname ACCESS-SW-01
interface GigabitEthernet1/0/48
 ip dhcp snooping trust
!
""")

    assert len(findings) == 1
    assert findings[0].rule_id == "DHCP-001"


def test_dhcp_001_does_not_fire_when_global_is_enabled():
    findings = evaluate("""hostname ACCESS-SW-01
ip dhcp snooping
ip dhcp snooping vlan 10
""")

    assert findings == []


def test_dhcp_001_does_not_fire_without_dhcp_snooping_context():
    findings = evaluate("""hostname ACCESS-SW-01
interface GigabitEthernet1/0/5
 description USER-PC
!
""")

    assert findings == []


def test_dhcp_001_contains_global_and_vlan_evidence():
    findings = evaluate("""hostname ACCESS-SW-01
no ip dhcp snooping
ip dhcp snooping vlan 10
ip dhcp snooping vlan 20
""")

    evidence = [
        (line.line_number, line.text.strip())
        for line in findings[0].evidence
    ]

    assert evidence == [
        (2, "no ip dhcp snooping"),
        (3, "ip dhcp snooping vlan 10"),
        (4, "ip dhcp snooping vlan 20"),
    ]


def test_dhcp_001_contains_interface_trust_evidence():
    findings = evaluate("""hostname ACCESS-SW-01
interface GigabitEthernet1/0/48
 description UPLINK-TO-DHCP-SERVER
 ip dhcp snooping trust
!
""")

    evidence = [
        (line.line_number, line.text.strip())
        for line in findings[0].evidence
    ]

    assert evidence == [
        (2, "interface GigabitEthernet1/0/48"),
        (4, "ip dhcp snooping trust"),
    ]
