from src.domain.models import (
    Confidence,
    ConfigState,
    InterfaceConfig,
    InterfaceMode,
    ParsedConfig,
    Severity,
)
from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.port_security.portsec_001 import (
    PORTSEC001InconsistentCoverageRule,
)


def evaluate(raw_config: str):
    config = CiscoIOSParser().parse(raw_config)
    return PORTSEC001InconsistentCoverageRule().evaluate(config)


def test_portsec_001_finds_unprotected_peer():
    findings = evaluate("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
 switchport port-security
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 20
!
""")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "PORTSEC-001"
    assert finding.title == (
        "Inconsistent Port Security coverage on peer access ports"
    )
    assert finding.category == "MAC_SPOOFING"
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.MEDIUM
    assert finding.affected_interfaces == ["GigabitEthernet1/0/2"]


def test_portsec_001_finds_explicitly_disabled_peer():
    findings = evaluate("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
 switchport port-security
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 20
 no switchport port-security
!
""")

    assert findings[0].affected_interfaces == ["GigabitEthernet1/0/2"]


def test_portsec_001_does_not_fire_without_policy_context():
    findings = evaluate("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 20
!
""")

    assert findings == []


def test_portsec_001_does_not_fire_when_all_peers_are_protected():
    findings = evaluate("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
 switchport port-security
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 20
 switchport port-security
!
""")

    assert findings == []


def test_portsec_001_does_not_carry_intent_between_vlans():
    findings = evaluate("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
 switchport port-security
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 30
!
""")

    assert findings == []


def test_portsec_001_excludes_trunk_interfaces():
    findings = evaluate("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
 switchport port-security
!
interface GigabitEthernet1/0/48
 switchport mode trunk
 switchport access vlan 20
!
""")

    assert findings == []


def test_portsec_001_excludes_access_interface_without_explicit_vlan():
    findings = evaluate("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
 switchport port-security
!
interface GigabitEthernet1/0/2
 switchport mode access
!
""")

    assert findings == []


def test_portsec_001_does_not_treat_unknown_or_unsupported_as_missing():
    config = ParsedConfig(
        vendor="cisco_ios",
        interfaces=[
            InterfaceConfig(
                name="GigabitEthernet1/0/1",
                mode=InterfaceMode.ACCESS,
                access_vlan=20,
                port_security=ConfigState.ENABLED,
            ),
            InterfaceConfig(
                name="GigabitEthernet1/0/2",
                mode=InterfaceMode.ACCESS,
                access_vlan=20,
                port_security=ConfigState.UNKNOWN,
            ),
            InterfaceConfig(
                name="GigabitEthernet1/0/3",
                mode=InterfaceMode.ACCESS,
                access_vlan=20,
                port_security=ConfigState.UNSUPPORTED,
            ),
        ],
    )

    findings = PORTSEC001InconsistentCoverageRule().evaluate(config)

    assert findings == []


def test_portsec_001_aggregates_missing_and_disabled_peers():
    findings = evaluate("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
 switchport port-security
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 20
!
interface GigabitEthernet1/0/3
 switchport mode access
 switchport access vlan 20
 no switchport port-security
!
""")

    assert len(findings) == 1
    assert findings[0].affected_interfaces == [
        "GigabitEthernet1/0/2",
        "GigabitEthernet1/0/3",
    ]


def test_portsec_001_orders_findings_by_vlan():
    findings = evaluate("""interface GigabitEthernet1/0/30
 switchport mode access
 switchport access vlan 30
 switchport port-security
!
interface GigabitEthernet1/0/31
 switchport mode access
 switchport access vlan 30
!
interface GigabitEthernet1/0/20
 switchport mode access
 switchport access vlan 20
 switchport port-security
!
interface GigabitEthernet1/0/21
 switchport mode access
 switchport access vlan 20
!
""")

    assert [finding.safe_config_example for finding in findings] == [
        "interface GigabitEthernet1/0/21\n"
        " switchport mode access\n"
        " switchport access vlan 20\n"
        " switchport port-security",
        "interface GigabitEthernet1/0/31\n"
        " switchport mode access\n"
        " switchport access vlan 30\n"
        " switchport port-security",
    ]


def test_portsec_001_naturally_sorts_affected_interfaces():
    findings = evaluate("""interface GigabitEthernet1/0/24
 switchport mode access
 switchport access vlan 20
 switchport port-security
!
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


def test_portsec_001_contains_peer_and_affected_evidence():
    findings = evaluate("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
 switchport port-security
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 20
 no switchport port-security
!
""")

    evidence = [
        (line.line_number, line.text.strip())
        for line in findings[0].evidence
    ]

    assert evidence == [
        (1, "interface GigabitEthernet1/0/1"),
        (2, "switchport mode access"),
        (3, "switchport access vlan 20"),
        (4, "switchport port-security"),
        (6, "interface GigabitEthernet1/0/2"),
        (7, "switchport mode access"),
        (8, "switchport access vlan 20"),
        (9, "no switchport port-security"),
    ]


def test_portsec_001_safe_example_uses_actual_interface_and_vlan():
    findings = evaluate("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 30
 switchport port-security
!
interface GigabitEthernet1/0/12
 switchport mode access
 switchport access vlan 30
!
""")

    assert findings[0].safe_config_example == (
        "interface GigabitEthernet1/0/12\n"
        " switchport mode access\n"
        " switchport access vlan 30\n"
        " switchport port-security"
    )
