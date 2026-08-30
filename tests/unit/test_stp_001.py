from src.domain.models import (
    Confidence,
    ConfigState,
    InterfaceConfig,
    InterfaceMode,
    ParsedConfig,
    Severity,
)
from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.stp.stp_001 import STP001PortFastWithoutBPDUGuardRule


def evaluate(raw_config: str):
    config = CiscoIOSParser().parse(raw_config)
    return STP001PortFastWithoutBPDUGuardRule().evaluate(config)


def test_stp_001_finds_explicit_portfast_without_bpdu_guard():
    findings = evaluate("""interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
!
""")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "STP-001"
    assert finding.title == "PortFast edge port lacks effective BPDU Guard"
    assert finding.category == "STP"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.HIGH
    assert finding.affected_interfaces == ["GigabitEthernet1/0/5"]


def test_stp_001_finds_inherited_portfast_without_bpdu_guard():
    findings = evaluate("""spanning-tree portfast default
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
""")

    assert len(findings) == 1
    assert findings[0].rule_id == "STP-001"


def test_stp_001_does_not_fire_with_interface_bpdu_guard():
    findings = evaluate("""interface GigabitEthernet1/0/5
 switchport mode access
 spanning-tree portfast
 spanning-tree bpduguard enable
!
""")

    assert findings == []


def test_stp_001_honors_inherited_bpdu_guard():
    findings = evaluate("""spanning-tree portfast bpduguard default
interface GigabitEthernet1/0/5
 switchport mode access
 spanning-tree portfast
!
""")

    assert findings == []


def test_stp_001_explicit_disable_overrides_bpdu_guard_default():
    findings = evaluate("""spanning-tree portfast bpduguard default
interface GigabitEthernet1/0/5
 switchport mode access
 spanning-tree portfast
 spanning-tree bpduguard disable
!
""")

    assert len(findings) == 1
    assert findings[0].affected_interfaces == ["GigabitEthernet1/0/5"]


def test_stp_001_does_not_fire_without_effective_portfast():
    findings = evaluate("""interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
""")

    assert findings == []


def test_stp_001_explicit_portfast_disable_overrides_global_default():
    config = ParsedConfig(
        vendor="cisco_ios",
        portfast_default=ConfigState.ENABLED,
        interfaces=[
            InterfaceConfig(
                name="GigabitEthernet1/0/5",
                mode=InterfaceMode.ACCESS,
                portfast=ConfigState.DISABLED,
            )
        ],
    )

    findings = STP001PortFastWithoutBPDUGuardRule().evaluate(config)

    assert findings == []


def test_stp_001_excludes_trunk_interface():
    findings = evaluate("""interface GigabitEthernet1/0/48
 switchport mode trunk
 spanning-tree portfast
!
""")

    assert findings == []


def test_stp_001_does_not_treat_unknown_states_as_missing():
    config = ParsedConfig(
        vendor="cisco_ios",
        portfast_default=ConfigState.UNKNOWN,
        interfaces=[
            InterfaceConfig(
                name="GigabitEthernet1/0/1",
                mode=InterfaceMode.ACCESS,
                portfast=ConfigState.UNKNOWN,
            ),
            InterfaceConfig(
                name="GigabitEthernet1/0/2",
                mode=InterfaceMode.ACCESS,
                portfast=ConfigState.ENABLED,
                bpdu_guard=ConfigState.UNSUPPORTED,
            ),
        ],
    )

    findings = STP001PortFastWithoutBPDUGuardRule().evaluate(config)

    assert findings == []


def test_stp_001_aggregates_and_naturally_sorts_interfaces():
    findings = evaluate("""spanning-tree portfast default
interface GigabitEthernet1/0/1
 switchport mode access
!
interface GigabitEthernet1/0/10
 switchport mode access
!
interface GigabitEthernet1/0/2
 switchport mode access
!
""")

    assert len(findings) == 1
    assert findings[0].affected_interfaces == [
        "GigabitEthernet1/0/1",
        "GigabitEthernet1/0/2",
        "GigabitEthernet1/0/10",
    ]


def test_stp_001_contains_explicit_interface_evidence():
    findings = evaluate("""interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast edge
 spanning-tree bpduguard disable
!
""")

    evidence = [
        (line.line_number, line.text.strip())
        for line in findings[0].evidence
    ]

    assert evidence == [
        (1, "interface GigabitEthernet1/0/5"),
        (2, "switchport mode access"),
        (3, "switchport access vlan 20"),
        (4, "spanning-tree portfast edge"),
        (5, "spanning-tree bpduguard disable"),
    ]


def test_stp_001_contains_global_inheritance_and_override_evidence():
    findings = evaluate("""spanning-tree portfast edge default
spanning-tree portfast edge bpduguard default
interface GigabitEthernet1/0/5
 switchport mode access
 spanning-tree bpduguard disable
!
""")

    evidence = [
        (line.line_number, line.text.strip())
        for line in findings[0].evidence
    ]

    assert evidence == [
        (1, "spanning-tree portfast edge default"),
        (2, "spanning-tree portfast edge bpduguard default"),
        (3, "interface GigabitEthernet1/0/5"),
        (4, "switchport mode access"),
        (5, "spanning-tree bpduguard disable"),
    ]


def test_stp_001_safe_example_uses_actual_interface():
    findings = evaluate("""interface GigabitEthernet1/0/12
 switchport mode access
 spanning-tree portfast
!
""")

    assert findings[0].safe_config_example == (
        "interface GigabitEthernet1/0/12\n"
        " spanning-tree bpduguard enable"
    )
