from src.domain.models import (
    Confidence,
    ConfigState,
    InterfaceConfig,
    InterfaceMode,
    ParsedConfig,
    Severity,
)
from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.ip_source_guard.ipsg_001 import (
    IPSG001DhcpEndpointWithoutIPSGRule,
)


def evaluate(raw_config: str):
    config = CiscoIOSParser().parse(raw_config)
    return IPSG001DhcpEndpointWithoutIPSGRule().evaluate(config)


def test_ipsg_001_finds_unprotected_dhcp_endpoint():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
""")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "IPSG-001"
    assert finding.title == (
        "DHCP-protected endpoint interface lacks IP Source Guard"
    )
    assert finding.category == "IP_SPOOFING"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.MEDIUM
    assert finding.affected_interfaces == ["GigabitEthernet1/0/5"]


def test_ipsg_001_finds_explicitly_disabled_ipsg():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
 no ip verify source
!
""")

    assert len(findings) == 1
    assert findings[0].affected_interfaces == ["GigabitEthernet1/0/5"]


def test_ipsg_001_does_not_fire_when_ipsg_is_enabled():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
 ip verify source
!
""")

    assert findings == []


def test_ipsg_001_does_not_fire_when_dhcp_snooping_is_inactive():
    findings = evaluate("""no ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
""")

    assert findings == []


def test_ipsg_001_does_not_fire_outside_dhcp_scope():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 30
!
""")

    assert findings == []


def test_ipsg_001_excludes_trunk_interface():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/48
 switchport mode trunk
 switchport access vlan 20
!
""")

    assert findings == []


def test_ipsg_001_requires_explicit_access_vlan():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
!
""")

    assert findings == []


def test_ipsg_001_excludes_dhcp_trusted_access_port():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
 ip dhcp snooping trust
!
""")

    assert findings == []


def test_ipsg_001_does_not_treat_unknown_or_unsupported_as_missing():
    config = ParsedConfig(
        vendor="cisco_ios",
        dhcp_snooping_global=ConfigState.ENABLED,
        dhcp_snooping_vlans={20},
        interfaces=[
            InterfaceConfig(
                name="GigabitEthernet1/0/1",
                mode=InterfaceMode.ACCESS,
                access_vlan=20,
                ip_source_guard=ConfigState.UNKNOWN,
            ),
            InterfaceConfig(
                name="GigabitEthernet1/0/2",
                mode=InterfaceMode.ACCESS,
                access_vlan=20,
                ip_source_guard=ConfigState.UNSUPPORTED,
            ),
        ],
    )

    evaluation = IPSG001DhcpEndpointWithoutIPSGRule().evaluate_detailed(
        config
    )

    assert evaluation.findings == []
    assert evaluation.assessed_units == 0


def test_ipsg_001_supported_states_are_assessed_without_changing_findings():
    config = ParsedConfig(
        vendor="cisco_ios",
        dhcp_snooping_global=ConfigState.ENABLED,
        dhcp_snooping_vlans={20},
        interfaces=[
            InterfaceConfig(
                name="GigabitEthernet1/0/1",
                mode=InterfaceMode.ACCESS,
                access_vlan=20,
                ip_source_guard=ConfigState.ENABLED,
            ),
            InterfaceConfig(
                name="GigabitEthernet1/0/2",
                mode=InterfaceMode.ACCESS,
                access_vlan=20,
                ip_source_guard=ConfigState.NOT_CONFIGURED,
            ),
            InterfaceConfig(
                name="GigabitEthernet1/0/3",
                mode=InterfaceMode.ACCESS,
                access_vlan=20,
                ip_source_guard=ConfigState.DISABLED,
            ),
        ],
    )

    evaluation = IPSG001DhcpEndpointWithoutIPSGRule().evaluate_detailed(
        config
    )

    assert evaluation.assessed_units == 3
    assert len(evaluation.findings) == 1
    assert evaluation.findings[0].affected_interfaces == [
        "GigabitEthernet1/0/2",
        "GigabitEthernet1/0/3",
    ]


def test_ipsg_001_aggregates_and_naturally_sorts_by_vlan():
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
    assert findings[0].safe_config_example == (
        "interface GigabitEthernet1/0/1\n"
        " ip verify source\n"
        "!\n"
        "interface GigabitEthernet1/0/2\n"
        " ip verify source\n"
        "!\n"
        "interface GigabitEthernet1/0/10\n"
        " ip verify source"
    )


def test_ipsg_001_orders_findings_by_vlan():
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

    assert [finding.affected_interfaces for finding in findings] == [
        ["GigabitEthernet1/0/20"],
        ["GigabitEthernet1/0/30"],
    ]


def test_ipsg_001_contains_dhcp_and_endpoint_evidence():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
 no ip verify source
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
        (6, "no ip verify source"),
    ]


def test_ipsg_001_safe_example_uses_actual_interface():
    findings = evaluate("""ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/12
 switchport mode access
 switchport access vlan 20
!
""")

    assert findings[0].safe_config_example == (
        "interface GigabitEthernet1/0/12\n"
        " ip verify source"
    )
