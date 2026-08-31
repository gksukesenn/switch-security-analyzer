import pytest

from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.dai.dai_001 import DAI001DhcpVlanWithoutDAIRule
from src.rules.dhcp.dhcp_001 import DHCP001GloballyInactiveRule
from src.rules.dhcp.dhcp_002 import DHCP002AccessVlanNotCoveredRule
from src.rules.dhcp.dhcp_003 import DHCP003TrustedAccessPortRule
from src.rules.ip_source_guard.ipsg_001 import (
    IPSG001DhcpEndpointWithoutIPSGRule,
)
from src.rules.management.mgmt_001 import MGMT001VtyTelnetEnabledRule
from src.rules.management.mgmt_002 import MGMT002InsecureHTTPServerRule
from src.rules.port_security.portsec_001 import (
    PORTSEC001InconsistentCoverageRule,
)
from src.rules.stp.stp_001 import STP001PortFastWithoutBPDUGuardRule


DHCP_RULES = (
    DHCP001GloballyInactiveRule(),
    DHCP002AccessVlanNotCoveredRule(),
    DHCP003TrustedAccessPortRule(),
    DAI001DhcpVlanWithoutDAIRule(),
    IPSG001DhcpEndpointWithoutIPSGRule(),
)


def test_absent_dhcp_has_no_findings_and_no_assessed_units():
    config = CiscoIOSParser().parse("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
""")

    for rule in DHCP_RULES:
        evaluation = rule.evaluate_detailed(config)
        assert evaluation.findings == []
        assert evaluation.assessed_units == 0


def test_fully_modeled_dhcp_dai_ipsg_is_safe_and_assessed():
    config = CiscoIOSParser().parse("""ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 ip verify source
""")

    for rule in DHCP_RULES:
        evaluation = rule.evaluate_detailed(config)
        assert evaluation.findings == []
        assert evaluation.assessed_units > 0


def test_explicit_enabled_global_dhcp_state_is_assessed():
    config = CiscoIOSParser().parse("ip dhcp snooping\n")

    evaluation = DHCP001GloballyInactiveRule().evaluate_detailed(config)

    assert evaluation.findings == []
    assert evaluation.assessed_units == 1


def test_port_security_all_absent_has_no_intent_or_assessed_units():
    config = CiscoIOSParser().parse("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 10
""")

    evaluation = PORTSEC001InconsistentCoverageRule().evaluate_detailed(config)

    assert evaluation.findings == []
    assert evaluation.assessed_units == 0


def test_port_security_all_enabled_is_safe_and_assessed():
    config = CiscoIOSParser().parse("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 switchport port-security
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 10
 switchport port-security
""")

    evaluation = PORTSEC001InconsistentCoverageRule().evaluate_detailed(config)

    assert evaluation.findings == []
    assert evaluation.assessed_units == 2


def test_port_security_mixed_has_finding_and_assessed_units():
    config = CiscoIOSParser().parse("""interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 switchport port-security
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 10
""")

    evaluation = PORTSEC001InconsistentCoverageRule().evaluate_detailed(config)

    assert [finding.rule_id for finding in evaluation.findings] == [
        "PORTSEC-001"
    ]
    assert evaluation.assessed_units == 2


def test_stp_without_portfast_context_is_not_assessed():
    config = CiscoIOSParser().parse("""interface GigabitEthernet1/0/1
 switchport mode access
""")

    evaluation = STP001PortFastWithoutBPDUGuardRule().evaluate_detailed(config)

    assert evaluation.findings == []
    assert evaluation.assessed_units == 0


def test_guarded_portfast_is_safe_and_assessed():
    config = CiscoIOSParser().parse("""interface GigabitEthernet1/0/1
 switchport mode access
 spanning-tree portfast
 spanning-tree bpduguard enable
""")

    evaluation = STP001PortFastWithoutBPDUGuardRule().evaluate_detailed(config)

    assert evaluation.findings == []
    assert evaluation.assessed_units == 1


@pytest.mark.parametrize(
    ("transport", "expected_units"),
    [
        (" transport input ssh\n", 1),
        ("", 0),
        (" transport input ssh lat\n", 0),
    ],
)
def test_vty_assessment_requires_explicit_supported_transport(
    transport,
    expected_units,
):
    config = CiscoIOSParser().parse(f"line vty 0 4\n{transport}")

    evaluation = MGMT001VtyTelnetEnabledRule().evaluate_detailed(config)

    assert evaluation.findings == []
    assert evaluation.assessed_units == expected_units


@pytest.mark.parametrize(
    ("command", "expected_units", "expected_findings"),
    [
        ("ip http server", 1, 1),
        ("no ip http server", 1, 0),
        ("ip http authentication local", 0, 0),
        ("hostname SW1", 0, 0),
    ],
)
def test_http_assessment_requires_explicit_supported_server_state(
    command,
    expected_units,
    expected_findings,
):
    config = CiscoIOSParser().parse(command)

    evaluation = MGMT002InsecureHTTPServerRule().evaluate_detailed(config)

    assert len(evaluation.findings) == expected_findings
    assert evaluation.assessed_units == expected_units
