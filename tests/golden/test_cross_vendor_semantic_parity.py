import pytest

from src.parsers.aruba.aos_cx import ArubaAOSCXParser
from src.parsers.cisco.ios import CiscoIOSParser
from src.renderers.safe_config import (
    ArubaSafeConfigRenderer,
    CiscoSafeConfigRenderer,
)
from src.rules.dai.dai_001 import DAI001DhcpVlanWithoutDAIRule
from src.rules.dhcp.dhcp_001 import DHCP001GloballyInactiveRule
from src.rules.dhcp.dhcp_002 import DHCP002AccessVlanNotCoveredRule
from src.rules.dhcp.dhcp_003 import DHCP003TrustedAccessPortRule
from src.rules.stp.stp_001 import STP001PortFastWithoutBPDUGuardRule


CASES = [
    (
        DHCP001GloballyInactiveRule,
        "no ip dhcp snooping\nip dhcp snooping vlan 20\n",
        "no dhcpv4-snooping\nvlan 20\n dhcpv4-snooping\n!\n",
    ),
    (
        DHCP002AccessVlanNotCoveredRule,
        """ip dhcp snooping
ip dhcp snooping vlan 10
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
!
""",
        """dhcpv4-snooping
vlan 10
 dhcpv4-snooping
!
interface 1/1/1
 no routing
 vlan access 20
!
""",
    ),
    (
        DHCP003TrustedAccessPortRule,
        """ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
 ip dhcp snooping trust
!
""",
        """dhcpv4-snooping
vlan 20
 dhcpv4-snooping
!
interface 1/1/1
 no routing
 vlan access 20
 dhcpv4-snooping trust
!
""",
    ),
    (
        DAI001DhcpVlanWithoutDAIRule,
        """ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
!
""",
        """dhcpv4-snooping
vlan 20
 dhcpv4-snooping
!
interface 1/1/1
 no routing
 vlan access 20
!
""",
    ),
    (
        STP001PortFastWithoutBPDUGuardRule,
        """interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
!
""",
        """interface 1/1/1
 no routing
 vlan access 20
 spanning-tree port-type admin-edge
!
""",
    ),
]


@pytest.mark.parametrize("rule_type,cisco_text,aruba_text", CASES)
def test_different_vendor_syntax_produces_same_rule_semantics(
    rule_type,
    cisco_text,
    aruba_text,
):
    cisco = rule_type(CiscoSafeConfigRenderer()).evaluate(
        CiscoIOSParser().parse(cisco_text)
    )[0]
    aruba = rule_type(ArubaSafeConfigRenderer()).evaluate(
        ArubaAOSCXParser().parse(aruba_text)
    )[0]

    semantic_fields = (
        "rule_id",
        "title",
        "category",
        "severity",
        "confidence",
        "technical_impact",
        "remediation",
    )
    assert tuple(getattr(cisco, field) for field in semantic_fields) == tuple(
        getattr(aruba, field) for field in semantic_fields
    )
    assert len(cisco.affected_interfaces) == len(aruba.affected_interfaces)
    assert cisco.safe_config_example != aruba.safe_config_example
    assert all("dhcpv4" not in line.text for line in cisco.evidence)
    assert all("switchport" not in line.text for line in aruba.evidence)
