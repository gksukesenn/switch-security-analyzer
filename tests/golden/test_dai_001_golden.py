from pathlib import Path

from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.dai.dai_001 import DAI001DhcpVlanWithoutDAIRule


INSECURE_SAMPLE_PATH = Path(
    "samples/cisco/dai_001_dhcp_vlan_without_dai.cfg"
)

SAFE_SAMPLE_PATH = Path(
    "samples/cisco/dai_001_dhcp_vlan_with_dai.cfg"
)


def test_dai_001_golden_sample():
    config = CiscoIOSParser().parse(
        INSECURE_SAMPLE_PATH.read_text(encoding="utf-8")
    )

    findings = DAI001DhcpVlanWithoutDAIRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert len(findings) == 1
    assert findings[0].rule_id == "DAI-001"
    assert findings[0].affected_interfaces == [
        "GigabitEthernet1/0/5"
    ]


def test_dai_001_safe_golden_sample_produces_no_finding():
    config = CiscoIOSParser().parse(
        SAFE_SAMPLE_PATH.read_text(encoding="utf-8")
    )

    findings = DAI001DhcpVlanWithoutDAIRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert findings == []
