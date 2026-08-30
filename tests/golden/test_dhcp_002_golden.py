from pathlib import Path

from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.dhcp.dhcp_002 import DHCP002AccessVlanNotCoveredRule


INSECURE_SAMPLE_PATH = Path(
    "samples/cisco/dhcp_002_uncovered_access_vlan.cfg"
)

SAFE_SAMPLE_PATH = Path(
    "samples/cisco/dhcp_002_safe_access_vlan.cfg"
)


def test_dhcp_002_golden_sample():
    raw_config = INSECURE_SAMPLE_PATH.read_text(encoding="utf-8")
    config = CiscoIOSParser().parse(raw_config)

    findings = DHCP002AccessVlanNotCoveredRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert len(findings) == 1
    assert findings[0].rule_id == "DHCP-002"
    assert findings[0].affected_interfaces == [
        "GigabitEthernet1/0/5"
    ]


def test_dhcp_002_safe_golden_sample_produces_no_finding():
    raw_config = SAFE_SAMPLE_PATH.read_text(encoding="utf-8")
    config = CiscoIOSParser().parse(raw_config)

    findings = DHCP002AccessVlanNotCoveredRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert findings == []
