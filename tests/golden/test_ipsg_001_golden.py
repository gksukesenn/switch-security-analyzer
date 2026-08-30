from pathlib import Path

from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.ip_source_guard.ipsg_001 import (
    IPSG001DhcpEndpointWithoutIPSGRule,
)


INSECURE_SAMPLE_PATH = Path(
    "samples/cisco/ipsg_001_dhcp_endpoint_without_ipsg.cfg"
)

SAFE_SAMPLE_PATH = Path(
    "samples/cisco/ipsg_001_dhcp_endpoint_with_ipsg.cfg"
)


def test_ipsg_001_golden_sample():
    config = CiscoIOSParser().parse(
        INSECURE_SAMPLE_PATH.read_text(encoding="utf-8")
    )

    findings = IPSG001DhcpEndpointWithoutIPSGRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert len(findings) == 1
    assert findings[0].rule_id == "IPSG-001"
    assert findings[0].affected_interfaces == [
        "GigabitEthernet1/0/5"
    ]


def test_ipsg_001_safe_golden_sample_produces_no_finding():
    config = CiscoIOSParser().parse(
        SAFE_SAMPLE_PATH.read_text(encoding="utf-8")
    )

    findings = IPSG001DhcpEndpointWithoutIPSGRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert findings == []
