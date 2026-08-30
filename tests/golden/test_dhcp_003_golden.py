from pathlib import Path

from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.dhcp.dhcp_003 import DHCP003TrustedAccessPortRule


INSECURE_SAMPLE_PATH = Path(
    "samples/cisco/dhcp_003_trusted_access.cfg"
)

SAFE_SAMPLE_PATH = Path(
    "samples/cisco/dhcp_003_safe_access.cfg"
)


def test_dhcp_003_golden_sample():
    raw_config = INSECURE_SAMPLE_PATH.read_text(
        encoding="utf-8"
    )

    parser = CiscoIOSParser()
    config = parser.parse(raw_config)

    rule = DHCP003TrustedAccessPortRule()
    findings = rule.evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"

    assert len(config.interfaces) == 1

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "DHCP-003"
    assert finding.affected_interfaces == [
        "GigabitEthernet1/0/5"
    ]

def test_dhcp_003_safe_golden_sample_produces_no_finding():
    raw_config = SAFE_SAMPLE_PATH.read_text(
        encoding="utf-8"
    )

    parser = CiscoIOSParser()
    config = parser.parse(raw_config)

    rule = DHCP003TrustedAccessPortRule()
    findings = rule.evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"

    assert len(config.interfaces) == 1

    interface = config.interfaces[0]

    assert interface.name == "GigabitEthernet1/0/5"

    assert findings == []