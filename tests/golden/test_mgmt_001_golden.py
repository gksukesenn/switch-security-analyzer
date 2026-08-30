from pathlib import Path

from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.management.mgmt_001 import MGMT001VtyTelnetEnabledRule


INSECURE_SAMPLE_PATH = Path(
    "samples/cisco/mgmt_001_vty_telnet_enabled.cfg"
)

SAFE_SAMPLE_PATH = Path(
    "samples/cisco/mgmt_001_vty_ssh_only.cfg"
)


def test_mgmt_001_golden_sample():
    config = CiscoIOSParser().parse(
        INSECURE_SAMPLE_PATH.read_text(encoding="utf-8")
    )

    findings = MGMT001VtyTelnetEnabledRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert len(findings) == 1
    assert findings[0].rule_id == "MGMT-001"


def test_mgmt_001_safe_golden_sample_produces_no_finding():
    config = CiscoIOSParser().parse(
        SAFE_SAMPLE_PATH.read_text(encoding="utf-8")
    )

    findings = MGMT001VtyTelnetEnabledRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert findings == []
