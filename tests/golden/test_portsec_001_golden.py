from pathlib import Path

from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.port_security.portsec_001 import (
    PORTSEC001InconsistentCoverageRule,
)


INSECURE_SAMPLE_PATH = Path(
    "samples/cisco/portsec_001_inconsistent_access_ports.cfg"
)

SAFE_SAMPLE_PATH = Path(
    "samples/cisco/portsec_001_consistent_access_ports.cfg"
)


def test_portsec_001_golden_sample():
    config = CiscoIOSParser().parse(
        INSECURE_SAMPLE_PATH.read_text(encoding="utf-8")
    )

    findings = PORTSEC001InconsistentCoverageRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert len(findings) == 1
    assert findings[0].rule_id == "PORTSEC-001"
    assert findings[0].affected_interfaces == [
        "GigabitEthernet1/0/2"
    ]


def test_portsec_001_consistent_golden_sample_produces_no_finding():
    config = CiscoIOSParser().parse(
        SAFE_SAMPLE_PATH.read_text(encoding="utf-8")
    )

    findings = PORTSEC001InconsistentCoverageRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert findings == []
