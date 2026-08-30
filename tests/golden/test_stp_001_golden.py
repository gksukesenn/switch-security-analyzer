from pathlib import Path

from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.stp.stp_001 import STP001PortFastWithoutBPDUGuardRule


INSECURE_SAMPLE_PATH = Path(
    "samples/cisco/stp_001_portfast_without_bpduguard.cfg"
)

SAFE_SAMPLE_PATH = Path(
    "samples/cisco/stp_001_portfast_with_bpduguard.cfg"
)


def test_stp_001_golden_sample():
    config = CiscoIOSParser().parse(
        INSECURE_SAMPLE_PATH.read_text(encoding="utf-8")
    )

    findings = STP001PortFastWithoutBPDUGuardRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert len(findings) == 1
    assert findings[0].rule_id == "STP-001"
    assert findings[0].affected_interfaces == [
        "GigabitEthernet1/0/5"
    ]


def test_stp_001_safe_golden_sample_produces_no_finding():
    config = CiscoIOSParser().parse(
        SAFE_SAMPLE_PATH.read_text(encoding="utf-8")
    )

    findings = STP001PortFastWithoutBPDUGuardRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert findings == []
