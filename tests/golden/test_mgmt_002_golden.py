from pathlib import Path

from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.management.mgmt_002 import MGMT002InsecureHTTPServerRule


INSECURE_SAMPLE_PATH = Path("samples/cisco/mgmt_002_http_enabled.cfg")
SAFE_SAMPLE_PATH = Path("samples/cisco/mgmt_002_http_disabled.cfg")


def test_mgmt_002_golden_sample():
    config = CiscoIOSParser().parse(
        INSECURE_SAMPLE_PATH.read_text(encoding="utf-8")
    )

    findings = MGMT002InsecureHTTPServerRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert len(findings) == 1
    assert findings[0].rule_id == "MGMT-002"


def test_mgmt_002_safe_golden_sample_produces_no_finding():
    config = CiscoIOSParser().parse(
        SAFE_SAMPLE_PATH.read_text(encoding="utf-8")
    )

    findings = MGMT002InsecureHTTPServerRule().evaluate(config)

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert findings == []
