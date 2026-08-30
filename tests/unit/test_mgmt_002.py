import pytest

from src.domain.models import ConfigState, Confidence, Severity
from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.management.mgmt_002 import MGMT002InsecureHTTPServerRule


def evaluate(raw_config: str):
    config = CiscoIOSParser().parse(raw_config)
    return MGMT002InsecureHTTPServerRule().evaluate(config)


@pytest.mark.parametrize(
    "https_command",
    [None, "ip http secure-server", "no ip http secure-server"],
)
def test_mgmt_002_fires_for_explicit_http_regardless_of_https_state(
    https_command,
):
    raw_config = "ip http server\n"
    if https_command is not None:
        raw_config += f"{https_command}\n"

    findings = evaluate(raw_config)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "MGMT-002"
    assert finding.title == (
        "Insecure HTTP management service explicitly enabled"
    )
    assert finding.category == "MGMT"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.HIGH
    assert finding.affected_interfaces == []


@pytest.mark.parametrize(
    "raw_config",
    [
        "ip http secure-server\n",
        "no ip http server\n",
        "hostname ACCESS-SW-01\n",
    ],
)
def test_mgmt_002_does_not_infer_http_state(raw_config):
    assert evaluate(raw_config) == []


def test_mgmt_002_uses_explicit_http_evidence_and_minimal_safe_example():
    finding = evaluate("""hostname ACCESS-SW-01
ip http server
ip http secure-server
""")[0]

    assert [
        (line.line_number, line.text) for line in finding.evidence
    ] == [(2, "ip http server")]
    assert finding.safe_config_example == "no ip http server"


def test_mgmt_002_does_not_fire_for_unknown_http_state():
    config = CiscoIOSParser().parse("hostname ACCESS-SW-01\n")
    config.http_server = ConfigState.UNKNOWN

    assert MGMT002InsecureHTTPServerRule().evaluate(config) == []
