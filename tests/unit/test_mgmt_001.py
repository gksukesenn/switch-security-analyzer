from src.domain.models import Confidence, Severity
from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.management.mgmt_001 import MGMT001VtyTelnetEnabledRule


def evaluate(raw_config: str):
    config = CiscoIOSParser().parse(raw_config)
    return MGMT001VtyTelnetEnabledRule().evaluate(config)


def test_mgmt_001_finds_explicit_telnet():
    findings = evaluate("""line vty 0 4
 transport input telnet
!
""")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "MGMT-001"
    assert finding.title == (
        "VTY lines explicitly permit Telnet management access"
    )
    assert finding.category == "MGMT"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.HIGH
    assert finding.affected_interfaces == []


def test_mgmt_001_finds_mixed_ssh_and_telnet():
    findings = evaluate("""line vty 0 4
 transport input ssh telnet
!
""")

    assert len(findings) == 1


def test_mgmt_001_finds_transport_all():
    findings = evaluate("""line vty 0 4
 transport input all
!
""")

    assert len(findings) == 1


def test_mgmt_001_does_not_fire_for_ssh_only():
    findings = evaluate("""line vty 0 4
 transport input ssh
!
""")

    assert findings == []


def test_mgmt_001_does_not_fire_for_transport_none():
    findings = evaluate("""line vty 0 4
 transport input none
!
""")

    assert findings == []


def test_mgmt_001_does_not_infer_absent_transport_default():
    findings = evaluate("""line vty 0 4
 login local
!
""")

    assert findings == []


def test_mgmt_001_does_not_fire_for_ambiguous_transport():
    findings = evaluate("""line vty 0 4
 transport input ssh
 transport input telnet
!
""")

    assert findings == []


def test_mgmt_001_aggregates_and_orders_affected_vty_ranges():
    findings = evaluate("""line vty 5 15
 transport input ssh telnet
!
line vty 0 4
 transport input telnet
!
""")

    assert len(findings) == 1
    assert findings[0].safe_config_example == (
        "line vty 0 4\n"
        " transport input ssh\n"
        "!\n"
        "line vty 5 15\n"
        " transport input ssh"
    )


def test_mgmt_001_excludes_safe_vty_blocks_from_finding_context():
    findings = evaluate("""line vty 0 4
 transport input ssh
!
line vty 5 15
 transport input telnet
!
""")

    assert findings[0].safe_config_example == (
        "line vty 5 15\n"
        " transport input ssh"
    )


def test_mgmt_001_contains_only_affected_vty_evidence():
    findings = evaluate("""line vty 0 4
 transport input ssh
!
line vty 5 15
 transport input telnet ssh
!
""")

    evidence = [
        (line.line_number, line.text.strip())
        for line in findings[0].evidence
    ]

    assert evidence == [
        (4, "line vty 5 15"),
        (5, "transport input telnet ssh"),
    ]
