from pathlib import Path

import pytest

from src.domain.models import (
    AnalysisConfidence,
    ConfigState,
    CoverageClass,
)
from src.parsers.cisco.ios import CiscoIOSParser
from src.services.coverage import CoverageCalculator, CoverageService


SAMPLES = Path("samples/cisco")


@pytest.mark.parametrize(
    ("name", "counts", "coverage", "unknown_ratio", "confidence"),
    [
        (
            "coverage_supported_only.cfg",
            (5, 0, 1, 0),
            1.0,
            0.0,
            AnalysisConfidence.HIGH,
        ),
        (
            "coverage_mixed.cfg",
            (5, 3, 0, 0),
            0.625,
            0.0,
            AnalysisConfidence.MEDIUM,
        ),
        (
            "coverage_unknown.cfg",
            (4, 1, 0, 2),
            0.8,
            2 / 7,
            AnalysisConfidence.MEDIUM,
        ),
        (
            "coverage_no_relevant.cfg",
            (0, 0, 2, 0),
            None,
            0.0,
            AnalysisConfidence.UNKNOWN,
        ),
    ],
)
def test_dedicated_coverage_fixtures(
    name,
    counts,
    coverage,
    unknown_ratio,
    confidence,
):
    raw_text = (SAMPLES / name).read_text()

    report = CoverageService().evaluate(raw_text)

    assert (
        report.supported_relevant,
        report.unsupported_relevant,
        report.out_of_scope,
        report.unknown_relevance,
    ) == counts
    if coverage is None:
        assert report.coverage is None
    else:
        assert report.coverage == pytest.approx(coverage)
    assert report.unknown_ratio == pytest.approx(unknown_ratio)
    assert report.analysis_confidence == confidence


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("hostname ACCESS-SW-01", CoverageClass.OUT_OF_SCOPE),
        ("interface GigabitEthernet1/0/5", CoverageClass.SUPPORTED_RELEVANT),
        ("line vty 0 4", CoverageClass.SUPPORTED_RELEVANT),
        ("ip dhcp snooping", CoverageClass.SUPPORTED_RELEVANT),
        ("ip http server", CoverageClass.SUPPORTED_RELEVANT),
        ("ip http secure-server", CoverageClass.SUPPORTED_RELEVANT),
        ("snmp-server community public RO", CoverageClass.UNSUPPORTED_RELEVANT),
        ("cdp run", CoverageClass.UNSUPPORTED_RELEVANT),
        ("lldp run", CoverageClass.UNSUPPORTED_RELEVANT),
        ("spanning-tree guard root", CoverageClass.UNSUPPORTED_RELEVANT),
        ("completely unknown meaningful command", CoverageClass.UNKNOWN_RELEVANCE),
    ],
)
def test_required_global_line_classifications(line, expected):
    report = CoverageService().evaluate(line)
    assert report.lines[0].classification == expected


@pytest.mark.parametrize(
    ("child", "expected"),
    [
        ("description USER-PC", CoverageClass.OUT_OF_SCOPE),
        ("switchport mode access", CoverageClass.SUPPORTED_RELEVANT),
        ("switchport trunk native vlan 99", CoverageClass.UNSUPPORTED_RELEVANT),
    ],
)
def test_required_interface_child_classifications(child, expected):
    report = CoverageService().evaluate(
        f"interface GigabitEthernet1/0/5\n {child}\n"
    )
    assert report.lines[1].classification == expected


@pytest.mark.parametrize(
    ("supported", "unsupported", "unknown", "expected"),
    [
        (80, 20, 0, AnalysisConfidence.HIGH),
        (79, 21, 0, AnalysisConfidence.MEDIUM),
        (60, 40, 0, AnalysisConfidence.MEDIUM),
        (59, 41, 0, AnalysisConfidence.LOW),
        (8, 0, 2, AnalysisConfidence.HIGH),
        (7, 0, 2, AnalysisConfidence.MEDIUM),
        (6, 0, 4, AnalysisConfidence.MEDIUM),
        (5, 0, 5, AnalysisConfidence.LOW),
    ],
)
def test_analysis_confidence_boundaries(
    supported,
    unsupported,
    unknown,
    expected,
):
    _, _, confidence = CoverageCalculator.calculate(
        supported,
        unsupported,
        0,
        unknown,
    )
    assert confidence == expected


def test_no_relevant_lines_produce_na_and_unknown_confidence():
    coverage, unknown_ratio, confidence = CoverageCalculator.calculate(
        0, 0, 10, 0
    )
    assert coverage is None
    assert unknown_ratio == 0.0
    assert confidence == AnalysisConfidence.UNKNOWN


def test_out_of_scope_lines_do_not_dilute_unknown_ratio():
    coverage, unknown_ratio, _ = CoverageCalculator.calculate(60, 20, 400, 20)
    assert coverage == 0.75
    assert unknown_ratio == 0.20


def test_every_meaningful_line_is_classified_exactly_once():
    raw_text = """hostname SW1
!
ip dhcp snooping
snmp-server community public RO
unknown command
"""
    report = CoverageService().evaluate(raw_text)
    assert len(report.lines) == 4
    assert len({line.source_line.line_number for line in report.lines}) == 4


@pytest.mark.parametrize("sample_path", sorted(SAMPLES.glob("*.cfg")))
def test_all_cisco_samples_classify_every_meaningful_line_once(sample_path):
    raw_text = sample_path.read_text()
    config = CiscoIOSParser().parse(raw_text)
    report = CoverageService().evaluate(raw_text, config)
    meaningful_numbers = {
        line_number
        for line_number, line in enumerate(raw_text.splitlines(), 1)
        if line.strip() and line.strip() != "!"
    }
    classified_numbers = [
        line.source_line.line_number for line in report.lines
    ]
    parsed_numbers = set(config.parsed_line_coverage)
    unparsed_numbers = {
        line.line_number for line in config.unparsed_lines
    }

    assert set(classified_numbers) == meaningful_numbers
    assert len(classified_numbers) == len(set(classified_numbers))
    assert parsed_numbers.isdisjoint(unparsed_numbers)
    assert parsed_numbers | unparsed_numbers == meaningful_numbers


def test_aaa_new_model_is_unparsed_and_unsupported_relevant():
    raw_text = "aaa new-model\n"
    config = CiscoIOSParser().parse(raw_text)
    report = CoverageService().evaluate(raw_text, config)

    assert [line.line_number for line in config.unparsed_lines] == [1]
    assert report.lines[0].classification == CoverageClass.UNSUPPORTED_RELEVANT
    assert report.lines[0].family_id == "aaa"


def test_port_security_subcommand_is_not_exact_supported_command():
    raw_text = """interface GigabitEthernet1/0/5
 switchport port-security maximum 5
"""
    config = CiscoIOSParser().parse(raw_text)
    report = CoverageService().evaluate(raw_text, config)

    assert config.interfaces[0].port_security == ConfigState.NOT_CONFIGURED
    assert [line.line_number for line in config.unparsed_lines] == [2]
    assert report.lines[1].classification == CoverageClass.UNSUPPORTED_RELEVANT


def test_http_authentication_is_not_exact_supported_server_command():
    raw_text = "ip http authentication local\n"
    config = CiscoIOSParser().parse(raw_text)
    report = CoverageService().evaluate(raw_text, config)

    assert config.http_server == ConfigState.NOT_CONFIGURED
    assert [line.line_number for line in config.unparsed_lines] == [1]
    assert report.lines[0].classification == CoverageClass.UNSUPPORTED_RELEVANT


@pytest.mark.parametrize(
    "line",
    [
        "aaa new-model",
        "snmp-server community public RO",
        "cdp run",
        "no cdp run",
        "lldp run",
        "no lldp run",
        "spanning-tree guard root",
        "switchport trunk native vlan 99",
        "switchport trunk allowed vlan 10,20",
        "switchport port-security maximum 5",
        "switchport port-security violation restrict",
        "switchport port-security mac-address sticky",
        "switchport port-security aging time 5",
        "ip arp inspection trust",
        "ip arp inspection limit rate 15",
        "ip arp inspection validate src-mac",
        "ip http authentication local",
        "ip http access-class 10",
    ],
)
def test_minimum_registry_contract(line):
    raw_text = f"interface GigabitEthernet1/0/5\n {line}\n"
    report = CoverageService().evaluate(raw_text)
    assert report.lines[1].classification == CoverageClass.UNSUPPORTED_RELEVANT


def test_known_unsupported_transport_is_not_coverage_unknown():
    raw_text = "line vty 0 4\n transport input ssh lat\n"
    report = CoverageService().evaluate(raw_text)
    assert report.lines[1].classification == CoverageClass.UNSUPPORTED_RELEVANT
