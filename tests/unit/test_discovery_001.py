from itertools import product

import pytest

from src.domain.models import (
    Confidence, ConfigState, CoverageClass, InterfaceConfig, InterfaceMode,
    ParsedConfig, Severity, SourceLine,
)
from src.domain.vendors import Vendor
from src.parsers.cisco.ios import CiscoIOSParser
from src.renderers.safe_config import (
    ArubaAOSSafeConfigRenderer, ArubaSafeConfigRenderer, CiscoSafeConfigRenderer,
    HuaweiVRPSafeConfigRenderer, UnavailableSafeConfigRenderer,
)
from src.rules.discovery.discovery_001 import Discovery001AccessAdvertisementRule
from src.services.analysis import AnalysisApplicationService
from src.services.coverage import CoverageService


def analyze(text):
    return Discovery001AccessAdvertisementRule().evaluate_detailed(CiscoIOSParser().parse(text))


@pytest.mark.parametrize("command,field,interface", [
    ("cdp run", "cdp_global", False),
    ("lldp run", "lldp_global", False),
    ("cdp enable", "cdp", True),
    ("lldp transmit", "lldp_transmit", True),
])
@pytest.mark.parametrize("negated", [False, True])
def test_exact_commands_and_provenance(command, field, interface, negated):
    command = ("no " if negated else "") + command
    text = f"interface Gi1/0/1\n {command}\n" if interface else command + "\n"
    parsed = CiscoIOSParser().parse(text)
    target = parsed.interfaces[0] if interface else parsed
    assert getattr(target, field) == (ConfigState.DISABLED if negated else ConfigState.ENABLED)
    line = SourceLine(2, " " + command) if interface else SourceLine(1, command)
    assert getattr(target, field + "_evidence") == line
    assert parsed.parsed_line_coverage[line.line_number] == CoverageClass.SUPPORTED_RELEVANT


@pytest.mark.parametrize("text", [
    "interface Gi1/0/1\n cdp run\n lldp run\n",
    "cdp enable\nlldp transmit\n",
    " cdp run\n lldp run\n",
    "line vty 0 4\n cdp run\n lldp run\n",
    "interface range Gi1/0/1 - 2\n cdp enable\n lldp transmit\n",
])
@pytest.mark.parametrize("negated", [False, True])
def test_wrong_context_does_not_create_discovery_state(text, negated):
    if negated:
        for command in ("cdp run", "lldp run", "cdp enable", "lldp transmit"):
            text = text.replace(command, "no " + command)
    parsed = CiscoIOSParser().parse(text)
    assert parsed.cdp_global == parsed.lldp_global == ConfigState.NOT_CONFIGURED
    assert all(i.cdp == i.lldp_transmit == ConfigState.NOT_CONFIGURED for i in parsed.interfaces)


@pytest.mark.parametrize("command,field,interface", [
    ("cdp run", "cdp_global", False), ("lldp run", "lldp_global", False),
    ("cdp enable", "cdp", True), ("lldp transmit", "lldp_transmit", True),
])
def test_repetition_and_conflicts(command, field, interface):
    def parse(commands):
        text = "\n".join(commands) + "\n"
        if interface:
            text = "interface Gi1/0/1\n" + "".join(" " + line + "\n" for line in commands)
        parsed = CiscoIOSParser().parse(text)
        return parsed.interfaces[0] if interface else parsed
    assert getattr(parse([command, command]), field) == ConfigState.ENABLED
    for commands in ([command, "no " + command], ["no " + command, command],
                     [command, "no " + command, command]):
        assert getattr(parse(commands), field) == ConfigState.UNKNOWN


@pytest.mark.parametrize("global_state,local_state", list(product(ConfigState, repeat=2)))
def test_protocol_effective_state(global_state, local_state):
    expected = False if ConfigState.DISABLED in (global_state, local_state) else (
        True if global_state == local_state == ConfigState.ENABLED else None
    )
    assert Discovery001AccessAdvertisementRule._advertised(global_state, local_state) is expected


@pytest.mark.parametrize("cdp,lldp", [(True, False), (False, True), (True, True)])
def test_exposure_evidence_and_selective_remediation(cdp, lldp):
    text = "cdp run\nlldp run\ninterface Gi1/0/1\n switchport mode access\n"
    text += " cdp enable\n" if cdp else ""
    text += " lldp transmit\n" if lldp else ""
    result = analyze(text)
    assert result.assessed_units == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.MEDIUM
    assert finding.risk_score == 4
    assert finding.category == "INFORMATION_LEAKAGE"
    assert finding.affected_interfaces == ["Gi1/0/1"]
    expected = ["interface Gi1/0/1"]
    if cdp:
        expected.append(" no cdp enable")
    if lldp:
        expected.append(" no lldp transmit")
    assert finding.safe_config_example == "\n".join(expected)
    evidence = [line.text.strip() for line in finding.evidence]
    assert ("cdp run" in evidence) == cdp
    assert ("lldp run" in evidence) == lldp
    assert ("cdp enable" in evidence) == cdp
    assert ("lldp transmit" in evidence) == lldp
    assert finding.evidence == sorted(set(finding.evidence), key=lambda line: line.line_number)
    assert "interface Gi1/0/1" in evidence
    assert "switchport mode access" in evidence


@pytest.mark.parametrize("global_commands,local_commands,assessed", [
    ("", "", 0),
    ("no cdp run\n", "", 0),
    ("no cdp run\nno lldp run\n", "", 1),
    ("", " no cdp enable\n no lldp transmit\n", 1),
    ("cdp run\nlldp run\n", "", 0),
])
def test_clean_and_unknown_assessment(global_commands, local_commands, assessed):
    result = analyze(global_commands + "interface Gi1/0/1\n switchport mode access\n" + local_commands)
    assert result.findings == []
    assert result.assessed_units == assessed


@pytest.mark.parametrize("mode", [InterfaceMode.TRUNK, InterfaceMode.UNKNOWN])
def test_non_access_excluded(mode):
    config = ParsedConfig(vendor="irrelevant", cdp_global=ConfigState.ENABLED,
        interfaces=[InterfaceConfig("port", mode=mode, cdp=ConfigState.ENABLED)])
    result = Discovery001AccessAdvertisementRule().evaluate_detailed(config)
    assert result.findings == []
    assert result.assessed_units == 0


@pytest.mark.parametrize("receive", ["lldp receive", "no lldp receive"])
def test_receive_neither_creates_nor_suppresses_exposure(receive):
    base = "lldp run\ninterface Gi1/0/1\n switchport mode access\n " + receive + "\n"
    assert analyze(base).assessed_units == 0
    assert len(analyze(base + " lldp transmit\n").findings) == 1
    assert CoverageService().evaluate(base).lines[-1].classification == CoverageClass.UNSUPPORTED_RELEVANT


@pytest.mark.parametrize("command", ["cdp timer 30", "lldp timer 30", "lldp tlv-select system-name", "cdp en", "default cdp enable"])
def test_variants_are_not_supported(command):
    report = CoverageService().evaluate("interface Gi1/0/1\n " + command + "\n")
    assert report.lines[-1].classification == CoverageClass.UNKNOWN_RELEVANCE


def test_one_finding_per_interface():
    text = "cdp run\n" + "".join(
        f"interface Gi1/0/{number}\n switchport mode access\n cdp enable\n!\n"
        for number in (10, 2)
    )
    result = analyze(text)
    assert result.assessed_units == 2
    assert [f.affected_interfaces for f in result.findings] == [["Gi1/0/2"], ["Gi1/0/10"]]


@pytest.mark.parametrize("vendor", [Vendor.ARUBA_AOS_CX, Vendor.ARUBA_AOS_S, Vendor.HUAWEI_VRP])
def test_other_platforms_keep_discovery_unassessed(vendor):
    result = AnalysisApplicationService().analyze("synthetic\n", vendor)
    assert result.posture.total_rule_count == 10
    assert result.evaluations["DISCOVERY-001"].assessed_units == 0
    assert result.evaluations["DISCOVERY-001"].findings == []


@pytest.mark.parametrize("renderer", [ArubaSafeConfigRenderer, ArubaAOSSafeConfigRenderer, HuaweiVRPSafeConfigRenderer, UnavailableSafeConfigRenderer])
def test_unsupported_renderers_return_na(renderer):
    assert renderer().disable_discovery_advertisement("port", cdp=True, lldp=True) == "N/A"


def test_empty_remediation_is_unavailable():
    assert CiscoSafeConfigRenderer().disable_discovery_advertisement("port", cdp=False, lldp=False) == "N/A"


def test_normalized_defaults_do_not_infer_platform_defaults():
    parsed = ParsedConfig("cisco_ios")
    interface = InterfaceConfig("Gi1/0/1")
    for field in ("cdp_global", "lldp_global"):
        assert getattr(parsed, field) == ConfigState.NOT_CONFIGURED
        assert getattr(parsed, field + "_evidence") is None
    for field in ("cdp", "lldp_transmit"):
        assert getattr(interface, field) == ConfigState.NOT_CONFIGURED
        assert getattr(interface, field + "_evidence") is None
    assert not hasattr(interface, "lldp_receive")


def test_conflicting_enablement_does_not_emit_finding():
    result = analyze(
        "cdp run\nno cdp run\ncdp run\n"
        "interface Gi1/0/1\n switchport mode access\n cdp enable\n"
    )
    assert result.findings == []
    assert result.assessed_units == 0


def test_explicit_disable_compensates_for_other_enabled_state():
    result = analyze(
        "no cdp run\nlldp run\n"
        "interface Gi1/0/1\n switchport mode access\n"
        " cdp enable\n no lldp transmit\n"
    )
    assert result.findings == []
    assert result.assessed_units == 1
