"""Frozen regression oracle for the normalized-evidence refactor.

This test preserves the pre-refactor Cisco evidence behavior only.
Do not extend it for new rules or vendors; new rules must test their
evidence in their own rule tests. This suite may be retired during a
future intentional model redesign.
"""

from dataclasses import asdict
from pathlib import Path

import pytest

from src.domain.models import ConfigState, InterfaceMode, SourceLine
from src.services.analyzer import AnalyzerService


SAMPLES = sorted(
    path
    for path in Path("samples/cisco").glob("*.cfg")
    if not path.name.startswith("coverage_")
)


def _interface_lines(interface, predicates) -> list[SourceLine]:
    return [
        line for line in interface.raw_lines
        if any(predicate(line.text.strip()) for predicate in predicates)
    ]


def _legacy_evidence(rule_id, finding, config) -> list[SourceLine]:
    affected = set(finding.affected_interfaces)
    interfaces = [i for i in config.interfaces if i.name in affected]
    starts = lambda prefix: lambda text: text.startswith(prefix)
    equals = lambda command: lambda text: text == command
    declaration = starts("interface ")
    mode = equals("switchport mode access")
    vlan = starts("switchport access vlan ")
    evidence: list[SourceLine] = []

    if rule_id == "DHCP-001":
        if config.dhcp_snooping_global_evidence is not None:
            evidence.append(config.dhcp_snooping_global_evidence)
        evidence.extend(
            config.dhcp_snooping_vlan_evidence[vlan_id]
            for vlan_id in sorted(config.dhcp_snooping_vlans)
        )
        for interface in config.interfaces:
            if interface.dhcp_snooping_trust == ConfigState.ENABLED:
                evidence.extend(_interface_lines(interface, [
                    declaration, equals("ip dhcp snooping trust")]))

    elif rule_id == "DHCP-002":
        evidence.append(config.dhcp_snooping_global_evidence)
        evidence.extend(config.dhcp_snooping_vlan_evidence.values())
        for interface in interfaces:
            evidence.extend(_interface_lines(
                interface, [declaration, mode, vlan]))

    elif rule_id == "DHCP-003":
        interface = interfaces[0]
        evidence.extend([
            config.dhcp_snooping_global_evidence,
            config.dhcp_snooping_vlan_evidence[interface.access_vlan],
        ])
        evidence.extend(_interface_lines(interface, [
            declaration, mode, vlan, equals("ip dhcp snooping trust")]))
        return evidence

    elif rule_id == "PORTSEC-001":
        vlan_ids = {interface.access_vlan for interface in interfaces}
        peers = [
            interface for interface in config.interfaces
            if interface.mode == InterfaceMode.ACCESS
            and interface.access_vlan in vlan_ids
            and interface.port_security == ConfigState.ENABLED
        ]
        for interface in [*peers, *interfaces]:
            evidence.extend(_interface_lines(interface, [
                declaration, mode, vlan,
                equals("switchport port-security"),
                equals("no switchport port-security"),
            ]))

    elif rule_id == "STP-001":
        if (any(i.portfast == ConfigState.NOT_CONFIGURED for i in interfaces)
                and config.portfast_default_evidence is not None):
            evidence.append(config.portfast_default_evidence)
        if config.bpdu_guard_default_evidence is not None:
            evidence.append(config.bpdu_guard_default_evidence)
        for interface in interfaces:
            evidence.extend(_interface_lines(interface, [
                declaration, mode, vlan,
                equals("spanning-tree portfast"),
                equals("spanning-tree portfast edge"),
                equals("spanning-tree bpduguard disable"),
            ]))
        return sorted(set(evidence), key=lambda line: line.line_number)

    elif rule_id in {"DAI-001", "IPSG-001"}:
        vlan_id = interfaces[0].access_vlan
        evidence.extend([
            config.dhcp_snooping_global_evidence,
            config.dhcp_snooping_vlan_evidence[vlan_id],
        ])
        predicates = [declaration, mode, vlan]
        if rule_id == "IPSG-001":
            predicates.append(equals("no ip verify source"))
        for interface in interfaces:
            evidence.extend(_interface_lines(interface, predicates))

    elif rule_id == "MGMT-001":
        for vty in config.vty_lines:
            if (vty.transport_input_state == ConfigState.ENABLED
                    and "telnet" in vty.transport_input):
                evidence.extend([
                    line for line in vty.raw_lines
                    if line.text.strip().startswith("line vty ")
                    or line is vty.transport_input_evidence
                ])

    elif rule_id == "MGMT-002":
        evidence.append(config.http_server_evidence)

    return sorted(evidence, key=lambda line: line.line_number)


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda path: path.name)
def test_cisco_findings_retain_exact_legacy_payload_and_evidence(sample):
    raw_text = sample.read_text()
    analyzer = AnalyzerService()
    config = analyzer.parser.parse(raw_text)

    for finding in analyzer.analyze(raw_text):
        expected_evidence = _legacy_evidence(finding.rule_id, finding, config)
        expected_payload = asdict(finding)
        expected_payload["evidence"] = [asdict(line) for line in expected_evidence]

        assert asdict(finding) == expected_payload
        assert finding.evidence == sorted(
            finding.evidence, key=lambda line: line.line_number)
        assert len(finding.evidence) == len(set(finding.evidence))
