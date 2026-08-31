from src.domain.models import (
    Confidence,
    ConfigState,
    Finding,
    InterfaceConfig,
    InterfaceMode,
    ParsedConfig,
    RuleEvaluation,
    Severity,
    SourceLine,
)
from src.utils import natural_sort_key


class DAI001DhcpVlanWithoutDAIRule:
    rule_id = "DAI-001"

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        return self.evaluate_detailed(config).findings

    def evaluate_detailed(self, config: ParsedConfig) -> RuleEvaluation:
        if config.dhcp_snooping_global != ConfigState.ENABLED:
            return RuleEvaluation([], 0)

        findings: list[Finding] = []
        assessed_units = 0

        for vlan_id in sorted(config.dhcp_snooping_vlans):
            affected_interfaces = sorted(
                (
                    interface
                    for interface in config.interfaces
                    if interface.mode == InterfaceMode.ACCESS
                    and interface.access_vlan == vlan_id
                ),
                key=lambda interface: natural_sort_key(interface.name),
            )

            if not affected_interfaces:
                continue

            assessed_units += 1

            if vlan_id in config.dai_vlans:
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=(
                        "DHCP Snooping protected VLAN lacks Dynamic ARP "
                        "Inspection"
                    ),
                    category="ARP_SPOOFING",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    technical_impact=(
                        "A VLAN protected by DHCP Snooping and used by "
                        "access interfaces is not included in the Dynamic "
                        "ARP Inspection scope. ARP traffic on this VLAN may "
                        "therefore not be validated against trusted "
                        "IP-to-MAC binding information, leaving an ARP "
                        "spoofing or poisoning exposure."
                    ),
                    remediation=(
                        "Verify that the affected VLAN uses DHCP and should "
                        "receive ARP validation. If so, enable Dynamic ARP "
                        "Inspection for the VLAN and verify the intended "
                        "trusted paths and any required handling for "
                        "statically addressed hosts."
                    ),
                    safe_config_example=(
                        f"ip arp inspection vlan {vlan_id}"
                    ),
                    evidence=self._collect_evidence(
                        config,
                        vlan_id,
                        affected_interfaces,
                    ),
                    affected_interfaces=[
                        interface.name
                        for interface in affected_interfaces
                    ],
                )
            )

        return RuleEvaluation(findings, assessed_units)

    @staticmethod
    def _collect_evidence(
        config: ParsedConfig,
        vlan_id: int,
        affected_interfaces: list[InterfaceConfig],
    ) -> list[SourceLine]:
        evidence: list[SourceLine] = []

        if config.dhcp_snooping_global_evidence is not None:
            evidence.append(config.dhcp_snooping_global_evidence)

        vlan_evidence = config.dhcp_snooping_vlan_evidence.get(vlan_id)
        if vlan_evidence is not None:
            evidence.append(vlan_evidence)

        for interface in affected_interfaces:
            evidence.extend(line for line in (
                interface.declaration_evidence,
                interface.mode_evidence,
                interface.access_vlan_evidence,
            ) if line is not None)

        evidence.sort(key=lambda line: line.line_number)
        return evidence
