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


class DHCP002AccessVlanNotCoveredRule:
    rule_id = "DHCP-002"

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        return self.evaluate_detailed(config).findings

    def evaluate_detailed(self, config: ParsedConfig) -> RuleEvaluation:
        if config.dhcp_snooping_global != ConfigState.ENABLED:
            return RuleEvaluation([], 0)

        interfaces_by_vlan: dict[int, list[InterfaceConfig]] = {}
        assessed_vlans: set[int] = set()

        for interface in config.interfaces:
            if interface.mode != InterfaceMode.ACCESS:
                continue

            if interface.access_vlan is None:
                continue

            if interface.dhcp_snooping_trust == ConfigState.ENABLED:
                continue

            assessed_vlans.add(interface.access_vlan)

            if interface.access_vlan in config.dhcp_snooping_vlans:
                continue

            interfaces_by_vlan.setdefault(
                interface.access_vlan,
                [],
            ).append(interface)

        findings: list[Finding] = []

        for vlan_id in sorted(interfaces_by_vlan):
            interfaces = sorted(
                interfaces_by_vlan[vlan_id],
                key=lambda interface: natural_sort_key(interface.name),
            )
            evidence = self._collect_evidence(config, interfaces)

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Access VLAN not covered by DHCP Snooping",
                    category="DHCP_SPOOFING",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    technical_impact=(
                        "An access VLAN with endpoint-facing interfaces is "
                        "not included in the configured DHCP Snooping VLAN "
                        "scope. DHCP Snooping protection may therefore not "
                        "be enforced for DHCP traffic on this VLAN."
                    ),
                    remediation=(
                        "Verify whether the affected VLAN uses DHCP and "
                        "should be protected. If so, add the VLAN to the "
                        "DHCP Snooping scope and verify that only authorized "
                        "DHCP server paths are trusted."
                    ),
                    safe_config_example=(
                        "ip dhcp snooping\n"
                        f"ip dhcp snooping vlan {vlan_id}"
                    ),
                    evidence=evidence,
                    affected_interfaces=[
                        interface.name for interface in interfaces
                    ],
                )
            )

        return RuleEvaluation(findings, len(assessed_vlans))

    @staticmethod
    def _collect_evidence(
        config: ParsedConfig,
        interfaces: list[InterfaceConfig],
    ) -> list[SourceLine]:
        evidence: list[SourceLine] = []

        if config.dhcp_snooping_global_evidence is not None:
            evidence.append(config.dhcp_snooping_global_evidence)

        evidence.extend(config.dhcp_snooping_vlan_evidence.values())

        for interface in interfaces:
            evidence.extend(line for line in (
                interface.declaration_evidence,
                interface.mode_evidence,
                interface.access_vlan_evidence,
            ) if line is not None)

        evidence.sort(key=lambda line: line.line_number)
        return evidence
