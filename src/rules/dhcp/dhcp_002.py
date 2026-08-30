from src.domain.models import (
    Confidence,
    ConfigState,
    Finding,
    InterfaceConfig,
    InterfaceMode,
    ParsedConfig,
    Severity,
    SourceLine,
)
from src.utils import natural_sort_key


class DHCP002AccessVlanNotCoveredRule:
    rule_id = "DHCP-002"

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        if config.dhcp_snooping_global != ConfigState.ENABLED:
            return []

        interfaces_by_vlan: dict[int, list[InterfaceConfig]] = {}

        for interface in config.interfaces:
            if interface.mode != InterfaceMode.ACCESS:
                continue

            if interface.access_vlan is None:
                continue

            if interface.dhcp_snooping_trust == ConfigState.ENABLED:
                continue

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

        return findings

    @staticmethod
    def _collect_evidence(
        config: ParsedConfig,
        interfaces: list[InterfaceConfig],
    ) -> list[SourceLine]:
        evidence: list[SourceLine] = []

        if config.dhcp_snooping_global_evidence is not None:
            evidence.append(config.dhcp_snooping_global_evidence)

        evidence.extend(config.dhcp_snooping_vlan_evidence.values())

        relevant_commands = (
            "interface ",
            "switchport mode access",
            "switchport access vlan ",
        )

        for interface in interfaces:
            evidence.extend(
                line
                for line in interface.raw_lines
                if line.text.strip().startswith(relevant_commands)
            )

        evidence.sort(key=lambda line: line.line_number)
        return evidence
