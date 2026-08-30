from src.domain.models import (
    Confidence,
    ConfigState,
    Finding,
    InterfaceMode,
    ParsedConfig,
    Severity,
    SourceLine,
)


class DHCP003TrustedAccessPortRule:
    rule_id = "DHCP-003"

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        findings: list[Finding] = []

        if config.dhcp_snooping_global != ConfigState.ENABLED:
            return findings

        for interface in config.interfaces:
            if interface.mode != InterfaceMode.ACCESS:
                continue

            if interface.access_vlan is None:
                continue

            if interface.access_vlan not in config.dhcp_snooping_vlans:
                continue

            if interface.dhcp_snooping_trust != ConfigState.ENABLED:
                continue

            evidence: list[SourceLine] = []

            if config.dhcp_snooping_global_evidence is not None:
                evidence.append(config.dhcp_snooping_global_evidence)

            vlan_evidence = config.dhcp_snooping_vlan_evidence.get(
                interface.access_vlan
            )

            if vlan_evidence is not None:
                evidence.append(vlan_evidence)

            evidence.extend(
                self._collect_evidence(interface.raw_lines)
            )

            finding = Finding(
                rule_id=self.rule_id,
                title="DHCP Snooping trusted on access port",
                category="DHCP_SPOOFING",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                technical_impact=(
                    "An access port in a DHCP Snooping-enabled VLAN "
                    "is explicitly trusted. DHCP server responses arriving "
                    "through this port may therefore be accepted."
                ),
                remediation=(
                    "Verify the physical role of the interface. "
                    "If it is an endpoint-facing access port, remove DHCP "
                    "Snooping trust. Trust should be limited to authorized "
                    "DHCP server paths."
                ),
                safe_config_example=(
                    f"interface {interface.name}\n"
                    " switchport mode access\n"
                    f" switchport access vlan {interface.access_vlan}"
                ),
                evidence=evidence,
                affected_interfaces=[interface.name],
            )

            findings.append(finding)

        return findings

    @staticmethod
    def _collect_evidence(
        raw_lines: list[SourceLine],
    ) -> list[SourceLine]:
        relevant_commands = (
            "interface ",
            "switchport mode access",
            "switchport access vlan ",
            "ip dhcp snooping trust",
        )

        return [
            line
            for line in raw_lines
            if line.text.strip().startswith(relevant_commands)
        ]
