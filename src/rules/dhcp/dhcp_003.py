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


class DHCP003TrustedAccessPortRule:
    rule_id = "DHCP-003"

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        return self.evaluate_detailed(config).findings

    def evaluate_detailed(self, config: ParsedConfig) -> RuleEvaluation:
        findings: list[Finding] = []
        assessed_units = 0

        if config.dhcp_snooping_global != ConfigState.ENABLED:
            return RuleEvaluation(findings, assessed_units)

        for interface in config.interfaces:
            if interface.mode != InterfaceMode.ACCESS:
                continue

            if interface.access_vlan is None:
                continue

            if interface.access_vlan not in config.dhcp_snooping_vlans:
                continue

            assessed_units += 1

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

            evidence.extend(self._collect_evidence(interface))

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

        return RuleEvaluation(findings, assessed_units)

    @staticmethod
    def _collect_evidence(
        interface: InterfaceConfig,
    ) -> list[SourceLine]:
        return [
            line
            for line in (
                interface.declaration_evidence,
                interface.mode_evidence,
                interface.access_vlan_evidence,
                interface.dhcp_snooping_trust_evidence,
            )
            if line is not None
        ]
