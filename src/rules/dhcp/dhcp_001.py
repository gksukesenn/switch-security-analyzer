from src.domain.models import (
    Confidence,
    ConfigState,
    Finding,
    ParsedConfig,
    RuleEvaluation,
    Severity,
    SourceLine,
)


class DHCP001GloballyInactiveRule:
    rule_id = "DHCP-001"

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        return self.evaluate_detailed(config).findings

    def evaluate_detailed(self, config: ParsedConfig) -> RuleEvaluation:

        trusted_interfaces = [
            interface
            for interface in config.interfaces
            if interface.dhcp_snooping_trust == ConfigState.ENABLED
        ]

        assessed_units = int(
            config.dhcp_snooping_global == ConfigState.ENABLED
            or bool(config.dhcp_snooping_vlans or trusted_interfaces)
        )

        if config.dhcp_snooping_global == ConfigState.ENABLED:
            return RuleEvaluation([], assessed_units)

        if assessed_units == 0:
            return RuleEvaluation([], 0)

        evidence: list[SourceLine] = []

        if config.dhcp_snooping_global_evidence is not None:
            evidence.append(config.dhcp_snooping_global_evidence)

        evidence.extend(
            config.dhcp_snooping_vlan_evidence[vlan_id]
            for vlan_id in sorted(config.dhcp_snooping_vlans)
            if vlan_id in config.dhcp_snooping_vlan_evidence
        )

        for interface in trusted_interfaces:
            evidence.extend(line for line in (
                interface.declaration_evidence,
                interface.dhcp_snooping_trust_evidence,
            ) if line is not None)

        evidence.sort(key=lambda line: line.line_number)

        safe_vlan_scope = [
            f"ip dhcp snooping vlan {vlan_id}"
            for vlan_id in sorted(config.dhcp_snooping_vlans)
        ]

        if not safe_vlan_scope:
            safe_vlan_scope.append(
                "ip dhcp snooping vlan <intended-vlan-id>"
            )

        safe_config_example = "\n".join([
            "ip dhcp snooping",
            *safe_vlan_scope,
        ])

        return RuleEvaluation(
            findings=[Finding(
                rule_id=self.rule_id,
                title="DHCP Snooping globally inactive",
                category="DHCP_SPOOFING",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                technical_impact=(
                    "DHCP Snooping-related configuration exists, but the "
                    "feature is not active globally. The expected DHCP "
                    "spoofing protection may therefore not be enforced."
                ),
                remediation=(
                    "Verify whether DHCP Snooping is intended for this "
                    "switch and the configured VLANs. If required, enable "
                    "DHCP Snooping globally and verify the intended VLAN "
                    "scope and trusted DHCP server paths."
                ),
                safe_config_example=safe_config_example,
                evidence=evidence,
            )],
            assessed_units=assessed_units,
        )
