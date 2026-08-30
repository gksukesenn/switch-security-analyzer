from src.domain.models import (
    Confidence,
    ConfigState,
    Finding,
    ParsedConfig,
    Severity,
    SourceLine,
)


class DHCP001GloballyInactiveRule:
    rule_id = "DHCP-001"

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        if config.dhcp_snooping_global == ConfigState.ENABLED:
            return []

        trusted_interfaces = [
            interface
            for interface in config.interfaces
            if interface.dhcp_snooping_trust == ConfigState.ENABLED
        ]

        if not config.dhcp_snooping_vlans and not trusted_interfaces:
            return []

        evidence: list[SourceLine] = []

        if config.dhcp_snooping_global_evidence is not None:
            evidence.append(config.dhcp_snooping_global_evidence)

        evidence.extend(
            config.dhcp_snooping_vlan_evidence[vlan_id]
            for vlan_id in sorted(config.dhcp_snooping_vlans)
            if vlan_id in config.dhcp_snooping_vlan_evidence
        )

        for interface in trusted_interfaces:
            evidence.extend(
                line
                for line in interface.raw_lines
                if line.text.strip().startswith("interface ")
                or line.text.strip() == "ip dhcp snooping trust"
            )

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

        return [
            Finding(
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
            )
        ]
