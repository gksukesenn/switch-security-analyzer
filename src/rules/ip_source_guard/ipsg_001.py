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
from src.renderers.safe_config import (
    SafeConfigRenderer,
    default_safe_config_renderer,
)
from src.utils import natural_sort_key


class IPSG001DhcpEndpointWithoutIPSGRule:
    rule_id = "IPSG-001"

    def __init__(self, renderer: SafeConfigRenderer | None = None) -> None:
        self.renderer = (
            renderer if renderer is not None else default_safe_config_renderer()
        )

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        return self.evaluate_detailed(config).findings

    def evaluate_detailed(self, config: ParsedConfig) -> RuleEvaluation:
        if config.dhcp_snooping_global != ConfigState.ENABLED:
            return RuleEvaluation([], 0)

        affected_by_vlan: dict[int, list[InterfaceConfig]] = {}
        assessed_units = 0

        for interface in config.interfaces:
            if interface.mode != InterfaceMode.ACCESS:
                continue

            if interface.access_vlan is None:
                continue

            if interface.access_vlan not in config.dhcp_snooping_vlans:
                continue

            if interface.dhcp_snooping_trust == ConfigState.ENABLED:
                continue

            if interface.ip_source_guard not in (
                ConfigState.ENABLED,
                ConfigState.NOT_CONFIGURED,
                ConfigState.DISABLED,
            ):
                continue

            assessed_units += 1

            if interface.ip_source_guard == ConfigState.ENABLED:
                continue

            affected_by_vlan.setdefault(
                interface.access_vlan,
                [],
            ).append(interface)

        findings: list[Finding] = []

        for vlan_id in sorted(affected_by_vlan):
            affected_interfaces = sorted(
                affected_by_vlan[vlan_id],
                key=lambda interface: natural_sort_key(interface.name),
            )

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=(
                        "DHCP-protected endpoint interface lacks IP "
                        "Source Guard"
                    ),
                    category="IP_SPOOFING",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    technical_impact=(
                        "An endpoint-facing access interface in a DHCP "
                        "Snooping-protected VLAN does not have IP Source "
                        "Guard enabled. Source-IP traffic on the interface "
                        "may therefore not be validated against trusted "
                        "binding information, leaving a source-IP spoofing "
                        "exposure."
                    ),
                    remediation=(
                        "Verify that the affected interfaces are "
                        "endpoint-facing ports using the DHCP Snooping "
                        "binding policy. If IP Source Guard is intended, "
                        "enable source-IP validation on the affected "
                        "interfaces and verify any required static bindings "
                        "or platform-specific source-validation policy."
                    ),
                    safe_config_example=self.renderer.enable_ip_source_guard(
                        interface.name for interface in affected_interfaces
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
                interface.ip_source_guard_evidence
                if interface.ip_source_guard == ConfigState.DISABLED
                else None,
            ) if line is not None)

        evidence.sort(key=lambda line: line.line_number)
        return evidence
