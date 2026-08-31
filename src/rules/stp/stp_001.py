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


class STP001PortFastWithoutBPDUGuardRule:
    rule_id = "STP-001"

    def __init__(self, renderer: SafeConfigRenderer | None = None) -> None:
        self.renderer = (
            renderer if renderer is not None else default_safe_config_renderer()
        )

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        return self.evaluate_detailed(config).findings

    def evaluate_detailed(self, config: ParsedConfig) -> RuleEvaluation:
        affected_interfaces: list[InterfaceConfig] = []
        assessed_units = 0

        for interface in config.interfaces:
            if interface.mode != InterfaceMode.ACCESS:
                continue

            if not self._has_effective_portfast(config, interface):
                continue

            effective_bpdu_guard = self._effective_bpdu_guard(
                config,
                interface,
            )

            if effective_bpdu_guard is None:
                continue

            assessed_units += 1

            if effective_bpdu_guard is False:
                affected_interfaces.append(interface)

        if not affected_interfaces:
            return RuleEvaluation([], assessed_units)

        affected_interfaces.sort(
            key=lambda interface: natural_sort_key(interface.name)
        )

        return RuleEvaluation(
            findings=[Finding(
                rule_id=self.rule_id,
                title="PortFast edge port lacks effective BPDU Guard",
                category="STP",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                technical_impact=(
                    "A PortFast edge interface does not have effective "
                    "BPDU Guard protection. Unexpected BPDUs received on "
                    "the edge port may influence spanning-tree behavior "
                    "and can contribute to topology disruption or loss of "
                    "availability."
                ),
                remediation=(
                    "Verify that the affected interfaces are intended to "
                    "be host-facing edge ports. If so, enable BPDU Guard "
                    "on the interfaces or use the appropriate global "
                    "PortFast BPDU Guard default policy. Do not use "
                    "PortFast edge semantics on switch-to-switch links."
                ),
                safe_config_example=self.renderer.enable_bpdu_guard(
                    interface.name for interface in affected_interfaces
                ),
                evidence=self._collect_evidence(
                    config,
                    affected_interfaces,
                ),
                affected_interfaces=[
                    interface.name for interface in affected_interfaces
                ],
            )],
            assessed_units=assessed_units,
        )

    @staticmethod
    def _has_effective_portfast(
        config: ParsedConfig,
        interface: InterfaceConfig,
    ) -> bool:
        if interface.portfast == ConfigState.ENABLED:
            return True

        return (
            interface.portfast == ConfigState.NOT_CONFIGURED
            and config.portfast_default == ConfigState.ENABLED
        )

    @staticmethod
    def _effective_bpdu_guard(
        config: ParsedConfig,
        interface: InterfaceConfig,
    ) -> bool | None:
        if interface.bpdu_guard == ConfigState.ENABLED:
            return True

        if interface.bpdu_guard == ConfigState.DISABLED:
            return False

        if interface.bpdu_guard in (
            ConfigState.UNKNOWN,
            ConfigState.UNSUPPORTED,
        ):
            return None

        if config.bpdu_guard_default == ConfigState.ENABLED:
            return True

        if config.bpdu_guard_default in (
            ConfigState.UNKNOWN,
            ConfigState.UNSUPPORTED,
        ):
            return None

        return False

    @staticmethod
    def _collect_evidence(
        config: ParsedConfig,
        affected_interfaces: list[InterfaceConfig],
    ) -> list[SourceLine]:
        evidence: list[SourceLine] = []

        if any(
            interface.portfast == ConfigState.NOT_CONFIGURED
            for interface in affected_interfaces
        ) and config.portfast_default_evidence is not None:
            evidence.append(config.portfast_default_evidence)

        if config.bpdu_guard_default_evidence is not None:
            evidence.append(config.bpdu_guard_default_evidence)

        for interface in affected_interfaces:
            evidence.extend(line for line in (
                interface.declaration_evidence,
                interface.mode_evidence,
                interface.access_vlan_evidence,
                interface.portfast_evidence
                if interface.portfast == ConfigState.ENABLED else None,
                interface.bpdu_guard_evidence
                if interface.bpdu_guard == ConfigState.DISABLED else None,
            ) if line is not None)

        return sorted(
            set(evidence),
            key=lambda line: line.line_number,
        )
