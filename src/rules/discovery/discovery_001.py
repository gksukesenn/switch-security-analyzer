from src.domain.models import (
    Confidence, ConfigState, Finding, InterfaceMode, ParsedConfig,
    RuleEvaluation, Severity,
)
from src.renderers.safe_config import (
    SafeConfigRenderer,
    default_safe_config_renderer,
)
from src.utils import natural_sort_key


class Discovery001AccessAdvertisementRule:
    rule_id = "DISCOVERY-001"

    def __init__(self, renderer: SafeConfigRenderer | None = None) -> None:
        self.renderer = (
            renderer if renderer is not None else default_safe_config_renderer()
        )

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        return self.evaluate_detailed(config).findings

    @staticmethod
    def _advertised(
        global_state: ConfigState, local_state: ConfigState,
    ) -> bool | None:
        if ConfigState.DISABLED in (global_state, local_state):
            return False
        if global_state == local_state == ConfigState.ENABLED:
            return True
        return None

    def evaluate_detailed(self, config: ParsedConfig) -> RuleEvaluation:
        findings: list[Finding] = []
        assessed_units = 0
        for interface in sorted(
            config.interfaces, key=lambda item: natural_sort_key(item.name),
        ):
            if interface.mode != InterfaceMode.ACCESS:
                continue
            cdp = self._advertised(config.cdp_global, interface.cdp)
            lldp = self._advertised(config.lldp_global, interface.lldp_transmit)
            if cdp is not True and lldp is not True:
                assessed_units += int(cdp is False and lldp is False)
                continue
            assessed_units += 1
            evidence = [interface.declaration_evidence, interface.mode_evidence]
            protocols = []
            if cdp is True:
                protocols.append("CDP")
                evidence.extend([
                    config.cdp_global_evidence, interface.cdp_evidence,
                ])
            if lldp is True:
                protocols.append("LLDP")
                evidence.extend([
                    config.lldp_global_evidence, interface.lldp_transmit_evidence,
                ])
            findings.append(Finding(
                rule_id=self.rule_id,
                title="Discovery advertisement enabled on an explicit access interface",
                category="INFORMATION_LEAKAGE",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                technical_impact=(
                    f"Explicit {' and '.join(protocols)} configuration permits discovery "
                    "advertisements on this access interface, potentially exposing device "
                    "identity and network information to attached endpoints. This describes "
                    "configured advertisement potential, not observed packets."
                ),
                remediation=(
                    "Verify the attached endpoint's discovery requirements. ACCESS mode is "
                    "only an endpoint-role approximation; phones and other managed endpoints "
                    "may legitimately need discovery. If unnecessary, disable the reported "
                    "advertisement protocols locally on this interface, preserving discovery "
                    "on infrastructure links."
                ),
                safe_config_example=self.renderer.disable_discovery_advertisement(
                    interface.name, cdp=cdp is True, lldp=lldp is True,
                ),
                evidence=sorted(
                    {line for line in evidence if line is not None},
                    key=lambda line: line.line_number,
                ),
                affected_interfaces=[interface.name],
            ))
        return RuleEvaluation(findings, assessed_units)
