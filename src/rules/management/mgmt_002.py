from src.domain.models import (
    ConfigState,
    Confidence,
    Finding,
    ParsedConfig,
    RuleEvaluation,
    Severity,
)
from src.renderers.safe_config import (
    SafeConfigRenderer,
    default_safe_config_renderer,
)


class MGMT002InsecureHTTPServerRule:
    rule_id = "MGMT-002"

    def __init__(self, renderer: SafeConfigRenderer | None = None) -> None:
        self.renderer = (
            renderer if renderer is not None else default_safe_config_renderer()
        )

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        return self.evaluate_detailed(config).findings

    def evaluate_detailed(self, config: ParsedConfig) -> RuleEvaluation:
        assessed_units = int(
            config.http_server_evidence is not None
            and config.http_server in (
                ConfigState.ENABLED,
                ConfigState.DISABLED,
            )
        )
        if config.http_server != ConfigState.ENABLED:
            return RuleEvaluation([], assessed_units)

        evidence = []
        if config.http_server_evidence is not None:
            evidence.append(config.http_server_evidence)
        evidence.sort(key=lambda line: line.line_number)

        return RuleEvaluation(
            findings=[Finding(
                rule_id=self.rule_id,
                title="Insecure HTTP management service explicitly enabled",
                category="MGMT",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                technical_impact=(
                    "The device explicitly enables the standard HTTP "
                    "management service. HTTP does not provide the encrypted "
                    "management transport expected from HTTPS, which can "
                    "expose management credentials or session data on "
                    "reachable network paths."
                ),
                remediation=(
                    "Verify whether web-based device management is required "
                    "and disable the standard HTTP server. If web management "
                    "is required, use an appropriately secured HTTPS "
                    "configuration and apply the authentication and "
                    "management-access restrictions required by the "
                    "environment."
                ),
                safe_config_example=(
                    self.renderer.disable_insecure_http_server()
                ),
                evidence=evidence,
            )],
            assessed_units=assessed_units,
        )
