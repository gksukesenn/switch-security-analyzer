from src.domain.models import (
    ConfigState,
    Confidence,
    Finding,
    ParsedConfig,
    Severity,
)


class MGMT002InsecureHTTPServerRule:
    rule_id = "MGMT-002"

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        if config.http_server != ConfigState.ENABLED:
            return []

        evidence = []
        if config.http_server_evidence is not None:
            evidence.append(config.http_server_evidence)
        evidence.sort(key=lambda line: line.line_number)

        return [
            Finding(
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
                safe_config_example="no ip http server",
                evidence=evidence,
            )
        ]
