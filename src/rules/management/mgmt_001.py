from src.domain.models import (
    ConfigState,
    Confidence,
    Finding,
    ParsedConfig,
    Severity,
    SourceLine,
    VtyConfig,
)


class MGMT001VtyTelnetEnabledRule:
    rule_id = "MGMT-001"

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        affected_vty_lines = sorted(
            (
                vty
                for vty in config.vty_lines
                if vty.transport_input_state == ConfigState.ENABLED
                and "telnet" in vty.transport_input
            ),
            key=lambda vty: (vty.start, vty.end),
        )

        if not affected_vty_lines:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                title="VTY lines explicitly permit Telnet management access",
                category="MGMT",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                technical_impact=(
                    "One or more VTY ranges explicitly permit Telnet for "
                    "remote device management. Telnet does not provide the "
                    "encrypted management transport expected from SSH, "
                    "which can expose management credentials and session "
                    "data to interception on reachable network paths."
                ),
                remediation=(
                    "Verify the intended remote-management access policy "
                    "and remove Telnet from the affected VTY ranges. Where "
                    "remote CLI access is required, restrict the VTY lines "
                    "to SSH and apply the appropriate authentication and "
                    "management-source restrictions for the environment."
                ),
                safe_config_example=self._build_safe_config_example(
                    affected_vty_lines
                ),
                evidence=self._collect_evidence(affected_vty_lines),
            )
        ]

    @staticmethod
    def _collect_evidence(
        affected_vty_lines: list[VtyConfig],
    ) -> list[SourceLine]:
        evidence: list[SourceLine] = []

        for vty in affected_vty_lines:
            evidence.extend(
                line
                for line in vty.raw_lines
                if line.text.strip().startswith("line vty ")
                or line is vty.transport_input_evidence
            )

        evidence.sort(key=lambda line: line.line_number)
        return evidence

    @staticmethod
    def _build_safe_config_example(
        affected_vty_lines: list[VtyConfig],
    ) -> str:
        return "\n!\n".join(
            (
                f"line vty {vty.start} {vty.end}\n"
                " transport input ssh"
            )
            for vty in affected_vty_lines
        )
