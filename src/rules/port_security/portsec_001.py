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
from src.utils import natural_sort_key


class PORTSEC001InconsistentCoverageRule:
    rule_id = "PORTSEC-001"

    def evaluate(self, config: ParsedConfig) -> list[Finding]:
        return self.evaluate_detailed(config).findings

    def evaluate_detailed(self, config: ParsedConfig) -> RuleEvaluation:
        peers_by_vlan: dict[int, list[InterfaceConfig]] = {}

        for interface in config.interfaces:
            if interface.mode != InterfaceMode.ACCESS:
                continue

            if interface.access_vlan is None:
                continue

            peers_by_vlan.setdefault(
                interface.access_vlan,
                [],
            ).append(interface)

        findings: list[Finding] = []
        assessed_units = 0

        for vlan_id in sorted(peers_by_vlan):
            peers = peers_by_vlan[vlan_id]
            protected_peers = [
                interface
                for interface in peers
                if interface.port_security == ConfigState.ENABLED
            ]

            if protected_peers:
                assessed_units += len(peers)
            affected_interfaces = [
                interface
                for interface in peers
                if interface.port_security
                in (ConfigState.NOT_CONFIGURED, ConfigState.DISABLED)
            ]

            if not protected_peers or not affected_interfaces:
                continue

            protected_peers.sort(
                key=lambda interface: natural_sort_key(interface.name)
            )
            affected_interfaces.sort(
                key=lambda interface: natural_sort_key(interface.name)
            )

            evidence = self._collect_evidence(
                protected_peers,
                affected_interfaces,
            )
            safe_config_example = self._build_safe_config_example(
                affected_interfaces
            )

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=(
                        "Inconsistent Port Security coverage on peer "
                        "access ports"
                    ),
                    category="MAC_SPOOFING",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    technical_impact=(
                        "Port Security is enabled on peer access ports in "
                        "the same VLAN but is missing or explicitly "
                        "disabled on other peer interfaces. These "
                        "interfaces may allow MAC addresses outside the "
                        "intended port-level policy."
                    ),
                    remediation=(
                        "Verify that the affected interfaces share the "
                        "same endpoint access policy as their protected "
                        "peers. If Port Security is intended, enable it on "
                        "the affected interfaces and configure the "
                        "appropriate MAC address, maximum, and violation "
                        "policy for the environment."
                    ),
                    safe_config_example=safe_config_example,
                    evidence=evidence,
                    affected_interfaces=[
                        interface.name
                        for interface in affected_interfaces
                    ],
                )
            )

        return RuleEvaluation(findings, assessed_units)

    @staticmethod
    def _collect_evidence(
        protected_peers: list[InterfaceConfig],
        affected_interfaces: list[InterfaceConfig],
    ) -> list[SourceLine]:
        evidence: list[SourceLine] = []

        for interface in [*protected_peers, *affected_interfaces]:
            evidence.extend(line for line in (
                interface.declaration_evidence,
                interface.mode_evidence,
                interface.access_vlan_evidence,
                interface.port_security_evidence,
            ) if line is not None)

        evidence.sort(key=lambda line: line.line_number)
        return evidence

    @staticmethod
    def _build_safe_config_example(
        affected_interfaces: list[InterfaceConfig],
    ) -> str:
        return "\n!\n".join(
            (
                f"interface {interface.name}\n"
                " switchport port-security"
            )
            for interface in affected_interfaces
        )
