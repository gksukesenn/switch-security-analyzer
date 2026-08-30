from src.domain.models import Finding
from src.parsers.cisco.ios import CiscoIOSParser
from src.rules.dhcp.dhcp_001 import DHCP001GloballyInactiveRule
from src.rules.dhcp.dhcp_002 import DHCP002AccessVlanNotCoveredRule
from src.rules.dhcp.dhcp_003 import DHCP003TrustedAccessPortRule
from src.rules.port_security.portsec_001 import (
    PORTSEC001InconsistentCoverageRule,
)


class AnalyzerService:
    def __init__(self) -> None:
        self.parser = CiscoIOSParser()

        self.rules = [
            DHCP001GloballyInactiveRule(),
            DHCP002AccessVlanNotCoveredRule(),
            DHCP003TrustedAccessPortRule(),
            PORTSEC001InconsistentCoverageRule(),
        ]

    def analyze(self, raw_text: str) -> list[Finding]:
        config = self.parser.parse(raw_text)

        findings: list[Finding] = []

        for rule in self.rules:
            rule_findings = rule.evaluate(config)
            findings.extend(rule_findings)

        return findings
