from src.domain.models import Finding
from src.parsers.cisco.ios import CiscoIOSParser
from src.renderers.safe_config import (
    CiscoSafeConfigRenderer,
    SafeConfigRenderer,
)
from src.rules.dai.dai_001 import DAI001DhcpVlanWithoutDAIRule
from src.rules.dhcp.dhcp_001 import DHCP001GloballyInactiveRule
from src.rules.dhcp.dhcp_002 import DHCP002AccessVlanNotCoveredRule
from src.rules.dhcp.dhcp_003 import DHCP003TrustedAccessPortRule
from src.rules.ip_source_guard.ipsg_001 import (
    IPSG001DhcpEndpointWithoutIPSGRule,
)
from src.rules.management.mgmt_001 import MGMT001VtyTelnetEnabledRule
from src.rules.management.mgmt_002 import MGMT002InsecureHTTPServerRule
from src.rules.port_security.portsec_001 import (
    PORTSEC001InconsistentCoverageRule,
)
from src.rules.stp.stp_001 import STP001PortFastWithoutBPDUGuardRule
from src.services.vendor_selection import ConfigParser


class AnalyzerService:
    def __init__(
        self,
        safe_config_renderer: SafeConfigRenderer | None = None,
        parser: ConfigParser | None = None,
    ) -> None:
        self.parser = parser if parser is not None else CiscoIOSParser()
        renderer = (
            safe_config_renderer
            if safe_config_renderer is not None
            else CiscoSafeConfigRenderer()
        )

        self.rules = [
            DHCP001GloballyInactiveRule(renderer),
            DHCP002AccessVlanNotCoveredRule(renderer),
            DHCP003TrustedAccessPortRule(renderer),
            PORTSEC001InconsistentCoverageRule(renderer),
            STP001PortFastWithoutBPDUGuardRule(renderer),
            DAI001DhcpVlanWithoutDAIRule(renderer),
            IPSG001DhcpEndpointWithoutIPSGRule(renderer),
            MGMT001VtyTelnetEnabledRule(renderer),
            MGMT002InsecureHTTPServerRule(renderer),
        ]

    def analyze(self, raw_text: str) -> list[Finding]:
        config = self.parser.parse(raw_text)

        findings: list[Finding] = []

        for rule in self.rules:
            rule_findings = rule.evaluate(config)
            findings.extend(rule_findings)

        return findings
