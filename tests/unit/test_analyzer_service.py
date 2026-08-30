from src.services.analyzer import AnalyzerService


def test_analyzer_produces_dhcp_003_finding():
    raw_config = """hostname ACCESS-SW-01
ip dhcp snooping
ip dhcp snooping vlan 10
!
interface GigabitEthernet1/0/5
 description USER-PC
 switchport mode access
 switchport access vlan 10
 ip dhcp snooping trust
!
"""

    analyzer = AnalyzerService()

    findings = analyzer.analyze(raw_config)

    assert len(findings) == 1
    assert findings[0].rule_id == "DHCP-003"


def test_analyzer_returns_no_finding_for_safe_access_port():
    raw_config = """hostname ACCESS-SW-01
ip dhcp snooping
ip dhcp snooping vlan 10
!
interface GigabitEthernet1/0/5
 description USER-PC
 switchport mode access
 switchport access vlan 10
!
"""

    analyzer = AnalyzerService()

    findings = analyzer.analyze(raw_config)

    assert findings == []


def test_analyzer_produces_dhcp_001_finding():
    raw_config = """hostname ACCESS-SW-01
no ip dhcp snooping
ip dhcp snooping vlan 10
"""

    analyzer = AnalyzerService()

    findings = analyzer.analyze(raw_config)

    assert len(findings) == 1
    assert findings[0].rule_id == "DHCP-001"
