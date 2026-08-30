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
ip arp inspection vlan 10
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
ip arp inspection vlan 10
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


def test_analyzer_produces_dhcp_002_finding():
    raw_config = """ip dhcp snooping
ip dhcp snooping vlan 10
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
"""

    findings = AnalyzerService().analyze(raw_config)

    assert len(findings) == 1
    assert findings[0].rule_id == "DHCP-002"


def test_analyzer_produces_portsec_001_finding():
    raw_config = """interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 20
 switchport port-security
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 20
!
"""

    findings = AnalyzerService().analyze(raw_config)

    assert len(findings) == 1
    assert findings[0].rule_id == "PORTSEC-001"


def test_analyzer_produces_stp_001_finding():
    raw_config = """interface GigabitEthernet1/0/5
 switchport mode access
 spanning-tree portfast edge
!
"""

    findings = AnalyzerService().analyze(raw_config)

    assert len(findings) == 1
    assert findings[0].rule_id == "STP-001"


def test_analyzer_produces_dai_001_finding():
    raw_config = """ip dhcp snooping
ip dhcp snooping vlan 20
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
!
"""

    findings = AnalyzerService().analyze(raw_config)

    assert len(findings) == 1
    assert findings[0].rule_id == "DAI-001"
