from pathlib import Path

from src.services.analysis import AnalysisApplicationService


def test_discovery_remediation_removes_modeled_exposure():
    service = AnalysisApplicationService()
    unsafe = Path("samples/cisco/discovery/access_advertised.cfg").read_text()
    safe = Path("samples/cisco/discovery/access_disabled.cfg").read_text()
    before = service.analyze(unsafe)
    finding, = before.findings
    assert finding.rule_id == "DISCOVERY-001"
    assert finding.risk_score == 4
    assert before.posture.total_rule_count == 10
    assert safe == "cdp run\nlldp run\n" + finding.safe_config_example.replace(
        "\n", "\n switchport mode access\n", 1,
    ) + "\n!\n"
    after = service.analyze(safe)
    assert after.findings == ()
    assert after.evaluations["DISCOVERY-001"].assessed_units == 1
