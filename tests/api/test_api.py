import httpx
import pytest

from src.api.app import MAX_CONFIG_BYTES, analysis_service, app
from src.services.analyzer import AnalyzerService


pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def api_request(method, path, *, raise_app_exceptions=True, **kwargs):
    transport = httpx.ASGITransport(
        app=app,
        raise_app_exceptions=raise_app_exceptions,
    )
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        return await client.request(method, path, **kwargs)


async def test_health():
    response = await api_request("GET", "/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_analyze_serializes_insecure_http_finding():
    response = await api_request(
        "POST",
        "/analyze",
        json={
            "config": (
                "hostname ACCESS-SW-01\n"
                "ip http server\n"
            )
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["device"] == {
        "vendor": "cisco_ios",
        "hostname": "ACCESS-SW-01",
    }
    assert body["analysis"]["analysis_confidence"] == "high"
    assert body["posture"]["score"] is None
    assert body["posture"]["risk_level"] is None
    assert body["posture"]["unavailable_reason"] == (
        "insufficient_rule_assessment"
    )

    finding = body["findings"][0]
    assert finding["rule_id"] == "MGMT-002"
    assert finding["severity"] == "high"
    assert finding["confidence"] == "high"
    assert finding["safe_config_example"] == "no ip http server"
    assert finding["evidence"] == [
        {"line_number": 2, "text": "ip http server"}
    ]


async def test_analyze_serializes_fully_assessed_numeric_posture():
    raw_text = """ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
no ip http server
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 switchport port-security
 spanning-tree portfast
 spanning-tree bpduguard enable
 ip verify source
!
line vty 0 4
 transport input ssh
"""

    response = await api_request(
        "POST", "/analyze", json={"config": raw_text}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["analysis"]["parser_coverage"] == 1.0
    assert body["analysis"]["analysis_confidence"] == "high"
    assert body["analysis"]["assessed_rule_count"] == 9
    assert body["analysis"]["total_rule_count"] == 9
    assert body["analysis"]["rule_assessment_ratio"] == 1.0
    assert body["posture"]["score"] == 100.0
    assert body["posture"]["display_score"] == 100
    assert body["posture"]["risk_level"] == "low"
    assert body["posture"]["total_penalty"] == 0.0
    assert body["posture"]["unavailable_reason"] is None
    assert body["posture"]["rule_penalties"] == []
    assert body["findings"] == []


async def test_analyze_preserves_na_posture_as_null():
    response = await api_request(
        "POST",
        "/analyze",
        json={"config": "hostname ACCESS-SW-01\n"},
    )

    assert response.status_code == 200
    posture = response.json()["posture"]
    assert posture["score"] is None
    assert posture["display_score"] is None
    assert posture["risk_level"] is None
    assert posture["total_penalty"] is None
    assert posture["unavailable_reason"] is not None


async def test_analyze_rejects_empty_and_whitespace_config():
    for config in ("", " \n\t"):
        response = await api_request(
            "POST", "/analyze", json={"config": config}
        )
        assert response.status_code == 422


async def test_analyze_rejects_oversized_config():
    response = await api_request(
        "POST",
        "/analyze",
        json={"config": "x" * (MAX_CONFIG_BYTES + 1)},
    )

    assert response.status_code == 413
    assert response.json() == {
        "detail": f"config exceeds the {MAX_CONFIG_BYTES}-byte limit"
    }


async def test_analyze_rejects_missing_config():
    response = await api_request("POST", "/analyze", json={})
    assert response.status_code == 422


async def test_analyze_rejects_wrong_config_type():
    response = await api_request(
        "POST", "/analyze", json={"config": 123}
    )
    assert response.status_code == 422


async def test_analyze_rejects_malformed_json():
    response = await api_request(
        "POST",
        "/analyze",
        content="{",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422


async def test_unexpected_errors_do_not_expose_tracebacks(monkeypatch):
    def fail_safely(_raw_text):
        raise RuntimeError("sensitive internal detail")

    monkeypatch.setattr(analysis_service, "analyze", fail_safely)
    response = await api_request(
        "POST",
        "/analyze",
        raise_app_exceptions=False,
        json={"config": "hostname SW1"},
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "sensitive internal detail" not in response.text
    assert "Traceback" not in response.text


async def test_analyzer_service_public_contract_remains_findings_list():
    findings = AnalyzerService().analyze("ip http server\n")

    assert isinstance(findings, list)
    assert [finding.rule_id for finding in findings] == ["MGMT-002"]
