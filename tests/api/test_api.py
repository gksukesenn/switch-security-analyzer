import httpx
import pytest

from src.api.app import MAX_CONFIG_BYTES, analysis_service, app
from src.services.batch_analysis import MAX_BATCH_DEVICES
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


async def test_browser_ui_serves_analyzer_page():
    response = await api_request("GET", "/")

    assert response.status_code == 200
    assert "Switch Security Analyzer" in response.text
    assert 'action="/analyze/file"' in response.text
    assert "Upload File" in response.text
    assert "Paste Configuration" in response.text
    assert 'id="config-text"' in response.text
    assert 'value="cisco_ios"' in response.text
    assert 'value="aruba_aos_cx"' in response.text
    assert 'value="aruba_aos_s"' in response.text
    assert "Aruba AOS-CX" in response.text
    assert "ArubaOS-Switch (AOS-S / 2930F)" in response.text
    assert '<option value="cisco_ios">Cisco IOS / IOS-XE</option>' in response.text
    assert '<option value="aruba_aos_cx">Aruba AOS-CX</option>' in response.text
    assert (
        '<option value="aruba_aos_s">ArubaOS-Switch (AOS-S / 2930F)</option>'
        in response.text
    )
    assert response.text.count('<option value="huawei_vrp">') == 1
    assert (
        '<option value="huawei_vrp">Huawei VRP (S5720 first slice)</option>'
        in response.text
    )


async def test_browser_ui_stylesheet_is_served():
    response = await api_request("GET", "/static/styles.css")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")


async def test_browser_ui_javascript_uses_existing_analysis_endpoints():
    response = await api_request("GET", "/static/app.js")

    assert response.status_code == 200
    assert "fetch(\"/analyze/file\"" in response.text
    assert "fetch(\"/analyze\"" in response.text
    assert "renderAnalysis(payload)" in response.text
    assert 'detailBlock("Finding risk score", `${finding.risk_score}/10`)' in response.text
    assert 'aruba_aos_cx: "Aruba AOS-CX"' in response.text
    assert 'huawei_vrp: "Huawei VRP (S5720 first slice)"' in response.text
    assert (
        'aruba_aos_s: "ArubaOS-Switch (AOS-S / 2930F)"'
        in response.text
    )


async def test_swagger_docs_remain_accessible():
    response = await api_request("GET", "/docs")

    assert response.status_code == 200
    assert "swagger-ui" in response.text


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


async def test_explicit_cisco_vendor_matches_omitted_vendor_response():
    config = "hostname ACCESS-SW-01\nip http server\n"

    omitted = await api_request(
        "POST", "/analyze", json={"config": config}
    )
    explicit = await api_request(
        "POST",
        "/analyze",
        json={"vendor": "cisco_ios", "config": config},
    )

    assert omitted.status_code == 200
    assert explicit.status_code == 200
    assert explicit.json() == omitted.json()


async def test_unknown_vendor_is_rejected():
    response = await api_request(
        "POST",
        "/analyze",
        json={"vendor": "unknown_vendor", "config": "hostname SW1"},
    )

    assert response.status_code == 422


async def test_analyze_file_accepts_cisco_config():
    response = await api_request(
        "POST",
        "/analyze/file",
        data={"vendor": "cisco_ios"},
        files={
            "file": (
                "untrusted-name.cfg",
                b"hostname ACCESS-SW-01\nip http server\n",
                "text/plain",
            )
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["device"] == {
        "vendor": "cisco_ios",
        "hostname": "ACCESS-SW-01",
    }
    assert [finding["rule_id"] for finding in body["findings"]] == [
        "MGMT-002"
    ]


async def test_analyze_file_accepts_aruba_config():
    response = await api_request(
        "POST",
        "/analyze/file",
        data={"vendor": "aruba_aos_cx"},
        files={
            "file": (
                "switch.txt",
                (
                    b"dhcpv4-snooping\n"
                    b"vlan 10\n dhcpv4-snooping\n!\n"
                    b"interface 1/1/1\n no routing\n vlan access 20\n!\n"
                ),
                "text/plain",
            )
        },
    )

    assert response.status_code == 200
    assert response.json()["device"]["vendor"] == "aruba_aos_cx"
    assert [finding["rule_id"] for finding in response.json()["findings"]] == [
        "DHCP-002"
    ]


async def test_analyze_file_rejects_unknown_vendor():
    response = await api_request(
        "POST",
        "/analyze/file",
        data={"vendor": "unknown_vendor"},
        files={"file": ("switch.cfg", b"hostname SW1", "text/plain")},
    )

    assert response.status_code == 422


@pytest.mark.parametrize("content", [b"", b" \n\t"])
async def test_analyze_file_rejects_empty_config(content):
    response = await api_request(
        "POST",
        "/analyze/file",
        data={"vendor": "cisco_ios"},
        files={"file": ("switch.cfg", content, "text/plain")},
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "config must not be empty or whitespace-only"
    }


async def test_analyze_file_rejects_oversized_config():
    response = await api_request(
        "POST",
        "/analyze/file",
        data={"vendor": "cisco_ios"},
        files={
            "file": (
                "switch.cfg",
                b"x" * (MAX_CONFIG_BYTES + 1),
                "text/plain",
            )
        },
    )

    assert response.status_code == 413
    assert response.json() == {
        "detail": f"config exceeds the {MAX_CONFIG_BYTES}-byte limit"
    }


async def test_analyze_file_rejects_invalid_utf8():
    response = await api_request(
        "POST",
        "/analyze/file",
        data={"vendor": "cisco_ios"},
        files={"file": ("switch.cfg", b"hostname SW1\n\xff", "text/plain")},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "config must be valid UTF-8 text"}


async def test_analyze_file_response_matches_json_analyze():
    config = "hostname ACCESS-SW-01\nip http server\n"
    json_response = await api_request(
        "POST",
        "/analyze",
        json={"vendor": "cisco_ios", "config": config},
    )
    file_response = await api_request(
        "POST",
        "/analyze/file",
        data={"vendor": "cisco_ios"},
        files={"file": ("switch.conf", config.encode(), "application/octet-stream")},
    )

    assert json_response.status_code == 200
    assert file_response.status_code == 200
    assert file_response.json() == json_response.json()


async def test_aruba_vendor_uses_aruba_pipeline():
    response = await api_request(
        "POST",
        "/analyze",
        json={
            "vendor": "aruba_aos_cx",
            "config": (
                "dhcpv4-snooping\n"
                "vlan 10\n"
                " dhcpv4-snooping\n"
                "!\n"
                "interface 1/1/1\n"
                " no routing\n"
                " vlan access 20\n"
                "!\n"
            ),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["device"]["vendor"] == "aruba_aos_cx"
    assert [finding["rule_id"] for finding in body["findings"]] == [
        "DHCP-002"
    ]
    assert body["findings"][0]["safe_config_example"] == (
        "dhcpv4-snooping\nvlan 20\n dhcpv4-snooping"
    )


async def test_analyze_accepts_aruba_aos_s_with_nullable_posture():
    response = await api_request(
        "POST",
        "/analyze",
        json={
            "vendor": "aruba_aos_s",
            "config": (
                "dhcp-snooping\n"
                "dhcp-snooping vlan 20\n"
                "vlan 20\n untagged 2\n exit\n"
            ),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["device"]["vendor"] == "aruba_aos_s"
    assert body["posture"]["score"] is None
    assert body["posture"]["risk_level"] is None
    assert body["analysis"]["total_rule_count"] == 10


async def test_analyze_file_accepts_aruba_aos_s():
    response = await api_request(
        "POST",
        "/analyze/file",
        data={"vendor": "aruba_aos_s"},
        files={
            "file": (
                "synthetic.cfg",
                b"dhcp-snooping\ndhcp-snooping vlan 20\n",
                "text/plain",
            )
        },
    )

    assert response.status_code == 200
    assert response.json()["device"]["vendor"] == "aruba_aos_s"


async def test_batch_analyze_accepts_aruba_aos_s_device():
    response = await api_request(
        "POST",
        "/analyze/batch",
        json={
            "devices": [{
                "device_id": "aos-s-01",
                "vendor": "aruba_aos_s",
                "config": "dhcp-snooping\ndhcp-snooping vlan 20\n",
            }]
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["devices"][0]["device"]["vendor"] == "aruba_aos_s"
    assert body["devices"][0]["posture"]["score"] is None
    assert body["devices"][0]["posture"]["risk_level"] is None
    assert body["statistics"]["by_vendor"]["aruba_aos_s"][
        "device_count"
    ] == 1


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
    assert body["analysis"]["total_rule_count"] == 10
    assert body["analysis"]["rule_assessment_ratio"] == 0.9
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


async def test_batch_analyze_preserves_order_and_aggregates_mixed_vendors():
    response = await api_request(
        "POST",
        "/analyze/batch",
        json={
            "devices": [
                {
                    "device_id": "aruba-01",
                    "vendor": "aruba_aos_cx",
                    "config": (
                        "dhcpv4-snooping\n"
                        "vlan 10\n dhcpv4-snooping\n!\n"
                        "interface 1/1/1\n"
                        " no routing\n vlan access 20\n"
                        " spanning-tree port-type admin-edge\n!\n"
                    ),
                },
                {
                    "device_id": "cisco-01",
                    "vendor": "cisco_ios",
                    "config": (
                        "ip dhcp snooping\n"
                        "ip dhcp snooping vlan 10\n"
                        "ip arp inspection vlan 10\n"
                        "ip http server\n"
                        "interface GigabitEthernet1/0/1\n"
                        " switchport mode access\n"
                        " switchport access vlan 10\n"
                        " switchport port-security\n"
                        " spanning-tree portfast\n"
                        " spanning-tree bpduguard enable\n"
                        " ip verify source\n!\n"
                        "line vty 0 4\n transport input ssh\n"
                    ),
                },
            ]
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert [device["device_id"] for device in body["devices"]] == [
        "aruba-01",
        "cisco-01",
    ]
    assert body["devices"][0]["device"]["vendor"] == "aruba_aos_cx"
    assert body["devices"][0]["posture"]["score"] is None
    assert body["devices"][1]["device"]["vendor"] == "cisco_ios"
    assert body["devices"][1]["posture"]["score"] == 85.0
    assert body["statistics"] == {
        "total_devices": 2,
        "total_findings": 3,
        "scored_devices": 1,
        "unscored_devices": 1,
        "by_vendor": {
            "cisco_ios": {
                "device_count": 1,
                "finding_count": 1,
                "scored_device_count": 1,
                "unscored_device_count": 0,
            },
            "aruba_aos_cx": {
                "device_count": 1,
                "finding_count": 2,
                "scored_device_count": 0,
                "unscored_device_count": 1,
            },
        },
        "by_category": {
            "DHCP_SPOOFING": 1,
            "MGMT": 1,
            "STP": 1,
        },
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"devices": []},
        {
            "devices": [
                {"device_id": "same", "vendor": "cisco_ios", "config": "x"},
                {"device_id": "same", "vendor": "aruba_aos_cx", "config": "y"},
            ]
        },
        {
            "devices": [
                {
                    "device_id": str(index),
                    "vendor": "cisco_ios",
                    "config": "hostname SW",
                }
                for index in range(MAX_BATCH_DEVICES + 1)
            ]
        },
    ],
)
async def test_batch_analyze_rejects_invalid_batch(payload):
    response = await api_request("POST", "/analyze/batch", json=payload)

    assert response.status_code == 422


async def test_batch_analyze_enforces_per_config_byte_limit():
    response = await api_request(
        "POST",
        "/analyze/batch",
        json={
            "devices": [{
                "device_id": "large",
                "vendor": "cisco_ios",
                "config": "x" * (MAX_CONFIG_BYTES + 1),
            }]
        },
    )

    assert response.status_code == 413
    assert response.json() == {
        "detail": (
            f"config for large exceeds the {MAX_CONFIG_BYTES}-byte limit"
        )
    }


@pytest.mark.parametrize("endpoint", ["/analyze", "/analyze/file", "/analyze/batch"])
async def test_huawei_surfaces_preserve_vendor_and_limited_posture(endpoint):
    config = (
        "sysname SYNTHETIC-HUAWEI\ndhcp snooping enable\n"
        "telnet server enable\nhttp server enable\n"
    )
    if endpoint == "/analyze/file":
        kwargs = {
            "data": {"vendor": "huawei_vrp"},
            "files": {"file": ("synthetic.cfg", config.encode(), "text/plain")},
        }
    elif endpoint == "/analyze/batch":
        kwargs = {"json": {"devices": [
            {"device_id": "cisco", "vendor": "cisco_ios", "config": "hostname SYNTHETIC\n"},
            {"device_id": "huawei", "vendor": "huawei_vrp", "config": config},
        ]}}
    else:
        kwargs = {"json": {"vendor": "huawei_vrp", "config": config}}

    response = await api_request("POST", endpoint, **kwargs)

    assert response.status_code == 200
    body = response.json()
    if endpoint == "/analyze/batch":
        assert body["devices"][0]["device"]["vendor"] == "cisco_ios"
        assert body["statistics"]["by_vendor"]["huawei_vrp"]["device_count"] == 1
        body = body["devices"][1]
        assert body["device_id"] == "huawei"
    assert body["device"]["vendor"] == "huawei_vrp"
    assert body["device"]["hostname"] == "SYNTHETIC-HUAWEI"
    assert body["analysis"]["total_rule_count"] == 10
    assert body["analysis"]["assessed_rule_count"] <= 4
    assert body["analysis"]["analysis_confidence"] == "low"
    assert body["posture"]["score"] is None
    assert body["posture"]["display_score"] is None
    assert body["posture"]["risk_level"] is None
    assert {finding["rule_id"] for finding in body["findings"]} <= {
        "DHCP-001", "DHCP-002", "DHCP-003", "STP-001",
    }


@pytest.mark.parametrize("endpoint", ["/analyze", "/analyze/file", "/analyze/batch"])
async def test_finding_risk_is_preserved_in_all_analysis_responses(endpoint):
    config = "ip http server\n"
    if endpoint == "/analyze/file":
        kwargs = {"data": {"vendor": "cisco_ios"}, "files": {
            "file": ("synthetic.cfg", config.encode(), "text/plain"),
        }}
    elif endpoint == "/analyze/batch":
        kwargs = {"json": {"devices": [{
            "device_id": "synthetic", "vendor": "cisco_ios", "config": config,
        }]}}
    else:
        kwargs = {"json": {"vendor": "cisco_ios", "config": config}}
    response = await api_request("POST", endpoint, **kwargs)
    assert response.status_code == 200
    body = response.json()
    if endpoint == "/analyze/batch":
        body = body["devices"][0]
    assert body["findings"][0]["rule_id"] == "MGMT-002"
    assert type(body["findings"][0]["risk_score"]) is int
    assert body["findings"][0]["risk_score"] == 8
    assert body["posture"]["score"] is None


@pytest.mark.parametrize("endpoint", ["/analyze", "/analyze/batch"])
async def test_discovery_serializes_through_existing_contract(endpoint):
    device = {"vendor": "cisco_ios", "config": (
        "cdp run\ninterface Gi1/0/1\n switchport mode access\n cdp enable\n"
    )}
    payload = {"devices": [{"device_id": "synthetic", **device}]} if endpoint.endswith("batch") else device
    response = await api_request("POST", endpoint, json=payload)
    assert response.status_code == 200
    body = response.json()
    if endpoint.endswith("batch"):
        assert body["statistics"]["by_category"] == {"INFORMATION_LEAKAGE": 1}
        body = body["devices"][0]
    finding, = body["findings"]
    assert finding["rule_id"] == "DISCOVERY-001"
    assert finding["severity"] == finding["confidence"] == "medium"
    assert finding["risk_score"] == 4
    assert finding["safe_config_example"] == "interface Gi1/0/1\n no cdp enable"
    assert finding["evidence"]
    assert finding["technical_impact"]
    assert finding["remediation"]
    assert body["analysis"]["total_rule_count"] == 10
