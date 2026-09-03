import io

import httpx
import pytest

from src.client import cli
from src.client.http import (
    DEFAULT_SERVER_URL,
    AnalyzerClientError,
    AnalyzerHttpClient,
)


def analysis_response():
    return {
        "device": {"vendor": "cisco_ios", "hostname": "ACCESS-SW-01"},
        "analysis": {
            "parser_coverage": 1.0,
            "analysis_confidence": "high",
            "assessed_rule_count": 1,
            "total_rule_count": 9,
            "rule_assessment_ratio": 1 / 9,
        },
        "posture": {"score": None, "risk_level": None},
        "findings": [{
            "rule_id": "MGMT-002",
            "title": "Insecure HTTP management service explicitly enabled",
            "severity": "high",
            "confidence": "high",
            "affected_interfaces": [],
            "technical_impact": "HTTP management traffic is unencrypted.",
            "evidence": [{"line_number": 2, "text": "ip http server"}],
            "remediation": "Disable the standard HTTP server.",
            "safe_config_example": "no ip http server",
        }],
    }


def test_default_server_url():
    client = AnalyzerHttpClient()

    assert client.server_url == DEFAULT_SERVER_URL


def test_custom_server_url_is_preserved():
    client = AnalyzerHttpClient("http://10.10.1.50:8000")

    assert client.server_url == "http://10.10.1.50:8000"


def test_server_trailing_slashes_are_normalized():
    client = AnalyzerHttpClient("http://localhost:8000///")

    assert client.server_url == "http://localhost:8000"


@pytest.mark.parametrize("vendor", ["cisco_ios", "aruba_aos_cx"])
def test_file_request_uses_multipart_for_supported_vendor(tmp_path, vendor):
    config_path = tmp_path / "synthetic.cfg"
    config_path.write_text("hostname TEST\n", encoding="utf-8")

    def handler(request):
        body = request.read()
        assert request.url == "http://server.test/analyze/file"
        assert request.headers["content-type"].startswith("multipart/form-data")
        assert vendor.encode() in body
        assert b"hostname TEST" in body
        assert str(config_path).encode() not in body
        return httpx.Response(200, json=analysis_response())

    client = AnalyzerHttpClient(
        "http://server.test",
        transport=httpx.MockTransport(handler),
    )

    assert client.analyze_file(config_path, vendor)["device"]["hostname"] == (
        "ACCESS-SW-01"
    )


def test_stdin_text_request_uses_json_contract():
    def handler(request):
        assert request.url == "http://server.test/analyze"
        assert request.headers["content-type"] == "application/json"
        assert request.read() == (
            b'{"vendor":"cisco_ios","config":"hostname STDIN\\n"}'
        )
        return httpx.Response(200, json=analysis_response())

    client = AnalyzerHttpClient(
        "http://server.test/",
        transport=httpx.MockTransport(handler),
    )

    client.analyze_text("hostname STDIN\n", "cisco_ios")


def test_missing_file_returns_input_error(tmp_path):
    stderr = io.StringIO()

    exit_code = cli.main(
        ["--vendor", "cisco_ios", "--file", str(tmp_path / "missing.cfg")],
        stderr=stderr,
    )

    assert exit_code == cli.INPUT_ERROR
    assert "does not exist" in stderr.getvalue()


def test_empty_stdin_returns_input_error():
    stderr = io.StringIO()

    exit_code = cli.main(
        ["--vendor", "cisco_ios", "--stdin"],
        stdin=io.StringIO(" \n"),
        stderr=stderr,
    )

    assert exit_code == cli.INPUT_ERROR
    assert "standard input is empty" in stderr.getvalue()


def test_connection_failure_has_safe_error():
    def handler(request):
        raise httpx.ConnectError("connection refused", request=request)

    client = AnalyzerHttpClient(
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(AnalyzerClientError, match="Could not connect"):
        client.analyze_text("hostname TEST", "cisco_ios")


@pytest.mark.parametrize("status_code", [422, 500])
def test_http_error_response_is_reported_without_body_dump(status_code):
    client = AnalyzerHttpClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                status_code,
                json={"detail": "safe server message"},
            )
        ),
    )

    with pytest.raises(AnalyzerClientError) as captured:
        client.analyze_text("secret configuration", "cisco_ios")

    assert f"HTTP {status_code}" in str(captured.value)
    assert "safe server message" in str(captured.value)
    assert "secret configuration" not in str(captured.value)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="not json"),
        httpx.Response(200, json={"unexpected": "shape"}),
    ],
)
def test_malformed_server_response_is_rejected(response):
    client = AnalyzerHttpClient(
        transport=httpx.MockTransport(lambda request: response),
    )

    with pytest.raises(AnalyzerClientError, match="invalid response"):
        client.analyze_text("hostname TEST", "cisco_ios")


def test_successful_terminal_rendering_includes_server_values():
    output = io.StringIO()

    cli.render_analysis(analysis_response(), output)

    rendered = output.getvalue()
    assert "Vendor:              cisco_ios" in rendered
    assert "Security score:      N/A" in rendered
    assert "Parser coverage:     100.0%" in rendered
    assert "Findings:            1" in rendered
    assert "MGMT-002" in rendered
    assert "line 2: ip http server" in rendered
    assert "no ip http server" in rendered


def test_client_failure_returns_nonzero_without_traceback(monkeypatch):
    class FailingClient:
        def __init__(self, server_url):
            pass

        def analyze_text(self, config, vendor):
            raise AnalyzerClientError("Could not connect to the analyzer server.")

    monkeypatch.setattr(cli, "AnalyzerHttpClient", FailingClient)
    stderr = io.StringIO()

    exit_code = cli.main(
        ["--vendor", "cisco_ios", "--stdin"],
        stdin=io.StringIO("hostname TEST"),
        stderr=stderr,
    )

    assert exit_code == cli.CLIENT_ERROR
    assert stderr.getvalue() == (
        "Error: Could not connect to the analyzer server.\n"
    )
    assert "Traceback" not in stderr.getvalue()
