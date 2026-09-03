from pathlib import Path
from typing import Any

import httpx


DEFAULT_SERVER_URL = "http://localhost:8000"
DEFAULT_TIMEOUT_SECONDS = 15.0


class AnalyzerClientError(RuntimeError):
    """A safe, user-facing HTTP client failure."""


def normalize_server_url(server_url: str) -> str:
    return server_url.rstrip("/")


class AnalyzerHttpClient:
    def __init__(
        self,
        server_url: str = DEFAULT_SERVER_URL,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.server_url = normalize_server_url(server_url)
        self.timeout = timeout
        self.transport = transport

    def analyze_file(self, config_path: Path, vendor: str) -> dict[str, Any]:
        try:
            with config_path.open("rb") as config_file:
                return self._request(
                    "/analyze/file",
                    data={"vendor": vendor},
                    files={
                        "file": (
                            config_path.name,
                            config_file,
                            "application/octet-stream",
                        )
                    },
                )
        except OSError as exception:
            raise AnalyzerClientError(
                "Could not read the selected configuration file."
            ) from exception

    def analyze_text(self, config: str, vendor: str) -> dict[str, Any]:
        return self._request(
            "/analyze",
            json={"vendor": vendor, "config": config},
        )

    def _request(self, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            with httpx.Client(
                base_url=self.server_url,
                timeout=self.timeout,
                transport=self.transport,
            ) as client:
                response = client.post(path, **kwargs)
        except httpx.TimeoutException as exception:
            raise AnalyzerClientError(
                "The analyzer server did not respond before the timeout."
            ) from exception
        except httpx.HTTPError as exception:
            raise AnalyzerClientError(
                "Could not connect to the analyzer server."
            ) from exception

        if response.is_error:
            detail = _safe_error_detail(response)
            message = f"Analyzer server returned HTTP {response.status_code}"
            if detail:
                message = f"{message}: {detail}"
            raise AnalyzerClientError(message)

        try:
            payload = response.json()
        except ValueError as exception:
            raise AnalyzerClientError(
                "Analyzer server returned an invalid response."
            ) from exception

        if not _is_analysis_response(payload):
            raise AnalyzerClientError(
                "Analyzer server returned an invalid response."
            )
        return payload


def _safe_error_detail(response: httpx.Response) -> str | None:
    try:
        payload = response.json()
    except ValueError:
        return None
    if isinstance(payload, dict) and isinstance(payload.get("detail"), str):
        return payload["detail"]
    return None


def _is_analysis_response(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    device = payload.get("device")
    analysis = payload.get("analysis")
    posture = payload.get("posture")
    findings = payload.get("findings")
    if not (
        isinstance(device, dict)
        and isinstance(analysis, dict)
        and isinstance(posture, dict)
        and isinstance(findings, list)
    ):
        return False
    if not all(
        _is_number_or_none(analysis.get(field))
        for field in ("parser_coverage", "rule_assessment_ratio")
    ):
        return False
    if not _is_number_or_none(posture.get("score")):
        return False
    return all(
        isinstance(finding, dict)
        and isinstance(finding.get("affected_interfaces"), list)
        and isinstance(finding.get("evidence"), list)
        and all(
            isinstance(evidence, dict)
            for evidence in finding["evidence"]
        )
        for finding in findings
    )


def _is_number_or_none(value: Any) -> bool:
    return value is None or isinstance(value, (int, float))
