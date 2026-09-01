import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from src.api.schemas import (
    AnalysisResponse,
    AnalyzeRequest,
    AnalyzeResponse,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    BatchDeviceResponse,
    BatchStatisticsResponse,
    DeviceResponse,
    EvidenceResponse,
    FindingResponse,
    HealthResponse,
    PostureResponse,
    RulePenaltyResponse,
    VendorStatisticsResponse,
)
from src.domain.vendors import UnsupportedVendorError
from src.services.analysis import (
    AnalysisApplicationService,
    ApplicationAnalysisResult,
)
from src.services.batch_analysis import (
    BatchAnalysisService,
    BatchDeviceInput,
    InvalidBatchError,
)


MAX_CONFIG_BYTES = 1024 * 1024

logger = logging.getLogger(__name__)
app = FastAPI(title="Switch Security Analyzer API", version="1.0")
analysis_service = AnalysisApplicationService()
batch_analysis_service = BatchAnalysisService(analysis_service)


@app.exception_handler(Exception)
async def unexpected_exception_handler(
    request: Request,
    exception: Exception,
) -> JSONResponse:
    logger.exception(
        "Unexpected error while handling %s %s",
        request.method,
        request.url.path,
        exc_info=exception,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    if len(request.config.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"config exceeds the {MAX_CONFIG_BYTES}-byte limit",
        )

    try:
        result = analysis_service.analyze(request.config, request.vendor)
    except UnsupportedVendorError as exception:
        raise HTTPException(
            status_code=422,
            detail=str(exception),
        ) from exception
    return _analysis_response(result)


@app.post("/analyze/batch", response_model=BatchAnalyzeResponse)
async def analyze_batch(
    request: BatchAnalyzeRequest,
) -> BatchAnalyzeResponse:
    for device in request.devices:
        if len(device.config.encode("utf-8")) > MAX_CONFIG_BYTES:
            raise HTTPException(
                status_code=413,
                detail=(
                    f"config for {device.device_id} exceeds the "
                    f"{MAX_CONFIG_BYTES}-byte limit"
                ),
            )

    try:
        result = batch_analysis_service.analyze([
            BatchDeviceInput(
                device_id=device.device_id,
                vendor=device.vendor,
                config=device.config,
            )
            for device in request.devices
        ])
    except (InvalidBatchError, UnsupportedVendorError) as exception:
        raise HTTPException(
            status_code=422,
            detail=str(exception),
        ) from exception

    return BatchAnalyzeResponse(
        devices=[
            BatchDeviceResponse(
                device_id=device.device_id,
                **_analysis_response(device.analysis).model_dump(),
            )
            for device in result.devices
        ],
        statistics=BatchStatisticsResponse(
            total_devices=result.statistics.total_devices,
            total_findings=result.statistics.total_findings,
            scored_devices=result.statistics.scored_devices,
            unscored_devices=result.statistics.unscored_devices,
            by_vendor={
                vendor: VendorStatisticsResponse(
                    device_count=statistics.device_count,
                    finding_count=statistics.finding_count,
                    scored_device_count=statistics.scored_device_count,
                    unscored_device_count=statistics.unscored_device_count,
                )
                for vendor, statistics
                in result.statistics.by_vendor.items()
            },
            by_category=result.statistics.by_category,
        ),
    )


def _analysis_response(
    result: ApplicationAnalysisResult,
) -> AnalyzeResponse:
    posture = result.posture

    return AnalyzeResponse(
        device=DeviceResponse(
            vendor=result.config.vendor,
            hostname=result.config.hostname,
        ),
        analysis=AnalysisResponse(
            parser_coverage=result.coverage.coverage,
            unknown_ratio=result.coverage.unknown_ratio,
            analysis_confidence=(
                result.coverage.analysis_confidence.value
            ),
            assessed_rule_count=posture.assessed_rule_count,
            total_rule_count=posture.total_rule_count,
            rule_assessment_ratio=posture.rule_assessment_ratio,
        ),
        posture=PostureResponse(
            score=posture.score,
            display_score=posture.display_score,
            risk_level=(
                posture.risk_level.value
                if posture.risk_level is not None
                else None
            ),
            total_penalty=posture.total_penalty,
            unavailable_reason=posture.unavailable_reason,
            rule_penalties=[
                RulePenaltyResponse(
                    rule_id=penalty.rule_id,
                    base_penalty=penalty.base_penalty,
                    exposure_factor=penalty.exposure_factor,
                    violating_units=penalty.violating_units,
                    penalty=penalty.penalty,
                )
                for penalty in posture.rule_penalties
            ],
        ),
        findings=[
            FindingResponse(
                rule_id=finding.rule_id,
                title=finding.title,
                category=finding.category,
                severity=finding.severity.value,
                confidence=finding.confidence.value,
                technical_impact=finding.technical_impact,
                remediation=finding.remediation,
                safe_config_example=finding.safe_config_example,
                affected_interfaces=finding.affected_interfaces,
                evidence=[
                    EvidenceResponse(
                        line_number=evidence.line_number,
                        text=evidence.text,
                    )
                    for evidence in finding.evidence
                ],
            )
            for finding in result.findings
        ],
    )
