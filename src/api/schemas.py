from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from src.domain.vendors import Vendor
from src.services.batch_analysis import MAX_BATCH_DEVICES


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(strict=True)

    config: str
    vendor: Annotated[Vendor, Field(strict=False)] = Vendor.CISCO_IOS

    @field_validator("config")
    @classmethod
    def config_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("config must not be empty or whitespace-only")
        return value


class BatchDeviceRequest(BaseModel):
    model_config = ConfigDict(strict=True)

    device_id: str
    vendor: Annotated[Vendor, Field(strict=False)]
    config: str

    @field_validator("device_id", "config")
    @classmethod
    def value_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must not be empty or whitespace-only")
        return value


class BatchAnalyzeRequest(BaseModel):
    model_config = ConfigDict(strict=True)

    devices: Annotated[
        list[BatchDeviceRequest],
        Field(min_length=1, max_length=MAX_BATCH_DEVICES),
    ]

    @model_validator(mode="after")
    def device_ids_must_be_unique(self):
        device_ids = [device.device_id for device in self.devices]
        if len(device_ids) != len(set(device_ids)):
            raise ValueError("device_id values must be unique")
        return self


class HealthResponse(BaseModel):
    status: str


class DeviceResponse(BaseModel):
    vendor: str
    hostname: str | None


class AnalysisResponse(BaseModel):
    parser_coverage: float | None
    unknown_ratio: float
    analysis_confidence: str
    assessed_rule_count: int
    total_rule_count: int
    rule_assessment_ratio: float


class RulePenaltyResponse(BaseModel):
    rule_id: str
    base_penalty: float
    exposure_factor: float
    violating_units: int
    penalty: float


class PostureResponse(BaseModel):
    score: float | None
    display_score: int | None
    risk_level: str | None
    total_penalty: float | None
    unavailable_reason: str | None
    rule_penalties: list[RulePenaltyResponse]


class EvidenceResponse(BaseModel):
    line_number: int
    text: str


class FindingResponse(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    risk_score: Annotated[int, Field(strict=True, ge=1, le=10)]
    technical_impact: str
    remediation: str
    safe_config_example: str
    affected_interfaces: list[str]
    evidence: list[EvidenceResponse]


class AnalyzeResponse(BaseModel):
    device: DeviceResponse
    analysis: AnalysisResponse
    posture: PostureResponse
    findings: list[FindingResponse]


class BatchDeviceResponse(AnalyzeResponse):
    device_id: str


class VendorStatisticsResponse(BaseModel):
    device_count: int
    finding_count: int
    scored_device_count: int
    unscored_device_count: int


class BatchStatisticsResponse(BaseModel):
    total_devices: int
    total_findings: int
    scored_devices: int
    unscored_devices: int
    by_vendor: dict[str, VendorStatisticsResponse]
    by_category: dict[str, int]


class BatchAnalyzeResponse(BaseModel):
    devices: list[BatchDeviceResponse]
    statistics: BatchStatisticsResponse
